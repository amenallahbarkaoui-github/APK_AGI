"""Smali Intermediate Representation — structured parse of smali bytecode.

Parses smali files into structured objects (SmaliClass / SmaliMethod /
SmaliInstruction) so that all downstream analysers can work on rich data
instead of raw regex over text.

Design goals:
  - Parse ONCE after decompilation → persist to disk as JSON / pickle
  - Expose a global SmaliIndex for instant lookups by class, method, string,
    API call, etc.
  - Foundation for data-flow, taint analysis, auto-patching, and Frida gen.
"""

from __future__ import annotations

import json
import os
import pickle
import re
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from threading import Lock
from typing import Any, Sequence

from apk_agent.parallelism import recommended_file_scan_workers


# ---------------------------------------------------------------------------
# Core IR dataclasses
# ---------------------------------------------------------------------------

@dataclass
class SmaliInstruction:
    """Single dalvik instruction parsed from smali."""
    opcode: str                         # "invoke-virtual", "const-string", "if-eqz" …
    operands: list[str] = field(default_factory=list)  # registers, literals, labels
    raw: str = ""                       # original line text (trimmed)
    line: int = 0                       # 1-based line number in the file
    # Derived / convenience
    is_invoke: bool = False
    is_branch: bool = False
    is_const: bool = False
    is_move: bool = False
    is_return: bool = False
    is_field_access: bool = False
    target_class: str = ""              # for invoke-*: callee class  (Lcom/…;)
    target_method: str = ""             # for invoke-*: callee method name
    target_return_type: str = ""        # for invoke-*: callee return type
    target_field: str = ""              # for *get/*put: field ref
    target_field_type: str = ""         # for *get/*put: field descriptor
    string_value: str | None = None     # for const-string: the literal
    const_value: str | None = None      # for const/*: the numeric literal
    registers: list[str] = field(default_factory=list)  # all registers used


@dataclass
class TryCatchBlock:
    """A .catch / .catchall block."""
    exception_type: str     # Ljava/lang/Exception;  or "all"
    start_label: str
    end_label: str
    handler_label: str


@dataclass
class BasicBlock:
    """A basic block in a method's control flow graph."""
    id: int
    start_idx: int           # first instruction index in method.instructions
    end_idx: int             # last instruction index (inclusive)
    successors: list[int] = field(default_factory=list)   # successor block IDs
    predecessors: list[int] = field(default_factory=list)  # predecessor block IDs
    is_entry: bool = False
    is_exit: bool = False


@dataclass
class SmaliField:
    """A .field declaration."""
    name: str
    type: str               # Smali type descriptor
    access_flags: set[str] = field(default_factory=set)
    value: str | None = None   # initial value if present
    line: int = 0


@dataclass
class SmaliMethod:
    """A complete method with parsed instructions."""
    name: str                 # e.g. "checkRoot"
    signature: str            # e.g. "checkRoot()Z"
    full_signature: str = ""  # e.g. "Lcom/app/Foo;->checkRoot()Z"
    access_flags: set[str] = field(default_factory=set)
    return_type: str = ""
    param_types: list[str] = field(default_factory=list)
    registers: int = 0
    locals: int = 0
    instructions: list[SmaliInstruction] = field(default_factory=list)
    try_catches: list[TryCatchBlock] = field(default_factory=list)
    labels: dict[str, int] = field(default_factory=dict)   # label → instruction index
    annotations: list[str] = field(default_factory=list)
    start_line: int = 0
    end_line: int = 0
    # Pre-computed summaries
    api_calls: list[str] = field(default_factory=list)     # "Lcom/…;->method"
    string_constants: list[str] = field(default_factory=list)
    complexity: int = 0       # branches + try/catch + switches
    category: str = "general" #  crypto / network / ssl_tls / storage / ipc / …
    basic_blocks: list[BasicBlock] = field(default_factory=list)  # CFG blocks
    liveness_in: list[set[str]] = field(default_factory=list)
    liveness_out: list[set[str]] = field(default_factory=list)
    inferred_register_types: list[dict[str, str]] = field(default_factory=list)

    def build_cfg(self) -> list[BasicBlock]:
        """Build basic blocks and CFG edges from instructions.

        A new basic block starts at:
        - The first instruction
        - Any branch target (label)
        - The instruction after a branch or goto
        """
        if not self.instructions:
            return []

        # Find block boundaries
        leaders: set[int] = {0}  # first instruction is always a leader
        for i, instr in enumerate(self.instructions):
            if instr.is_branch or instr.opcode.startswith("goto"):
                # Instruction after branch is a new leader
                if i + 1 < len(self.instructions):
                    leaders.add(i + 1)
                # Branch target is a new leader (via label)
                for op in instr.operands:
                    if op.startswith(":"):
                        target_idx = self.labels.get(op)
                        if target_idx is not None:
                            leaders.add(target_idx)
            elif instr.is_return:
                if i + 1 < len(self.instructions):
                    leaders.add(i + 1)

        for try_catch in self.try_catches:
            start_idx = self.labels.get(try_catch.start_label)
            end_idx = self.labels.get(try_catch.end_label)
            handler_idx = self.labels.get(try_catch.handler_label)
            if start_idx is not None:
                leaders.add(start_idx)
            if end_idx is not None and end_idx < len(self.instructions):
                leaders.add(end_idx)
            if handler_idx is not None:
                leaders.add(handler_idx)

        sorted_leaders = sorted(leaders)
        leader_to_block: dict[int, int] = {}
        instruction_to_block: dict[int, int] = {}

        blocks: list[BasicBlock] = []
        for bid, start in enumerate(sorted_leaders):
            end = (sorted_leaders[bid + 1] - 1) if bid + 1 < len(sorted_leaders) else len(self.instructions) - 1
            bb = BasicBlock(id=bid, start_idx=start, end_idx=end,
                            is_entry=(bid == 0))
            blocks.append(bb)
            leader_to_block[start] = bid
            for instr_idx in range(start, end + 1):
                instruction_to_block[instr_idx] = bid

        # Build edges
        for bb in blocks:
            last_instr = self.instructions[bb.end_idx]
            if last_instr.is_return:
                bb.is_exit = True
                continue
            if last_instr.opcode.startswith("goto"):
                for op in last_instr.operands:
                    if op.startswith(":"):
                        target_idx = self.labels.get(op)
                        if target_idx is not None and target_idx in leader_to_block:
                            succ = leader_to_block[target_idx]
                            bb.successors.append(succ)
                            blocks[succ].predecessors.append(bb.id)
                continue
            if last_instr.is_branch:
                # Conditional branch: fall-through + target
                if bb.end_idx + 1 < len(self.instructions):
                    fall_idx = bb.end_idx + 1
                    if fall_idx in leader_to_block:
                        succ = leader_to_block[fall_idx]
                        bb.successors.append(succ)
                        blocks[succ].predecessors.append(bb.id)
                for op in last_instr.operands:
                    if op.startswith(":"):
                        target_idx = self.labels.get(op)
                        if target_idx is not None and target_idx in leader_to_block:
                            succ = leader_to_block[target_idx]
                            if succ not in bb.successors:
                                bb.successors.append(succ)
                                blocks[succ].predecessors.append(bb.id)
                continue
            # Fall-through
            if bb.end_idx + 1 < len(self.instructions):
                fall_idx = bb.end_idx + 1
                if fall_idx in leader_to_block:
                    succ = leader_to_block[fall_idx]
                    bb.successors.append(succ)
                    blocks[succ].predecessors.append(bb.id)

        for try_catch in self.try_catches:
            start_idx = self.labels.get(try_catch.start_label)
            end_idx = self.labels.get(try_catch.end_label)
            handler_idx = self.labels.get(try_catch.handler_label)
            if start_idx is None or handler_idx is None:
                continue

            protected_end = end_idx if end_idx is not None else len(self.instructions)
            handler_block = instruction_to_block.get(handler_idx)
            if handler_block is None:
                continue

            for bb in blocks:
                if bb.end_idx < start_idx or bb.start_idx >= protected_end:
                    continue
                if handler_block not in bb.successors:
                    bb.successors.append(handler_block)
                if bb.id not in blocks[handler_block].predecessors:
                    blocks[handler_block].predecessors.append(bb.id)

        self.basic_blocks = blocks
        return blocks

    def build_liveness(self) -> dict[str, list[set[str]]]:
        """Compute register liveness at every instruction using the CFG."""
        if not self.instructions:
            self.liveness_in = []
            self.liveness_out = []
            return {"live_in": [], "live_out": []}

        blocks = self.basic_blocks or self.build_cfg()
        live_in = [set() for _ in self.instructions]
        live_out = [set() for _ in self.instructions]

        changed = True
        while changed:
            changed = False
            for bb in reversed(blocks):
                successor_live: set[str] = set()
                for succ in bb.successors:
                    successor_live.update(live_in[blocks[succ].start_idx])

                current_live = set(successor_live)
                for instr_idx in range(bb.end_idx, bb.start_idx - 1, -1):
                    if current_live != live_out[instr_idx]:
                        live_out[instr_idx] = set(current_live)
                        changed = True

                    reads, writes = _instruction_reads_writes(self.instructions[instr_idx])
                    next_live = (current_live - writes) | reads
                    if next_live != live_in[instr_idx]:
                        live_in[instr_idx] = set(next_live)
                        changed = True
                    current_live = next_live

        self.liveness_in = live_in
        self.liveness_out = live_out
        return {"live_in": live_in, "live_out": live_out}

    def infer_register_types(self, owner_class: str = "") -> list[dict[str, str]]:
        """Infer coarse register types across the method CFG."""
        if not self.instructions:
            self.inferred_register_types = []
            return []

        blocks = self.basic_blocks or self.build_cfg()
        inferred = [dict() for _ in self.instructions]
        block_entry: list[dict[str, str]] = [dict() for _ in blocks]
        block_exit: list[dict[str, str]] = [dict() for _ in blocks]
        initial_types = _initial_register_types(self, owner_class)

        changed = True
        while changed:
            changed = False
            for bb in blocks:
                incoming_states = [block_exit[pred] for pred in bb.predecessors]
                if bb.is_entry:
                    incoming_states = [initial_types, *incoming_states]

                entry_state = _merge_register_type_maps(incoming_states) if incoming_states else dict(block_entry[bb.id])
                if entry_state != block_entry[bb.id]:
                    block_entry[bb.id] = dict(entry_state)
                    changed = True

                current_state = dict(entry_state)
                last_invoke_return = ""
                for instr_idx in range(bb.start_idx, bb.end_idx + 1):
                    current_state, last_invoke_return = _apply_type_transfer(
                        self.instructions[instr_idx],
                        current_state,
                        last_invoke_return,
                    )
                    snapshot = dict(current_state)
                    if inferred[instr_idx] != snapshot:
                        inferred[instr_idx] = snapshot
                        changed = True

                if current_state != block_exit[bb.id]:
                    block_exit[bb.id] = dict(current_state)
                    changed = True

        self.inferred_register_types = inferred
        return inferred


@dataclass
class SmaliClass:
    """A complete smali class."""
    name: str                  # Lcom/example/Foo;
    super_class: str = ""
    interfaces: list[str] = field(default_factory=list)
    access_flags: set[str] = field(default_factory=set)
    source_file: str = ""
    file_path: str = ""        # relative path from smali root
    abs_path: str = ""         # absolute path on disk
    fields: list[SmaliField] = field(default_factory=list)
    methods: list[SmaliMethod] = field(default_factory=list)
    annotations: list[str] = field(default_factory=list)
    line_count: int = 0


# ---------------------------------------------------------------------------
# Global index — built ONCE, queried by every analyser
# ---------------------------------------------------------------------------

class SmaliIndex:
    """Indexed view over all parsed smali classes.

    Provides O(1) lookups by class name, method signature, string constant,
    API callee, etc.  Built once by ``build_index`` then persisted to disk.
    """

    def __init__(self) -> None:
        self.classes: dict[str, SmaliClass] = {}                  # class_name → SmaliClass
        self.methods: dict[str, SmaliMethod] = {}                 # full_sig   → SmaliMethod
        self.string_index: dict[str, list[tuple[str, int]]] = defaultdict(list)  # string → [(file, line), …]
        self.api_callers: dict[str, list[str]] = defaultdict(list)               # callee_sig → [caller_sig, …]
        self.field_accessors: dict[str, list[str]] = defaultdict(list)           # field_ref  → [method_sig, …]
        self.call_graph: dict[str, list[str]] = defaultdict(list)                # caller_sig → [callee_sig, …]
        self.class_hierarchy: dict[str, list[str]] = defaultdict(list)           # parent → [children]
        self.interface_implementors: dict[str, list[str]] = defaultdict(list)    # iface → [class, …]
        self.total_files: int = 0
        self.total_instructions: int = 0
        self.built_at: float = 0.0

    # ---- query helpers ----

    def get_class(self, name: str) -> SmaliClass | None:
        return self.classes.get(name)

    def get_method(self, full_sig: str) -> SmaliMethod | None:
        return self.methods.get(full_sig)

    def search_classes(self, pattern: str) -> list[SmaliClass]:
        """Case-insensitive substring match on class name."""
        pat = pattern.lower()
        return [c for c in self.classes.values() if pat in c.name.lower()]

    def search_methods(self, pattern: str) -> list[SmaliMethod]:
        pat = pattern.lower()
        return [m for m in self.methods.values() if pat in m.full_signature.lower()]

    def find_string_usages(self, text: str) -> list[tuple[str, int]]:
        """Find all files/lines where a string constant appears."""
        return self.string_index.get(text, [])

    def find_api_callers(self, api: str) -> list[str]:
        """Find all methods that call a given API (partial match)."""
        results = []
        api_lower = api.lower()
        for key, callers in self.api_callers.items():
            if api_lower in key.lower():
                results.extend(callers)
        return results

    def find_field_accessors(self, field_ref: str) -> list[str]:
        """Find methods that access a given field reference."""
        return self.field_accessors.get(field_ref, [])

    def get_subclasses(self, class_name: str) -> list[str]:
        return self.class_hierarchy.get(class_name, [])

    def get_implementors(self, interface_name: str) -> list[str]:
        return self.interface_implementors.get(interface_name, [])

    def methods_by_category(self, category: str) -> list[SmaliMethod]:
        return [m for m in self.methods.values() if m.category == category]


# ---------------------------------------------------------------------------
# Regex patterns for smali parsing
# ---------------------------------------------------------------------------

_RE_CLASS = re.compile(r"^\.class\s+(.*?)\s+(L[\w/$]+;)\s*$", re.MULTILINE)
_RE_SUPER = re.compile(r"^\.super\s+(L[\w/$]+;)", re.MULTILINE)
_RE_IMPLEMENTS = re.compile(r"^\.implements\s+(L[\w/$]+;)", re.MULTILINE)
_RE_SOURCE = re.compile(r'^\.source\s+"(.*?)"', re.MULTILINE)
_RE_FIELD = re.compile(
    r"^\.field\s+(.*?)\s+([\w$]+):(.*?)(?:\s*=\s*(.*))?$", re.MULTILINE,
)
_RE_METHOD_HDR = re.compile(
    r"^\.method\s+(.*?)([\w<>$]+)\((.*?)\)(.+)$",
)
_RE_ANNOTATION = re.compile(r"\.annotation\s+.*?(L[\w/$]+;)")
_RE_INVOKE = re.compile(r"(L[\w/$]+;)->([\w<>$]+)\(")
_RE_METHOD_REF = re.compile(r"(L[\w/$]+;)->([\w<>$]+)\((.*?)\)([^\s,}#]+)")
_RE_CONST_STRING = re.compile(r'const-string(?:/jumbo)?\s+(\w+),\s*"((?:[^"\\]|\\.)*)"')
_RE_CONST_NUM = re.compile(r"const(?:/4|/16|/high16)?\s+(\w+),\s*(.*?)$")
_RE_REGISTER = re.compile(r"\b([vp]\d+)\b")
_RE_REGISTER_RANGE = re.compile(r"\{([vp])(\d+)\s+\.\.\s+([vp])(\d+)\}")
_RE_TRY_CATCH = re.compile(
    r"\.catch\s+(L[\w/$]+;|\.\.\.)\s+\{(\S+)\s+\.\.\s+(\S+)\}\s+(\S+)"
)
_RE_CATCHALL = re.compile(
    r"\.catchall\s+\{(\S+)\s+\.\.\s+(\S+)\}\s+(\S+)"
)
_RE_NEW_INSTANCE = re.compile(r"new-instance\s+\w+,\s*(L[\w/$]+;)")
_RE_NEW_ARRAY = re.compile(r"new-array\s+\w+,\s+\w+,\s*(\[[^\s,}#]+)")
_RE_CHECK_CAST = re.compile(r"check-cast\s+\w+,\s*(\[[^\s,}#]+|L[\w/$]+;)")

# Opcode classification sets
_INVOKE_OPCODES = frozenset({
    "invoke-virtual", "invoke-super", "invoke-direct", "invoke-static",
    "invoke-interface", "invoke-virtual/range", "invoke-super/range",
    "invoke-direct/range", "invoke-static/range", "invoke-interface/range",
    "invoke-polymorphic", "invoke-polymorphic/range", "invoke-custom",
    "invoke-custom/range",
})
_BRANCH_OPCODES = frozenset({
    "if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le",
    "if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez",
    "goto", "goto/16", "goto/32",
    "packed-switch", "sparse-switch",
})
_CONST_OPCODES = frozenset({
    "const", "const/4", "const/16", "const/high16",
    "const-wide", "const-wide/16", "const-wide/32", "const-wide/high16",
    "const-string", "const-string/jumbo", "const-class",
})
_MOVE_OPCODES = frozenset({
    "move", "move/from16", "move/16", "move-wide", "move-wide/from16",
    "move-wide/16", "move-object", "move-object/from16", "move-object/16",
    "move-result", "move-result-wide", "move-result-object", "move-exception",
})
_RETURN_OPCODES = frozenset({
    "return-void", "return", "return-wide", "return-object",
})
_FIELD_OPCODES = frozenset({
    "iget", "iget-wide", "iget-object", "iget-boolean", "iget-byte",
    "iget-char", "iget-short", "iput", "iput-wide", "iput-object",
    "iput-boolean", "iput-byte", "iput-char", "iput-short",
    "sget", "sget-wide", "sget-object", "sget-boolean", "sget-byte",
    "sget-char", "sget-short", "sput", "sput-wide", "sput-object",
    "sput-boolean", "sput-byte", "sput-char", "sput-short",
})

# Method category detection
_CATEGORY_PATTERNS: dict[str, re.Pattern] = {
    "crypto": re.compile(
        r"Ljavax/crypto/|SecretKeySpec|IvParameterSpec|Cipher;->|"
        r"MessageDigest;->|KeyGenerator;->|Mac;->|Signature;->",
    ),
    "network": re.compile(
        r"Ljava/net/URL|HttpURLConnection|Lokhttp3/|Lretrofit2/|"
        r"Lorg/apache/http|SSLSocket|SSLContext|HttpClient",
    ),
    "ssl_tls": re.compile(
        r"X509TrustManager|checkServerTrusted|HostnameVerifier|"
        r"CertificatePinner|SSLSocketFactory|TrustManagerFactory",
    ),
    "storage": re.compile(
        r"SharedPreferences|SQLiteDatabase|ContentResolver|"
        r"FileOutputStream|FileInputStream|getExternalStorage",
    ),
    "ipc": re.compile(
        r"startActivity|sendBroadcast|startService|bindService|"
        r"ContentProvider|BroadcastReceiver",
    ),
    "reflection": re.compile(
        r"java/lang/reflect/|Class;->forName|getDeclaredMethod|"
        r"getDeclaredField|setAccessible",
    ),
    "dynamic_load": re.compile(
        r"DexClassLoader|PathClassLoader|InMemoryDexClassLoader|"
        r"loadClass|Runtime;->exec|ProcessBuilder",
    ),
}

_FRAMEWORK_HINTS: dict[str, tuple[str, ...]] = {
    "okhttp": ("lokhttp3/", "okhttp"),
    "retrofit": ("lretrofit2/", "retrofit"),
    "gson": ("gson", "lgson/"),
    "moshi": ("moshi", "lcom/squareup/moshi/"),
    "firebase": ("firebase", "lcom/google/firebase/"),
    "billing": ("billingclient", "launchbillingflow", "lcom/android/billingclient/"),
    "revenuecat": ("revenuecat",),
    "qonversion": ("qonversion",),
    "room": ("androidx/room",),
    "coroutines": ("kotlinx/coroutines",),
    "compose": ("androidx/compose", "setcontent"),
    "react_native": ("reactnative", "reactcontextbasejavamodule", "nativemodule"),
    "flutter": ("flutter", "io/flutter"),
    "webview": ("android/webkit/webview", "addjavascriptinterface"),
    "glide": ("bumptech/glide",),
    "xposed": ("xposed", "lsposed"),
}


def _expand_register_range(raw: str) -> list[str]:
    """Expand invoke/range register lists like {v0 .. v3}."""
    match = _RE_REGISTER_RANGE.search(raw)
    if not match:
        return []
    start_prefix, start_idx, end_prefix, end_idx = match.groups()
    if start_prefix != end_prefix:
        return []
    start = int(start_idx)
    end = int(end_idx)
    if end < start:
        return []
    return [f"{start_prefix}{idx}" for idx in range(start, end + 1)]


def _register_sort_key(register: str) -> tuple[int, int, str]:
    prefix_weight = 0 if register.startswith("v") else 1
    try:
        reg_num = int(register[1:])
    except ValueError:
        reg_num = -1
    return prefix_weight, reg_num, register


def _is_reference_descriptor(descriptor: str) -> bool:
    return descriptor.startswith(("L", "["))


def _merge_type_values(left: str, right: str) -> str:
    if not left:
        return right
    if not right or left == right:
        return left
    if _is_reference_descriptor(left) and _is_reference_descriptor(right):
        return "Ljava/lang/Object;"
    return "unknown"


def _merge_register_type_maps(states: list[dict[str, str]]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for state in states:
        for register, reg_type in state.items():
            merged[register] = _merge_type_values(merged.get(register, ""), reg_type)
    return merged


def _instruction_reads_writes(instr: SmaliInstruction) -> tuple[set[str], set[str]]:
    """Return coarse read/write register sets for one instruction."""
    registers = list(dict.fromkeys(instr.registers))
    if not registers:
        return set(), set()

    opcode = instr.opcode
    if instr.is_invoke:
        return set(registers), set()
    if opcode in {"move-result", "move-result-wide", "move-result-object", "move-exception"}:
        return set(), {registers[0]}
    if opcode.startswith(("move", "array-length")):
        return set(registers[1:]), {registers[0]}
    if opcode.startswith("const") or opcode.startswith(("new-instance", "new-array")):
        return set(registers[1:]), {registers[0]}
    if opcode == "check-cast":
        return {registers[0]}, {registers[0]}
    if instr.is_return or opcode.startswith(("if-", "throw", "monitor-", "filled-new-array")):
        return set(registers), set()

    if instr.is_field_access:
        if opcode.startswith(("sget",)):
            return set(), {registers[0]}
        if opcode.startswith(("sput",)):
            return {registers[0]}, set()
        if opcode.startswith(("iget",)):
            reads = {registers[1]} if len(registers) > 1 else set()
            return reads, {registers[0]}
        if opcode.startswith(("iput",)):
            reads = {registers[0]}
            if len(registers) > 1:
                reads.add(registers[1])
            return reads, set()

    if opcode.startswith((
        "add", "sub", "mul", "div", "rem", "and", "or", "xor",
        "shl", "shr", "ushr", "rsub", "neg", "not", "cmp",
        "int-to", "long-to", "float-to", "double-to",
    )):
        return set(registers[1:]), {registers[0]}

    return set(registers[1:]), {registers[0]}


def _initial_register_types(method: SmaliMethod, owner_class: str) -> dict[str, str]:
    """Seed register types from the method receiver and parameters."""
    types: dict[str, str] = {}
    param_slot = 0
    if "static" not in method.access_flags:
        types["p0"] = owner_class or "Ljava/lang/Object;"
        param_slot = 1

    for param in method.param_types:
        if not param:
            continue
        types[f"p{param_slot}"] = param
        param_slot += 2 if param in {"J", "D"} else 1

    return types


def _apply_type_transfer(
    instr: SmaliInstruction,
    current_state: dict[str, str],
    last_invoke_return: str,
) -> tuple[dict[str, str], str]:
    """Apply one instruction's coarse type effect to the current state."""
    next_state = dict(current_state)
    reads, writes = _instruction_reads_writes(instr)
    opcode = instr.opcode
    registers = list(dict.fromkeys(instr.registers))
    dest = registers[0] if registers else ""
    next_invoke_return = ""

    if instr.is_invoke:
        return next_state, instr.target_return_type

    if opcode == "move-exception" and dest:
        next_state[dest] = "Ljava/lang/Throwable;"
        return next_state, ""
    if opcode == "move-result-object" and dest:
        next_state[dest] = last_invoke_return or "Ljava/lang/Object;"
        return next_state, ""
    if opcode == "move-result-wide" and dest:
        next_state[dest] = last_invoke_return or "J"
        return next_state, ""
    if opcode == "move-result" and dest:
        next_state[dest] = last_invoke_return or "I"
        return next_state, ""
    if opcode.startswith("move-object") and len(registers) > 1:
        next_state[dest] = next_state.get(registers[1], "Ljava/lang/Object;")
        return next_state, ""
    if opcode.startswith("move-wide") and len(registers) > 1:
        next_state[dest] = next_state.get(registers[1], "J")
        return next_state, ""
    if opcode.startswith("move") and len(registers) > 1:
        next_state[dest] = next_state.get(registers[1], "I")
        return next_state, ""
    if instr.string_value is not None and dest:
        next_state[dest] = "Ljava/lang/String;"
        return next_state, ""
    if opcode == "const-class" and dest:
        next_state[dest] = "Ljava/lang/Class;"
        return next_state, ""
    if opcode.startswith("const-wide") and dest:
        next_state[dest] = "J"
        return next_state, ""
    if opcode.startswith("const") and dest:
        next_state[dest] = "I"
        return next_state, ""
    if opcode.startswith("new-instance") and dest:
        match = _RE_NEW_INSTANCE.search(instr.raw)
        next_state[dest] = match.group(1) if match else "Ljava/lang/Object;"
        return next_state, ""
    if opcode.startswith("new-array") and dest:
        match = _RE_NEW_ARRAY.search(instr.raw)
        next_state[dest] = match.group(1) if match else "[Ljava/lang/Object;"
        return next_state, ""
    if opcode == "check-cast" and dest:
        match = _RE_CHECK_CAST.search(instr.raw)
        next_state[dest] = match.group(1) if match else next_state.get(dest, "Ljava/lang/Object;")
        return next_state, ""

    if instr.is_field_access and dest:
        if opcode.startswith(("iget-object", "sget-object")):
            next_state[dest] = instr.target_field_type or "Ljava/lang/Object;"
        elif opcode.startswith(("iget-wide", "sget-wide")):
            next_state[dest] = instr.target_field_type or "J"
        elif opcode.startswith(("iget-boolean", "sget-boolean")):
            next_state[dest] = "Z"
        elif opcode.startswith(("iget-byte", "sget-byte")):
            next_state[dest] = "B"
        elif opcode.startswith(("iget-char", "sget-char")):
            next_state[dest] = "C"
        elif opcode.startswith(("iget-short", "sget-short")):
            next_state[dest] = "S"
        elif opcode.startswith(("iget", "sget")):
            next_state[dest] = instr.target_field_type or "I"
        return next_state, ""

    if writes:
        inferred_type = "I"
        if reads:
            source_reg = sorted(reads, key=_register_sort_key)[0]
            inferred_type = next_state.get(source_reg, inferred_type)
        next_state[dest] = inferred_type

    return next_state, next_invoke_return


# ---------------------------------------------------------------------------
# Instruction parser
# ---------------------------------------------------------------------------

def _parse_instruction(raw_line: str, line_no: int) -> SmaliInstruction | None:
    """Parse a single smali instruction line into SmaliInstruction.

    Skips directives (lines starting with .), labels (:), and comments (#).
    """
    stripped = raw_line.strip()
    if not stripped or stripped.startswith((".")) or stripped.startswith((":")) or stripped.startswith(("#")):
        return None

    parts = stripped.split(None, 1)
    opcode = parts[0]
    operand_str = parts[1] if len(parts) > 1 else ""
    operands = [o.strip() for o in operand_str.split(",") if o.strip()] if operand_str else []
    range_registers = _expand_register_range(stripped)
    registers = range_registers or _RE_REGISTER.findall(stripped)

    instr = SmaliInstruction(
        opcode=opcode,
        operands=operands,
        raw=stripped[:300],
        line=line_no,
        registers=registers,
        is_invoke=opcode in _INVOKE_OPCODES,
        is_branch=opcode in _BRANCH_OPCODES,
        is_const=opcode in _CONST_OPCODES,
        is_move=opcode in _MOVE_OPCODES,
        is_return=opcode in _RETURN_OPCODES,
        is_field_access=opcode in _FIELD_OPCODES,
    )

    # Extract target for invoke-*
    if instr.is_invoke:
        m = _RE_METHOD_REF.search(stripped)
        if m:
            instr.target_class = m.group(1)
            instr.target_method = m.group(2)
            instr.target_return_type = m.group(4)

    # Extract field ref for *get/*put
    if instr.is_field_access:
        m = re.search(r"(L[\w/$]+;)->([\w$]+):([^\s,}#]+)", stripped)
        if m:
            instr.target_field = f"{m.group(1)}->{m.group(2)}"
            instr.target_field_type = m.group(3)

    # Extract const-string value
    m = _RE_CONST_STRING.search(stripped)
    if m:
        instr.string_value = m.group(2)

    # Extract numeric const
    if opcode in _CONST_OPCODES and instr.string_value is None:
        m = _RE_CONST_NUM.match(stripped)
        if m:
            instr.const_value = m.group(2).strip()

    return instr


# ---------------------------------------------------------------------------
# Method parser
# ---------------------------------------------------------------------------

def _parse_method(lines: list[str], start_idx: int, end_idx: int,
                  class_name: str) -> SmaliMethod:
    """Parse a method block [start_idx .. end_idx] into SmaliMethod."""
    header = lines[start_idx].strip()
    m = _RE_METHOD_HDR.match(header)
    if not m:
        # Fallback: best-effort parse
        name = "unknown"
        access_str = ""
        param_str = ""
        ret_type = "V"
    else:
        access_str = m.group(1).strip()
        name = m.group(2)
        param_str = m.group(3)
        ret_type = m.group(4).strip()

    access_flags = set(access_str.split()) if access_str else set()
    signature = f"{name}({param_str}){ret_type}"
    full_sig = f"{class_name}->{signature}"

    method = SmaliMethod(
        name=name,
        signature=signature,
        full_signature=full_sig,
        access_flags=access_flags,
        return_type=ret_type,
        param_types=_parse_param_types(param_str),
        start_line=start_idx + 1,
        end_line=end_idx + 1,
    )

    # Parse body
    instructions: list[SmaliInstruction] = []
    labels: dict[str, int] = {}
    try_catches: list[TryCatchBlock] = []
    annotations: list[str] = []
    api_calls: list[str] = []
    string_constants: list[str] = []
    branches = 0
    switches = 0

    body_text = ""
    for i in range(start_idx + 1, end_idx):
        raw = lines[i]
        stripped = raw.strip()
        body_text += stripped + "\n"

        # .locals / .registers
        if stripped.startswith(".locals"):
            try:
                method.locals = int(stripped.split()[1])
            except (IndexError, ValueError):
                pass
        elif stripped.startswith(".registers"):
            try:
                method.registers = int(stripped.split()[1])
            except (IndexError, ValueError):
                pass

        # Labels
        elif stripped.startswith(":"):
            labels[stripped] = len(instructions)

        # Annotations
        elif stripped.startswith(".annotation"):
            am = _RE_ANNOTATION.search(stripped)
            if am:
                annotations.append(am.group(1))

        # Try/catch
        else:
            tc = _RE_TRY_CATCH.search(stripped)
            if tc:
                try_catches.append(TryCatchBlock(
                    exception_type=tc.group(1),
                    start_label=tc.group(2),
                    end_label=tc.group(3),
                    handler_label=tc.group(4),
                ))
                continue
            tc_all = _RE_CATCHALL.search(stripped)
            if tc_all:
                try_catches.append(TryCatchBlock(
                    exception_type="all",
                    start_label=tc_all.group(1),
                    end_label=tc_all.group(2),
                    handler_label=tc_all.group(3),
                ))
                continue

            # Actual instruction
            instr = _parse_instruction(raw, i + 1)
            if instr:
                instructions.append(instr)

                if instr.is_invoke:
                    callee = f"{instr.target_class}->{instr.target_method}"
                    if callee != "->":
                        api_calls.append(callee)

                if instr.string_value is not None:
                    string_constants.append(instr.string_value)

                if instr.is_branch:
                    branches += 1
                    if "switch" in instr.opcode:
                        switches += 1

    method.instructions = instructions
    method.labels = labels
    method.try_catches = try_catches
    method.annotations = annotations
    method.api_calls = list(set(api_calls))
    method.string_constants = string_constants
    method.complexity = branches + len(try_catches) + switches

    # Classify method
    for cat, pat in _CATEGORY_PATTERNS.items():
        if pat.search(body_text):
            method.category = cat
            break

    _ensure_method_analysis(method, class_name)

    return method


def _parse_param_types(param_str: str) -> list[str]:
    """Parse smali parameter descriptor 'ILjava/lang/String;[B' into list."""
    types: list[str] = []
    i = 0
    while i < len(param_str):
        c = param_str[i]
        if c == "L":
            end = param_str.index(";", i)
            types.append(param_str[i:end + 1])
            i = end + 1
        elif c == "[":
            # Array — next char is the element type
            if i + 1 < len(param_str) and param_str[i + 1] == "L":
                end = param_str.index(";", i)
                types.append(param_str[i:end + 1])
                i = end + 1
            else:
                types.append(param_str[i:i + 2] if i + 1 < len(param_str) else param_str[i:])
                i += 2
        else:
            types.append(c)
            i += 1
    return types


def _ensure_method_analysis(method: SmaliMethod, owner_class: str) -> None:
    """Populate CFG/liveness/type summaries when they are missing."""
    if not method.instructions:
        method.basic_blocks = []
        method.liveness_in = []
        method.liveness_out = []
        method.inferred_register_types = []
        return

    try:
        if not method.basic_blocks:
            method.build_cfg()
        if len(method.liveness_in) != len(method.instructions) or len(method.liveness_out) != len(method.instructions):
            method.build_liveness()
        if len(method.inferred_register_types) != len(method.instructions):
            method.infer_register_types(owner_class)
    except Exception:
        if not method.basic_blocks:
            method.basic_blocks = []
        if len(method.liveness_in) != len(method.instructions):
            method.liveness_in = []
        if len(method.liveness_out) != len(method.instructions):
            method.liveness_out = []
        if len(method.inferred_register_types) != len(method.instructions):
            method.inferred_register_types = []


# ---------------------------------------------------------------------------
# File-level parser  (thread-safe)
# ---------------------------------------------------------------------------

def parse_smali_file(file_path: Path, base_dir: Path | None = None) -> SmaliClass | None:
    """Parse a single .smali file into a SmaliClass object.

    Thread-safe — no shared mutable state.
    Returns None on parse failure.
    """
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None

    lines = text.splitlines()

    # Class header
    cm = _RE_CLASS.search(text)
    if not cm:
        return None

    access_str = cm.group(1).strip()
    class_name = cm.group(2)

    sm = _RE_SUPER.search(text)
    super_class = sm.group(1) if sm else ""

    interfaces = _RE_IMPLEMENTS.findall(text)

    src = _RE_SOURCE.search(text)
    source_file = src.group(1) if src else ""

    rel_path = str(file_path.relative_to(base_dir)) if base_dir else str(file_path)

    cls = SmaliClass(
        name=class_name,
        super_class=super_class,
        interfaces=interfaces,
        access_flags=set(access_str.split()) if access_str else set(),
        source_file=source_file,
        file_path=rel_path,
        abs_path=str(file_path),
        line_count=len(lines),
    )

    # Fields
    for fm in _RE_FIELD.finditer(text):
        access = fm.group(1).strip()
        fname = fm.group(2)
        ftype = fm.group(3).strip()
        fval = fm.group(4).strip() if fm.group(4) else None
        line_no = text[:fm.start()].count("\n") + 1
        cls.fields.append(SmaliField(
            name=fname,
            type=ftype,
            access_flags=set(access.split()) if access else set(),
            value=fval,
            line=line_no,
        ))

    # Class-level annotations
    cls.annotations = list(set(_RE_ANNOTATION.findall(text)))

    # Methods
    method_starts: list[int] = []
    method_ends: list[int] = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(".method"):
            method_starts.append(i)
        elif stripped == ".end method":
            method_ends.append(i)

    for ms, me in zip(method_starts, method_ends):
        method = _parse_method(lines, ms, me, class_name)
        cls.methods.append(method)

    return cls


# ---------------------------------------------------------------------------
# Build full index from smali directories (parallel)
# ---------------------------------------------------------------------------

_PARSE_POOL = ThreadPoolExecutor(max_workers=recommended_file_scan_workers())


def build_index(
    smali_dirs: Sequence[str | Path],
    progress_callback: Any | None = None,
) -> SmaliIndex:
    """Parse all smali files under *smali_dirs* and build a SmaliIndex.

    Uses a CPU-aware parallel I/O worker count for fast parsing.
    ``progress_callback(pct: float, msg: str)`` is called periodically.
    """
    index = SmaliIndex()

    # Collect file tasks
    file_tasks: list[tuple[Path, Path]] = []
    for sd in smali_dirs:
        sd = Path(sd)
        if not sd.is_dir():
            continue
        for root, _dirs, files in os.walk(sd):
            for fname in files:
                if fname.endswith(".smali"):
                    file_tasks.append((Path(root) / fname, sd))

    total = len(file_tasks)
    if total == 0:
        return index

    index.total_files = total
    done = [0]
    lock = Lock()

    def _worker(args: tuple[Path, Path]) -> SmaliClass | None:
        fpath, base = args
        return parse_smali_file(fpath, base)

    futures = {_PARSE_POOL.submit(_worker, t): t for t in file_tasks}

    for future in as_completed(futures):
        cls = future.result()
        done[0] += 1

        if progress_callback and done[0] % 100 == 0:
            pct = done[0] / total * 100
            progress_callback(pct, f"Parsing smali: {done[0]}/{total} files")

        if cls is None:
            continue

        with lock:
            _merge_class(index, cls)

    index.built_at = time.time()
    index.total_instructions = sum(
        len(m.instructions) for m in index.methods.values()
    )

    if progress_callback:
        progress_callback(100, f"Index built: {len(index.classes)} classes, "
                          f"{len(index.methods)} methods, "
                          f"{index.total_instructions} instructions")

    return index


def _merge_class(index: SmaliIndex, cls: SmaliClass) -> None:
    """Merge parsed class into the global index (call under lock)."""
    index.classes[cls.name] = cls

    # Hierarchy
    if cls.super_class:
        index.class_hierarchy[cls.super_class].append(cls.name)
    for iface in cls.interfaces:
        index.interface_implementors[iface].append(cls.name)

    # Methods and cross-refs
    for method in cls.methods:
        index.methods[method.full_signature] = method

        # String index
        for s in method.string_constants:
            index.string_index[s].append((cls.file_path, method.start_line))

        # API callers index
        for api in dict.fromkeys(method.api_calls):
            index.api_callers[api].append(method.full_signature)
            index.call_graph[method.full_signature].append(api)

        for field_ref in dict.fromkeys(
            instr.target_field for instr in method.instructions if instr.target_field
        ):
            index.field_accessors[field_ref].append(method.full_signature)


def _normalize_loaded_index(index: SmaliIndex) -> SmaliIndex:
    """Backfill newer SmaliIndex/IR fields for older persisted pickles."""
    if not hasattr(index, "classes"):
        index.classes = {}
    if not hasattr(index, "methods"):
        index.methods = {}
    if not hasattr(index, "string_index"):
        index.string_index = defaultdict(list)
    if not hasattr(index, "api_callers"):
        index.api_callers = defaultdict(list)
    if not hasattr(index, "field_accessors"):
        index.field_accessors = defaultdict(list)
    if not hasattr(index, "call_graph"):
        index.call_graph = defaultdict(list)
    if not hasattr(index, "class_hierarchy"):
        index.class_hierarchy = defaultdict(list)
    if not hasattr(index, "interface_implementors"):
        index.interface_implementors = defaultdict(list)
    if not hasattr(index, "total_files"):
        index.total_files = 0
    if not hasattr(index, "total_instructions"):
        index.total_instructions = 0
    if not hasattr(index, "built_at"):
        index.built_at = 0.0

    for cls in index.classes.values():
        if not hasattr(cls, "fields"):
            cls.fields = []
        if not hasattr(cls, "methods"):
            cls.methods = []
        for method in cls.methods:
            if not hasattr(method, "basic_blocks"):
                method.basic_blocks = []
            if not hasattr(method, "liveness_in"):
                method.liveness_in = []
            if not hasattr(method, "liveness_out"):
                method.liveness_out = []
            if not hasattr(method, "inferred_register_types"):
                method.inferred_register_types = []
            if not hasattr(method, "instructions"):
                method.instructions = []
            for instr in method.instructions:
                if not hasattr(instr, "target_return_type"):
                    instr.target_return_type = ""
                if not hasattr(instr, "target_field_type"):
                    instr.target_field_type = ""
            _ensure_method_analysis(method, cls.name)

    _rebuild_auxiliary_indices(index)
    return index


def _rebuild_auxiliary_indices(index: SmaliIndex) -> None:
    """Recompute derived indices from the loaded class/method graph."""
    classes = getattr(index, "classes", {}) or {}
    index.methods = {}
    index.string_index = defaultdict(list)
    index.api_callers = defaultdict(list)
    index.field_accessors = defaultdict(list)
    index.call_graph = defaultdict(list)
    index.class_hierarchy = defaultdict(list)
    index.interface_implementors = defaultdict(list)

    total_instructions = 0
    for cls in classes.values():
        if cls.super_class:
            index.class_hierarchy[cls.super_class].append(cls.name)
        for iface in cls.interfaces:
            index.interface_implementors[iface].append(cls.name)

        for method in cls.methods:
            index.methods[method.full_signature] = method
            total_instructions += len(method.instructions)

            for string_value in method.string_constants:
                index.string_index[string_value].append((cls.file_path, method.start_line))

            for api in dict.fromkeys(method.api_calls):
                index.api_callers[api].append(method.full_signature)
                index.call_graph[method.full_signature].append(api)

            for field_ref in dict.fromkeys(
                instr.target_field for instr in method.instructions if instr.target_field
            ):
                index.field_accessors[field_ref].append(method.full_signature)

    index.total_files = len(classes)
    index.total_instructions = total_instructions


def _class_package(class_name: str) -> str:
    cleaned = class_name[1:-1] if class_name.startswith("L") and class_name.endswith(";") else class_name
    if "/" not in cleaned:
        return ""
    return cleaned.rsplit("/", 1)[0].replace("/", ".")


def _class_simple_name(class_name: str) -> str:
    cleaned = class_name[1:-1] if class_name.startswith("L") and class_name.endswith(";") else class_name
    return cleaned.rsplit("/", 1)[-1].rsplit("$", 1)[-1]


def _looks_obfuscated_token(token: str, *, allow_special: bool = False) -> bool:
    if not token:
        return False
    if not allow_special and token in {"<init>", "<clinit>"}:
        return False
    cleaned = re.sub(r"[^A-Za-z0-9]", "", token)
    if not cleaned:
        return False
    return len(cleaned) <= 2 or bool(re.fullmatch(r"[a-z]{1,3}\d?", cleaned))


def _scan_native_files(apktool_dir: str | Path | None) -> tuple[list[str], list[str]]:
    if not apktool_dir:
        return [], []
    apk_root = Path(apktool_dir)
    lib_dir = apk_root / "lib"
    if not lib_dir.is_dir():
        return [], []

    libs: list[str] = []
    abis: set[str] = set()
    for so_file in sorted(lib_dir.rglob("*.so")):
        try:
            libs.append(str(so_file.relative_to(apk_root)).replace("\\", "/"))
        except ValueError:
            libs.append(str(so_file))
        if so_file.parent != lib_dir:
            abis.add(so_file.parent.name)
    return libs, sorted(abis)


def _resolve_load_library_name(method: SmaliMethod, invoke_idx: int) -> str:
    instr = method.instructions[invoke_idx]
    if not instr.registers:
        return ""
    target_reg = instr.registers[0]
    for prev_idx in range(invoke_idx - 1, -1, -1):
        prev_instr = method.instructions[prev_idx]
        reads, writes = _instruction_reads_writes(prev_instr)
        if target_reg not in writes:
            continue
        if prev_instr.string_value is not None:
            return prev_instr.string_value
        break
    return ""


def _build_native_summary(index: SmaliIndex, apktool_dir: str | Path | None = None) -> dict[str, Any]:
    declared_native_methods = sorted(
        method.full_signature
        for method in index.methods.values()
        if "native" in method.access_flags
    )
    load_library_calls: list[dict[str, str]] = []
    load_library_names: set[str] = set()
    for method in index.methods.values():
        for idx, instr in enumerate(method.instructions):
            if not instr.is_invoke:
                continue
            if instr.target_class not in {"Ljava/lang/System;", "Ljava/lang/Runtime;"}:
                continue
            if instr.target_method not in {"loadLibrary", "load"}:
                continue
            library_name = _resolve_load_library_name(method, idx)
            if library_name:
                load_library_names.add(library_name)
            load_library_calls.append({
                "caller": method.full_signature,
                "kind": instr.target_method,
                "library": library_name,
            })

    native_libraries, native_abis = _scan_native_files(apktool_dir)
    return {
        "declared_native_method_count": len(declared_native_methods),
        "declared_native_methods": declared_native_methods[:40],
        "load_library_call_count": len(load_library_calls),
        "load_library_calls": load_library_calls[:30],
        "load_library_names": sorted(load_library_names),
        "native_library_count": len(native_libraries),
        "native_libraries": native_libraries[:50],
        "native_abis": native_abis,
    }


def _collect_framework_hints(index: SmaliIndex, native_summary: dict[str, Any]) -> list[str]:
    blobs: list[str] = []
    for cls in index.classes.values():
        blobs.append(" ".join([
            cls.name,
            cls.super_class,
            " ".join(cls.interfaces),
            cls.source_file,
        ]).lower())
        for method in cls.methods[:80]:
            blobs.append(" ".join([
                method.full_signature,
                method.category,
                " ".join(method.api_calls[:40]),
                " ".join(method.string_constants[:20]),
            ]).lower())

    for lib_name in native_summary.get("native_libraries", []):
        blobs.append(str(lib_name).lower())
    for load_name in native_summary.get("load_library_names", []):
        blobs.append(str(load_name).lower())

    combined = "\n".join(blobs)
    hints: list[str] = []
    for framework, tokens in _FRAMEWORK_HINTS.items():
        if any(token in combined for token in tokens):
            hints.append(framework)
    return sorted(hints)


def _build_obfuscation_summary(index: SmaliIndex) -> dict[str, Any]:
    class_tokens = [_class_simple_name(cls.name) for cls in index.classes.values()]
    method_tokens = [method.name for method in index.methods.values()]
    field_tokens = [field.name for cls in index.classes.values() for field in cls.fields]

    obfuscated_classes = [token for token in class_tokens if _looks_obfuscated_token(token, allow_special=True)]
    obfuscated_methods = [token for token in method_tokens if _looks_obfuscated_token(token)]
    obfuscated_fields = [token for token in field_tokens if _looks_obfuscated_token(token, allow_special=True)]

    total_symbols = len(class_tokens) + len(method_tokens) + len(field_tokens)
    obfuscated_symbols = len(obfuscated_classes) + len(obfuscated_methods) + len(obfuscated_fields)
    obfuscated_pct = int(obfuscated_symbols / max(total_symbols, 1) * 100)

    level = "none"
    if obfuscated_pct >= 50:
        level = "heavy"
    elif obfuscated_pct >= 20:
        level = "moderate"
    elif obfuscated_pct >= 5:
        level = "light"

    return {
        "level": level,
        "obfuscated_symbol_pct": obfuscated_pct,
        "obfuscated_classes": len(obfuscated_classes),
        "obfuscated_methods": len(obfuscated_methods),
        "obfuscated_fields": len(obfuscated_fields),
    }


def _build_semantic_summary(index: SmaliIndex, apktool_dir: str | Path | None = None) -> dict[str, Any]:
    native_summary = _build_native_summary(index, apktool_dir=apktool_dir)
    framework_hints = _collect_framework_hints(index, native_summary)
    obfuscation_summary = _build_obfuscation_summary(index)

    package_counts = Counter(
        package for package in (_class_package(class_name) for class_name in index.classes) if package
    )
    total_fields = sum(len(cls.fields) for cls in index.classes.values())
    call_edge_count = sum(len(dict.fromkeys(callees)) for callees in index.call_graph.values())
    field_access_edge_count = sum(len(dict.fromkeys(accessors)) for accessors in index.field_accessors.values())

    return {
        "total_fields": total_fields,
        "total_call_graph_edges": call_edge_count,
        "total_field_access_edges": field_access_edge_count,
        "top_packages": [
            {"package": package, "class_count": count}
            for package, count in package_counts.most_common(12)
        ],
        "framework_hints": framework_hints,
        "native_summary": native_summary,
        "obfuscation_summary": obfuscation_summary,
    }


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_index(index: SmaliIndex, output_path: str | Path) -> dict:
    """Persist index to a pickle file."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output_path.with_suffix(output_path.suffix + ".tmp")
    try:
        with open(temp_path, "wb") as f:
            pickle.dump(index, f, protocol=pickle.HIGHEST_PROTOCOL)
        temp_path.replace(output_path)
    except MemoryError:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
        return {
            "success": False,
            "path": str(output_path),
            "error_type": "MemoryError",
            "error": "SmaliIndex is too large to serialize with pickle in the current process memory budget.",
            "recovery_hint": "Index remains available in the current session, but it was not persisted to disk.",
            "classes": len(index.classes),
            "methods": len(index.methods),
            "strings": len(index.string_index),
        }
    size_kb = output_path.stat().st_size / 1024
    return {
        "success": True,
        "path": str(output_path),
        "size_kb": round(size_kb, 1),
        "classes": len(index.classes),
        "methods": len(index.methods),
        "strings": len(index.string_index),
    }


def load_index(index_path: str | Path) -> SmaliIndex | None:
    """Load index from pickle. Returns None if not found."""
    p = Path(index_path)
    if not p.is_file():
        return None
    try:
        with open(p, "rb") as f:
            loaded = pickle.load(f)
            if isinstance(loaded, SmaliIndex):
                return _normalize_loaded_index(loaded)
            return None
    except Exception:
        return None


def index_stats(index: SmaliIndex, *, apktool_dir: str | Path | None = None) -> dict:
    """Return a human-readable stats summary of the index."""
    index = _normalize_loaded_index(index)
    categories: dict[str, int] = defaultdict(int)
    for m in index.methods.values():
        categories[m.category] += 1

    semantic_summary = _build_semantic_summary(index, apktool_dir=apktool_dir)

    return {
        "total_classes": len(index.classes),
        "total_methods": len(index.methods),
        "total_instructions": index.total_instructions,
        "total_fields": semantic_summary["total_fields"],
        "total_strings": len(index.string_index),
        "total_api_targets": len(index.api_callers),
        "total_call_graph_edges": semantic_summary["total_call_graph_edges"],
        "total_field_access_edges": semantic_summary["total_field_access_edges"],
        "method_categories": dict(sorted(categories.items(), key=lambda x: -x[1])),
        "hierarchy_roots": sum(1 for v in index.class_hierarchy.values() if v),
        "framework_hints": semantic_summary["framework_hints"],
        "native_summary": semantic_summary["native_summary"],
        "obfuscation_summary": semantic_summary["obfuscation_summary"],
        "semantic_summary": semantic_summary,
        "built_at": index.built_at,
    }
