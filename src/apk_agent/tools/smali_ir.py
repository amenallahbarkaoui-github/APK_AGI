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
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from threading import Lock
from typing import Any

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
    target_field: str = ""              # for *get/*put: field ref
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

        sorted_leaders = sorted(leaders)
        leader_to_block: dict[int, int] = {}

        blocks: list[BasicBlock] = []
        for bid, start in enumerate(sorted_leaders):
            end = (sorted_leaders[bid + 1] - 1) if bid + 1 < len(sorted_leaders) else len(self.instructions) - 1
            bb = BasicBlock(id=bid, start_idx=start, end_idx=end,
                            is_entry=(bid == 0))
            blocks.append(bb)
            leader_to_block[start] = bid

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

        self.basic_blocks = blocks
        return blocks


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
_RE_CONST_STRING = re.compile(r'const-string(?:/jumbo)?\s+(\w+),\s*"((?:[^"\\]|\\.)*)"')
_RE_CONST_NUM = re.compile(r"const(?:/4|/16|/high16)?\s+(\w+),\s*(.*?)$")
_RE_REGISTER = re.compile(r"\b([vp]\d+)\b")
_RE_TRY_CATCH = re.compile(
    r"\.catch\s+(L[\w/$]+;|\.\.\.)\s+\{(\S+)\s+\.\.\s+(\S+)\}\s+(\S+)"
)
_RE_CATCHALL = re.compile(
    r"\.catchall\s+\{(\S+)\s+\.\.\s+(\S+)\}\s+(\S+)"
)

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
    registers = _RE_REGISTER.findall(stripped)

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
        m = _RE_INVOKE.search(stripped)
        if m:
            instr.target_class = m.group(1)
            instr.target_method = m.group(2)

    # Extract field ref for *get/*put
    if instr.is_field_access:
        m = re.search(r"(L[\w/$]+;)->([\w$]+):", stripped)
        if m:
            instr.target_field = f"{m.group(1)}->{m.group(2)}"

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
    smali_dirs: list[str | Path],
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
        for api in method.api_calls:
            index.api_callers[api].append(method.full_signature)


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
            return pickle.load(f)
    except Exception:
        return None


def index_stats(index: SmaliIndex) -> dict:
    """Return a human-readable stats summary of the index."""
    categories: dict[str, int] = defaultdict(int)
    for m in index.methods.values():
        categories[m.category] += 1

    return {
        "total_classes": len(index.classes),
        "total_methods": len(index.methods),
        "total_instructions": index.total_instructions,
        "total_strings": len(index.string_index),
        "total_api_targets": len(index.api_callers),
        "method_categories": dict(sorted(categories.items(), key=lambda x: -x[1])),
        "hierarchy_roots": sum(1 for v in index.class_hierarchy.values() if v),
        "built_at": index.built_at,
    }
