"""Data Flow Analysis — intra-method register tracking + inter-procedural taint.

Phase 2 (P2): Intra-method register data flow
  - For each instruction, track what each register "contains"
  - Detects: hardcoded keys, static IVs, predictable seeds, leaked creds

Phase 5 (P5): Inter-procedural taint analysis
  - Define taint sources (user input, device IDs, credentials)
  - Define taint sinks (logs, network, IPC, storage)
  - Trace taint propagation across method boundaries via SmaliIndex call graph

Operates entirely on the SmaliIndex IR — no file I/O.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apk_agent.tools.smali_ir import SmaliIndex, SmaliMethod, SmaliInstruction, SmaliClass


# ---------------------------------------------------------------------------
# Register state model
# ---------------------------------------------------------------------------

@dataclass
class RegisterValue:
    """What we know about a register's contents at a point in execution."""
    kind: str = "unknown"    # string, const, field, param, return, new_instance, array, unknown
    value: str | None = None # actual value if known (e.g. string literal, numeric const)
    type_desc: str = ""      # smali type descriptor (Ljava/lang/String;)
    source_line: int = 0     # where the value was assigned
    taint: set[str] = field(default_factory=set)  # taint labels (e.g. {"CREDENTIAL", "DEVICE_ID"})
    is_hardcoded: bool = False  # came from a const-string / const


# ---------------------------------------------------------------------------
# Intra-method data flow analysis (P2)
# ---------------------------------------------------------------------------

def analyze_method_flow(method: "SmaliMethod") -> dict:
    """Track register values through a method's instructions.

    Returns a dict with:
      - register_states: final state of each register
      - sensitive_flows: API calls with resolved register origins
      - hardcoded_into_crypto: cases where const values flow into crypto APIs
      - data_flow_summary: human-readable summary
    """
    regs: dict[str, RegisterValue] = {}
    sensitive_flows: list[dict] = []
    hardcoded_crypto: list[dict] = []
    last_invoke_target: str = ""

    for instr in method.instructions:
        opcode = instr.opcode

        # --- const-string vN, "value" ---
        if instr.string_value is not None and instr.registers:
            reg = instr.registers[0]
            regs[reg] = RegisterValue(
                kind="string",
                value=instr.string_value,
                type_desc="Ljava/lang/String;",
                source_line=instr.line,
                is_hardcoded=True,
            )

        # --- const vN, 0xNN ---
        elif instr.is_const and instr.const_value is not None and instr.registers:
            reg = instr.registers[0]
            regs[reg] = RegisterValue(
                kind="const",
                value=instr.const_value,
                source_line=instr.line,
                is_hardcoded=True,
            )

        # --- sget/iget vN, Class;->field ---
        elif instr.is_field_access and instr.registers:
            reg = instr.registers[0]
            is_get = opcode.startswith(("sget", "iget"))
            if is_get:
                regs[reg] = RegisterValue(
                    kind="field",
                    value=instr.target_field,
                    source_line=instr.line,
                )

        # --- new-instance vN, Ltype; ---
        elif opcode == "new-instance" and instr.registers:
            reg = instr.registers[0]
            type_match = re.search(r"(L[\w/$]+;)", instr.raw)
            type_desc = type_match.group(1) if type_match else ""
            regs[reg] = RegisterValue(
                kind="new_instance",
                type_desc=type_desc,
                source_line=instr.line,
            )

        # --- move-result vN ---
        elif instr.is_move and "result" in opcode and instr.registers:
            reg = instr.registers[0]
            regs[reg] = RegisterValue(
                kind="return",
                value=last_invoke_target,
                source_line=instr.line,
            )

        # --- move vDst, vSrc ---
        elif instr.is_move and len(instr.registers) >= 2:
            dst, src = instr.registers[0], instr.registers[1]
            if src in regs:
                regs[dst] = RegisterValue(
                    kind=regs[src].kind,
                    value=regs[src].value,
                    type_desc=regs[src].type_desc,
                    source_line=instr.line,
                    taint=set(regs[src].taint),
                    is_hardcoded=regs[src].is_hardcoded,
                )

        # --- invoke-* ---
        elif instr.is_invoke:
            target = f"{instr.target_class}->{instr.target_method}"
            last_invoke_target = target

            # Resolve register values for this call
            call_regs = {}
            for r in instr.registers:
                if r in regs:
                    rv = regs[r]
                    call_regs[r] = {
                        "kind": rv.kind,
                        "value": rv.value,
                        "hardcoded": rv.is_hardcoded,
                        "line": rv.source_line,
                    }

            # Check if sensitive API
            if _is_sensitive_api(target):
                sensitive_flows.append({
                    "api": target,
                    "line": instr.line,
                    "registers": call_regs,
                    "raw": instr.raw[:200],
                })

            # Check hardcoded value flowing into crypto
            if _is_crypto_api(target):
                hardcoded_args = {
                    r: info for r, info in call_regs.items()
                    if info.get("hardcoded")
                }
                if hardcoded_args:
                    hardcoded_crypto.append({
                        "api": target,
                        "line": instr.line,
                        "hardcoded_args": hardcoded_args,
                    })

            # Apply taint from sources
            taint_label = _get_taint_source(target)
            if taint_label:
                # The result register will carry this taint
                # (handled in move-result above, but we mark it here)
                for r in instr.registers:
                    if r in regs:
                        regs[r].taint.add(taint_label)

    # Build summary
    summary_parts = []
    if hardcoded_crypto:
        summary_parts.append(f"{len(hardcoded_crypto)} hardcoded values flowing into crypto APIs")
    if sensitive_flows:
        summary_parts.append(f"{len(sensitive_flows)} sensitive API calls with resolved data")

    return {
        "method": method.full_signature,
        "register_count": len(regs),
        "sensitive_flows": sensitive_flows,
        "hardcoded_into_crypto": hardcoded_crypto,
        "data_flow_summary": "; ".join(summary_parts) if summary_parts else "No notable data flows",
    }


# ---------------------------------------------------------------------------
# Inter-procedural taint analysis (P5)
# ---------------------------------------------------------------------------

# Taint sources — methods that produce sensitive data
TAINT_SOURCES: dict[str, str] = {
    # Device identifiers
    "Landroid/telephony/TelephonyManager;->getDeviceId": "DEVICE_ID",
    "Landroid/telephony/TelephonyManager;->getImei": "DEVICE_ID",
    "Landroid/telephony/TelephonyManager;->getSubscriberId": "DEVICE_ID",
    "Landroid/telephony/TelephonyManager;->getLine1Number": "PHONE_NUMBER",
    "Landroid/provider/Settings$Secure;->getString": "ANDROID_ID",
    # Location
    "Landroid/location/LocationManager;->getLastKnownLocation": "LOCATION",
    "Landroid/location/Location;->getLatitude": "LOCATION",
    "Landroid/location/Location;->getLongitude": "LOCATION",
    # Credentials / input
    "Landroid/widget/EditText;->getText": "USER_INPUT",
    "Landroid/content/Intent;->getStringExtra": "EXTERNAL_INPUT",
    "Landroid/content/Intent;->getParcelableExtra": "EXTERNAL_INPUT",
    "Landroid/content/Intent;->getData": "EXTERNAL_INPUT",
    # Storage reads
    "Landroid/content/SharedPreferences;->getString": "STORED_DATA",
    "Landroid/database/Cursor;->getString": "DATABASE",
    # Clipboard
    "Landroid/content/ClipboardManager;->getPrimaryClip": "CLIPBOARD",
    # Account
    "Landroid/accounts/AccountManager;->getPassword": "CREDENTIAL",
    "Landroid/accounts/AccountManager;->peekAuthToken": "AUTH_TOKEN",
}

# Taint sinks — methods where sensitive data should NOT end up
TAINT_SINKS: dict[str, str] = {
    # Logging
    "Landroid/util/Log;->d": "LOG",
    "Landroid/util/Log;->v": "LOG",
    "Landroid/util/Log;->i": "LOG",
    "Landroid/util/Log;->w": "LOG",
    "Landroid/util/Log;->e": "LOG",
    "Ljava/io/PrintStream;->println": "LOG",
    # Network
    "Ljava/net/HttpURLConnection;->getOutputStream": "NETWORK",
    "Lokhttp3/Request$Builder;->post": "NETWORK",
    "Lokhttp3/RequestBody;->create": "NETWORK",
    # IPC
    "Landroid/content/Context;->sendBroadcast": "BROADCAST",
    "Landroid/content/Context;->startActivity": "IPC",
    "Landroid/content/Context;->startService": "IPC",
    # Storage (unencrypted)
    "Landroid/content/SharedPreferences$Editor;->putString": "UNENCRYPTED_STORAGE",
    "Landroid/database/sqlite/SQLiteDatabase;->execSQL": "DATABASE_WRITE",
    "Landroid/database/sqlite/SQLiteDatabase;->rawQuery": "DATABASE_QUERY",
    # SMS
    "Landroid/telephony/SmsManager;->sendTextMessage": "SMS",
    # WebView
    "Landroid/webkit/WebView;->loadUrl": "WEBVIEW",
    "Landroid/webkit/WebView;->evaluateJavascript": "WEBVIEW",
}


@dataclass
class TaintFlow:
    """A detected source → sink taint flow."""
    source_api: str
    source_taint: str           # e.g. "CREDENTIAL"
    sink_api: str
    sink_type: str              # e.g. "LOG"
    source_method: str          # full sig of method containing source
    sink_method: str            # full sig of method containing sink
    source_file: str
    source_line: int
    sink_file: str
    sink_line: int
    path_length: int            # number of hops from source to sink
    severity: str               # computed from source+sink combo


def run_taint_analysis(index: "SmaliIndex", max_depth: int = 5,
                       max_flows: int = 200) -> dict:
    """Run inter-procedural taint analysis across the SmaliIndex.

    1. Find all methods that call taint sources
    2. Propagate taint forward through method return values
    3. Check if tainted data reaches any sink

    Uses BFS on the call graph (api_callers index) to propagate.
    """
    flows: list[TaintFlow] = []

    # Step 1: Find source invocations and their containing methods
    source_methods: list[tuple[str, str, str, int]] = []  # (method_sig, taint_label, file, line)

    for source_api, taint_label in TAINT_SOURCES.items():
        # Find callers of this source API
        callers = index.find_api_callers(source_api)
        for caller_sig in callers:
            method = index.get_method(caller_sig)
            if method is None:
                continue
            cls = _get_class_for_method(index, caller_sig)
            file_path = cls.file_path if cls else ""
            # Find the exact line
            line = 0
            for instr in method.instructions:
                if instr.is_invoke and source_api in instr.raw:
                    line = instr.line
                    break
            source_methods.append((caller_sig, taint_label, file_path, line))

    # Step 2: For each source, BFS forward to find sinks
    for src_sig, taint_label, src_file, src_line in source_methods:
        _bfs_taint_forward(
            index, src_sig, taint_label, src_file, src_line,
            max_depth, flows, max_flows - len(flows),
        )
        if len(flows) >= max_flows:
            break

    # Deduplicate and sort
    seen = set()
    unique_flows: list[TaintFlow] = []
    for f in flows:
        key = f"{f.source_taint}|{f.sink_type}|{f.source_method}|{f.sink_method}"
        if key not in seen:
            seen.add(key)
            unique_flows.append(f)

    unique_flows.sort(key=lambda f: _severity_order(f.severity), reverse=True)

    # Summary
    taint_types: dict[str, int] = defaultdict(int)
    sink_types: dict[str, int] = defaultdict(int)
    for f in unique_flows:
        taint_types[f.source_taint] += 1
        sink_types[f.sink_type] += 1

    return {
        "success": True,
        "total_flows": len(unique_flows),
        "taint_sources_found": len(source_methods),
        "taint_type_summary": dict(sorted(taint_types.items(), key=lambda x: -x[1])),
        "sink_type_summary": dict(sorted(sink_types.items(), key=lambda x: -x[1])),
        "flows": [_flow_to_dict(f) for f in unique_flows[:max_flows]],
    }


def _bfs_taint_forward(
    index: "SmaliIndex",
    start_sig: str,
    taint_label: str,
    src_file: str,
    src_line: int,
    max_depth: int,
    flows: list[TaintFlow],
    budget: int,
) -> None:
    """BFS from a taint source method to find reachable sinks."""
    if budget <= 0:
        return

    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque()  # (method_sig, depth)
    queue.append((start_sig, 0))
    found = 0

    while queue and found < budget:
        current_sig, depth = queue.popleft()
        if current_sig in visited or depth > max_depth:
            continue
        visited.add(current_sig)

        method = index.get_method(current_sig)
        if method is None:
            continue
        cls = _get_class_for_method(index, current_sig)

        # Check if this method calls any sink
        for instr in method.instructions:
            if not instr.is_invoke:
                continue
            target = f"{instr.target_class}->{instr.target_method}"
            sink_type = _get_taint_sink(target)
            if sink_type:
                severity = _compute_taint_severity(taint_label, sink_type)
                flows.append(TaintFlow(
                    source_api=taint_label,
                    source_taint=taint_label,
                    sink_api=target,
                    sink_type=sink_type,
                    source_method=start_sig,
                    sink_method=current_sig,
                    source_file=src_file,
                    source_line=src_line,
                    sink_file=cls.file_path if cls else "",
                    sink_line=instr.line,
                    path_length=depth,
                    severity=severity,
                ))
                found += 1

        # Follow callers of this method (who calls the method that has the taint?)
        # Actually, follow the CALLEES — taint flows FORWARD
        for api_call in method.api_calls:
            # Find methods that are called by this method
            # and propagate taint into them
            callers_of_api = index.find_api_callers(api_call)
            # But we actually want: what does *this* method call?
            # The api_calls list gives us what this method invokes
            # We need to find the actual body of those callees
            callee_method = index.get_method(api_call)
            if callee_method and api_call not in visited:
                queue.append((api_call, depth + 1))

        # Also: methods that call *this* method get the taint propagated
        # (return value carries taint)
        callers = index.api_callers.get(current_sig.split("(")[0], [])
        # We DON'T propagate to callers — taint flows forward only


def _get_class_for_method(index: "SmaliIndex", method_sig: str) -> "SmaliClass | None":
    """Extract class name from method sig and look it up."""
    if "->" in method_sig:
        class_name = method_sig.split("->")[0]
        return index.get_class(class_name)
    return None


# ---------------------------------------------------------------------------
# Helper: classify APIs
# ---------------------------------------------------------------------------

_SENSITIVE_APIS = re.compile(
    r"Ljavax/crypto/|Ljavax/net/ssl/|Ljava/security/|"
    r"SecretKeySpec|IvParameterSpec|Cipher;->|MessageDigest;->|"
    r"Landroid/util/Log;->|Landroid/webkit/WebView;->|"
    r"SharedPreferences|SQLiteDatabase|Runtime;->exec|"
    r"ProcessBuilder|sendBroadcast|startActivity|"
    r"TrustManager|HostnameVerifier|loadLibrary",
    re.IGNORECASE,
)

_CRYPTO_APIS = re.compile(
    r"Ljavax/crypto/|SecretKeySpec|IvParameterSpec|Cipher;->|"
    r"MessageDigest;->|KeyGenerator;->|Mac;->|Signature;->|"
    r"KeyStore;->|SecureRandom",
    re.IGNORECASE,
)


def _is_sensitive_api(target: str) -> bool:
    return bool(_SENSITIVE_APIS.search(target))


def _is_crypto_api(target: str) -> bool:
    return bool(_CRYPTO_APIS.search(target))


def _get_taint_source(target: str) -> str | None:
    """Check if an API call is a taint source."""
    for api, label in TAINT_SOURCES.items():
        if api in target:
            return label
    return None


def _get_taint_sink(target: str) -> str | None:
    """Check if an API call is a taint sink."""
    for api, sink_type in TAINT_SINKS.items():
        if api in target:
            return sink_type
    return None


# Severity matrix: source_type × sink_type → severity
_SEVERITY_MATRIX: dict[tuple[str, str], str] = {
    ("CREDENTIAL", "LOG"): "CRITICAL",
    ("CREDENTIAL", "NETWORK"): "HIGH",
    ("CREDENTIAL", "UNENCRYPTED_STORAGE"): "CRITICAL",
    ("CREDENTIAL", "SMS"): "CRITICAL",
    ("AUTH_TOKEN", "LOG"): "CRITICAL",
    ("AUTH_TOKEN", "UNENCRYPTED_STORAGE"): "CRITICAL",
    ("DEVICE_ID", "LOG"): "MEDIUM",
    ("DEVICE_ID", "NETWORK"): "LOW",
    ("PHONE_NUMBER", "LOG"): "HIGH",
    ("PHONE_NUMBER", "NETWORK"): "MEDIUM",
    ("LOCATION", "LOG"): "HIGH",
    ("LOCATION", "NETWORK"): "MEDIUM",
    ("USER_INPUT", "DATABASE_QUERY"): "HIGH",  # SQL injection
    ("USER_INPUT", "WEBVIEW"): "HIGH",          # XSS
    ("EXTERNAL_INPUT", "DATABASE_QUERY"): "CRITICAL",  # SQL injection via intent
    ("EXTERNAL_INPUT", "WEBVIEW"): "HIGH",
    ("EXTERNAL_INPUT", "IPC"): "HIGH",          # intent redirection
    ("STORED_DATA", "LOG"): "MEDIUM",
    ("CLIPBOARD", "LOG"): "LOW",
    ("CLIPBOARD", "NETWORK"): "MEDIUM",
}


def _compute_taint_severity(source_type: str, sink_type: str) -> str:
    """Compute severity based on what data went where."""
    return _SEVERITY_MATRIX.get((source_type, sink_type), "MEDIUM")


def _severity_order(sev: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(sev, 0)


def _flow_to_dict(f: TaintFlow) -> dict:
    return {
        "source_taint": f.source_taint,
        "sink_type": f.sink_type,
        "severity": f.severity,
        "source_method": f.source_method,
        "sink_method": f.sink_method,
        "source_file": f.source_file,
        "source_line": f.source_line,
        "sink_file": f.sink_file,
        "sink_line": f.sink_line,
        "path_length": f.path_length,
        "description": f"Tainted data ({f.source_taint}) from {f.source_api} "
                       f"flows to {f.sink_type} sink at {f.sink_api}",
    }


# ---------------------------------------------------------------------------
# Convenience: analyze all crypto methods for hardcoded keys
# ---------------------------------------------------------------------------

def find_hardcoded_crypto(index: "SmaliIndex") -> dict:
    """Scan all crypto-category methods for hardcoded key/IV values.

    Uses data flow to distinguish:
      - SecretKeySpec with const-string "mysecret" → CRITICAL
      - SecretKeySpec with value from KeyStore → OK
      - IvParameterSpec with const byte array → HIGH
      - IvParameterSpec with SecureRandom → OK
    """
    findings: list[dict] = []

    crypto_methods = index.methods_by_category("crypto")
    for method in crypto_methods:
        flow = analyze_method_flow(method)
        if flow["hardcoded_into_crypto"]:
            cls = _get_class_for_method(index, method.full_signature)
            findings.append({
                "method": method.full_signature,
                "file": cls.file_path if cls else "",
                "start_line": method.start_line,
                "hardcoded_crypto_calls": flow["hardcoded_into_crypto"],
                "all_sensitive_flows": flow["sensitive_flows"][:5],
            })

    return {
        "success": True,
        "total_crypto_methods": len(crypto_methods),
        "methods_with_hardcoded": len(findings),
        "findings": findings[:100],
    }
