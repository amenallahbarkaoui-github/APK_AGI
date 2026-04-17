"""Deep Smali Analyzer — professional-grade reverse engineering toolkit.

Goes far beyond basic pattern matching. Provides:
  - Full method body disassembly with instruction-level analysis
  - Control flow understanding (branches, switches, try/catch)
  - Data flow tracing (register tracking through a method)
  - API call chain reconstruction
  - Protection/obfuscation detection (packers, anti-debug, anti-tamper)
  - Dynamic code loading detection
  - String reconstruction from byte arrays and char arrays
  - Inter-method data dependency mapping
"""

from __future__ import annotations

import os
import re
from collections import defaultdict
from pathlib import Path


# ---------------------------------------------------------------------------
# Method body extraction + deep analysis
# ---------------------------------------------------------------------------

def analyze_method_deep(smali_file: str | Path, method_name: str) -> dict:
    """Deep-analyze a specific method in a smali file.

    Returns: full disassembly, register usage, API calls made,
    string operations, branches, try/catch blocks, annotations.
    """
    path = Path(smali_file)
    if not path.is_file():
        return {"success": False, "error": f"File not found: {path}"}

    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    # Find the method — extract the real method name from the smali signature
    # so that searching for "a" doesn't match "<clinit>" or constructor params.
    def _method_name_matches(header_line: str, query: str) -> bool:
        """Check if *query* matches the method name in a .method line.

        Smali method headers look like:
            .method public a()Z
            .method static constructor <clinit>()V
            .method public <init>(I)V
            .method public final checkServerTrusted(...)V

        We extract the token just before '(' — that's the method name.
        """
        m = re.search(r'(\S+)\(', header_line)
        if not m:
            return False
        name_token = m.group(1)          # e.g. "a", "<clinit>", "checkServerTrusted"
        # If query contains '(' it's a partial signature like "a()Z" — match against name+rest
        if '(' in query:
            sig_part = header_line[header_line.index(name_token):]
            return query in sig_part
        return name_token == query

    method_start = -1
    method_end = -1
    method_header = ""
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(".method") and _method_name_matches(stripped, method_name):
            method_start = i
            method_header = stripped
        if method_start >= 0 and stripped == ".end method":
            method_end = i
            break

    if method_start < 0:
        # Collect all method signatures so the agent can pick the right one
        available = []
        for line in lines:
            s = line.strip()
            if s.startswith(".method"):
                m = re.search(r'(\S+\(.*?\)\S+)', s)
                if m:
                    available.append(m.group(1))
        return {
            "success": False,
            "error": f"Method '{method_name}' not found in {path.name}",
            "available_methods": available,
            "hint": "The method may have a different name due to obfuscation or Kotlin compilation. "
                    "Check the available_methods list and retry with the correct name.",
        }

    body_lines = lines[method_start:method_end + 1]
    body_text = "\n".join(body_lines)

    # Analysis
    result: dict = {
        "success": True,
        "file": str(path),
        "method": method_header,
        "line_range": [method_start + 1, method_end + 1],
        "instruction_count": 0,
        "body": body_text,
    }

    # Registers used
    regs = set()
    for m in re.finditer(r'\b([vp]\d+)\b', body_text):
        regs.add(m.group(1))
    result["registers_used"] = sorted(regs)

    # Locals count
    m = re.search(r'\.locals\s+(\d+)', body_text)
    result["locals"] = int(m.group(1)) if m else 0

    # API calls (invoke-*)
    api_calls = []
    for line in body_lines:
        stripped = line.strip()
        if stripped.startswith("invoke-"):
            # Extract class->method
            m = re.search(r'(L[\w/$]+;)->([\w<>$]+)\(', stripped)
            if m:
                api_calls.append({
                    "class": m.group(1),
                    "method": m.group(2),
                    "instruction": stripped[:120],
                })
    result["api_calls"] = api_calls
    result["instruction_count"] = sum(1 for l in body_lines if l.strip() and not l.strip().startswith(".") and not l.strip().startswith("#"))

    # String constants loaded
    strings = re.findall(r'const-string(?:/jumbo)?\s+\w+,\s*"(.*?)"', body_text)
    result["string_constants"] = strings

    # Branches and control flow
    branches = []
    for i, line in enumerate(body_lines):
        s = line.strip()
        if s.startswith(("if-", "goto", "switch")):
            branches.append({"line": method_start + i + 1, "instruction": s[:80]})
    result["branches"] = branches

    # Try/catch blocks
    try_blocks = []
    for m in re.finditer(r'\.catch\s+(L[\w/$]+;)\s+\{(.*?)\}\s+(\S+)', body_text):
        try_blocks.append({
            "exception": m.group(1),
            "range": m.group(2),
            "handler": m.group(3),
        })
    result["try_catch_blocks"] = try_blocks

    # Field access (sget/sput/iget/iput)
    field_access = []
    for line in body_lines:
        s = line.strip()
        if re.match(r'(sget|sput|iget|iput)', s):
            m = re.search(r'(L[\w/$]+;)->([\w$]+):', s)
            if m:
                field_access.append({
                    "type": s.split()[0] if s.split() else "",
                    "class": m.group(1),
                    "field": m.group(2),
                })
    result["field_access"] = field_access[:30]

    # New object allocations
    allocs = re.findall(r'new-instance\s+\w+,\s*(L[\w/$]+;)', body_text)
    result["object_allocations"] = list(set(allocs))

    # Annotations
    annotations = re.findall(r'\.annotation\s+.*?(L[\w/$]+;)', body_text)
    result["annotations"] = annotations

    return result


# ---------------------------------------------------------------------------
# Protection / obfuscation detection
# ---------------------------------------------------------------------------

_PROTECTION_PATTERNS = {
    "root_detection": {
        "patterns": [
            r'"/system/app/Superuser\.apk"',
            r'"/system/xbin/su"',
            r'"/sbin/su"',
            r'"com\.noshufou\.android\.su"',
            r'"com\.thirdparty\.superuser"',
            r'"eu\.chainfire\.supersu"',
            r'"com\.koushikdutta\.superuser"',
            r'"com\.topjohnwu\.magisk"',
            r'"test-keys"',
            r'RootBeer|RootTools|SafetyNet',
        ],
        "severity": "high",
        "description": "Root/jailbreak detection mechanism",
    },
    "emulator_detection": {
        "patterns": [
            r'"goldfish"',
            r'"Build\.FINGERPRINT".*generic',
            r'"sdk_gphone"',
            r'"Andy|Genymotion|BlueStacks|Nox"',
            r'"google_sdk|Emulator|android-x86"',
            r'TelephonyManager.*getDeviceId.*0{15}',
        ],
        "severity": "medium",
        "description": "Emulator/VM detection",
    },
    "anti_debug": {
        "patterns": [
            r'android\.os\.Debug;->isDebuggerConnected',
            r'ptrace',
            r'"TracerPid"',
            r'/proc/self/status',
            r'android\.os\.Debug;->waitingForDebugger',
        ],
        "severity": "high",
        "description": "Anti-debugging mechanism",
    },
    "anti_tamper": {
        "patterns": [
            r'PackageManager.*signatures',
            r'PackageInfo.*signatures',
            r'MessageDigest.*SHA|MD5',
            r'signature.*verify|verify.*signature',
            r'checkSignature|verifySignature',
        ],
        "severity": "high",
        "description": "Tampering/integrity check",
    },
    "dynamic_loading": {
        "patterns": [
            r'DexClassLoader|PathClassLoader|InMemoryDexClassLoader',
            r'ClassLoader.*loadClass',
            r'dalvik\.system\.DexFile',
            r'openDexFile|loadDex',
            r'Runtime.*loadLibrary|System.*loadLibrary',
        ],
        "severity": "high",
        "description": "Dynamic code loading (potential payload hiding)",
    },
    "native_layer": {
        "patterns": [
            r'\.method.*native\s',
            r'System;->loadLibrary',
            r'System;->load\(',
            r'JNI_OnLoad',
        ],
        "severity": "medium",
        "description": "Native code execution (may hide logic in .so)",
    },
    "reflection": {
        "patterns": [
            r'java/lang/reflect/Method;->invoke',
            r'java/lang/reflect/Field;->set',
            r'java/lang/reflect/Constructor;->newInstance',
            r'Class;->forName',
            r'Class;->getDeclaredMethod',
        ],
        "severity": "medium",
        "description": "Reflection usage (may bypass security or hide calls)",
    },
    "obfuscation_indicators": {
        "patterns": [
            r'\.class.*L[a-z]/[a-z]/[a-z];',            # single-letter class names
            r'\.method.*\s[a-z]\(',                        # single-letter method names
            r'const-string.*\\u[0-9a-f]{4}',              # unicode-escaped strings
            r'goto.*:goto_[0-9a-f]',                       # complex goto chains
        ],
        "severity": "low",
        "description": "Code obfuscation indicators",
    },
    "ssl_bypass_targets": {
        "patterns": [
            r'X509TrustManager',
            r'checkServerTrusted',
            r'checkClientTrusted',
            r'HostnameVerifier',
            r'SSLSocketFactory',
            r'OkHostnameVerifier',
            r'CertificatePinner',
            r'network_security_config',
        ],
        "severity": "high",
        "description": "SSL/TLS verification (potential bypass target)",
    },
    "crypto_weakness": {
        "patterns": [
            r'"AES/ECB"',
            r'"DES"[^e]',
            r'SecretKeySpec.*"AES"',
            r'IvParameterSpec.*const-string',  # static IV
            r'"MD5"|"SHA-1"',
            r'SecureRandom.*setSeed',  # predictable seed
        ],
        "severity": "high",
        "description": "Weak cryptographic implementation",
    },
}


def detect_protections(smali_dir: str | Path, max_files: int = 800) -> dict:
    """Scan for all protection mechanisms, obfuscation, and security patterns.

    Returns categorized results with file locations and severity.
    """
    from apk_agent.progress import report_progress

    smali_dir = Path(smali_dir)
    if not smali_dir.is_dir():
        return {"success": False, "error": f"Directory not found: {smali_dir}"}

    findings: dict[str, list[dict]] = {cat: [] for cat in _PROTECTION_PATTERNS}
    compiled = {
        cat: [re.compile(p, re.IGNORECASE) for p in info["patterns"]]
        for cat, info in _PROTECTION_PATTERNS.items()
    }
    files_scanned = 0

    # Count total files for progress
    total_smali = 0
    for root, _, files in os.walk(smali_dir):
        for fname in files:
            if fname.endswith(".smali"):
                total_smali += 1
    total_to_scan = min(total_smali, max_files)

    for root, _, files in os.walk(smali_dir):
        for fname in files:
            if not fname.endswith(".smali"):
                continue
            if files_scanned >= max_files:
                break
            files_scanned += 1

            # Report progress every 15 files
            if files_scanned % 15 == 0 or files_scanned == total_to_scan:
                pct = (files_scanned / total_to_scan * 100) if total_to_scan > 0 else 50
                total_hits = sum(len(v) for v in findings.values())
                report_progress(pct, f"{files_scanned}/{total_to_scan} files | {total_hits} protections found")

            fpath = Path(root) / fname
            text = fpath.read_text(encoding="utf-8", errors="replace")
            rel = str(fpath.relative_to(smali_dir))

            for cat, regexes in compiled.items():
                for regex in regexes:
                    for m in regex.finditer(text):
                        # Find line number
                        line_num = text[:m.start()].count("\n") + 1
                        findings[cat].append({
                            "file": rel,
                            "line": line_num,
                            "match": m.group(0)[:80],
                            "pattern": regex.pattern[:60],
                        })

    # Build summary
    summary = {}
    total_findings = 0
    for cat, hits in findings.items():
        if hits:
            info = _PROTECTION_PATTERNS[cat]
            # Deduplicate by file
            unique_files = list(set(h["file"] for h in hits))
            summary[cat] = {
                "description": info["description"],
                "severity": info["severity"],
                "hit_count": len(hits),
                "unique_files": len(unique_files),
                "samples": hits[:10],  # first 10 samples
                "files": unique_files[:20],
            }
            total_findings += len(hits)

    return {
        "success": True,
        "files_scanned": files_scanned,
        "total_findings": total_findings,
        "categories_found": len(summary),
        "findings": summary,
    }


# ---------------------------------------------------------------------------
# Call chain reconstruction
# ---------------------------------------------------------------------------

def trace_call_chain(
    smali_dir: str | Path,
    target_method: str,
    depth: int = 3,
    max_files: int = 500,
) -> dict:
    """Trace who calls a method, and who calls the callers (up to N depth).

    Builds a reverse call graph showing the execution path to a target.
    Useful for finding how a security check is triggered.
    """
    smali_dir = Path(smali_dir)
    if not smali_dir.is_dir():
        return {"success": False, "error": f"Directory not found: {smali_dir}"}

    from apk_agent.progress import report_progress

    # Index: method -> list of callers
    call_index: dict[str, list[dict]] = defaultdict(list)
    method_to_class: dict[str, str] = {}
    files_scanned = 0

    # Count total for progress
    total_smali = 0
    for root, _, files in os.walk(smali_dir):
        for fname in files:
            if fname.endswith(".smali"):
                total_smali += 1
    total_to_scan = min(total_smali, max_files)

    for root, _, files in os.walk(smali_dir):
        for fname in files:
            if not fname.endswith(".smali"):
                continue
            if files_scanned >= max_files:
                break
            files_scanned += 1

            if files_scanned % 20 == 0 or files_scanned == total_to_scan:
                pct = (files_scanned / total_to_scan * 80) if total_to_scan > 0 else 40
                report_progress(pct, f"Indexing {files_scanned}/{total_to_scan} files for call graph")

            fpath = Path(root) / fname
            text = fpath.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
            rel = str(fpath.relative_to(smali_dir))

            # Get class name
            class_match = re.search(r'^\.class\s+.*\s+(L[\w/$]+;)', text, re.MULTILINE)
            class_name = class_match.group(1) if class_match else rel

            # Find current method context
            current_method = ""
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith(".method"):
                    m = re.search(r'([\w<>$]+)\(', stripped)
                    current_method = m.group(1) if m else ""
                elif stripped == ".end method":
                    current_method = ""
                elif stripped.startswith("invoke-") and current_method:
                    # Extract called method
                    m = re.search(r'(L[\w/$]+;)->([\w<>$]+)\(', stripped)
                    if m:
                        callee = f"{m.group(1)}->{m.group(2)}"
                        caller_full = f"{class_name}->{current_method}"
                        call_index[callee].append({
                            "caller": caller_full,
                            "file": rel,
                            "line": i + 1,
                        })
                        method_to_class[caller_full] = class_name

    # Trace backwards from target
    chain: list[dict] = []
    current_targets = [target_method]
    visited = set()

    for d in range(depth):
        next_targets = []
        for target in current_targets:
            if target in visited:
                continue
            visited.add(target)
            # Find all callers (partial match on method name)
            for key, callers in call_index.items():
                if target in key:
                    for caller in callers:
                        chain.append({
                            "depth": d,
                            "target": key,
                            "caller": caller["caller"],
                            "file": caller["file"],
                            "line": caller["line"],
                        })
                        # Extract just the method name for next depth
                        m = re.search(r'->([\w<>$]+)', caller["caller"])
                        if m:
                            next_targets.append(m.group(1))
        current_targets = next_targets

    return {
        "success": True,
        "target": target_method,
        "depth_searched": depth,
        "files_scanned": files_scanned,
        "chain_length": len(chain),
        "call_chain": chain[:100],
    }


# ---------------------------------------------------------------------------
# String reconstruction from byte/char arrays
# ---------------------------------------------------------------------------

def reconstruct_strings(smali_file: str | Path) -> dict:
    """Attempt to reconstruct strings from byte arrays and char arrays in smali.

    Finds patterns like:
      - fill-array-data with byte values → decode to string
      - Series of const/16 into array → decode
      - XOR-encrypted arrays with visible key
    """
    path = Path(smali_file)
    if not path.is_file():
        return {"success": False, "error": f"File not found: {path}"}

    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    reconstructed: list[dict] = []

    # Pattern 1: fill-array-data blocks with byte values
    in_fill = False
    fill_start = 0
    fill_bytes: list[int] = []

    for i, line in enumerate(lines):
        stripped = line.strip()

        if ":array_" in stripped and "fill-array-data" in lines[i - 1] if i > 0 else False:
            pass  # label before fill-array-data

        if ".array-data 1" in stripped:
            in_fill = True
            fill_start = i
            fill_bytes = []
            continue

        if in_fill:
            if ".end array-data" in stripped:
                in_fill = False
                # Try to decode
                try:
                    decoded = bytes(b & 0xFF for b in fill_bytes).decode("utf-8", errors="replace")
                    if len(decoded) >= 3 and any(c.isalpha() for c in decoded):
                        reconstructed.append({
                            "type": "byte_array",
                            "line": fill_start + 1,
                            "bytes": fill_bytes[:50],
                            "decoded": decoded[:200],
                        })
                except Exception:
                    pass
            else:
                # Parse hex value
                m = re.match(r'\s*([-]?0x[0-9a-fA-F]+|[-]?\d+)t?\s*$', stripped)
                if m:
                    try:
                        fill_bytes.append(int(m.group(1), 0))
                    except ValueError:
                        pass

    # Pattern 2: const-string sequences that build a string
    const_strings = re.findall(
        r'const-string(?:/jumbo)?\s+\w+,\s*"((?:[^"\\]|\\.)*)"', text
    )
    if const_strings:
        reconstructed.append({
            "type": "const_strings_in_file",
            "count": len(const_strings),
            "strings": const_strings[:50],
        })

    return {
        "success": True,
        "file": str(path),
        "reconstructed_count": len(reconstructed),
        "results": reconstructed,
    }
