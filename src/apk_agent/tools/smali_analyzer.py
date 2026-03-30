"""Smali code analyzer — deep, obfuscation-aware reverse engineering toolkit.

Pure Python.  Provides:
  - Class/method listing from smali files
  - Crypto API usage detection
  - String decryption pattern finder (const-string, sget, arrays)
  - Method cross-reference scanning
  - Obfuscation level analysis and deobfuscation hints
  - Method complexity scoring (control flow, data flow)
  - Auto-classification of methods (crypto, network, storage, IPC, etc.)
  - Register data-flow tracking within methods
  - String deobfuscation (XOR, base64, char-array, byte-array)
"""

from __future__ import annotations

import base64
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SmaliClass:
    """Parsed smali class summary."""
    file_path: str
    class_name: str
    super_class: str = ""
    interfaces: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    fields: list[str] = field(default_factory=list)
    string_constants: list[str] = field(default_factory=list)
    annotations: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Crypto / encryption patterns in smali
# ---------------------------------------------------------------------------

_CRYPTO_PATTERNS = {
    "AES usage": re.compile(r'Ljavax/crypto/Cipher;|"AES', re.IGNORECASE),
    "DES usage (weak)": re.compile(r'"DES"|"DESede"', re.IGNORECASE),
    "RSA usage": re.compile(r'"RSA"|Ljava/security/KeyPairGenerator;'),
    "ECB mode (weak)": re.compile(r'"AES/ECB|"DES/ECB', re.IGNORECASE),
    "Static IV": re.compile(r'Ljavax/crypto/spec/IvParameterSpec;'),
    "Hardcoded SecretKey": re.compile(r'Ljavax/crypto/spec/SecretKeySpec;'),
    "MD5 hash (weak)": re.compile(r'"MD5"'),
    "SHA1 hash (weak)": re.compile(r'"SHA-?1"', re.IGNORECASE),
    "Base64 encode/decode": re.compile(r'Landroid/util/Base64;'),
    "KeyStore usage": re.compile(r'Ljava/security/KeyStore;'),
    "TrustManager": re.compile(r'Ljavax/net/ssl/X509TrustManager;'),
    "HostnameVerifier": re.compile(r'Ljavax/net/ssl/HostnameVerifier;'),
    "CertificatePinner": re.compile(r'CertificatePinner'),
    "WebView JS enabled": re.compile(r'setJavaScriptEnabled'),
    "Runtime.exec": re.compile(r'Ljava/lang/Runtime;->exec'),
    "ProcessBuilder": re.compile(r'Ljava/lang/ProcessBuilder;'),
    "SharedPreferences": re.compile(r'Landroid/content/SharedPreferences;'),
    "SQLiteDatabase": re.compile(r'Landroid/database/sqlite/SQLiteDatabase;'),
    "ContentResolver": re.compile(r'Landroid/content/ContentResolver;'),
    "PackageManager": re.compile(r'Landroid/content/pm/PackageManager;'),
    "Reflection": re.compile(r'Ljava/lang/reflect/Method;->invoke'),
    "DexClassLoader": re.compile(r'Ldalvik/system/DexClassLoader;'),
    "Native method": re.compile(r'\.method.*native\s'),
}

# Patterns for string encryption/obfuscation
_STRING_DECRYPT_PATTERNS = {
    "XOR decryption loop": re.compile(r'xor-int|xor-long', re.IGNORECASE),
    "String.valueOf from bytes": re.compile(r'new-instance.*Ljava/lang/String;.*\[B'),
    "Cipher.doFinal": re.compile(r'invoke.*Ljavax/crypto/Cipher;->doFinal'),
    "Base64.decode → String": re.compile(r'Base64;->decode'),
    "char[] → String": re.compile(r'new-instance.*Ljava/lang/String;.*\[C'),
    "StringBuilder chaining": re.compile(r'Ljava/lang/StringBuilder;->append.*\n.*invoke.*append'),
}


def parse_smali_class(file_path: str | Path) -> dict:
    """Parse a single smali file — deep obfuscation-aware analysis.

    Returns dict with: class_name, super_class, interfaces, methods,
    fields, string_constants, crypto_findings, obfuscation_analysis,
    method_classifications, data_flow_hints, decoded_strings, line_count.
    """
    file_path = Path(file_path)
    if not file_path.is_file():
        return {"success": False, "error": f"File not found: {file_path}"}

    text = file_path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    result: dict = {
        "success": True,
        "file": str(file_path),
        "line_count": len(lines),
    }

    # Class name
    m = re.search(r"^\.class\s+.*\s+(L[\w/$]+;)", text, re.MULTILINE)
    result["class_name"] = m.group(1) if m else "unknown"

    # Super class
    m = re.search(r"^\.super\s+(L[\w/$]+;)", text, re.MULTILINE)
    result["super_class"] = m.group(1) if m else ""

    # Interfaces
    result["interfaces"] = re.findall(
        r"^\.implements\s+(L[\w/$]+;)", text, re.MULTILINE
    )

    # Access flags (public, final, abstract, etc.)
    m = re.search(r"^\.class\s+(.*?)\s+L", text, re.MULTILINE)
    result["access_flags"] = m.group(1).strip() if m else ""

    # Source file (useful for deobfuscation)
    m = re.search(r'^\.source\s+"(.*?)"', text, re.MULTILINE)
    result["source_file"] = m.group(1) if m else ""

    # Annotations (class-level)
    class_annotations = re.findall(
        r"\.annotation\s+.*?(L[\w/$]+;)", text
    )
    result["class_annotations"] = list(set(class_annotations))[:20]

    # Methods — enhanced with complexity and classification
    methods = []
    method_blocks = _extract_method_blocks(lines)

    for mb in method_blocks:
        method_info = {
            "name": mb["name"],
            "access": mb["access"],
            "signature": mb["signature"],
            "line_range": [mb["start_line"] + 1, mb["end_line"] + 1],
            "instruction_count": mb["instruction_count"],
            "complexity": mb["complexity"],
            "category": _classify_method(mb["body_text"]),
        }
        # For interesting methods, add API calls
        if mb["api_calls"]:
            method_info["api_calls"] = mb["api_calls"][:15]
        methods.append(method_info)

    result["methods"] = methods

    # Fields
    fields: list[str] = re.findall(r"^\.field\s+(.*)", text, re.MULTILINE)
    result["fields"] = list(fields[:50])

    # String constants (const-string)
    strings: list[str] = re.findall(r'const-string(?:/jumbo)?\s+\w+,\s*"(.*?)"', text)
    result["string_constants"] = list(strings[:100])

    # Crypto/security API findings
    crypto_hits = []
    for pattern_name, regex in _CRYPTO_PATTERNS.items():
        matches = regex.findall(text)
        if matches:
            crypto_hits.append({
                "pattern": pattern_name,
                "count": len(matches),
            })
    result["crypto_findings"] = crypto_hits

    # === NEW: Obfuscation analysis ===
    result["obfuscation"] = _analyze_obfuscation(result["class_name"], methods, text)

    # === NEW: Auto-decoded strings ===
    decoded = _auto_decode_strings(text, lines)
    if decoded:
        result["decoded_strings"] = decoded

    # === NEW: Data flow hints for security-critical methods ===
    security_methods = [m for m in method_blocks
                        if m.get("has_security_calls")]
    if security_methods:
        result["security_data_flow"] = [
            _trace_method_data_flow(m) for m in security_methods[:5]
        ]

    return result


# ---------------------------------------------------------------------------
# Helper: extract method blocks with full analysis
# ---------------------------------------------------------------------------

_SECURITY_API_PATTERNS = re.compile(
    r"Ljavax/crypto/|Ljavax/net/ssl/|Ljava/security/|"
    r"Landroid/util/Base64|checkServerTrusted|checkClientTrusted|"
    r"HostnameVerifier|CertificatePinner|SSLSocketFactory|"
    r"SecretKeySpec|IvParameterSpec|Cipher;->|MessageDigest;->|"
    r"KeyStore;->|TrustManager|X509Certificate",
    re.IGNORECASE,
)

# Method categories by API usage
_METHOD_CATEGORY_PATTERNS = {
    "crypto": re.compile(
        r"Ljavax/crypto/|SecretKeySpec|IvParameterSpec|Cipher;->|"
        r"MessageDigest;->|KeyGenerator;->|Mac;->|Signature;->",
    ),
    "network": re.compile(
        r"Ljava/net/URL|HttpURLConnection|OkHttp|Retrofit|"
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
        r"getDeclaredField|setAccessible|invoke\(",
    ),
    "dynamic_load": re.compile(
        r"DexClassLoader|PathClassLoader|InMemoryDexClassLoader|"
        r"loadClass|loadDex|Runtime;->exec|ProcessBuilder",
    ),
    "obfuscation": re.compile(
        r"xor-int|xor-long|Base64;->decode|Base64;->encode|"
        r"StringBuilder;->append.*invoke.*append",
    ),
}


def _extract_method_blocks(lines: list[str]) -> list[dict]:
    """Extract all method blocks from smali lines with analysis."""
    methods = []
    method_start = -1
    method_header = ""

    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(".method"):
            method_start = i
            method_header = stripped
        elif stripped == ".end method" and method_start >= 0:
            body_lines = lines[method_start:i + 1]
            body_text = "\n".join(body_lines)

            # Parse header
            hdr_match = re.search(
                r"\.method\s+(.*?)\s+([\w<>$]+)\((.*?)\)(.*?)$", method_header,
            )
            if not hdr_match:
                method_start = -1
                continue

            access = hdr_match.group(1).strip()
            name = hdr_match.group(2)
            params = hdr_match.group(3)
            ret = hdr_match.group(4)

            # Count real instructions (skip directives, labels, comments)
            instr_count = 0
            branches = 0
            for bline in body_lines:
                bs = bline.strip()
                if bs and not bs.startswith((".")) and not bs.startswith(("#") ) and not bs.startswith(":"):
                    instr_count += 1
                if bs.startswith(("if-", "goto", "switch")):
                    branches += 1

            # API calls
            api_calls = []
            for bline in body_lines:
                bs = bline.strip()
                if bs.startswith("invoke-"):
                    m = re.search(r"(L[\w/$]+;)->([\w<>$]+)\(", bs)
                    if m:
                        api_calls.append(f"{m.group(1)}->{m.group(2)}")

            # Complexity: branches + try/catch + switches
            try_catches = body_text.count(".catch ")
            switches = body_text.count("packed-switch") + body_text.count("sparse-switch")
            complexity = branches + try_catches + switches

            has_security = bool(_SECURITY_API_PATTERNS.search(body_text))

            methods.append({
                "name": name,
                "access": access,
                "signature": f"{name}({params}){ret}",
                "start_line": method_start,
                "end_line": i,
                "instruction_count": instr_count,
                "complexity": complexity,
                "api_calls": list(set(api_calls)),
                "body_text": body_text,
                "body_lines": body_lines,
                "has_security_calls": has_security,
            })
            method_start = -1

    return methods


def _classify_method(body_text: str) -> str:
    """Classify a method by its API usage patterns."""
    for category, pattern in _METHOD_CATEGORY_PATTERNS.items():
        if pattern.search(body_text):
            return category
    return "general"


# ---------------------------------------------------------------------------
# Obfuscation analysis
# ---------------------------------------------------------------------------

def _analyze_obfuscation(class_name: str, methods: list[dict], text: str) -> dict:
    """Analyze obfuscation level and provide deobfuscation hints."""
    indicators = []
    score = 0  # 0-100, higher = more obfuscated

    # 1. Short class name (single letter = obfuscated)
    cn_parts = class_name.strip("L;").split("/")
    short_names = [p for p in cn_parts if len(p) <= 2 and p.isalpha()]
    if short_names:
        score += 20
        indicators.append(f"Short class name segments: {short_names}")

    # 2. Short method names
    short_methods = [m["name"] for m in methods
                     if len(m["name"]) <= 2 and m["name"] not in ("<init>", "<clinit>")]
    if short_methods:
        ratio = len(short_methods) / max(len(methods), 1)
        score += int(ratio * 30)
        indicators.append(f"{len(short_methods)}/{len(methods)} methods have short names")

    # 3. String encryption evidence
    has_xor = bool(re.search(r"xor-int|xor-long", text))
    has_byte_arrays = len(re.findall(r"\.array-data\s+1", text))
    has_base64 = bool(re.search(r"Base64;->decode", text))
    if has_xor:
        score += 15
        indicators.append("XOR operations found (possible string encryption)")
    if has_byte_arrays > 2:
        score += 10
        indicators.append(f"{has_byte_arrays} byte arrays (possible encoded data)")
    if has_base64:
        score += 5
        indicators.append("Base64 decode usage")

    # 4. Complex control flow (many gotos, switches in small methods)
    goto_count = text.count("goto ")
    if goto_count > 20:
        score += 10
        indicators.append(f"High goto count: {goto_count} (control flow flattening?)")

    # 5. No .source directive = stripped debug info
    if '.source "' not in text:
        score += 5
        indicators.append("No .source directive (debug info stripped)")

    # 6. Unicode-escaped strings
    unicode_strings = re.findall(r'const-string.*?".*?\\u[0-9a-fA-F]{4}.*?"', text)
    if unicode_strings:
        score += 10
        indicators.append(f"{len(unicode_strings)} unicode-escaped strings")

    # Deobfuscation hints
    hints = []
    if has_xor:
        hints.append("Use reconstruct_strings to decode XOR-encrypted strings")
    if has_byte_arrays > 0:
        hints.append("Use reconstruct_strings to decode byte array data")
    if short_methods:
        hints.append("Use graph_callers/graph_callees to trace method purpose by call context")
    if has_base64:
        hints.append("Check for base64-encoded URLs, keys, or config data")
    if score >= 40:
        hints.append("Use graph_class_info to understand this class through its relationships")

    level = "none"
    if score >= 60:
        level = "heavy"
    elif score >= 35:
        level = "moderate"
    elif score >= 15:
        level = "light"

    return {
        "level": level,
        "score": min(score, 100),
        "indicators": indicators,
        "deobfuscation_hints": hints,
    }


# ---------------------------------------------------------------------------
# Auto string decoding (XOR, base64, char arrays, byte arrays)
# ---------------------------------------------------------------------------

def _auto_decode_strings(text: str, lines: list[str]) -> list[dict]:
    """Attempt automatic string decoding from obfuscation patterns."""
    decoded = []

    # 1. Byte array fill-array-data → string
    in_fill = False
    fill_start = 0
    fill_bytes: list[int] = []

    for i, line in enumerate(lines):
        stripped = line.strip()
        if ".array-data 1" in stripped:
            in_fill = True
            fill_start = i
            fill_bytes = []
            continue

        if in_fill:
            if ".end array-data" in stripped:
                in_fill = False
                try:
                    raw = bytes(b & 0xFF for b in fill_bytes)
                    s = raw.decode("utf-8", errors="replace")
                    if len(s) >= 3 and any(c.isalnum() for c in s):
                        decoded.append({
                            "type": "byte_array",
                            "line": fill_start + 1,
                            "decoded": s[:200],
                            "confidence": "high" if all(32 <= b < 127 for b in fill_bytes) else "medium",
                        })
                except Exception:
                    pass
            else:
                m = re.match(r"\s*([-]?0x[0-9a-fA-F]+|[-]?\d+)t?\s*$", stripped)
                if m:
                    try:
                        fill_bytes.append(int(m.group(1), 0))
                    except ValueError:
                        pass

    # 2. Base64 encoded const-strings → attempt decode
    for m in re.finditer(r'const-string(?:/jumbo)?\s+\w+,\s*"([A-Za-z0-9+/=]{16,})"', text):
        b64str = m.group(1)
        try:
            raw = base64.b64decode(b64str)
            s = raw.decode("utf-8", errors="strict")
            if len(s) >= 3 and s.isprintable():
                line_no = text[:m.start()].count("\n") + 1
                decoded.append({
                    "type": "base64_string",
                    "line": line_no,
                    "encoded": b64str[:60],
                    "decoded": s[:200],
                    "confidence": "high",
                })
        except Exception:
            pass

    # 3. Char array construction (series of const/16 followed by aput-char)
    char_sequences = re.findall(
        r"const/16\s+(\w+),\s*(0x[0-9a-fA-F]+)\s*\n\s*aput-char",
        text,
    )
    if char_sequences:
        chars = []
        for _, hex_val in char_sequences:
            try:
                chars.append(chr(int(hex_val, 16)))
            except (ValueError, OverflowError):
                pass
        if len(chars) >= 3:
            decoded.append({
                "type": "char_array",
                "decoded": "".join(chars)[:200],
                "confidence": "medium",
                "char_count": len(chars),
            })

    return decoded[:20]


# ---------------------------------------------------------------------------
# Data flow tracing within a method
# ---------------------------------------------------------------------------

def _trace_method_data_flow(method_block: dict) -> dict:
    """Trace register data flow in a security-critical method.

    Shows what values flow into sensitive API calls.
    """
    body_lines = method_block["body_lines"]
    body_text = method_block["body_text"]

    # Track register assignments
    reg_sources: dict[str, str] = {}  # register -> last known source
    sensitive_flows = []

    for line in body_lines:
        s = line.strip()

        # const-string vN, "value" → register gets a known string
        m = re.match(r'const-string(?:/jumbo)?\s+(\w+),\s*"(.*?)"', s)
        if m:
            reg_sources[m.group(1)] = f'string:"{m.group(2)[:50]}"'
            continue

        # const vN, 0xNN → register gets a constant
        m = re.match(r"const(?:/4|/16|/high16)?\s+(\w+),\s*(.*?)$", s)
        if m:
            reg_sources[m.group(1)] = f"const:{m.group(2)}"
            continue

        # sget vN, Lclass;->field → register gets a static field
        m = re.match(r"sget\S*\s+(\w+),\s*(L[\w/$]+;->[\w$]+)", s)
        if m:
            reg_sources[m.group(1)] = f"field:{m.group(2)}"
            continue

        # iget vN, vM, Lclass;->field → register gets an instance field
        m = re.match(r"iget\S*\s+(\w+),\s*\w+,\s*(L[\w/$]+;->[\w$]+)", s)
        if m:
            reg_sources[m.group(1)] = f"field:{m.group(2)}"
            continue

        # move-result vN → register gets return value of last invoke
        m = re.match(r"move-result\S*\s+(\w+)", s)
        if m:
            reg_sources[m.group(1)] = "return_value"
            continue

        # invoke-* with sensitive API → track what registers flow in
        if s.startswith("invoke-") and _SECURITY_API_PATTERNS.search(s):
            # Extract registers used
            reg_match = re.search(r"\{([^}]*)\}", s)
            api_match = re.search(r"(L[\w/$]+;->[\w<>$]+)\(", s)
            if reg_match and api_match:
                regs = [r.strip() for r in reg_match.group(1).split(",") if r.strip()]
                sources = {r: reg_sources.get(r, "unknown") for r in regs}
                sensitive_flows.append({
                    "api": api_match.group(1),
                    "registers": sources,
                })

    return {
        "method": method_block["signature"],
        "sensitive_api_flows": sensitive_flows[:10],
    }


def scan_smali_directory(
    smali_dir: str | Path,
    max_files: int = 500,
) -> dict:
    """Scan a smali directory and return a summary of all classes.

    Returns: class_count, method_count, crypto_summary, interesting_classes.
    """
    from apk_agent.progress import report_progress

    smali_dir = Path(smali_dir)
    if not smali_dir.is_dir():
        return {"success": False, "error": f"Directory not found: {smali_dir}"}

    all_crypto: dict[str, int] = {}
    interesting: list[dict] = []
    class_count: int = 0
    method_count: int = 0
    files_scanned: int = 0
    obfuscated_classes: int = 0

    # Count total files first for accurate progress
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

            fpath = Path(root) / fname
            files_scanned += 1

            # Report progress every 10 files
            if files_scanned % 10 == 0 or files_scanned == total_to_scan:
                pct = (files_scanned / total_to_scan * 100) if total_to_scan > 0 else 50
                report_progress(pct, f"{files_scanned}/{total_to_scan} smali files scanned")

            text = fpath.read_text(encoding="utf-8", errors="replace")

            class_count += 1
            method_count += len(re.findall(r"^\.method\s", text, re.MULTILINE))

            # Check crypto patterns
            file_hits = []
            for pattern_name, regex in _CRYPTO_PATTERNS.items():
                matches = regex.findall(text)
                if matches:
                    all_crypto[pattern_name] = all_crypto.get(pattern_name, 0) + len(matches)
                    file_hits.append(pattern_name)

            # Track obfuscation indicators
            class_match = re.search(r"^\.class\s+.*\s+(L[\w/$]+;)", text, re.MULTILINE)
            cname = class_match.group(1) if class_match else fname
            cn_last = cname.strip("L;").split("/")[-1]
            if len(cn_last) <= 2 and cn_last.isalpha():
                obfuscated_classes += 1

            # Track "interesting" files
            if file_hits:
                rel = str(fpath.relative_to(smali_dir))
                interesting.append({
                    "file": rel,
                    "findings": file_hits,
                })

    obfuscation_pct = int(obfuscated_classes / max(class_count, 1) * 100)
    obfuscation_level = "none"
    if obfuscation_pct >= 50:
        obfuscation_level = "heavy"
    elif obfuscation_pct >= 20:
        obfuscation_level = "moderate"
    elif obfuscation_pct >= 5:
        obfuscation_level = "light"

    return {
        "success": True,
        "files_scanned": files_scanned,
        "class_count": class_count,
        "method_count": method_count,
        "obfuscation": {
            "level": obfuscation_level,
            "obfuscated_classes": obfuscated_classes,
            "obfuscated_pct": obfuscation_pct,
        },
        "crypto_summary": dict(sorted(all_crypto.items(), key=lambda x: -x[1])),
        "interesting_classes": list(interesting[:80]),
    }


def find_string_decryption(
    smali_dir: str | Path,
    max_files: int = 300,
) -> dict:
    """Find potential string decryption/deobfuscation patterns in smali.

    Looks for XOR loops, byte array to String conversions,
    Base64 decoding, and cipher operations used to decrypt strings.
    """
    smali_dir = Path(smali_dir)
    if not smali_dir.is_dir():
        return {"success": False, "error": f"Directory not found: {smali_dir}"}

    findings: list[dict] = []
    files_scanned = 0

    for root, _, files in os.walk(smali_dir):
        for fname in files:
            if not fname.endswith(".smali"):
                continue
            if files_scanned >= max_files:
                break

            fpath = Path(root) / fname
            files_scanned += 1
            text = fpath.read_text(encoding="utf-8", errors="replace")

            file_patterns = []
            for pattern_name, regex in _STRING_DECRYPT_PATTERNS.items():
                matches = regex.findall(text)
                if matches:
                    file_patterns.append({
                        "pattern": pattern_name,
                        "count": len(matches),
                    })

            if file_patterns:
                rel = str(fpath.relative_to(smali_dir))
                findings.append({
                    "file": rel,
                    "decryption_patterns": file_patterns,
                })

    return {
        "success": True,
        "files_scanned": files_scanned,
        "files_with_decryption": len(findings),
        "findings": list(findings[:60]),
    }


def find_method_calls(
    smali_dir: str | Path,
    method_signature: str,
    max_results: int = 50,
) -> dict:
    """Find all call sites of a specific method across smali files.

    Args:
        method_signature: Full or partial smali method signature,
            e.g. "Landroid/util/Log;->d" or "checkServerTrusted".
    """
    smali_dir = Path(smali_dir)
    if not smali_dir.is_dir():
        return {"success": False, "error": f"Directory not found: {smali_dir}"}

    results: list[dict] = []

    for root, _, files in os.walk(smali_dir):
        for fname in files:
            if not fname.endswith(".smali"):
                continue
            fpath = Path(root) / fname
            try:
                lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                continue

            for i, line in enumerate(lines, 1):
                if method_signature in line:
                    # Get surrounding context
                    ctx_start = max(0, i - 3)
                    ctx_end = min(len(lines), i + 2)
                    context = lines[ctx_start:ctx_end]
                    results.append({
                        "file": str(fpath.relative_to(smali_dir)),
                        "line": i,
                        "content": line.strip(),
                        "context": "\n".join(context),
                    })
                    if len(results) >= max_results:
                        return {
                            "success": True,
                            "total_found": len(results),
                            "truncated": True,
                            "results": results,
                        }

    return {
        "success": True,
        "total_found": len(results),
        "truncated": False,
        "results": results,
    }
