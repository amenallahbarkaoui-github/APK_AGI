"""Smali code analyzer — parse, decode, and find patterns in smali files.

Pure Python.  Provides:
  - Class/method listing from smali files
  - Crypto API usage detection
  - String decryption pattern finder (const-string, sget, arrays)
  - Method cross-reference scanning
  - Smali instruction statistics
"""

from __future__ import annotations

import os
import re
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
    """Parse a single smali file and return class info.

    Returns dict with: class_name, super_class, interfaces, methods,
    fields, string_constants, crypto_findings, line_count.
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

    # Methods
    methods = []
    for m in re.finditer(
        r"^\.method\s+(.*?)\s+([\w<>$]+)\((.*?)\)(.*?)$", text, re.MULTILINE
    ):
        access = m.group(1)
        name = m.group(2)
        params = m.group(3)
        ret = m.group(4)
        methods.append({
            "name": name,
            "access": access.strip(),
            "signature": f"{name}({params}){ret}",
        })
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

    return result


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

            # Track "interesting" files
            if file_hits:
                rel = str(fpath.relative_to(smali_dir))
                interesting.append({
                    "file": rel,
                    "findings": file_hits,
                })

    return {
        "success": True,
        "files_scanned": files_scanned,
        "class_count": class_count,
        "method_count": method_count,
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
