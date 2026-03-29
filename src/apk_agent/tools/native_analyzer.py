"""Native library (.so) analyzer for Android APKs.

Analyzes native libraries in lib/ directory:
- Architecture detection (arm64, armeabi, x86)  
- Library listing with sizes
- Symbol extraction (exported functions)
- String extraction from binaries
- JNI method detection
"""

from __future__ import annotations

import os
import re
import struct
from pathlib import Path


def analyze_native_libs(apktool_dir: str | Path) -> dict:
    """Analyze native libraries in the APK's lib/ directory.

    Args:
        apktool_dir: Path to the apktool decompiled directory.

    Returns:
        Summary of native libraries found.
    """
    apktool_dir = Path(apktool_dir)
    lib_dir = apktool_dir / "lib"

    if not lib_dir.is_dir():
        return {
            "success": True,
            "has_native_libs": False,
            "note": "No lib/ directory found — app has no native libraries.",
        }

    result = {
        "success": True,
        "has_native_libs": True,
        "architectures": [],
        "libraries": [],
        "total_size_mb": 0,
        "jni_methods": [],
        "interesting_strings": [],
    }

    total_size = 0

    for arch_dir in sorted(lib_dir.iterdir()):
        if not arch_dir.is_dir():
            continue

        arch = arch_dir.name
        result["architectures"].append(arch)

        for so_file in sorted(arch_dir.glob("*.so")):
            size = so_file.stat().st_size
            total_size += size

            lib_info = {
                "name": so_file.name,
                "architecture": arch,
                "size_kb": round(size / 1024, 1),
                "path": str(so_file.relative_to(apktool_dir)),
            }

            # Extract strings from the .so file
            try:
                strings = _extract_binary_strings(so_file)
                lib_info["string_count"] = len(strings)

                # Find JNI registration patterns
                jni_methods = [s for s in strings if s.startswith("Java_")]
                if jni_methods:
                    lib_info["jni_methods"] = jni_methods[:20]
                    result["jni_methods"].extend(jni_methods[:20])

                # Find interesting strings (URLs, IPs, keys)
                interesting = _classify_strings(strings)
                if interesting:
                    lib_info["interesting_strings"] = interesting[:10]
                    result["interesting_strings"].extend(interesting[:10])

            except Exception:
                lib_info["string_count"] = 0

            result["libraries"].append(lib_info)

    result["total_size_mb"] = round(total_size / (1024 * 1024), 2)

    return result


def _extract_binary_strings(path: Path, min_length: int = 6) -> list[str]:
    """Extract printable ASCII strings from a binary file."""
    strings = []
    try:
        data = path.read_bytes()
        current = []

        for byte in data:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append("".join(current))
                current = []

        if len(current) >= min_length:
            strings.append("".join(current))

    except Exception:
        pass

    return strings[:2000]  # Cap at 2000 strings


def _classify_strings(strings: list[str]) -> list[dict]:
    """Classify interesting strings from binary analysis."""
    patterns = {
        "url": re.compile(r'https?://[\w\-.]+(?:\.\w+)+', re.IGNORECASE),
        "ip_address": re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
        "api_key": re.compile(r'(?:api|key|token|secret|auth)[_-]?\w*', re.IGNORECASE),
        "crypto_function": re.compile(r'(?:AES|DES|RSA|SHA|MD5|HMAC|encrypt|decrypt)', re.IGNORECASE),
        "file_path": re.compile(r'/(?:data|system|proc|dev|sdcard)/\w+'),
        "jni_native": re.compile(r'Java_\w+'),
    }

    results = []
    seen = set()

    for s in strings:
        for category, regex in patterns.items():
            if regex.search(s) and s not in seen:
                seen.add(s)
                results.append({
                    "category": category,
                    "value": s[:200],
                })
                break

    return results
