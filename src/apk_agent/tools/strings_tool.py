"""Pure-Python strings extractor — scan APK/DEX for printable strings.

No external binary required.  Extracts ASCII/UTF-8 strings from all .dex
files inside the APK ZIP and classifies them using regex heuristics.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

# Minimum string length to keep
MIN_LENGTH = 6

# Classification patterns
_PATTERNS: dict[str, re.Pattern] = {
    "url": re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
    "ip_address": re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b"),
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "api_key": re.compile(
        r"(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?([^\s'\"]+)",
        re.IGNORECASE,
    ),
    "bearer_token": re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE),
    "base64_blob": re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
    "firebase_url": re.compile(r"https://[a-z0-9-]+\.firebaseio\.com", re.IGNORECASE),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "private_key": re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"),
}


def extract_strings(
    apk_path: str | Path,
    min_length: int = MIN_LENGTH,
    max_strings: int = 2000,
    scan_all_files: bool = False,
) -> dict:
    """Extract printable strings from an APK file.

    Args:
        apk_path: Path to the .apk file.
        min_length: Minimum string length to keep.
        max_strings: Cap on total strings returned.
        scan_all_files: If True, scan all files in APK, not just .dex.

    Returns:
        Dict with keys: success, total_strings, classified (dict of
        category → list), raw_sample (first N unclassified strings).
    """
    apk_path = Path(apk_path).resolve()
    if not apk_path.is_file():
        return {"success": False, "error": f"File not found: {apk_path}"}

    try:
        raw_strings = _extract_from_zip(apk_path, min_length, scan_all_files)
    except Exception as e:
        return {"success": False, "error": f"Failed to read APK: {e}"}

    # Deduplicate, preserve order
    seen: set[str] = set()
    unique: list[str] = []
    for s in raw_strings:
        if s not in seen:
            seen.add(s)
            unique.append(s)
        if len(unique) >= max_strings:
            break

    # Classify
    classified: dict[str, list[str]] = {cat: [] for cat in _PATTERNS}
    unclassified: list[str] = []

    for s in unique:
        matched = False
        for cat, pat in _PATTERNS.items():
            if pat.search(s):
                classified[cat].append(s[:500])
                matched = True
                break  # first match wins
        if not matched:
            unclassified.append(s)

    # Remove empty categories
    classified = {k: v for k, v in classified.items() if v}

    return {
        "success": True,
        "total_strings": len(unique),
        "classified": classified,
        "classified_count": sum(len(v) for v in classified.values()),
        "raw_sample": unclassified[:100],  # first 100 unclassified
    }


def _extract_from_zip(
    apk_path: Path,
    min_length: int,
    scan_all: bool,
) -> list[str]:
    """Open APK as ZIP, extract printable strings from .dex entries."""
    strings: list[str] = []

    with zipfile.ZipFile(apk_path, "r") as zf:
        for name in zf.namelist():
            if not scan_all:
                # Only scan .dex files by default
                if not name.endswith(".dex"):
                    continue
            try:
                data = zf.read(name)
            except Exception:
                continue
            strings.extend(_extract_printable(data, min_length))

    return strings


def _extract_printable(data: bytes, min_length: int) -> list[str]:
    """Extract printable ASCII strings from raw bytes."""
    result: list[str] = []
    current: list[str] = []

    for byte in data:
        # Printable ASCII range (32-126)
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                result.append("".join(current))
            current = []

    # Don't forget the last accumulation
    if len(current) >= min_length:
        result.append("".join(current))

    return result
