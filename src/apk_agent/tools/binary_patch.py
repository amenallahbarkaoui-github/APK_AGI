"""Semantic binary string search and patch helpers.

These utilities work at the embedded string level for binary files such as
native `.so` libraries and raw `.dex` files. They are intentionally more
structured than blind hex replacement, while staying lightweight and dependency-free.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

_PRINTABLE_MIN = 32
_PRINTABLE_MAX = 126
_DEX_SUFFIXES = {".dex", ".cdex"}

_CATEGORY_PATTERNS: dict[str, re.Pattern[str]] = {
    "url": re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
    "ip_address": re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
    "api_key": re.compile(r"(?:api|key|token|secret|auth)[_-]?\w*", re.IGNORECASE),
    "crypto_function": re.compile(r"(?:AES|DES|RSA|SHA|MD5|HMAC|encrypt|decrypt)", re.IGNORECASE),
    "file_path": re.compile(r"(?:/[\w./-]+|[A-Za-z]:\\[\w .\\-]+)"),
    "jni_native": re.compile(r"^Java_\w+"),
    "class_descriptor": re.compile(r"^L[\w/$-]+;$"),
    "java_package": re.compile(r"^(?:[A-Za-z_]\w*\.){2,}[A-Za-z_]\w*$"),
}


def _is_printable(byte_value: int) -> bool:
    return _PRINTABLE_MIN <= byte_value <= _PRINTABLE_MAX


def _classify_string(value: str) -> str:
    for category, pattern in _CATEGORY_PATTERNS.items():
        if pattern.search(value):
            return category
    return "generic"


def _iter_printable_strings(data: bytes, min_length: int) -> Iterable[dict]:
    start = -1
    current = bytearray()

    for idx, byte_value in enumerate(data):
        if _is_printable(byte_value):
            if start < 0:
                start = idx
            current.append(byte_value)
            continue

        if len(current) >= min_length:
            value = bytes(current).decode("ascii", errors="ignore")
            yield {
                "value": value,
                "offset": start,
                "offset_hex": f"0x{start:x}",
                "length": len(current),
                "category": _classify_string(value),
            }
        start = -1
        current.clear()

    if len(current) >= min_length:
        value = bytes(current).decode("ascii", errors="ignore")
        yield {
            "value": value,
            "offset": start,
            "offset_hex": f"0x{start:x}",
            "length": len(current),
            "category": _classify_string(value),
        }


def _search_bytes(
    data: bytes,
    *,
    query_re: re.Pattern[str] | None,
    category_set: set[str],
    min_length: int,
    max_results: int,
) -> tuple[int, list[dict]]:
    matches: list[dict] = []
    total_strings = 0

    for entry in _iter_printable_strings(data, min_length):
        total_strings += 1
        if query_re and not query_re.search(entry["value"]):
            continue
        if category_set and entry["category"].lower() not in category_set:
            continue
        matches.append(entry)
        if len(matches) >= max_results:
            break

    return total_strings, matches


def _iter_directory_targets(path: Path) -> Iterable[Path]:
    for candidate in sorted(path.rglob("*")):
        if not candidate.is_file():
            continue
        yield candidate


def search_binary_strings(
    file_path: str | Path,
    *,
    query: str = "",
    categories: list[str] | None = None,
    min_length: int = 4,
    max_results: int = 100,
) -> dict:
    """Search printable embedded strings inside a binary file.

    Returns offsets for exact patch planning.
    """
    path = Path(file_path)
    if not path.exists():
        return {"success": False, "error": f"File not found: {path}"}

    if min_length < 2:
        min_length = 2
    if max_results < 1:
        max_results = 1

    query_re: re.Pattern[str] | None = None
    if query:
        try:
            query_re = re.compile(query, re.IGNORECASE)
        except re.error:
            query_re = re.compile(re.escape(query), re.IGNORECASE)

    category_set = {c.strip().lower() for c in (categories or []) if c.strip()}
    if path.is_dir():
        matches: list[dict] = []
        total_strings = 0
        files_scanned = 0

        for target in _iter_directory_targets(path):
            try:
                data = target.read_bytes()
            except OSError:
                continue
            files_scanned += 1
            remaining = max_results - len(matches)
            if remaining <= 0:
                break
            file_total, file_matches = _search_bytes(
                data,
                query_re=query_re,
                category_set=category_set,
                min_length=min_length,
                max_results=remaining,
            )
            total_strings += file_total
            for match in file_matches:
                match["file"] = str(target)
                try:
                    match["relative_file"] = str(target.relative_to(path))
                except ValueError:
                    match["relative_file"] = target.name
            matches.extend(file_matches)

        return {
            "success": True,
            "path": str(path),
            "search_mode": "directory",
            "file_type": "directory",
            "files_scanned": files_scanned,
            "total_strings_scanned": total_strings,
            "matches_returned": len(matches),
            "matches": matches,
            "patch_rule": (
                "Inspect the matched file paths first. Patch one concrete file at a time with patch_binary_strings; "
                "DEX replacements must keep the exact same UTF-8 byte length, while other binaries can use shorter replacements with NUL padding."
            ),
        }

    if not path.is_file():
        return {"success": False, "error": f"File not found: {path}"}

    data = path.read_bytes()
    total_strings, matches = _search_bytes(
        data,
        query_re=query_re,
        category_set=category_set,
        min_length=min_length,
        max_results=max_results,
    )

    return {
        "success": True,
        "path": str(path),
        "search_mode": "file",
        "file_type": path.suffix.lower(),
        "total_strings_scanned": total_strings,
        "matches_returned": len(matches),
        "matches": matches,
        "patch_rule": (
            "DEX replacements must keep the exact same UTF-8 byte length. "
            "Other binaries can use shorter replacements with NUL padding."
        ),
    }


def _find_bounded_occurrences(data: bytes, needle: bytes) -> list[int]:
    """Find string-like byte occurrences bounded by non-printable neighbors."""
    if not needle:
        return []

    offsets: list[int] = []
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx < 0:
            break
        before_ok = idx == 0 or not _is_printable(data[idx - 1])
        end_idx = idx + len(needle)
        after_ok = end_idx >= len(data) or not _is_printable(data[end_idx])
        if before_ok and after_ok:
            offsets.append(idx)
        start = idx + 1
    return offsets


def patch_binary_strings(
    file_path: str | Path,
    replacements: list[dict],
    *,
    backup_path: str | Path | None = None,
) -> dict:
    """Patch embedded strings in a binary file with length-safe rules."""
    path = Path(file_path)
    if not path.is_file():
        return {"success": False, "error": f"File not found: {path}"}

    if not replacements:
        return {"success": False, "error": "No replacements provided."}

    original = path.read_bytes()
    data = bytearray(original)
    suffix = path.suffix.lower()
    exact_len_only = suffix in _DEX_SUFFIXES

    results: list[dict] = []
    total_patched = 0

    for repl in replacements:
        old_string = str(repl.get("old_string") or "")
        new_string = str(repl.get("new_string") or "")
        occurrence = int(repl.get("occurrence", 1) or 1)
        replace_all = bool(repl.get("replace_all", False))

        if not old_string:
            results.append({
                "success": False,
                "error": "Replacement entry is missing old_string.",
            })
            continue

        old_bytes = old_string.encode("utf-8")
        new_bytes = new_string.encode("utf-8")

        if exact_len_only and len(new_bytes) != len(old_bytes):
            results.append({
                "success": False,
                "old_string": old_string,
                "new_string": new_string,
                "error": "DEX string patch requires replacement with identical UTF-8 byte length.",
                "old_len": len(old_bytes),
                "new_len": len(new_bytes),
            })
            continue

        if not exact_len_only and len(new_bytes) > len(old_bytes):
            results.append({
                "success": False,
                "old_string": old_string,
                "new_string": new_string,
                "error": "Replacement string is longer than the original. Use an equal or shorter string.",
                "old_len": len(old_bytes),
                "new_len": len(new_bytes),
            })
            continue

        target_offsets = _find_bounded_occurrences(bytes(data), old_bytes)
        if not target_offsets:
            results.append({
                "success": False,
                "old_string": old_string,
                "new_string": new_string,
                "error": "Original string not found as a bounded binary string.",
            })
            continue

        if replace_all:
            chosen_offsets = target_offsets
        else:
            if occurrence < 1 or occurrence > len(target_offsets):
                results.append({
                    "success": False,
                    "old_string": old_string,
                    "new_string": new_string,
                    "error": f"Occurrence {occurrence} not found. Total matches: {len(target_offsets)}",
                })
                continue
            chosen_offsets = [target_offsets[occurrence - 1]]

        if exact_len_only:
            replacement_bytes = new_bytes
            mode = "exact_length"
        else:
            replacement_bytes = new_bytes + (b"\x00" * (len(old_bytes) - len(new_bytes)))
            mode = "exact_length" if len(new_bytes) == len(old_bytes) else "null_padded"

        for offset in chosen_offsets:
            data[offset:offset + len(old_bytes)] = replacement_bytes

        total_patched += len(chosen_offsets)
        results.append({
            "success": True,
            "old_string": old_string,
            "new_string": new_string,
            "matches_found": len(target_offsets),
            "patched_occurrences": len(chosen_offsets),
            "offsets": [f"0x{offset:x}" for offset in chosen_offsets],
            "mode": mode,
        })

    if total_patched == 0:
        return {
            "success": False,
            "path": str(path),
            "file_type": suffix,
            "exact_length_required": exact_len_only,
            "replacements": results,
        }

    if backup_path is not None:
        backup = Path(backup_path)
        backup.parent.mkdir(parents=True, exist_ok=True)
        if not backup.exists():
            backup.write_bytes(original)
    else:
        backup = None

    path.write_bytes(bytes(data))

    return {
        "success": True,
        "path": str(path),
        "file_type": suffix,
        "exact_length_required": exact_len_only,
        "patched_operations": total_patched,
        "backup_path": str(backup) if backup else "",
        "replacements": results,
    }