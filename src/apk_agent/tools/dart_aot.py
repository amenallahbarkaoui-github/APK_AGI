"""Lightweight Flutter Dart AOT helpers for Android release builds.

This module does not try to fully decode Dart VM snapshots. The MVP focuses on
three practical capabilities for `libapp.so`:

1. Fingerprint ELF/native characteristics and detect Flutter/Dart AOT signals.
2. Build a searchable index of printable strings and code-adjacent anchors.
3. Locate candidate regions for business-logic patches using anchors/hints.

The output is intentionally structured so the agent can reason about what is
supported instead of claiming generic Dart bytecode patching.
"""

from __future__ import annotations

import json
import re
import struct
import shutil
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


_PRINTABLE_MIN = 32
_PRINTABLE_MAX = 126
_DEFAULT_WINDOW_BYTES = 4096
_DEFAULT_MAX_MATCHES = 25
_INDEX_VERSION = 1

_FLUTTER_STRING_HINTS = (
    "flutter",
    "dart",
    "methodchannel",
    "platformexception",
    "missingpluginexception",
    "_userprovider",
    "provider",
    "paywall",
    "purchase",
    "wallet",
    "subscription",
    "entitlement",
    "revenuecat",
)

_DART_AOT_SUPPORT_NOTES = {
    "strong": "Strong Flutter/Dart AOT signals found in ELF/native payload.",
    "weak": "ELF/native file is readable but Flutter/Dart-specific markers are sparse.",
    "unsupported": "File does not look like a supported Android ELF shared library.",
}


@dataclass
class ElfSection:
    name: str
    offset: int
    size: int
    addr: int
    flags: int
    section_type: int


@dataclass
class DartAotFingerprint:
    success: bool
    path: str
    file_size: int
    file_type: str
    arch: str = "unknown"
    bitness: int = 0
    endian: str = "unknown"
    machine: int = 0
    is_shared_object: bool = False
    has_flutter_markers: bool = False
    has_dart_markers: bool = False
    support_level: str = "unsupported"
    build_id: str = ""
    section_names: list[str] = field(default_factory=list)
    candidate_snapshot_ranges: list[dict[str, Any]] = field(default_factory=list)
    string_hint_counts: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _decode_ascii(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("ascii", errors="ignore")


def _arch_name(machine: int) -> tuple[str, int]:
    mapping = {
        0x03: ("x86", 32),
        0x28: ("arm", 32),
        0x3E: ("x86_64", 64),
        0xB7: ("arm64", 64),
    }
    return mapping.get(machine, (f"machine_{machine}", 0))


def _iter_printable_strings(data: bytes, min_length: int = 4):
    start = -1
    current = bytearray()

    for idx, value in enumerate(data):
        if _PRINTABLE_MIN <= value <= _PRINTABLE_MAX:
            if start < 0:
                start = idx
            current.append(value)
            continue

        if len(current) >= min_length:
            text = bytes(current).decode("ascii", errors="ignore")
            yield {
                "value": text,
                "offset": start,
                "offset_hex": f"0x{start:x}",
                "length": len(current),
            }
        start = -1
        current.clear()

    if len(current) >= min_length:
        text = bytes(current).decode("ascii", errors="ignore")
        yield {
            "value": text,
            "offset": start,
            "offset_hex": f"0x{start:x}",
            "length": len(current),
        }


def _read_elf_sections(data: bytes) -> tuple[list[ElfSection], list[str]]:
    errors: list[str] = []
    if len(data) < 0x40 or data[:4] != b"\x7fELF":
        return [], ["Not an ELF file."]

    ei_class = data[4]
    ei_data = data[5]
    is_64 = ei_class == 2
    little = ei_data == 1
    if ei_class not in (1, 2):
        return [], [f"Unsupported ELF class: {ei_class}"]
    if ei_data not in (1, 2):
        return [], [f"Unsupported ELF endianness: {ei_data}"]

    prefix = "<" if little else ">"
    try:
        if is_64:
            header = struct.unpack_from(prefix + "HHIQQQIHHHHHH", data, 16)
            _, _, _, _, _, shoff, _, _, _, _, shentsize, shnum, shstrndx = header
            sh_fmt = prefix + "IIQQQQIIQQ"
        else:
            header = struct.unpack_from(prefix + "HHIIIIIHHHHHH", data, 16)
            _, _, _, _, _, shoff, _, _, _, _, shentsize, shnum, shstrndx = header
            sh_fmt = prefix + "IIIIIIIIII"
    except struct.error as exc:
        return [], [f"ELF header parse failed: {exc}"]

    if not shoff or not shnum or not shentsize:
        return [], ["ELF has no section table."]

    try:
        shstr_off = shoff + (shstrndx * shentsize)
        if is_64:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(sh_fmt, data, shstr_off)
        else:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(sh_fmt, data, shstr_off)
        shstr = data[sh_offset: sh_offset + sh_size]
    except struct.error as exc:
        return [], [f"ELF section string table parse failed: {exc}"]

    sections: list[ElfSection] = []
    for idx in range(shnum):
        entry_off = shoff + (idx * shentsize)
        try:
            values = struct.unpack_from(sh_fmt, data, entry_off)
        except struct.error:
            errors.append(f"Section {idx} header truncated.")
            continue

        if is_64:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = values
        else:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = values

        name = _decode_ascii(shstr[sh_name:]) if sh_name < len(shstr) else f"section_{idx}"
        sections.append(
            ElfSection(
                name=name,
                offset=int(sh_offset),
                size=int(sh_size),
                addr=int(sh_addr),
                flags=int(sh_flags),
                section_type=int(sh_type),
            )
        )
    return sections, errors


def _extract_build_id(data: bytes) -> str:
    marker = b"GNU"
    idx = data.find(marker)
    if idx < 0:
        return ""
    start = max(0, idx - 32)
    end = min(len(data), idx + 96)
    blob = data[start:end]
    hexish = re.findall(rb"[0-9a-f]{16,64}", blob, re.IGNORECASE)
    if hexish:
        return hexish[0].decode("ascii", errors="ignore")
    return ""


def _section_snapshot_ranges(sections: list[ElfSection]) -> list[dict[str, Any]]:
    ranges: list[dict[str, Any]] = []
    for section in sections:
        lname = section.name.lower()
        if lname in {".text", ".rodata", ".data.rel.ro", ".dynstr"} or "rodata" in lname or "text" in lname:
            ranges.append({
                "name": section.name,
                "offset": section.offset,
                "offset_hex": f"0x{section.offset:x}",
                "size": section.size,
                "addr": section.addr,
                "addr_hex": f"0x{section.addr:x}",
            })
    return ranges[:20]


def analyze_dart_aot(file_path: str | Path) -> dict[str, Any]:
    path = Path(file_path)
    if not path.is_file():
        return {
            "success": False,
            "error": f"File not found: {path}",
        }

    data = path.read_bytes()
    sections, section_errors = _read_elf_sections(data)

    fingerprint = DartAotFingerprint(
        success=True,
        path=str(path),
        file_size=len(data),
        file_type=path.suffix.lower() or "binary",
        section_names=[section.name for section in sections[:40]],
        candidate_snapshot_ranges=_section_snapshot_ranges(sections),
        errors=section_errors[:10],
    )

    if data[:4] != b"\x7fELF":
        fingerprint.success = False
        fingerprint.support_level = "unsupported"
        fingerprint.notes.append(_DART_AOT_SUPPORT_NOTES["unsupported"])
        return asdict(fingerprint)

    ei_class = data[4]
    ei_data = data[5]
    little = ei_data == 1
    prefix = "<" if little else ">"
    fingerprint.endian = "little" if little else "big"
    fingerprint.bitness = 64 if ei_class == 2 else 32 if ei_class == 1 else 0

    try:
        header = struct.unpack_from(prefix + ("HHIQQQIHHHHHH" if fingerprint.bitness == 64 else "HHIIIIIHHHHHH"), data, 16)
        e_type = int(header[0])
        e_machine = int(header[1])
        fingerprint.machine = e_machine
        fingerprint.arch, _ = _arch_name(e_machine)
        fingerprint.is_shared_object = e_type == 3
    except struct.error as exc:
        fingerprint.errors.append(f"ELF machine parse failed: {exc}")

    strings = list(_iter_printable_strings(data, min_length=4))
    counter: Counter[str] = Counter()
    for entry in strings:
        lowered = entry["value"].lower()
        for hint in _FLUTTER_STRING_HINTS:
            if hint in lowered:
                counter[hint] += 1

    fingerprint.string_hint_counts = dict(counter)
    fingerprint.has_flutter_markers = any(k in counter for k in ("flutter", "methodchannel", "missingpluginexception"))
    fingerprint.has_dart_markers = any(k in counter for k in ("dart", "platformexception", "_userprovider", "paywall", "purchase"))
    fingerprint.build_id = _extract_build_id(data)

    if fingerprint.is_shared_object and (fingerprint.has_flutter_markers or fingerprint.has_dart_markers):
        fingerprint.support_level = "strong"
    elif fingerprint.is_shared_object:
        fingerprint.support_level = "weak"
    else:
        fingerprint.support_level = "unsupported"

    fingerprint.notes.append(_DART_AOT_SUPPORT_NOTES[fingerprint.support_level])
    if fingerprint.support_level != "unsupported":
        fingerprint.notes.append(
            "This analyzer is heuristic: it locates anchors and candidate regions, not full Dart VM function recovery."
        )

    return asdict(fingerprint)


def _strings_near_offset(strings: list[dict[str, Any]], target_offset: int, window_bytes: int) -> list[dict[str, Any]]:
    matches = []
    start = max(0, target_offset - window_bytes)
    end = target_offset + window_bytes
    for entry in strings:
        if start <= int(entry["offset"]) <= end:
            matches.append(entry)
    return matches[:25]


def build_dart_aot_index(file_path: str | Path, *, output_path: str | Path | None = None) -> dict[str, Any]:
    path = Path(file_path)
    if not path.is_file():
        return {"success": False, "error": f"File not found: {path}"}

    data = path.read_bytes()
    fingerprint = analyze_dart_aot(path)
    if not fingerprint.get("success"):
        return fingerprint

    strings = list(_iter_printable_strings(data, min_length=4))
    strings_sorted = sorted(strings, key=lambda item: int(item["offset"]))
    top_hints: list[dict[str, Any]] = []
    for entry in strings_sorted:
        lowered = entry["value"].lower()
        matched_hints = [hint for hint in _FLUTTER_STRING_HINTS if hint in lowered]
        if matched_hints:
            top_hints.append({
                **entry,
                "matched_hints": matched_hints,
            })

    sections, _ = _read_elf_sections(data)
    index = {
        "success": True,
        "index_version": _INDEX_VERSION,
        "path": str(path),
        "file_size": len(data),
        "fingerprint": fingerprint,
        "sections": [asdict(section) for section in sections[:40]],
        "stats": {
            "total_strings": len(strings_sorted),
            "matched_hint_strings": len(top_hints),
            "support_level": fingerprint.get("support_level", "unsupported"),
        },
        "strings": strings_sorted,
        "hint_strings": top_hints[:400],
    }

    if output_path is not None:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        temp = output.with_suffix(output.suffix + ".tmp")
        temp.write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(output)
        index["output_file"] = str(output)

    return index


def locate_dart_aot_candidates(
    index_or_path: str | Path | dict[str, Any],
    *,
    query: str = "",
    anchors: list[str] | None = None,
    window_bytes: int = _DEFAULT_WINDOW_BYTES,
    max_matches: int = _DEFAULT_MAX_MATCHES,
) -> dict[str, Any]:
    if isinstance(index_or_path, dict):
        index = index_or_path
    else:
        path = Path(index_or_path)
        if path.is_file() and path.suffix.lower() == ".json":
            index = json.loads(path.read_text(encoding="utf-8"))
        else:
            index = build_dart_aot_index(path)

    if not isinstance(index, dict) or not index.get("success"):
        return {"success": False, "error": "Invalid or unsuccessful Dart AOT index input."}

    strings = list(index.get("strings") or [])
    if not strings:
        return {"success": False, "error": "Index contains no extracted strings."}

    anchors = [str(item).strip() for item in (anchors or []) if str(item).strip()]
    effective_terms = anchors[:]
    if query.strip():
        effective_terms.append(query.strip())
    if not effective_terms:
        effective_terms = ["flutter", "dart"]

    pattern_cache = []
    for term in effective_terms:
        try:
            pattern_cache.append((term, re.compile(term, re.IGNORECASE)))
        except re.error:
            pattern_cache.append((term, re.compile(re.escape(term), re.IGNORECASE)))

    matched: list[dict[str, Any]] = []
    sections = index.get("sections", [])
    
    for entry in strings:
        lowered = entry["value"]
        hit_terms = [term for term, regex in pattern_cache if regex.search(lowered)]
        if not hit_terms:
            continue
        
        offset_val = int(entry["offset"])
        section_name = ""
        for sec in sections:
            if sec["offset"] <= offset_val < sec["offset"] + sec["size"]:
                section_name = sec["name"]
                break
                
        neighborhood = _strings_near_offset(strings, offset_val, window_bytes)
        neighborhood_values = [n["value"] for n in neighborhood]
        confidence = min(0.99, 0.35 + (0.12 * len(hit_terms)) + (0.01 * min(len(neighborhood), 20)))
        
        if ".rodata" in section_name:
            confidence = min(0.99, confidence + 0.15)
        elif ".text" in section_name:
            confidence = min(0.99, confidence + 0.05)
            
        suggestion = "inspect_nearby_branch_or_constant"
        if any(hint in entry["value"].lower() for hint in ("purchase", "wallet", "subscription", "entitlement")):
            suggestion = "candidate_business_logic_gate"
        matched.append({
            "offset": offset_val,
            "section": section_name,
            "offset_hex": entry["offset_hex"],
            "value": entry["value"],
            "matched_terms": hit_terms,
            "confidence": round(confidence, 2),
            "suggested_patch_kind": suggestion,
            "nearby_strings": neighborhood_values[:12],
            "window_start_hex": f"0x{max(0, offset_val - window_bytes):x}",
            "window_end_hex": f"0x{offset_val + window_bytes:x}",
        })
        if len(matched) >= max_matches:
            break

    matched.sort(key=lambda item: (-float(item["confidence"]), int(item["offset"])))
    return {
        "success": True,
        "path": index.get("path", ""),
        "query": query,
        "anchors": anchors,
        "matches_returned": len(matched),
        "matches": matched,
        "summary": (
            f"Located {len(matched)} candidate Dart AOT anchor regions from {len(effective_terms)} search term(s). "
            "Use the returned offsets/windows to plan bounded native patches instead of assuming full Dart symbol recovery."
        ),
    }


def preview_dart_aot_patch(file_path: str | Path, patch_plan: dict[str, Any]) -> dict[str, Any]:
    path = Path(file_path)
    if not path.is_file():
        return {"success": False, "error": f"File not found: {path}"}

    offset = int(patch_plan.get("offset", -1))
    replace_hex = str(patch_plan.get("replace_hex") or "")
    if offset < 0 or not replace_hex:
        return {"success": False, "error": "Patch plan must include offset and replace_hex."}

    cleaned = replace_hex.replace("\\x", "").replace("0x", "")
    cleaned = "".join(cleaned.split())
    if len(cleaned) % 2 != 0:
        return {"success": False, "error": "replace_hex has odd length."}
    replace = bytes.fromhex(cleaned)
    data = path.read_bytes()
    original_len = len(replace)
    if offset + original_len > len(data):
        return {"success": False, "error": "Patch extends past end of file."}

    original = data[offset: offset + original_len]
    expected_original_hex = str(patch_plan.get("expected_original_hex") or "").strip().lower()
    if expected_original_hex:
        expected_original_hex = "".join(expected_original_hex.replace("\\x", "").replace("0x", "").split())
        if original.hex() != expected_original_hex:
            return {
                "success": False,
                "error": "Original bytes do not match expected_original_hex.",
                "actual_original_hex": original.hex(),
                "expected_original_hex": expected_original_hex,
            }

    return {
        "success": True,
        "path": str(path),
        "offset": offset,
        "offset_hex": f"0x{offset:x}",
        "byte_length": len(replace),
        "original_hex": original.hex(),
        "replace_hex": replace.hex(),
        "description": patch_plan.get("description", ""),
        "validation_rules": [
            "Patch is bounded to exact byte length.",
            "Caller should keep a backup before apply.",
            "Caller should validate original bytes again at apply-time.",
        ],
    }


def validate_dart_aot_patch(file_path: str | Path, *, offset: int, expected_hex: str) -> dict[str, Any]:
    path = Path(file_path)
    if not path.is_file():
        return {"success": False, "error": f"File not found: {path}"}

    cleaned = "".join(str(expected_hex or "").replace("\\x", "").replace("0x", "").split())
    if not cleaned or len(cleaned) % 2 != 0:
        return {"success": False, "error": "expected_hex is empty or malformed."}
    expected = bytes.fromhex(cleaned)
    data = path.read_bytes()
    if offset < 0 or offset + len(expected) > len(data):
        return {"success": False, "error": "Validation range is outside file bounds."}

    actual = data[offset: offset + len(expected)]
    return {
        "success": actual == expected,
        "path": str(path),
        "offset": offset,
        "offset_hex": f"0x{offset:x}",
        "expected_hex": expected.hex(),
        "actual_hex": actual.hex(),
    }
def apply_dart_aot_patch(
    file_path: str | Path,
    patch_plan: dict[str, Any],
    backup_dir: str | Path | None = None
) -> dict[str, Any]:
    path = Path(file_path)
    if not path.is_file():
        return {"success": False, "error": f"File not found: {path}"}

    preview = preview_dart_aot_patch(file_path, patch_plan)
    if not preview.get("success"):
        return preview

    try:
        backup_path = None
        if backup_dir:
            bd = Path(backup_dir)
            bd.mkdir(parents=True, exist_ok=True)
            backup_path = bd / f"{path.name}.bak"
            shutil.copy2(path, backup_path)
        
        data = bytearray(path.read_bytes())
        
        offset = preview["offset"]
        replace_bytes = bytes.fromhex(preview["replace_hex"])
        data[offset : offset + len(replace_bytes)] = replace_bytes
        
        path.write_bytes(data)
        
        return {
            "success": True,
            "path": str(path),
            "backup_path": str(backup_path) if backup_path else None,
            "offset": preview["offset"],
            "offset_hex": preview["offset_hex"],
            "original_hex": preview["original_hex"],
            "replace_hex": preview["replace_hex"],
            "bytes_written": len(replace_bytes)
        }
    except Exception as e:
        return {"success": False, "error": f"Patch application failed: {e}"}
