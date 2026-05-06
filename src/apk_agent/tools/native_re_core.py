"""Native reverse-engineering core for ELF/JNI analysis and patch planning.

This module stays dependency-free while providing a materially deeper native
surface than simple string extraction:
  - ELF header and section parsing
  - dynamic/static symbol table recovery
  - imported/exported function inventory
  - JNI export discovery
  - DT_NEEDED dependency extraction
  - heuristic function boundary recovery from executable prologues
  - ranked native patch target planning

It does not claim to be a full disassembler or binary rewriter. The goal is to
give the agent concrete native anchors, offsets, and routeable patch targets so
it can stop treating `.so` files as opaque blobs.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any


_ELF_MAGIC = b"\x7fELF"

_EM_ARCH = {
    0x03: "x86",
    0x28: "arm",
    0x3E: "x86_64",
    0xB7: "arm64",
}

_SHT_SYMTAB = 2
_SHT_STRTAB = 3
_SHT_DYNAMIC = 6
_SHT_DYNSYM = 11

_SHN_UNDEF = 0
_SHF_EXECINSTR = 0x4

_STT_NOTYPE = 0
_STT_OBJECT = 1
_STT_FUNC = 2

_DT_NEEDED = 1

_SYMBOL_KEYWORDS: dict[str, str] = {
    "ptrace": "anti_debug",
    "prctl": "anti_debug",
    "syscall": "anti_debug",
    "tracerpid": "anti_debug",
    "registernatives": "jni_boundary",
    "jni_onload": "jni_boundary",
    "android_dlopen_ext": "dynamic_loading",
    "dlopen": "dynamic_loading",
    "dlsym": "dynamic_loading",
    "ssl_": "tls_ssl",
    "x509_": "tls_ssl",
    "evp_": "crypto",
    "aes": "crypto",
    "rsa": "crypto",
    "hmac": "crypto",
    "frida": "anti_instrumentation",
    "gum": "anti_instrumentation",
    "magisk": "root_detection",
    "xposed": "hook_detection",
    "verify": "guard_logic",
    "pin": "tls_ssl",
    "root": "root_detection",
}

_STRING_PATTERNS: dict[str, re.Pattern[str]] = {
    "url": re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
    "jni_export": re.compile(r"^Java_[A-Za-z0-9_]+"),
    "class_descriptor": re.compile(r"^L[\w/$-]+;$"),
    "crypto": re.compile(r"AES|DES|RSA|SHA|MD5|HMAC|encrypt|decrypt", re.IGNORECASE),
    "tls_ssl": re.compile(r"ssl|x509|trust|pin|certificate|hostname", re.IGNORECASE),
    "anti_debug": re.compile(r"ptrace|tracerpid|debug|frida|gum|gadget", re.IGNORECASE),
    "root_detection": re.compile(r"magisk|xposed|supersu|/system/xbin/su|root", re.IGNORECASE),
}

_PROLOGUE_PATTERNS: dict[str, list[tuple[str, bytes]]] = {
    "arm64": [
        ("arm64_frame", bytes.fromhex("fd7bbfa9")),
        ("arm64_frame_alt", bytes.fromhex("f657bda9")),
    ],
    "x86_64": [
        ("x86_64_frame", bytes.fromhex("554889e5")),
        ("x86_64_frame_alt", bytes.fromhex("41574156")),
    ],
    "x86": [("x86_frame", bytes.fromhex("5589e5"))],
    "arm": [("arm_push_lr", bytes.fromhex("2de9f041"))],
}


def analyze_native_binary(
    file_path: str | Path,
    *,
    focus_hint: str = "",
    max_strings: int = 60,
    max_symbols: int = 120,
    max_targets: int = 16,
) -> dict[str, Any]:
    """Return a detailed ELF/JNI/native patchability view for one library."""
    path = Path(file_path)
    if not path.is_file():
        return {"success": False, "error": f"File not found: {path}"}

    data = path.read_bytes()
    parsed = _parse_elf(data)
    if not parsed.get("success"):
        parsed["path"] = str(path)
        return parsed

    strings = _extract_printable_strings(data, min_length=4, limit=max(max_strings * 4, 120))
    string_findings = _classify_strings(strings)[:max_strings]
    function_candidates = _recover_function_candidates(parsed, data)
    patch_targets = _rank_patch_targets(
        parsed,
        function_candidates,
        string_findings,
        focus_hint=focus_hint,
        max_results=max_targets,
    )

    imports = [symbol for symbol in parsed["symbols"] if symbol["kind"] == "import_function"]
    exports = [symbol for symbol in parsed["symbols"] if symbol["kind"] == "export_function"]
    jni_exports = [symbol for symbol in parsed["symbols"] if symbol["category"] == "jni_export"]
    suspicious_symbols = [symbol for symbol in parsed["symbols"] if symbol["category"] != "generic"]

    return {
        "success": True,
        "path": str(path),
        "file_name": path.name,
        "format": "ELF",
        "arch": parsed["arch"],
        "bits": parsed["bits"],
        "endianness": parsed["endianness"],
        "library_type": _classify_library_type(path.name, parsed, string_findings),
        "needed_libraries": parsed["needed_libraries"],
        "sections": parsed["sections"],
        "section_names": [section["name"] for section in parsed["sections"]],
        "imported_functions_count": len(imports),
        "imported_functions": _limit_named_entries(imports, max_symbols),
        "exported_functions_count": len(exports),
        "exported_functions": _limit_named_entries(exports, max_symbols),
        "jni_export_count": len(jni_exports),
        "jni_exports": _limit_named_entries(jni_exports, 40),
        "suspicious_symbols": _limit_named_entries(suspicious_symbols, 60),
        "function_candidates_count": len(function_candidates),
        "function_candidates": function_candidates[:max_symbols],
        "string_findings_count": len(string_findings),
        "string_findings": string_findings,
        "patch_targets": patch_targets,
        "summary": {
            "imports": len(imports),
            "exports": len(exports),
            "jni_exports": len(jni_exports),
            "function_candidates": len(function_candidates),
            "interesting_strings": len(string_findings),
            "needed_libraries": len(parsed["needed_libraries"]),
        },
    }


def plan_native_patch_targets(
    file_path: str | Path,
    *,
    focus_hint: str = "",
    max_results: int = 12,
) -> dict[str, Any]:
    """Return ranked native patch targets with concrete offsets and strategies."""
    result = analyze_native_binary(
        file_path,
        focus_hint=focus_hint,
        max_strings=max(40, max_results * 4),
        max_symbols=max(80, max_results * 6),
        max_targets=max_results,
    )
    if not result.get("success"):
        return result

    return {
        "success": True,
        "path": result["path"],
        "arch": result["arch"],
        "library_type": result["library_type"],
        "focus_hint": focus_hint,
        "recommended_starting_points": result["patch_targets"][:max_results],
        "summary": result["summary"],
    }


def analyze_native_project(
    apktool_dir: str | Path,
    *,
    focus_hint: str = "",
    max_targets_per_library: int = 4,
) -> dict[str, Any]:
    """Analyze all project native libraries using the deeper ELF/JNI core."""
    apktool_dir = Path(apktool_dir)
    lib_dir = apktool_dir / "lib"
    if not lib_dir.is_dir():
        return {
            "success": True,
            "has_native_libs": False,
            "note": "No lib/ directory found — app has no native libraries.",
        }

    architectures: list[str] = []
    libraries: list[dict[str, Any]] = []
    total_size = 0
    all_jni_names: set[str] = set()
    interesting_strings: list[dict[str, Any]] = []
    framework_hints: set[str] = set()

    for arch_dir in sorted(lib_dir.iterdir()):
        if not arch_dir.is_dir():
            continue
        architectures.append(arch_dir.name)
        for so_file in sorted(arch_dir.glob("*.so")):
            total_size += so_file.stat().st_size
            analysis = analyze_native_binary(so_file, focus_hint=focus_hint, max_targets=max_targets_per_library)
            if not analysis.get("success"):
                libraries.append({
                    "name": so_file.name,
                    "architecture": arch_dir.name,
                    "path": str(so_file.relative_to(apktool_dir)),
                    "error": analysis.get("error", "analysis failed"),
                })
                continue

            for item in analysis.get("jni_exports", []):
                name = str(item.get("name", "")).strip()
                if name:
                    all_jni_names.add(name)
            interesting_strings.extend(analysis.get("string_findings", [])[:6])

            library_kind = str(analysis.get("library_type", "generic_native"))
            if library_kind != "generic_native":
                framework_hints.add(library_kind)

            libraries.append({
                "name": so_file.name,
                "architecture": arch_dir.name,
                "size_kb": round(so_file.stat().st_size / 1024, 1),
                "path": str(so_file.relative_to(apktool_dir)),
                "library_type": analysis.get("library_type", "generic_native"),
                "needed_libraries": analysis.get("needed_libraries", [])[:12],
                "imported_functions_count": analysis.get("imported_functions_count", 0),
                "exported_functions_count": analysis.get("exported_functions_count", 0),
                "jni_export_count": analysis.get("jni_export_count", 0),
                "function_candidates_count": analysis.get("function_candidates_count", 0),
                "jni_methods": [item.get("name", "") for item in analysis.get("jni_exports", [])[:20]],
                "interesting_strings": analysis.get("string_findings", [])[:10],
                "suspicious_symbols": analysis.get("suspicious_symbols", [])[:10],
                "top_patch_targets": analysis.get("patch_targets", [])[:max_targets_per_library],
            })

    return {
        "success": True,
        "has_native_libs": bool(libraries),
        "architectures": sorted(set(architectures)),
        "libraries": libraries,
        "total_size_mb": round(total_size / (1024 * 1024), 2),
        "jni_methods": sorted(all_jni_names),
        "interesting_strings": interesting_strings[:40],
        "framework_hints": sorted(framework_hints),
        "summary": {
            "library_count": len(libraries),
            "jni_method_count": len(all_jni_names),
            "framework_hints": sorted(framework_hints),
        },
    }


def _parse_elf(data: bytes) -> dict[str, Any]:
    if len(data) < 64 or data[:4] != _ELF_MAGIC:
        return {"success": False, "error": "Target file is not a supported ELF binary."}

    elf_class = data[4]
    bits = 64 if elf_class == 2 else 32 if elf_class == 1 else 0
    if bits == 0:
        return {"success": False, "error": f"Unsupported ELF class: {elf_class}"}

    endian_mark = data[5]
    endian = "<" if endian_mark == 1 else ">" if endian_mark == 2 else ""
    if not endian:
        return {"success": False, "error": f"Unsupported ELF endianness marker: {endian_mark}"}

    if bits == 64:
        header = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
        e_machine = header[1]
        e_shoff = header[5]
        e_shentsize = header[10]
        e_shnum = header[11]
        e_shstrndx = header[12]
    else:
        header = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)
        e_machine = header[1]
        e_shoff = header[5]
        e_shentsize = header[10]
        e_shnum = header[11]
        e_shstrndx = header[12]

    sections = _parse_sections(
        data,
        bits=bits,
        endian=endian,
        section_offset=e_shoff,
        section_entry_size=e_shentsize,
        section_count=e_shnum,
        shstr_index=e_shstrndx,
    )
    symbols = _parse_symbols(data, sections, bits=bits, endian=endian)
    needed = _parse_needed_libraries(data, sections, bits=bits, endian=endian)

    return {
        "success": True,
        "bits": bits,
        "endianness": "little" if endian == "<" else "big",
        "arch": _EM_ARCH.get(e_machine, f"machine_{e_machine}"),
        "machine": e_machine,
        "sections": sections,
        "symbols": symbols,
        "needed_libraries": needed,
    }


def _parse_sections(
    data: bytes,
    *,
    bits: int,
    endian: str,
    section_offset: int,
    section_entry_size: int,
    section_count: int,
    shstr_index: int,
) -> list[dict[str, Any]]:
    if not section_offset or not section_count or section_offset >= len(data):
        return []

    sections: list[dict[str, Any]] = []
    fmt = endian + ("IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII")
    size = struct.calcsize(fmt)
    entry_size = section_entry_size or size

    for index in range(section_count):
        start = section_offset + index * entry_size
        if start + size > len(data):
            break
        raw = struct.unpack_from(fmt, data, start)
        if bits == 64:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = raw
        else:
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = raw
        sections.append({
            "index": index,
            "name_offset": sh_name,
            "type": sh_type,
            "flags": sh_flags,
            "address": sh_addr,
            "offset": sh_offset,
            "size": sh_size,
            "link": sh_link,
            "info": sh_info,
            "alignment": sh_addralign,
            "entry_size": sh_entsize,
            "name": "",
            "is_executable": bool(sh_flags & _SHF_EXECINSTR),
        })

    if 0 <= shstr_index < len(sections):
        shstr = sections[shstr_index]
        string_blob = _slice_bytes(data, shstr["offset"], shstr["size"])
        for section in sections:
            section["name"] = _read_c_string(string_blob, section["name_offset"])

    return sections


def _parse_symbols(
    data: bytes,
    sections: list[dict[str, Any]],
    *,
    bits: int,
    endian: str,
) -> list[dict[str, Any]]:
    symbols: list[dict[str, Any]] = []

    for section in sections:
        if section["type"] not in {_SHT_SYMTAB, _SHT_DYNSYM}:
            continue
        entry_size = int(section.get("entry_size") or (24 if bits == 64 else 16))
        if entry_size <= 0:
            entry_size = 24 if bits == 64 else 16
        if section["link"] >= len(sections):
            continue
        string_table = sections[section["link"]]
        string_blob = _slice_bytes(data, string_table["offset"], string_table["size"])
        symbol_blob = _slice_bytes(data, section["offset"], section["size"])

        fmt = endian + ("IBBHQQ" if bits == 64 else "IIIBBH")
        struct_size = struct.calcsize(fmt)

        for offset in range(0, len(symbol_blob), entry_size):
            if offset + struct_size > len(symbol_blob):
                break
            raw = struct.unpack_from(fmt, symbol_blob, offset)
            if bits == 64:
                st_name, st_info, st_other, st_shndx, st_value, st_size = raw
            else:
                st_name, st_value, st_size, st_info, st_other, st_shndx = raw
            if st_name == 0 and st_value == 0 and st_size == 0 and st_info == 0 and st_shndx == 0:
                continue
            name = _read_c_string(string_blob, st_name)
            sym_type = st_info & 0x0F
            bind = st_info >> 4
            symbols.append({
                "name": name,
                "kind": _symbol_kind(sym_type, st_shndx),
                "category": _categorize_symbol(name),
                "symbol_table": section.get("name", ""),
                "type": _symbol_type_name(sym_type),
                "bind": _symbol_bind_name(bind),
                "visibility": st_other & 0x03,
                "section_index": st_shndx,
                "section": _section_name_by_index(sections, st_shndx),
                "value": st_value,
                "value_hex": f"0x{st_value:x}",
                "size": st_size,
            })

    symbols.sort(key=lambda item: (item["value"], item["name"]))
    return symbols


def _parse_needed_libraries(
    data: bytes,
    sections: list[dict[str, Any]],
    *,
    bits: int,
    endian: str,
) -> list[str]:
    needed: list[str] = []
    for section in sections:
        if section["type"] != _SHT_DYNAMIC or section["link"] >= len(sections):
            continue
        dynstr = sections[section["link"]]
        string_blob = _slice_bytes(data, dynstr["offset"], dynstr["size"])
        blob = _slice_bytes(data, section["offset"], section["size"])
        fmt = endian + ("QQ" if bits == 64 else "II")
        entry_size = int(section.get("entry_size") or struct.calcsize(fmt))
        struct_size = struct.calcsize(fmt)
        for offset in range(0, len(blob), entry_size):
            if offset + struct_size > len(blob):
                break
            tag, value = struct.unpack_from(fmt, blob, offset)
            if tag == _DT_NEEDED:
                lib_name = _read_c_string(string_blob, value)
                if lib_name and lib_name not in needed:
                    needed.append(lib_name)
    return needed


def _recover_function_candidates(parsed: dict[str, Any], data: bytes) -> list[dict[str, Any]]:
    sections = parsed.get("sections", [])
    arch = parsed.get("arch", "")
    candidates: list[dict[str, Any]] = []
    seen_offsets: set[int] = set()

    func_symbols = [symbol for symbol in parsed.get("symbols", []) if symbol.get("type") == "FUNC" and symbol.get("kind") != "import_function"]
    func_symbols.sort(key=lambda item: (int(item.get("value", 0)), item.get("name", "")))

    for index, symbol in enumerate(func_symbols):
        value = int(symbol.get("value", 0))
        section = _find_section_for_address(sections, value)
        if not section:
            continue
        file_offset = section["offset"] + max(0, value - section["address"])
        if file_offset in seen_offsets or file_offset >= len(data):
            continue
        size = int(symbol.get("size", 0))
        if size <= 0:
            next_value = _next_symbol_address(func_symbols, index, section)
            if next_value and next_value > value:
                size = next_value - value
        if size <= 0:
            size = min(32, max(0, section["offset"] + section["size"] - file_offset))
        candidates.append({
            "name": symbol.get("name", ""),
            "source": "symbol",
            "category": symbol.get("category", "generic"),
            "section": section.get("name", ""),
            "virtual_address": value,
            "virtual_address_hex": f"0x{value:x}",
            "offset": file_offset,
            "offset_hex": f"0x{file_offset:x}",
            "size": size,
            "anchor_hex": data[file_offset:file_offset + min(size, 16)].hex(),
        })
        seen_offsets.add(file_offset)

    for section in sections:
        if not section.get("is_executable"):
            continue
        section_data = _slice_bytes(data, section["offset"], section["size"])
        for label, pattern in _PROLOGUE_PATTERNS.get(arch, []):
            start = 0
            while True:
                hit = section_data.find(pattern, start)
                if hit < 0:
                    break
                file_offset = section["offset"] + hit
                if not _is_near_existing_offset(file_offset, seen_offsets, window=16):
                    virtual_address = section["address"] + hit
                    candidates.append({
                        "name": f"sub_{virtual_address:x}",
                        "source": "heuristic_prologue",
                        "category": label,
                        "section": section.get("name", ""),
                        "virtual_address": virtual_address,
                        "virtual_address_hex": f"0x{virtual_address:x}",
                        "offset": file_offset,
                        "offset_hex": f"0x{file_offset:x}",
                        "size": 0,
                        "anchor_hex": data[file_offset:file_offset + min(len(pattern) + 12, 16)].hex(),
                    })
                    seen_offsets.add(file_offset)
                start = hit + len(pattern)

    candidates.sort(key=lambda item: (item["offset"], item["name"]))
    return candidates


def _rank_patch_targets(
    parsed: dict[str, Any],
    function_candidates: list[dict[str, Any]],
    string_findings: list[dict[str, Any]],
    *,
    focus_hint: str,
    max_results: int,
) -> list[dict[str, Any]]:
    tokens = {token.lower() for token in re.findall(r"[A-Za-z0-9_.$/-]+", focus_hint or "") if len(token) >= 3}
    targets: list[dict[str, Any]] = []

    for candidate in function_candidates:
        name = str(candidate.get("name", ""))
        category = str(candidate.get("category", "generic"))
        score = 20
        reasons = [f"function candidate from {candidate.get('source', 'analysis')}"]
        if category != "generic":
            score += 18
            reasons.append(f"category={category}")
        if name.startswith("Java_"):
            score += 22
            reasons.append("JNI export boundary")
        for token in tokens:
            if token in name.lower() or token in category.lower():
                score += 28
                reasons.append(f"focus match: {token}")

        targets.append({
            "kind": "function_candidate",
            "name": name,
            "score": score,
            "offset_hex": candidate.get("offset_hex", ""),
            "virtual_address_hex": candidate.get("virtual_address_hex", ""),
            "section": candidate.get("section", ""),
            "source": candidate.get("source", ""),
            "anchor_hex": candidate.get("anchor_hex", ""),
            "recommended_tools": ["patch_binary_hex", "search_native_code", "analyze_native_re_core"],
            "patch_strategy": "Locate this function boundary and use exact-byte or bounded patching around the anchor bytes.",
            "reasons": reasons,
        })

    for symbol in parsed.get("symbols", []):
        name = str(symbol.get("name", ""))
        if not name:
            continue
        category = str(symbol.get("category", "generic"))
        if symbol.get("kind") not in {"import_function", "export_function"} and category == "generic":
            continue
        score = 14
        reasons = [f"symbol kind={symbol.get('kind', '')}"]
        if category != "generic":
            score += 16
            reasons.append(f"category={category}")
        for token in tokens:
            if token in name.lower() or token in category.lower():
                score += 24
                reasons.append(f"focus match: {token}")
        targets.append({
            "kind": symbol.get("kind", "symbol"),
            "name": name,
            "score": score,
            "offset_hex": "",
            "virtual_address_hex": symbol.get("value_hex", ""),
            "section": symbol.get("section", ""),
            "source": symbol.get("symbol_table", ""),
            "recommended_tools": ["search_native_code", "analyze_native_re_core"],
            "patch_strategy": "Use this symbol as a native entry anchor, then recover the surrounding function/body before patching.",
            "reasons": reasons,
        })

    for item in string_findings:
        value = str(item.get("value", ""))
        category = str(item.get("category", "generic"))
        score = 10
        reasons = [f"embedded {category} string"]
        for token in tokens:
            if token in value.lower() or token in category.lower():
                score += 18
                reasons.append(f"focus match: {token}")
        if category in {"tls_ssl", "anti_debug", "root_detection", "jni_export", "crypto"}:
            score += 12
        targets.append({
            "kind": "embedded_string",
            "name": value[:120],
            "score": score,
            "offset_hex": item.get("offset_hex", ""),
            "virtual_address_hex": "",
            "section": item.get("section", ""),
            "source": "string_scan",
            "recommended_tools": ["patch_binary_strings", "patch_binary_hex", "search_binary_strings"],
            "patch_strategy": "Use semantic string patching if the string is a stable behavioral anchor; otherwise pivot from the nearby offset to a code target.",
            "reasons": reasons,
        })

    targets.sort(key=lambda item: (-int(item.get("score", 0)), item.get("name", "")))
    return targets[:max_results]


def _extract_printable_strings(data: bytes, *, min_length: int, limit: int) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    start = -1
    current = bytearray()

    for index, byte_value in enumerate(data):
        if 32 <= byte_value < 127:
            if start < 0:
                start = index
            current.append(byte_value)
            continue
        if len(current) >= min_length:
            value = bytes(current).decode("ascii", errors="ignore")
            results.append({"value": value, "offset": start, "offset_hex": f"0x{start:x}"})
            if len(results) >= limit:
                break
        start = -1
        current.clear()

    if len(results) < limit and len(current) >= min_length and start >= 0:
        value = bytes(current).decode("ascii", errors="ignore")
        results.append({"value": value, "offset": start, "offset_hex": f"0x{start:x}"})

    return results


def _classify_strings(strings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in strings:
        value = str(item.get("value", ""))
        category = "generic"
        for name, pattern in _STRING_PATTERNS.items():
            if pattern.search(value):
                category = name
                break
        if category == "generic":
            continue
        key = (category, value)
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "category": category,
            "value": value[:200],
            "offset": item.get("offset", 0),
            "offset_hex": item.get("offset_hex", ""),
            "section": "",
        })
    return findings


def _classify_library_type(file_name: str, parsed: dict[str, Any], string_findings: list[dict[str, Any]]) -> str:
    lower = file_name.lower()
    if lower == "libflutter.so":
        return "flutter_runtime"
    if lower == "libapp.so" and any(item.get("category") in {"tls_ssl", "crypto", "jni_export"} for item in string_findings):
        return "flutter_or_dart_payload"
    if "il2cpp" in lower:
        return "unity_il2cpp"
    if "hermes" in lower or "reactnative" in lower:
        return "react_native_runtime"
    if any(item.get("name") == "JNI_OnLoad" for item in parsed.get("symbols", [])):
        return "jni_bridge_library"
    return "generic_native"


def _categorize_symbol(name: str) -> str:
    if not name:
        return "generic"
    if name.startswith("Java_") or name in {"JNI_OnLoad", "RegisterNatives"}:
        return "jni_export"
    lower = name.lower()
    for keyword, category in _SYMBOL_KEYWORDS.items():
        if keyword in lower:
            return category
    return "generic"


def _symbol_kind(sym_type: int, shndx: int) -> str:
    if sym_type == _STT_FUNC:
        return "import_function" if shndx == _SHN_UNDEF else "export_function"
    if sym_type == _STT_OBJECT:
        return "import_object" if shndx == _SHN_UNDEF else "export_object"
    return "undefined" if shndx == _SHN_UNDEF else "symbol"


def _symbol_type_name(sym_type: int) -> str:
    if sym_type == _STT_FUNC:
        return "FUNC"
    if sym_type == _STT_OBJECT:
        return "OBJECT"
    if sym_type == _STT_NOTYPE:
        return "NOTYPE"
    return f"TYPE_{sym_type}"


def _symbol_bind_name(bind: int) -> str:
    if bind == 0:
        return "LOCAL"
    if bind == 1:
        return "GLOBAL"
    if bind == 2:
        return "WEAK"
    return f"BIND_{bind}"


def _section_name_by_index(sections: list[dict[str, Any]], index: int) -> str:
    if 0 <= index < len(sections):
        return str(sections[index].get("name", ""))
    return ""


def _read_c_string(blob: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\x00", offset)
    if end < 0:
        end = len(blob)
    return blob[offset:end].decode("utf-8", errors="replace")


def _slice_bytes(data: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size <= 0 or offset >= len(data):
        return b""
    return data[offset:offset + size]


def _find_section_for_address(sections: list[dict[str, Any]], address: int) -> dict[str, Any] | None:
    for section in sections:
        start = int(section.get("address", 0))
        size = int(section.get("size", 0))
        if start <= address < start + size:
            return section
    return None


def _next_symbol_address(symbols: list[dict[str, Any]], index: int, section: dict[str, Any]) -> int | None:
    current = int(symbols[index].get("value", 0))
    section_name = section.get("name", "")
    for future in symbols[index + 1:]:
        value = int(future.get("value", 0))
        if value > current and future.get("section", "") == section_name:
            return value
    return None


def _is_near_existing_offset(offset: int, seen_offsets: set[int], *, window: int) -> bool:
    return any(abs(offset - existing) <= window for existing in seen_offsets)


def _limit_named_entries(entries: list[dict[str, Any]], max_results: int) -> list[dict[str, Any]]:
    return [entry for entry in entries if entry.get("name")][:max_results]