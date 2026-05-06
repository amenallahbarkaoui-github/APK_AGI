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

from apk_agent.tools.binary_patch import (
    describe_unsupported_binary_artifact,
    is_unsupported_binary_artifact,
)


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

_SMALI_CLASS_RE = re.compile(r"^\.class\b.*?\s(?P<descriptor>L[^;]+;)")
_SMALI_METHOD_RE = re.compile(
    r"^\.method\b(?P<qualifiers>.*?)\s(?P<name>[A-Za-z0-9_$<>-]+)\((?P<params>[^)]*)\)(?P<ret>\S+)"
)
_SMALI_CONST_STRING_RE = re.compile(r'const-string(?:/jumbo)?\s+\S+,\s+"(?P<value>[^"]+)"')
_SMALI_LOAD_LIBRARY_RE = re.compile(r"Ljava/lang/(?:System|Runtime);->(?:loadLibrary|load)\(")


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

    if is_unsupported_binary_artifact(path):
        return {
            "success": False,
            "path": str(path),
            "error": describe_unsupported_binary_artifact(
                path,
                supported_targets_hint=(
                    "Native RE tools only support app native libraries such as `.so` / ELF binaries, "
                    "typically under `lib/` in the decoded APK."
                ),
            ),
        }

    data = path.read_bytes()
    parsed = _parse_elf(data)
    if not parsed.get("success"):
        parsed["path"] = str(path)
        return parsed

    strings = _extract_printable_strings(data, min_length=4, limit=max(max_strings * 4, 120))
    string_findings = _classify_strings(strings)[:max_strings]
    function_candidates = _recover_function_candidates(parsed, data)
    disassembly_previews = _build_disassembly_previews(parsed, data, function_candidates)
    jni_trace = _build_binary_jni_trace(parsed, function_candidates, disassembly_previews, string_findings)
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
        "jni_trace_count": len(jni_trace),
        "jni_trace": jni_trace,
        "suspicious_symbols": _limit_named_entries(suspicious_symbols, 60),
        "function_candidates_count": len(function_candidates),
        "function_candidates": function_candidates[:max_symbols],
        "disassembly_preview_count": len(disassembly_previews),
        "disassembly_previews": disassembly_previews,
        "string_findings_count": len(string_findings),
        "string_findings": string_findings,
        "patch_targets": patch_targets,
        "summary": {
            "imports": len(imports),
            "exports": len(exports),
            "jni_exports": len(jni_exports),
            "jni_trace_entries": len(jni_trace),
            "function_candidates": len(function_candidates),
            "disassembly_previews": len(disassembly_previews),
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
    binary_jni_entries: list[dict[str, Any]] = []
    per_library_binary_traces: dict[str, list[dict[str, Any]]] = {}

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
            binary_trace_items = [
                {
                    **entry,
                    "library_path": str(so_file.relative_to(apktool_dir)),
                    "library_name": so_file.name,
                    "library_basename": _library_basename(so_file.name),
                    "architecture": arch_dir.name,
                }
                for entry in analysis.get("jni_trace", [])
            ]
            binary_jni_entries.extend(binary_trace_items)
            per_library_binary_traces[str(so_file.relative_to(apktool_dir))] = binary_trace_items

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
                "jni_trace": analysis.get("jni_trace", [])[:8],
                "disassembly_previews": analysis.get("disassembly_previews", [])[:4],
                "interesting_strings": analysis.get("string_findings", [])[:10],
                "suspicious_symbols": analysis.get("suspicious_symbols", [])[:10],
                "top_patch_targets": analysis.get("patch_targets", [])[:max_targets_per_library],
            })

    project_jni = _scan_project_jni_surfaces(apktool_dir, binary_jni_entries)

    return {
        "success": True,
        "has_native_libs": bool(libraries),
        "architectures": sorted(set(architectures)),
        "libraries": libraries,
        "total_size_mb": round(total_size / (1024 * 1024), 2),
        "jni_methods": sorted(all_jni_names),
        "jni_traces": project_jni["jni_traces"],
        "native_method_declarations": project_jni["native_method_declarations"],
        "load_library_calls": project_jni["load_library_calls"],
        "interesting_strings": interesting_strings[:40],
        "framework_hints": sorted(framework_hints),
        "summary": {
            "library_count": len(libraries),
            "jni_method_count": len(all_jni_names),
            "jni_trace_count": len(project_jni["jni_traces"]),
            "native_method_declaration_count": len(project_jni["native_method_declarations"]),
            "load_library_call_count": len(project_jni["load_library_calls"]),
            "framework_hints": sorted(framework_hints),
        },
    }


def _build_disassembly_previews(
    parsed: dict[str, Any],
    data: bytes,
    function_candidates: list[dict[str, Any]],
    *,
    max_windows: int = 12,
    max_instructions: int = 8,
) -> list[dict[str, Any]]:
    arch = str(parsed.get("arch") or "")
    if arch not in {"arm64", "arm"}:
        return []

    prioritized = sorted(
        function_candidates,
        key=lambda item: (
            0 if item.get("category") not in {"generic", ""} else 1,
            0 if item.get("source") == "symbol" else 1,
            int(item.get("offset", 0)),
        ),
    )
    previews: list[dict[str, Any]] = []
    seen_offsets: set[int] = set()

    for candidate in prioritized:
        offset = int(candidate.get("offset", -1) or -1)
        if offset < 0 or offset in seen_offsets or offset >= len(data):
            continue
        virtual_address = int(candidate.get("virtual_address", 0) or 0)
        size = int(candidate.get("size", 0) or 0)
        window_size = _preview_window_size(arch, size=size, max_instructions=max_instructions)
        code_blob = _slice_bytes(data, offset, window_size)
        instructions = _disassemble_preview(
            arch,
            code_blob,
            start_address=virtual_address,
            max_instructions=max_instructions,
        )
        if not instructions:
            continue
        previews.append({
            "function_name": str(candidate.get("name", "")),
            "source": str(candidate.get("source", "")),
            "category": str(candidate.get("category", "generic")),
            "offset": offset,
            "offset_hex": str(candidate.get("offset_hex", f"0x{offset:x}")),
            "virtual_address": virtual_address,
            "virtual_address_hex": str(candidate.get("virtual_address_hex", f"0x{virtual_address:x}")),
            "instruction_count": len(instructions),
            "instructions": instructions,
        })
        seen_offsets.add(offset)
        if len(previews) >= max_windows:
            break

    return previews


def _preview_window_size(arch: str, *, size: int, max_instructions: int) -> int:
    if arch == "arm64":
        default_size = max_instructions * 4
    elif arch == "arm":
        default_size = max_instructions * 4
    else:
        default_size = max_instructions * 4
    if size > 0:
        return min(size, default_size)
    return default_size


def _disassemble_preview(
    arch: str,
    code_blob: bytes,
    *,
    start_address: int,
    max_instructions: int,
) -> list[dict[str, Any]]:
    if arch == "arm64":
        return _disassemble_arm64_preview(code_blob, start_address=start_address, max_instructions=max_instructions)
    if arch == "arm":
        return _disassemble_arm_preview(code_blob, start_address=start_address, max_instructions=max_instructions)
    return []


def _disassemble_arm64_preview(
    code_blob: bytes,
    *,
    start_address: int,
    max_instructions: int,
) -> list[dict[str, Any]]:
    instructions: list[dict[str, Any]] = []
    limit = min(len(code_blob) // 4, max_instructions)
    for index in range(limit):
        offset = index * 4
        raw = code_blob[offset:offset + 4]
        word = int.from_bytes(raw, "little")
        address = start_address + offset
        mnemonic, op_str = _decode_arm64_instruction(word, address)
        instructions.append({
            "address": address,
            "address_hex": f"0x{address:x}",
            "raw_hex": raw.hex(),
            "mnemonic": mnemonic,
            "op_str": op_str,
        })
        if mnemonic == "ret":
            break
    return instructions


def _decode_arm64_instruction(word: int, address: int) -> tuple[str, str]:
    if word == 0xD503201F:
        return "nop", ""

    if word & 0xFFFFFC1F == 0xD65F0000:
        reg = (word >> 5) & 0x1F
        return "ret", _aarch64_reg_name(reg)

    if word & 0xFC000000 == 0x94000000:
        imm26 = _sign_extend(word & 0x03FFFFFF, 26) << 2
        return "bl", f"0x{address + imm26:x}"

    if word & 0xFC000000 == 0x14000000:
        imm26 = _sign_extend(word & 0x03FFFFFF, 26) << 2
        return "b", f"0x{address + imm26:x}"

    if word & 0x7F000000 in {0x34000000, 0x35000000}:
        imm19 = _sign_extend((word >> 5) & 0x7FFFF, 19) << 2
        register = word & 0x1F
        mnemonic = "cbz" if (word & 0x7F000000) == 0x34000000 else "cbnz"
        reg_prefix = "x" if ((word >> 31) & 0x1) else "w"
        return mnemonic, f"{reg_prefix}{register}, 0x{address + imm19:x}"

    if word & 0xFFC00000 == 0xA9800000:
        rt = word & 0x1F
        rn = (word >> 5) & 0x1F
        rt2 = (word >> 10) & 0x1F
        imm7 = _sign_extend((word >> 15) & 0x7F, 7) * 8
        return "stp", (
            f"{_aarch64_reg_name(rt)}, {_aarch64_reg_name(rt2)}, "
            f"[{_aarch64_reg_name(rn, allow_sp=True)}, #{imm7}]!"
        )

    if word & 0xFFC00000 == 0xA8C00000:
        rt = word & 0x1F
        rn = (word >> 5) & 0x1F
        rt2 = (word >> 10) & 0x1F
        imm7 = _sign_extend((word >> 15) & 0x7F, 7) * 8
        return "ldp", (
            f"{_aarch64_reg_name(rt)}, {_aarch64_reg_name(rt2)}, "
            f"[{_aarch64_reg_name(rn, allow_sp=True)}], #{imm7}"
        )

    if word & 0xFF0003E0 == 0x910003E0:
        rd = word & 0x1F
        imm12 = (word >> 10) & 0xFFF
        if imm12 == 0:
            return "mov", f"{_aarch64_reg_name(rd)}, sp"
        return "add", f"{_aarch64_reg_name(rd)}, sp, #{imm12}"

    return ".word", f"0x{word:08x}"


def _aarch64_reg_name(register: int, *, allow_sp: bool = False) -> str:
    if register == 31:
        return "sp" if allow_sp else "xzr"
    return f"x{register}"


def _disassemble_arm_preview(
    code_blob: bytes,
    *,
    start_address: int,
    max_instructions: int,
) -> list[dict[str, Any]]:
    instructions: list[dict[str, Any]] = []
    offset = 0
    while offset < len(code_blob) and len(instructions) < max_instructions:
        address = start_address + offset

        if offset + 4 <= len(code_blob):
            window = code_blob[offset:offset + 4]
            if window == bytes.fromhex("2de9f041"):
                instructions.append({
                    "address": address,
                    "address_hex": f"0x{address:x}",
                    "raw_hex": window.hex(),
                    "mnemonic": "push.w",
                    "op_str": "{r4-r8, lr}",
                })
                offset += 4
                continue

        if offset + 2 > len(code_blob):
            break

        halfword_blob = code_blob[offset:offset + 2]
        halfword = int.from_bytes(halfword_blob, "little")
        mnemonic = ".hword"
        op_str = f"0x{halfword:04x}"
        step = 2

        if halfword == 0x4770:
            mnemonic = "bx"
            op_str = "lr"
        elif halfword == 0xBF00:
            mnemonic = "nop"
            op_str = ""
        elif halfword & 0xFE00 == 0xB400:
            mnemonic = "push"
            op_str = _format_thumb_reg_list(halfword & 0x01FF, include_lr=bool(halfword & 0x0100))
        elif halfword & 0xFE00 == 0xBC00:
            mnemonic = "pop"
            op_str = _format_thumb_reg_list(halfword & 0x01FF, include_pc=bool(halfword & 0x0100))
        elif halfword & 0xF800 == 0xE000:
            imm11 = _sign_extend(halfword & 0x07FF, 11) << 1
            mnemonic = "b"
            op_str = f"0x{address + 4 + imm11:x}"

        instructions.append({
            "address": address,
            "address_hex": f"0x{address:x}",
            "raw_hex": code_blob[offset:offset + step].hex(),
            "mnemonic": mnemonic,
            "op_str": op_str,
        })
        offset += step
        if mnemonic == "bx" and op_str == "lr":
            break

    return instructions


def _format_thumb_reg_list(mask: int, *, include_lr: bool = False, include_pc: bool = False) -> str:
    registers = [f"r{index}" for index in range(8) if mask & (1 << index)]
    if include_lr and "lr" not in registers:
        registers.append("lr")
    if include_pc and "pc" not in registers:
        registers.append("pc")
    return "{" + ", ".join(registers) + "}"


def _sign_extend(value: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    return (value ^ sign_bit) - sign_bit


def _build_binary_jni_trace(
    parsed: dict[str, Any],
    function_candidates: list[dict[str, Any]],
    disassembly_previews: list[dict[str, Any]],
    string_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidate_by_name = {
        str(candidate.get("name", "")): candidate
        for candidate in function_candidates
        if candidate.get("name")
    }
    preview_by_name = {
        str(preview.get("function_name", "")): preview
        for preview in disassembly_previews
        if preview.get("function_name")
    }

    trace: list[dict[str, Any]] = []
    for symbol in parsed.get("symbols", []):
        name = str(symbol.get("name", ""))
        if not name:
            continue
        if name.startswith("Java_"):
            decoded = _decode_jni_export_name(name)
            candidate = candidate_by_name.get(name, {})
            preview = preview_by_name.get(name, {})
            trace.append({
                "kind": "static_jni_export",
                "symbol": name,
                "java_class": decoded.get("java_class", ""),
                "class_descriptor": decoded.get("class_descriptor", ""),
                "java_method": decoded.get("java_method", ""),
                "registration": "static_export",
                "virtual_address_hex": str(symbol.get("value_hex", "")),
                "offset_hex": str(candidate.get("offset_hex", "")),
                "evidence": [
                    "exported Java_* symbol",
                    f"section={symbol.get('section', '')}" if symbol.get("section") else "symbol table hit",
                ],
                "disassembly_preview": preview.get("instructions", [])[:4],
            })
            continue

        if name == "JNI_OnLoad":
            candidate = candidate_by_name.get(name, {})
            preview = preview_by_name.get(name, {})
            trace.append({
                "kind": "jni_onload",
                "symbol": name,
                "registration": "dynamic_bootstrap",
                "virtual_address_hex": str(symbol.get("value_hex", "")),
                "offset_hex": str(candidate.get("offset_hex", "")),
                "evidence": ["JNI_OnLoad export found"],
                "disassembly_preview": preview.get("instructions", [])[:4],
            })
            continue

        if name == "RegisterNatives":
            trace.append({
                "kind": "register_natives_symbol",
                "symbol": name,
                "registration": "dynamic_registration",
                "virtual_address_hex": str(symbol.get("value_hex", "")),
                "offset_hex": "",
                "evidence": [f"symbol kind={symbol.get('kind', '')}"],
                "disassembly_preview": [],
            })

    if any(item.get("category") == "jni_export" and item.get("value") == "JNI_OnLoad" for item in string_findings):
        trace.append({
            "kind": "jni_onload_string",
            "symbol": "JNI_OnLoad",
            "registration": "dynamic_bootstrap",
            "virtual_address_hex": "",
            "offset_hex": next((item.get("offset_hex", "") for item in string_findings if item.get("value") == "JNI_OnLoad"), ""),
            "evidence": ["JNI_OnLoad string anchor"],
            "disassembly_preview": [],
        })

    if any(
        str(symbol.get("name", "")).lower() == "registernatives"
        or str(symbol.get("category", "")) == "jni_boundary"
        for symbol in parsed.get("symbols", [])
    ):
        trace.append({
            "kind": "dynamic_registration_signal",
            "symbol": "RegisterNatives",
            "registration": "dynamic_registration",
            "virtual_address_hex": "",
            "offset_hex": "",
            "evidence": ["RegisterNatives or JNI boundary signal found in symbols"],
            "disassembly_preview": [],
        })

    trace.sort(key=lambda item: (item.get("kind", ""), item.get("symbol", "")))
    return trace


def _decode_jni_export_name(symbol_name: str) -> dict[str, str]:
    if not symbol_name.startswith("Java_"):
        return {
            "java_class": "",
            "class_descriptor": "",
            "java_method": "",
        }

    payload = symbol_name[len("Java_"):]
    if "__" in payload:
        payload, _ = payload.split("__", 1)
    segments = _split_jni_export_segments(payload)
    if len(segments) < 2:
        return {
            "java_class": "",
            "class_descriptor": "",
            "java_method": payload,
        }
    class_parts = segments[:-1]
    method_name = segments[-1]
    return {
        "java_class": ".".join(class_parts),
        "class_descriptor": "L" + "/".join(class_parts) + ";",
        "java_method": method_name,
    }


def _split_jni_export_segments(payload: str) -> list[str]:
    segments: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(payload):
        char = payload[index]
        if char == "_":
            if index + 1 < len(payload):
                marker = payload[index + 1]
                if marker == "1":
                    current.append("_")
                    index += 2
                    continue
                if marker == "2":
                    current.append(";")
                    index += 2
                    continue
                if marker == "3":
                    current.append("[")
                    index += 2
                    continue
                if marker == "0" and index + 5 < len(payload):
                    hex_chunk = payload[index + 2:index + 6]
                    try:
                        current.append(chr(int(hex_chunk, 16)))
                        index += 6
                        continue
                    except ValueError:
                        pass
            segments.append("".join(current))
            current = []
            index += 1
            continue
        current.append(char)
        index += 1
    if current or not segments:
        segments.append("".join(current))
    return [segment for segment in segments if segment]


def _scan_project_jni_surfaces(
    apktool_dir: Path,
    binary_jni_entries: list[dict[str, Any]],
    *,
    max_results: int = 120,
) -> dict[str, list[dict[str, Any]]]:
    declarations: list[dict[str, Any]] = []
    load_calls: list[dict[str, Any]] = []

    smali_files: list[Path] = []
    for smali_root in sorted(apktool_dir.glob("smali*")):
        if smali_root.is_dir():
            smali_files.extend(sorted(smali_root.rglob("*.smali")))

    for smali_file in smali_files:
        relative_path = str(smali_file.relative_to(apktool_dir))
        try:
            lines = smali_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

        class_descriptor = ""
        recent_strings: list[str] = []
        for line_number, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not class_descriptor:
                class_match = _SMALI_CLASS_RE.match(line)
                if class_match:
                    class_descriptor = str(class_match.group("descriptor") or "")

            const_match = _SMALI_CONST_STRING_RE.search(line)
            if const_match:
                recent_strings.append(str(const_match.group("value") or ""))
                recent_strings = recent_strings[-4:]

            method_match = _SMALI_METHOD_RE.match(line)
            if method_match:
                qualifiers = str(method_match.group("qualifiers") or "")
                if re.search(r"\bnative\b", qualifiers):
                    declarations.append({
                        "kind": "smali_native_declaration",
                        "file": relative_path,
                        "class_descriptor": class_descriptor,
                        "method_name": str(method_match.group("name") or ""),
                        "method_descriptor": (
                            f"{class_descriptor}->{method_match.group('name')}"
                            f"({method_match.group('params')}){method_match.group('ret')}"
                        ),
                        "line": line_number,
                    })

            if _SMALI_LOAD_LIBRARY_RE.search(line):
                load_calls.append({
                    "kind": "load_library_call",
                    "file": relative_path,
                    "class_descriptor": class_descriptor,
                    "library_name": recent_strings[-1] if recent_strings else "",
                    "line": line_number,
                    "invoke": line[:200],
                })

    traces = _link_jni_project_traces(declarations, load_calls, binary_jni_entries, max_results=max_results)
    return {
        "jni_traces": traces,
        "native_method_declarations": declarations[:max_results],
        "load_library_calls": load_calls[:max_results],
    }


def _link_jni_project_traces(
    declarations: list[dict[str, Any]],
    load_calls: list[dict[str, Any]],
    binary_jni_entries: list[dict[str, Any]],
    *,
    max_results: int,
) -> list[dict[str, Any]]:
    export_map: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for entry in binary_jni_entries:
        if entry.get("kind") != "static_jni_export":
            continue
        key = (str(entry.get("class_descriptor", "")), str(entry.get("java_method", "")))
        export_map.setdefault(key, []).append(entry)

    load_map: dict[str, list[str]] = {}
    for item in load_calls:
        class_descriptor = str(item.get("class_descriptor", ""))
        if not class_descriptor:
            continue
        library_name = str(item.get("library_name", ""))
        if not library_name:
            continue
        load_map.setdefault(class_descriptor, []).append(library_name)

    traces: list[dict[str, Any]] = []
    for declaration in declarations:
        class_descriptor = str(declaration.get("class_descriptor", ""))
        method_name = str(declaration.get("method_name", ""))
        matching_exports = export_map.get((class_descriptor, method_name), [])
        library_hints = load_map.get(class_descriptor, [])
        if matching_exports:
            for export in matching_exports[:2]:
                library_basename = str(export.get("library_basename", ""))
                confidence = "high" if library_basename in library_hints else "medium"
                traces.append({
                    "kind": "jni_export_link",
                    "class_descriptor": class_descriptor,
                    "method_name": method_name,
                    "method_descriptor": declaration.get("method_descriptor", ""),
                    "declaring_file": declaration.get("file", ""),
                    "line": declaration.get("line", 0),
                    "library_path": export.get("library_path", ""),
                    "library_name": export.get("library_name", ""),
                    "library_hint": library_hints[0] if library_hints else "",
                    "export_symbol": export.get("symbol", ""),
                    "registration": export.get("registration", ""),
                    "confidence": confidence,
                })
        else:
            traces.append({
                "kind": "jni_native_declaration",
                "class_descriptor": class_descriptor,
                "method_name": method_name,
                "method_descriptor": declaration.get("method_descriptor", ""),
                "declaring_file": declaration.get("file", ""),
                "line": declaration.get("line", 0),
                "library_hint": library_hints[0] if library_hints else "",
                "export_symbol": "",
                "registration": "unresolved",
                "confidence": "low",
            })

    for load_call in load_calls:
        traces.append({
            "kind": "load_library_call",
            "class_descriptor": load_call.get("class_descriptor", ""),
            "method_name": "",
            "method_descriptor": "",
            "declaring_file": load_call.get("file", ""),
            "line": load_call.get("line", 0),
            "library_path": "",
            "library_name": load_call.get("library_name", ""),
            "library_hint": load_call.get("library_name", ""),
            "export_symbol": "",
            "registration": "load_library",
            "confidence": "context",
        })

    traces.sort(key=lambda item: (str(item.get("kind", "")), str(item.get("class_descriptor", "")), str(item.get("method_name", ""))))
    return traces[:max_results]


def _library_basename(file_name: str) -> str:
    name = str(file_name or "")
    if name.startswith("lib"):
        name = name[3:]
    if name.endswith(".so"):
        name = name[:-3]
    return name


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