"""Advanced API response flow patching at the model boundary.

This tool does not try to edit raw endpoints blindly. Instead, it patches the
points where server-derived state becomes *application state*:
  - constructors of the target entity/model
  - setter-like writer methods on the target entity/model
  - response/factory methods that return the target entity from a network or
    serialization boundary

That keeps the patch aligned with the app's own structure while staying safer
than ad-hoc string replacement.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from apk_agent.tools.advanced_search import _is_third_party_path
from apk_agent.tools.code_injector import inject_code_in_method, override_constructor_fields
from apk_agent.tools.deep_analysis import validate_smali_syntax


_NETWORK_HINTS = ("lokhttp3/", "lretrofit2/", "httpurlconnection", "requestbody", "responsebody", "ktor", "apollo")
_SERIALIZATION_HINTS = ("gson", "moshi", "jackson", "org/json", "jsonobject", "jsonarray", "fromjson", "tojson", "parse", "deserialize", "serialize")
_RESPONSE_METHOD_HINTS = ("onresponse", "onsuccess", "parse", "decode", "deserialize", "fromjson", "map", "transform", "adapt")
_MARKER = "# APK-AGI: API RESPONSE OVERRIDE"


def _escape_smali_string(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def _field_override_lines(class_descriptor: str, field_overrides: dict[str, dict[str, Any]], *, object_reg: str) -> list[str]:
    lines: list[str] = [_MARKER]
    for field_name, field_info in field_overrides.items():
        ftype = str(field_info.get("type", "")).strip()
        value = field_info.get("value")
        if ftype == "Ljava/lang/String;":
            if value is None:
                continue
            lines.append(f'const-string v0, "{_escape_smali_string(value)}"')
            lines.append(f"iput-object v0, {object_reg}, {class_descriptor}->{field_name}:{ftype}")
        elif ftype == "Z":
            val = "0x1" if bool(value) else "0x0"
            lines.append(f"const/4 v0, {val}")
            lines.append(f"iput-boolean v0, {object_reg}, {class_descriptor}->{field_name}:{ftype}")
        elif ftype == "I":
            if value is None:
                continue
            iv = int(value)
            if -8 <= iv <= 7:
                lines.append(f"const/4 v0, {hex(iv)}")
            elif -32768 <= iv <= 32767:
                lines.append(f"const/16 v0, {hex(iv)}")
            else:
                lines.append(f"const v0, {hex(iv)}")
            lines.append(f"iput v0, {object_reg}, {class_descriptor}->{field_name}:{ftype}")
        elif ftype == "J":
            if value is None:
                continue
            lines.append(f"const-wide v2, {hex(int(value))}")
            lines.append(f"iput-wide v2, {object_reg}, {class_descriptor}->{field_name}:{ftype}")
        elif ftype.startswith("L") or ftype.startswith("["):
            if value is None:
                lines.append("const/4 v0, 0x0")
                lines.append(f"iput-object v0, {object_reg}, {class_descriptor}->{field_name}:{ftype}")
    return lines


def _backup_file(file_path: Path, apktool_dir: Path, backup_dir: Path | None, backed_up: dict[str, str]) -> str:
    if backup_dir is None:
        return ""
    key = str(file_path.resolve())
    if key in backed_up:
        return backed_up[key]
    try:
        rel = file_path.resolve().relative_to(apktool_dir.resolve())
    except ValueError:
        rel = Path(file_path.name)
    backup_path = backup_dir / rel
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(file_path, backup_path)
    backed_up[key] = str(backup_path)
    return str(backup_path)


def _method_line_range(file_path: Path, method_query: str) -> tuple[int, int]:
    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = -1
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(".method"):
            if method_query in stripped or ("(" not in method_query and method_query in stripped.split()[-1]):
                start = idx
        elif start >= 0 and stripped == ".end method":
            return start, idx
    return -1, -1


def _method_has_marker(file_path: Path, method_query: str, marker: str = _MARKER) -> bool:
    start, end = _method_line_range(file_path, method_query)
    if start < 0 or end < 0:
        return False
    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    return any(marker in line for line in lines[start : end + 1])


def _setter_candidates(smali_class, target_fields: set[str]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for method in smali_class.methods:
        if method.name == "<init>":
            continue
        touched = [instr.target_field.split("->", 1)[1] for instr in method.instructions if instr.target_field in target_fields and instr.opcode.startswith(("iput", "sput"))]
        if not touched:
            continue
        if len(method.param_types) >= 1 or method.name.startswith("set") or method.return_type == "V":
            candidates.append({
                "method": method.signature,
                "full_signature": method.full_signature,
                "touched_fields": sorted(set(touched)),
            })
    return candidates


def _factory_candidates(index, target_class: str, *, endpoint_hint: str = "", max_methods: int = 8) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    endpoint_lower = endpoint_hint.lower().strip()
    for method in index.methods.values():
        owner_class = method.full_signature.split("->", 1)[0] if "->" in method.full_signature else ""
        owner = index.get_class(owner_class)
        if owner is not None and _is_third_party_path(owner.file_path):
            continue
        if method.return_type != target_class:
            continue
        blob = " ".join([
            method.name,
            method.signature,
            method.return_type,
            " ".join(method.api_calls[:30]),
            " ".join(method.string_constants[:20]),
        ]).lower()
        if not (
            any(hint in blob for hint in _NETWORK_HINTS)
            or any(hint in blob for hint in _SERIALIZATION_HINTS)
            or any(hint in method.name.lower() for hint in _RESPONSE_METHOD_HINTS)
            or (endpoint_lower and endpoint_lower in blob)
        ):
            continue
        results.append({
            "method": method.signature,
            "full_signature": method.full_signature,
            "class": owner_class,
            "file": owner.file_path if owner is not None else "",
            "reason": "network_or_serialization_boundary",
        })
        if len(results) >= max_methods:
            break
    return results


def _last_return_object_reg(file_path: Path, method_query: str) -> str:
    start, end = _method_line_range(file_path, method_query)
    if start < 0 or end < 0:
        return ""
    lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    for idx in range(end, start - 1, -1):
        stripped = lines[idx].strip()
        if stripped.startswith("return-object"):
            parts = stripped.split()
            if len(parts) >= 2:
                return parts[1].rstrip(",")
    return ""


def _return_override_code(return_reg: str, class_descriptor: str, field_overrides: dict[str, dict[str, Any]]) -> str:
    alias_reg = "v1"
    lines: list[str] = []
    if return_reg.startswith("v"):
        try:
            reg_no = int(return_reg[1:])
        except ValueError:
            reg_no = 0
        if reg_no > 15:
            lines.append(f"move-object/from16 {alias_reg}, {return_reg}")
        else:
            lines.append(f"move-object {alias_reg}, {return_reg}")
    else:
        lines.append(f"move-object/from16 {alias_reg}, {return_reg}")
    lines.extend(_field_override_lines(class_descriptor, field_overrides, object_reg=alias_reg))
    return "\n".join(lines)


def patch_api_response_flow(
    index,
    apktool_dir: str | Path,
    target_class: str,
    field_overrides: dict[str, dict[str, Any]],
    *,
    endpoint_hint: str = "",
    strategy: str = "auto",
    backup_dir: str | Path | None = None,
    max_factory_methods: int = 8,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Patch the model boundary where API response state becomes app state."""
    if index is None:
        return {"success": False, "error": "SmaliIndex is required"}
    if not field_overrides:
        return {"success": False, "error": "field_overrides is required"}

    apktool_dir = Path(apktool_dir)
    backup_root = Path(backup_dir) if backup_dir else None
    target = index.get_class(target_class)
    if target is None:
        return {"success": False, "error": f"Target class not found: {target_class}"}
    if not target.abs_path:
        return {"success": False, "error": f"Target class has no source file path: {target_class}"}

    target_file = Path(target.abs_path)
    target_fields = {f"{target_class}->{name}" for name in field_overrides}
    backed_up: dict[str, str] = {}
    touched_files: set[str] = set()
    validations: list[dict[str, Any]] = []
    setter_results: list[dict[str, Any]] = []
    factory_results: list[dict[str, Any]] = []
    errors: list[str] = []
    selected_strategy: list[str] = []
    constructor_result: dict[str, Any] | None = None

    setters = _setter_candidates(target, target_fields)
    factories = _factory_candidates(index, target_class, endpoint_hint=endpoint_hint, max_methods=max_factory_methods)

    if dry_run:
        return {
            "success": True,
            "dry_run": True,
            "target_class": target_class,
            "target_file": str(target_file),
            "selected_strategy": ["constructor_override", "setter_override", "factory_return_override"],
            "setter_candidates": setters,
            "candidate_response_handlers": factories,
        }

    try:
        _backup_file(target_file, apktool_dir, backup_root, backed_up)

        if strategy in {"auto", "full_pipeline", "constructors", "model_boundary"}:
            constructor_result = override_constructor_fields(str(target_file), target_class, field_overrides)
            if constructor_result.get("success"):
                selected_strategy.append("constructor_override")
                touched_files.add(str(target_file))
            else:
                errors.append(str(constructor_result.get("error", "constructor override failed")))

        if strategy in {"auto", "full_pipeline", "setters", "model_boundary"}:
            for candidate in setters:
                if _method_has_marker(target_file, candidate["method"]):
                    continue
                code = "\n".join(_field_override_lines(target_class, field_overrides, object_reg="p0"))
                result = inject_code_in_method(str(target_file), candidate["method"], code, "before_return")
                setter_results.append({
                    "method": candidate["full_signature"],
                    "result": result,
                })
                if result.get("success"):
                    selected_strategy.append("setter_override")
                    touched_files.add(str(target_file))
                else:
                    errors.append(f"Setter patch failed for {candidate['full_signature']}: {result.get('error', 'unknown error')}")

        if strategy in {"auto", "full_pipeline", "factories", "response_handlers"}:
            for candidate in factories:
                owner = index.get_class(candidate["class"])
                if owner is None or not owner.abs_path:
                    continue
                owner_file = Path(owner.abs_path)
                if _method_has_marker(owner_file, candidate["method"]):
                    continue
                return_reg = _last_return_object_reg(owner_file, candidate["method"])
                if not return_reg:
                    continue
                code = _return_override_code(return_reg, target_class, field_overrides)
                _backup_file(owner_file, apktool_dir, backup_root, backed_up)
                result = inject_code_in_method(str(owner_file), candidate["method"], code, "before_return")
                factory_results.append({
                    "method": candidate["full_signature"],
                    "file": str(owner_file),
                    "result": result,
                })
                if result.get("success"):
                    selected_strategy.append("factory_return_override")
                    touched_files.add(str(owner_file))
                else:
                    errors.append(f"Factory patch failed for {candidate['full_signature']}: {result.get('error', 'unknown error')}")

        for file_name in sorted(touched_files):
            validation = validate_smali_syntax(Path(file_name))
            validations.append({"file": file_name, **validation})
            if not validation.get("valid", False):
                backup_path = backed_up.get(str(Path(file_name).resolve()))
                if backup_path:
                    shutil.copy2(backup_path, file_name)
                errors.append(f"Syntax validation failed for {file_name}; restored from backup")

    except Exception as exc:
        errors.append(str(exc))

    unique_strategy = []
    for item in selected_strategy:
        if item not in unique_strategy:
            unique_strategy.append(item)

    setter_patched = sum(1 for item in setter_results if item["result"].get("success"))
    factory_patched = sum(1 for item in factory_results if item["result"].get("success"))
    constructors_patched = int((constructor_result or {}).get("constructors_patched", 0) or 0)

    return {
        "success": len(errors) == 0 and bool(touched_files),
        "target_class": target_class,
        "target_file": str(target_file),
        "field_overrides": field_overrides,
        "selected_strategy": unique_strategy,
        "setter_candidates": setters,
        "candidate_response_handlers": factories,
        "setters_patched": setter_patched,
        "factory_methods_patched": factory_patched,
        "constructors_patched": constructors_patched,
        "patches_applied": constructors_patched + setter_patched + factory_patched,
        "files_modified": sorted(touched_files),
        "rollback_files": list(backed_up.values()),
        "validation": validations,
        "errors": errors[:20],
    }