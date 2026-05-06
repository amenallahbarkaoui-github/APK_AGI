"""Dex topology, dependency, relocation, and helper-emission utilities.

These helpers are intentionally additive. They give the agent explicit dex-aware
visibility and execution primitives instead of forcing it to improvise file
moves or helper placement heuristics from generic file tools.
"""

from __future__ import annotations

import json
import re
import shutil
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from apk_agent.tools.code_injector import find_startup_entry
from apk_agent.tools.deep_analysis import validate_smali_syntax
from apk_agent.tools.manifest_parser import parse_manifest


_DEX_METHOD_LIMIT = 65536
_SMALI_ROOT_PATTERN = re.compile(r"^smali(?:_classes\d+)?$")
_CLASS_DEF_RE = re.compile(r"^\s*\.class\b.*?\s+(L[^;]+;)", re.MULTILINE)
_METHOD_DEF_RE = re.compile(r"^\s*\.method\b[^\n]*?([\w$<>-]+)\(([^)]*)\)([^\s#]+)", re.MULTILINE)
_METHOD_REF_RE = re.compile(r"([\w/$;\[]+)->([\w$<>-]+)\(([^)]*)\)([^\s,}#]+)")
_FIELD_REF_RE = re.compile(r"([\w/$;\[]+)->([\w$<>-]+):([^\s,}#]+)")
_DESCRIPTOR_RE = re.compile(r"L[^;]+;")
_NATIVE_METHOD_RE = re.compile(r"^\s*\.method\b.*\bnative\b", re.MULTILINE)
_ROOT_LOAD_RE = re.compile(r"System;->loadLibrary|Runtime;->loadLibrary|Runtime;->load\(")
_RESOURCE_CLASS_RE = re.compile(r"L[^;]+/R(?:\$[^;]+)?;")
_DOTTED_CLASS_RE = re.compile(r"(?:[A-Za-z_][\w$]*\.)+[A-Za-z_][\w$]*(?:\$[A-Za-z_][\w$]*)*")
_REFLECTION_MARKERS = (
    "Ljava/lang/reflect/Method;",
    "Ljava/lang/reflect/Field;",
    "Ljava/lang/reflect/Constructor;",
    "Ljava/lang/Class;->forName",
    "Ljava/lang/ClassLoader;",
    "Ldalvik/system/DexClassLoader;",
    "Ldalvik/system/PathClassLoader;",
)
_DEX_OVERFLOW_MARKERS = (
    "too many method references",
    "dexindexoverflow",
    "method id not in [0, 0xffff]",
    "unsigned short value out of range",
)


def normalize_smali_root_name(root_name: str | None) -> str:
    normalized = str(root_name or "smali").strip().replace("\\", "/")
    if not normalized:
        normalized = "smali"
    if normalized == "primary":
        normalized = "smali"
    if normalized == "auto":
        return normalized
    if not _SMALI_ROOT_PATTERN.match(normalized):
        raise ValueError("smali root must be smali or smali_classesN")
    return normalized


def list_smali_roots(apktool_dir: str | Path) -> list[Path]:
    apk_root = Path(apktool_dir)
    if not apk_root.is_dir():
        return []
    roots = [
        child
        for child in sorted(apk_root.iterdir())
        if child.is_dir() and _SMALI_ROOT_PATTERN.match(child.name)
    ]
    return roots


def get_smali_root_path(apktool_dir: str | Path, root_name: str, *, create: bool = False) -> Path:
    apk_root = Path(apktool_dir)
    normalized = normalize_smali_root_name(root_name)
    if normalized == "auto":
        raise ValueError("auto is not a concrete smali root")
    target = apk_root / normalized
    if create:
        target.mkdir(parents=True, exist_ok=True)
    return target


def _descriptor_to_dotted(descriptor: str) -> str:
    cleaned = str(descriptor or "").strip()
    if cleaned.startswith("L") and cleaned.endswith(";"):
        cleaned = cleaned[1:-1]
    return cleaned.replace("/", ".")


def _descriptor_to_rel_path(descriptor: str) -> Path:
    cleaned = str(descriptor or "").strip()
    if not cleaned.startswith("L") or not cleaned.endswith(";"):
        raise ValueError(f"Invalid class descriptor: {descriptor}")
    return Path(cleaned[1:-1] + ".smali")


def _component_to_descriptor(name: str, package_name: str) -> str:
    cleaned = str(name or "").strip()
    if not cleaned:
        return ""
    if cleaned.startswith("L") and cleaned.endswith(";"):
        return cleaned
    if cleaned.startswith(".") and package_name:
        cleaned = f"{package_name}{cleaned}"
    elif "/" in cleaned:
        cleaned = cleaned.replace("/", ".")
    elif "." not in cleaned and package_name:
        cleaned = f"{package_name}.{cleaned}"
    return f"L{cleaned.replace('.', '/')};"


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _scan_smali_file(smali_file: Path, root_name: str) -> dict[str, Any] | None:
    text = _read_text(smali_file)
    class_match = _CLASS_DEF_RE.search(text)
    if class_match is None:
        return None
    descriptor = class_match.group(1)
    method_defs = {
        f"{descriptor}->{name}({params}){ret}"
        for name, params, ret in _METHOD_DEF_RE.findall(text)
    }
    method_refs = {
        f"{owner}->{name}({params}){ret}"
        for owner, name, params, ret in _METHOD_REF_RE.findall(text)
        if owner.startswith("L")
    }
    field_refs = {
        f"{owner}->{name}:{field_type}"
        for owner, name, field_type in _FIELD_REF_RE.findall(text)
        if owner.startswith("L")
    }
    class_refs = {ref for ref in _DESCRIPTOR_RE.findall(text) if ref != descriptor}
    package_name = descriptor[1:-1].rsplit("/", 1)[0] if "/" in descriptor[1:-1] else ""
    return {
        "descriptor": descriptor,
        "file": str(smali_file),
        "root": root_name,
        "package": package_name,
        "method_defs": sorted(method_defs),
        "method_refs": sorted(method_refs),
        "field_refs": sorted(field_refs),
        "class_refs": sorted(class_refs),
        "reflection_sensitive": any(marker in text for marker in _REFLECTION_MARKERS),
        "jni_bound": bool(_NATIVE_METHOD_RE.search(text) or _ROOT_LOAD_RE.search(text)),
        "native_method_count": len(_NATIVE_METHOD_RE.findall(text)),
        "resource_related": bool(_RESOURCE_CLASS_RE.search(text)),
    }


def _scan_xml_resource_references(apktool_dir: Path, descriptors: set[str]) -> set[str]:
    res_dir = apktool_dir / "res"
    if not res_dir.is_dir() or not descriptors:
        return set()
    hits: set[str] = set()
    for xml_file in res_dir.rglob("*.xml"):
        text = _read_text(xml_file)
        for dotted in _DOTTED_CLASS_RE.findall(text):
            descriptor = _component_to_descriptor(dotted, "")
            if descriptor in descriptors:
                hits.add(descriptor)
    return hits


def _component_descriptors(apktool_dir: Path) -> tuple[set[str], set[str], str]:
    manifest_path = apktool_dir / "AndroidManifest.xml"
    manifest = parse_manifest(manifest_path)
    package_name = str(manifest.get("package") or "") if manifest.get("success") else ""
    components: set[str] = set()

    if manifest.get("success"):
        for tag in ("activities", "services", "receivers", "providers"):
            for component in manifest.get(tag) or []:
                descriptor = _component_to_descriptor(component.get("name", ""), package_name)
                if descriptor:
                    components.add(descriptor)

    startup: set[str] = set()
    entry = find_startup_entry(manifest_path, apktool_dir)
    if entry.get("success"):
        descriptor = _component_to_descriptor(str(entry.get("class_name") or ""), package_name)
        if descriptor:
            startup.add(descriptor)
            components.add(descriptor)

    return components, startup, package_name


def _build_inventory(apktool_dir: str | Path) -> dict[str, Any]:
    apk_root = Path(apktool_dir)
    roots = list_smali_roots(apk_root)
    components, startup_descriptors, package_name = _component_descriptors(apk_root)
    class_infos: list[dict[str, Any]] = []
    descriptor_to_info: dict[str, dict[str, Any]] = {}
    duplicates: dict[str, list[str]] = defaultdict(list)

    for root in roots:
        for smali_file in root.rglob("*.smali"):
            info = _scan_smali_file(smali_file, root.name)
            if info is None:
                continue
            descriptor = str(info["descriptor"])
            duplicates[descriptor].append(str(smali_file))
            descriptor_to_info[descriptor] = info
            class_infos.append(info)

    descriptor_set = set(descriptor_to_info)
    resource_references = _scan_xml_resource_references(apk_root, descriptor_set)
    app_prefix = f"L{package_name.replace('.', '/')}/" if package_name else ""

    for info in class_infos:
        descriptor = str(info["descriptor"])
        class_refs = set(info.get("class_refs") or [])
        method_ref_classes = {ref.split("->", 1)[0] for ref in info.get("method_refs") or [] if "->" in ref}
        field_ref_classes = {ref.split("->", 1)[0] for ref in info.get("field_refs") or [] if "->" in ref}
        all_ref_classes = (class_refs | method_ref_classes | field_ref_classes) - {descriptor}
        app_dependencies = sorted(ref for ref in all_ref_classes if ref in descriptor_set)
        unresolved_app_refs = sorted(
            ref for ref in all_ref_classes
            if ref not in descriptor_set and app_prefix and ref.startswith(app_prefix)
        )
        info["app_dependencies"] = app_dependencies
        info["unresolved_app_refs"] = unresolved_app_refs
        info["manifest_referenced"] = descriptor in components
        info["bootstrap_critical"] = descriptor in startup_descriptors or descriptor in components
        info["xml_resource_referenced"] = descriptor in resource_references

    reverse_edges: dict[str, set[str]] = defaultdict(set)
    for info in class_infos:
        for dependency in info.get("app_dependencies") or []:
            reverse_edges[dependency].add(str(info["descriptor"]))

    for info in class_infos:
        info["dependents"] = sorted(reverse_edges.get(str(info["descriptor"]), set()))

    cross_root = Counter()
    root_package_counts: dict[str, Counter[str]] = defaultdict(Counter)
    root_method_ids: dict[str, set[str]] = defaultdict(set)
    root_class_refs: dict[str, set[str]] = defaultdict(set)
    for info in class_infos:
        root_name = str(info["root"])
        root_package_counts[root_name][str(info.get("package") or "")] += 1
        root_method_ids[root_name].update(info.get("method_defs") or [])
        root_method_ids[root_name].update(info.get("method_refs") or [])
        root_class_refs[root_name].update(info.get("class_refs") or [])
        for dependency in info.get("app_dependencies") or []:
            target = descriptor_to_info.get(dependency)
            if target and str(target["root"]) != root_name:
                cross_root[(root_name, str(target["root"]))] += 1

    root_summaries: list[dict[str, Any]] = []
    for root in roots:
        root_name = root.name
        root_classes = [info for info in class_infos if str(info["root"]) == root_name]
        method_ids = root_method_ids[root_name]
        estimated_ratio = len(method_ids) / _DEX_METHOD_LIMIT if method_ids else 0.0
        root_summaries.append({
            "name": root_name,
            "path": str(root),
            "file_count": len(root_classes),
            "class_count": len(root_classes),
            "method_def_count": sum(len(info.get("method_defs") or []) for info in root_classes),
            "unique_method_ref_count": len(method_ids),
            "unique_class_ref_count": len(root_class_refs[root_name]),
            "bootstrap_critical_count": sum(1 for info in root_classes if info.get("bootstrap_critical")),
            "reflection_sensitive_count": sum(1 for info in root_classes if info.get("reflection_sensitive")),
            "jni_bound_count": sum(1 for info in root_classes if info.get("jni_bound")),
            "pressure_ratio": round(estimated_ratio, 4),
            "pressure_percent": round(estimated_ratio * 100.0, 2),
            "crowded": estimated_ratio >= 0.85,
            "packages": [
                {"package": package, "class_count": count}
                for package, count in root_package_counts[root_name].most_common(15)
            ],
        })

    return {
        "apktool_dir": str(apk_root),
        "roots": root_summaries,
        "class_infos": class_infos,
        "descriptor_to_info": descriptor_to_info,
        "duplicate_descriptors": {descriptor: paths for descriptor, paths in duplicates.items() if len(paths) > 1},
        "cross_root_dependencies": [
            {"from_root": src, "to_root": dst, "edge_count": count}
            for (src, dst), count in sorted(cross_root.items())
        ],
        "package_name": package_name,
        "manifest_descriptors": sorted(components),
        "startup_descriptors": sorted(startup_descriptors),
    }


def analyze_dex_method_pressure(apktool_dir: str | Path) -> dict[str, Any]:
    inventory = _build_inventory(apktool_dir)
    roots = list(inventory.get("roots") or [])
    if not roots:
        return {"success": False, "error": "No smali roots found. Run apktool_decompile first."}

    sorted_roots = sorted(roots, key=lambda item: (float(item.get("pressure_ratio", 0.0)), int(item.get("bootstrap_critical_count", 0))))
    recommended = next((root for root in sorted_roots if root.get("name") != "smali"), sorted_roots[0])
    return {
        "success": True,
        "dex_roots": roots,
        "crowded_roots": [root["name"] for root in roots if root.get("crowded")],
        "recommended_helper_root": str(recommended.get("name") or "smali"),
        "recommended_helper_reason": (
            f"{recommended.get('name')} has the lowest estimated method-reference pressure among discovered dex roots"
        ),
        "summary": {
            "root_count": len(roots),
            "highest_pressure_root": max(roots, key=lambda item: float(item.get("pressure_ratio", 0.0))).get("name"),
            "lowest_pressure_root": recommended.get("name"),
        },
    }


def map_dex_topology(apktool_dir: str | Path) -> dict[str, Any]:
    inventory = _build_inventory(apktool_dir)
    roots = list(inventory.get("roots") or [])
    if not roots:
        return {"success": False, "error": "No smali roots found. Run apktool_decompile first."}
    return {
        "success": True,
        "package_name": inventory.get("package_name", ""),
        "dex_roots": roots,
        "cross_root_dependencies": inventory.get("cross_root_dependencies", []),
        "manifest_descriptors": inventory.get("manifest_descriptors", []),
        "startup_descriptors": inventory.get("startup_descriptors", []),
    }


def extract_dependency_graph(
    apktool_dir: str | Path,
    *,
    focus_hint: str = "",
    max_nodes: int = 80,
) -> dict[str, Any]:
    inventory = _build_inventory(apktool_dir)
    class_infos = list(inventory.get("class_infos") or [])
    if not class_infos:
        return {"success": False, "error": "No smali classes found. Run apktool_decompile first."}

    hint = str(focus_hint or "").strip().lower()
    if hint:
        filtered = [
            info
            for info in class_infos
            if hint in str(info.get("descriptor", "")).lower()
            or hint in str(info.get("package", "")).lower()
            or hint in str(info.get("file", "")).lower()
        ]
    else:
        filtered = class_infos

    ranked = sorted(
        filtered,
        key=lambda info: (
            bool(info.get("bootstrap_critical")),
            bool(info.get("reflection_sensitive")),
            bool(info.get("jni_bound")),
            len(info.get("dependents") or []),
            len(info.get("app_dependencies") or []),
        ),
        reverse=True,
    )
    nodes = []
    edges = []
    for info in ranked[: max(1, int(max_nodes or 80))]:
        descriptor = str(info.get("descriptor") or "")
        nodes.append({
            "descriptor": descriptor,
            "class": descriptor,
            "file": str(info.get("file") or ""),
            "smali_root": str(info.get("root") or ""),
            "dependency_count": len(info.get("app_dependencies") or []),
            "dependent_count": len(info.get("dependents") or []),
            "bootstrap_critical": bool(info.get("bootstrap_critical")),
            "manifest_referenced": bool(info.get("manifest_referenced")),
            "xml_resource_referenced": bool(info.get("xml_resource_referenced")),
            "reflection_sensitive": bool(info.get("reflection_sensitive")),
            "jni_bound": bool(info.get("jni_bound")),
            "native_method_count": int(info.get("native_method_count", 0) or 0),
            "depends_on": list(info.get("app_dependencies") or [])[:20],
            "dependents": list(info.get("dependents") or [])[:20],
            "unresolved_app_refs": list(info.get("unresolved_app_refs") or [])[:20],
        })
        for dependency in info.get("app_dependencies") or []:
            edges.append({
                "from": descriptor,
                "to": dependency,
                "cross_root": inventory["descriptor_to_info"].get(dependency, {}).get("root") != info.get("root"),
            })

    return {
        "success": True,
        "focus_hint": focus_hint,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges[: max(50, len(nodes) * 4)],
        "critical_nodes": {
            "bootstrap_critical": [node["descriptor"] for node in nodes if node.get("bootstrap_critical")][:20],
            "reflection_sensitive": [node["descriptor"] for node in nodes if node.get("reflection_sensitive")][:20],
            "jni_bound": [node["descriptor"] for node in nodes if node.get("jni_bound")][:20],
            "manifest_referenced": [node["descriptor"] for node in nodes if node.get("manifest_referenced")][:20],
            "xml_resource_referenced": [node["descriptor"] for node in nodes if node.get("xml_resource_referenced")][:20],
        },
    }


def resolve_dex_target(
    apktool_dir: str | Path,
    *,
    target_package: str = "",
    preferred_root: str = "",
    purpose: str = "helper_injection",
    estimated_new_method_refs: int = 0,
    avoid_roots: list[str] | None = None,
) -> dict[str, Any]:
    pressure = analyze_dex_method_pressure(apktool_dir)
    if not pressure.get("success"):
        return pressure

    package_hint = str(target_package or "").strip().replace(".", "/").strip("/")
    avoid = {normalize_smali_root_name(root) for root in (avoid_roots or []) if str(root).strip()}
    preferred = normalize_smali_root_name(preferred_root) if str(preferred_root or "").strip() else ""
    candidates = []
    for root in pressure.get("dex_roots") or []:
        root_name = str(root.get("name") or "")
        if root_name in avoid:
            continue
        locality_count = 0
        for package_info in root.get("packages") or []:
            package_name = str(package_info.get("package") or "")
            if package_hint and package_name.startswith(package_hint):
                locality_count += int(package_info.get("class_count", 0) or 0)
        estimated_ratio = float(root.get("pressure_ratio", 0.0) or 0.0) + (max(0, int(estimated_new_method_refs or 0)) / _DEX_METHOD_LIMIT)
        score = estimated_ratio
        if purpose in {"helper_injection", "runtime_scaffold"} and root_name == "smali":
            score += 0.08
        if int(root.get("bootstrap_critical_count", 0) or 0) > 0 and root_name == "smali":
            score += 0.02
        if locality_count:
            score -= min(0.12, locality_count / 1000.0)
        if preferred and preferred == root_name:
            score -= 0.05
        candidates.append({
            **root,
            "locality_count": locality_count,
            "estimated_post_injection_ratio": round(estimated_ratio, 4),
            "score": round(score, 4),
        })

    if not candidates:
        return {"success": False, "error": "No candidate dex roots available."}

    candidates.sort(key=lambda item: (float(item.get("score", 1.0)), float(item.get("pressure_ratio", 1.0))))
    recommended = candidates[0]
    return {
        "success": True,
        "purpose": purpose,
        "target_package": target_package,
        "preferred_root": preferred,
        "recommended_root": recommended["name"],
        "recommended_path": str(Path(apktool_dir) / recommended["name"]),
        "estimated_post_injection_ratio": recommended["estimated_post_injection_ratio"],
        "candidates": candidates,
        "reasoning": [
            f"{recommended['name']} currently has estimated pressure {recommended.get('pressure_percent', 0.0)}%.",
            "The resolver penalizes the primary dex for helper-heavy injections and rewards package locality when available.",
        ],
    }


def _estimate_smali_payload(content: str) -> dict[str, Any]:
    method_defs = {
        f"{name}({params}){ret}"
        for name, params, ret in _METHOD_DEF_RE.findall(content)
    }
    method_refs = {
        f"{owner}->{name}({params}){ret}"
        for owner, name, params, ret in _METHOD_REF_RE.findall(content)
        if owner.startswith("L")
    }
    class_defs = _CLASS_DEF_RE.findall(content)
    return {
        "class_count": len(class_defs),
        "method_def_count": len(method_defs),
        "method_ref_count": len(method_refs | {ref for ref in class_defs}),
    }


def plan_dex_injection(
    apktool_dir: str | Path,
    *,
    helper_files: dict[str, str] | None = None,
    target_package: str = "",
    preferred_root: str = "",
    purpose: str = "helper_injection",
    estimated_new_methods: int = 0,
) -> dict[str, Any]:
    normalized_helpers = dict(helper_files or {})
    payload_stats = Counter()
    for content in normalized_helpers.values():
        payload_stats.update(_estimate_smali_payload(str(content)))

    estimated_method_refs = int(payload_stats.get("method_ref_count", 0) or 0) + max(0, int(estimated_new_methods or 0))
    resolution = resolve_dex_target(
        apktool_dir,
        target_package=target_package,
        preferred_root=preferred_root,
        purpose=purpose,
        estimated_new_method_refs=estimated_method_refs,
    )
    if not resolution.get("success"):
        return resolution

    warnings: list[str] = []
    if float(resolution.get("estimated_post_injection_ratio", 0.0) or 0.0) >= 0.9:
        warnings.append("The recommended dex root will still be close to the 64K method-reference ceiling after injection.")
    if normalized_helpers and resolution.get("recommended_root") == "smali":
        warnings.append("The resolver still picked the primary dex; consider relocating optional helpers if the build already reports method-pressure problems.")

    return {
        "success": True,
        "estimated_payload": {
            "helper_file_count": len(normalized_helpers),
            "estimated_new_classes": int(payload_stats.get("class_count", 0) or 0),
            "estimated_new_methods": int(payload_stats.get("method_def_count", 0) or 0),
            "estimated_new_method_refs": estimated_method_refs,
        },
        "recommended_root": resolution.get("recommended_root"),
        "recommended_path": resolution.get("recommended_path"),
        "estimated_post_injection_ratio": resolution.get("estimated_post_injection_ratio"),
        "candidates": resolution.get("candidates", []),
        "warnings": warnings,
        "suggested_followups": [
            "emit_smali_helper_bundle",
            "inject_runtime_menu_scaffold",
            "inject_runtime_override_layer",
        ],
    }


def _normalize_helper_files(raw_files: Any) -> dict[str, str]:
    if not isinstance(raw_files, dict) or not raw_files:
        raise ValueError("helper_files_json must be a non-empty JSON object mapping relative .smali paths to file contents")
    normalized: dict[str, str] = {}
    for raw_name, raw_content in raw_files.items():
        rel = str(raw_name or "").strip().replace("\\", "/")
        path_obj = Path(rel)
        if not rel or path_obj.is_absolute() or ".." in path_obj.parts or path_obj.suffix.lower() != ".smali":
            raise ValueError(f"Invalid helper path: {rel}")
        normalized[path_obj.as_posix()] = str(raw_content)
    return normalized


def _backup_file(file_path: Path, apktool_dir: Path, backup_dir: Path | None, backed_up: dict[str, str]) -> None:
    if backup_dir is None:
        return
    key = str(file_path.resolve())
    if key in backed_up:
        return
    rel = file_path.resolve().relative_to(apktool_dir.resolve())
    backup_path = backup_dir / rel
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    if file_path.exists():
        shutil.copy2(file_path, backup_path)
    backed_up[key] = str(backup_path)


def emit_smali_helper_bundle(
    apktool_dir: str | Path,
    helper_files: dict[str, str],
    *,
    target_smali_root: str = "smali",
    backup_dir: str | Path | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    apk_root = Path(apktool_dir)
    normalized_helpers = _normalize_helper_files(helper_files)
    if normalize_smali_root_name(target_smali_root) == "auto":
        resolution = plan_dex_injection(apk_root, helper_files=normalized_helpers)
        target_root_name = str(resolution.get("recommended_root") or "smali")
    else:
        target_root_name = normalize_smali_root_name(target_smali_root)
    target_root = get_smali_root_path(apk_root, target_root_name, create=not dry_run)
    if dry_run:
        return {
            "success": True,
            "dry_run": True,
            "target_smali_root": target_root_name,
            "files_planned": [str(target_root / rel) for rel in sorted(normalized_helpers)],
        }

    backup_root = Path(backup_dir) if backup_dir else None
    touched_files: set[str] = set()
    backed_up: dict[str, str] = {}
    validations: list[dict[str, Any]] = []
    errors: list[str] = []
    for relative_name, content in normalized_helpers.items():
        helper_path = target_root / relative_name
        helper_path.parent.mkdir(parents=True, exist_ok=True)
        _backup_file(helper_path, apk_root, backup_root, backed_up)
        helper_path.write_text(content, encoding="utf-8")
        touched_files.add(str(helper_path))
        validation = validate_smali_syntax(helper_path)
        validations.append({"file": str(helper_path), **validation})
        if not validation.get("valid", False):
            errors.append(f"Syntax validation failed for {helper_path}")

    return {
        "success": len(errors) == 0 and bool(touched_files),
        "target_smali_root": target_root_name,
        "files_modified": sorted(touched_files),
        "rollback_files": list(backed_up.values()),
        "validation": validations,
        "errors": errors[:20],
    }


def _resolve_smali_source(apktool_dir: Path, source_path: str | Path) -> Path | None:
    raw = Path(str(source_path).replace("\\", "/"))
    if raw.is_absolute():
        return raw if raw.exists() else None
    normalized = str(raw).strip().lstrip("/")
    direct = apktool_dir / normalized
    if direct.exists():
        return direct
    for root in list_smali_roots(apktool_dir):
        candidate = root / normalized
        if candidate.exists():
            return candidate
    return None


def _owning_smali_root(apktool_dir: Path, path: Path) -> Path:
    rel = path.resolve().relative_to(apktool_dir.resolve())
    return apktool_dir / rel.parts[0]


def _collect_descriptors_under(path: Path) -> list[str]:
    files = [path] if path.is_file() else sorted(path.rglob("*.smali"))
    descriptors: list[str] = []
    for smali_file in files:
        class_match = _CLASS_DEF_RE.search(_read_text(smali_file))
        if class_match:
            descriptors.append(class_match.group(1))
    return descriptors


def relocate_smali_tree(
    apktool_dir: str | Path,
    source_path: str | Path,
    *,
    target_smali_root: str,
    backup_dir: str | Path | None = None,
    dry_run: bool = False,
    allow_bootstrap_move: bool = False,
    overwrite: bool = False,
) -> dict[str, Any]:
    apk_root = Path(apktool_dir)
    source = _resolve_smali_source(apk_root, source_path)
    if source is None:
        return {"success": False, "error": f"Source not found: {source_path}"}
    source_root = _owning_smali_root(apk_root, source)
    target_root_name = normalize_smali_root_name(target_smali_root)
    if target_root_name == "auto":
        target_root_name = str(resolve_dex_target(apk_root, purpose="relocation").get("recommended_root") or "smali")
    if source_root.name == target_root_name:
        return {"success": False, "error": "Source already belongs to the requested dex root."}

    descriptors = _collect_descriptors_under(source)
    inventory = _build_inventory(apk_root)
    bootstrap_hits = [descriptor for descriptor in descriptors if descriptor in set(inventory.get("startup_descriptors") or [])]
    if bootstrap_hits and not allow_bootstrap_move:
        return {
            "success": False,
            "error": "Refusing to move bootstrap-critical classes without allow_bootstrap_move=true.",
            "bootstrap_critical_descriptors": bootstrap_hits,
        }

    rel_tail = source.resolve().relative_to(source_root.resolve())
    target_root = get_smali_root_path(apk_root, target_root_name, create=not dry_run)
    target_path = target_root / rel_tail
    source_files = [source] if source.is_file() else sorted(path for path in source.rglob("*") if path.is_file())
    collisions = []
    planned = []
    for file_path in source_files:
        rel_file = file_path.resolve().relative_to(source_root.resolve())
        destination = target_root / rel_file
        planned.append({"from": str(file_path), "to": str(destination)})
        if destination.exists() and not overwrite:
            collisions.append(str(destination))
    if collisions:
        return {"success": False, "error": "Target files already exist.", "collisions": collisions[:20]}
    if dry_run:
        return {
            "success": True,
            "dry_run": True,
            "source_root": source_root.name,
            "target_root": target_root_name,
            "planned_moves": planned,
            "descriptors": descriptors,
            "bootstrap_critical_descriptors": bootstrap_hits,
        }

    backup_root = Path(backup_dir) if backup_dir else None
    backed_up: dict[str, str] = {}
    moved: list[dict[str, str]] = []
    for file_path in source_files:
        rel_file = file_path.resolve().relative_to(source_root.resolve())
        destination = target_root / rel_file
        destination.parent.mkdir(parents=True, exist_ok=True)
        _backup_file(file_path, apk_root, backup_root, backed_up)
        if destination.exists() and overwrite:
            _backup_file(destination, apk_root, backup_root, backed_up)
            destination.unlink()
        shutil.move(str(file_path), str(destination))
        moved.append({"from": str(file_path), "to": str(destination)})

    cleanup_root = source if source.is_dir() else source.parent
    while cleanup_root != source_root and cleanup_root.exists() and not any(cleanup_root.iterdir()):
        cleanup_root.rmdir()
        cleanup_root = cleanup_root.parent

    return {
        "success": True,
        "source_root": source_root.name,
        "target_root": target_root_name,
        "moved_files": moved,
        "rollback_files": list(backed_up.values()),
        "descriptors": descriptors,
        "target_path": str(target_path),
        "bootstrap_critical_descriptors": bootstrap_hits,
    }


def _normalize_descriptor_mapping(raw_mapping: Any) -> dict[str, str]:
    if isinstance(raw_mapping, dict):
        items = raw_mapping.items()
    elif isinstance(raw_mapping, list):
        items = []
        for item in raw_mapping:
            if isinstance(item, dict):
                items.extend(item.items())
    else:
        raise ValueError("mapping_json must describe a descriptor mapping")

    normalized: dict[str, str] = {}
    for old_raw, new_raw in items:
        old_descriptor = _component_to_descriptor(str(old_raw), "")
        new_descriptor = _component_to_descriptor(str(new_raw), "")
        if old_descriptor == new_descriptor or not old_descriptor or not new_descriptor:
            continue
        normalized[old_descriptor] = new_descriptor
    if not normalized:
        raise ValueError("No valid descriptor mappings were found")
    return normalized


def rewrite_smali_references(
    apktool_dir: str | Path,
    mapping: dict[str, str],
    *,
    backup_dir: str | Path | None = None,
    include_manifest: bool = True,
    include_resources: bool = True,
    dry_run: bool = False,
) -> dict[str, Any]:
    apk_root = Path(apktool_dir)
    descriptor_map = _normalize_descriptor_mapping(mapping)
    backup_root = Path(backup_dir) if backup_dir else None
    planned_changes: list[dict[str, Any]] = []
    touched_files: set[str] = set()
    backed_up: dict[str, str] = {}
    errors: list[str] = []
    descriptor_moves: list[dict[str, str]] = []

    def _replace_text(path: Path, *, dotted: bool = False) -> None:
        original = _read_text(path)
        updated = original
        for old_descriptor, new_descriptor in descriptor_map.items():
            updated = updated.replace(old_descriptor, new_descriptor)
            if dotted:
                updated = updated.replace(_descriptor_to_dotted(old_descriptor), _descriptor_to_dotted(new_descriptor))
        if updated == original:
            return
        planned_changes.append({"file": str(path), "kind": ("xml" if dotted else "smali")})
        if dry_run:
            return
        _backup_file(path, apk_root, backup_root, backed_up)
        path.write_text(updated, encoding="utf-8")
        touched_files.add(str(path))

    for root in list_smali_roots(apk_root):
        for smali_file in root.rglob("*.smali"):
            original = _read_text(smali_file)
            updated = original
            class_match = _CLASS_DEF_RE.search(original)
            defined_descriptor = class_match.group(1) if class_match else ""
            for old_descriptor, new_descriptor in descriptor_map.items():
                updated = updated.replace(old_descriptor, new_descriptor)
            if updated != original:
                planned_changes.append({"file": str(smali_file), "kind": "smali"})
                if not dry_run:
                    _backup_file(smali_file, apk_root, backup_root, backed_up)
                    smali_file.write_text(updated, encoding="utf-8")
                    touched_files.add(str(smali_file))
            if defined_descriptor in descriptor_map:
                new_path = root / _descriptor_to_rel_path(descriptor_map[defined_descriptor])
                descriptor_moves.append({"from": str(smali_file), "to": str(new_path)})
                if not dry_run:
                    if new_path.exists() and new_path != smali_file:
                        errors.append(f"Target class file already exists: {new_path}")
                        continue
                    new_path.parent.mkdir(parents=True, exist_ok=True)
                    if smali_file != new_path:
                        shutil.move(str(smali_file), str(new_path))
                        touched_files.discard(str(smali_file))
                        touched_files.add(str(new_path))

    if include_manifest:
        manifest_path = apk_root / "AndroidManifest.xml"
        if manifest_path.is_file():
            _replace_text(manifest_path, dotted=True)
    if include_resources:
        res_dir = apk_root / "res"
        if res_dir.is_dir():
            for xml_file in res_dir.rglob("*.xml"):
                _replace_text(xml_file, dotted=True)

    validations: list[dict[str, Any]] = []
    if not dry_run:
        for file_name in sorted(touched_files):
            if not file_name.endswith(".smali"):
                continue
            validation = validate_smali_syntax(Path(file_name))
            validations.append({"file": file_name, **validation})
            if not validation.get("valid", False):
                errors.append(f"Syntax validation failed for {file_name}")

    return {
        "success": len(errors) == 0,
        "dry_run": dry_run,
        "mapping": descriptor_map,
        "planned_changes": planned_changes,
        "descriptor_moves": descriptor_moves,
        "files_modified": sorted(touched_files),
        "rollback_files": list(backed_up.values()),
        "validation": validations,
        "errors": errors[:20],
    }


def validate_dex_integrity(
    apktool_dir: str | Path,
    *,
    expected_descriptors: list[str] | None = None,
    touched_paths: list[str] | None = None,
) -> dict[str, Any]:
    inventory = _build_inventory(apktool_dir)
    class_map = dict(inventory.get("descriptor_to_info") or {})
    missing_expected = [descriptor for descriptor in (expected_descriptors or []) if descriptor not in class_map]
    duplicate_descriptors = inventory.get("duplicate_descriptors", {})
    broken_dependencies = []
    for info in inventory.get("class_infos") or []:
        unresolved = list(info.get("unresolved_app_refs") or [])
        if unresolved:
            broken_dependencies.append({
                "class": info.get("descriptor"),
                "file": info.get("file"),
                "missing_dependencies": unresolved[:20],
            })
    manifest_missing = [descriptor for descriptor in inventory.get("manifest_descriptors") or [] if descriptor not in class_map]
    startup_not_primary = [
        descriptor
        for descriptor in inventory.get("startup_descriptors") or []
        if descriptor in class_map and str(class_map[descriptor].get("root")) != "smali"
    ]
    touched_validations = []
    for path_value in touched_paths or []:
        path = Path(path_value)
        if path.is_file() and path.suffix == ".smali":
            touched_validations.append({"file": str(path), **validate_smali_syntax(path)})
    return {
        "success": not missing_expected and not duplicate_descriptors and not broken_dependencies and not manifest_missing and all(item.get("valid", False) for item in touched_validations or [{"valid": True}]),
        "missing_expected_descriptors": missing_expected,
        "duplicate_descriptors": duplicate_descriptors,
        "broken_app_dependencies": broken_dependencies[:40],
        "manifest_missing_descriptors": manifest_missing,
        "bootstrap_root_warnings": startup_not_primary,
        "touched_validation": touched_validations,
    }


def _classify_build_error(build_error: str) -> str:
    lowered = str(build_error or "").lower()
    if any(marker in lowered for marker in _DEX_OVERFLOW_MARKERS):
        return "dex_64k_overflow"
    if "invalid register" in lowered:
        return "register_pressure"
    if "unknown opcode" in lowered:
        return "opcode_error"
    if "unclosed method" in lowered or ".end method" in lowered:
        return "method_balance_error"
    return "generic_build_failure"


def plan_injection_fallback_strategies(
    apktool_dir: str | Path,
    *,
    objective: str = "",
    helper_scope: str = "",
    build_error: str = "",
) -> dict[str, Any]:
    pressure = analyze_dex_method_pressure(apktool_dir)
    failure_kind = _classify_build_error(build_error)
    strategies = [
        {
            "strategy": "reuse_existing_app_class",
            "priority": 1,
            "when": "Best default for small hooks or bootstrap probes because it adds minimal dex footprint.",
        },
        {
            "strategy": "emit_helper_bundle_in_secondary_dex",
            "priority": 2,
            "when": "Use when you genuinely need new helper classes but want to avoid loading more method references into the primary dex.",
        },
        {
            "strategy": "runtime_override_without_menu_ui",
            "priority": 3,
            "when": "Prefer this when menu scaffolding is optional and the build is already close to the 64K ceiling.",
        },
        {
            "strategy": "static_root_cause_patch",
            "priority": 4,
            "when": "Fall back when helper-heavy runtime control is not justified by the actual enforcement surface.",
        },
    ]
    if failure_kind == "dex_64k_overflow":
        strategies.insert(0, {
            "strategy": "relocate_optional_helpers_out_of_primary_dex",
            "priority": 0,
            "when": "The build already reported dex method-reference overflow.",
        })
    return {
        "success": True,
        "objective": objective,
        "helper_scope": helper_scope,
        "failure_kind": failure_kind,
        "recommended_helper_root": pressure.get("recommended_helper_root", "smali"),
        "strategies": strategies,
    }


def plan_dex_auto_remediation(
    apktool_dir: str | Path,
    *,
    build_error: str = "",
    helper_files: dict[str, str] | None = None,
    target_package: str = "",
    focus_hint: str = "",
) -> dict[str, Any]:
    failure_kind = _classify_build_error(build_error)
    pressure = analyze_dex_method_pressure(apktool_dir)
    topology = map_dex_topology(apktool_dir)
    injection_plan = plan_dex_injection(apktool_dir, helper_files=helper_files, target_package=target_package)
    fallbacks = plan_injection_fallback_strategies(
        apktool_dir,
        objective=focus_hint,
        helper_scope=target_package,
        build_error=build_error,
    )

    tool_chain = ["analyze_dex_method_pressure", "map_dex_topology", "extract_dependency_graph"]
    if failure_kind == "dex_64k_overflow":
        tool_chain.extend(["resolve_dex_target", "relocate_smali_tree", "validate_dex_integrity", "apktool_build"])
    elif failure_kind == "register_pressure":
        tool_chain.extend(["plan_injection_fallback_strategies", "validate_patch", "apktool_build"])
    else:
        tool_chain.extend(["validate_dex_integrity", "apktool_build"])

    return {
        "success": True,
        "failure_kind": failure_kind,
        "focus_hint": focus_hint,
        "pressure_summary": pressure.get("summary", {}),
        "topology_summary": {
            "root_count": len(topology.get("dex_roots") or []),
            "cross_root_dependency_count": len(topology.get("cross_root_dependencies") or []),
        },
        "recommended_root": injection_plan.get("recommended_root", pressure.get("recommended_helper_root", "smali")),
        "tool_chain": tool_chain,
        "fallback_strategies": fallbacks.get("strategies", []),
        "notes": [
            "Use dependency graph extraction before relocating bootstrap-critical, reflection-sensitive, or JNI-bound classes.",
            "Treat dex overflow as topology and helper-footprint pressure first, not as a syntax problem.",
        ],
    }


def plan_self_healing_build_loop(
    apktool_dir: str | Path,
    *,
    build_error: str = "",
    objective: str = "",
    helper_files: dict[str, str] | None = None,
) -> dict[str, Any]:
    remediation = plan_dex_auto_remediation(
        apktool_dir,
        build_error=build_error,
        helper_files=helper_files,
        focus_hint=objective,
    )
    return {
        "success": True,
        "objective": objective,
        "failure_kind": remediation.get("failure_kind", "generic_build_failure"),
        "loop_steps": [
            {"step": 1, "tool": "analyze_dex_method_pressure", "purpose": "Measure per-dex method-reference pressure before changing placement."},
            {"step": 2, "tool": "map_dex_topology", "purpose": "See available dex roots and cross-root dependency shape."},
            {"step": 3, "tool": "extract_dependency_graph", "purpose": "Identify bootstrap-critical, reflection-sensitive, JNI-bound, and manifest/resource-referenced classes."},
            {"step": 4, "tool": "plan_dex_auto_remediation", "purpose": "Choose the smallest safe topology fix."},
            {"step": 5, "tool": "validate_dex_integrity", "purpose": "Check duplicates, missing descriptors, and broken app-owned dependencies before rebuild."},
            {"step": 6, "tool": "apktool_build", "purpose": "Retry the build only after the topology and integrity checks pass."},
        ],
        "recommended_root": remediation.get("recommended_root", "smali"),
        "fallback_strategies": remediation.get("fallback_strategies", []),
        "notes": [
            "This tool is planning-only. It produces the recovery loop the agent should follow instead of mutating the project directly.",
            "If the failure kind is dex_64k_overflow, prefer relocation or helper re-targeting before simplifying patches.",
        ],
    }