"""Profile guard, revalidation, and overwrite surfaces in hardened APKs.

This module identifies where an app re-checks or re-applies protected state at
runtime: lifecycle hooks, network callbacks, security guards, dynamic loading,
and persistence overwrite points.
"""

from __future__ import annotations

from typing import Any

from apk_agent.tools.advanced_search import _is_third_party_path


_TRIGGER_NAMES = (
    "oncreate",
    "onstart",
    "onresume",
    "onrestart",
    "onactivitycreated",
    "onreceive",
    "dobackgroundwork",
    "dowork",
    "run",
    "call",
    "handlemessage",
    "onresponse",
    "onsuccess",
    "onnext",
    "oncomplete",
    "onpurchasesupdated",
    "onbillingsetupfinished",
)

_GUARD_HINTS = (
    "root",
    "emulator",
    "debug",
    "tamper",
    "signature",
    "integrity",
    "attestation",
    "verify",
    "validate",
    "license",
    "premium",
    "subscription",
    "purchase",
    "ssl",
    "pinning",
    "pairip",
)

_DYNAMIC_NATIVE_HINTS = (
    "dexclassloader",
    "pathclassloader",
    "inmemorydexclassloader",
    "class.forname",
    "method.invoke",
    "proxy",
    "system.loadlibrary",
    "system.load",
    "jni_onload",
    "native",
)

_OVERWRITE_HINTS = (
    "sharedpreferences$editor;->put",
    "sqlitedatabase;->insert",
    "sqlitedatabase;->update",
    "sqlitedatabase;->execsql",
    "datastore",
    "realm",
    "room",
)


def _method_blob(smali_method) -> str:
    parts = [smali_method.name, smali_method.signature, smali_method.return_type]
    parts.extend(smali_method.param_types[:8])
    parts.extend(smali_method.api_calls[:50])
    parts.extend(smali_method.string_constants[:20])
    return " ".join(p for p in parts if p).lower()


def _method_tags(smali_method, focus_terms: list[str]) -> tuple[list[str], list[str], list[str]]:
    blob = _method_blob(smali_method)
    trigger_tags: list[str] = []
    guard_tags: list[str] = []
    boundary_tags: list[str] = []

    if any(name in smali_method.name.lower() for name in _TRIGGER_NAMES):
        trigger_tags.append("named_trigger")
    if any(name in blob for name in _TRIGGER_NAMES):
        trigger_tags.append("callback_or_lifecycle")

    for hint in _GUARD_HINTS:
        if hint in blob:
            guard_tags.append(hint)
    for hint in _DYNAMIC_NATIVE_HINTS:
        if hint in blob:
            boundary_tags.append(hint)
    for hint in _OVERWRITE_HINTS:
        if hint in blob:
            boundary_tags.append("state_overwrite_api")
            break
    if focus_terms and any(term in blob for term in focus_terms):
        guard_tags.append("focus_match")

    return sorted(set(trigger_tags)), sorted(set(guard_tags)), sorted(set(boundary_tags))


def profile_guard_and_revalidation_surface(index, *, focus_hint: str = "", max_clusters: int = 30) -> dict[str, Any]:
    """Profile runtime guard and revalidation surfaces.

    Args:
        index: Loaded SmaliIndex.
        focus_hint: Optional domain hint such as premium, auth, subscription.
        max_clusters: Maximum number of clusters to return.
    """
    if index is None:
        return {"success": False, "error": "SmaliIndex is required"}

    focus_terms = [term.strip().lower() for term in focus_hint.split(",") if term.strip()]
    guard_clusters: list[dict[str, Any]] = []
    overwrite_points: list[dict[str, Any]] = []
    native_dynamic_boundaries: list[dict[str, Any]] = []
    revalidation_loops: list[dict[str, Any]] = []

    for smali_class in index.classes.values():
        if _is_third_party_path(smali_class.file_path):
            continue

        class_has_multiple_rechecks = 0
        for method in smali_class.methods:
            trigger_tags, guard_tags, boundary_tags = _method_tags(method, focus_terms)
            if not trigger_tags and not guard_tags and not boundary_tags:
                continue

            state_writes = 0
            field_writes: list[str] = []
            for instr in method.instructions:
                if instr.opcode.startswith(("iput", "sput")):
                    state_writes += 1
                    if instr.target_field and len(field_writes) < 6:
                        field_writes.append(instr.target_field)

            if state_writes > 0:
                overwrite_points.append({
                    "class": smali_class.name,
                    "file": smali_class.file_path,
                    "method": method.full_signature,
                    "state_write_count": state_writes,
                    "field_targets": field_writes,
                    "guard_tags": guard_tags,
                    "trigger_tags": trigger_tags,
                })

            if boundary_tags:
                native_dynamic_boundaries.append({
                    "class": smali_class.name,
                    "file": smali_class.file_path,
                    "method": method.full_signature,
                    "boundary_tags": boundary_tags,
                    "guard_tags": guard_tags,
                })

            if trigger_tags and (guard_tags or state_writes > 0 or boundary_tags):
                class_has_multiple_rechecks += 1

            patch_points: list[str] = []
            runtime_points: list[str] = []
            if guard_tags:
                patch_points.append("method_return_or_branch_patch")
            if state_writes > 0:
                patch_points.append("writer_override_or_constructor_patch")
            if boundary_tags:
                runtime_points.append("runtime_hook_recommended")
            if trigger_tags:
                runtime_points.append("lifecycle_reapply_hook")

            severity = len(guard_tags) + len(boundary_tags) + (2 if state_writes > 0 else 0) + len(trigger_tags)
            guard_clusters.append({
                "class": smali_class.name,
                "file": smali_class.file_path,
                "method": method.full_signature,
                "trigger_tags": trigger_tags,
                "guard_tags": guard_tags,
                "boundary_tags": boundary_tags,
                "state_write_count": state_writes,
                "field_targets": field_writes,
                "suggested_static_patch_points": sorted(set(patch_points)),
                "suggested_runtime_hook_points": sorted(set(runtime_points)),
                "severity_score": severity,
            })

        if class_has_multiple_rechecks >= 2:
            revalidation_loops.append({
                "class": smali_class.name,
                "file": smali_class.file_path,
                "revalidation_method_count": class_has_multiple_rechecks,
            })

    guard_clusters.sort(key=lambda item: (-item["severity_score"], item["class"], item["method"]))
    overwrite_points.sort(key=lambda item: (-item["state_write_count"], item["class"], item["method"]))
    native_dynamic_boundaries.sort(key=lambda item: (-len(item["boundary_tags"]), item["class"], item["method"]))
    revalidation_loops.sort(key=lambda item: (-item["revalidation_method_count"], item["class"]))

    return {
        "success": True,
        "focus_hint": focus_hint,
        "guard_clusters": guard_clusters[:max_clusters],
        "overwrite_points": overwrite_points[:40],
        "native_or_dynamic_boundaries": native_dynamic_boundaries[:40],
        "revalidation_loops": revalidation_loops[:25],
        "summary": {
            "guard_clusters": len(guard_clusters),
            "overwrite_points": len(overwrite_points),
            "native_dynamic_boundaries": len(native_dynamic_boundaries),
            "revalidation_loops": len(revalidation_loops),
        },
        "recommendations": [
            "Patch overwrite points before UI symptoms if state gets re-applied after startup.",
            "Use runtime hooks when a cluster crosses lifecycle callbacks with native/dynamic boundaries.",
            "Combine constructor or response patching with revalidation-hook coverage for hardened apps.",
        ],
    }