"""Unified behavior graph built from the existing semantic analyzers.

This module is intentionally additive. It does not replace any current tool.
Instead, it materializes one reusable behavior graph pack that combines:

- semantic architecture recovery
- hidden state model recovery
- guard and revalidation profiling
- enforcement surface ranking
- the existing application knowledge pack

The goal is to expose a single behavior-first layer for feature control
location, state transition recovery, security surface mapping, runtime hook
planning, graph-aware querying, network flow analysis, and semantic symbol
recovery in obfuscated apps.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from typing import Any

from apk_agent.tools.patch_strategy import (
    annotate_runtime_hook_recommendations,
    summarize_runtime_hook_recommendations,
)


PACK_VERSION = 1


def build_behavior_graph(
    index,
    *,
    graph=None,
    focus_hint: str = "",
    package_name: str = "",
    app_label: str = "",
    max_surfaces: int = 25,
    max_controls: int = 40,
    max_transitions: int = 80,
    max_security: int = 40,
    max_hooks: int = 20,
    max_symbol_hints: int = 20,
    progress_callback=None,
) -> dict[str, Any]:
    """Build a unified control/data/state/security behavior graph pack."""
    if index is None:
        return {"success": False, "error": "SmaliIndex is required"}

    def _emit_progress(pct: float, detail: str) -> None:
        if progress_callback is not None:
            progress_callback(pct, detail)

    from apk_agent.tools.app_knowledge import build_app_knowledge_pack
    from apk_agent.tools.semantic_cache import (
        get_cached_guard_surface_profile,
        get_cached_hidden_state_model,
        get_cached_semantic_architecture,
    )
    from apk_agent.tools.semantic_graph import find_enforcement_surfaces

    warnings: list[str] = []

    # Warm the widest semantic views first so narrower downstream consumers
    # (app knowledge, enforcement context, query helpers) reuse the same pass.
    _emit_progress(4, "Preparing behavior graph inputs")
    _emit_progress(8, "Recovering semantic architecture layers")
    get_cached_semantic_architecture(
        index,
        focus_hint=focus_hint,
        max_per_role=20,
        progress_callback=lambda pct, detail: _emit_progress(8 + (pct * 0.18), detail),
    )
    _emit_progress(28, "Recovering hidden-state model")
    get_cached_hidden_state_model(
        index,
        focus_hint=focus_hint,
        max_candidates=50,
        progress_callback=lambda pct, detail: _emit_progress(28 + (pct * 0.18), detail),
    )
    _emit_progress(48, "Profiling guard and revalidation surfaces")
    get_cached_guard_surface_profile(index, focus_hint=focus_hint, max_clusters=50)
    _emit_progress(58, "Guard surface profile ready")

    _emit_progress(60, "Building application knowledge pack")
    app_pack = build_app_knowledge_pack(
        index,
        focus_hint=focus_hint,
        package_name=package_name,
        app_label=app_label,
    )
    _emit_progress(72, f"Application knowledge ready: {len(app_pack.get('records', []))} records")
    if not app_pack.get("success", False):
        warnings.append(str(app_pack.get("error", "app knowledge build failed")))
        app_pack = {
            "success": False,
            "knowledge": {},
            "records": [],
            "summary": {},
            "identity": {},
            "warnings": [],
        }

    hidden_state = get_cached_hidden_state_model(index, focus_hint=focus_hint, max_candidates=50)
    if not hidden_state.get("success", False):
        warnings.append(str(hidden_state.get("error", "hidden state recovery failed")))
        hidden_state = {"candidate_models": [], "candidate_state_fields": [], "writer_chains": [], "reader_chains": [], "summary": {}}

    guard_surface = get_cached_guard_surface_profile(index, focus_hint=focus_hint, max_clusters=50)
    if not guard_surface.get("success", False):
        warnings.append(str(guard_surface.get("error", "guard surface profiling failed")))
        guard_surface = {
            "guard_clusters": [],
            "overwrite_points": [],
            "native_or_dynamic_boundaries": [],
            "revalidation_loops": [],
            "summary": {},
        }

    _emit_progress(74, "Recovering enforcement surfaces")
    enforcement = find_enforcement_surfaces(
        index,
        feature=focus_hint,
        graph=graph,
        max_results=max_surfaces,
        progress_callback=lambda pct, detail: _emit_progress(74 + (pct * 0.18), detail),
    )
    if not enforcement.get("success", False):
        warnings.append(str(enforcement.get("error", "enforcement surface recovery failed")))
        enforcement = {"surfaces": [], "summary": {}, "role_summary": {}, "total_candidates": 0}

    _emit_progress(94, "Assembling behavior graph records")
    feature_controls = _build_feature_controls(
        enforcement.get("surfaces", []),
        hidden_state.get("candidate_state_fields", []),
        guard_surface.get("overwrite_points", []),
    )[:max_controls]
    state_transitions = _build_state_transitions(
        hidden_state.get("candidate_state_fields", []),
        guard_surface.get("revalidation_loops", []),
    )[:max_transitions]
    security_surfaces = _build_security_surfaces(
        guard_surface.get("guard_clusters", []),
        guard_surface.get("native_or_dynamic_boundaries", []),
        enforcement.get("surfaces", []),
    )[:max_security]
    runtime_hooks = _build_runtime_hooks(feature_controls, security_surfaces)[:max_hooks]
    network_behavior = _build_network_behavior(
        enforcement.get("surfaces", []),
        hidden_state.get("candidate_state_fields", []),
        app_pack.get("knowledge", {}).get("workflows", []),
    )
    symbol_hints = _build_symbol_hints(
        app_pack.get("knowledge", {}).get("entities", []),
        hidden_state.get("candidate_models", []),
        enforcement.get("surfaces", []),
        max_symbol_hints=max_symbol_hints,
    )
    semantic_relations = _build_semantic_relations(hidden_state)
    records = _build_records(
        app_pack.get("records", []),
        feature_controls,
        state_transitions,
        security_surfaces,
        runtime_hooks,
        network_behavior,
        symbol_hints,
        semantic_relations,
    )

    built_at = time.time()
    _emit_progress(98, "Computing behavior graph summary")
    pack = {
        "success": True,
        "pack_version": PACK_VERSION,
        "built_at": built_at,
        "focus_hint": focus_hint,
        "identity": {
            "package_name": package_name,
            "app_label": app_label,
            "total_classes": len(getattr(index, "classes", {}) or {}),
            "total_methods": len(getattr(index, "methods", {}) or {}),
            "smali_index_built_at": getattr(index, "built_at", 0.0),
        },
        "upstream": {
            "app_knowledge_summary": app_pack.get("summary", {}),
            "hidden_state_summary": hidden_state.get("summary", {}),
            "hidden_state_semantic_core": _semantic_core_summary(hidden_state, semantic_relations),
            "guard_surface_summary": guard_surface.get("summary", {}),
            "enforcement_summary": {
                "total_candidates": enforcement.get("total_candidates", 0),
                "role_summary": enforcement.get("role_summary", {}),
                "architecture_summary": enforcement.get("architecture_summary", {}),
            },
        },
        "behavior": {
            "feature_controls": feature_controls,
            "state_transitions": state_transitions,
            "security_surfaces": security_surfaces,
            "runtime_hooks": runtime_hooks,
            "network_behavior": network_behavior,
            "symbol_hints": symbol_hints,
            "semantic_relations": semantic_relations,
            "enforcement_surfaces": enforcement.get("surfaces", []),
        },
        "records": records[:400],
        "summary": _build_summary(
            feature_controls,
            state_transitions,
            security_surfaces,
            runtime_hooks,
            network_behavior,
            symbol_hints,
            semantic_relations,
            enforcement.get("surfaces", []),
        ),
        "warnings": warnings + list(app_pack.get("warnings", [])),
    }
    _emit_progress(
        100,
        f"Behavior graph complete: {len(records[:400])} records, {len(feature_controls)} controls, {len(enforcement.get('surfaces', []))} enforcement surfaces",
    )
    return pack


def save_behavior_graph(pack: dict[str, Any], output_path: str | Path) -> dict[str, Any]:
    """Persist a behavior graph pack as JSON using an atomic replace."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = output.with_suffix(output.suffix + ".tmp")
    payload = json.dumps(pack, ensure_ascii=False, indent=2)
    temp.write_text(payload, encoding="utf-8")
    temp.replace(output)
    return {
        "success": True,
        "path": str(output),
        "size_kb": round(output.stat().st_size / 1024, 1),
        "records": len(pack.get("records", [])),
        "pack_version": pack.get("pack_version", PACK_VERSION),
    }


def load_behavior_graph(input_path: str | Path) -> dict[str, Any] | None:
    """Load a persisted behavior graph pack from disk."""
    path = Path(input_path)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def summarize_behavior_graph(pack: dict[str, Any]) -> dict[str, Any]:
    """Return a compact summary of the behavior graph."""
    summary = dict(pack.get("summary", {}))
    summary.update({
        "pack_version": pack.get("pack_version", PACK_VERSION),
        "built_at": pack.get("built_at", 0.0),
        "package_name": pack.get("identity", {}).get("package_name", ""),
        "app_label": pack.get("identity", {}).get("app_label", ""),
        "record_count": len(pack.get("records", [])),
        "warning_count": len(pack.get("warnings", [])),
    })
    return {"success": True, "summary": summary}


def query_behavior_graph(
    pack: dict[str, Any],
    query: str,
    *,
    feature: str = "",
    class_name: str = "",
    method_name: str = "",
    record_type: str = "",
    max_results: int = 10,
) -> dict[str, Any]:
    """Query the unified behavior graph records."""
    if not pack:
        return {"success": False, "error": "Behavior graph pack is required"}

    tokens = _query_tokens(query, feature, class_name, method_name, record_type)
    if not tokens and not class_name and not method_name and not record_type:
        return {
            "success": False,
            "error": "At least one query token, class_name, method_name, or record_type is required",
        }

    matches: list[dict[str, Any]] = []
    for record in pack.get("records", []):
        if record_type and record.get("type", "") != record_type:
            continue
        score, reasons = _score_record(record, tokens, class_name=class_name, method_name=method_name)
        if score <= 0:
            continue
        item = dict(record)
        item["match_score"] = score
        item["match_reasons"] = reasons
        matches.append(item)

    matches.sort(key=lambda item: (-item.get("match_score", 0), -item.get("score", 0), item.get("title", "")))
    return {
        "success": True,
        "query": query,
        "feature": feature,
        "class_name": class_name,
        "method_name": method_name,
        "record_type": record_type,
        "total_matches": len(matches),
        "matches": matches[:max_results],
        "summary": summarize_behavior_graph(pack).get("summary", {}),
    }


def locate_feature_controls(
    pack: dict[str, Any],
    *,
    feature: str = "",
    class_name: str = "",
    method_name: str = "",
    max_results: int = 12,
) -> dict[str, Any]:
    """Return ranked feature activation, deactivation, and check control points."""
    if not pack:
        return {"success": False, "error": "Behavior graph pack is required"}

    tokens = _query_tokens(feature, "", class_name, method_name, "")
    matches = _rank_entries(
        pack.get("behavior", {}).get("feature_controls", []),
        tokens,
        class_name=class_name,
        method_name=method_name,
        text_builder=_feature_control_text,
    )
    return {
        "success": True,
        "feature": feature,
        "class_name": class_name,
        "method_name": method_name,
        "total_matches": len(matches),
        "controls": matches[:max_results],
        "summary": summarize_behavior_graph(pack).get("summary", {}),
    }


def recover_state_transitions(
    pack: dict[str, Any],
    *,
    class_name: str = "",
    field_name: str = "",
    max_results: int = 20,
) -> dict[str, Any]:
    """Return ranked state transitions from the unified behavior graph."""
    if not pack:
        return {"success": False, "error": "Behavior graph pack is required"}

    tokens = _query_tokens("", "", class_name, "", field_name)
    matches = _rank_entries(
        pack.get("behavior", {}).get("state_transitions", []),
        tokens,
        class_name=class_name,
        field_name=field_name,
        text_builder=_transition_text,
    )
    return {
        "success": True,
        "class_name": class_name,
        "field_name": field_name,
        "total_matches": len(matches),
        "transitions": matches[:max_results],
        "summary": summarize_behavior_graph(pack).get("summary", {}),
    }


def map_security_surfaces(
    pack: dict[str, Any],
    *,
    focus_hint: str = "",
    class_name: str = "",
    max_results: int = 20,
) -> dict[str, Any]:
    """Return ranked security and validation surfaces."""
    if not pack:
        return {"success": False, "error": "Behavior graph pack is required"}

    tokens = _query_tokens(focus_hint, "", class_name, "", "")
    matches = _rank_entries(
        pack.get("behavior", {}).get("security_surfaces", []),
        tokens,
        class_name=class_name,
        text_builder=_security_surface_text,
    )
    return {
        "success": True,
        "focus_hint": focus_hint,
        "class_name": class_name,
        "total_matches": len(matches),
        "security_surfaces": matches[:max_results],
        "summary": summarize_behavior_graph(pack).get("summary", {}),
    }


def plan_runtime_hooks(
    pack: dict[str, Any],
    *,
    focus_hint: str = "",
    class_name: str = "",
    max_results: int = 12,
) -> dict[str, Any]:
    """Return ranked runtime hook opportunities and guidance."""
    if not pack:
        return {"success": False, "error": "Behavior graph pack is required"}

    tokens = _query_tokens(focus_hint, "", class_name, "", "")
    matches = _rank_entries(
        pack.get("behavior", {}).get("runtime_hooks", []),
        tokens,
        class_name=class_name,
        text_builder=_runtime_hook_text,
    )
    return {
        "success": True,
        "focus_hint": focus_hint,
        "class_name": class_name,
        "total_matches": len(matches),
        "runtime_hooks": matches[:max_results],
        "summary": summarize_behavior_graph(pack).get("summary", {}),
    }


def annotate_runtime_hook_plan(
    hook_plan: dict[str, Any],
    *,
    smali_index=None,
) -> dict[str, Any]:
    """Attach strategy routing metadata to a runtime hook plan."""
    if not hook_plan:
        return {"success": False, "error": "Runtime hook plan is required"}

    hooks = list(hook_plan.get("runtime_hooks") or [])
    annotated = annotate_runtime_hook_recommendations(hooks, smali_index=smali_index)
    result = dict(hook_plan)
    result["runtime_hooks"] = annotated
    result["routing_summary"] = summarize_runtime_hook_recommendations(annotated)
    return result


def analyze_network_behavior(
    pack: dict[str, Any],
    *,
    focus_hint: str = "",
    max_results: int = 20,
) -> dict[str, Any]:
    """Return ranked network-to-state behavior paths."""
    if not pack:
        return {"success": False, "error": "Behavior graph pack is required"}

    network_behavior = pack.get("behavior", {}).get("network_behavior", {})
    entries = list(network_behavior.get("paths", [])) + list(network_behavior.get("state_ingress_fields", []))
    tokens = _query_tokens(focus_hint, "", "", "", "")
    matches = _rank_entries(entries, tokens, text_builder=_network_entry_text)
    return {
        "success": True,
        "focus_hint": focus_hint,
        "total_matches": len(matches),
        "client_categories": network_behavior.get("client_categories", {}),
        "workflows": network_behavior.get("workflows", []),
        "paths": matches[:max_results],
        "summary": summarize_behavior_graph(pack).get("summary", {}),
    }


def recover_semantic_symbols(
    pack: dict[str, Any],
    *,
    class_name: str = "",
    max_results: int = 12,
) -> dict[str, Any]:
    """Return behavior-derived semantic naming hints for obfuscated classes."""
    if not pack:
        return {"success": False, "error": "Behavior graph pack is required"}

    tokens = _query_tokens("", "", class_name, "", "")
    matches = _rank_entries(
        pack.get("behavior", {}).get("symbol_hints", []),
        tokens,
        class_name=class_name,
        text_builder=_symbol_hint_text,
    )
    return {
        "success": True,
        "class_name": class_name,
        "total_matches": len(matches),
        "symbol_hints": matches[:max_results],
        "summary": summarize_behavior_graph(pack).get("summary", {}),
    }


def _build_feature_controls(
    enforcement_surfaces: list[dict[str, Any]],
    state_fields: list[dict[str, Any]],
    overwrite_points: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    controls: dict[tuple[str, str, str, str], dict[str, Any]] = {}

    for surface in enforcement_surfaces:
        entry = {
            "action": _surface_action(surface),
            "origin": _surface_origin(surface),
            "class": surface.get("class", ""),
            "file": surface.get("file", ""),
            "method": surface.get("method", ""),
            "field": surface.get("state_field_hits", [""])[0] if surface.get("state_field_hits") else "",
            "score": float(surface.get("score", 0)),
            "control_role": surface.get("surface_role", "gate_method"),
            "state_semantics": surface.get("state_field_semantics", []),
            "api_categories": surface.get("api_categories", []),
            "reasons": surface.get("reasons", [])[:6],
            "source": "semantic_graph",
        }
        _store_ranked(controls, entry, key=(entry["action"], entry["class"], entry["method"], entry["field"]))

    for field in state_fields[:30]:
        writer_tags = set(field.get("writer_tags", []))
        reader_tags = set(field.get("reader_tags", []))
        origin = _tags_origin(writer_tags or reader_tags)
        action = "activate" if writer_tags & {"network", "serialization", "billing"} else "state_source"
        entry = {
            "action": action,
            "origin": origin,
            "class": field.get("class", ""),
            "file": field.get("file", ""),
            "method": "",
            "field": f"{field.get('class', '')}->{field.get('field', '')}",
            "score": float(field.get("score", 0)) + float(field.get("confidence", 0)) * 10.0,
            "control_role": "state_source_of_truth",
            "state_semantics": [field.get("semantic_guess", "state_value")],
            "api_categories": sorted(writer_tags | reader_tags),
            "reasons": [
                f"semantic: {field.get('semantic_guess', 'state_value')}",
                f"readers={field.get('read_count', 0)} writers={field.get('write_count', 0)}",
                f"recommended: {field.get('recommended_patch_strategy', '')}",
            ],
            "source": "state_model_recovery",
        }
        _store_ranked(controls, entry, key=(entry["action"], entry["class"], entry["method"], entry["field"]))

    for point in overwrite_points[:25]:
        trigger_tags = point.get("trigger_tags", [])
        guard_tags = point.get("guard_tags", [])
        entry = {
            "action": "deactivate",
            "origin": "runtime" if trigger_tags else "local",
            "class": point.get("class", ""),
            "file": point.get("file", ""),
            "method": point.get("method", ""),
            "field": ", ".join(point.get("field_targets", [])[:3]),
            "score": float(point.get("state_write_count", 0)) * 8.0,
            "control_role": "state_overwrite",
            "state_semantics": [],
            "api_categories": list(trigger_tags),
            "reasons": [
                f"state writes: {point.get('state_write_count', 0)}",
                f"guard tags: {', '.join(guard_tags[:4])}" if guard_tags else "",
                f"trigger tags: {', '.join(trigger_tags[:4])}" if trigger_tags else "",
            ],
            "source": "guard_surface_profiler",
        }
        _store_ranked(controls, entry, key=(entry["action"], entry["class"], entry["method"], entry["field"]))

    results = list(controls.values())
    results.sort(key=lambda item: (-item.get("score", 0), item.get("class", ""), item.get("method", "")))
    return results


def _build_state_transitions(
    state_fields: list[dict[str, Any]],
    revalidation_loops: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    transitions: list[dict[str, Any]] = []

    for field in state_fields[:30]:
        field_ref = f"{field.get('class', '')}->{field.get('field', '')}"
        semantic = field.get("semantic_guess", "state_value")
        score_base = float(field.get("score", 0)) + float(field.get("confidence", 0)) * 10.0
        writer_samples = field.get("writer_samples", [])[:2]
        reader_samples = field.get("reader_samples", [])[:2]

        for writer in writer_samples:
            transitions.append({
                "class": field.get("class", ""),
                "file": writer.get("file", field.get("file", "")),
                "source": writer.get("method", ""),
                "target": field_ref,
                "via_field": field_ref,
                "transition_type": _writer_transition_type(writer.get("tags", []), semantic),
                "trigger_tags": writer.get("tags", []),
                "reader_tags": [],
                "score": score_base + 8.0,
                "reasons": [f"writer -> {field_ref}", f"semantic: {semantic}"],
            })

        for reader in reader_samples:
            transitions.append({
                "class": field.get("class", ""),
                "file": reader.get("file", field.get("file", "")),
                "source": field_ref,
                "target": reader.get("method", ""),
                "via_field": field_ref,
                "transition_type": _reader_transition_type(reader.get("tags", []), semantic),
                "trigger_tags": [],
                "reader_tags": reader.get("tags", []),
                "score": score_base + 6.0,
                "reasons": [f"{field_ref} -> reader", f"semantic: {semantic}"],
            })

        for writer in writer_samples:
            for reader in reader_samples:
                transitions.append({
                    "class": field.get("class", ""),
                    "file": field.get("file", ""),
                    "source": writer.get("method", ""),
                    "target": reader.get("method", ""),
                    "via_field": field_ref,
                    "transition_type": _bridge_transition_type(writer.get("tags", []), reader.get("tags", []), semantic),
                    "trigger_tags": writer.get("tags", []),
                    "reader_tags": reader.get("tags", []),
                    "score": score_base + 12.0,
                    "reasons": [
                        f"via field: {field_ref}",
                        f"semantic: {semantic}",
                        f"writer tags: {', '.join(writer.get('tags', [])[:3])}",
                    ],
                })

    for loop in revalidation_loops[:20]:
        transitions.append({
            "class": loop.get("class", ""),
            "file": loop.get("file", ""),
            "source": loop.get("class", ""),
            "target": loop.get("class", ""),
            "via_field": "",
            "transition_type": "lifecycle_revalidation_cycle",
            "trigger_tags": ["revalidation_loop"],
            "reader_tags": [],
            "score": float(loop.get("revalidation_method_count", 0)) * 10.0,
            "reasons": [f"revalidation methods: {loop.get('revalidation_method_count', 0)}"],
        })

    transitions.sort(key=lambda item: (-item.get("score", 0), item.get("class", ""), item.get("source", ""), item.get("target", "")))
    return transitions


def _build_security_surfaces(
    guard_clusters: list[dict[str, Any]],
    native_boundaries: list[dict[str, Any]],
    enforcement_surfaces: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    surfaces: dict[tuple[str, str, str], dict[str, Any]] = {}

    for item in guard_clusters[:50]:
        surface_type = "revalidation_boundary" if float(item.get("state_write_count", 0)) > 0 else "validation_point"
        entry = {
            "surface_type": surface_type,
            "class": item.get("class", ""),
            "file": item.get("file", ""),
            "method": item.get("method", ""),
            "severity": float(item.get("severity_score", 0)),
            "tags": list(dict.fromkeys(item.get("guard_tags", []) + item.get("boundary_tags", []) + item.get("trigger_tags", []))),
            "reasons": [
                f"guard tags: {', '.join(item.get('guard_tags', [])[:4])}" if item.get("guard_tags") else "",
                f"trigger tags: {', '.join(item.get('trigger_tags', [])[:4])}" if item.get("trigger_tags") else "",
                f"state writes: {item.get('state_write_count', 0)}",
            ],
            "suggested_runtime_hook_points": item.get("suggested_runtime_hook_points", []),
            "suggested_static_patch_points": item.get("suggested_static_patch_points", []),
            "source": "guard_surface_profiler",
        }
        _store_ranked(surfaces, entry, key=(entry["surface_type"], entry["class"], entry["method"]))

    for item in native_boundaries[:30]:
        entry = {
            "surface_type": "dynamic_or_native_boundary",
            "class": item.get("class", ""),
            "file": item.get("file", ""),
            "method": item.get("method", ""),
            "severity": float(len(item.get("boundary_tags", []))) * 8.0,
            "tags": list(dict.fromkeys(item.get("boundary_tags", []) + item.get("guard_tags", []))),
            "reasons": [
                f"boundary tags: {', '.join(item.get('boundary_tags', [])[:4])}" if item.get("boundary_tags") else "dynamic/native boundary",
                f"guard tags: {', '.join(item.get('guard_tags', [])[:4])}" if item.get("guard_tags") else "",
            ],
            "suggested_runtime_hook_points": ["runtime_hook_recommended"],
            "suggested_static_patch_points": [],
            "source": "guard_surface_profiler",
        }
        _store_ranked(surfaces, entry, key=(entry["surface_type"], entry["class"], entry["method"]))

    for item in enforcement_surfaces[:40]:
        api_categories = set(item.get("api_categories", []))
        if api_categories & {"ssl_tls", "crypto"}:
            entry = {
                "surface_type": "crypto_or_tls_boundary",
                "class": item.get("class", ""),
                "file": item.get("file", ""),
                "method": item.get("method", ""),
                "severity": float(item.get("score", 0)),
                "tags": sorted(api_categories),
                "reasons": item.get("reasons", [])[:6],
                "suggested_runtime_hook_points": ["frida_probe_tls_path"],
                "suggested_static_patch_points": ["patch_boundary_before_build"],
                "source": "semantic_graph",
            }
            _store_ranked(surfaces, entry, key=(entry["surface_type"], entry["class"], entry["method"]))
        elif api_categories & {"network", "serialization", "billing"} and item.get("surface_role") in {"revalidation_boundary", "state_mutator"}:
            entry = {
                "surface_type": "api_boundary",
                "class": item.get("class", ""),
                "file": item.get("file", ""),
                "method": item.get("method", ""),
                "severity": float(item.get("score", 0)),
                "tags": sorted(api_categories),
                "reasons": item.get("reasons", [])[:6],
                "suggested_runtime_hook_points": ["observe_response_boundary"],
                "suggested_static_patch_points": ["patch_api_response_flow"],
                "source": "semantic_graph",
            }
            _store_ranked(surfaces, entry, key=(entry["surface_type"], entry["class"], entry["method"]))

    results = list(surfaces.values())
    results.sort(key=lambda item: (-item.get("severity", 0), item.get("class", ""), item.get("method", "")))
    return results


def _build_runtime_hooks(
    feature_controls: list[dict[str, Any]],
    security_surfaces: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    hooks: dict[tuple[str, str], dict[str, Any]] = {}

    for surface in security_surfaces:
        runtime_points = surface.get("suggested_runtime_hook_points", [])
        if not runtime_points and surface.get("surface_type") not in {"revalidation_boundary", "dynamic_or_native_boundary"}:
            continue
        strategy = "observe_and_override_state" if surface.get("surface_type") == "revalidation_boundary" else "probe_runtime_boundary"
        entry = {
            "class": surface.get("class", ""),
            "file": surface.get("file", ""),
            "method": surface.get("method", ""),
            "score": float(surface.get("severity", 0)),
            "strategy": strategy,
            "observe": runtime_points or [surface.get("surface_type", "runtime_path")],
            "mutate": ["override return/state"] if surface.get("surface_type") != "dynamic_or_native_boundary" else ["inspect hidden runtime branch"],
            "recommended_tools": ["inject_runtime_override_layer"] if surface.get("surface_type") == "revalidation_boundary" else ["frida_script_generator"],
            "reasons": surface.get("reasons", [])[:5],
            "source": surface.get("source", "behavior_engine"),
        }
        _store_ranked(hooks, entry, key=(entry["class"], entry["method"]))

    for control in feature_controls:
        if control.get("origin") != "runtime" and control.get("action") not in {"deactivate", "revalidate"}:
            continue
        entry = {
            "class": control.get("class", ""),
            "file": control.get("file", ""),
            "method": control.get("method", ""),
            "score": float(control.get("score", 0)),
            "strategy": "hook_feature_revalidation",
            "observe": [control.get("control_role", "runtime_check")],
            "mutate": [control.get("action", "override")],
            "recommended_tools": ["inject_runtime_override_layer", "frida_script_generator"],
            "reasons": control.get("reasons", [])[:5],
            "source": control.get("source", "behavior_engine"),
        }
        _store_ranked(hooks, entry, key=(entry["class"], entry["method"]))

    results = list(hooks.values())
    results.sort(key=lambda item: (-item.get("score", 0), item.get("class", ""), item.get("method", "")))
    return results


def _build_network_behavior(
    enforcement_surfaces: list[dict[str, Any]],
    state_fields: list[dict[str, Any]],
    workflows: list[dict[str, Any]],
) -> dict[str, Any]:
    client_categories: Counter[str] = Counter()
    paths: list[dict[str, Any]] = []
    ingress_fields: list[dict[str, Any]] = []

    for item in enforcement_surfaces[:40]:
        api_categories = set(item.get("api_categories", []))
        network_tags = sorted(api_categories & {"network", "serialization", "billing"})
        if not network_tags:
            continue
        for tag in network_tags:
            client_categories[tag] += 1
        paths.append({
            "class": item.get("class", ""),
            "file": item.get("file", ""),
            "method": item.get("method", ""),
            "score": float(item.get("score", 0)),
            "surface_role": item.get("surface_role", ""),
            "api_categories": item.get("api_categories", []),
            "state_field_semantics": item.get("state_field_semantics", []),
            "reasons": item.get("reasons", [])[:5],
        })

    for field in state_fields[:30]:
        writer_tags = set(field.get("writer_tags", []))
        if not writer_tags & {"network", "serialization", "billing"}:
            continue
        ingress_fields.append({
            "class": field.get("class", ""),
            "file": field.get("file", ""),
            "method": "",
            "field": f"{field.get('class', '')}->{field.get('field', '')}",
            "score": float(field.get("score", 0)) + float(field.get("confidence", 0)) * 10.0,
            "writer_tags": field.get("writer_tags", []),
            "semantic_guess": field.get("semantic_guess", "state_value"),
            "recommended_patch_strategy": field.get("recommended_patch_strategy", ""),
            "reasons": [
                f"writer tags: {', '.join(field.get('writer_tags', [])[:4])}",
                f"semantic: {field.get('semantic_guess', 'state_value')}",
            ],
        })

    behavior_workflows = [
        workflow
        for workflow in workflows
        if "network" in workflow.get("name", "") or "billing" in workflow.get("name", "")
    ]
    paths.sort(key=lambda item: (-item.get("score", 0), item.get("class", ""), item.get("method", "")))
    ingress_fields.sort(key=lambda item: (-item.get("score", 0), item.get("class", ""), item.get("field", "")))
    return {
        "client_categories": dict(client_categories),
        "paths": paths[:25],
        "state_ingress_fields": ingress_fields[:25],
        "workflows": behavior_workflows[:10],
    }


def _build_symbol_hints(
    entities: list[dict[str, Any]],
    candidate_models: list[dict[str, Any]],
    enforcement_surfaces: list[dict[str, Any]],
    *,
    max_symbol_hints: int,
) -> list[dict[str, Any]]:
    entity_map = {item.get("class", ""): item for item in entities if item.get("class")}
    surfaces_by_class: dict[str, list[dict[str, Any]]] = {}
    for surface in enforcement_surfaces:
        class_name = surface.get("class", "")
        if not class_name:
            continue
        surfaces_by_class.setdefault(class_name, []).append(surface)

    hints: list[dict[str, Any]] = []
    seen: set[str] = set()
    for model in candidate_models:
        class_name = model.get("class", "")
        if not class_name or class_name in seen:
            continue
        seen.add(class_name)
        entity = entity_map.get(class_name, {})
        role_candidates = list(entity.get("roles", [])) + list(entity.get("dominant_roles", []))
        roles = list(dict.fromkeys(role_candidates))
        surfaces = surfaces_by_class.get(class_name, [])
        short_name = class_name.strip("L;").split("/")[-1]
        semantic_guesses = [field.get("semantic_guess", "") for field in entity.get("top_fields", []) if field.get("semantic_guess")]
        obfuscated = len(short_name) <= 3
        confidence = 0.45
        reasons: list[str] = []
        if obfuscated:
            confidence += 0.2
            reasons.append("short class token suggests obfuscation")
        if roles:
            confidence += 0.15
            reasons.append(f"roles: {', '.join(roles[:3])}")
        if semantic_guesses:
            confidence += 0.15
            reasons.append(f"field semantics: {', '.join(semantic_guesses[:3])}")
        if surfaces:
            confidence += 0.1
            reasons.append(f"enforcement surfaces: {len(surfaces)}")

        hints.append({
            "class": class_name,
            "file": model.get("file", entity.get("file", "")),
            "score": float(model.get("score", 0)) + len(surfaces) * 6.0,
            "obfuscated": obfuscated,
            "suggested_name": _suggest_symbol_name(roles, semantic_guesses),
            "roles": roles,
            "semantic_guesses": semantic_guesses[:5],
            "related_methods": [surface.get("method", "") for surface in surfaces[:5]],
            "confidence": round(min(confidence, 0.95), 3),
            "reasons": reasons,
        })

    hints.sort(key=lambda item: (-item.get("obfuscated", False), -item.get("score", 0), item.get("class", "")))
    return hints[:max_symbol_hints]


def _suggest_symbol_name(roles: list[str], semantic_guesses: list[str]) -> str:
    role_set = set(roles)
    semantic_set = set(semantic_guesses)
    if "billing_flow" in role_set:
        return "BillingCoordinator"
    if "security_guards" in role_set:
        return "IntegrityGuard"
    if "dynamic_native_boundaries" in role_set:
        return "DynamicBridge"
    if "network_layer" in role_set and "serialization_layer" in role_set:
        return "NetworkResponseMapper"
    if "state_models" in role_set and semantic_set & {"entitlement_flag", "subscription_plan", "subscription_tier"}:
        return "EntitlementState"
    if "state_models" in role_set and "expiry_or_timestamp" in semantic_set:
        return "AccessExpiryState"
    if "state_models" in role_set:
        return "StateEntity"
    if "ui_gate_controllers" in role_set:
        return "FeatureGateController"
    return "SemanticClassHint"


def _build_records(
    base_records: list[dict[str, Any]],
    feature_controls: list[dict[str, Any]],
    state_transitions: list[dict[str, Any]],
    security_surfaces: list[dict[str, Any]],
    runtime_hooks: list[dict[str, Any]],
    network_behavior: dict[str, Any],
    symbol_hints: list[dict[str, Any]],
    semantic_relations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    records = [dict(record) for record in base_records[:180]]

    for control in feature_controls[:50]:
        records.append(_record(
            record_type="feature_control",
            title=f"{control.get('action', 'control')}: {control.get('class', '')}",
            score=float(control.get("score", 0)),
            class_name=control.get("class", ""),
            method_name=control.get("method", ""),
            field_name=control.get("field", ""),
            file_path=control.get("file", ""),
            evidence=[control.get("origin", ""), control.get("control_role", ""), *control.get("reasons", [])],
            source=control.get("source", "behavior_engine"),
        ))

    for transition in state_transitions[:80]:
        records.append(_record(
            record_type="state_transition",
            title=f"transition: {transition.get('transition_type', 'state_flow')}",
            score=float(transition.get("score", 0)),
            class_name=transition.get("class", ""),
            method_name=transition.get("target", "") if "->" in transition.get("target", "") else transition.get("source", ""),
            field_name=transition.get("via_field", ""),
            file_path=transition.get("file", ""),
            evidence=[transition.get("source", ""), transition.get("target", ""), *transition.get("reasons", [])],
            source="behavior_engine",
        ))

    for surface in security_surfaces[:40]:
        records.append(_record(
            record_type="security_surface",
            title=f"{surface.get('surface_type', 'security_surface')}: {surface.get('class', '')}",
            score=float(surface.get("severity", 0)),
            class_name=surface.get("class", ""),
            method_name=surface.get("method", ""),
            file_path=surface.get("file", ""),
            evidence=[*surface.get("tags", []), *surface.get("reasons", [])],
            source=surface.get("source", "behavior_engine"),
        ))

    for hook in runtime_hooks[:25]:
        records.append(_record(
            record_type="runtime_hook",
            title=f"runtime hook: {hook.get('class', '')}",
            score=float(hook.get("score", 0)),
            class_name=hook.get("class", ""),
            method_name=hook.get("method", ""),
            file_path=hook.get("file", ""),
            evidence=[hook.get("strategy", ""), *hook.get("observe", []), *hook.get("mutate", []), *hook.get("reasons", [])],
            source=hook.get("source", "behavior_engine"),
        ))

    for path in network_behavior.get("paths", [])[:25]:
        records.append(_record(
            record_type="network_behavior",
            title=f"network path: {path.get('class', '')}",
            score=float(path.get("score", 0)),
            class_name=path.get("class", ""),
            method_name=path.get("method", ""),
            file_path=path.get("file", ""),
            evidence=[path.get("surface_role", ""), *path.get("api_categories", []), *path.get("state_field_semantics", []), *path.get("reasons", [])],
            source="behavior_engine",
        ))

    for field in network_behavior.get("state_ingress_fields", [])[:25]:
        records.append(_record(
            record_type="network_state_ingress",
            title=f"network ingress: {field.get('class', '')}",
            score=float(field.get("score", 0)),
            class_name=field.get("class", ""),
            field_name=field.get("field", ""),
            file_path=field.get("file", ""),
            evidence=[field.get("semantic_guess", ""), *field.get("writer_tags", []), *field.get("reasons", [])],
            source="behavior_engine",
        ))

    for hint in symbol_hints[:20]:
        records.append(_record(
            record_type="symbol_hint",
            title=f"symbol hint: {hint.get('suggested_name', '')}",
            score=float(hint.get("score", 0)),
            class_name=hint.get("class", ""),
            file_path=hint.get("file", ""),
            evidence=[hint.get("suggested_name", ""), *hint.get("roles", []), *hint.get("semantic_guesses", []), *hint.get("reasons", [])],
            source="behavior_engine",
        ))

    for relation in semantic_relations[:40]:
        records.append(_record(
            record_type="semantic_relation",
            title=f"semantic relation: {relation.get('relation_type', '')}",
            score=float(relation.get("score", 0)),
            class_name=relation.get("class", ""),
            method_name=relation.get("method", ""),
            field_name=relation.get("field", ""),
            file_path=relation.get("file", ""),
            evidence=relation.get("reasons", []),
            source="semantic_core",
        ))

    return records


def _build_summary(
    feature_controls: list[dict[str, Any]],
    state_transitions: list[dict[str, Any]],
    security_surfaces: list[dict[str, Any]],
    runtime_hooks: list[dict[str, Any]],
    network_behavior: dict[str, Any],
    symbol_hints: list[dict[str, Any]],
    semantic_relations: list[dict[str, Any]],
    enforcement_surfaces: list[dict[str, Any]],
) -> dict[str, Any]:
    action_counts = Counter(item.get("action", "unknown") for item in feature_controls)
    origin_counts = Counter(item.get("origin", "unknown") for item in feature_controls)
    transition_counts = Counter(item.get("transition_type", "unknown") for item in state_transitions)
    security_counts = Counter(item.get("surface_type", "unknown") for item in security_surfaces)
    hook_counts = Counter(item.get("strategy", "unknown") for item in runtime_hooks)
    semantic_relation_counts = Counter(item.get("relation_type", "unknown") for item in semantic_relations)
    return {
        "feature_control_count": len(feature_controls),
        "state_transition_count": len(state_transitions),
        "security_surface_count": len(security_surfaces),
        "runtime_hook_count": len(runtime_hooks),
        "network_path_count": len(network_behavior.get("paths", [])),
        "network_ingress_count": len(network_behavior.get("state_ingress_fields", [])),
        "symbol_hint_count": len(symbol_hints),
        "semantic_relation_count": len(semantic_relations),
        "enforcement_surface_count": len(enforcement_surfaces),
        "control_actions": dict(action_counts),
        "control_origins": dict(origin_counts),
        "transition_types": dict(transition_counts.most_common(10)),
        "security_surface_types": dict(security_counts),
        "runtime_hook_strategies": dict(hook_counts),
        "semantic_relation_types": dict(semantic_relation_counts),
        "network_client_categories": network_behavior.get("client_categories", {}),
    }


def _build_semantic_relations(hidden_state: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(hidden_state, dict):
        return []

    nodes = hidden_state.get("nodes", []) if isinstance(hidden_state.get("nodes"), list) else []
    edges = hidden_state.get("edges", []) if isinstance(hidden_state.get("edges"), list) else []
    cycle_summary = hidden_state.get("cycle_summary", {}) if isinstance(hidden_state.get("cycle_summary"), dict) else {}
    node_by_id = {
        str(node.get("id", "")): node
        for node in nodes
        if isinstance(node, dict) and node.get("id")
    }

    relations: list[dict[str, Any]] = []
    for edge in edges[:160]:
        if not isinstance(edge, dict):
            continue
        source_node = node_by_id.get(str(edge.get("source", "")), {})
        source_ref = str(source_node.get("source_ref", ""))
        class_name, _, field_part = source_ref.partition("->")
        field_name = field_part.split(":", 1)[0] if field_part else ""
        kind = str(edge.get("kind", ""))
        if kind == "capability_link":
            target_node = node_by_id.get(str(edge.get("target", "")), {})
            relations.append({
                "relation_type": "capability_link",
                "class": class_name,
                "file": "",
                "method": "",
                "field": field_name,
                "score": 32.0,
                "reasons": [
                    f"capability: {target_node.get('capability_kind', '')}",
                    f"state_class: {source_node.get('state_class', '')}",
                    f"rule: {edge.get('rule_id', '')}",
                ],
            })
        elif kind == "contradiction":
            relations.append({
                "relation_type": "contradiction",
                "class": class_name,
                "file": "",
                "method": "",
                "field": field_name,
                "score": 22.0,
                "reasons": [
                    f"kind: {edge.get('contradiction_kind', '')}",
                    f"state_class: {source_node.get('state_class', '')}",
                    f"rule: {edge.get('rule_id', '')}",
                ],
            })
        elif kind == "derive":
            relations.append({
                "relation_type": "derive",
                "class": class_name,
                "file": "",
                "method": "",
                "field": field_name,
                "score": 20.0,
                "reasons": [
                    f"from: {source_ref}",
                    f"rule: {edge.get('rule_id', '')}",
                ],
            })

    for component in cycle_summary.get("components", [])[:12] if isinstance(cycle_summary.get("components"), list) else []:
        if not isinstance(component, dict):
            continue
        relations.append({
            "relation_type": "cycle_summary",
            "class": "",
            "file": "",
            "method": "",
            "field": "",
            "score": 18.0 + float(component.get("size", 0) or 0),
            "reasons": [
                f"component: {component.get('component_id', '')}",
                f"size: {component.get('size', 0)}",
            ],
        })

    relations.sort(key=lambda item: (-float(item.get("score", 0)), item.get("relation_type", ""), item.get("class", ""), item.get("field", "")))
    return relations


def _semantic_core_summary(hidden_state: dict[str, Any], semantic_relations: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(hidden_state, dict):
        return {}
    return {
        "semantic_schema_version": str(hidden_state.get("semantic_schema_version", "") or ""),
        "artifact_kind": str(hidden_state.get("artifact_kind", "") or ""),
        "rule_count": len(hidden_state.get("rule_manifest", []) if isinstance(hidden_state.get("rule_manifest"), list) else []),
        "node_count": len(hidden_state.get("nodes", []) if isinstance(hidden_state.get("nodes"), list) else []),
        "edge_count": len(hidden_state.get("edges", []) if isinstance(hidden_state.get("edges"), list) else []),
        "cycle_count": int((hidden_state.get("cycle_summary", {}) if isinstance(hidden_state.get("cycle_summary"), dict) else {}).get("cycle_count", 0) or 0),
        "semantic_relation_count": len(semantic_relations),
    }


def _record(
    *,
    record_type: str,
    title: str,
    score: float,
    class_name: str = "",
    method_name: str = "",
    field_name: str = "",
    file_path: str = "",
    evidence: list[Any] | None = None,
    source: str = "behavior_engine",
) -> dict[str, Any]:
    evidence_list = [str(item) for item in (evidence or []) if str(item).strip()]
    text = " ".join(part for part in [title, class_name, method_name, field_name, file_path, *evidence_list] if part)
    return {
        "type": record_type,
        "title": title,
        "score": round(float(score), 3),
        "class": class_name,
        "method": method_name,
        "field": field_name,
        "file": file_path,
        "evidence": evidence_list[:10],
        "source": source,
        "text": text,
    }


def _store_ranked(store: dict[tuple[str, ...], dict[str, Any]], entry: dict[str, Any], *, key: tuple[str, ...]) -> None:
    current = store.get(key)
    if current is None or float(entry.get("score", entry.get("severity", 0))) > float(current.get("score", current.get("severity", 0))):
        reasons = [reason for reason in entry.get("reasons", []) if reason]
        entry["reasons"] = reasons
        store[key] = entry


def _surface_origin(surface: dict[str, Any]) -> str:
    api_categories = set(surface.get("api_categories", []))
    if api_categories & {"network", "serialization", "billing"}:
        return "server"
    if surface.get("revalidation_loop_owner") or surface.get("guard_cluster_match"):
        return "runtime"
    if api_categories & {"storage"}:
        return "storage"
    return "local"


def _tags_origin(tags: set[str]) -> str:
    if tags & {"network", "serialization", "billing"}:
        return "server"
    if tags & {"persistence"}:
        return "storage"
    if tags & {"ui", "time", "state"}:
        return "local"
    return "local"


def _surface_action(surface: dict[str, Any]) -> str:
    role = surface.get("surface_role", "gate_method")
    if role in {"gate_method", "gate_accessor"}:
        return "check"
    if role == "revalidation_boundary":
        return "revalidate"
    if role == "state_mutator":
        return "activate" if _surface_origin(surface) == "server" else "mutate"
    return "check"


def _writer_transition_type(tags: list[str], semantic: str) -> str:
    tag_set = set(tags)
    if tag_set & {"network", "serialization", "billing"}:
        return "server_or_parser_write"
    if tag_set & {"persistence"}:
        return "persisted_state_write"
    if tag_set & {"time"} or "expiry" in semantic:
        return "expiry_state_write"
    if tag_set & {"ui"}:
        return "ui_local_write"
    return "state_write"


def _reader_transition_type(tags: list[str], semantic: str) -> str:
    tag_set = set(tags)
    if tag_set & {"ui"}:
        return "ui_gate_read"
    if tag_set & {"persistence"}:
        return "cached_state_read"
    if tag_set & {"network"}:
        return "network_reuse"
    if tag_set & {"time"} or "expiry" in semantic:
        return "expiry_gate_read"
    return "state_read"


def _bridge_transition_type(writer_tags: list[str], reader_tags: list[str], semantic: str) -> str:
    writer_set = set(writer_tags)
    reader_set = set(reader_tags)
    if writer_set & {"network", "serialization", "billing"} and reader_set & {"ui", "state", "persistence"}:
        return "server_response_to_feature_gate"
    if writer_set & {"persistence"} and reader_set & {"ui"}:
        return "persisted_state_to_ui"
    if writer_set & {"time"} or reader_set & {"time"} or "expiry" in semantic:
        return "expiry_or_time_gate"
    return "state_propagation"


def _rank_entries(
    entries: list[dict[str, Any]],
    tokens: set[str],
    *,
    class_name: str = "",
    method_name: str = "",
    field_name: str = "",
    text_builder=None,
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for entry in entries:
        text = text_builder(entry) if text_builder is not None else _entry_text(entry)
        record = {
            "text": text,
            "score": float(entry.get("score", entry.get("severity", 0))),
            "class": entry.get("class", ""),
            "method": entry.get("method", ""),
            "field": entry.get("field", entry.get("via_field", "")),
        }
        score, reasons = _score_record(record, tokens, class_name=class_name, method_name=method_name, field_name=field_name)
        if score <= 0 and (tokens or class_name or method_name or field_name):
            continue
        item = dict(entry)
        item["match_score"] = score if score > 0 else float(entry.get("score", entry.get("severity", 0))) * 0.05
        item["match_reasons"] = reasons
        matches.append(item)

    matches.sort(key=lambda item: (-item.get("match_score", 0), -float(item.get("score", item.get("severity", 0))), item.get("class", ""), item.get("method", "")))
    return matches


def _feature_control_text(entry: dict[str, Any]) -> str:
    return " ".join([
        str(entry.get("action", "")),
        str(entry.get("origin", "")),
        str(entry.get("class", "")),
        str(entry.get("method", "")),
        str(entry.get("field", "")),
        str(entry.get("control_role", "")),
        " ".join(str(item) for item in entry.get("state_semantics", [])),
        " ".join(str(item) for item in entry.get("api_categories", [])),
        " ".join(str(item) for item in entry.get("reasons", [])),
    ])


def _transition_text(entry: dict[str, Any]) -> str:
    return " ".join([
        str(entry.get("transition_type", "")),
        str(entry.get("class", "")),
        str(entry.get("source", "")),
        str(entry.get("target", "")),
        str(entry.get("via_field", "")),
        " ".join(str(item) for item in entry.get("trigger_tags", [])),
        " ".join(str(item) for item in entry.get("reader_tags", [])),
        " ".join(str(item) for item in entry.get("reasons", [])),
    ])


def _security_surface_text(entry: dict[str, Any]) -> str:
    return " ".join([
        str(entry.get("surface_type", "")),
        str(entry.get("class", "")),
        str(entry.get("method", "")),
        " ".join(str(item) for item in entry.get("tags", [])),
        " ".join(str(item) for item in entry.get("reasons", [])),
    ])


def _runtime_hook_text(entry: dict[str, Any]) -> str:
    return " ".join([
        str(entry.get("strategy", "")),
        str(entry.get("class", "")),
        str(entry.get("method", "")),
        " ".join(str(item) for item in entry.get("observe", [])),
        " ".join(str(item) for item in entry.get("mutate", [])),
        " ".join(str(item) for item in entry.get("reasons", [])),
    ])


def _network_entry_text(entry: dict[str, Any]) -> str:
    return " ".join([
        str(entry.get("class", "")),
        str(entry.get("method", "")),
        str(entry.get("field", "")),
        str(entry.get("surface_role", "")),
        str(entry.get("semantic_guess", "")),
        str(entry.get("recommended_patch_strategy", "")),
        " ".join(str(item) for item in entry.get("api_categories", [])),
        " ".join(str(item) for item in entry.get("writer_tags", [])),
        " ".join(str(item) for item in entry.get("reasons", [])),
    ])


def _symbol_hint_text(entry: dict[str, Any]) -> str:
    return " ".join([
        str(entry.get("class", "")),
        str(entry.get("suggested_name", "")),
        " ".join(str(item) for item in entry.get("roles", [])),
        " ".join(str(item) for item in entry.get("semantic_guesses", [])),
        " ".join(str(item) for item in entry.get("reasons", [])),
    ])


def _entry_text(entry: dict[str, Any]) -> str:
    return " ".join(str(value) for value in entry.values() if isinstance(value, (str, int, float)))


def _query_tokens(*parts: str) -> set[str]:
    blob = " ".join(part for part in parts if part)
    return {
        token.lower()
        for token in blob.replace("->", " ").replace(":", " ").replace("(", " ").replace(")", " ").split()
        if len(token) >= 2
    }


def _score_record(
    record: dict[str, Any],
    tokens: set[str],
    *,
    class_name: str = "",
    method_name: str = "",
    field_name: str = "",
) -> tuple[float, list[str]]:
    text = str(record.get("text", "")).lower()
    score = float(record.get("score", 0)) * 0.05
    reasons: list[str] = []

    for token in tokens:
        if token in text:
            score += 6.0
            reasons.append(f"token:{token}")

    record_class = str(record.get("class", ""))
    record_method = str(record.get("method", ""))
    record_field = str(record.get("field", ""))

    if class_name and class_name == record_class:
        score += 40.0
        reasons.append("class exact")
    elif class_name and class_name.lower() in record_class.lower():
        score += 18.0
        reasons.append("class partial")

    if method_name and method_name == record_method:
        score += 40.0
        reasons.append("method exact")
    elif method_name and method_name.lower() in record_method.lower():
        score += 18.0
        reasons.append("method partial")

    if field_name and field_name == record_field:
        score += 30.0
        reasons.append("field exact")
    elif field_name and field_name.lower() in record_field.lower():
        score += 14.0
        reasons.append("field partial")

    if record_field and any(token == record_field.lower() for token in tokens):
        score += 12.0
        reasons.append("field token")

    return score, reasons