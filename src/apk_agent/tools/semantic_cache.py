"""Runtime-scoped memoization for expensive semantic analyses.

This keeps heavyweight semantic passes reusable across additive tools that all
operate on the same SmaliIndex during one session.
"""

from __future__ import annotations

import copy
import inspect
from typing import Any

from apk_agent.agent.execution_context import get_runtime_slot, set_runtime_slot
from apk_agent.tools.semantic_core.identity import normalize_field_source
from apk_agent.tools.semantic_core.schema import SEMANTIC_SCHEMA_VERSION


_ARCHITECTURE_ROLES = (
    "entry_points",
    "network_layer",
    "serialization_layer",
    "state_models",
    "state_stores",
    "ui_gate_controllers",
    "security_guards",
    "dynamic_native_boundaries",
    "billing_flow",
)


def _slot_cache(name: str) -> dict[tuple[Any, ...], Any]:
    cache = get_runtime_slot(name)
    if isinstance(cache, dict):
        return cache
    cache = {}
    set_runtime_slot(name, cache)
    return cache


def _index_signature(index) -> tuple[Any, ...]:
    classes = getattr(index, "classes", {}) or {}
    methods = getattr(index, "methods", {}) or {}
    return (
        id(index),
        float(getattr(index, "built_at", 0.0) or 0.0),
        len(classes),
        len(methods),
    )


def _best_cached_result(
    cache: dict[tuple[Any, ...], Any],
    index_signature: tuple[Any, ...],
    focus_hint: str,
    requested_limit: int,
):
    best_key = None
    best_limit = None
    for key in cache:
        if len(key) != 3:
            continue
        cached_signature, cached_focus_hint, cached_limit = key
        if cached_signature != index_signature or cached_focus_hint != focus_hint:
            continue
        if int(cached_limit) < requested_limit:
            continue
        if best_limit is None or int(cached_limit) < best_limit:
            best_key = key
            best_limit = int(cached_limit)
    if best_key is None:
        return None
    return cache[best_key]


def _trim_semantic_architecture(result: dict[str, Any], max_per_role: int) -> dict[str, Any]:
    trimmed = copy.deepcopy(result)
    architecture_layers = trimmed.get("architecture_layers", {})
    if isinstance(architecture_layers, dict):
        for role, entries in architecture_layers.items():
            if isinstance(entries, list):
                architecture_layers[role] = entries[:max_per_role]
    return trimmed


def _trim_hidden_state_model(result: dict[str, Any], max_candidates: int) -> dict[str, Any]:
    trimmed = copy.deepcopy(result)
    candidate_state_fields = trimmed.get("candidate_state_fields")
    if isinstance(candidate_state_fields, list):
        trimmed["candidate_state_fields"] = candidate_state_fields[:max_candidates]
    compatibility_views = trimmed.get("compatibility_views")
    if isinstance(compatibility_views, dict):
        compatibility_fields = compatibility_views.get("candidate_state_fields")
        if isinstance(compatibility_fields, list):
            compatibility_views["candidate_state_fields"] = compatibility_fields[:max_candidates]

    kept_field_refs = {
        normalize_field_source(
            item.get("class", ""),
            item.get("field", ""),
            item.get("type", ""),
        )
        for item in trimmed.get("candidate_state_fields", [])
        if isinstance(item, dict)
    }

    kept_field_keys = {
        (str(item.get("class", "")), str(item.get("field", "")))
        for item in trimmed.get("candidate_state_fields", [])
        if isinstance(item, dict)
    }

    for chain_key, method_key in (("writer_chains", "writer"), ("reader_chains", "reader")):
        chain_items = trimmed.get(chain_key)
        if isinstance(chain_items, list):
            trimmed[chain_key] = [
                item for item in chain_items
                if (str(item.get("class", "")), str(item.get("field", ""))) in kept_field_keys and item.get(method_key)
            ][:40]

    nodes = trimmed.get("nodes")
    edges = trimmed.get("edges")
    evidence = trimmed.get("evidence")
    inferences = trimmed.get("inferences")
    if isinstance(nodes, list) and isinstance(edges, list) and isinstance(evidence, list) and isinstance(inferences, list):
        field_node_ids = {
            str(node.get("id", ""))
            for node in nodes
            if isinstance(node, dict) and node.get("kind") == "field" and str(node.get("source_ref", "")) in kept_field_refs
        }
        kept_node_ids = set(field_node_ids)
        kept_edge_ids: set[str] = set()

        changed = True
        while changed:
            changed = False
            for edge in edges:
                if not isinstance(edge, dict):
                    continue
                edge_id = str(edge.get("id", ""))
                source = str(edge.get("source", ""))
                target = str(edge.get("target", ""))
                if not edge_id or not source or not target:
                    continue
                if source in kept_node_ids or target in kept_node_ids:
                    if edge_id not in kept_edge_ids:
                        kept_edge_ids.add(edge_id)
                        changed = True
                    if source not in kept_node_ids:
                        kept_node_ids.add(source)
                        changed = True
                    if target not in kept_node_ids:
                        kept_node_ids.add(target)
                        changed = True

        trimmed["nodes"] = [
            node for node in nodes
            if isinstance(node, dict) and str(node.get("id", "")) in kept_node_ids
        ]
        trimmed["edges"] = [
            edge for edge in edges
            if isinstance(edge, dict) and str(edge.get("id", "")) in kept_edge_ids
        ]

        kept_evidence_ids: set[str] = set()
        for record in trimmed["nodes"] + trimmed["edges"]:
            if not isinstance(record, dict):
                continue
            kept_evidence_ids.update(str(item) for item in record.get("evidence_refs", []) if item)

        trimmed["inferences"] = [
            inference for inference in inferences
            if isinstance(inference, dict) and any(
                str(ref) in kept_node_ids or str(ref) in kept_edge_ids
                for ref in inference.get("output_refs", [])
            )
        ]
        for inference in trimmed["inferences"]:
            kept_evidence_ids.update(str(item) for item in inference.get("evidence_refs", []) if item)

        trimmed["evidence"] = [
            item for item in evidence
            if isinstance(item, dict) and str(item.get("id", "")) in kept_evidence_ids
        ]

        cycle_summary = trimmed.get("cycle_summary")
        if isinstance(cycle_summary, dict):
            components = cycle_summary.get("components")
            if isinstance(components, list):
                cycle_summary["components"] = [
                    component for component in components
                    if isinstance(component, dict) and any(
                        str(node_id) in kept_node_ids for node_id in component.get("node_ids", [])
                    )
                ]
                cycle_summary["cycle_count"] = len(cycle_summary["components"])
    return trimmed


def compact_hidden_state_model_for_transport(result: dict[str, Any], max_candidates: int) -> dict[str, Any]:
    return _trim_hidden_state_model(result, max_candidates)


def _supports_progress_callback(func: Any) -> bool:
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError):
        return True
    parameters = signature.parameters.values()
    return "progress_callback" in signature.parameters or any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in parameters)


def _invoke_with_optional_progress_callback(func: Any, *args: Any, progress_callback=None, **kwargs: Any) -> Any:
    if progress_callback is None or not _supports_progress_callback(func):
        return func(*args, **kwargs)
    return func(*args, progress_callback=progress_callback, **kwargs)


def _hidden_state_schema_matches(result: Any) -> bool:
    if not isinstance(result, dict):
        return True
    version = str(result.get("semantic_schema_version", "") or "")
    return not version or version == SEMANTIC_SCHEMA_VERSION


def _trim_guard_surface_profile(result: dict[str, Any], max_clusters: int) -> dict[str, Any]:
    trimmed = copy.deepcopy(result)
    guard_clusters = trimmed.get("guard_clusters")
    if isinstance(guard_clusters, list):
        trimmed["guard_clusters"] = guard_clusters[:max_clusters]
    return trimmed


def get_cached_semantic_architecture(index, *, focus_hint: str = "", max_per_role: int = 12, progress_callback=None) -> dict[str, Any]:
    if index is None:
        return {"success": False, "error": "SmaliIndex is required"}

    index_signature = _index_signature(index)
    normalized_focus_hint = str(focus_hint or "")
    key = (index_signature, normalized_focus_hint, int(max_per_role))
    cache = _slot_cache("semantic_architecture_cache")
    if key in cache:
        if progress_callback is not None:
            architecture_layers = cache[key].get("architecture_layers", {}) if isinstance(cache[key], dict) else {}
            ranked_role_hits = sum(len(items) for items in architecture_layers.values() if isinstance(items, list))
            progress_callback(100, f"Using cached semantic architecture: {ranked_role_hits} ranked role hits")
        return cache[key]

    cached_result = _best_cached_result(cache, index_signature, normalized_focus_hint, int(max_per_role))
    if cached_result is not None:
        cache[key] = _trim_semantic_architecture(cached_result, int(max_per_role))
        if progress_callback is not None:
            architecture_layers = cache[key].get("architecture_layers", {}) if isinstance(cache[key], dict) else {}
            ranked_role_hits = sum(len(items) for items in architecture_layers.values() if isinstance(items, list))
            progress_callback(100, f"Using cached semantic architecture: {ranked_role_hits} ranked role hits")
        return cache[key]

    from apk_agent.tools.semantic_architecture import map_semantic_architecture

    cache[key] = _invoke_with_optional_progress_callback(
        map_semantic_architecture,
        index,
        focus_hint=normalized_focus_hint,
        max_per_role=max_per_role,
        progress_callback=progress_callback,
    )
    return cache[key]


def get_cached_hidden_state_model(index, *, focus_hint: str = "", max_candidates: int = 30, progress_callback=None) -> dict[str, Any]:
    if index is None:
        return {"success": False, "error": "SmaliIndex is required"}

    index_signature = _index_signature(index)
    normalized_focus_hint = str(focus_hint or "")
    key = (index_signature, normalized_focus_hint, int(max_candidates))
    cache = _slot_cache("hidden_state_model_cache")
    if key not in cache:
        cached_result = _best_cached_result(cache, index_signature, normalized_focus_hint, int(max_candidates))
        if cached_result is not None and _hidden_state_schema_matches(cached_result):
            cache[key] = _trim_hidden_state_model(cached_result, int(max_candidates))
    if key in cache and not _hidden_state_schema_matches(cache[key]):
        cache.pop(key, None)
    if key in cache:
        if progress_callback is not None:
            summary = cache[key].get("summary", {}) if isinstance(cache[key], dict) else {}
            progress_callback(
                100,
                f"Using cached hidden-state model: {summary.get('model_count', 0)} models, {summary.get('field_candidates', 0)} field candidates",
            )
        return cache[key]
    if key not in cache:
        from apk_agent.tools.state_model_recovery import recover_hidden_state_model

        cache[key] = _invoke_with_optional_progress_callback(
            recover_hidden_state_model,
            index,
            focus_hint=normalized_focus_hint,
            max_candidates=max_candidates,
            progress_callback=progress_callback,
        )
    return cache[key]


def get_cached_guard_surface_profile(index, *, focus_hint: str = "", max_clusters: int = 30) -> dict[str, Any]:
    if index is None:
        return {"success": False, "error": "SmaliIndex is required"}

    index_signature = _index_signature(index)
    normalized_focus_hint = str(focus_hint or "")
    key = (index_signature, normalized_focus_hint, int(max_clusters))
    cache = _slot_cache("guard_surface_profile_cache")
    if key not in cache:
        cached_result = _best_cached_result(cache, index_signature, normalized_focus_hint, int(max_clusters))
        if cached_result is not None:
            cache[key] = _trim_guard_surface_profile(cached_result, int(max_clusters))
    if key not in cache:
        from apk_agent.tools.guard_surface_profiler import profile_guard_and_revalidation_surface

        cache[key] = profile_guard_and_revalidation_surface(index, focus_hint=normalized_focus_hint, max_clusters=max_clusters)
    return cache[key]


def get_cached_architecture_context(index, *, focus_terms: set[str] | None = None, progress_callback=None) -> dict[str, Any]:
    if index is None:
        return {
            "role_classes": {role: set() for role in _ARCHITECTURE_ROLES},
            "role_scores": {},
            "state_fields": set(),
            "state_field_semantics": {},
            "state_field_scores": {},
            "writer_methods": set(),
            "reader_methods": set(),
            "guard_methods": set(),
            "guard_method_scores": {},
            "overwrite_methods": set(),
            "dynamic_boundary_methods": set(),
            "revalidation_classes": set(),
            "summary": {},
        }

    def _emit_progress(pct: float, detail: str) -> None:
        if progress_callback is not None:
            progress_callback(pct, detail)

    normalized_focus_terms = tuple(sorted(term for term in (focus_terms or set()) if term))
    key = (_index_signature(index), normalized_focus_terms)
    cache = _slot_cache("architecture_context_cache")
    if key in cache:
        summary = cache[key].get("summary", {}) if isinstance(cache[key], dict) else {}
        _emit_progress(100, f"Using cached architecture context: {summary.get('recovered_state_fields', 0)} state fields, {summary.get('guard_methods', 0)} guard methods")
        return cache[key]

    focus_hint = ",".join(normalized_focus_terms)
    if normalized_focus_terms:
        _emit_progress(4, f"Recovering semantic architecture layers for {len(normalized_focus_terms)} focus terms")
    else:
        _emit_progress(4, "Recovering semantic architecture layers")
    architecture = get_cached_semantic_architecture(index, focus_hint=focus_hint, max_per_role=20)
    architecture_layers = architecture.get("architecture_layers", {}) if isinstance(architecture, dict) else {}
    ranked_role_hits = sum(len(items) for items in architecture_layers.values() if isinstance(items, list))
    _emit_progress(28, f"Semantic architecture ready: {ranked_role_hits} ranked role hits")

    _emit_progress(30, "Recovering hidden-state model")
    if progress_callback is not None:
        hidden_state = get_cached_hidden_state_model(
            index,
            focus_hint=focus_hint,
            max_candidates=50,
            progress_callback=lambda pct, detail: _emit_progress(30 + (pct * 0.42), detail),
        )
    else:
        hidden_state = get_cached_hidden_state_model(index, focus_hint=focus_hint, max_candidates=50)
    hidden_summary = hidden_state.get("summary", {}) if isinstance(hidden_state, dict) else {}
    _emit_progress(74, f"Hidden-state recovery ready: {hidden_summary.get('field_candidates', 0)} field candidates")

    _emit_progress(76, "Profiling guard and revalidation surfaces")
    guard_surface = get_cached_guard_surface_profile(index, focus_hint=focus_hint, max_clusters=50)
    guard_summary = guard_surface.get("summary", {}) if isinstance(guard_surface, dict) else {}
    _emit_progress(92, f"Merging architecture context: {guard_summary.get('guard_clusters', 0)} guard clusters, {guard_summary.get('revalidation_loops', 0)} revalidation loops")

    role_classes: dict[str, set[str]] = {role: set() for role in _ARCHITECTURE_ROLES}
    role_scores: dict[str, dict[str, float]] = {}
    for role in _ARCHITECTURE_ROLES:
        for item in architecture.get("architecture_layers", {}).get(role, []):
            class_name = item.get("class", "")
            if not class_name:
                continue
            role_classes[role].add(class_name)
            role_scores.setdefault(class_name, {})[role] = float(item.get("score", 0))

    state_fields: set[str] = set()
    state_field_semantics: dict[str, str] = {}
    state_field_scores: dict[str, float] = {}
    for item in hidden_state.get("candidate_state_fields", []):
        field_ref = f"{item.get('class', '')}->{item.get('field', '')}"
        if not field_ref.endswith("->"):
            state_fields.add(field_ref)
            state_field_semantics[field_ref] = str(item.get("semantic_guess", "state_value"))
            state_field_scores[field_ref] = float(item.get("score", 0))

    writer_methods = {item.get("writer", "") for item in hidden_state.get("writer_chains", []) if item.get("writer")}
    reader_methods = {item.get("reader", "") for item in hidden_state.get("reader_chains", []) if item.get("reader")}

    guard_methods: set[str] = set()
    guard_method_scores: dict[str, int] = {}
    for item in guard_surface.get("guard_clusters", []):
        method_sig = item.get("method", "")
        if method_sig:
            guard_methods.add(method_sig)
            guard_method_scores[method_sig] = int(item.get("severity_score", 0))

    overwrite_methods = {item.get("method", "") for item in guard_surface.get("overwrite_points", []) if item.get("method")}
    dynamic_boundary_methods = {item.get("method", "") for item in guard_surface.get("native_or_dynamic_boundaries", []) if item.get("method")}
    revalidation_classes = {item.get("class", "") for item in guard_surface.get("revalidation_loops", []) if item.get("class")}

    context = {
        "role_classes": role_classes,
        "role_scores": role_scores,
        "state_fields": state_fields,
        "state_field_semantics": state_field_semantics,
        "state_field_scores": state_field_scores,
        "writer_methods": writer_methods,
        "reader_methods": reader_methods,
        "guard_methods": guard_methods,
        "guard_method_scores": guard_method_scores,
        "overwrite_methods": overwrite_methods,
        "dynamic_boundary_methods": dynamic_boundary_methods,
        "revalidation_classes": revalidation_classes,
        "summary": {
            "focus_terms": list(normalized_focus_terms),
            "state_models": len(role_classes["state_models"]),
            "network_layer": len(role_classes["network_layer"]),
            "serialization_layer": len(role_classes["serialization_layer"]),
            "ui_gate_controllers": len(role_classes["ui_gate_controllers"]),
            "guard_methods": len(guard_methods),
            "recovered_state_fields": len(state_fields),
            "revalidation_classes": len(revalidation_classes),
        },
    }
    cache[key] = context
    _emit_progress(100, f"Architecture context ready: {len(state_fields)} state fields, {len(guard_methods)} guard methods, {len(revalidation_classes)} revalidation classes")
    return context
