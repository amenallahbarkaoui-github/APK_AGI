"""Runtime-scoped memoization for expensive semantic analyses.

This keeps heavyweight semantic passes reusable across additive tools that all
operate on the same SmaliIndex during one session.
"""

from __future__ import annotations

import copy
from typing import Any

from apk_agent.agent.execution_context import get_runtime_slot, set_runtime_slot


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
    return trimmed


def _trim_guard_surface_profile(result: dict[str, Any], max_clusters: int) -> dict[str, Any]:
    trimmed = copy.deepcopy(result)
    guard_clusters = trimmed.get("guard_clusters")
    if isinstance(guard_clusters, list):
        trimmed["guard_clusters"] = guard_clusters[:max_clusters]
    return trimmed


def get_cached_semantic_architecture(index, *, focus_hint: str = "", max_per_role: int = 12) -> dict[str, Any]:
    if index is None:
        return {"success": False, "error": "SmaliIndex is required"}

    index_signature = _index_signature(index)
    normalized_focus_hint = str(focus_hint or "")
    key = (index_signature, normalized_focus_hint, int(max_per_role))
    cache = _slot_cache("semantic_architecture_cache")
    if key not in cache:
        cached_result = _best_cached_result(cache, index_signature, normalized_focus_hint, int(max_per_role))
        if cached_result is not None:
            cache[key] = _trim_semantic_architecture(cached_result, int(max_per_role))
    if key not in cache:
        from apk_agent.tools.semantic_architecture import map_semantic_architecture

        cache[key] = map_semantic_architecture(index, focus_hint=normalized_focus_hint, max_per_role=max_per_role)
    return cache[key]


def get_cached_hidden_state_model(index, *, focus_hint: str = "", max_candidates: int = 30) -> dict[str, Any]:
    if index is None:
        return {"success": False, "error": "SmaliIndex is required"}

    index_signature = _index_signature(index)
    normalized_focus_hint = str(focus_hint or "")
    key = (index_signature, normalized_focus_hint, int(max_candidates))
    cache = _slot_cache("hidden_state_model_cache")
    if key not in cache:
        cached_result = _best_cached_result(cache, index_signature, normalized_focus_hint, int(max_candidates))
        if cached_result is not None:
            cache[key] = _trim_hidden_state_model(cached_result, int(max_candidates))
    if key not in cache:
        from apk_agent.tools.state_model_recovery import recover_hidden_state_model

        cache[key] = recover_hidden_state_model(index, focus_hint=normalized_focus_hint, max_candidates=max_candidates)
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


def get_cached_architecture_context(index, *, focus_terms: set[str] | None = None) -> dict[str, Any]:
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

    normalized_focus_terms = tuple(sorted(term for term in (focus_terms or set()) if term))
    key = (_index_signature(index), normalized_focus_terms)
    cache = _slot_cache("architecture_context_cache")
    if key in cache:
        return cache[key]

    focus_hint = ",".join(normalized_focus_terms)
    architecture = get_cached_semantic_architecture(index, focus_hint=focus_hint, max_per_role=20)
    hidden_state = get_cached_hidden_state_model(index, focus_hint=focus_hint, max_candidates=50)
    guard_surface = get_cached_guard_surface_profile(index, focus_hint=focus_hint, max_clusters=50)

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
    return context