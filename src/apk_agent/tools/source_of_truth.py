"""Static-first source-of-truth inference built on top of the behavior graph.

This module is intentionally additive. It does not replace the current
behavior/evidence layers and it does not require runtime instrumentation.
Instead, it consumes the persisted behavior graph and infers likely state
surfaces into explicit categories such as remote authority, cache, persisted
mirror, UI projection, derived consumer, and transient memory.

The outputs are advisory rather than absolute. Every classification is meant to
stay contestable and overridable by later evidence, manual reasoning, or
task-specific goals such as exploratory patches or tactical UI-only changes.
"""

from __future__ import annotations

import json
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any


PACK_VERSION = 2
STATE_SURFACE_TYPES = (
    "LOCAL_CACHE",
    "REMOTE_AUTHORITY",
    "DERIVED_STATE",
    "UI_STATE",
    "PERSISTED_STATE",
    "TRANSIENT_MEMORY",
)

_NETWORK_HINTS = {"network", "serialization", "billing"}
_PERSISTENCE_HINTS = {
    "sharedpreferences",
    "datastore",
    "sqlite",
    "storage",
    "room",
    "realm",
    "persisted",
    "persistence",
}
_UI_HINTS = {
    "activity",
    "fragment",
    "dialog",
    "view",
    "compose",
    "adapter",
    "render",
    "display",
    "ui",
    "screen",
}
_REMOTE_TRANSITION_TYPES = {
    "server_or_parser_write",
    "network_response_to_state",
    "billing_to_state",
}
_REFRESH_TRANSITION_TYPES = {
    "lifecycle_revalidation_cycle",
}


def build_source_of_truth_pack(
    behavior_pack: dict[str, Any],
    *,
    focus_hint: str = "",
    max_surfaces: int = 80,
    max_relationships: int = 120,
    max_claims: int = 30,
) -> dict[str, Any]:
    """Build a source-of-truth inference pack from the behavior graph."""
    if not behavior_pack:
        return {"success": False, "error": "Behavior graph pack is required"}

    surfaces: dict[str, dict[str, Any]] = {}
    relationships: dict[tuple[str, str, str], dict[str, Any]] = {}

    behavior = behavior_pack.get("behavior", {})
    records = list(behavior_pack.get("records", []))
    feature_controls = list(behavior.get("feature_controls", []))
    state_transitions = list(behavior.get("state_transitions", []))
    enforcement_surfaces = list(behavior.get("enforcement_surfaces", []))
    security_surfaces = list(behavior.get("security_surfaces", []))
    network_behavior = dict(behavior.get("network_behavior", {}))

    _ingest_records(records, surfaces)
    _ingest_network_behavior(network_behavior, surfaces)
    _ingest_feature_controls(feature_controls, surfaces)
    _ingest_enforcement_surfaces(enforcement_surfaces, surfaces)
    _ingest_security_surfaces(security_surfaces, surfaces)
    _ingest_state_transitions(state_transitions, surfaces, relationships)
    _ingest_overwrite_controls(feature_controls, surfaces, relationships)

    _attach_relationships(surfaces, relationships)
    _finalize_surfaces(surfaces)

    surface_items = sorted(
        (_public_surface(surface) for surface in surfaces.values()),
        key=lambda item: (-float(item.get("importance_score", 0)), item.get("surface_ref", "")),
    )[:max_surfaces]
    relationship_items = sorted(
        (dict(rel) for rel in relationships.values()),
        key=lambda item: (-float(item.get("confidence", 0)), item.get("relationship_type", ""), item.get("source_surface_id", ""), item.get("target_surface_id", "")),
    )[:max_relationships]
    lifecycle_model = _build_state_lifecycle_model(surface_items)
    authority_claims = _build_authority_claims(surface_items, relationships)[:max_claims]
    patch_target_advisories = _build_patch_target_advisories(surface_items)[:max_claims]
    blocked_patch_targets = [dict(item) for item in patch_target_advisories]
    authority_propagation_graph = _build_authority_propagation_graph(
        surface_items,
        relationship_items,
        max_routes=max_claims,
    )
    records_out = _build_records(
        surface_items,
        relationship_items,
        authority_claims,
        patch_target_advisories,
        authority_propagation_graph,
        lifecycle_model,
    )

    built_at = time.time()
    return {
        "success": True,
        "pack_version": PACK_VERSION,
        "built_at": built_at,
        "focus_hint": focus_hint,
        "identity": dict(behavior_pack.get("identity", {})),
        "upstream": {
            "behavior_built_at": behavior_pack.get("built_at", 0.0),
            "behavior_summary": dict(behavior_pack.get("summary", {})),
        },
        "source_of_truth": {
            "surfaces": surface_items,
            "relationships": relationship_items,
            "authority_claims": authority_claims,
            "patch_target_advisories": patch_target_advisories,
            "blocked_patch_targets": blocked_patch_targets,
            "authority_propagation_graph": authority_propagation_graph,
            "state_lifecycle_model": lifecycle_model,
        },
        "records": records_out,
        "summary": _build_summary(
            surface_items,
            relationship_items,
            authority_claims,
            patch_target_advisories,
            authority_propagation_graph,
            lifecycle_model,
        ),
        "warnings": list(behavior_pack.get("warnings", [])),
    }


def save_source_of_truth_pack(pack: dict[str, Any], output_path: str | Path) -> dict[str, Any]:
    """Persist a source-of-truth pack as JSON using an atomic replace."""
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


def load_source_of_truth_pack(input_path: str | Path) -> dict[str, Any] | None:
    """Load a persisted source-of-truth pack from disk."""
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


def summarize_source_of_truth_pack(pack: dict[str, Any]) -> dict[str, Any]:
    """Return a compact summary of the source-of-truth pack."""
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


def query_source_of_truth(
    pack: dict[str, Any],
    query: str,
    *,
    class_name: str = "",
    method_name: str = "",
    field_name: str = "",
    record_type: str = "",
    authority_label: str = "",
    max_results: int = 10,
) -> dict[str, Any]:
    """Run a semantic query over source-of-truth surfaces and claims."""
    if not pack:
        return {"success": False, "error": "Source-of-truth pack is required"}

    tokens = _query_tokens(query, class_name, method_name, field_name, record_type, authority_label)
    if not tokens and not class_name and not method_name and not field_name and not record_type and not authority_label:
        return {
            "success": False,
            "error": "At least one query token, class_name, method_name, field_name, record_type, or authority_label is required",
        }

    requested_record_types = _normalize_record_types(record_type)
    matches: list[dict[str, Any]] = []
    requested_authority = authority_label.strip().lower()
    for record in pack.get("records", []):
        if requested_record_types and record.get("type", "") not in requested_record_types:
            continue
        if requested_authority and str(record.get("authority_label", "")).lower() != requested_authority:
            continue
        score, reasons = _score_record(
            record,
            tokens,
            class_name=class_name,
            method_name=method_name,
            field_name=field_name,
        )
        if score <= 0 and (tokens or class_name or method_name or field_name):
            continue
        item = dict(record)
        item["match_score"] = score if score > 0 else float(record.get("score", 0)) * 0.05
        item["match_reasons"] = reasons
        matches.append(item)

    matches.sort(key=lambda item: (-item.get("match_score", 0), -float(item.get("score", 0)), item.get("title", "")))
    return {
        "success": True,
        "query": query,
        "class_name": class_name,
        "method_name": method_name,
        "field_name": field_name,
        "record_type": record_type,
        "authority_label": authority_label,
        "total_matches": len(matches),
        "matches": matches[:max_results],
        "summary": summarize_source_of_truth_pack(pack).get("summary", {}),
    }


def _ingest_records(records: list[dict[str, Any]], surfaces: dict[str, dict[str, Any]]) -> None:
    for record in records:
        record_type = str(record.get("type", ""))
        class_name = str(record.get("class", ""))
        method_name = str(record.get("method", ""))
        field_name = str(record.get("field", ""))
        file_path = str(record.get("file", ""))
        evidence = [str(item) for item in record.get("evidence", []) if str(item).strip()]
        text_blob = " ".join(evidence).lower()

        if record_type == "state_field" and class_name and field_name:
            surface = _ensure_field_surface(surfaces, _field_ref(class_name, field_name), file_path=file_path)
            _add_surface_score(surface, "TRANSIENT_MEMORY", 4.0, "state field recovered from behavior graph")
            if any(hint in text_blob for hint in _PERSISTENCE_HINTS):
                _add_surface_score(surface, "PERSISTED_STATE", 5.0, "state field evidence references persistence")
            if any(hint in text_blob for hint in _NETWORK_HINTS):
                _add_surface_score(surface, "LOCAL_CACHE", 3.0, "state field evidence references network ingress")
                surface["overwrite_risk"] += 0.2
        elif record_type == "entity" and class_name:
            surface = _ensure_class_surface(surfaces, class_name, file_path=file_path)
            _add_surface_score(surface, "TRANSIENT_MEMORY", 2.0, "entity class recovered from hidden-state analysis")
            if method_name:
                _add_surface_score(surface, "DERIVED_STATE", 1.5, "entity record includes method coupling")


def _ingest_network_behavior(network_behavior: dict[str, Any], surfaces: dict[str, dict[str, Any]]) -> None:
    for path in network_behavior.get("paths", []):
        class_name = str(path.get("class", ""))
        method_name = str(path.get("method", ""))
        file_path = str(path.get("file", ""))
        api_categories = {str(item) for item in path.get("api_categories", [])}
        if not class_name or not method_name:
            continue
        surface = _ensure_method_surface(surfaces, method_name, file_path=file_path, class_name=class_name)
        if api_categories & _NETWORK_HINTS:
            _add_surface_score(surface, "REMOTE_AUTHORITY", 8.0, "network path mutates application state")
            _set_mutation_authority(surface, "authoritative_writer", priority=5)
            surface["overwrite_risk"] += 0.15
        else:
            _add_surface_score(surface, "TRANSIENT_MEMORY", 2.0, "network-adjacent method participates in state flow")

    for field in network_behavior.get("state_ingress_fields", []):
        class_name = str(field.get("class", ""))
        field_name = str(field.get("field", ""))
        file_path = str(field.get("file", ""))
        writer_tags = {str(item) for item in field.get("writer_tags", [])}
        if not class_name or not field_name:
            continue
        surface = _ensure_field_surface(surfaces, _field_ref(class_name, field_name), file_path=file_path)
        _add_surface_score(surface, "LOCAL_CACHE", 6.0, "field is written from network/serialization boundary")
        if writer_tags & {"persistence"}:
            _add_surface_score(surface, "PERSISTED_STATE", 3.5, "network-ingress field also touches persistence")
        _set_mutation_authority(surface, "cache_writer", priority=3)
        surface["overwrite_risk"] += 0.35


def _ingest_feature_controls(feature_controls: list[dict[str, Any]], surfaces: dict[str, dict[str, Any]]) -> None:
    for control in feature_controls:
        class_name = str(control.get("class", ""))
        method_name = str(control.get("method", ""))
        field_ref = str(control.get("field", ""))
        file_path = str(control.get("file", ""))
        action = str(control.get("action", ""))
        origin = str(control.get("origin", ""))
        control_role = str(control.get("control_role", ""))
        text_blob = " ".join([class_name, method_name, field_ref, action, origin, control_role]).lower()

        if field_ref and _looks_like_field_ref(field_ref):
            field_surface = _ensure_field_surface(surfaces, field_ref, file_path=file_path)
            if control_role == "state_source_of_truth":
                _add_surface_score(field_surface, "TRANSIENT_MEMORY", 5.5, "field surfaced as a state-source candidate")
                if origin == "storage":
                    _add_surface_score(field_surface, "PERSISTED_STATE", 4.5, "control origin points at storage-backed state")
                elif origin == "server":
                    _add_surface_score(field_surface, "LOCAL_CACHE", 3.0, "state source is fed by server-side origin")

        if not method_name:
            continue

        method_surface = _ensure_method_surface(surfaces, method_name, file_path=file_path, class_name=class_name)
        if origin == "ui" or any(hint in text_blob for hint in _UI_HINTS):
            _add_surface_score(method_surface, "UI_STATE", 8.5, "control is a UI projection or display path")
            _set_mutation_authority(method_surface, "ui_projection", priority=1)
        elif control_role in {"gate_method", "gate_accessor"} or action == "check":
            _add_surface_score(method_surface, "DERIVED_STATE", 7.0, "control is a derived enforcement consumer")
            _set_mutation_authority(method_surface, "derived_reader", priority=2)
        elif control_role == "state_overwrite" or action == "deactivate":
            _add_surface_score(method_surface, "DERIVED_STATE", 3.5, "control overwrites or invalidates state")
            _set_mutation_authority(method_surface, "revalidation_writer", priority=4)
            method_surface["overwrite_risk"] += 0.35


def _ingest_enforcement_surfaces(enforcement_surfaces: list[dict[str, Any]], surfaces: dict[str, dict[str, Any]]) -> None:
    for surface_entry in enforcement_surfaces:
        class_name = str(surface_entry.get("class", ""))
        method_name = str(surface_entry.get("method", ""))
        file_path = str(surface_entry.get("file", ""))
        surface_role = str(surface_entry.get("surface_role", ""))
        api_categories = {str(item) for item in surface_entry.get("api_categories", [])}
        if not class_name or not method_name:
            continue

        surface = _ensure_method_surface(surfaces, method_name, file_path=file_path, class_name=class_name)
        if surface_role in {"gate_method", "gate_accessor"}:
            _add_surface_score(surface, "DERIVED_STATE", 6.0, "enforcement surface reads or checks derived state")
            _set_mutation_authority(surface, "derived_reader", priority=2)
        elif surface_role == "state_mutator" and api_categories & _NETWORK_HINTS:
            _add_surface_score(surface, "REMOTE_AUTHORITY", 6.5, "network-backed mutator sits close to authoritative state")
            _set_mutation_authority(surface, "authoritative_writer", priority=5)
        elif surface_role == "revalidation_boundary":
            _add_surface_score(surface, "DERIVED_STATE", 4.0, "revalidation boundary can rewrite local state")
            _set_mutation_authority(surface, "revalidation_writer", priority=4)
            surface["overwrite_risk"] += 0.25

        for field_hit in surface_entry.get("state_field_hits", [])[:3]:
            if _looks_like_field_ref(str(field_hit)):
                field_surface = _ensure_field_surface(surfaces, str(field_hit), file_path=file_path)
                _add_surface_score(field_surface, "TRANSIENT_MEMORY", 1.5, "field is attached to an enforcement surface")


def _ingest_security_surfaces(security_surfaces: list[dict[str, Any]], surfaces: dict[str, dict[str, Any]]) -> None:
    for entry in security_surfaces:
        class_name = str(entry.get("class", ""))
        method_name = str(entry.get("method", ""))
        file_path = str(entry.get("file", ""))
        surface_type = str(entry.get("surface_type", ""))
        tags = {str(item) for item in entry.get("tags", [])}
        if not class_name or not method_name:
            continue
        surface = _ensure_method_surface(surfaces, method_name, file_path=file_path, class_name=class_name)
        if surface_type == "api_boundary" and tags & _NETWORK_HINTS:
            _add_surface_score(surface, "REMOTE_AUTHORITY", 5.5, "API boundary likely feeds state truth from server data")
            _set_mutation_authority(surface, "authoritative_writer", priority=5)
        elif surface_type == "revalidation_boundary":
            _add_surface_score(surface, "DERIVED_STATE", 4.5, "revalidation boundary can invalidate local truth assumptions")
            _set_mutation_authority(surface, "revalidation_writer", priority=4)
            surface["overwrite_risk"] += 0.35


def _ingest_state_transitions(
    state_transitions: list[dict[str, Any]],
    surfaces: dict[str, dict[str, Any]],
    relationships: dict[tuple[str, str, str], dict[str, Any]],
) -> None:
    for transition in state_transitions:
        transition_type = str(transition.get("transition_type", ""))
        source_ref = str(transition.get("source", ""))
        target_ref = str(transition.get("target", ""))
        via_field = str(transition.get("via_field", ""))
        class_name = str(transition.get("class", ""))
        file_path = str(transition.get("file", ""))
        trigger_tags = {str(item) for item in transition.get("trigger_tags", [])}
        reader_tags = {str(item) for item in transition.get("reader_tags", [])}
        reasons = [str(item) for item in transition.get("reasons", []) if str(item).strip()]
        confidence = min(0.99, round(0.35 + float(transition.get("score", 0)) / 140.0, 3))

        target_surface_id = ""
        if via_field and _looks_like_field_ref(via_field):
            target_surface_id = _ensure_field_surface(surfaces, via_field, file_path=file_path)["surface_id"]
        elif _looks_like_field_ref(target_ref):
            target_surface_id = _ensure_field_surface(surfaces, target_ref, file_path=file_path)["surface_id"]
        elif _looks_like_method_ref(target_ref):
            target_surface_id = _ensure_method_surface(surfaces, target_ref, file_path=file_path, class_name=class_name)["surface_id"]
        elif class_name:
            target_surface_id = _ensure_class_surface(surfaces, class_name, file_path=file_path)["surface_id"]

        if transition_type in _REMOTE_TRANSITION_TYPES or trigger_tags & _NETWORK_HINTS:
            source_surface_id = _ensure_remote_surface(surfaces, source_ref or class_name, file_path=file_path)["surface_id"]
            if target_surface_id:
                _store_relationship(
                    relationships,
                    source_surface_id,
                    target_surface_id,
                    "syncs_to",
                    confidence,
                    reasons or ["remote/network source feeds local state"],
                )
            continue

        if transition_type in _REFRESH_TRANSITION_TYPES or "revalidation_loop" in trigger_tags:
            source_surface_id = _ensure_method_surface(
                surfaces,
                source_ref if _looks_like_method_ref(source_ref) else _class_method_ref(class_name, "<revalidation>"),
                file_path=file_path,
                class_name=class_name,
            )["surface_id"]
            if target_surface_id:
                _store_relationship(
                    relationships,
                    source_surface_id,
                    target_surface_id,
                    "refreshes",
                    confidence,
                    reasons or ["lifecycle or revalidation flow refreshes state"],
                )
            continue

        if "ui" in reader_tags:
            source_surface_id = ""
            ui_target_surface_id = target_surface_id
            if _looks_like_method_ref(target_ref):
                ui_target_surface_id = _ensure_method_surface(surfaces, target_ref, file_path=file_path, class_name=class_name)["surface_id"]
            if via_field and _looks_like_field_ref(via_field):
                source_surface_id = _ensure_field_surface(surfaces, via_field, file_path=file_path)["surface_id"]
            elif _looks_like_field_ref(source_ref):
                source_surface_id = _ensure_field_surface(surfaces, source_ref, file_path=file_path)["surface_id"]
            elif _looks_like_method_ref(source_ref):
                source_surface_id = _ensure_method_surface(surfaces, source_ref, file_path=file_path, class_name=class_name)["surface_id"]
            if source_surface_id and ui_target_surface_id:
                _store_relationship(
                    relationships,
                    source_surface_id,
                    ui_target_surface_id,
                    "projects_to_ui",
                    confidence,
                    reasons or ["state is projected into UI"],
                )
            continue

        source_surface_id = ""
        if _looks_like_field_ref(source_ref):
            source_surface_id = _ensure_field_surface(surfaces, source_ref, file_path=file_path)["surface_id"]
        elif _looks_like_method_ref(source_ref):
            source_surface_id = _ensure_method_surface(surfaces, source_ref, file_path=file_path, class_name=class_name)["surface_id"]
        elif class_name:
            source_surface_id = _ensure_class_surface(surfaces, class_name, file_path=file_path)["surface_id"]
        if source_surface_id and target_surface_id:
            _store_relationship(
                relationships,
                source_surface_id,
                target_surface_id,
                "derives_to",
                confidence,
                reasons or ["state transition derives downstream behavior"],
            )


def _ingest_overwrite_controls(
    feature_controls: list[dict[str, Any]],
    surfaces: dict[str, dict[str, Any]],
    relationships: dict[tuple[str, str, str], dict[str, Any]],
) -> None:
    for control in feature_controls:
        control_role = str(control.get("control_role", ""))
        action = str(control.get("action", ""))
        if control_role != "state_overwrite" and action != "deactivate":
            continue

        class_name = str(control.get("class", ""))
        method_name = str(control.get("method", ""))
        file_path = str(control.get("file", ""))
        field_targets = [item.strip() for item in str(control.get("field", "")).split(",") if item.strip()]
        reasons = [str(item) for item in control.get("reasons", []) if str(item).strip()]
        if not method_name:
            continue

        source_surface = _ensure_method_surface(surfaces, method_name, file_path=file_path, class_name=class_name)
        _add_surface_score(source_surface, "DERIVED_STATE", 3.0, "overwrite control can invalidate downstream state")
        _set_mutation_authority(source_surface, "revalidation_writer", priority=4)
        source_surface["overwrite_risk"] += 0.25

        for field_target in field_targets[:4]:
            if not _looks_like_field_ref(field_target):
                continue
            target_surface = _ensure_field_surface(surfaces, field_target, file_path=file_path)
            _store_relationship(
                relationships,
                source_surface["surface_id"],
                target_surface["surface_id"],
                "overwrites",
                0.82,
                reasons or ["state overwrite control rewrites this field"],
            )


def _attach_relationships(
    surfaces: dict[str, dict[str, Any]],
    relationships: dict[tuple[str, str, str], dict[str, Any]],
) -> None:
    for relationship in relationships.values():
        source = surfaces.get(str(relationship.get("source_surface_id", "")))
        target = surfaces.get(str(relationship.get("target_surface_id", "")))
        if source is None or target is None:
            continue

        _append_unique(source["downstream_surface_ids"], target["surface_id"])
        _append_unique(target["upstream_surface_ids"], source["surface_id"])
        _append_unique(
            source["sync_relationships"],
            {
                "direction": "outgoing",
                "relationship_type": relationship["relationship_type"],
                "surface_id": target["surface_id"],
                "confidence": relationship["confidence"],
            },
        )
        _append_unique(
            target["sync_relationships"],
            {
                "direction": "incoming",
                "relationship_type": relationship["relationship_type"],
                "surface_id": source["surface_id"],
                "confidence": relationship["confidence"],
            },
        )

        relation_type = relationship["relationship_type"]
        reason_summary = relationship.get("summary", relation_type)
        if relation_type == "syncs_to":
            target["overwrite_risk"] += 0.22
            _append_unique(target["counter_evidence"], f"upstream sync exists: {reason_summary}")
        elif relation_type == "refreshes":
            target["overwrite_risk"] += 0.28
            _append_unique(target["lifecycle_refresh_triggers"], reason_summary)
            _append_unique(target["counter_evidence"], f"lifecycle refresh exists: {reason_summary}")
        elif relation_type == "overwrites":
            target["overwrite_risk"] += 0.32
            _append_unique(target["counter_evidence"], f"overwrite surface exists: {reason_summary}")


def _finalize_surfaces(surfaces: dict[str, dict[str, Any]]) -> None:
    for surface in surfaces.values():
        scores = {name: float(surface["state_surface_scores"].get(name, 0.0)) for name in STATE_SURFACE_TYPES}
        ordered = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
        best_surface, best_score = ordered[0]
        second_score = ordered[1][1] if len(ordered) > 1 else 0.0
        surface["state_surface"] = best_surface

        incoming_relationships = [
            rel
            for rel in surface["sync_relationships"]
            if rel.get("direction") == "incoming"
        ]
        incoming_remote = any(
            rel.get("relationship_type") in {"syncs_to", "refreshes", "overwrites"}
            for rel in incoming_relationships
        )
        uiish = best_surface == "UI_STATE" or any(hint in surface["surface_ref"].lower() for hint in _UI_HINTS)
        overwrite_risk = min(0.99, round(float(surface.get("overwrite_risk", 0.0)), 3))
        surface["overwrite_risk"] = overwrite_risk

        if best_surface == "REMOTE_AUTHORITY":
            surface["authority_label"] = "authoritative"
            surface["patchability_class"] = "patch_boundary_or_mapper"
            _set_mutation_authority(surface, "authoritative_writer", priority=5)
        elif uiish:
            surface["state_surface"] = "UI_STATE"
            surface["authority_label"] = "display_only"
            surface["patchability_class"] = "cosmetic_only"
            _set_mutation_authority(surface, "ui_projection", priority=1)
        elif best_surface == "DERIVED_STATE":
            surface["authority_label"] = "mirror"
            surface["patchability_class"] = "consumer_only"
            _set_mutation_authority(surface, "derived_reader", priority=2)
        elif best_surface == "LOCAL_CACHE" or (best_surface == "TRANSIENT_MEMORY" and incoming_remote):
            if best_surface == "TRANSIENT_MEMORY" and incoming_remote:
                surface["state_surface"] = "LOCAL_CACHE"
            if incoming_remote:
                surface["authority_label"] = "cache"
                surface["patchability_class"] = "likely_temporary_patch"
            elif overwrite_risk >= 0.45:
                surface["authority_label"] = "uncertain"
                surface["patchability_class"] = "volatile_cache"
            else:
                surface["authority_label"] = "likely_authoritative"
                surface["patchability_class"] = "candidate_root_cause"
            _set_mutation_authority(surface, "cache_writer", priority=3)
        elif best_surface == "PERSISTED_STATE":
            if incoming_remote:
                surface["authority_label"] = "mirror"
                surface["patchability_class"] = "storage_mirror"
            else:
                surface["authority_label"] = "likely_authoritative"
                surface["patchability_class"] = "candidate_root_cause"
            _set_mutation_authority(surface, "persistent_writer", priority=4)
        else:
            if incoming_remote or overwrite_risk >= 0.45:
                surface["authority_label"] = "uncertain"
                surface["patchability_class"] = "volatile_state"
            else:
                surface["authority_label"] = "likely_authoritative" if best_score >= 4.5 else "uncertain"
                surface["patchability_class"] = "candidate_root_cause" if best_score >= 4.5 else "uncertain"
            _set_mutation_authority(surface, "transient_writer", priority=3)

        classification_reasons = [
            f"score:{name.lower()}={round(value, 3)}"
            for name, value in ordered
            if value > 0
        ][:3]
        for signal in surface.get("supporting_signals", []):
            if len(classification_reasons) >= 6:
                break
            _append_unique(classification_reasons, signal)

        counter_signals: list[str] = []
        if incoming_remote:
            _append_unique(counter_signals, "incoming upstream state flow can override local mutations")
        if overwrite_risk >= 0.45:
            _append_unique(counter_signals, "revalidation or overwrite pressure reduces local durability")
        for item in surface.get("counter_evidence", []):
            _append_unique(counter_signals, str(item))

        classification_confidence = 0.24 + (best_score / 20.0) + max(0.0, best_score - second_score) / 36.0
        if incoming_remote:
            classification_confidence += 0.05
        if uiish:
            classification_confidence += 0.04
        if overwrite_risk >= 0.75:
            classification_confidence -= 0.03
        classification_confidence = round(min(0.96, max(0.22, classification_confidence)), 3)

        surface["classification_confidence"] = classification_confidence
        surface["classification_reasons"] = classification_reasons[:6]
        surface["counter_signals"] = counter_signals[:6]
        surface["classification_status"] = (
            "leading_hypothesis"
            if classification_confidence >= 0.74
            else "contestable_hypothesis"
        )
        surface["classification_contestable"] = True
        surface["classification_overridable"] = True
        surface["ownership_confidence"] = classification_confidence
        surface["importance_score"] = round(
            (best_score * 4.0)
            + (classification_confidence * 25.0)
            + (len(surface["upstream_surface_ids"]) * 3.0)
            + (len(surface["downstream_surface_ids"]) * 2.0),
            3,
        )
        surface["counter_evidence"] = counter_signals[:6]
        surface["lifecycle_refresh_triggers"] = surface["lifecycle_refresh_triggers"][:6]
        surface["supporting_signals"] = surface["supporting_signals"][:8]
        surface["sync_relationships"] = surface["sync_relationships"][:8]
        surface["state_surface_scores"] = {
            name: round(value, 3)
            for name, value in scores.items()
            if value > 0
        }
        surface.pop("_mutation_priority", None)


def _build_authority_claims(
    surfaces: list[dict[str, Any]],
    relationships: dict[tuple[str, str, str], dict[str, Any]],
) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    relationships_by_target: dict[str, list[dict[str, Any]]] = {}
    for relationship in relationships.values():
        relationships_by_target.setdefault(str(relationship.get("target_surface_id", "")), []).append(relationship)

    for surface in surfaces:
        label = str(surface.get("authority_label", ""))
        if label in {"authoritative", "likely_authoritative"}:
            support = [rel.get("summary", rel.get("relationship_type", "")) for rel in relationships_by_target.get(surface["surface_id"], [])[:4]]
            claims.append({
                "claim_id": f"authority:{surface['surface_id']}",
                "claim_type": "authority_claim",
                "surface_id": surface["surface_id"],
                "surface_ref": surface["surface_ref"],
                "state_surface": surface["state_surface"],
                "authority_label": label,
                "classification_status": surface.get("classification_status", "contestable_hypothesis"),
                "classification_confidence": surface.get("classification_confidence", surface.get("ownership_confidence", 0.0)),
                "classification_reasons": list(surface.get("classification_reasons", []))[:5],
                "counter_signals": list(surface.get("counter_signals", []))[:4],
                "contestable": True,
                "overridable": True,
                "ownership_confidence": surface["ownership_confidence"],
                "mutation_authority": surface["mutation_authority"],
                "status": "leading_hypothesis" if surface["ownership_confidence"] >= 0.75 else "plausible_hypothesis",
                "supporting_signals": surface.get("supporting_signals", [])[:5],
                "counter_evidence": surface.get("counter_signals", [])[:4],
                "relationship_support": support,
                "score": round(surface["importance_score"] + (surface["ownership_confidence"] * 15.0), 3),
            })

        if label in {"cache", "mirror"} and surface.get("upstream_surface_ids"):
            claims.append({
                "claim_id": f"sync:{surface['surface_id']}",
                "claim_type": "sync_claim",
                "surface_id": surface["surface_id"],
                "surface_ref": surface["surface_ref"],
                "state_surface": surface["state_surface"],
                "authority_label": label,
                "classification_status": surface.get("classification_status", "contestable_hypothesis"),
                "classification_confidence": surface.get("classification_confidence", surface.get("ownership_confidence", 0.0)),
                "classification_reasons": list(surface.get("classification_reasons", []))[:5],
                "counter_signals": list(surface.get("counter_signals", []))[:4],
                "contestable": True,
                "overridable": True,
                "ownership_confidence": surface["ownership_confidence"],
                "mutation_authority": surface["mutation_authority"],
                "status": "leading_hypothesis",
                "supporting_signals": surface.get("supporting_signals", [])[:4],
                "counter_evidence": surface.get("counter_signals", [])[:4],
                "relationship_support": [
                    rel.get("surface_id", "")
                    for rel in surface.get("sync_relationships", [])
                    if rel.get("direction") == "incoming"
                ][:4],
                "score": round(surface["importance_score"] + 8.0, 3),
            })

    claims.sort(key=lambda item: (-float(item.get("score", 0)), item.get("surface_ref", "")))
    return claims


def _build_patch_target_advisories(surfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    advisories: list[dict[str, Any]] = []
    for surface in surfaces:
        patchability = str(surface.get("patchability_class", ""))
        if patchability not in {
            "cosmetic_only",
            "consumer_only",
            "likely_temporary_patch",
            "storage_mirror",
            "volatile_cache",
            "volatile_state",
        }:
            continue

        advisories.append({
            "advisory_id": f"advisory:{surface['surface_id']}",
            "advisory_type": "patch_target_advisory",
            "surface_id": surface["surface_id"],
            "surface_ref": surface["surface_ref"],
            "class": surface.get("class", ""),
            "method": surface.get("method", ""),
            "field": surface.get("field", ""),
            "state_surface": surface.get("state_surface", ""),
            "authority_label": surface.get("authority_label", ""),
            "patchability_class": patchability,
            "classification_status": surface.get("classification_status", "contestable_hypothesis"),
            "classification_confidence": surface.get("classification_confidence", surface.get("ownership_confidence", 0.0)),
            "classification_reasons": list(surface.get("classification_reasons", []))[:5],
            "counter_signals": list(surface.get("counter_signals", []))[:4],
            "advisory_mode": "non_blocking",
            "planner_effect": "advisory_only",
            "exploratory_patch_allowed": True,
            "instrumentation_patch_allowed": True,
            "partial_bypass_patch_allowed": True,
            "contestable": True,
            "overridable": True,
            "preferred_upstream_surface_ids": list(surface.get("upstream_surface_ids", []))[:4],
            "reason": _patch_advisory_reason(surface),
            "score": round(surface.get("importance_score", 0.0) + (surface.get("overwrite_risk", 0.0) * 10.0), 3),
        })

    advisories.sort(key=lambda item: (-float(item.get("score", 0)), item.get("surface_ref", "")))
    return advisories


def _build_records(
    surfaces: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
    authority_claims: list[dict[str, Any]],
    patch_target_advisories: list[dict[str, Any]],
    authority_propagation_graph: dict[str, Any],
    lifecycle_model: dict[str, Any],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    for surface in surfaces[:120]:
        records.append(_record(
            record_type="state_surface",
            title=f"{surface.get('authority_label', 'uncertain')}: {surface.get('surface_ref', '')}",
            score=float(surface.get("importance_score", 0)),
            class_name=surface.get("class", ""),
            method_name=surface.get("method", ""),
            field_name=surface.get("field", ""),
            authority_label=surface.get("authority_label", ""),
            file_path=surface.get("file", ""),
            evidence=[
                surface.get("state_surface", ""),
                surface.get("mutation_authority", ""),
                surface.get("classification_status", ""),
                *surface.get("classification_reasons", []),
                surface.get("temporal_profile", ""),
                *surface.get("supporting_signals", []),
                *surface.get("counter_signals", []),
            ],
            source="source_of_truth",
        ))

    for relationship in relationships[:140]:
        records.append(_record(
            record_type="state_relationship",
            title=f"{relationship.get('relationship_type', '')}: {relationship.get('source_surface_id', '')}",
            score=float(relationship.get("confidence", 0)) * 100.0,
            authority_label="",
            evidence=[
                relationship.get("source_surface_id", ""),
                relationship.get("target_surface_id", ""),
                relationship.get("summary", ""),
                *relationship.get("reasons", []),
            ],
            source="source_of_truth",
        ))

    for claim in authority_claims[:80]:
        records.append(_record(
            record_type=claim.get("claim_type", "authority_claim"),
            title=f"{claim.get('claim_type', 'claim')}: {claim.get('surface_ref', '')}",
            score=float(claim.get("score", 0)),
            class_name=_extract_class_from_ref(claim.get("surface_ref", "")),
            authority_label=claim.get("authority_label", ""),
            evidence=[
                claim.get("state_surface", ""),
                claim.get("status", ""),
                *claim.get("classification_reasons", []),
                *claim.get("supporting_signals", []),
                *claim.get("counter_signals", []),
            ],
            source="source_of_truth",
        ))

    for advisory in patch_target_advisories[:80]:
        records.append(_record(
            record_type="patch_target_advisory",
            title=f"advisory: {advisory.get('surface_ref', '')}",
            score=float(advisory.get("score", 0)),
            class_name=advisory.get("class", ""),
            method_name=advisory.get("method", ""),
            field_name=advisory.get("field", ""),
            authority_label=advisory.get("authority_label", ""),
            evidence=[
                advisory.get("state_surface", ""),
                advisory.get("patchability_class", ""),
                advisory.get("advisory_mode", ""),
                advisory.get("reason", ""),
                *advisory.get("classification_reasons", []),
                *advisory.get("preferred_upstream_surface_ids", []),
            ],
            source="source_of_truth",
        ))

    for route in authority_propagation_graph.get("routes", [])[:60]:
        records.append(_record(
            record_type="authority_propagation_route",
            title=f"route: {route.get('source_surface_ref', '')} -> {route.get('terminal_surface_ref', '')}",
            score=float(route.get("score", 0)),
            class_name=_extract_class_from_ref(route.get("source_surface_ref", "")),
            authority_label=route.get("source_authority_label", ""),
            evidence=[
                *route.get("relationship_types", []),
                route.get("recommended_interception_ref", ""),
                route.get("recommended_interception_reason", ""),
                *route.get("path_surface_refs", [])[:4],
            ],
            source="source_of_truth",
        ))

    for profile in lifecycle_model.get("profiles", [])[:80]:
        records.append(_record(
            record_type="state_lifecycle",
            title=f"lifecycle: {profile.get('temporal_profile', '')}: {profile.get('surface_ref', '')}",
            score=float(profile.get("score", 0)),
            class_name=profile.get("class", ""),
            method_name=profile.get("method", ""),
            field_name=profile.get("field", ""),
            authority_label=profile.get("authority_label", ""),
            evidence=[
                profile.get("state_surface", ""),
                profile.get("temporal_profile", ""),
                *profile.get("temporal_reasons", []),
                *profile.get("temporal_counter_signals", []),
            ],
            source="source_of_truth",
        ))

    return records


def _build_summary(
    surfaces: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
    authority_claims: list[dict[str, Any]],
    patch_target_advisories: list[dict[str, Any]],
    authority_propagation_graph: dict[str, Any],
    lifecycle_model: dict[str, Any],
) -> dict[str, Any]:
    surface_counts = Counter(surface.get("state_surface", "UNKNOWN") for surface in surfaces)
    label_counts = Counter(surface.get("authority_label", "uncertain") for surface in surfaces)
    patchability_counts = Counter(surface.get("patchability_class", "uncertain") for surface in surfaces)
    relationship_counts = Counter(rel.get("relationship_type", "unknown") for rel in relationships)
    return {
        "surface_count": len(surfaces),
        "relationship_count": len(relationships),
        "claim_count": len(authority_claims),
        "patch_target_advisory_count": len(patch_target_advisories),
        "blocked_patch_target_count": len(patch_target_advisories),
        "propagation_route_count": authority_propagation_graph.get("route_count", 0),
        "interception_point_count": len(authority_propagation_graph.get("interception_points", [])),
        "lifecycle_profile_count": lifecycle_model.get("profile_count", 0),
        "state_surface_counts": dict(surface_counts),
        "authority_label_counts": dict(label_counts),
        "patchability_counts": dict(patchability_counts),
        "relationship_types": dict(relationship_counts),
        "lifecycle_profile_types": dict(lifecycle_model.get("profile_types", {})),
        "top_authority_surfaces": [
            {
                "surface_id": claim.get("surface_id", ""),
                "surface_ref": claim.get("surface_ref", ""),
                "authority_label": claim.get("authority_label", ""),
                "state_surface": claim.get("state_surface", ""),
            }
            for claim in authority_claims[:5]
        ],
        "top_patch_target_advisories": [
            {
                "surface_id": advisory.get("surface_id", ""),
                "surface_ref": advisory.get("surface_ref", ""),
                "patchability_class": advisory.get("patchability_class", ""),
            }
            for advisory in patch_target_advisories[:5]
        ],
        "top_blocked_patch_targets": [
            {
                "surface_id": advisory.get("surface_id", ""),
                "surface_ref": advisory.get("surface_ref", ""),
                "patchability_class": advisory.get("patchability_class", ""),
            }
            for advisory in patch_target_advisories[:5]
        ],
        "top_authority_routes": [
            {
                "source_surface_ref": route.get("source_surface_ref", ""),
                "terminal_surface_ref": route.get("terminal_surface_ref", ""),
                "recommended_interception_ref": route.get("recommended_interception_ref", ""),
            }
            for route in authority_propagation_graph.get("routes", [])[:5]
        ],
    }


def _build_state_lifecycle_model(surfaces: list[dict[str, Any]]) -> dict[str, Any]:
    profiles: list[dict[str, Any]] = []
    for surface in surfaces:
        incoming_relationships = [
            rel
            for rel in surface.get("sync_relationships", [])
            if rel.get("direction") == "incoming"
        ]
        incoming_types = {str(rel.get("relationship_type", "")) for rel in incoming_relationships}
        temporal_reasons: list[str] = []
        temporal_counter_signals: list[str] = []

        if surface.get("state_surface") == "UI_STATE":
            temporal_profile = "ui_projection_after_hydration"
            temporal_reasons.append("display path depends on upstream state projection before render")
        elif "refreshes" in incoming_types or "overwrites" in incoming_types:
            temporal_profile = "overwritten_after_refresh"
            temporal_reasons.append("refresh or overwrite relationship can replace local value")
        elif surface.get("state_surface") in {"LOCAL_CACHE", "TRANSIENT_MEMORY"} and "syncs_to" in incoming_types:
            temporal_profile = "survives_until_sync"
            temporal_reasons.append("local value can survive briefly until upstream sync lands")
        elif surface.get("state_surface") == "PERSISTED_STATE" and not incoming_types:
            temporal_profile = "persists_across_relaunch"
            temporal_reasons.append("persistence-backed state has no explicit overwrite path in current evidence")
        elif surface.get("state_surface") == "REMOTE_AUTHORITY":
            temporal_profile = "refresh_origin"
            temporal_reasons.append("surface acts as an upstream refresh source")
        else:
            temporal_profile = "session_scoped"
            temporal_reasons.append("no durable persistence or refresh window was recovered")

        for trigger in surface.get("lifecycle_refresh_triggers", [])[:3]:
            _append_unique(temporal_reasons, trigger)
        if float(surface.get("overwrite_risk", 0.0)) >= 0.55:
            _append_unique(temporal_counter_signals, "elevated overwrite risk compresses value lifetime")
        for signal in surface.get("counter_signals", []):
            if len(temporal_counter_signals) >= 4:
                break
            _append_unique(temporal_counter_signals, str(signal))

        temporal_confidence = round(
            min(0.95, 0.3 + (float(surface.get("classification_confidence", 0.0)) * 0.6) + (0.05 if incoming_types else 0.0)),
            3,
        )
        surface["temporal_profile"] = temporal_profile
        surface["temporal_confidence"] = temporal_confidence
        surface["temporal_reasons"] = temporal_reasons[:5]
        surface["temporal_counter_signals"] = temporal_counter_signals[:4]

        profiles.append({
            "surface_id": surface.get("surface_id", ""),
            "surface_ref": surface.get("surface_ref", ""),
            "class": surface.get("class", ""),
            "method": surface.get("method", ""),
            "field": surface.get("field", ""),
            "state_surface": surface.get("state_surface", ""),
            "authority_label": surface.get("authority_label", ""),
            "temporal_profile": temporal_profile,
            "temporal_confidence": temporal_confidence,
            "temporal_reasons": temporal_reasons[:5],
            "temporal_counter_signals": temporal_counter_signals[:4],
            "score": round(float(surface.get("importance_score", 0.0)) + (temporal_confidence * 12.0), 3),
        })

    profiles.sort(key=lambda item: (-float(item.get("score", 0)), item.get("surface_ref", "")))
    return {
        "profile_count": len(profiles),
        "profile_types": dict(Counter(profile.get("temporal_profile", "unknown") for profile in profiles)),
        "profiles": profiles[:80],
        "risk_windows": [
            {
                "surface_id": profile.get("surface_id", ""),
                "surface_ref": profile.get("surface_ref", ""),
                "temporal_profile": profile.get("temporal_profile", ""),
                "reason": (profile.get("temporal_reasons", []) or [""])[0],
            }
            for profile in profiles
            if profile.get("temporal_profile") in {"ui_projection_after_hydration", "survives_until_sync", "overwritten_after_refresh"}
        ][:15],
    }


def _build_authority_propagation_graph(
    surfaces: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
    *,
    max_routes: int = 30,
) -> dict[str, Any]:
    surface_by_id = {str(surface.get("surface_id", "")): surface for surface in surfaces}
    outgoing: dict[str, list[dict[str, Any]]] = {}
    edges: list[dict[str, Any]] = []

    for relationship in relationships:
        source = surface_by_id.get(str(relationship.get("source_surface_id", "")))
        target = surface_by_id.get(str(relationship.get("target_surface_id", "")))
        if source is None or target is None:
            continue
        outgoing.setdefault(source["surface_id"], []).append(relationship)
        edges.append({
            "edge_id": f"edge:{relationship.get('source_surface_id', '')}:{relationship.get('relationship_type', '')}:{relationship.get('target_surface_id', '')}",
            "source_surface_id": source["surface_id"],
            "source_surface_ref": source.get("surface_ref", ""),
            "source_authority_label": source.get("authority_label", ""),
            "target_surface_id": target["surface_id"],
            "target_surface_ref": target.get("surface_ref", ""),
            "target_authority_label": target.get("authority_label", ""),
            "relationship_type": relationship.get("relationship_type", ""),
            "confidence": relationship.get("confidence", 0.0),
            "propagation_role": _propagation_role(source, target, str(relationship.get("relationship_type", ""))),
        })

    routes: list[dict[str, Any]] = []
    source_ids = [
        surface["surface_id"]
        for surface in surfaces
        if surface.get("authority_label") in {"authoritative", "likely_authoritative"}
        and float(surface.get("classification_confidence", 0.0)) >= 0.45
    ]
    for source_id in source_ids[:12]:
        _collect_propagation_routes(
            source_id,
            outgoing,
            surface_by_id,
            path_ids=[source_id],
            path_edges=[],
            routes=routes,
            max_depth=4,
            max_routes=max_routes,
        )
        if len(routes) >= max_routes:
            break

    routes.sort(key=lambda item: (-float(item.get("score", 0)), item.get("terminal_surface_ref", "")))
    interception_points = _build_interception_points(routes, surface_by_id)
    return {
        "edge_count": len(edges),
        "route_count": len(routes[:max_routes]),
        "edges": edges[:120],
        "routes": routes[:max_routes],
        "interception_points": interception_points[:20],
    }


def _collect_propagation_routes(
    current_surface_id: str,
    outgoing: dict[str, list[dict[str, Any]]],
    surface_by_id: dict[str, dict[str, Any]],
    *,
    path_ids: list[str],
    path_edges: list[dict[str, Any]],
    routes: list[dict[str, Any]],
    max_depth: int,
    max_routes: int,
) -> None:
    if len(routes) >= max_routes:
        return

    next_edges = [
        edge
        for edge in sorted(outgoing.get(current_surface_id, []), key=lambda item: -float(item.get("confidence", 0)))
        if str(edge.get("target_surface_id", "")) not in path_ids
    ]

    if len(path_edges) >= max_depth or not next_edges:
        if len(path_ids) > 1:
            routes.append(_materialize_propagation_route(path_ids, path_edges, surface_by_id))
        return

    for edge in next_edges[:3]:
        target_surface_id = str(edge.get("target_surface_id", ""))
        _collect_propagation_routes(
            target_surface_id,
            outgoing,
            surface_by_id,
            path_ids=[*path_ids, target_surface_id],
            path_edges=[*path_edges, edge],
            routes=routes,
            max_depth=max_depth,
            max_routes=max_routes,
        )
        if len(routes) >= max_routes:
            return


def _materialize_propagation_route(
    path_ids: list[str],
    path_edges: list[dict[str, Any]],
    surface_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    route_surfaces = [surface_by_id[surface_id] for surface_id in path_ids if surface_id in surface_by_id]
    source = route_surfaces[0]
    terminal = route_surfaces[-1]
    interception_surface, interception_reason = _pick_interception_surface(route_surfaces)
    confidence_parts = [float(surface.get("classification_confidence", 0.0)) for surface in route_surfaces]
    confidence_parts.extend(float(edge.get("confidence", 0.0)) for edge in path_edges)
    route_confidence = round(sum(confidence_parts) / max(len(confidence_parts), 1), 3)
    return {
        "route_id": f"route:{'|'.join(path_ids)}",
        "source_surface_id": source.get("surface_id", ""),
        "source_surface_ref": source.get("surface_ref", ""),
        "source_authority_label": source.get("authority_label", ""),
        "terminal_surface_id": terminal.get("surface_id", ""),
        "terminal_surface_ref": terminal.get("surface_ref", ""),
        "terminal_authority_label": terminal.get("authority_label", ""),
        "path_surface_ids": path_ids,
        "path_surface_refs": [surface.get("surface_ref", "") for surface in route_surfaces],
        "path_state_surfaces": [surface.get("state_surface", "") for surface in route_surfaces],
        "path_authority_labels": [surface.get("authority_label", "") for surface in route_surfaces],
        "relationship_types": [str(edge.get("relationship_type", "")) for edge in path_edges],
        "route_confidence": route_confidence,
        "recommended_interception_surface_id": interception_surface.get("surface_id", ""),
        "recommended_interception_ref": interception_surface.get("surface_ref", ""),
        "recommended_interception_reason": interception_reason,
        "score": round((route_confidence * 100.0) + float(interception_surface.get("importance_score", 0.0)), 3),
    }


def _build_interception_points(
    routes: list[dict[str, Any]],
    surface_by_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    points: list[dict[str, Any]] = []
    seen: set[str] = set()
    for route in routes:
        surface_id = str(route.get("recommended_interception_surface_id", ""))
        if not surface_id or surface_id in seen:
            continue
        surface = surface_by_id.get(surface_id)
        if surface is None:
            continue
        seen.add(surface_id)
        points.append({
            "surface_id": surface_id,
            "surface_ref": surface.get("surface_ref", ""),
            "authority_label": surface.get("authority_label", ""),
            "patchability_class": surface.get("patchability_class", ""),
            "classification_confidence": surface.get("classification_confidence", 0.0),
            "reason": route.get("recommended_interception_reason", ""),
            "score": round(float(route.get("score", 0.0)) + float(surface.get("classification_confidence", 0.0)) * 10.0, 3),
        })

    points.sort(key=lambda item: (-float(item.get("score", 0)), item.get("surface_ref", "")))
    return points


def _pick_interception_surface(route_surfaces: list[dict[str, Any]]) -> tuple[dict[str, Any], str]:
    for surface in route_surfaces:
        if surface.get("authority_label") in {"authoritative", "likely_authoritative"} and surface.get("patchability_class") in {"patch_boundary_or_mapper", "candidate_root_cause"}:
            return surface, "earliest high-confidence upstream interception point on this recovered authority route"
    for surface in route_surfaces:
        if surface.get("patchability_class") not in {"cosmetic_only", "consumer_only"}:
            return surface, "earliest non-cosmetic interception point on this recovered authority route"
    return route_surfaces[0], "upstream route anchor recovered from static authority flow"


def _propagation_role(source: dict[str, Any], target: dict[str, Any], relationship_type: str) -> str:
    if relationship_type == "projects_to_ui" or target.get("authority_label") == "display_only":
        return "state_to_ui_projection"
    if relationship_type in {"refreshes", "overwrites"}:
        return "refresh_or_overwrite"
    if source.get("authority_label") in {"authoritative", "likely_authoritative"} and target.get("authority_label") == "cache":
        return "authority_to_cache"
    if source.get("authority_label") == "cache" and target.get("authority_label") == "mirror":
        return "cache_to_consumer"
    return "state_flow"


def _normalize_record_types(record_type: str) -> set[str]:
    normalized = record_type.strip()
    if not normalized:
        return set()
    if normalized in {"blocked_patch_target", "patch_target_advisory"}:
        return {"blocked_patch_target", "patch_target_advisory"}
    return {normalized}


def _record(
    *,
    record_type: str,
    title: str,
    score: float,
    class_name: str = "",
    method_name: str = "",
    field_name: str = "",
    authority_label: str = "",
    file_path: str = "",
    evidence: list[Any] | None = None,
    source: str = "source_of_truth",
) -> dict[str, Any]:
    evidence_list = [str(item) for item in (evidence or []) if str(item).strip()]
    text = " ".join(part for part in [title, class_name, method_name, field_name, authority_label, file_path, *evidence_list] if part)
    return {
        "type": record_type,
        "title": title,
        "score": round(float(score), 3),
        "class": class_name,
        "method": method_name,
        "field": field_name,
        "authority_label": authority_label,
        "file": file_path,
        "evidence": evidence_list[:10],
        "source": source,
        "text": text,
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


def _query_tokens(*parts: str) -> set[str]:
    blob = " ".join(part for part in parts if part)
    return {
        token.lower()
        for token in blob.replace("->", " ").replace(":", " ").replace("(", " ").replace(")", " ").split()
        if len(token) >= 2
    }


def _ensure_method_surface(
    surfaces: dict[str, dict[str, Any]],
    method_ref: str,
    *,
    file_path: str = "",
    class_name: str = "",
) -> dict[str, Any]:
    normalized = method_ref.strip()
    if class_name and normalized and not normalized.startswith("L"):
        normalized = _class_method_ref(class_name, normalized)
    owner = _extract_class_from_ref(normalized) or class_name
    surface_id = f"method:{normalized}"
    return _ensure_surface(
        surfaces,
        surface_id,
        surface_kind="method",
        surface_ref=normalized,
        class_name=owner,
        method_name=normalized,
        file_path=file_path,
    )


def _ensure_field_surface(
    surfaces: dict[str, dict[str, Any]],
    field_ref: str,
    *,
    file_path: str = "",
) -> dict[str, Any]:
    normalized = field_ref.strip()
    owner = _extract_class_from_ref(normalized)
    field_name = normalized.split("->", 1)[1] if "->" in normalized else normalized
    surface_id = f"field:{normalized}"
    return _ensure_surface(
        surfaces,
        surface_id,
        surface_kind="field",
        surface_ref=normalized,
        class_name=owner,
        field_name=field_name,
        file_path=file_path,
    )


def _ensure_class_surface(
    surfaces: dict[str, dict[str, Any]],
    class_ref: str,
    *,
    file_path: str = "",
) -> dict[str, Any]:
    normalized = class_ref.strip()
    surface_id = f"class:{normalized}"
    return _ensure_surface(
        surfaces,
        surface_id,
        surface_kind="class",
        surface_ref=normalized,
        class_name=normalized,
        file_path=file_path,
    )


def _ensure_remote_surface(
    surfaces: dict[str, dict[str, Any]],
    ref: str,
    *,
    file_path: str = "",
) -> dict[str, Any]:
    normalized = ref.strip() or "<remote-authority>"
    if _looks_like_method_ref(normalized):
        surface = _ensure_method_surface(
            surfaces,
            normalized,
            file_path=file_path,
            class_name=_extract_class_from_ref(normalized),
        )
        _add_surface_score(surface, "REMOTE_AUTHORITY", 9.0, "remote-backed method inferred as authoritative state boundary")
        _set_mutation_authority(surface, "authoritative_writer", priority=5)
        return surface
    surface_id = f"remote:{_slugify(normalized)}"
    surface = _ensure_surface(
        surfaces,
        surface_id,
        surface_kind="synthetic",
        surface_ref=normalized,
        file_path=file_path,
    )
    _add_surface_score(surface, "REMOTE_AUTHORITY", 9.0, "synthetic remote authority inferred from state transition")
    _set_mutation_authority(surface, "authoritative_writer", priority=5)
    return surface


def _ensure_surface(
    surfaces: dict[str, dict[str, Any]],
    surface_id: str,
    *,
    surface_kind: str,
    surface_ref: str,
    class_name: str = "",
    method_name: str = "",
    field_name: str = "",
    file_path: str = "",
) -> dict[str, Any]:
    surface = surfaces.get(surface_id)
    if surface is None:
        surface = {
            "surface_id": surface_id,
            "surface_kind": surface_kind,
            "surface_ref": surface_ref,
            "class": class_name,
            "method": method_name,
            "field": field_name,
            "file": file_path,
            "state_surface_scores": {name: 0.0 for name in STATE_SURFACE_TYPES},
            "state_surface": "TRANSIENT_MEMORY",
            "authority_label": "uncertain",
            "ownership_confidence": 0.0,
            "classification_confidence": 0.0,
            "classification_reasons": [],
            "counter_signals": [],
            "classification_status": "contestable_hypothesis",
            "classification_contestable": True,
            "classification_overridable": True,
            "mutation_authority": "observer",
            "patchability_class": "uncertain",
            "overwrite_risk": 0.0,
            "sync_relationships": [],
            "upstream_surface_ids": [],
            "downstream_surface_ids": [],
            "lifecycle_refresh_triggers": [],
            "temporal_profile": "unknown",
            "temporal_confidence": 0.0,
            "temporal_reasons": [],
            "temporal_counter_signals": [],
            "supporting_signals": [],
            "counter_evidence": [],
            "importance_score": 0.0,
            "_mutation_priority": 0,
        }
        surfaces[surface_id] = surface

    if class_name and not surface.get("class"):
        surface["class"] = class_name
    if method_name and not surface.get("method"):
        surface["method"] = method_name
    if field_name and not surface.get("field"):
        surface["field"] = field_name
    if file_path and not surface.get("file"):
        surface["file"] = file_path
    return surface


def _add_surface_score(surface: dict[str, Any], state_surface: str, amount: float, reason: str) -> None:
    surface["state_surface_scores"][state_surface] = float(surface["state_surface_scores"].get(state_surface, 0.0)) + float(amount)
    _append_unique(surface["supporting_signals"], reason)


def _set_mutation_authority(surface: dict[str, Any], value: str, *, priority: int) -> None:
    if priority >= int(surface.get("_mutation_priority", 0)):
        surface["mutation_authority"] = value
        surface["_mutation_priority"] = priority


def _store_relationship(
    relationships: dict[tuple[str, str, str], dict[str, Any]],
    source_surface_id: str,
    target_surface_id: str,
    relationship_type: str,
    confidence: float,
    reasons: list[str],
) -> None:
    key = (source_surface_id, target_surface_id, relationship_type)
    summary = reasons[0] if reasons else relationship_type
    current = relationships.get(key)
    if current is None or float(current.get("confidence", 0)) < float(confidence):
        relationships[key] = {
            "source_surface_id": source_surface_id,
            "target_surface_id": target_surface_id,
            "relationship_type": relationship_type,
            "confidence": round(float(confidence), 3),
            "summary": summary,
            "reasons": reasons[:5],
        }


def _public_surface(surface: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in surface.items()
        if not key.startswith("_")
    }


def _append_unique(store: list[Any], value: Any) -> None:
    if value not in store:
        store.append(value)


def _patch_advisory_reason(surface: dict[str, Any]) -> str:
    label = str(surface.get("authority_label", ""))
    if label == "display_only":
        return "Likely UI projection; prefer upstream state for durable changes, but a UI patch can still be useful for tactical display-only goals."
    if label == "mirror":
        return "Likely upstream mirror; durable behavior changes usually belong upstream, but local edits may still help for instrumentation or partial bypass."
    if label == "cache":
        return "Likely local cache fed by upstream authority; a local patch may work temporarily until the next sync or refresh."
    if surface.get("patchability_class") in {"volatile_cache", "volatile_state"}:
        return "This surface appears volatile or refresh-driven; patching it alone may not survive lifecycle refresh, but it remains a valid exploratory target."
    return "This surface is probably not the most stable root-cause patch target under current evidence, but the advisory is contestable."


def _field_ref(class_name: str, field_name: str) -> str:
    normalized_field = field_name
    if normalized_field.startswith(f"{class_name}->"):
        return normalized_field
    return f"{class_name}->{normalized_field}"


def _class_method_ref(class_name: str, method_name: str) -> str:
    if method_name.startswith("L"):
        return method_name
    if "(" in method_name:
        return f"{class_name}->{method_name}"
    return f"{class_name}->{method_name}()V"


def _extract_class_from_ref(ref: object) -> str:
    text = str(ref or "").strip()
    if not text.startswith("L"):
        return ""
    if "->" in text:
        return text.split("->", 1)[0]
    if text.endswith(";"):
        return text
    return ""


def _looks_like_method_ref(ref: str) -> bool:
    text = ref.strip()
    return text.startswith("L") and "->" in text and "(" in text and ")" in text


def _looks_like_field_ref(ref: str) -> bool:
    text = ref.strip()
    return text.startswith("L") and "->" in text and "(" not in text


def _slugify(value: str) -> str:
    lowered = value.strip().lower()
    lowered = lowered.replace("->", "_")
    return re.sub(r"[^a-z0-9_]+", "_", lowered).strip("_") or "surface"