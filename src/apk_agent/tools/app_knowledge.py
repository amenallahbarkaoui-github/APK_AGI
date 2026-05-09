"""Application Knowledge Layer built from existing static analysis outputs.

This module is intentionally additive: it materializes a reusable knowledge pack
from the project's current semantic analyzers without replacing any existing
tooling or introducing local model training.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from typing import Any


PACK_VERSION = 1


def build_app_knowledge_pack(
    index,
    *,
    focus_hint: str = "",
    package_name: str = "",
    app_label: str = "",
    max_per_role: int = 12,
    max_state_fields: int = 40,
    max_guard_clusters: int = 40,
) -> dict[str, Any]:
    """Build a reusable application knowledge pack from existing analyzers."""
    if index is None:
        return {"success": False, "error": "SmaliIndex is required"}

    from apk_agent.tools.semantic_cache import (
        get_cached_guard_surface_profile,
        get_cached_hidden_state_model,
        get_cached_semantic_architecture,
    )

    warnings: list[str] = []
    architecture = get_cached_semantic_architecture(index, focus_hint=focus_hint, max_per_role=max_per_role)
    if not architecture.get("success", False):
        warnings.append(str(architecture.get("error", "semantic architecture build failed")))
        architecture = {}

    hidden_state = get_cached_hidden_state_model(index, focus_hint=focus_hint, max_candidates=max_state_fields)
    if not hidden_state.get("success", False):
        warnings.append(str(hidden_state.get("error", "hidden state recovery failed")))
        hidden_state = {}

    guard_surface = get_cached_guard_surface_profile(index, focus_hint=focus_hint, max_clusters=max_guard_clusters)
    if not guard_surface.get("success", False):
        warnings.append(str(guard_surface.get("error", "guard surface profiling failed")))
        guard_surface = {}

    semantic_core = _build_semantic_core_view(hidden_state, max_state_fields=max_state_fields)

    entities = _build_entities(
        architecture.get("architecture_layers", {}),
        architecture.get("high_value_components", []),
        hidden_state.get("candidate_models", []),
        hidden_state.get("candidate_state_fields", []),
    )
    control_points = _build_control_points(
        architecture.get("high_value_components", []),
        hidden_state.get("candidate_state_fields", []),
        guard_surface.get("guard_clusters", []),
        guard_surface.get("overwrite_points", []),
    )
    workflows = _infer_workflows(
        architecture.get("architecture_layers", {}),
        guard_surface.get("revalidation_loops", []),
    )
    records = _build_records(
        architecture.get("architecture_layers", {}),
        entities,
        hidden_state.get("candidate_state_fields", []),
        control_points,
        workflows,
        semantic_core,
    )

    built_at = time.time()
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
        "knowledge": {
            "architecture_layers": architecture.get("architecture_layers", {}),
            "high_value_components": architecture.get("high_value_components", [])[:20],
            "entities": entities[:20],
            "state_fields": hidden_state.get("candidate_state_fields", [])[:max_state_fields],
            "semantic_core": semantic_core,
            "guard_surfaces": guard_surface.get("guard_clusters", [])[:max_guard_clusters],
            "overwrite_points": guard_surface.get("overwrite_points", [])[:25],
            "revalidation_loops": guard_surface.get("revalidation_loops", [])[:20],
            "control_points": control_points[:25],
            "workflows": workflows,
        },
        "records": records[:250],
        "summary": _build_summary(
            architecture.get("architecture_layers", {}),
            entities,
            hidden_state.get("candidate_state_fields", []),
            guard_surface.get("guard_clusters", []),
            control_points,
            workflows,
            semantic_core,
        ),
        "warnings": warnings,
    }
    return pack


def save_app_knowledge_pack(pack: dict[str, Any], output_path: str | Path) -> dict[str, Any]:
    """Persist a knowledge pack as JSON using an atomic replace."""
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


def load_app_knowledge_pack(input_path: str | Path) -> dict[str, Any] | None:
    """Load a persisted knowledge pack from disk."""
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


def summarize_app_knowledge_pack(pack: dict[str, Any]) -> dict[str, Any]:
    """Return a compact summary for UI/tool responses."""
    knowledge = pack.get("knowledge", {})
    summary = dict(pack.get("summary", {}))
    summary.update({
        "pack_version": pack.get("pack_version", PACK_VERSION),
        "built_at": pack.get("built_at", 0.0),
        "package_name": pack.get("identity", {}).get("package_name", ""),
        "app_label": pack.get("identity", {}).get("app_label", ""),
        "workflow_count": len(knowledge.get("workflows", [])),
        "record_count": len(pack.get("records", [])),
        "warning_count": len(pack.get("warnings", [])),
    })
    return {"success": True, "summary": summary}


def query_app_knowledge(
    pack: dict[str, Any],
    query: str,
    *,
    feature: str = "",
    class_name: str = "",
    method_name: str = "",
    max_results: int = 8,
) -> dict[str, Any]:
    """Query the knowledge pack using graph-aware semantic records."""
    if not pack:
        return {"success": False, "error": "Knowledge pack is required"}

    tokens = _query_tokens(query, feature, class_name, method_name)
    if not tokens and not class_name and not method_name:
        return {
            "success": False,
            "error": "At least one query token, class_name, or method_name is required",
        }

    matches: list[dict[str, Any]] = []
    for record in pack.get("records", []):
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
        "total_matches": len(matches),
        "matches": matches[:max_results],
        "summary": summarize_app_knowledge_pack(pack).get("summary", {}),
    }


def _build_entities(
    architecture_layers: dict[str, list[dict[str, Any]]],
    high_value_components: list[dict[str, Any]],
    candidate_models: list[dict[str, Any]],
    state_fields: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    role_map = _role_map(architecture_layers)
    component_map = {item.get("class", ""): item for item in high_value_components if item.get("class")}
    fields_by_class: dict[str, list[dict[str, Any]]] = {}
    for field in state_fields:
        cls = field.get("class", "")
        if not cls:
            continue
        fields_by_class.setdefault(cls, []).append(field)

    entities: list[dict[str, Any]] = []
    for model in candidate_models:
        class_name = model.get("class", "")
        if not class_name:
            continue
        attached_fields = sorted(
            fields_by_class.get(class_name, []),
            key=lambda item: (-float(item.get("score", 0)), -float(item.get("confidence", 0))),
        )
        component = component_map.get(class_name, {})
        entities.append({
            "class": class_name,
            "file": model.get("file", ""),
            "score": float(model.get("score", 0)) + float(component.get("score_total", 0)),
            "evidence": model.get("evidence", [])[:6],
            "roles": role_map.get(class_name, []),
            "top_fields": attached_fields[:6],
            "dominant_roles": component.get("dominant_roles", [])[:3],
            "field_count": model.get("field_count", 0),
            "method_count": model.get("method_count", 0),
        })
    entities.sort(key=lambda item: (-item.get("score", 0), item.get("class", "")))
    return entities


def _build_control_points(
    high_value_components: list[dict[str, Any]],
    state_fields: list[dict[str, Any]],
    guard_clusters: list[dict[str, Any]],
    overwrite_points: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    control_points: list[dict[str, Any]] = []

    for item in guard_clusters:
        method_name = str(item.get("method", ""))
        score = float(item.get("severity_score", 0)) * 3.0 + float(item.get("state_write_count", 0)) * 2.0
        control_points.append({
            "type": "guard_surface" if float(item.get("state_write_count", 0)) <= 0 else "revalidation_boundary",
            "class": item.get("class", ""),
            "file": item.get("file", ""),
            "method": method_name,
            "score": score,
            "reasons": [
                f"guard tags: {', '.join(item.get('guard_tags', [])[:4])}" if item.get("guard_tags") else "guard cluster",
                f"trigger tags: {', '.join(item.get('trigger_tags', [])[:3])}" if item.get("trigger_tags") else "",
            ],
            "source": "guard_surface_profiler",
        })

    for item in overwrite_points:
        control_points.append({
            "type": "overwrite_point",
            "class": item.get("class", ""),
            "file": item.get("file", ""),
            "method": item.get("method", ""),
            "score": float(item.get("state_write_count", 0)) * 4.0,
            "reasons": [f"state writes: {item.get('state_write_count', 0)}"],
            "source": "guard_surface_profiler",
        })

    for item in state_fields[:12]:
        control_points.append({
            "type": "state_source_of_truth",
            "class": item.get("class", ""),
            "file": item.get("file", ""),
            "field": item.get("field", ""),
            "score": float(item.get("score", 0)) + float(item.get("confidence", 0)) * 10.0,
            "reasons": [
                f"semantic: {item.get('semantic_guess', 'state_value')}",
                f"readers={item.get('read_count', 0)} writers={item.get('write_count', 0)}",
            ],
            "source": "state_model_recovery",
        })

    for item in high_value_components[:10]:
        control_points.append({
            "type": "architecture_anchor",
            "class": item.get("class", ""),
            "file": item.get("file", ""),
            "score": float(item.get("score_total", 0)),
            "reasons": [f"roles: {', '.join(item.get('dominant_roles', [])[:3])}"],
            "source": "semantic_architecture",
        })

    for item in control_points:
        item["reasons"] = [reason for reason in item.get("reasons", []) if reason]
    control_points.sort(key=lambda item: (-item.get("score", 0), item.get("class", ""), item.get("method", "")))
    return control_points


def _infer_workflows(
    architecture_layers: dict[str, list[dict[str, Any]]],
    revalidation_loops: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    workflows: list[dict[str, Any]] = []

    def _top_classes(role: str) -> list[str]:
        return [item.get("class", "") for item in architecture_layers.get(role, [])[:4] if item.get("class")]

    network = _top_classes("network_layer")
    serialization = _top_classes("serialization_layer")
    state_models = _top_classes("state_models")
    ui = _top_classes("ui_gate_controllers")
    guards = _top_classes("security_guards")
    billing = _top_classes("billing_flow")

    if network or serialization or state_models:
        workflows.append({
            "name": "network_response_to_state",
            "description": "Where server responses, parsers, and state entities converge.",
            "anchor_classes": list(dict.fromkeys(network + serialization + state_models))[:10],
        })
    if ui or state_models:
        workflows.append({
            "name": "ui_gate_to_state",
            "description": "UI controllers and gate readers that depend on recovered state models.",
            "anchor_classes": list(dict.fromkeys(ui + state_models))[:10],
        })
    if billing or state_models:
        workflows.append({
            "name": "billing_entitlement_flow",
            "description": "Billing or entitlement sources that eventually drive the app state model.",
            "anchor_classes": list(dict.fromkeys(billing + state_models))[:10],
        })
    if guards or revalidation_loops:
        loop_classes = [item.get("class", "") for item in revalidation_loops[:4] if item.get("class")]
        workflows.append({
            "name": "guard_revalidation_cycle",
            "description": "Guard or lifecycle paths that can restore or re-check protected state.",
            "anchor_classes": list(dict.fromkeys(guards + loop_classes))[:10],
        })
    return workflows


def _build_records(
    architecture_layers: dict[str, list[dict[str, Any]]],
    entities: list[dict[str, Any]],
    state_fields: list[dict[str, Any]],
    control_points: list[dict[str, Any]],
    workflows: list[dict[str, Any]],
    semantic_core: dict[str, Any],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    for role, items in architecture_layers.items():
        for item in items[:12]:
            records.append(_record(
                record_type="architecture_role",
                title=f"{role}: {item.get('class', '')}",
                score=float(item.get("score", 0)),
                class_name=item.get("class", ""),
                file_path=item.get("file", ""),
                evidence=item.get("evidence", []),
                source="semantic_architecture",
            ))

    for entity in entities[:20]:
        field_terms = [field.get("field", "") for field in entity.get("top_fields", [])]
        records.append(_record(
            record_type="entity",
            title=f"entity: {entity.get('class', '')}",
            score=float(entity.get("score", 0)),
            class_name=entity.get("class", ""),
            file_path=entity.get("file", ""),
            evidence=list(entity.get("evidence", [])) + list(entity.get("roles", [])) + field_terms,
            source="state_model_recovery",
        ))

    for field in state_fields[:40]:
        records.append(_record(
            record_type="state_field",
            title=f"state field: {field.get('class', '')}->{field.get('field', '')}",
            score=float(field.get("score", 0)),
            class_name=field.get("class", ""),
            field_name=field.get("field", ""),
            file_path=field.get("file", ""),
            evidence=[
                field.get("semantic_guess", ""),
                f"readers={field.get('read_count', 0)}",
                f"writers={field.get('write_count', 0)}",
                *field.get("evidence", []),
            ],
            source="state_model_recovery",
        ))

    for point in control_points[:30]:
        records.append(_record(
            record_type="control_point",
            title=f"{point.get('type', 'control_point')}: {point.get('class', '')}",
            score=float(point.get("score", 0)),
            class_name=point.get("class", ""),
            method_name=point.get("method", ""),
            field_name=point.get("field", ""),
            file_path=point.get("file", ""),
            evidence=point.get("reasons", []),
            source=point.get("source", "app_knowledge"),
        ))

    for workflow in workflows:
        records.append(_record(
            record_type="workflow",
            title=f"workflow: {workflow.get('name', '')}",
            score=40.0,
            evidence=[workflow.get("description", ""), *workflow.get("anchor_classes", [])],
            source="app_knowledge",
        ))

    for item in semantic_core.get("capability_links", [])[:12]:
        records.append(_record(
            record_type="semantic_capability_link",
            title=f"semantic capability: {item.get('capability_kind', '')}",
            score=38.0,
            class_name=item.get("class", ""),
            field_name=item.get("field", ""),
            file_path=item.get("file", ""),
            evidence=[item.get("state_class", ""), item.get("rule_id", ""), item.get("source_ref", "")],
            source="semantic_core",
        ))

    for item in semantic_core.get("contradictions", [])[:12]:
        records.append(_record(
            record_type="semantic_contradiction",
            title=f"semantic contradiction: {item.get('contradiction_kind', '')}",
            score=28.0,
            class_name=item.get("class", ""),
            field_name=item.get("field", ""),
            file_path=item.get("file", ""),
            evidence=[item.get("state_class", ""), item.get("rule_id", ""), item.get("source_ref", "")],
            source="semantic_core",
        ))

    for component in semantic_core.get("cycle_components", [])[:8]:
        records.append(_record(
            record_type="semantic_cycle",
            title=f"semantic cycle: {component.get('component_id', '')}",
            score=24.0 + float(component.get("size", 0)),
            evidence=[f"size={component.get('size', 0)}", *component.get("source_refs", [])[:4]],
            source="semantic_core",
        ))

    return records


def _build_summary(
    architecture_layers: dict[str, list[dict[str, Any]]],
    entities: list[dict[str, Any]],
    state_fields: list[dict[str, Any]],
    guard_clusters: list[dict[str, Any]],
    control_points: list[dict[str, Any]],
    workflows: list[dict[str, Any]],
    semantic_core: dict[str, Any],
) -> dict[str, Any]:
    role_counts = {role: len(items) for role, items in architecture_layers.items()}
    control_types = Counter(item.get("type", "unknown") for item in control_points)
    top_state_semantics = Counter(item.get("semantic_guess", "state_value") for item in state_fields)
    return {
        "role_counts": role_counts,
        "entity_count": len(entities),
        "state_field_count": len(state_fields),
        "guard_surface_count": len(guard_clusters),
        "control_point_count": len(control_points),
        "control_point_types": dict(control_types),
        "top_state_semantics": dict(top_state_semantics.most_common(8)),
        "workflow_count": len(workflows),
        "semantic_schema_version": semantic_core.get("semantic_schema_version", ""),
        "semantic_field_node_count": semantic_core.get("field_node_count", 0),
        "semantic_capability_link_count": len(semantic_core.get("capability_links", [])),
        "semantic_contradiction_count": len(semantic_core.get("contradictions", [])),
        "semantic_cycle_count": semantic_core.get("cycle_count", 0),
    }


def _build_semantic_core_view(hidden_state: dict[str, Any], *, max_state_fields: int) -> dict[str, Any]:
    if not isinstance(hidden_state, dict):
        return {
            "semantic_schema_version": "",
            "artifact_kind": "",
            "field_nodes": [],
            "capability_links": [],
            "contradictions": [],
            "cycle_components": [],
            "field_node_count": 0,
            "cycle_count": 0,
            "state_class_counts": {},
            "edge_kind_counts": {},
            "rule_count": 0,
        }

    nodes = hidden_state.get("nodes", []) if isinstance(hidden_state.get("nodes"), list) else []
    edges = hidden_state.get("edges", []) if isinstance(hidden_state.get("edges"), list) else []
    rule_manifest = hidden_state.get("rule_manifest", []) if isinstance(hidden_state.get("rule_manifest"), list) else []
    cycle_summary = hidden_state.get("cycle_summary", {}) if isinstance(hidden_state.get("cycle_summary"), dict) else {}

    node_by_id = {
        str(node.get("id", "")): node
        for node in nodes
        if isinstance(node, dict) and node.get("id")
    }

    field_nodes = []
    state_class_counts: Counter[str] = Counter()
    for node in nodes:
        if not isinstance(node, dict) or node.get("kind") != "field":
            continue
        state_class = str(node.get("state_class", "unknown"))
        state_class_counts[state_class] += 1
        source_ref = str(node.get("source_ref", ""))
        class_name, _, field_part = source_ref.partition("->")
        field_name = field_part.split(":", 1)[0] if field_part else ""
        field_nodes.append({
            "id": str(node.get("id", "")),
            "class": class_name,
            "field": field_name,
            "source_ref": source_ref,
            "state_class": state_class,
            "rule_id": str(node.get("rule_id", "")),
        })

    capability_links = []
    contradictions = []
    edge_kind_counts: Counter[str] = Counter()
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        kind = str(edge.get("kind", "unknown"))
        edge_kind_counts[kind] += 1
        source_node = node_by_id.get(str(edge.get("source", "")), {})
        source_ref = str(source_node.get("source_ref", ""))
        class_name, _, field_part = source_ref.partition("->")
        field_name = field_part.split(":", 1)[0] if field_part else ""
        if kind == "capability_link":
            target_node = node_by_id.get(str(edge.get("target", "")), {})
            capability_links.append({
                "class": class_name,
                "field": field_name,
                "file": "",
                "source_ref": source_ref,
                "state_class": str(source_node.get("state_class", "")),
                "capability_kind": str(target_node.get("capability_kind", "")),
                "rule_id": str(edge.get("rule_id", "")),
            })
        elif kind == "contradiction":
            contradictions.append({
                "class": class_name,
                "field": field_name,
                "file": "",
                "source_ref": source_ref,
                "state_class": str(source_node.get("state_class", "")),
                "contradiction_kind": str(edge.get("contradiction_kind", "")),
                "rule_id": str(edge.get("rule_id", "")),
            })

    cycle_components = []
    for component in cycle_summary.get("components", [])[:8] if isinstance(cycle_summary.get("components"), list) else []:
        if not isinstance(component, dict):
            continue
        source_refs = [
            str(node_by_id.get(str(node_id), {}).get("source_ref", ""))
            for node_id in component.get("node_ids", [])
            if node_by_id.get(str(node_id), {}).get("source_ref")
        ]
        cycle_components.append({
            "component_id": str(component.get("component_id", "")),
            "size": int(component.get("size", len(component.get("node_ids", [])) or 0)),
            "source_refs": source_refs,
        })

    return {
        "semantic_schema_version": str(hidden_state.get("semantic_schema_version", "") or ""),
        "artifact_kind": str(hidden_state.get("artifact_kind", "") or ""),
        "field_nodes": field_nodes[:max_state_fields],
        "capability_links": capability_links[:12],
        "contradictions": contradictions[:12],
        "cycle_components": cycle_components,
        "field_node_count": len(field_nodes),
        "cycle_count": int(cycle_summary.get("cycle_count", 0) or 0),
        "state_class_counts": dict(state_class_counts),
        "edge_kind_counts": dict(edge_kind_counts),
        "rule_count": len(rule_manifest),
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
    source: str = "app_knowledge",
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
        "evidence": evidence_list[:8],
        "source": source,
        "text": text,
    }


def _role_map(architecture_layers: dict[str, list[dict[str, Any]]]) -> dict[str, list[str]]:
    roles: dict[str, list[str]] = {}
    for role, items in architecture_layers.items():
        for item in items:
            class_name = item.get("class", "")
            if not class_name:
                continue
            roles.setdefault(class_name, []).append(role)
    for class_name in list(roles):
        roles[class_name] = sorted(set(roles[class_name]))
    return roles


def _query_tokens(query: str, feature: str, class_name: str, method_name: str) -> set[str]:
    blob = " ".join(part for part in (query, feature, class_name, method_name) if part)
    return {token.lower() for token in blob.replace("->", " ").replace(":", " ").replace("(", " ").replace(")", " ").split() if len(token) >= 2}


def _score_record(
    record: dict[str, Any],
    tokens: set[str],
    *,
    class_name: str = "",
    method_name: str = "",
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

    if record_field and any(token == record_field.lower() for token in tokens):
        score += 12.0
        reasons.append("field exact")

    return score, reasons