"""Invariant validation helpers for Semantic Core v0.1.0."""

from __future__ import annotations

from typing import Any

from apk_agent.tools.semantic_core.rules import RULE_IDS
from apk_agent.tools.semantic_core.schema import (
    ALLOWED_INFERENCE_CLASSES,
    BOUNDARY_KINDS,
    CAPABILITY_KINDS,
    EDGE_KINDS,
    NODE_KINDS,
    SEMANTIC_SCHEMA_VERSION,
    STATE_CLASSES,
)


_AUTHORITATIVE_BOUNDARIES = {
    "persistence_boundary",
    "serialization_boundary",
    "network_boundary",
    "vm_runtime_boundary",
    "native_boundary",
    "trust_boundary",
}


def _has_provenance(record: dict[str, Any]) -> bool:
    return bool(record.get("rule_id") and record.get("derived_from") and record.get("evidence_refs"))


def validate_artifact(artifact: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if artifact.get("semantic_schema_version") != SEMANTIC_SCHEMA_VERSION:
        errors.append("semantic_schema_version missing or unsupported")

    nodes = artifact.get("nodes", [])
    edges = artifact.get("edges", [])
    evidence = artifact.get("evidence", [])
    inferences = artifact.get("inferences", [])
    evidence_ids = {item.get("id") for item in evidence if isinstance(item, dict) and item.get("id")}
    node_ids = {item.get("id") for item in nodes if isinstance(item, dict) and item.get("id")}
    nodes_by_id = {item.get("id"): item for item in nodes if isinstance(item, dict) and item.get("id")}
    derive_targets = {item.get("target") for item in edges if isinstance(item, dict) and item.get("kind") == "derive"}

    if len(node_ids) != len(nodes):
        errors.append("node IDs must be unique")
    if len({item.get('id') for item in edges if isinstance(item, dict) and item.get('id')}) != len(edges):
        errors.append("edge IDs must be unique")

    for node in nodes:
        if not isinstance(node, dict):
            errors.append("node record must be a dict")
            continue
        if node.get("kind") not in NODE_KINDS:
            errors.append(f"invalid node kind: {node.get('kind')}")
        if node.get("state_class") not in STATE_CLASSES:
            errors.append(f"invalid node state_class: {node.get('state_class')}")
        if node.get("inference_class") not in ALLOWED_INFERENCE_CLASSES:
            errors.append(f"invalid node inference_class: {node.get('inference_class')}")
        if not _has_provenance(node):
            errors.append(f"node lacks provenance: {node.get('id')}")
        if node.get("rule_id") not in RULE_IDS:
            errors.append(f"node rule_id is not registered: {node.get('rule_id')}")
        if any(ref not in evidence_ids for ref in node.get("evidence_refs", [])):
            errors.append(f"node evidence_refs unresolved: {node.get('id')}")

        if node.get("kind") == "field":
            state_class = node.get("state_class")
            if state_class == "canonical_state" and node.get("origin_kind") not in _AUTHORITATIVE_BOUNDARIES:
                errors.append(f"canonical field node missing authoritative origin: {node.get('id')}")
            if state_class == "derived_state" and node.get("id") not in derive_targets:
                errors.append(f"derived field node missing incoming derive edge: {node.get('id')}")
            if state_class == "presentation_state" and "ui" not in node.get("tags", []):
                errors.append(f"presentation field node missing ui tag: {node.get('id')}")
        if node.get("kind") == "boundary" and node.get("state_class") != "boundary_source":
            errors.append(f"boundary node must have boundary_source state_class: {node.get('id')}")
        if node.get("kind") == "capability":
            if node.get("state_class") != "capability_target":
                errors.append(f"capability node must have capability_target state_class: {node.get('id')}")
            if node.get("capability_kind") not in CAPABILITY_KINDS:
                errors.append(f"capability node missing bounded capability_kind: {node.get('id')}")

    for edge in edges:
        if not isinstance(edge, dict):
            errors.append("edge record must be a dict")
            continue
        if edge.get("kind") not in EDGE_KINDS:
            errors.append(f"invalid edge kind: {edge.get('kind')}")
        if edge.get("inference_class") not in ALLOWED_INFERENCE_CLASSES:
            errors.append(f"invalid edge inference_class: {edge.get('inference_class')}")
        if edge.get("source") not in node_ids or edge.get("target") not in node_ids:
            errors.append(f"edge endpoints unresolved: {edge.get('id')}")
        if not _has_provenance(edge):
            errors.append(f"edge lacks provenance: {edge.get('id')}")
        if edge.get("rule_id") not in RULE_IDS:
            errors.append(f"edge rule_id is not registered: {edge.get('rule_id')}")
        if any(ref not in evidence_ids for ref in edge.get("evidence_refs", [])):
            errors.append(f"edge evidence_refs unresolved: {edge.get('id')}")
        if edge.get("kind") in {"serialize", "deserialize"} and edge.get("boundary_kind") not in BOUNDARY_KINDS:
            errors.append(f"serialized boundary edge missing boundary_kind: {edge.get('id')}")
        if edge.get("kind") == "contradiction" and not edge.get("contradiction_kind"):
            errors.append(f"contradiction edge missing contradiction_kind: {edge.get('id')}")
        if edge.get("kind") == "capability_link":
            target = nodes_by_id.get(edge.get("target"), {})
            if target.get("kind") != "capability":
                errors.append(f"capability_link must target capability node: {edge.get('id')}")

    for inference in inferences:
        if not isinstance(inference, dict):
            errors.append("inference record must be a dict")
            continue
        if inference.get("rule_id") not in RULE_IDS:
            errors.append(f"inference rule_id is not registered: {inference.get('rule_id')}")
        if inference.get("inference_class") not in ALLOWED_INFERENCE_CLASSES:
            errors.append(f"invalid inference_class: {inference.get('inference_class')}")
        if not inference.get("derived_from"):
            errors.append(f"inference missing derived_from: {inference.get('id')}")
        if any(ref not in evidence_ids for ref in inference.get("evidence_refs", [])):
            errors.append(f"inference evidence_refs unresolved: {inference.get('id')}")
        output_refs = inference.get("output_refs", [])
        if any(ref not in node_ids and ref not in {edge.get('id') for edge in edges} for ref in output_refs):
            errors.append(f"inference output_refs unresolved: {inference.get('id')}")

    return sorted(set(errors))