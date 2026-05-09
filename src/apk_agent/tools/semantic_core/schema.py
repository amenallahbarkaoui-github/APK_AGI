"""Schema helpers for Semantic Core v0.1.0."""

from __future__ import annotations

from typing import Any


SEMANTIC_SCHEMA_VERSION = "0.1.0"
ARTIFACT_KIND = "semantic_core"

ALLOWED_INFERENCE_CLASSES = frozenset({
    "factual_evidence",
    "deterministic_inference",
    "heuristic_hint",
})

STATE_CLASSES = frozenset({
    "canonical_state",
    "derived_state",
    "ephemeral_state",
    "presentation_state",
    "boundary_source",
    "capability_target",
})

NODE_KINDS = frozenset({
    "field",
    "boundary",
    "capability",
})

EDGE_KINDS = frozenset({
    "write",
    "derive",
    "project",
    "serialize",
    "deserialize",
    "contradiction",
    "capability_link",
})

BOUNDARY_KINDS = frozenset({
    "persistence_boundary",
    "serialization_boundary",
    "network_boundary",
    "vm_runtime_boundary",
    "native_boundary",
    "trust_boundary",
})

CAPABILITY_KINDS = frozenset({
    "execution_capability",
    "access_capability",
    "billing_capability",
    "presentation_capability",
    "transport_capability",
    "crypto_capability",
})

RULE_CLASSES = frozenset({
    "validation_rule",
    "classification_rule",
    "link_rule",
    "demotion_rule",
})


def empty_artifact() -> dict[str, Any]:
    return {
        "semantic_schema_version": SEMANTIC_SCHEMA_VERSION,
        "artifact_kind": ARTIFACT_KIND,
        "nodes": [],
        "edges": [],
        "evidence": [],
        "inferences": [],
        "compatibility_views": {},
        "rule_manifest": [],
        "cycle_summary": {"cycle_count": 0, "components": []},
        "summary": {},
    }


def make_node(
    *,
    node_id: str,
    kind: str,
    state_class: str,
    label: str,
    source_ref: str,
    inference_class: str,
    rule_id: str,
    derived_from: list[str],
    evidence_refs: list[str],
    **extra: Any,
) -> dict[str, Any]:
    record = {
        "id": node_id,
        "kind": kind,
        "state_class": state_class,
        "label": label,
        "source_ref": source_ref,
        "inference_class": inference_class,
        "rule_id": rule_id,
        "derived_from": list(derived_from),
        "evidence_refs": list(evidence_refs),
    }
    record.update(extra)
    return record


def make_edge(
    *,
    edge_id: str,
    kind: str,
    source: str,
    target: str,
    boundary_kind: str | None,
    inference_class: str,
    rule_id: str,
    derived_from: list[str],
    evidence_refs: list[str],
    **extra: Any,
) -> dict[str, Any]:
    record = {
        "id": edge_id,
        "kind": kind,
        "source": source,
        "target": target,
        "boundary_kind": boundary_kind,
        "inference_class": inference_class,
        "rule_id": rule_id,
        "derived_from": list(derived_from),
        "evidence_refs": list(evidence_refs),
    }
    record.update(extra)
    return record


def make_evidence(*, evidence_id: str, evidence_kind: str, source_ref: str, payload_ref: str, **extra: Any) -> dict[str, Any]:
    record = {
        "id": evidence_id,
        "evidence_kind": evidence_kind,
        "source_ref": source_ref,
        "payload_ref": payload_ref,
    }
    record.update(extra)
    return record


def make_inference(
    *,
    inference_id: str,
    rule_id: str,
    inference_class: str,
    derived_from: list[str],
    evidence_refs: list[str],
    output_refs: list[str],
    **extra: Any,
) -> dict[str, Any]:
    record = {
        "id": inference_id,
        "rule_id": rule_id,
        "inference_class": inference_class,
        "derived_from": list(derived_from),
        "evidence_refs": list(evidence_refs),
        "output_refs": list(output_refs),
    }
    record.update(extra)
    return record