"""Minimal rule registry for Semantic Core v0.1.0."""

from __future__ import annotations

from copy import deepcopy


_RULE_MANIFEST = [
    {
        "rule_id": "canonical_state_authoritative_origin",
        "rule_class": "classification_rule",
        "description": "Canonical state requires authoritative persistence, serialization, network, or bounded runtime origin.",
        "inputs": ["field", "writer_samples"],
        "outputs": ["state_class:canonical_state"],
        "invariant_refs": ["canonical_state_origin"],
        "deterministic": True,
        "enabled_in_schema_versions": ["0.1.0"],
    },
    {
        "rule_id": "presentation_state_ui_projection",
        "rule_class": "classification_rule",
        "description": "UI-only state is classified as presentation_state by default.",
        "inputs": ["field", "reader_samples"],
        "outputs": ["state_class:presentation_state"],
        "invariant_refs": ["presentation_state_ui_primary"],
        "deterministic": True,
        "enabled_in_schema_versions": ["0.1.0"],
    },
    {
        "rule_id": "ephemeral_state_runtime_fallback",
        "rule_class": "classification_rule",
        "description": "Non-authoritative runtime state defaults to ephemeral_state when no stronger invariant applies.",
        "inputs": ["field", "reader_samples", "writer_samples"],
        "outputs": ["state_class:ephemeral_state"],
        "invariant_refs": ["ephemeral_state_runtime_scope"],
        "deterministic": True,
        "enabled_in_schema_versions": ["0.1.0"],
    },
    {
        "rule_id": "derived_state_requires_upstream",
        "rule_class": "classification_rule",
        "description": "Derived state requires at least one upstream semantic dependency.",
        "inputs": ["field", "derive_edge"],
        "outputs": ["state_class:derived_state"],
        "invariant_refs": ["derived_state_has_upstream"],
        "deterministic": True,
        "enabled_in_schema_versions": ["0.1.0"],
    },
    {
        "rule_id": "field_write_depends_on_upstream_read",
        "rule_class": "link_rule",
        "description": "A write to one field that occurs in a method that reads another field emits a derive edge.",
        "inputs": ["method_flow", "field", "field"],
        "outputs": ["edge:derive"],
        "invariant_refs": ["derive_edge_requires_upstream"],
        "deterministic": True,
        "enabled_in_schema_versions": ["0.1.0"],
    },
    {
        "rule_id": "projection_contradiction_ui_projection",
        "rule_class": "demotion_rule",
        "description": "Presentation-state projections emit a projection contradiction to prevent accidental promotion.",
        "inputs": ["state_class:presentation_state"],
        "outputs": ["edge:contradiction"],
        "invariant_refs": ["contradiction_is_typed"],
        "deterministic": True,
        "enabled_in_schema_versions": ["0.1.0"],
    },
    {
        "rule_id": "capability_link_from_gate_reader",
        "rule_class": "link_rule",
        "description": "Gate-like reader methods may emit a bounded capability link.",
        "inputs": ["field", "reader_samples"],
        "outputs": ["edge:capability_link"],
        "invariant_refs": ["capability_link_has_taxonomy_target"],
        "deterministic": True,
        "enabled_in_schema_versions": ["0.1.0"],
    },
    {
        "rule_id": "cycle_summary_detect_scc",
        "rule_class": "validation_rule",
        "description": "Promoted graph cycles are summarized without amplifying canonicalization.",
        "inputs": ["nodes", "edges"],
        "outputs": ["cycle_summary"],
        "invariant_refs": ["cycles_do_not_amplify_canonicalization"],
        "deterministic": True,
        "enabled_in_schema_versions": ["0.1.0"],
    },
]

RULE_IDS = frozenset(rule["rule_id"] for rule in _RULE_MANIFEST)


def get_rule_manifest() -> list[dict[str, object]]:
    return deepcopy(sorted(_RULE_MANIFEST, key=lambda item: item["rule_id"]))