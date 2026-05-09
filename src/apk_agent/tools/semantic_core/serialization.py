"""Canonical serialization helpers for Semantic Core v0.1.0."""

from __future__ import annotations

from copy import deepcopy
from typing import Any


def _sorted_strings(values: list[Any]) -> list[Any]:
    return sorted(values, key=lambda value: str(value))


def _sort_record_lists(records: list[dict[str, Any]], *, id_key: str = "id") -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for record in records:
        item = deepcopy(record)
        for key in (
            "derived_from",
            "evidence_refs",
            "output_refs",
            "tags",
            "inputs",
            "outputs",
            "invariant_refs",
            "enabled_in_schema_versions",
            "reader_tags",
            "writer_tags",
        ):
            value = item.get(key)
            if isinstance(value, list):
                item[key] = _sorted_strings(value)
        normalized.append(item)
    return sorted(normalized, key=lambda item: str(item.get(id_key, "")))


def canonicalize_artifact(artifact: dict[str, Any]) -> dict[str, Any]:
    normalized = deepcopy(artifact)
    for key in ("nodes", "edges", "evidence", "inferences"):
        value = normalized.get(key)
        if isinstance(value, list):
            normalized[key] = _sort_record_lists(value)

    rule_manifest = normalized.get("rule_manifest")
    if isinstance(rule_manifest, list):
        normalized["rule_manifest"] = _sort_record_lists(rule_manifest, id_key="rule_id")

    cycle_summary = normalized.get("cycle_summary")
    if isinstance(cycle_summary, dict):
        components = cycle_summary.get("components")
        if isinstance(components, list):
            cycle_summary["components"] = _sort_record_lists(components, id_key="component_id")

    compatibility = normalized.get("compatibility_views")
    if isinstance(compatibility, dict):
        models = compatibility.get("candidate_models")
        if isinstance(models, list):
            compatibility["candidate_models"] = sorted(
                deepcopy(models),
                key=lambda item: (-float(item.get("score", 0)), str(item.get("class", ""))),
            )
        fields = compatibility.get("candidate_state_fields")
        if isinstance(fields, list):
            compatibility["candidate_state_fields"] = sorted(
                deepcopy(fields),
                key=lambda item: (
                    -float(item.get("score", 0)),
                    -float(item.get("confidence", 0)),
                    str(item.get("class", "")),
                    str(item.get("field", "")),
                ),
            )
    return normalized