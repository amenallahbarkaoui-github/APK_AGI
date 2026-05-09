"""Recover hidden state models and high-value fields from obfuscated apps.

This module focuses on *behavioral* signals rather than obvious keywords. It
tries to identify entity/state classes and infer the meaning of important fields
by observing who reads them, who writes them, and in which contexts they move
through the app.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from apk_agent.tools.advanced_search import _is_third_party_path
from apk_agent.tools.semantic_core import (
    CAPABILITY_KINDS,
    SEMANTIC_SCHEMA_VERSION,
    canonicalize_artifact,
    empty_artifact,
    get_rule_manifest,
    make_edge,
    make_evidence,
    make_inference,
    make_node,
    normalize_field_source,
    normalize_method_source,
    stable_identity,
    summarize_cycles,
    validate_artifact,
)


_NETWORK_HINTS = ("lokhttp3/", "lretrofit2/", "httpurlconnection", "requestbody", "responsebody", "apollo", "ktor")
_SERIALIZATION_HINTS = ("gson", "moshi", "jackson", "org/json", "jsonobject", "jsonarray", "fromjson", "tojson", "parse", "deserialize", "serialize")
_STORE_HINTS = ("sharedpreferences", "datastore", "sqlitedatabase", "room", "realm", "cursor")
_BILLING_HINTS = ("billingclient", "purchase", "subscription", "premium", "license", "entitlement", "revenuecat", "qonversion")
_UI_HINTS = ("dialog", "activity", "fragment", "view", "paywall", "upgrade", "menu", "visibility")
_TIME_HINTS = ("time", "timestamp", "expire", "expiry", "renew", "valid", "until", "deadline", "due")
_STATE_HINTS = ("active", "enabled", "premium", "paid", "trial", "locked", "subscribed", "plan", "tier", "role", "pro", "vip")
_POSITIVE_VALUE_HINTS = ("premium", "pro", "vip", "svip", "paid", "gold", "diamond", "elite", "lifetime", "active", "valid", "subscribed", "owned", "unlock")
_NEGATIVE_VALUE_HINTS = ("free", "trial", "basic", "lite", "demo", "guest", "locked", "expired", "inactive", "invalid", "none")
_CRYPTO_HINTS = ("cipher", "secretkey", "messagedigest", "signature", "decrypt", "encrypt")
_STRONG_BILLING_HINTS = ("billingclient", "purchase", "subscription", "license", "entitlement", "revenuecat", "qonversion")
_AUTHORITATIVE_TAG_TO_BOUNDARY = (
    ("network", "network_boundary"),
    ("serialization", "serialization_boundary"),
    ("persistence", "persistence_boundary"),
)


def _method_blob(smali_method) -> str:
    parts: list[str] = [smali_method.name, smali_method.signature, smali_method.return_type]
    parts.extend(smali_method.param_types[:8])
    parts.extend(smali_method.api_calls[:40])
    parts.extend(smali_method.string_constants[:25])
    return " ".join(p for p in parts if p).lower()


def _class_blob(smali_class) -> str:
    parts: list[str] = [smali_class.name, smali_class.super_class, smali_class.source_file, smali_class.file_path]
    parts.extend(smali_class.interfaces[:10])
    parts.extend(field.name for field in smali_class.fields[:30])
    parts.extend(field.type for field in smali_class.fields[:30])
    return " ".join(p for p in parts if p).lower()


def _normalize_field_ref(field_ref: str) -> str:
    return field_ref.split(":", 1)[0] if ":" in field_ref else field_ref


def _candidate_class_score(smali_class) -> tuple[int, list[str]]:
    score = 0
    evidence: list[str] = []
    field_count = len(smali_class.fields)
    method_count = len(smali_class.methods)
    super_lower = (smali_class.super_class or "").lower()
    blob = _class_blob(smali_class)

    if 2 <= field_count <= 40:
        score += 4
        evidence.append(f"{field_count} fields")
    if field_count >= 6:
        score += 3
        evidence.append("dense field surface")
    if method_count <= 35:
        score += 2
        evidence.append("compact method surface")
    if all(token not in super_lower for token in ("activity;", "fragment;", "service;", "receiver;", "contentprovider;", "view;")):
        score += 2
        evidence.append("non-UI/non-component superclass")
    if any(hint in blob for hint in _SERIALIZATION_HINTS + _BILLING_HINTS + _STORE_HINTS):
        score += 4
        evidence.append("serialization/billing/store adjacency")
    if any(method.name.startswith(("get", "set", "is")) for method in smali_class.methods):
        score += 2
        evidence.append("accessor-like method patterns")

    return score, evidence


def _method_context_tags(smali_method) -> list[str]:
    blob = _method_blob(smali_method)
    tags: list[str] = []
    if any(h in blob for h in _NETWORK_HINTS):
        tags.append("network")
    if any(h in blob for h in _SERIALIZATION_HINTS):
        tags.append("serialization")
    if any(h in blob for h in _STORE_HINTS):
        tags.append("persistence")
    if any(h in blob for h in _BILLING_HINTS):
        tags.append("billing")
    if any(h in blob for h in _UI_HINTS):
        tags.append("ui")
    if any(h in blob for h in _TIME_HINTS):
        tags.append("time")
    if any(h in blob for h in _STATE_HINTS):
        tags.append("state")
    return tags


def _semantic_guess(field_type: str, usage: dict[str, Any], focus_terms: list[str]) -> tuple[str, Any, float, list[str]]:
    evidence: list[str] = []
    semantic = "state_value"
    score = 0

    reader_tags = usage["reader_tags"]
    writer_tags = usage["writer_tags"]
    combined = reader_tags | writer_tags
    field_name_lower = usage["field_name"].lower()

    if focus_terms and any(term in field_name_lower for term in focus_terms):
        score += 4
        evidence.append("focus term matched field name")

    if field_type == "Z":
        score += 3
        evidence.append("boolean field")
        semantic = "access_flag"
        likely_value: Any = True
    elif field_type in ("I", "J"):
        likely_value = 1
        if "time" in combined or any(token in field_name_lower for token in _TIME_HINTS):
            semantic = "expiry_or_timestamp"
            score += 6
            evidence.append("time-based access pattern")
            likely_value = 4102444800000 if field_type == "J" else 2147483647
        else:
            semantic = "tier_or_counter"
            score += 2
            evidence.append("numeric state field")
            likely_value = 2
    elif field_type == "Ljava/lang/String;":
        semantic = "plan_or_role"
        score += 3
        evidence.append("string state field")
        likely_value = "premium"
    else:
        likely_value = None

    if "billing" in combined:
        score += 5
        evidence.append("billing-linked reads/writes")
        if semantic in ("access_flag", "state_value"):
            semantic = "entitlement_flag"
        elif semantic == "tier_or_counter":
            semantic = "subscription_tier"
        elif semantic == "plan_or_role":
            semantic = "subscription_plan"
    if "serialization" in writer_tags or "network" in writer_tags:
        score += 4
        evidence.append("written from network/serialization context")
    if "persistence" in writer_tags or "persistence" in reader_tags:
        score += 2
        evidence.append("participates in persistence boundary")
    if "ui" in reader_tags:
        score += 3
        evidence.append("consumed by UI control path")
    if usage["read_count"] >= 3:
        score += 2
        evidence.append("multiple readers")
    if usage["write_count"] >= 2:
        score += 2
        evidence.append("multiple writers")

    confidence = min(0.98, round(0.35 + (score / 22.0), 3))
    return semantic, likely_value, confidence, evidence


def _parse_numeric_literal(raw: object) -> int | None:
    if raw is None:
        return None
    text = str(raw).strip().lower()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _coerce_literal_value(raw: object, field_type: str) -> Any | None:
    if raw is None:
        return None
    if field_type == "Ljava/lang/String;":
        text = str(raw)
        return text if text else None
    if field_type == "Z":
        numeric = _parse_numeric_literal(raw)
        if numeric is None:
            return None
        return bool(numeric)
    if field_type in ("I", "J"):
        return _parse_numeric_literal(raw)
    return None


def _literal_score(
    value: Any,
    *,
    field_type: str,
    semantic: str,
    method_name: str,
    tags: set[str],
    focus_terms: list[str],
) -> int:
    score = 0
    text = str(value).lower()

    if tags & {"network", "serialization", "billing"}:
        score += 2
    if tags & {"ui", "state"}:
        score += 1

    if field_type == "Z":
        if semantic in {"entitlement_flag", "access_flag"}:
            score += 4 if value is True else -4
        elif any(token in semantic for token in ("locked", "trial", "expiry", "timestamp")):
            score += 3 if value is False else -3
        else:
            score += 1 if value is True else 0
    elif field_type in ("I", "J"):
        numeric = int(value)
        if semantic == "expiry_or_timestamp":
            score += 4 if numeric > 1_000_000 else -3
        else:
            if numeric > 0:
                score += 1
            if numeric == 0:
                score -= 2
    elif field_type == "Ljava/lang/String;":
        if any(token in text for token in _POSITIVE_VALUE_HINTS):
            score += 4
        if any(token in text for token in _NEGATIVE_VALUE_HINTS):
            score -= 5
        if focus_terms and any(term in text for term in focus_terms):
            score += 1

    if any(token in method_name for token in _POSITIVE_VALUE_HINTS):
        score += 1
    if any(token in method_name for token in _NEGATIVE_VALUE_HINTS):
        score -= 1

    return score


def _resolve_exact_value_candidates(
    index,
    *,
    class_name: str,
    field_name: str,
    field_type: str,
    semantic: str,
    usage: dict[str, Any],
    focus_terms: list[str],
) -> tuple[Any | None, list[dict[str, Any]], str, bool]:
    target_field = f"{class_name}->{field_name}"
    candidate_map: dict[tuple[str, Any], dict[str, Any]] = {}

    def _record_candidate(value: Any, *, source: str, score: int, evidence: str, method_sig: str) -> None:
        key = (field_type, value)
        entry = candidate_map.setdefault(key, {
            "value": value,
            "score": 0,
            "sources": set(),
            "methods": set(),
            "evidence": [],
        })
        entry["score"] += score
        entry["sources"].add(source)
        entry["methods"].add(method_sig)
        if evidence not in entry["evidence"] and len(entry["evidence"]) < 5:
            entry["evidence"].append(evidence)

    for sample_kind, samples in (("writer", usage["writer_samples"]), ("reader", usage["reader_samples"])):
        for sample in samples[:8]:
            method_sig = str(sample.get("method", "")).strip()
            method = index.get_method(method_sig)
            if method is None:
                continue
            tags = set(sample.get("tags", []))
            method_name = method.name.lower()

            for idx, instr in enumerate(method.instructions):
                if instr.target_field != target_field:
                    continue
                if sample_kind == "writer" and not instr.opcode.startswith(("iput", "sput")):
                    continue
                if sample_kind == "reader" and not instr.opcode.startswith(("iget", "sget")):
                    continue

                start = max(0, idx - 3)
                end = min(len(method.instructions), idx + 4)
                for neighbor in method.instructions[start:end]:
                    raw_literal = neighbor.string_value if neighbor.string_value is not None else neighbor.const_value
                    coerced = _coerce_literal_value(raw_literal, field_type)
                    if coerced is None:
                        continue
                    base_score = 4 if sample_kind == "writer" else 3
                    source = "writer_literal" if sample_kind == "writer" else "reader_literal"
                    total_score = base_score + _literal_score(
                        coerced,
                        field_type=field_type,
                        semantic=semantic,
                        method_name=method_name,
                        tags=tags,
                        focus_terms=focus_terms,
                    )
                    _record_candidate(
                        coerced,
                        source=source,
                        score=total_score,
                        evidence=f"{source} in {method_sig}",
                        method_sig=method_sig,
                    )

            if sample_kind == "reader" and field_type == "Ljava/lang/String;":
                for literal in method.string_constants[:6]:
                    coerced = _coerce_literal_value(literal, field_type)
                    if coerced is None:
                        continue
                    total_score = 1 + _literal_score(
                        coerced,
                        field_type=field_type,
                        semantic=semantic,
                        method_name=method_name,
                        tags=tags,
                        focus_terms=focus_terms,
                    )
                    _record_candidate(
                        coerced,
                        source="reader_method_literal",
                        score=total_score,
                        evidence=f"reader method constant in {method_sig}",
                        method_sig=method_sig,
                    )

    candidates = sorted(
        (
            {
                "value": item["value"],
                "score": int(item["score"]),
                "sources": sorted(item["sources"]),
                "methods": sorted(item["methods"]),
                "evidence": item["evidence"],
            }
            for item in candidate_map.values()
            if int(item["score"]) > 0
        ),
        key=lambda item: (-item["score"], str(item["value"])),
    )

    if not candidates:
        return None, [], "semantic_guess", False

    top = candidates[0]
    conflicting_peer = any(
        candidate["value"] != top["value"] and candidate["score"] >= top["score"] - 1
        for candidate in candidates[1:]
    )
    if top["score"] >= 6 and not conflicting_peer:
        primary_source = top["sources"][0] if top["sources"] else "exact_literal_evidence"
        return top["value"], candidates[:5], primary_source, True

    return None, candidates[:5], "literal_candidates_conflict", False


def _sorted_classes(index) -> list[Any]:
    return sorted(index.classes.values(), key=lambda item: (item.name, item.file_path))


def _sorted_methods(index) -> list[Any]:
    return sorted(index.methods.values(), key=lambda item: item.full_signature)


def _field_source_ref(field_candidate: dict[str, Any]) -> str:
    return normalize_field_source(
        str(field_candidate.get("class", "")),
        str(field_candidate.get("field", "")),
        str(field_candidate.get("type", "")),
    )


def _origin_kind_for_field(field_candidate: dict[str, Any]) -> str | None:
    writer_tags = set(field_candidate.get("writer_tags", []))
    for tag, boundary_kind in _AUTHORITATIVE_TAG_TO_BOUNDARY:
        if tag in writer_tags:
            return boundary_kind
    return None


def _is_gate_like_method(smali_method) -> bool:
    if smali_method is None:
        return False
    if smali_method.return_type == "Z":
        return True
    if any(instr.is_branch for instr in smali_method.instructions):
        return True
    return any("equals" in api_call.lower() for api_call in smali_method.api_calls[:12])


def _field_is_ui_projection(index, field_candidate: dict[str, Any]) -> bool:
    reader_tags = set(field_candidate.get("reader_tags", []))
    if "ui" not in reader_tags:
        return False
    for sample in field_candidate.get("reader_samples", [])[:8]:
        method = index.get_method(str(sample.get("method", "")))
        if _is_gate_like_method(method) and "ui" not in set(sample.get("tags", [])):
            return False
    return True


def _has_strong_billing_signal(index, field_candidate: dict[str, Any]) -> bool:
    blobs: list[str] = [
        str(field_candidate.get("class", "")).lower(),
        str(field_candidate.get("field", "")).lower(),
    ]
    for sample in field_candidate.get("writer_samples", [])[:8] + field_candidate.get("reader_samples", [])[:8]:
        method = index.get_method(str(sample.get("method", "")))
        if method is not None:
            blobs.append(_method_blob(method))
    merged = " ".join(blob for blob in blobs if blob)
    return any(hint in merged for hint in _STRONG_BILLING_HINTS)


def _capability_kind_for_field(index, field_candidate: dict[str, Any]) -> tuple[str | None, list[str]]:
    reader_tags = set(field_candidate.get("reader_tags", []))
    writer_tags = set(field_candidate.get("writer_tags", []))
    combined = reader_tags | writer_tags
    gate_methods: list[str] = []
    crypto_methods: list[str] = []

    for sample in field_candidate.get("reader_samples", [])[:8]:
        method_sig = str(sample.get("method", ""))
        method = index.get_method(method_sig)
        if _is_gate_like_method(method):
            gate_methods.append(method_sig)
        if method is not None and any(hint in _method_blob(method) for hint in _CRYPTO_HINTS):
            crypto_methods.append(method_sig)

    if "billing" in combined and _has_strong_billing_signal(index, field_candidate):
        return "billing_capability", sorted(set(gate_methods or [sample.get("method", "") for sample in field_candidate.get("reader_samples", [])[:2]]))
    if crypto_methods:
        return "crypto_capability", sorted(set(crypto_methods))
    if gate_methods:
        return "access_capability", sorted(set(gate_methods))
    if "network" in combined or "serialization" in combined:
        methods = [str(sample.get("method", "")) for sample in field_candidate.get("writer_samples", [])[:2] if sample.get("method")]
        return "transport_capability", sorted(set(methods))
    if "ui" in combined:
        methods = [str(sample.get("method", "")) for sample in field_candidate.get("reader_samples", [])[:2] if sample.get("method")]
        return "presentation_capability", sorted(set(methods))
    return None, []


def _append_inference(
    inferences: list[dict[str, Any]],
    *,
    rule_id: str,
    inference_class: str,
    derived_from: list[str],
    evidence_refs: list[str],
    output_refs: list[str],
) -> None:
    inferences.append(make_inference(
        inference_id=stable_identity("inference", rule_id, sorted(output_refs), sorted(derived_from), sorted(evidence_refs)),
        rule_id=rule_id,
        inference_class=inference_class,
        derived_from=sorted(derived_from),
        evidence_refs=sorted(evidence_refs),
        output_refs=sorted(output_refs),
    ))


def _build_semantic_core_artifact(
    index,
    *,
    focus_hint: str,
    candidate_models: list[dict[str, Any]],
    field_candidates: list[dict[str, Any]],
    compatibility_fields: list[dict[str, Any]],
    method_relations: list[dict[str, Any]],
) -> dict[str, Any]:
    artifact = empty_artifact()
    artifact["rule_manifest"] = get_rule_manifest()

    evidence: list[dict[str, Any]] = []
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    inferences: list[dict[str, Any]] = []
    field_context: dict[str, dict[str, Any]] = {}
    field_ref_by_key: dict[tuple[str, str], str] = {}
    relation_evidence: dict[tuple[str, str, tuple[str, ...], tuple[str, ...]], str] = {}

    sorted_fields = sorted(
        field_candidates,
        key=lambda item: (str(item.get("class", "")), str(item.get("field", "")), str(item.get("type", ""))),
    )

    for field_candidate in sorted_fields:
        source_ref = _field_source_ref(field_candidate)
        field_node_id = stable_identity("node", "field", source_ref)
        base_evidence_id = stable_identity("evidence", "field_observed", source_ref)
        field_evidence = {
            "field": base_evidence_id,
            "writer": [],
            "reader": [],
            "writer_by_method": {},
            "reader_by_method": {},
        }
        evidence.append(make_evidence(
            evidence_id=base_evidence_id,
            evidence_kind="field_observed",
            source_ref=source_ref,
            payload_ref="field_observed",
        ))

        for sample in sorted(
            field_candidate.get("writer_samples", []),
            key=lambda item: (str(item.get("method", "")), int(item.get("line", 0) or 0), str(item.get("opcode", ""))),
        ):
            evidence_id = stable_identity(
                "evidence",
                "writer_sample",
                source_ref,
                str(sample.get("method", "")),
                int(sample.get("line", 0) or 0),
                str(sample.get("opcode", "")),
            )
            evidence.append(make_evidence(
                evidence_id=evidence_id,
                evidence_kind="writer_sample",
                source_ref=source_ref,
                payload_ref=f"{sample.get('method', '')}:{sample.get('line', 0)}:{sample.get('opcode', '')}",
                tags=sorted(sample.get("tags", [])),
            ))
            field_evidence["writer"].append(evidence_id)
            field_evidence["writer_by_method"].setdefault(str(sample.get("method", "")), []).append(evidence_id)

        for sample in sorted(
            field_candidate.get("reader_samples", []),
            key=lambda item: (str(item.get("method", "")), int(item.get("line", 0) or 0), str(item.get("opcode", ""))),
        ):
            evidence_id = stable_identity(
                "evidence",
                "reader_sample",
                source_ref,
                str(sample.get("method", "")),
                int(sample.get("line", 0) or 0),
                str(sample.get("opcode", "")),
            )
            evidence.append(make_evidence(
                evidence_id=evidence_id,
                evidence_kind="reader_sample",
                source_ref=source_ref,
                payload_ref=f"{sample.get('method', '')}:{sample.get('line', 0)}:{sample.get('opcode', '')}",
                tags=sorted(sample.get("tags", [])),
            ))
            field_evidence["reader"].append(evidence_id)
            field_evidence["reader_by_method"].setdefault(str(sample.get("method", "")), []).append(evidence_id)

        field_context[source_ref] = {
            "candidate": field_candidate,
            "node_id": field_node_id,
            "evidence": field_evidence,
        }
        field_ref_by_key[(str(field_candidate.get("class", "")), str(field_candidate.get("field", "")))] = source_ref

    for relation in sorted(
        method_relations,
        key=lambda item: (
            str(item.get("class", "")),
            str(item.get("method", "")),
            tuple(item.get("reads", [])),
            tuple(item.get("writes", [])),
        ),
    ):
        reads = tuple(str(item) for item in relation.get("reads", []))
        writes = tuple(str(item) for item in relation.get("writes", []))
        method_ref = normalize_method_source(str(relation.get("method", "")))
        evidence_id = stable_identity("evidence", "method_flow", str(relation.get("class", "")), method_ref, reads, writes)
        evidence.append(make_evidence(
            evidence_id=evidence_id,
            evidence_kind="method_flow",
            source_ref=method_ref,
            payload_ref=f"reads={','.join(reads)}|writes={','.join(writes)}",
            tags=sorted(relation.get("tags", [])),
            has_branch=bool(relation.get("has_branch", False)),
            returns_boolean=bool(relation.get("returns_boolean", False)),
        ))
        relation_evidence[(str(relation.get("class", "")), method_ref, reads, writes)] = evidence_id

    derive_inputs: dict[str, dict[str, Any]] = {}
    for relation in sorted(
        method_relations,
        key=lambda item: (
            str(item.get("class", "")),
            str(item.get("method", "")),
            tuple(item.get("reads", [])),
            tuple(item.get("writes", [])),
        ),
    ):
        relation_key = (
            str(relation.get("class", "")),
            normalize_method_source(str(relation.get("method", ""))),
            tuple(str(item) for item in relation.get("reads", [])),
            tuple(str(item) for item in relation.get("writes", [])),
        )
        relation_evidence_id = relation_evidence.get(relation_key)
        if not relation_evidence_id:
            continue
        read_refs = [field_ref_by_key[(str(relation.get("class", "")), field_name)] for field_name in relation.get("reads", []) if (str(relation.get("class", "")), field_name) in field_ref_by_key]
        write_refs = [field_ref_by_key[(str(relation.get("class", "")), field_name)] for field_name in relation.get("writes", []) if (str(relation.get("class", "")), field_name) in field_ref_by_key]
        for read_ref in read_refs:
            for write_ref in write_refs:
                if read_ref == write_ref:
                    continue
                source_node_id = field_context[read_ref]["node_id"]
                target_node_id = field_context[write_ref]["node_id"]
                edge_id = stable_identity("edge", "derive", source_node_id, target_node_id)
                entry = derive_inputs.setdefault(edge_id, {
                    "source": source_node_id,
                    "target": target_node_id,
                    "derived_from": {source_node_id},
                    "evidence_refs": set(),
                    "layer": "state_relations",
                })
                entry["evidence_refs"].add(relation_evidence_id)

    incoming_derive_nodes: dict[str, list[str]] = {}
    incoming_derive_evidence: dict[str, list[str]] = {}
    for edge_id, entry in sorted(derive_inputs.items(), key=lambda item: item[0]):
        edge = make_edge(
            edge_id=edge_id,
            kind="derive",
            source=str(entry["source"]),
            target=str(entry["target"]),
            boundary_kind=None,
            inference_class="deterministic_inference",
            rule_id="field_write_depends_on_upstream_read",
            derived_from=sorted(entry["derived_from"]),
            evidence_refs=sorted(entry["evidence_refs"]),
            layer=str(entry["layer"]),
        )
        edges.append(edge)
        incoming_derive_nodes.setdefault(str(entry["target"]), []).extend(sorted(entry["derived_from"]))
        incoming_derive_evidence.setdefault(str(entry["target"]), []).extend(sorted(entry["evidence_refs"]))
        _append_inference(
            inferences,
            rule_id="field_write_depends_on_upstream_read",
            inference_class="deterministic_inference",
            derived_from=sorted(entry["derived_from"]),
            evidence_refs=sorted(entry["evidence_refs"]),
            output_refs=[edge_id],
        )

    for source_ref, context in sorted(field_context.items(), key=lambda item: item[0]):
        field_candidate = context["candidate"]
        field_node_id = context["node_id"]
        field_evidence = context["evidence"]
        origin_kind = _origin_kind_for_field(field_candidate)
        combined_tags = sorted(set(field_candidate.get("reader_tags", [])) | set(field_candidate.get("writer_tags", [])))
        if origin_kind is not None:
            state_class = "canonical_state"
            rule_id = "canonical_state_authoritative_origin"
            evidence_refs = field_evidence["writer"] or [field_evidence["field"]]
            derived_from = [field_evidence["field"]]
        elif field_node_id in incoming_derive_nodes:
            state_class = "derived_state"
            rule_id = "derived_state_requires_upstream"
            evidence_refs = sorted(set(incoming_derive_evidence.get(field_node_id, []))) or [field_evidence["field"]]
            derived_from = sorted(set(incoming_derive_nodes.get(field_node_id, [])))
        elif _field_is_ui_projection(index, field_candidate):
            state_class = "presentation_state"
            rule_id = "presentation_state_ui_projection"
            evidence_refs = field_evidence["reader"] or [field_evidence["field"]]
            derived_from = [field_evidence["field"]]
        else:
            state_class = "ephemeral_state"
            rule_id = "ephemeral_state_runtime_fallback"
            evidence_refs = field_evidence["writer"] or field_evidence["reader"] or [field_evidence["field"]]
            derived_from = [field_evidence["field"]]

        node = make_node(
            node_id=field_node_id,
            kind="field",
            state_class=state_class,
            label=source_ref,
            source_ref=source_ref,
            inference_class="deterministic_inference",
            rule_id=rule_id,
            derived_from=derived_from,
            evidence_refs=evidence_refs,
            origin_kind=origin_kind,
            tags=combined_tags,
            layer="state_relations",
        )
        nodes.append(node)
        _append_inference(
            inferences,
            rule_id=rule_id,
            inference_class="deterministic_inference",
            derived_from=derived_from,
            evidence_refs=evidence_refs,
            output_refs=[field_node_id],
        )

    field_nodes_by_ref = {node["source_ref"]: node for node in nodes if node.get("kind") == "field"}
    for source_ref, field_node in sorted(field_nodes_by_ref.items(), key=lambda item: item[0]):
        origin_kind = field_node.get("origin_kind")
        if not origin_kind:
            continue
        context = field_context[source_ref]
        boundary_source_ref = f"{source_ref}|{origin_kind}"
        boundary_node_id = stable_identity("node", "boundary", boundary_source_ref)
        boundary_evidence_refs = context["evidence"]["writer"] or [context["evidence"]["field"]]
        boundary_node = make_node(
            node_id=boundary_node_id,
            kind="boundary",
            state_class="boundary_source",
            label=origin_kind,
            source_ref=boundary_source_ref,
            inference_class="deterministic_inference",
            rule_id="canonical_state_authoritative_origin",
            derived_from=[context["evidence"]["field"]],
            evidence_refs=boundary_evidence_refs,
            boundary_kind=origin_kind,
            layer="boundary_relations",
        )
        nodes.append(boundary_node)
        _append_inference(
            inferences,
            rule_id="canonical_state_authoritative_origin",
            inference_class="deterministic_inference",
            derived_from=[context["evidence"]["field"]],
            evidence_refs=boundary_evidence_refs,
            output_refs=[boundary_node_id],
        )

        boundary_edge_id = stable_identity("edge", origin_kind, boundary_node_id, field_node["id"])
        boundary_edge_kind = "deserialize" if origin_kind in {"network_boundary", "serialization_boundary"} else "write"
        boundary_edge = make_edge(
            edge_id=boundary_edge_id,
            kind=boundary_edge_kind,
            source=boundary_node_id,
            target=field_node["id"],
            boundary_kind=origin_kind,
            inference_class="deterministic_inference",
            rule_id="canonical_state_authoritative_origin",
            derived_from=[boundary_node_id],
            evidence_refs=boundary_evidence_refs,
            layer="boundary_relations",
        )
        edges.append(boundary_edge)
        _append_inference(
            inferences,
            rule_id="canonical_state_authoritative_origin",
            inference_class="deterministic_inference",
            derived_from=[boundary_node_id],
            evidence_refs=boundary_evidence_refs,
            output_refs=[boundary_edge_id],
        )

    for field_node in sorted((node for node in nodes if node.get("kind") == "field"), key=lambda item: item["id"]):
        if field_node.get("state_class") == "presentation_state":
            contradiction_edge_id = stable_identity("edge", "projection_contradiction", field_node["id"])
            contradiction_edge = make_edge(
                edge_id=contradiction_edge_id,
                kind="contradiction",
                source=field_node["id"],
                target=field_node["id"],
                boundary_kind=None,
                inference_class="deterministic_inference",
                rule_id="projection_contradiction_ui_projection",
                derived_from=[field_node["id"]],
                evidence_refs=list(field_node.get("evidence_refs", [])),
                contradiction_kind="projection_contradiction",
                layer="contradiction_relations",
            )
            edges.append(contradiction_edge)
            _append_inference(
                inferences,
                rule_id="projection_contradiction_ui_projection",
                inference_class="deterministic_inference",
                derived_from=[field_node["id"]],
                evidence_refs=list(field_node.get("evidence_refs", [])),
                output_refs=[contradiction_edge_id],
            )

    for source_ref, context in sorted(field_context.items(), key=lambda item: item[0]):
        capability_kind, capability_methods = _capability_kind_for_field(index, context["candidate"])
        if capability_kind not in CAPABILITY_KINDS:
            continue
        field_node_id = context["node_id"]
        capability_source_ref = f"{source_ref}|capability:{capability_kind}"
        capability_node_id = stable_identity("node", "capability", capability_source_ref)
        capability_evidence_refs = []
        for method_sig in capability_methods:
            capability_evidence_refs.extend(context["evidence"]["reader_by_method"].get(method_sig, []))
            capability_evidence_refs.extend(context["evidence"]["writer_by_method"].get(method_sig, []))
        if not capability_evidence_refs:
            capability_evidence_refs = context["evidence"]["reader"] or context["evidence"]["writer"] or [context["evidence"]["field"]]

        capability_node = make_node(
            node_id=capability_node_id,
            kind="capability",
            state_class="capability_target",
            label=capability_kind,
            source_ref=capability_source_ref,
            inference_class="heuristic_hint",
            rule_id="capability_link_from_gate_reader",
            derived_from=[field_node_id],
            evidence_refs=capability_evidence_refs,
            capability_kind=capability_kind,
            layer="capability_links",
        )
        nodes.append(capability_node)
        _append_inference(
            inferences,
            rule_id="capability_link_from_gate_reader",
            inference_class="heuristic_hint",
            derived_from=[field_node_id],
            evidence_refs=capability_evidence_refs,
            output_refs=[capability_node_id],
        )

        capability_edge_id = stable_identity("edge", "capability_link", field_node_id, capability_node_id)
        capability_edge = make_edge(
            edge_id=capability_edge_id,
            kind="capability_link",
            source=field_node_id,
            target=capability_node_id,
            boundary_kind=None,
            inference_class="heuristic_hint",
            rule_id="capability_link_from_gate_reader",
            derived_from=[field_node_id],
            evidence_refs=capability_evidence_refs,
            layer="capability_links",
        )
        edges.append(capability_edge)
        _append_inference(
            inferences,
            rule_id="capability_link_from_gate_reader",
            inference_class="heuristic_hint",
            derived_from=[field_node_id],
            evidence_refs=capability_evidence_refs,
            output_refs=[capability_edge_id],
        )

    artifact["nodes"] = nodes
    artifact["edges"] = edges
    artifact["evidence"] = evidence
    artifact["inferences"] = inferences
    artifact["compatibility_views"] = {
        "candidate_models": list(candidate_models),
        "candidate_state_fields": list(compatibility_fields),
    }
    artifact["cycle_summary"] = summarize_cycles(nodes, edges)

    state_class_counts = Counter(
        node.get("state_class")
        for node in nodes
        if node.get("kind") == "field"
    )
    layer_counts = Counter(
        edge.get("layer")
        for edge in edges
        if edge.get("layer")
    )
    artifact["summary"] = {
        "focus_hint": focus_hint,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "evidence_count": len(evidence),
        "inference_count": len(inferences),
        "state_class_counts": dict(sorted(state_class_counts.items())),
        "layer_counts": dict(sorted(layer_counts.items())),
        "cycle_count": int(artifact["cycle_summary"].get("cycle_count", 0)),
    }

    artifact = canonicalize_artifact(artifact)
    validation_errors = validate_artifact(artifact)
    return {
        "artifact": artifact,
        "validation_errors": validation_errors,
    }


def recover_hidden_state_model(index, *, focus_hint: str = "", max_candidates: int = 30, progress_callback=None) -> dict[str, Any]:
    """Recover likely state models and high-value hidden fields.

    Args:
        index: Loaded SmaliIndex.
        focus_hint: Optional hint such as premium, auth, subscription, license.
        max_candidates: Maximum number of top field candidates to return.
    """
    if index is None:
        return {"success": False, "error": "SmaliIndex is required"}

    focus_terms = [term.strip().lower() for term in focus_hint.split(",") if term.strip()]
    candidate_models: dict[str, dict[str, Any]] = {}
    total_classes = len(index.classes)
    candidate_scan_interval = max(1, total_classes // 12) if total_classes > 0 else 1
    all_methods = _sorted_methods(index)

    def _emit_progress(pct: float, detail: str) -> None:
        if progress_callback is not None:
            progress_callback(pct, detail)

    _emit_progress(4, f"Scanning {total_classes} classes for candidate state models")

    for class_idx, smali_class in enumerate(_sorted_classes(index), start=1):
        if _is_third_party_path(smali_class.file_path):
            continue
        score, evidence = _candidate_class_score(smali_class)
        if focus_terms and any(term in _class_blob(smali_class) for term in focus_terms):
            score += 4
            evidence.append(f"focus hint match: {focus_hint}")
        if score >= 8:
            candidate_models[smali_class.name] = {
                "class": smali_class.name,
                "file": smali_class.file_path,
                "score": score,
                "evidence": evidence[:6],
                "field_count": len(smali_class.fields),
                "method_count": len(smali_class.methods),
            }

        if class_idx == total_classes or class_idx % candidate_scan_interval == 0:
            scan_pct = 4 + (class_idx / max(total_classes, 1)) * 24
            _emit_progress(
                scan_pct,
                f"Model scan: {class_idx}/{total_classes} classes | {len(candidate_models)} candidate models",
            )

    field_candidates: list[dict[str, Any]] = []
    writer_chains: list[dict[str, Any]] = []
    reader_chains: list[dict[str, Any]] = []
    method_relations: list[dict[str, Any]] = []
    total_models = len(candidate_models)

    if total_models == 0:
        _emit_progress(92, "No strong candidate state models found; ranking empty result set")

    model_scan_interval = max(1, total_models // 10) if total_models > 0 else 1
    _emit_progress(30, f"Analyzing fields across {total_models} candidate models")

    for model_idx, (class_name, model_info) in enumerate(sorted(candidate_models.items(), key=lambda item: item[0]), start=1):
        smali_class = index.get_class(class_name)
        if smali_class is None:
            continue

        usage_map: dict[str, dict[str, Any]] = {}
        for field in sorted(smali_class.fields, key=lambda item: item.name):
            usage_map[field.name] = {
                "field_name": field.name,
                "type": field.type,
                "read_count": 0,
                "write_count": 0,
                "reader_samples": [],
                "writer_samples": [],
                "reader_tags": set(),
                "writer_tags": set(),
            }

        target_fields = {f"{class_name}->{field.name}": field.name for field in sorted(smali_class.fields, key=lambda item: item.name)}
        if not target_fields:
            continue

        for method in all_methods:
            owner_class = method.full_signature.split("->", 1)[0] if "->" in method.full_signature else ""
            owner_info = index.get_class(owner_class)
            if owner_info is not None and _is_third_party_path(owner_info.file_path):
                continue
            method_tags = _method_context_tags(method)
            method_reads: set[str] = set()
            method_writes: set[str] = set()

            for instr in method.instructions:
                field_name = target_fields.get(_normalize_field_ref(instr.target_field))
                if not field_name:
                    continue
                entry = {
                    "method": method.full_signature,
                    "file": owner_info.file_path if owner_info is not None else "",
                    "line": instr.line,
                    "opcode": instr.opcode,
                    "tags": method_tags,
                }
                if instr.opcode.startswith(("iput", "sput")):
                    usage_map[field_name]["write_count"] += 1
                    usage_map[field_name]["writer_tags"].update(method_tags)
                    method_writes.add(field_name)
                    if len(usage_map[field_name]["writer_samples"]) < 8:
                        usage_map[field_name]["writer_samples"].append(entry)
                else:
                    usage_map[field_name]["read_count"] += 1
                    usage_map[field_name]["reader_tags"].update(method_tags)
                    method_reads.add(field_name)
                    if len(usage_map[field_name]["reader_samples"]) < 8:
                        usage_map[field_name]["reader_samples"].append(entry)

            if method_reads or method_writes:
                method_relations.append({
                    "class": class_name,
                    "method": method.full_signature,
                    "file": owner_info.file_path if owner_info is not None else "",
                    "tags": sorted(method_tags),
                    "reads": sorted(method_reads),
                    "writes": sorted(method_writes),
                    "has_branch": any(instr.is_branch for instr in method.instructions),
                    "returns_boolean": method.return_type == "Z",
                })

        for field in sorted(smali_class.fields, key=lambda item: item.name):
            usage = usage_map[field.name]
            semantic, suggested_value, confidence, evidence = _semantic_guess(field.type, usage, focus_terms)
            if usage["read_count"] == 0 and usage["write_count"] == 0:
                continue

            exact_value, exact_value_candidates, value_origin, safe_for_auto_override = _resolve_exact_value_candidates(
                index,
                class_name=class_name,
                field_name=field.name,
                field_type=field.type,
                semantic=semantic,
                usage=usage,
                focus_terms=focus_terms,
            )

            field_score = (
                model_info["score"]
                + usage["read_count"] * 1.5
                + usage["write_count"] * 1.8
                + len(usage["reader_tags"]) * 2
                + len(usage["writer_tags"]) * 2
            )

            field_candidates.append({
                "class": class_name,
                "file": smali_class.file_path,
                "field": field.name,
                "type": field.type,
                "semantic_guess": semantic,
                "likely_unlocked_value": exact_value,
                "suggested_unlocked_value": suggested_value,
                "value_origin": value_origin,
                "safe_for_auto_override": safe_for_auto_override,
                "exact_value_candidates": exact_value_candidates,
                "confidence": confidence,
                "score": round(field_score, 2),
                "evidence": evidence[:6],
                "read_count": usage["read_count"],
                "write_count": usage["write_count"],
                "reader_tags": sorted(usage["reader_tags"]),
                "writer_tags": sorted(usage["writer_tags"]),
                "reader_samples": usage["reader_samples"],
                "writer_samples": usage["writer_samples"],
                "recommended_patch_strategy": (
                    "constructor_or_response_override"
                    if ("serialization" in usage["writer_tags"] or "network" in usage["writer_tags"])
                    else "constructor_or_runtime_override"
                ),
            })

            for sample in usage["writer_samples"][:3]:
                writer_chains.append({
                    "class": class_name,
                    "field": field.name,
                    "writer": sample["method"],
                    "line": sample["line"],
                    "tags": sample["tags"],
                })
            for sample in usage["reader_samples"][:3]:
                reader_chains.append({
                    "class": class_name,
                    "field": field.name,
                    "reader": sample["method"],
                    "line": sample["line"],
                    "tags": sample["tags"],
                })

        if model_idx == total_models or model_idx % model_scan_interval == 0:
            field_pct = 30 + (model_idx / max(total_models, 1)) * 58
            _emit_progress(
                field_pct,
                f"Field analysis: {model_idx}/{total_models} models | {len(field_candidates)} field candidates",
            )

    _emit_progress(92, f"Ranking {len(field_candidates)} field candidates across {len(candidate_models)} models")
    field_candidates.sort(key=lambda item: (-item["score"], -item["confidence"], item["class"], item["field"]))
    writer_chains.sort(key=lambda item: (item["class"], item["field"], item["writer"]))
    reader_chains.sort(key=lambda item: (item["class"], item["field"], item["reader"]))

    top_semantics = Counter(item["semantic_guess"] for item in field_candidates)
    ranked_models = sorted(candidate_models.values(), key=lambda item: (-item["score"], item["class"]))[:15]
    compatibility_fields = field_candidates[:max_candidates]

    semantic_core_result = _build_semantic_core_artifact(
        index,
        focus_hint=focus_hint,
        candidate_models=ranked_models,
        field_candidates=field_candidates,
        compatibility_fields=compatibility_fields,
        method_relations=method_relations,
    )
    validation_errors = semantic_core_result["validation_errors"]
    if validation_errors:
        return {
            "success": False,
            "error": "Semantic core invariant validation failed",
            "validation_errors": validation_errors,
            "focus_hint": focus_hint,
            "candidate_models": ranked_models,
            "candidate_state_fields": compatibility_fields,
            "writer_chains": writer_chains[:40],
            "reader_chains": reader_chains[:40],
        }
    artifact = semantic_core_result["artifact"]

    _emit_progress(
        100,
        f"recover_hidden_state_model complete: {len(candidate_models)} models, {len(field_candidates)} field candidates",
    )

    return {
        "success": True,
        "focus_hint": focus_hint,
        "semantic_schema_version": SEMANTIC_SCHEMA_VERSION,
        "artifact_kind": artifact["artifact_kind"],
        "nodes": artifact["nodes"],
        "edges": artifact["edges"],
        "evidence": artifact["evidence"],
        "inferences": artifact["inferences"],
        "compatibility_views": artifact["compatibility_views"],
        "rule_manifest": artifact["rule_manifest"],
        "cycle_summary": artifact["cycle_summary"],
        "candidate_models": ranked_models,
        "candidate_state_fields": compatibility_fields,
        "writer_chains": writer_chains[:40],
        "reader_chains": reader_chains[:40],
        "summary": {
            "model_count": len(candidate_models),
            "field_candidates": len(field_candidates),
            "top_semantics": dict(top_semantics.most_common(10)),
            "semantic_node_count": len(artifact["nodes"]),
            "semantic_edge_count": len(artifact["edges"]),
            "semantic_evidence_count": len(artifact["evidence"]),
            "semantic_inference_count": len(artifact["inferences"]),
            "semantic_cycle_count": int(artifact["cycle_summary"].get("cycle_count", 0)),
        },
    }