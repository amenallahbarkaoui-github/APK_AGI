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


_NETWORK_HINTS = ("lokhttp3/", "lretrofit2/", "httpurlconnection", "requestbody", "responsebody", "apollo", "ktor")
_SERIALIZATION_HINTS = ("gson", "moshi", "jackson", "org/json", "jsonobject", "jsonarray", "fromjson", "tojson", "parse", "deserialize", "serialize")
_STORE_HINTS = ("sharedpreferences", "datastore", "sqlitedatabase", "room", "realm", "cursor")
_BILLING_HINTS = ("billingclient", "purchase", "subscription", "premium", "license", "entitlement", "revenuecat", "qonversion")
_UI_HINTS = ("dialog", "activity", "fragment", "view", "paywall", "upgrade", "menu", "visibility")
_TIME_HINTS = ("time", "timestamp", "expire", "expiry", "renew", "valid", "until", "deadline", "due")
_STATE_HINTS = ("active", "enabled", "premium", "paid", "trial", "locked", "subscribed", "plan", "tier", "role", "pro", "vip")
_POSITIVE_VALUE_HINTS = ("premium", "pro", "vip", "svip", "paid", "gold", "diamond", "elite", "lifetime", "active", "valid", "subscribed", "owned", "unlock")
_NEGATIVE_VALUE_HINTS = ("free", "trial", "basic", "lite", "demo", "guest", "locked", "expired", "inactive", "invalid", "none")


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


def recover_hidden_state_model(index, *, focus_hint: str = "", max_candidates: int = 30) -> dict[str, Any]:
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

    for smali_class in index.classes.values():
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

    field_candidates: list[dict[str, Any]] = []
    writer_chains: list[dict[str, Any]] = []
    reader_chains: list[dict[str, Any]] = []

    for class_name, model_info in candidate_models.items():
        smali_class = index.get_class(class_name)
        if smali_class is None:
            continue

        usage_map: dict[str, dict[str, Any]] = {}
        for field in smali_class.fields:
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

        target_fields = {f"{class_name}->{field.name}": field.name for field in smali_class.fields}
        if not target_fields:
            continue

        for method in index.methods.values():
            owner_class = method.full_signature.split("->", 1)[0] if "->" in method.full_signature else ""
            owner_info = index.get_class(owner_class)
            if owner_info is not None and _is_third_party_path(owner_info.file_path):
                continue
            method_tags = _method_context_tags(method)

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
                    if len(usage_map[field_name]["writer_samples"]) < 8:
                        usage_map[field_name]["writer_samples"].append(entry)
                else:
                    usage_map[field_name]["read_count"] += 1
                    usage_map[field_name]["reader_tags"].update(method_tags)
                    if len(usage_map[field_name]["reader_samples"]) < 8:
                        usage_map[field_name]["reader_samples"].append(entry)

        for field in smali_class.fields:
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

    field_candidates.sort(key=lambda item: (-item["score"], -item["confidence"], item["class"], item["field"]))
    writer_chains.sort(key=lambda item: (item["class"], item["field"], item["writer"]))
    reader_chains.sort(key=lambda item: (item["class"], item["field"], item["reader"]))

    top_semantics = Counter(item["semantic_guess"] for item in field_candidates)

    return {
        "success": True,
        "focus_hint": focus_hint,
        "candidate_models": sorted(candidate_models.values(), key=lambda item: (-item["score"], item["class"]))[:15],
        "candidate_state_fields": field_candidates[:max_candidates],
        "writer_chains": writer_chains[:40],
        "reader_chains": reader_chains[:40],
        "summary": {
            "model_count": len(candidate_models),
            "field_candidates": len(field_candidates),
            "top_semantics": dict(top_semantics.most_common(10)),
        },
    }