"""Semantic architecture mapper for APK applications.

Builds a role-oriented architecture view over the existing SmaliIndex so the
agent can reason about hardened, obfuscated apps without relying on obvious
keywords alone.

The goal is to identify the *shape* of the app:
  - entry points and bootstraps
  - network / serialization boundaries
  - state models and state stores
  - UI gate controllers
  - security guard clusters
  - dynamic/native boundaries
  - billing / premium infrastructure
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from apk_agent.tools.advanced_search import _is_third_party_path


_NETWORK_HINTS = (
    "lokhttp3/",
    "lretrofit2/",
    "httpurlconnection",
    "requestbody",
    "responsebody",
    "websocket",
    "apollo",
    "ktor",
)

_SERIALIZATION_HINTS = (
    "gson",
    "moshi",
    "jackson",
    "org/json",
    "jsonobject",
    "jsonarray",
    "kotlinx/serialization",
    "fromjson",
    "tojson",
    "deserialize",
    "serialize",
    "parse",
)

_STORE_HINTS = (
    "sharedpreferences",
    "datastore",
    "sqlitedatabase",
    "room",
    "cursor",
    "realm",
    "hawk",
)

_SECURITY_HINTS = (
    "root",
    "tamper",
    "signature",
    "debug",
    "emulator",
    "pairip",
    "integrity",
    "attestation",
    "certificate",
    "ssl",
    "hostnameverifier",
    "trustmanager",
    "pinning",
)

_DYNAMIC_HINTS = (
    "dexclassloader",
    "pathclassloader",
    "inmemorydexclassloader",
    "class.forname",
    "method.invoke",
    "proxy",
    "system.loadlibrary",
    "system.load",
    "jni_onload",
    "native",
)

_BILLING_HINTS = (
    "billingclient",
    "querypurchases",
    "launchbillingflow",
    "purchase",
    "subscription",
    "entitlement",
    "revenuecat",
    "qonversion",
    "premium",
    "license",
)

_UI_HINTS = (
    "activity",
    "fragment",
    "dialog",
    "bottomsheet",
    "setvisibility",
    "menu",
    "viewbinding",
    "compose",
    "recyclerview",
    "alertdialog",
    "paywall",
    "upgrade",
)


def _class_blob(smali_class) -> str:
    parts: list[str] = [
        smali_class.name,
        smali_class.super_class,
        smali_class.source_file,
        smali_class.file_path,
        " ".join(smali_class.interfaces),
    ]
    for method in smali_class.methods[:80]:
        parts.append(method.name)
        parts.append(method.signature)
        if method.api_calls:
            parts.append(" ".join(method.api_calls[:40]))
        if method.string_constants:
            parts.append(" ".join(method.string_constants[:20]))
    return " ".join(p for p in parts if p).lower()


def _push_role(
    role_scores: dict[str, dict[str, int]],
    role_evidence: dict[str, dict[str, list[str]]],
    class_name: str,
    role: str,
    score: int,
    evidence: str,
) -> None:
    role_scores[class_name][role] += score
    if evidence and evidence not in role_evidence[class_name][role]:
        role_evidence[class_name][role].append(evidence)


def _looks_like_state_model(smali_class, blob: str) -> tuple[int, list[str]]:
    score = 0
    evidence: list[str] = []

    field_count = len(smali_class.fields)
    method_count = len(smali_class.methods)
    super_lower = (smali_class.super_class or "").lower()

    if 2 <= field_count <= 40:
        score += 4
        evidence.append(f"{field_count} fields")
    if field_count >= 6:
        score += 3
        evidence.append("high field density")
    if method_count <= 30:
        score += 2
        evidence.append("compact method surface")
    if all(token not in super_lower for token in ("activity", "fragment", "service", "receiver", "view")):
        score += 2
        evidence.append("not a UI/component superclass")
    if any(hint in blob for hint in _SERIALIZATION_HINTS + _BILLING_HINTS):
        score += 4
        evidence.append("serialization/billing context")
    if any(m.name.startswith(("get", "set", "is")) for m in smali_class.methods):
        score += 2
        evidence.append("getter/setter style methods")

    return score, evidence


def map_semantic_architecture(index, *, focus_hint: str = "", max_per_role: int = 12, progress_callback=None) -> dict[str, Any]:
    """Infer the application's semantic architecture from SmaliIndex.

    Args:
        index: Loaded SmaliIndex.
        focus_hint: Optional user/domain hint (premium, subscription, auth, etc.).
        max_per_role: Maximum number of classes returned per role.
    """
    if index is None:
        return {"success": False, "error": "SmaliIndex is required"}

    def _emit_progress(pct: float, detail: str) -> None:
        if progress_callback is not None:
            progress_callback(pct, detail)

    focus_terms = [term.strip().lower() for term in focus_hint.split(",") if term.strip()]
    role_scores: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    role_evidence: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    state_edges: list[dict[str, str]] = []
    entry_edges: list[dict[str, str]] = []

    candidate_state_models: set[str] = set()

    classes_to_scan = [
        smali_class
        for smali_class in index.classes.values()
        if not _is_third_party_path(smali_class.file_path)
    ]
    total_classes = len(classes_to_scan)
    scan_interval = max(1, total_classes // 12) if total_classes > 0 else 1
    link_interval = max(1, total_classes // 10) if total_classes > 0 else 1

    _emit_progress(4, f"Scanning {total_classes} classes for semantic architecture roles")

    for class_idx, smali_class in enumerate(classes_to_scan, start=1):

        blob = _class_blob(smali_class)
        cls_name = smali_class.name
        super_lower = (smali_class.super_class or "").lower()

        if "application;" in super_lower or "activity;" in super_lower or "fragment;" in super_lower or "service;" in super_lower or "receiver;" in super_lower or "contentprovider;" in super_lower:
            _push_role(role_scores, role_evidence, cls_name, "entry_points", 6, f"component superclass: {smali_class.super_class}")

        method_names = {m.name.lower() for m in smali_class.methods}
        if {"oncreate", "onresume", "onstart", "onreceive", "attachbasecontext"} & method_names:
            _push_role(role_scores, role_evidence, cls_name, "entry_points", 4, "lifecycle methods present")

        if any(hint in blob for hint in _NETWORK_HINTS):
            _push_role(role_scores, role_evidence, cls_name, "network_layer", 6, "network API usage")
        if any(hint in blob for hint in _SERIALIZATION_HINTS):
            _push_role(role_scores, role_evidence, cls_name, "serialization_layer", 5, "serialization/parsing hints")
        if any(hint in blob for hint in _STORE_HINTS):
            _push_role(role_scores, role_evidence, cls_name, "state_stores", 6, "persistent state APIs")
        if any(hint in blob for hint in _SECURITY_HINTS):
            _push_role(role_scores, role_evidence, cls_name, "security_guards", 6, "security/protection indicators")
        if any(hint in blob for hint in _DYNAMIC_HINTS):
            _push_role(role_scores, role_evidence, cls_name, "dynamic_native_boundaries", 6, "dynamic/native indicators")
        if any(hint in blob for hint in _BILLING_HINTS):
            _push_role(role_scores, role_evidence, cls_name, "billing_flow", 6, "billing/premium indicators")
        if any(hint in blob for hint in _UI_HINTS):
            _push_role(role_scores, role_evidence, cls_name, "ui_gate_controllers", 4, "UI control indicators")

        model_score, model_evidence = _looks_like_state_model(smali_class, blob)
        if model_score > 0:
            for evidence in model_evidence:
                _push_role(role_scores, role_evidence, cls_name, "state_models", model_score // max(len(model_evidence), 1), evidence)
        if model_score >= 8:
            candidate_state_models.add(cls_name)

        if focus_terms and any(term in blob for term in focus_terms):
            for role in (
                "network_layer",
                "serialization_layer",
                "state_models",
                "state_stores",
                "ui_gate_controllers",
                "security_guards",
                "billing_flow",
            ):
                _push_role(role_scores, role_evidence, cls_name, role, 2, f"focus hint match: {focus_hint}")

        if class_idx == total_classes or class_idx % scan_interval == 0:
            scan_pct = 4 + (class_idx / max(total_classes, 1)) * 54
            _emit_progress(
                scan_pct,
                f"Architecture scan: {class_idx}/{total_classes} classes | {len(role_scores)} scored classes",
            )

    _emit_progress(60, f"Linking state and entry boundaries across {total_classes} classes")

    for class_idx, smali_class in enumerate(classes_to_scan, start=1):

        class_role_map = role_scores.get(smali_class.name, {})
        if not class_role_map:
            continue

        for method in smali_class.methods:
            for ref_class in [method.return_type, *method.param_types]:
                if ref_class in candidate_state_models and smali_class.name != ref_class:
                    if class_role_map.get("network_layer", 0) > 0 or class_role_map.get("serialization_layer", 0) > 0:
                        state_edges.append({
                            "from_class": smali_class.name,
                            "from_method": method.full_signature,
                            "to_state_class": ref_class,
                            "relation": "returns_or_accepts_state_model",
                        })
                    if class_role_map.get("entry_points", 0) > 0:
                        entry_edges.append({
                            "from_class": smali_class.name,
                            "from_method": method.full_signature,
                            "to_state_class": ref_class,
                            "relation": "entry_touches_state_model",
                        })

            for api_call in method.api_calls:
                if any(term in api_call.lower() for term in _BILLING_HINTS):
                    _push_role(role_scores, role_evidence, smali_class.name, "billing_flow", 2, f"billing API call: {api_call}")
                if any(term in api_call.lower() for term in _STORE_HINTS):
                    _push_role(role_scores, role_evidence, smali_class.name, "state_stores", 2, f"store API call: {api_call}")

        if class_idx == total_classes or class_idx % link_interval == 0:
            link_pct = 60 + (class_idx / max(total_classes, 1)) * 28
            _emit_progress(
                link_pct,
                f"Boundary linking: {class_idx}/{total_classes} classes | {len(state_edges)} state edges, {len(entry_edges)} entry edges",
            )

    architecture_layers: dict[str, list[dict[str, Any]]] = {}
    role_overlap: list[dict[str, Any]] = []

    _emit_progress(90, "Ranking architecture layers")

    for role in (
        "entry_points",
        "network_layer",
        "serialization_layer",
        "state_models",
        "state_stores",
        "ui_gate_controllers",
        "security_guards",
        "dynamic_native_boundaries",
        "billing_flow",
    ):
        ranked: list[dict[str, Any]] = []
        for class_name, score_map in role_scores.items():
            score = score_map.get(role, 0)
            if score <= 0:
                continue
            ranked.append({
                "class": class_name,
                "file": index.classes[class_name].file_path if class_name in index.classes else "",
                "score": score,
                "evidence": role_evidence[class_name][role][:6],
                "field_count": len(index.classes[class_name].fields) if class_name in index.classes else 0,
                "method_count": len(index.classes[class_name].methods) if class_name in index.classes else 0,
            })
        ranked.sort(key=lambda item: (-item["score"], item["class"]))
        architecture_layers[role] = ranked[:max_per_role]

    for class_name, score_map in role_scores.items():
        active_roles = [role for role, score in score_map.items() if score >= 5]
        if len(active_roles) >= 2:
            role_overlap.append({
                "class": class_name,
                "roles": sorted(active_roles),
                "score_total": sum(score_map[r] for r in active_roles),
            })
    role_overlap.sort(key=lambda item: (-item["score_total"], item["class"]))

    high_value_components: list[dict[str, Any]] = []
    for class_name, score_map in role_scores.items():
        total = sum(score_map.values())
        if total <= 0:
            continue
        high_value_components.append({
            "class": class_name,
            "file": index.classes[class_name].file_path if class_name in index.classes else "",
            "score_total": total,
            "dominant_roles": sorted(score_map, key=score_map.get, reverse=True)[:3],
        })
    high_value_components.sort(key=lambda item: (-item["score_total"], item["class"]))

    recommendations: list[str] = []
    _emit_progress(96, "Computing architecture overlaps and next targets")
    if architecture_layers["billing_flow"]:
        recommendations.append("Start from billing_flow classes, then trace into state_models and ui_gate_controllers.")
    if architecture_layers["security_guards"]:
        recommendations.append("Profile security_guards before patching to avoid late revalidation or anti-tamper rollback.")
    if architecture_layers["network_layer"] and architecture_layers["state_models"]:
        recommendations.append("Use network_layer + serialization_layer + state_models as the primary response-mutation boundary.")
    if architecture_layers["dynamic_native_boundaries"]:
        recommendations.append("Expect static patches to be incomplete unless dynamic/native boundaries are mapped and guarded.")

    result = {
        "success": True,
        "focus_hint": focus_hint,
        "total_classes_analyzed": total_classes,
        "architecture_layers": architecture_layers,
        "high_value_components": high_value_components[:20],
        "role_overlaps": role_overlap[:20],
        "network_to_state_paths": state_edges[:30],
        "entry_to_state_paths": entry_edges[:30],
        "recommended_next_targets": recommendations,
    }
    _emit_progress(
        100,
        f"Semantic architecture complete: {len(high_value_components)} high-value components across {total_classes} classes",
    )
    return result