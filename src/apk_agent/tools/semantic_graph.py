"""Graph-aware semantic analysis helpers built on top of SmaliIndex + code graph.

These helpers do not replace the legacy graph or search tools. They provide an
extra semantic/context-aware layer that scores likely enforcement methods and
summarizes a method as a patchable slice.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import TYPE_CHECKING, Any

from apk_agent.tools.advanced_search import _is_third_party_path
from apk_agent.tools.semantic_cache import get_cached_architecture_context

if TYPE_CHECKING:
    from apk_agent.tools.smali_ir import SmaliClass, SmaliIndex, SmaliMethod


_BILLING_HINTS = (
    "billingclient",
    "querypurchases",
    "launchbillingflow",
    "purchase",
    "revenuecat",
    "qonversion",
    "productdetails",
    "sku",
    "purchasehistory",
    "acknowledgepurchase",
    "consumeasync",
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
    "bundle",
    "parcel",
)

_CALLER_UI_HINTS = (
    "activity",
    "fragment",
    "dialog",
    "bottomsheet",
    "menu",
    "adapter",
    "onclick",
    "viewmodel",
    "compose",
    "setvisibility",
)

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

_FOCUS_SYNONYMS = {
    "premium": {"pro", "paid", "vip", "subscription", "license", "unlock", "member"},
    "license": {"licensed", "activation", "premium", "subscription"},
    "subscription": {"premium", "trial", "billing", "purchase", "entitlement"},
    "billing": {"purchase", "subscription", "entitlement", "premium"},
    "ads": {"ad", "banner", "interstitial", "rewarded", "paywall"},
}


def semantic_method_slice(
    index: "SmaliIndex",
    class_name: str,
    method_name: str,
    *,
    graph=None,
    max_depth: int = 2,
) -> dict[str, Any]:
    """Build a context-aware semantic slice for one method."""
    cls = _match_class(index, class_name)
    if cls is None:
        return {"success": False, "error": f"Class not found: {class_name}"}

    method = _match_method(cls, method_name)
    if method is None:
        return {"success": False, "error": f"Method not found in {cls.name}: {method_name}"}

    if not method.basic_blocks:
        method.build_cfg()

    graph_sig = f"{cls.name}->{method.name}"
    direct_callers = _direct_callers(graph, graph_sig) if graph is not None else []
    direct_callees = _direct_callees(graph, graph_sig) if graph is not None else []

    field_accesses = [instr.target_field for instr in method.instructions if instr.is_field_access and instr.target_field]
    branch_opcodes = [instr.opcode for instr in method.instructions if instr.is_branch]
    api_calls = list(dict.fromkeys(method.api_calls))
    api_categories = _classify_api_calls(api_calls)
    string_constants = list(dict.fromkeys(method.string_constants))
    branch_blocks = [bb for bb in method.basic_blocks if len(bb.successors) > 1]

    return {
        "success": True,
        "class": cls.name,
        "file": cls.file_path,
        "method": {
            "name": method.name,
            "signature": method.signature,
            "full_signature": method.full_signature,
            "return_type": method.return_type,
            "param_types": method.param_types,
            "category": method.category,
            "complexity": method.complexity,
            "instruction_count": len(method.instructions),
        },
        "guard_profile": {
            "is_gate_like": _is_gate_like(method, branch_blocks, field_accesses),
            "branch_count": len(branch_opcodes),
            "field_access_count": len(field_accesses),
            "field_accesses": field_accesses[:20],
            "string_constants": string_constants[:20],
            "api_categories": api_categories,
            "api_calls": api_calls[:25],
            "guard_signals": _build_guard_signals(method, branch_blocks, field_accesses, api_categories),
        },
        "cfg": {
            "block_count": len(method.basic_blocks),
            "entry_blocks": [bb.id for bb in method.basic_blocks if bb.is_entry],
            "exit_blocks": [bb.id for bb in method.basic_blocks if bb.is_exit],
            "branch_blocks": [
                {
                    "id": bb.id,
                    "start_idx": bb.start_idx,
                    "end_idx": bb.end_idx,
                    "successors": bb.successors,
                }
                for bb in branch_blocks[:12]
            ],
        },
        "context": {
            "direct_callers": direct_callers[:20],
            "direct_callees": direct_callees[:20],
            "max_depth_requested": max_depth,
            "caller_count": len(direct_callers),
            "callee_count": len(direct_callees),
        },
        "patch_hints": _build_patch_hints(method, direct_callers, api_categories, field_accesses),
    }


def find_enforcement_surfaces(
    index: "SmaliIndex",
    feature: str,
    *,
    graph=None,
    extra_keywords: str = "",
    max_results: int = 25,
) -> dict[str, Any]:
    """Find likely enforcement methods using architecture/state/revalidation context.

    `feature` and `extra_keywords` are treated as optional focus hints only.
    They may help narrow or tie-break results, but they do not gate discovery.
    The ranking is architecture-first so it still works when business strings and
    method/class names are obfuscated.
    """
    focus_terms = _focus_terms(feature, extra_keywords)
    architecture_context = _build_architecture_context(index, focus_terms)

    candidates: list[dict[str, Any]] = []
    role_counts: Counter[str] = Counter()

    for method in index.methods.values():
        class_name = method.full_signature.split("->", 1)[0] if "->" in method.full_signature else ""
        cls = index.get_class(class_name)
        file_path = cls.file_path if cls else ""

        field_accesses = [instr.target_field for instr in method.instructions if instr.is_field_access and instr.target_field]
        branch_count = sum(1 for instr in method.instructions if instr.is_branch)
        field_count = sum(1 for instr in method.instructions if instr.is_field_access)
        field_write_count = _field_write_count(method)
        api_categories = _classify_api_calls(method.api_calls)

        graph_sig = _graph_method_signature(method.full_signature)
        direct_callers = _direct_callers(graph, graph_sig) if graph is not None else []
        direct_callees = _direct_callees(graph, graph_sig) if graph is not None else []
        graph_role_contexts = _graph_role_contexts(direct_callers, direct_callees, architecture_context)
        structure = _method_architecture_profile(
            method,
            class_name,
            file_path,
            field_accesses,
            field_write_count,
            api_categories,
            architecture_context,
        )
        focus_hits = _focus_hits(
            [
                class_name,
                file_path,
                cls.source_file if cls else "",
                method.name,
                method.full_signature,
                *method.api_calls,
                *method.string_constants,
                *field_accesses,
            ],
            focus_terms,
        )

        if not _is_structural_enforcement_candidate(
            method,
            structure,
            branch_count,
            field_count,
            field_write_count,
            direct_callers,
            direct_callees,
        ):
            continue

        surface_role = _surface_role(method, branch_count, field_write_count, api_categories, structure, graph_role_contexts)
        third_party_path = bool(file_path and _is_third_party_path(file_path))
        score, reasons = _score_method(
            method,
            branch_count,
            field_count,
            field_write_count,
            api_categories,
            direct_callers,
            direct_callees,
            graph_role_contexts,
            third_party_path,
            surface_role,
            structure,
            focus_hits,
        )

        if score < 24:
            continue

        role_counts[surface_role] += 1
        candidates.append({
            "score": score,
            "reasons": reasons,
            "surface_role": surface_role,
            "class": class_name,
            "file": file_path,
            "method": method.full_signature,
            "return_type": method.return_type,
            "category": method.category,
            "focus_matches": focus_hits[:8],
            "api_categories": api_categories,
            "caller_count": len(direct_callers),
            "callee_count": len(direct_callees),
            "graph_role_contexts": graph_role_contexts,
            "owner_roles": structure["owner_roles"],
            "architecture_signals": structure["signals"][:10],
            "state_field_hits": structure["state_field_hits"][:8],
            "state_field_semantics": structure["state_field_semantics"][:8],
            "direct_callers": direct_callers[:8],
            "direct_callees": direct_callees[:8],
            "branch_count": branch_count,
            "field_access_count": field_count,
            "field_write_count": field_write_count,
            "guard_cluster_match": structure["guard_cluster_match"],
            "revalidation_loop_owner": structure["revalidation_loop_owner"],
            "third_party_path": third_party_path,
        })

    candidates.sort(key=lambda item: (-item["score"], item["method"]))
    top = candidates[:max_results]
    return {
        "success": True,
        "feature": feature,
        "discovery_mode": "architecture_first",
        "focus_terms": sorted(focus_terms),
        "keywords": sorted(focus_terms),
        "architecture_summary": architecture_context["summary"],
        "total_candidates": len(candidates),
        "role_summary": dict(role_counts),
        "surfaces": top,
        "next_step": (
            "Start from the highest-scoring app-owned gate_method or revalidation_boundary. "
            "If architecture_signals mention recovered state fields or overwrite loops, patch the response/state-writer "
            "boundary first, then inspect downstream accessors with semantic_method_slice before rebuilding."
        ),
    }


def _match_class(index: "SmaliIndex", class_name: str) -> "SmaliClass | None":
    exact = index.get_class(class_name)
    if exact is not None:
        return exact
    matches = index.search_classes(class_name)
    return matches[0] if matches else None


def _match_method(cls: "SmaliClass", method_name: str) -> "SmaliMethod | None":
    for method in cls.methods:
        if method_name == method.name or method_name in method.full_signature or method_name in method.signature:
            return method
    return None


def _graph_method_signature(full_signature: str) -> str:
    return full_signature.split("(", 1)[0] if "(" in full_signature else full_signature


def _direct_callers(graph, graph_sig: str) -> list[dict[str, Any]]:
    if graph is None or graph_sig not in graph:
        return []
    results = []
    for pred in graph.predecessors(graph_sig):
        edge = graph.edges[pred, graph_sig]
        if edge.get("relation") != "calls":
            continue
        pred_data = graph.nodes.get(pred, {})
        results.append({
            "method": pred,
            "file": pred_data.get("file", ""),
            "line": edge.get("line", 0),
        })
    return results


def _direct_callees(graph, graph_sig: str) -> list[dict[str, Any]]:
    if graph is None or graph_sig not in graph:
        return []
    results = []
    for succ in graph.successors(graph_sig):
        edge = graph.edges[graph_sig, succ]
        if edge.get("relation") != "calls":
            continue
        succ_data = graph.nodes.get(succ, {})
        results.append({
            "method": succ,
            "file": succ_data.get("file", ""),
            "class": succ_data.get("class_name", ""),
        })
    return results


def _classify_api_calls(api_calls: list[str]) -> list[str]:
    categories = Counter()
    for api in api_calls:
        lower = api.lower()
        if any(k in lower for k in _BILLING_HINTS):
            categories["billing"] += 1
        if any(k in lower for k in _SERIALIZATION_HINTS):
            categories["serialization"] += 1
        if any(k in lower for k in ("cipher", "secretkeyspec", "messagedigest", "keystore", "securerandom")):
            categories["crypto"] += 1
        if any(k in lower for k in ("ssl", "trustmanager", "hostnameverifier", "certificatepinner")):
            categories["ssl_tls"] += 1
        if any(k in lower for k in ("okhttp", "retrofit", "httpurlconnection", "webview;->loadurl", "requestbody")):
            categories["network"] += 1
        if any(k in lower for k in ("sharedpreferences", "sqlitedatabase", "contentresolver", "fileoutputstream")):
            categories["storage"] += 1
        if any(k in lower for k in ("class;->forname", "reflect", "dexclassloader", "pathclassloader")):
            categories["dynamic_reflection"] += 1
        if any(k in lower for k in ("log;->", "printstream;->println")):
            categories["logging"] += 1
    return [name for name, _ in categories.most_common()]


def _is_gate_like(method: "SmaliMethod", branch_blocks: list[Any], field_accesses: list[str]) -> bool:
    if method.return_type in {"Z", "I"} and branch_blocks:
        return True
    if field_accesses and branch_blocks:
        return True
    return False


def _build_guard_signals(
    method: "SmaliMethod",
    branch_blocks: list[Any],
    field_accesses: list[str],
    api_categories: list[str],
) -> list[str]:
    signals: list[str] = []
    if method.return_type in {"Z", "I"}:
        signals.append(f"Returns {method.return_type} — typical for gate/enforcement methods")
    if branch_blocks:
        signals.append(f"Has {len(branch_blocks)} branch block(s) — decision logic present")
    if field_accesses:
        signals.append(f"Reads/writes {len(field_accesses)} field reference(s)")
    if "billing" in api_categories:
        signals.append("Touches billing/entitlement APIs — likely tied to real premium verification")
    if "serialization" in api_categories:
        signals.append("Touches serialization APIs — may overwrite premium state from responses")
    if "network" in api_categories:
        signals.append("Touches network APIs — may participate in server-side validation")
    if "storage" in api_categories:
        signals.append("Touches storage APIs — may cache or persist entitlement state")
    if "dynamic_reflection" in api_categories:
        signals.append("Uses reflection/class loading — hidden enforcement path risk")
    return signals


def _build_patch_hints(
    method: "SmaliMethod",
    direct_callers: list[dict[str, Any]],
    api_categories: list[str],
    field_accesses: list[str],
) -> list[str]:
    hints: list[str] = []
    if method.return_type == "Z":
        hints.append("Boolean method — patch-to-false/true strategy may be viable after reviewing callers")
    elif method.return_type == "I":
        hints.append("Integer gate — check whether 0/1 encodes entitlement or error state")
    if direct_callers:
        hints.append("Review direct callers before patching — upstream AND-conditions may still block flow")
    if field_accesses:
        hints.append("Trace field writers/readers too — cached state can overwrite a method-level patch")
    if "billing" in api_categories:
        hints.append("Billing/entitlement APIs present — patch the purchase validation boundary, not just UI gates")
    if "serialization" in api_categories:
        hints.append("Serialization/deserializer logic present — use patch_api_response_flow if entity fields get overwritten")
    if "network" in api_categories:
        hints.append("Look for re-validation on refresh/startup — patch may need network or deserializer companion changes")
    if "dynamic_reflection" in api_categories:
        hints.append("Reflection/dynamic loading present — verify alternate code paths after patching")
    return hints


def _score_method(
    method: "SmaliMethod",
    branch_count: int,
    field_count: int,
    field_write_count: int,
    api_categories: list[str],
    direct_callers: list[dict[str, Any]],
    direct_callees: list[dict[str, Any]],
    graph_role_contexts: list[str],
    third_party_path: bool,
    surface_role: str,
    structure: dict[str, Any],
    focus_hits: list[str],
) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    if method.return_type in {"Z", "I"} and branch_count > 0:
        score += 18
        reasons.append(f"Gate-like return type {method.return_type} with branch logic")
    elif method.return_type in {"Z", "I"}:
        score += 8
        reasons.append(f"Gate-like return type {method.return_type}")
    if field_count > 0:
        score += min(12, field_count * 2)
        reasons.append(f"Field-backed state checks: {field_count}")
    if field_write_count > 0:
        score += min(14, field_write_count * 3)
        reasons.append(f"Writes state fields: {field_write_count}")
    if direct_callers:
        score += min(15, len(direct_callers) * 2)
        reasons.append(f"Reachable from {len(direct_callers)} caller(s)")
    if direct_callees:
        score += min(8, len(direct_callees))
    if structure["state_field_hits"]:
        score += min(22, 10 + len(structure["state_field_hits"]) * 4)
        reasons.append("Touches recovered high-value state fields")
    if structure["state_model_owner"]:
        score += 10
        reasons.append("Owned by a recovered state model class")
    if structure["network_state_boundary"]:
        score += 16
        reasons.append("Bridges network/serialization flow into recovered state")
    if structure["writer_chain_match"]:
        score += 14
        reasons.append("Recovered as a writer in the hidden-state model")
    if structure["reader_chain_match"]:
        score += 8
        reasons.append("Recovered as a reader of the hidden-state model")
    if structure["guard_cluster_match"]:
        score += min(18, 8 + structure["guard_cluster_severity"] * 2)
        reasons.append("Participates in a profiled guard/revalidation cluster")
    if structure["revalidation_loop_owner"]:
        score += 12
        reasons.append("Owner class sits in a lifecycle/revalidation loop")
    if structure["state_store_boundary"]:
        score += 8
        reasons.append("Touches persistence/state-store boundary")
    if structure["entry_point_owner"] and field_write_count > 0:
        score += 8
        reasons.append("Lifecycle/entry path rewrites state")
    if graph_role_contexts:
        score += min(16, len(graph_role_contexts) * 3)
        reasons.append(f"Graph neighbors cross key architecture roles: {', '.join(graph_role_contexts)}")
    if surface_role == "revalidation_boundary":
        score += 14
        reasons.append("Looks like a response/revalidation boundary that can overwrite server-derived state")
    elif surface_role == "state_mutator":
        score += 8
        reasons.append("Looks like a state mutator rather than a simple UI symptom")
    elif surface_role == "gate_accessor":
        score += 4
        reasons.append("Looks like a compact gate/accessor method")
    if "billing" in api_categories:
        score += 10
        reasons.append("Billing framework adjacency")
    if "serialization" in api_categories:
        score += 10
        reasons.append("Serialization/deserializer boundary")
    if "network" in api_categories:
        score += 8
        reasons.append("Network validation signal")
    if "storage" in api_categories:
        score += 5
        reasons.append("Cached state/storage signal")
    if method.category in {"network", "ssl_tls", "storage"}:
        score += 4
    if focus_hits:
        score += min(6, len(focus_hits) * 2)
        reasons.append(f"Optional focus hint overlap: {', '.join(focus_hits)}")
    if third_party_path:
        score -= 18
        reasons.append("Third-party SDK path — demoted in favor of app-owned enforcement code")
    return score, reasons


def _focus_terms(feature: str, extra_keywords: str) -> set[str]:
    blob = ",".join(part for part in (feature, extra_keywords) if part)
    tokens = {token.lower() for token in re.findall(r"\w+", blob, flags=re.UNICODE) if len(token) >= 3}
    expanded = set(tokens)
    for token in list(tokens):
        expanded.update(_FOCUS_SYNONYMS.get(token, set()))
    return expanded


def _focus_hits(values: list[str], focus_terms: set[str]) -> list[str]:
    if not focus_terms:
        return []
    hits: set[str] = set()
    for value in values:
        tokens = {token.lower() for token in re.findall(r"\w+", value, flags=re.UNICODE)}
        for focus_term in focus_terms:
            if focus_term in tokens:
                hits.add(focus_term)
    return sorted(hits)


def _build_architecture_context(index: "SmaliIndex", focus_terms: set[str]) -> dict[str, Any]:
    return get_cached_architecture_context(index, focus_terms=focus_terms)


def _method_architecture_profile(
    method: "SmaliMethod",
    class_name: str,
    file_path: str,
    field_accesses: list[str],
    field_write_count: int,
    api_categories: list[str],
    architecture_context: dict[str, Any],
) -> dict[str, Any]:
    role_classes = architecture_context["role_classes"]
    owner_roles = sorted(role for role, classes in role_classes.items() if class_name in classes)
    state_fields = architecture_context["state_fields"]
    state_model_classes = role_classes["state_models"]
    normalized_field_accesses = [_normalize_field_ref(field) for field in field_accesses]

    state_field_hits = [field for field in normalized_field_accesses if field in state_fields]
    state_field_semantics = sorted({architecture_context["state_field_semantics"].get(field, "state_value") for field in state_field_hits})
    touched_state_model_classes = sorted({
        _field_owner(field)
        for field in normalized_field_accesses
        if _field_owner(field) in state_model_classes
    })
    if method.return_type in state_model_classes:
        touched_state_model_classes.append(method.return_type)
    touched_state_model_classes.extend(param for param in method.param_types if param in state_model_classes)
    touched_state_model_classes = sorted(set(touched_state_model_classes))

    network_state_boundary = bool(
        ({"network_layer", "serialization_layer", "billing_flow"} & set(owner_roles))
        and (state_field_hits or touched_state_model_classes or field_write_count > 0)
    )
    state_store_boundary = bool(
        ({"state_stores"} & set(owner_roles))
        and (state_field_hits or field_write_count > 0)
    )
    entry_point_owner = "entry_points" in owner_roles
    state_model_owner = "state_models" in owner_roles
    writer_chain_match = method.full_signature in architecture_context["writer_methods"]
    reader_chain_match = method.full_signature in architecture_context["reader_methods"]
    guard_cluster_match = method.full_signature in architecture_context["guard_methods"] or method.full_signature in architecture_context["overwrite_methods"]
    guard_cluster_severity = architecture_context["guard_method_scores"].get(method.full_signature, 0)
    revalidation_loop_owner = class_name in architecture_context["revalidation_classes"]
    dynamic_boundary_match = method.full_signature in architecture_context["dynamic_boundary_methods"]

    signals: list[str] = []
    if owner_roles:
        signals.append(f"Owner roles: {', '.join(owner_roles)}")
    if state_field_hits:
        signals.append("Touches recovered state fields")
    if touched_state_model_classes:
        signals.append(f"Touches recovered state model classes: {', '.join(touched_state_model_classes[:4])}")
    if network_state_boundary:
        signals.append("Network/serialization boundary feeds recovered state")
    if state_store_boundary:
        signals.append("Persistence boundary reads/writes recovered state")
    if writer_chain_match:
        signals.append("Recovered writer chain into state model")
    if reader_chain_match:
        signals.append("Recovered reader chain from state model")
    if guard_cluster_match:
        signals.append("Appears inside profiled guard/revalidation cluster")
    if revalidation_loop_owner:
        signals.append("Owner class participates in revalidation loop")
    if dynamic_boundary_match:
        signals.append("Near native/dynamic execution boundary")
    if file_path and _is_third_party_path(file_path):
        signals.append("Third-party SDK ownership")

    return {
        "owner_roles": owner_roles,
        "state_field_hits": state_field_hits,
        "state_field_semantics": state_field_semantics,
        "touched_state_model_classes": touched_state_model_classes,
        "network_state_boundary": network_state_boundary,
        "state_store_boundary": state_store_boundary,
        "entry_point_owner": entry_point_owner,
        "state_model_owner": state_model_owner,
        "writer_chain_match": writer_chain_match,
        "reader_chain_match": reader_chain_match,
        "guard_cluster_match": guard_cluster_match,
        "guard_cluster_severity": guard_cluster_severity,
        "revalidation_loop_owner": revalidation_loop_owner,
        "dynamic_boundary_match": dynamic_boundary_match,
        "signals": signals,
    }


def _is_structural_enforcement_candidate(
    method: "SmaliMethod",
    structure: dict[str, Any],
    branch_count: int,
    field_count: int,
    field_write_count: int,
    direct_callers: list[dict[str, Any]],
    direct_callees: list[dict[str, Any]],
) -> bool:
    if structure["state_field_hits"] or structure["writer_chain_match"] or structure["reader_chain_match"]:
        return True
    if structure["guard_cluster_match"] or structure["revalidation_loop_owner"]:
        return True
    if structure["network_state_boundary"] or structure["state_store_boundary"]:
        return True
    if method.return_type in {"Z", "I"} and branch_count > 0 and (field_count > 0 or structure["state_model_owner"] or direct_callers):
        return True
    if field_write_count > 0 and (structure["entry_point_owner"] or structure["state_model_owner"] or direct_callees):
        return True
    if structure["dynamic_boundary_match"] and (branch_count > 0 or field_write_count > 0):
        return True
    return False


def _field_write_count(method: "SmaliMethod") -> int:
    return sum(1 for instr in method.instructions if instr.is_field_access and "put" in instr.opcode)


def _normalize_field_ref(field_ref: str) -> str:
    return field_ref.split(":", 1)[0] if ":" in field_ref else field_ref


def _field_owner(field_ref: str) -> str:
    return field_ref.split("->", 1)[0] if "->" in field_ref else ""


def _graph_role_contexts(
    direct_callers: list[dict[str, Any]],
    direct_callees: list[dict[str, Any]],
    architecture_context: dict[str, Any],
) -> list[str]:
    role_classes = architecture_context["role_classes"]
    hits: set[str] = set()
    for label, items in (("caller", direct_callers), ("callee", direct_callees)):
        for item in items:
            class_name = _field_owner(item.get("method", ""))
            for role, classes in role_classes.items():
                if class_name in classes:
                    hits.add(f"{label}:{role}")
                    if role == "ui_gate_controllers":
                        hits.add(f"{label}:ui_controller")
            blob = f"{item.get('method', '')} {item.get('file', '')}".lower()
            if any(hint in blob for hint in _CALLER_UI_HINTS):
                hits.add(f"{label}:ui_context")
    return sorted(hits)


def _surface_role(
    method: "SmaliMethod",
    branch_count: int,
    field_write_count: int,
    api_categories: list[str],
    structure: dict[str, Any],
    graph_role_contexts: list[str],
) -> str:
    if field_write_count > 0 and (
        structure["network_state_boundary"]
        or structure["revalidation_loop_owner"]
        or structure["guard_cluster_match"]
        or any(cat in api_categories for cat in ("serialization", "network", "storage"))
    ):
        return "revalidation_boundary"
    if method.return_type in {"Z", "I"} and branch_count > 0 and (
        structure["state_field_hits"]
        or structure["state_model_owner"]
        or any(ctx.endswith("ui_controller") or ctx.endswith("ui_context") for ctx in graph_role_contexts)
    ):
        return "gate_method"
    if field_write_count > 0:
        return "state_mutator"
    if method.return_type in {"Z", "I"} and (structure["state_field_hits"] or structure["reader_chain_match"]):
        return "gate_accessor"
    return "candidate"