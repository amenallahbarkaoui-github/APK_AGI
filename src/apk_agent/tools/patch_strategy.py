"""Routing heuristics for runtime hook execution strategies.

This module is intentionally additive. It does not replace existing hook
planning or runtime-menu generation. Instead, it classifies each runtime hook
into the most appropriate execution lane so higher-level workflows can stop
defaulting every hook to a floating-menu injection path.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping


class PatchStrategy(str, Enum):
    STATIC_PATCH_ONLY = "static_patch_only"
    RUNTIME_MENU_GOOD_FIT = "runtime_menu_good_fit"
    RUNTIME_OVERRIDE_GOOD_FIT = "runtime_override_good_fit"
    HYBRID_REQUIRED = "hybrid_required"
    NOT_SUITABLE_WITHOUT_EXTERNAL_RUNTIME = "not_suitable_without_external_runtime"


@dataclass(frozen=True)
class StrategyRecommendation:
    strategy: PatchStrategy
    confidence: float
    reasons: tuple[str, ...]
    fallback_strategies: tuple[PatchStrategy, ...] = ()
    strategy_binding_status: str = "unknown_without_index"
    external_runtime_required: bool = False
    compatible_with_static_patch: bool = False
    compatible_with_runtime_menu: bool = False
    compatible_with_runtime_override: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy_recommendation": self.strategy.value,
            "strategy_confidence": round(self.confidence, 3),
            "strategy_reasons": list(self.reasons),
            "strategy_fallbacks": [item.value for item in self.fallback_strategies],
            "strategy_binding_status": self.strategy_binding_status,
            "external_runtime_required": self.external_runtime_required,
            "compatible_with_static_patch": self.compatible_with_static_patch,
            "compatible_with_runtime_menu": self.compatible_with_runtime_menu,
            "compatible_with_runtime_override": self.compatible_with_runtime_override,
        }


_SUPPORTED_MENU_SIGNATURES = {
    tuple(),
    ("Landroid/content/Context;",),
    ("Z",),
    ("Landroid/content/Context;", "Z"),
    ("I",),
    ("Landroid/content/Context;", "I"),
}

_EXTERNAL_RUNTIME_HINTS = {
    "dynamic_or_native_boundary",
    "native",
    "jni",
    "frida",
    "classloader",
    "dynamic_load",
    "external_runtime",
    "native_only",
}

_REVALIDATION_HINTS = {
    "observe_and_override_state",
    "hook_feature_revalidation",
    "revalidation_boundary",
    "lifecycle_reapply_hook",
    "callback_or_lifecycle",
    "reapply",
    "resume",
    "state writes",
    "refreshfromresponse",
}

_STATIC_PATCH_HINTS = {
    "writer_override_or_constructor_patch",
    "constructor_patch",
    "static_patch",
    "rewrite gate",
}

_FEASIBLE_STRATEGY_ORDER = {
    PatchStrategy.HYBRID_REQUIRED: 4,
    PatchStrategy.RUNTIME_OVERRIDE_GOOD_FIT: 3,
    PatchStrategy.RUNTIME_MENU_GOOD_FIT: 2,
    PatchStrategy.STATIC_PATCH_ONLY: 1,
    PatchStrategy.NOT_SUITABLE_WITHOUT_EXTERNAL_RUNTIME: 0,
}


def _iter_text(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        text = value.strip()
        if text:
            yield text.lower()
        return
    if isinstance(value, Mapping):
        for nested in value.values():
            yield from _iter_text(nested)
        return
    if isinstance(value, (list, tuple, set)):
        for nested in value:
            yield from _iter_text(nested)


def _hook_text(hook: Mapping[str, Any]) -> str:
    parts: list[str] = []
    for key in ("strategy", "observe", "mutate", "reasons", "recommended_tools", "class", "method", "source"):
        parts.extend(_iter_text(hook.get(key)))
    return " ".join(parts)


def _method_name(method_value: str) -> str:
    tail = method_value.split("->", 1)[-1]
    return tail.split("(", 1)[0].strip()


def _candidate_methods(hook: Mapping[str, Any], smali_index: Any | None) -> list[Any]:
    if smali_index is None:
        return []

    class_name = str(hook.get("class") or "").strip()
    method_value = str(hook.get("method") or "").strip()
    candidates: list[Any] = []

    if method_value and hasattr(smali_index, "get_method"):
        if "->" in method_value:
            full_signature = method_value if method_value.startswith("L") else f"{class_name}->{method_value}"
            method = smali_index.get_method(full_signature)
            if method is not None:
                candidates.append(method)

    if not candidates and class_name and hasattr(smali_index, "get_class"):
        class_obj = smali_index.get_class(class_name)
        if class_obj is not None:
            target_name = _method_name(method_value)
            for method in getattr(class_obj, "methods", []):
                if getattr(method, "name", "") == target_name:
                    candidates.append(method)

    if not candidates and method_value and hasattr(smali_index, "search_methods"):
        target_name = _method_name(method_value)
        for method in smali_index.search_methods(target_name):
            full_signature = str(getattr(method, "full_signature", ""))
            if class_name and not full_signature.startswith(f"{class_name}->"):
                continue
            candidates.append(method)
            if len(candidates) >= 8:
                break

    deduped: list[Any] = []
    seen: set[str] = set()
    for method in candidates:
        signature = str(getattr(method, "full_signature", ""))
        if signature in seen:
            continue
        seen.add(signature)
        deduped.append(method)
    return deduped


def _is_menu_bindable(method: Any) -> bool:
    access_flags = set(getattr(method, "access_flags", set()) or set())
    if "static" not in access_flags:
        return False
    if str(getattr(method, "return_type", "")) != "V":
        return False
    params = tuple(getattr(method, "param_types", []) or [])
    return params in _SUPPORTED_MENU_SIGNATURES


def _binding_status(hook: Mapping[str, Any], smali_index: Any | None) -> tuple[str, list[Any]]:
    if smali_index is None:
        return "unknown_without_index", []

    candidates = _candidate_methods(hook, smali_index)
    if not candidates:
        return "deferred_lookup_target", []

    bindable = [method for method in candidates if _is_menu_bindable(method)]
    if bindable:
        return ("resolved_static_target" if len(bindable) == 1 else "reflection_target"), candidates
    if any("native" in set(getattr(method, "access_flags", set()) or set()) for method in candidates):
        return "unsupported_target", candidates
    return "reflection_target", candidates


def recommend_runtime_patch_strategy(
    hook: Mapping[str, Any],
    *,
    smali_index: Any | None = None,
) -> StrategyRecommendation:
    text = _hook_text(hook)
    binding_status, methods = _binding_status(hook, smali_index)
    reasons: list[str] = []

    requires_external_runtime = any(token in text for token in _EXTERNAL_RUNTIME_HINTS)
    needs_reapply = any(token in text for token in _REVALIDATION_HINTS)
    prefers_static_patch = any(token in text for token in _STATIC_PATCH_HINTS)

    if any("native" in set(getattr(method, "access_flags", set()) or set()) for method in methods):
        requires_external_runtime = True
        reasons.append("resolved hook target is native, so in-APK dispatcher binding is not enough")

    if binding_status == "unknown_without_index":
        reasons.append("smali index is unavailable, so routing falls back to hook metadata heuristics")
    elif binding_status == "resolved_static_target":
        reasons.append("hook target resolves to a supported static void signature for menu dispatch")
    elif binding_status == "reflection_target":
        reasons.append("hook target exists but does not map cleanly to the current static dispatcher signatures")
    elif binding_status == "deferred_lookup_target":
        reasons.append("hook target could not be resolved from the current smali index")
    elif binding_status == "unsupported_target":
        reasons.append("hook target shape is not suitable for the current in-APK runtime dispatch path")

    if requires_external_runtime:
        reasons.append("hook metadata points at dynamic or native boundaries that need an external runtime layer")
        return StrategyRecommendation(
            PatchStrategy.NOT_SUITABLE_WITHOUT_EXTERNAL_RUNTIME,
            0.92,
            tuple(reasons),
            fallback_strategies=(PatchStrategy.STATIC_PATCH_ONLY,),
            strategy_binding_status=("unsupported_target" if binding_status == "unknown_without_index" else binding_status),
            external_runtime_required=True,
            compatible_with_static_patch=True,
        )

    if needs_reapply and binding_status == "resolved_static_target":
        reasons.append("revalidation-style hooks need runtime override plus a menu control plane, not menu-only injection")
        return StrategyRecommendation(
            PatchStrategy.HYBRID_REQUIRED,
            0.88,
            tuple(reasons),
            fallback_strategies=(PatchStrategy.RUNTIME_OVERRIDE_GOOD_FIT, PatchStrategy.STATIC_PATCH_ONLY),
            strategy_binding_status=binding_status,
            compatible_with_static_patch=True,
            compatible_with_runtime_menu=True,
            compatible_with_runtime_override=True,
        )

    if needs_reapply:
        reasons.append("hook metadata indicates late revalidation or state overwrite pressure")
        return StrategyRecommendation(
            PatchStrategy.RUNTIME_OVERRIDE_GOOD_FIT,
            0.84,
            tuple(reasons),
            fallback_strategies=(PatchStrategy.HYBRID_REQUIRED, PatchStrategy.STATIC_PATCH_ONLY),
            strategy_binding_status=binding_status,
            compatible_with_static_patch=True,
            compatible_with_runtime_override=True,
        )

    if binding_status == "resolved_static_target":
        reasons.append("menu injection can call this hook directly without extra adapter glue")
        return StrategyRecommendation(
            PatchStrategy.RUNTIME_MENU_GOOD_FIT,
            0.83,
            tuple(reasons),
            fallback_strategies=(PatchStrategy.HYBRID_REQUIRED, PatchStrategy.RUNTIME_OVERRIDE_GOOD_FIT),
            strategy_binding_status=binding_status,
            compatible_with_static_patch=True,
            compatible_with_runtime_menu=True,
        )

    if binding_status == "unknown_without_index":
        reasons.append("menu-first routing remains provisional until a smali index confirms the target signature")
        return StrategyRecommendation(
            PatchStrategy.RUNTIME_MENU_GOOD_FIT,
            0.61,
            tuple(reasons),
            fallback_strategies=(PatchStrategy.RUNTIME_OVERRIDE_GOOD_FIT, PatchStrategy.STATIC_PATCH_ONLY),
            strategy_binding_status=binding_status,
            compatible_with_static_patch=True,
            compatible_with_runtime_menu=True,
        )

    if prefers_static_patch or binding_status in {"reflection_target", "unsupported_target", "deferred_lookup_target"}:
        reasons.append("the current runtime menu dispatcher cannot bind this surface cleanly, so keep static patching in the loop")
        return StrategyRecommendation(
            PatchStrategy.STATIC_PATCH_ONLY,
            0.76,
            tuple(reasons),
            fallback_strategies=(PatchStrategy.RUNTIME_OVERRIDE_GOOD_FIT,),
            strategy_binding_status=binding_status,
            compatible_with_static_patch=True,
        )

    return StrategyRecommendation(
        PatchStrategy.RUNTIME_OVERRIDE_GOOD_FIT,
        0.68,
        tuple(reasons or ["fallback to runtime override when the hook does not cleanly fit menu or static-only routing"]),
        fallback_strategies=(PatchStrategy.STATIC_PATCH_ONLY,),
        strategy_binding_status=binding_status,
        compatible_with_static_patch=True,
        compatible_with_runtime_override=True,
    )


def annotate_runtime_hook_recommendations(
    hooks: Iterable[Mapping[str, Any]],
    *,
    smali_index: Any | None = None,
) -> list[dict[str, Any]]:
    annotated: list[dict[str, Any]] = []
    for hook in hooks:
        recommendation = recommend_runtime_patch_strategy(hook, smali_index=smali_index)
        annotated.append({**dict(hook), **recommendation.to_dict()})
    return annotated


def summarize_runtime_hook_recommendations(hooks: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    hooks_list = list(hooks)
    counts = Counter(str(hook.get("strategy_recommendation") or "") for hook in hooks_list if hook.get("strategy_recommendation"))
    confidence_by_strategy: dict[str, list[float]] = {}
    for hook in hooks_list:
        strategy = str(hook.get("strategy_recommendation") or "")
        if not strategy:
            continue
        confidence_by_strategy.setdefault(strategy, []).append(float(hook.get("strategy_confidence") or 0.0))

    def _score(strategy_name: str) -> tuple[int, float, int]:
        count = int(counts.get(strategy_name, 0))
        confidences = confidence_by_strategy.get(strategy_name, [])
        average_confidence = (sum(confidences) / len(confidences)) if confidences else 0.0
        try:
            priority = _FEASIBLE_STRATEGY_ORDER[PatchStrategy(strategy_name)]
        except ValueError:
            priority = -1
        return count, average_confidence, priority

    recommended_strategy = PatchStrategy.RUNTIME_MENU_GOOD_FIT.value
    feasible = [
        strategy.value
        for strategy in (
            PatchStrategy.HYBRID_REQUIRED,
            PatchStrategy.RUNTIME_OVERRIDE_GOOD_FIT,
            PatchStrategy.RUNTIME_MENU_GOOD_FIT,
            PatchStrategy.STATIC_PATCH_ONLY,
        )
        if counts.get(strategy.value)
    ]
    if feasible:
        recommended_strategy = max(feasible, key=_score)
    elif counts.get(PatchStrategy.NOT_SUITABLE_WITHOUT_EXTERNAL_RUNTIME.value):
        recommended_strategy = PatchStrategy.NOT_SUITABLE_WITHOUT_EXTERNAL_RUNTIME.value

    binding_status_counts = Counter(
        str(hook.get("strategy_binding_status") or "") for hook in hooks_list if hook.get("strategy_binding_status")
    )

    return {
        "counts": dict(counts),
        "binding_status_counts": dict(binding_status_counts),
        "recommended_next_strategy": recommended_strategy,
        "runtime_menu_candidate_count": int(counts.get(PatchStrategy.RUNTIME_MENU_GOOD_FIT.value, 0)) + int(counts.get(PatchStrategy.HYBRID_REQUIRED.value, 0)),
        "runtime_override_candidate_count": int(counts.get(PatchStrategy.RUNTIME_OVERRIDE_GOOD_FIT.value, 0)) + int(counts.get(PatchStrategy.HYBRID_REQUIRED.value, 0)),
        "static_patch_candidate_count": int(counts.get(PatchStrategy.STATIC_PATCH_ONLY.value, 0)) + int(counts.get(PatchStrategy.HYBRID_REQUIRED.value, 0)),
        "external_runtime_candidate_count": int(counts.get(PatchStrategy.NOT_SUITABLE_WITHOUT_EXTERNAL_RUNTIME.value, 0)),
    }


def finalize_runtime_hook_strategy_recommendation(
    routing_summary: Mapping[str, Any] | None,
    *,
    resolved_menu_bindings: int = 0,
) -> str:
    summary = dict(routing_summary or {})
    counts = {
        str(key): int(value or 0)
        for key, value in dict(summary.get("counts") or {}).items()
    }
    recommended = str(summary.get("recommended_next_strategy") or PatchStrategy.RUNTIME_MENU_GOOD_FIT.value)
    binding_ready_count = int(summary.get("runtime_menu_binding_ready_candidate_count") or 0)
    provisional_count = int(summary.get("runtime_menu_provisional_candidate_count") or 0)

    if resolved_menu_bindings > 0:
        return recommended

    if provisional_count > 0 and binding_ready_count <= 0:
        return PatchStrategy.RUNTIME_OVERRIDE_GOOD_FIT.value

    if recommended == PatchStrategy.RUNTIME_MENU_GOOD_FIT.value:
        if counts.get(PatchStrategy.HYBRID_REQUIRED.value, 0) > 0:
            return PatchStrategy.HYBRID_REQUIRED.value
        if counts.get(PatchStrategy.RUNTIME_OVERRIDE_GOOD_FIT.value, 0) > 0:
            return PatchStrategy.RUNTIME_OVERRIDE_GOOD_FIT.value
        if counts.get(PatchStrategy.RUNTIME_MENU_GOOD_FIT.value, 0) > 0:
            return PatchStrategy.RUNTIME_OVERRIDE_GOOD_FIT.value
        if counts.get(PatchStrategy.STATIC_PATCH_ONLY.value, 0) > 0:
            return PatchStrategy.STATIC_PATCH_ONLY.value
        if counts.get(PatchStrategy.NOT_SUITABLE_WITHOUT_EXTERNAL_RUNTIME.value, 0) > 0:
            return PatchStrategy.NOT_SUITABLE_WITHOUT_EXTERNAL_RUNTIME.value

    if recommended == PatchStrategy.HYBRID_REQUIRED.value:
        if counts.get(PatchStrategy.RUNTIME_OVERRIDE_GOOD_FIT.value, 0) > 0:
            return PatchStrategy.RUNTIME_OVERRIDE_GOOD_FIT.value
        if counts.get(PatchStrategy.STATIC_PATCH_ONLY.value, 0) > 0:
            return PatchStrategy.STATIC_PATCH_ONLY.value

    return recommended