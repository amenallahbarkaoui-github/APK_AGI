"""App-aware routing for reverse-engineering workflows.

The agent already has many tools; this module tells it which family to use
first based on the actual app topology instead of leaving the decision to broad
prompt heuristics alone.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from apk_agent.tools.native_re_core import analyze_native_project
from apk_agent.tools.targeted_analysis import search_dynamic_loading, search_native_bridges


def route_reverse_engineering_workflow(
    apktool_dir: str | Path,
    *,
    jadx_dir: str | Path | None = None,
    objective: str = "",
    focus_hint: str = "",
) -> dict[str, Any]:
    """Classify the app and return the recommended RE workflow route."""
    apktool_dir = Path(apktool_dir)
    jadx_dir = Path(jadx_dir) if jadx_dir else None

    native = analyze_native_project(apktool_dir, focus_hint=focus_hint)
    dynamic = search_dynamic_loading(apktool_dir, max_results=20)
    bridges = search_native_bridges(apktool_dir, max_results=20)
    profile = _build_project_profile(apktool_dir, jadx_dir, native, dynamic, bridges)
    route = _choose_route(profile)
    sequence = _route_sequence(route, objective=objective)

    return {
        "success": True,
        "objective": objective,
        "focus_hint": focus_hint,
        "route": route,
        "profile": profile,
        "recommended_sequence": sequence,
        "starting_tools": [step["tool"] for step in sequence[:6]],
        "blocking_risks": _blocking_risks(profile, route),
    }


def _build_project_profile(
    apktool_dir: Path,
    jadx_dir: Path | None,
    native: dict[str, Any],
    dynamic: dict[str, Any],
    bridges: dict[str, Any],
) -> dict[str, Any]:
    lib_names = {library.get("name", "") for library in native.get("libraries", [])}
    framework_hints = set(native.get("framework_hints", []))
    asset_flags = _detect_assets(apktool_dir)
    jadx_flags = _detect_jadx_markers(jadx_dir)

    frameworks: list[str] = []
    if "libflutter.so" in lib_names or asset_flags["flutter"] or {"flutter_runtime", "flutter_or_dart_payload"} & framework_hints:
        frameworks.append("flutter")
    if "libil2cpp.so" in lib_names or asset_flags["unity"] or jadx_flags["unity"]:
        frameworks.append("unity")
    if asset_flags["react_native"] or "react_native_runtime" in framework_hints or jadx_flags["react_native"]:
        frameworks.append("react_native")
    if asset_flags["webview"] or jadx_flags["webview"]:
        frameworks.append("webview_hybrid")

    return {
        "frameworks": frameworks,
        "framework_hints": sorted(framework_hints),
        "native_library_count": len(native.get("libraries", [])),
        "native_bridge_count": len(bridges.get("native_bridges", [])),
        "dynamic_loader_count": len(dynamic.get("dynamic_loading", [])),
        "hidden_loader_artifacts": len(dynamic.get("hidden_dex", [])),
        "has_native_libs": native.get("has_native_libs", False),
        "architectures": native.get("architectures", []),
        "asset_flags": asset_flags,
        "jadx_flags": jadx_flags,
        "libraries": native.get("libraries", [])[:12],
    }


def _choose_route(profile: dict[str, Any]) -> dict[str, Any]:
    frameworks = set(profile.get("frameworks", []))
    native_library_count = int(profile.get("native_library_count", 0))
    native_bridge_count = int(profile.get("native_bridge_count", 0))
    dynamic_loader_count = int(profile.get("dynamic_loader_count", 0))
    hidden_loader_artifacts = int(profile.get("hidden_loader_artifacts", 0))

    if "flutter" in frameworks:
        return {"name": "flutter_native_first", "confidence": 0.94, "reason": "Flutter runtime/libapp evidence detected."}
    if "unity" in frameworks:
        return {"name": "unity_il2cpp_first", "confidence": 0.93, "reason": "Unity IL2CPP artifacts detected."}
    if "react_native" in frameworks:
        return {"name": "react_native_bundle_first", "confidence": 0.91, "reason": "React Native/Hermes bundle evidence detected."}
    if dynamic_loader_count >= 3 or hidden_loader_artifacts > 0:
        return {"name": "packed_dynamic_loader_first", "confidence": 0.88, "reason": "Dynamic code loading or hidden secondary artifacts detected."}
    if native_library_count >= 3 or native_bridge_count >= 2:
        return {"name": "hybrid_native_first", "confidence": 0.86, "reason": "Multiple native libraries or JNI bridges suggest native-heavy logic."}
    if "webview_hybrid" in frameworks:
        return {"name": "webview_hybrid_first", "confidence": 0.8, "reason": "WebView/bundle assets suggest a web-hybrid route."}
    return {"name": "java_kotlin_static_first", "confidence": 0.72, "reason": "No strong framework/native route dominated the project."}


def _route_sequence(route: dict[str, Any], *, objective: str) -> list[dict[str, str]]:
    objective_lower = (objective or "").lower()

    if route["name"] == "flutter_native_first":
        steps = [
            ("analyze_native_libs", "Inventory Flutter runtime and libapp payloads first."),
            ("analyze_native_re_core", "Recover ELF imports/exports/function anchors from libapp.so or companion libs."),
            ("build_dart_aot_index", "Build a searchable anchor map for Flutter AOT payloads."),
            ("locate_dart_aot_candidates", "Rank bounded candidate regions near business-logic strings."),
            ("plan_native_patch_targets", "Pick the native patch windows before editing bytes."),
            ("build_behavior_graph", "Correlate native route with recovered Java/network/state surfaces."),
        ]
    elif route["name"] == "unity_il2cpp_first":
        steps = [
            ("analyze_native_libs", "Inventory libil2cpp and metadata-bearing native libraries."),
            ("analyze_native_re_core", "Recover exported/imported functions and JNI/native anchors."),
            ("search_binary_strings", "Find Unity metadata and gameplay string anchors in native/assets payloads."),
            ("plan_native_patch_targets", "Rank concrete function/string patch targets in the IL2CPP path."),
            ("search_dynamic_loaders", "Confirm whether Unity loads extra payloads dynamically."),
            ("build_behavior_graph", "Tie Unity-native findings back to app-owned state and validation flows."),
        ]
    elif route["name"] == "react_native_bundle_first":
        steps = [
            ("search_native_code", "Locate React Native bridges and Hermes/JSC runtimes."),
            ("search_binary_strings", "Inspect JS bundle or Hermes-related assets for route anchors."),
            ("analyze_native_re_core", "Analyze Hermes/reactnative native libraries when logic sinks into `.so` code."),
            ("plan_native_patch_targets", "Rank native/runtime anchors before low-level edits."),
            ("analyze_network_behavior", "Trace network-to-state boundaries that drive the JS/native layer."),
            ("build_behavior_graph", "Correlate JS/native boundaries with state mutators and revalidation."),
        ]
    elif route["name"] == "packed_dynamic_loader_first":
        steps = [
            ("search_dynamic_loaders", "Confirm loader classes, reflection, and hidden dex/jar assets."),
            ("search_native_code", "Map native bridges that may unpack or dispatch payloads."),
            ("analyze_native_re_core", "Recover loader-related imports and suspicious native anchors."),
            ("analyze_native_libs", "Inventory packed companion libraries and JNI exports."),
            ("plan_native_patch_targets", "Rank the native loader/guard anchors before patching."),
            ("build_behavior_graph", "Connect unpacked/runtime boundaries to downstream enforcement paths."),
        ]
    elif route["name"] == "hybrid_native_first":
        steps = [
            ("analyze_native_libs", "Inventory native libraries, JNI exports, and suspicious imports first."),
            ("search_native_code", "Map Java/Kotlin to native bridge boundaries."),
            ("analyze_native_re_core", "Recover executable anchors and imported/exported functions in target libraries."),
            ("plan_native_patch_targets", "Produce ranked native patch targets with concrete offsets."),
            ("map_security_surfaces", "Correlate native findings with runtime/security boundaries."),
            ("build_behavior_graph", "Keep the native path tied to state and revalidation logic."),
        ]
    elif route["name"] == "webview_hybrid_first":
        steps = [
            ("search_binary_strings", "Inspect bundle/assets routes before touching Java symptoms."),
            ("analyze_network_behavior", "Trace request/response boundaries into the hybrid state layer."),
            ("build_behavior_graph", "Map state sources and gates around the web bridge."),
            ("patch_api_response_flow", "Prefer boundary patching when the web/native layer overwrites state."),
            ("analyze_native_re_core", "Only pivot to native analysis if the bridge drops into `.so` code."),
        ]
    else:
        steps = [
            ("build_behavior_graph", "Start with the unified app-owned behavior map."),
            ("locate_feature_controls", "Separate activation, deactivation, and enforcement points."),
            ("map_security_surfaces", "Rank validation and API boundaries before editing."),
            ("analyze_network_behavior", "Identify network/state overwrite paths early."),
            ("search_native_code", "Quickly confirm whether native pivots are needed."),
        ]

    if any(token in objective_lower for token in ("ssl", "tls", "pin", "certificate")):
        steps.insert(0, ("search_interceptors", "Network/TLS objective detected — inspect client interception points immediately."))
    if any(token in objective_lower for token in ("root", "debug", "frida", "tamper")):
        steps.insert(0, ("detect_protections", "Protection-bypass objective detected — map anti-debug/root/tamper surfaces early."))

    return [{"tool": tool, "why": why} for tool, why in steps]


def _detect_assets(apktool_dir: Path) -> dict[str, bool]:
    assets_dir = apktool_dir / "assets"
    lib_dir = apktool_dir / "lib"
    asset_files = list(assets_dir.rglob("*")) if assets_dir.exists() else []
    lib_files = list(lib_dir.rglob("*.so")) if lib_dir.exists() else []
    return {
        "flutter": (assets_dir / "flutter_assets").exists() or any(path.name == "libflutter.so" for path in lib_files),
        "unity": (assets_dir / "bin" / "Data").exists() or any(path.name == "global-metadata.dat" for path in asset_files if path.is_file()),
        "react_native": any(path.name in {"index.android.bundle", "index.bundle"} for path in asset_files if path.is_file()),
        "webview": any(path.suffix in {".html", ".js", ".css"} for path in asset_files if path.is_file()),
    }


def _detect_jadx_markers(jadx_dir: Path | None) -> dict[str, bool]:
    if not jadx_dir or not jadx_dir.exists():
        return {"unity": False, "react_native": False, "webview": False}

    text_hits = {"unity": False, "react_native": False, "webview": False}
    markers = {
        "unity": re.compile(r"UnityPlayer|com\.unity3d", re.IGNORECASE),
        "react_native": re.compile(r"com\.facebook\.react|ReactNativeHost|Hermes", re.IGNORECASE),
        "webview": re.compile(r"android\.webkit\.WebView|loadUrl\(|addJavascriptInterface", re.IGNORECASE),
    }
    for file_path in list(jadx_dir.rglob("*.java"))[:160]:
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name, regex in markers.items():
            if not text_hits[name] and regex.search(text):
                text_hits[name] = True
        if all(text_hits.values()):
            break
    return text_hits


def _blocking_risks(profile: dict[str, Any], route: dict[str, Any]) -> list[str]:
    risks: list[str] = []
    if int(profile.get("dynamic_loader_count", 0)) > 0:
        risks.append("Dynamic loaders present: static findings may be incomplete until loader paths are mapped.")
    if int(profile.get("native_library_count", 0)) >= 4 and route["name"] != "java_kotlin_static_first":
        risks.append("Multiple native libraries detected: avoid gate-only smali patches before native boundaries are ranked.")
    if "flutter" in set(profile.get("frameworks", [])):
        risks.append("Flutter route detected: app logic may live in libapp.so rather than visible Java/Kotlin classes.")
    if "unity" in set(profile.get("frameworks", [])):
        risks.append("Unity route detected: gameplay/business logic may be IL2CPP-native and require asset/native pivots.")
    return risks