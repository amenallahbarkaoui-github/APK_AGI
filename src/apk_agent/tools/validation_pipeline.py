"""Layered patch validation helpers.

Complements existing validators instead of replacing them:
  - validate_patch(file) for single-file syntax checks
  - validate_patch_completeness(class) for class-level gate coverage
  - verify_bypass_completeness() for whole-codebase gate re-scan
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from apk_agent.tools.deep_analysis import validate_smali_syntax


def run_patch_validation_pipeline(
    *,
    project_root: Path,
    apktool_dir: Path,
    backup_dir: Path,
    patch_journal: list[dict[str, Any]],
    task_plan: list[dict[str, Any]] | None = None,
    source_of_truth_pack: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run a journal-aware syntax + plan-consistency validation pass."""
    patched_files = _collect_patched_files(apktool_dir, backup_dir, patch_journal)
    patched_smali = [p for p in patched_files if p.suffix.lower() == ".smali"]
    patched_xml = [p for p in patched_files if p.suffix.lower() == ".xml"]

    invalid_smali: list[dict[str, Any]] = []
    warning_samples: list[dict[str, Any]] = []
    total_smali_warnings = 0
    for smali_file in patched_smali[:80]:
        result = validate_smali_syntax(smali_file)
        total_smali_warnings += len(result.get("warnings", []))
        if not result.get("valid", False):
            invalid_smali.append({
                "file": _rel_to_apktool(apktool_dir, smali_file),
                "errors": result.get("errors", [])[:10],
                "warnings": result.get("warnings", [])[:6],
            })
        elif result.get("warnings") and len(warning_samples) < 10:
            warning_samples.append({
                "file": _rel_to_apktool(apktool_dir, smali_file),
                "warnings": result.get("warnings", [])[:5],
            })

    tool_summary = Counter(entry.get("tool", "unknown") for entry in patch_journal if entry.get("tool"))

    next_actions: list[str] = []
    if invalid_smali:
        next_actions.append("Fix invalid smali files before build; use validate_patch on each broken file.")
    if patched_smali and not invalid_smali:
        next_actions.append("Patched smali syntax looks clean; proceed to completeness checks or build.")
    if not patched_files:
        next_actions.append("No patched files were detected from patch journal/backups; confirm a patch actually ran.")

    plan_consistency = _evaluate_plan_consistency(
        apktool_dir=apktool_dir,
        patch_journal=patch_journal,
        task_plan=list(task_plan or []),
        source_of_truth_pack=source_of_truth_pack,
    )
    next_actions.extend(
        action for action in plan_consistency["next_actions"]
        if action not in next_actions
    )

    return {
        "success": True,
        "advisory_only": True,
        "decision_owner": "agent",
        "evidence_mode": "evidence_first",
        "project_root": str(project_root),
        "patched_files_count": len(patched_files),
        "patched_smali_count": len(patched_smali),
        "patched_xml_count": len(patched_xml),
        "patched_files": [_rel_to_apktool(apktool_dir, p) for p in patched_files[:40]],
        "prebuild_mode": "syntax_only",
        "plan_consistency_mode": "additive",
        "journal_summary": {
            "entries": len(patch_journal),
            "by_tool": dict(sorted(tool_summary.items())),
        },
        "syntax": {
            "invalid_smali_count": len(invalid_smali),
            "total_warning_count": total_smali_warnings,
            "invalid_smali": invalid_smali[:20],
            "warning_samples": warning_samples,
        },
        "plan_consistency": plan_consistency,
        "plan_consistency_score": plan_consistency["score"],
        "coverage_gaps": plan_consistency["coverage_gaps"],
        "unsafe_overlaps": plan_consistency["unsafe_overlaps"],
        "missing_followups": plan_consistency["missing_followups"],
        "soft_prior_warnings": plan_consistency["soft_prior_warnings"],
        "lifecycle_risks": plan_consistency["lifecycle_risks"],
        "next_actions": next_actions,
    }


def generate_runtime_validation_plan(
    *,
    patch_journal: list[dict[str, Any]],
    task: str = "",
) -> dict[str, Any]:
    """Generate a concrete runtime validation checklist from patch history.

    This does not execute a device/emulator run. It prepares a structured test
    plan so runtime validation can happen consistently without losing context.
    """
    scenarios = [
        {
            "name": "Cold start smoke test",
            "goal": "Ensure the app launches after patch/build without immediate crash.",
            "success": "Main launcher screen renders and app remains stable for 10+ seconds.",
            "failure": "Crash, ANR, splash-loop, or integrity/tamper screen appears.",
        },
        {
            "name": "Resume/reopen test",
            "goal": "Catch protections that re-run on resume or warm start.",
            "success": "Patched behavior remains bypassed after background/foreground cycle.",
            "failure": "Premium lock, root detection, or SSL/tamper logic returns after resume.",
        },
    ]

    tool_names = {entry.get("tool", "") for entry in patch_journal}
    descriptions = " ".join(str(entry.get("description", "")) for entry in patch_journal).lower()
    task_lower = task.lower()
    signals = {task_lower, descriptions, " ".join(sorted(tool_names)).lower()}
    signal_blob = " ".join(signals)

    if any(k in signal_blob for k in ("premium", "subscription", "license", "purchase", "vip", "pro")):
        scenarios.append({
            "name": "Entitlement enforcement test",
            "goal": "Verify the premium gate stays bypassed across UI + refresh paths.",
            "success": "Locked screens/features open without paywall after refresh and relaunch.",
            "failure": "Any upgrade dialog, locked banner, or server refresh re-locks access.",
        })
    if any(k in signal_blob for k in ("ssl", "trust", "certificate", "pinning")):
        scenarios.append({
            "name": "Network interception test",
            "goal": "Confirm SSL/pinning bypass under real traffic.",
            "success": "App completes HTTPS requests under interception/debug proxy without SSL failure.",
            "failure": "Handshake failure, certificate error, or retry loop persists.",
        })
    if any(k in signal_blob for k in ("root", "magisk", "emulator", "debug", "tamper")):
        scenarios.append({
            "name": "Environment guard test",
            "goal": "Verify root/debug/emulator/tamper checks no longer block execution.",
            "success": "App runs normally in the previously blocked environment.",
            "failure": "Detection dialog, forced exit, feature disable, or process kill remains.",
        })

    return {
        "success": True,
        "task": task,
        "scenarios": scenarios,
        "operator_notes": [
            "Run each scenario on both first launch and after data refresh when possible.",
            "Capture screenshots/logcat/network evidence for every failure condition.",
            "If a scenario fails after refresh only, inspect caller/deserializer paths rather than re-patching blindly.",
        ],
    }


def _evaluate_plan_consistency(
    *,
    apktool_dir: Path,
    patch_journal: list[dict[str, Any]],
    task_plan: list[dict[str, Any]],
    source_of_truth_pack: dict[str, Any] | None = None,
) -> dict[str, Any]:
    successful_entries = [entry for entry in patch_journal if entry.get("success", True)]
    coverage_gaps: list[str] = []
    missing_followups: list[str] = []
    soft_prior_warnings: list[str] = []
    lifecycle_risks: list[dict[str, Any]] = []
    unsafe_overlaps: list[dict[str, Any]] = []

    pending_statuses = {"pending", "in_progress", "in-progress", "not-started", "not_started"}
    for item in task_plan[:12]:
        status = str(item.get("status", "")).strip().lower()
        desc = str(item.get("desc") or item.get("task") or item.get("label") or "").strip()
        if status in pending_statuses and desc:
            coverage_gaps.append(f"Task plan item still {status}: {desc}")

    if successful_entries and not task_plan:
        coverage_gaps.append("Patches were recorded without any durable task plan for this workflow.")

    gate_patch_tools = {
        "apply_smali_patch",
        "apply_text_patch",
        "smart_entity_patch",
        "batch_patch_methods",
        "patch_binary_hex",
        "patch_shared_prefs_reads",
        "apply_dart_aot_patch",
    }
    companion_tools = {"patch_api_response_flow", "inject_runtime_override_layer"}

    gate_like_seen = any(str(entry.get("tool", "")) in gate_patch_tools for entry in successful_entries)
    companion_seen = any(str(entry.get("tool", "")) in companion_tools for entry in successful_entries)
    if gate_like_seen and not companion_seen:
        missing_followups.append(
            "Gate-oriented patches were recorded without any response/state-boundary or runtime override companion patch; this is an evidence-backed durability warning, not a hard block."
        )

    framework_state_risk = _detect_framework_state_authority_gap(
        apktool_dir=apktool_dir,
        successful_entries=successful_entries,
        companion_seen=companion_seen,
    )
    if framework_state_risk is not None:
        missing_followups.append(framework_state_risk["warning"])

    for entry in successful_entries:
        advisory = entry.get("source_of_truth_soft_prior")
        if not isinstance(advisory, dict):
            continue
        overwrite_probability = float(advisory.get("overwrite_probability", 0.0) or 0.0)
        durability_risk = float(advisory.get("durability_risk", 0.0) or 0.0)
        surface_ref = str(advisory.get("surface_ref", "") or entry.get("description", "patch target")).strip()
        recommended_interception_ref = str(advisory.get("recommended_interception_ref", "") or "").strip()
        if overwrite_probability >= 0.55:
            lifecycle_risks.append({
                "surface_ref": surface_ref,
                "overwrite_probability": round(overwrite_probability, 3),
                "recommended_interception_ref": recommended_interception_ref,
            })
            soft_prior_warnings.append(
                "Source-of-truth soft prior flags high overwrite probability for "
                f"{surface_ref} ({overwrite_probability:.2f}); prefer upstream interception"
                + (f" via {recommended_interception_ref}" if recommended_interception_ref else "")
                + " when durability matters."
            )
            if not companion_seen:
                missing_followups.append(
                    "High overwrite probability evidence was recovered for "
                    f"{surface_ref} ({overwrite_probability:.2f}); consider upstream interception"
                    + (f" via {recommended_interception_ref}" if recommended_interception_ref else "")
                    + " before treating a gate-only patch as durable. This remains advisory only."
                )
        elif durability_risk >= 0.6:
            soft_prior_warnings.append(
                "Durability risk remains elevated for "
                f"{surface_ref} ({durability_risk:.2f}); treat the patch as potentially temporary unless lifecycle/revalidation followups are covered."
            )

    if isinstance(source_of_truth_pack, dict) and gate_like_seen:
        advisories = source_of_truth_pack.get("source_of_truth", {}).get("patch_target_advisories", [])
        if isinstance(advisories, list):
            for advisory in advisories[:2]:
                if not isinstance(advisory, dict):
                    continue
                overwrite_probability = float(advisory.get("overwrite_probability", 0.0) or 0.0)
                if overwrite_probability < 0.65:
                    continue
                soft_prior_warnings.append(
                    "Source-of-truth soft prior reports overwrite-heavy targets such as "
                    f"{advisory.get('surface_ref', '')}; use this as a warning, not a hard block."
                )
                break

    targets: dict[str, set[str]] = {}
    for entry in successful_entries:
        target = str(entry.get("target_file", "") or "").strip()
        tool = str(entry.get("tool", "unknown") or "unknown")
        if not target:
            continue
        targets.setdefault(target, set()).add(tool)

    for target, tools in sorted(targets.items()):
        if len(tools) > 1:
            unsafe_overlaps.append({
                "target_file": target,
                "tools": sorted(tools),
                "risk": "multiple_patch_tools_same_target",
            })

    score = 100
    score -= min(40, len(coverage_gaps) * 10)
    score -= min(30, len(missing_followups) * 20)
    score -= min(15, len(soft_prior_warnings) * 5)
    score -= min(15, len(lifecycle_risks) * 8)
    score -= min(20, len(unsafe_overlaps) * 10)
    score = max(0, score)

    next_actions: list[str] = []
    if coverage_gaps:
        next_actions.append("Close the remaining task-plan gaps before treating the patch set as complete.")
    if missing_followups:
        next_actions.append("Review response/state-boundary or runtime override followups before build if runtime revalidation can overwrite the patched state; this is guidance, not a forced gate.")
    if framework_state_risk is not None:
        next_actions.append(framework_state_risk["next_action"])
    if soft_prior_warnings or lifecycle_risks:
        next_actions.append("Inspect source-of-truth overwrite/lifecycle advisories before build; consider upstream interception when a patch looks temporary, but keep final patch choice with the agent.")
    if unsafe_overlaps:
        next_actions.append("Inspect files touched by multiple patch tools and confirm the final method/file state before rebuild.")

    return {
        "score": score,
        "score_advisory_only": True,
        "decision_owner": "agent",
        "evidence_mode": "evidence_first",
        "coverage_gaps": coverage_gaps,
        "unsafe_overlaps": unsafe_overlaps,
        "missing_followups": missing_followups,
        "soft_prior_warnings": soft_prior_warnings,
        "lifecycle_risks": lifecycle_risks,
        "next_actions": next_actions,
        "signals": {
            "task_plan_items": len(task_plan),
            "successful_patch_entries": len(successful_entries),
            "gate_like_seen": gate_like_seen,
            "companion_seen": companion_seen,
            "framework_bundle_state_evidence": framework_state_risk is not None and framework_state_risk["bundle_state_evidence"],
            "framework_bridge_or_mirror_patch_seen": framework_state_risk is not None and framework_state_risk["bridge_or_mirror_patch_seen"],
            "framework_state_followup_seen": framework_state_risk is not None and framework_state_risk["state_followup_seen"],
            "source_of_truth_available": isinstance(source_of_truth_pack, dict),
            "soft_prior_warning_count": len(soft_prior_warnings),
            "lifecycle_risk_count": len(lifecycle_risks),
        },
    }


def _detect_framework_state_authority_gap(
    *,
    apktool_dir: Path,
    successful_entries: list[dict[str, Any]],
    companion_seen: bool,
) -> dict[str, Any] | None:
    framework_profile = _detect_framework_state_profile(apktool_dir)
    bundle_state_evidence = framework_profile["managed_state_evidence"]
    bridge_or_mirror_patch_seen = _has_bridge_or_mirror_patch(successful_entries, framework_profile)
    state_followup_seen = companion_seen or _has_framework_state_followup(successful_entries, framework_profile)

    if not bundle_state_evidence or not bridge_or_mirror_patch_seen or state_followup_seen:
        return None

    surfaces = ", ".join(framework_profile["surface_labels"])

    return {
        "bundle_state_evidence": bundle_state_evidence,
        "bridge_or_mirror_patch_seen": bridge_or_mirror_patch_seen,
        "state_followup_seen": state_followup_seen,
        "warning": (
            "Framework-managed state evidence was found"
            + (f" ({surfaces})" if surfaces else "")
            + ", but the recorded patches still look focused on bridge/mirror layers without any bundle-side, native-runtime, or state-boundary followup; the final premium decision may still be owned by a hydrated selector, projection, native authority, or response-boundary writer rather than the patched bridge."
        ),
        "next_action": (
            "Before build, ask whether the patched class is the state authority or only a bridge/mirror. If a framework-managed runtime layer exists, inspect bundle-side selectors, native payload authorities, projections, and response-boundary writers instead of treating packaging success as proof of functional unlock."
        ),
        "surface_labels": framework_profile["surface_labels"],
    }


def _detect_framework_state_profile(apktool_dir: Path) -> dict[str, Any]:
    assets_dir = apktool_dir / "assets"
    lib_dir = apktool_dir / "lib"
    asset_files = list(assets_dir.rglob("*")) if assets_dir.is_dir() else []
    lib_files = list(lib_dir.rglob("*.so")) if lib_dir.is_dir() else []

    react_native = any(path.name in {"index.android.bundle", "index.bundle"} for path in asset_files if path.is_file())
    if not react_native:
        react_native = any(path.suffix.lower() in {".bundle", ".jsbundle", ".hbc"} for path in asset_files if path.is_file())

    flutter = (assets_dir / "flutter_assets").exists() or any(
        path.name in {"libflutter.so", "libapp.so"} for path in lib_files
    )
    unity = (assets_dir / "bin" / "Data").exists() or any(
        path.name == "global-metadata.dat" for path in asset_files if path.is_file()
    ) or any(path.name == "libil2cpp.so" for path in lib_files)

    surface_labels: list[str] = []
    if react_native:
        surface_labels.append("bundle assets")
    if flutter:
        surface_labels.append("flutter runtime/native payloads")
    if unity:
        surface_labels.append("unity il2cpp/native metadata")

    return {
        "react_native": react_native,
        "flutter": flutter,
        "unity": unity,
        "managed_state_evidence": bool(surface_labels),
        "surface_labels": surface_labels,
    }


def _has_bridge_or_mirror_patch(
    successful_entries: list[dict[str, Any]],
    framework_profile: dict[str, Any],
) -> bool:
    bridge_terms = (
        "bridge",
        "mapper",
        "module",
        "wrapper",
        "adapter",
        "projection",
        "mirror",
        "hydrat",
        "selector",
        "channel",
        "plugin",
    )
    state_terms = (
        "premium",
        "pro",
        "trial",
        "subscription",
        "purchase",
        "billing",
        "entitlement",
        "offer",
        "paywall",
        "unlock",
    )
    framework_terms = ["native"]
    if framework_profile.get("react_native"):
        framework_terms.extend(("react", "bundle", "js", "hermes"))
    if framework_profile.get("flutter"):
        framework_terms.extend(("flutter", "dart", "methodchannel", "channel", "libapp", "libflutter"))
    if framework_profile.get("unity"):
        framework_terms.extend(("unity", "il2cpp", "metadata", "player"))

    for entry in successful_entries:
        blob = " ".join(
            str(entry.get(key, "") or "")
            for key in ("tool", "target_file", "description", "target_class", "class_name")
        ).lower()
        has_bridge_term = any(term in blob for term in bridge_terms)
        has_state_term = any(term in blob for term in state_terms)
        has_framework_term = any(term in blob for term in framework_terms)
        if has_bridge_term and (has_state_term or has_framework_term):
            return True
    return False


def _has_framework_state_followup(
    successful_entries: list[dict[str, Any]],
    framework_profile: dict[str, Any],
) -> bool:
    framework_file_markers: set[str] = set()
    framework_blob_terms = {"selector", "hydrat", "offer", "trial label", "state writer"}
    if framework_profile.get("react_native"):
        framework_file_markers.update({".bundle", ".jsbundle", ".hbc"})
        framework_blob_terms.update({"bundle", "projection", "hermes"})
    if framework_profile.get("flutter"):
        framework_file_markers.update({"libapp.so", "libflutter.so"})
        framework_blob_terms.update({"libapp", "libflutter", "dart aot", "native payload", "ffi writer"})
    if framework_profile.get("unity"):
        framework_file_markers.update({"libil2cpp.so", "global-metadata.dat"})
        framework_blob_terms.update({"libil2cpp", "global-metadata", "native payload", "playerloop"})

    for entry in successful_entries:
        tool = str(entry.get("tool", "") or "").strip().lower()
        target_file = str(entry.get("target_file", "") or "").strip().lower()
        description = str(entry.get("description", "") or "").strip().lower()
        blob = " ".join((tool, target_file, description))
        if tool in {"patch_api_response_flow", "inject_runtime_override_layer"}:
            return True
        if any(marker in target_file for marker in framework_file_markers):
            return True
        if any(term in blob for term in framework_blob_terms):
            return True
    return False


def _collect_patched_files(apktool_dir: Path, backup_dir: Path, patch_journal: list[dict[str, Any]]) -> list[Path]:
    resolved: dict[str, Path] = {}

    for entry in patch_journal:
        target = str(entry.get("target_file", "") or "").strip()
        if not target or target.endswith(" files"):
            continue
        candidate = _resolve_target(apktool_dir, target)
        if candidate is not None and _candidate_differs_from_backup(apktool_dir, backup_dir, candidate):
            resolved[str(candidate)] = candidate

    if backup_dir.is_dir():
        for backup_file in backup_dir.rglob("*"):
            if not backup_file.is_file():
                continue
            rel = backup_file.relative_to(backup_dir)
            candidate = apktool_dir / rel
            if candidate.is_file() and _candidate_differs_from_backup(
                apktool_dir,
                backup_dir,
                candidate,
                backup_file=backup_file,
            ):
                resolved[str(candidate)] = candidate

    return sorted(resolved.values(), key=lambda p: p.as_posix())


def _candidate_differs_from_backup(
    apktool_dir: Path,
    backup_dir: Path,
    candidate: Path,
    *,
    backup_file: Path | None = None,
) -> bool:
    if not candidate.is_file():
        return False

    backup_match = backup_file or _find_backup_for_candidate(apktool_dir, backup_dir, candidate)
    if backup_match is None:
        return True

    try:
        return candidate.read_bytes() != backup_match.read_bytes()
    except OSError:
        return True


def _find_backup_for_candidate(apktool_dir: Path, backup_dir: Path, candidate: Path) -> Path | None:
    try:
        rel = candidate.relative_to(apktool_dir)
    except ValueError:
        return None

    direct = backup_dir / rel
    if direct.is_file():
        return direct

    flattened = backup_dir / rel.as_posix().replace("/", "_")
    if flattened.is_file():
        return flattened

    return None


def _resolve_target(apktool_dir: Path, target: str) -> Path | None:
    cleaned = target.replace("\\", "/").lstrip("/")
    if not cleaned:
        return None
    direct = apktool_dir / cleaned
    if direct.is_file():
        return direct
    if cleaned.endswith(".smali") and not cleaned.startswith("smali"):
        smali_dirs = list(apktool_dir.iterdir()) if apktool_dir.is_dir() else []
        for smali_dir in smali_dirs:
            if smali_dir.is_dir() and (smali_dir.name == "smali" or smali_dir.name.startswith("smali_classes")):
                candidate = smali_dir / cleaned
                if candidate.is_file():
                    return candidate
    return None


def _rel_to_apktool(apktool_dir: Path, path: Path) -> str:
    try:
        return str(path.relative_to(apktool_dir)).replace("\\", "/")
    except ValueError:
        return str(path)