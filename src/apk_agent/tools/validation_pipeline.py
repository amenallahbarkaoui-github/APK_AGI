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
        patch_journal=patch_journal,
        task_plan=list(task_plan or []),
    )
    next_actions.extend(
        action for action in plan_consistency["next_actions"]
        if action not in next_actions
    )

    return {
        "success": True,
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
    patch_journal: list[dict[str, Any]],
    task_plan: list[dict[str, Any]],
) -> dict[str, Any]:
    successful_entries = [entry for entry in patch_journal if entry.get("success", True)]
    coverage_gaps: list[str] = []
    missing_followups: list[str] = []
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
            "Gate-oriented patches were recorded without any response/state-boundary or runtime override companion patch."
        )

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
    score -= min(20, len(unsafe_overlaps) * 10)
    score = max(0, score)

    next_actions: list[str] = []
    if coverage_gaps:
        next_actions.append("Close the remaining task-plan gaps before treating the patch set as complete.")
    if missing_followups:
        next_actions.append("Review response/state-boundary or runtime override followups before build if runtime revalidation can overwrite the patched state.")
    if unsafe_overlaps:
        next_actions.append("Inspect files touched by multiple patch tools and confirm the final method/file state before rebuild.")

    return {
        "score": score,
        "coverage_gaps": coverage_gaps,
        "unsafe_overlaps": unsafe_overlaps,
        "missing_followups": missing_followups,
        "next_actions": next_actions,
        "signals": {
            "task_plan_items": len(task_plan),
            "successful_patch_entries": len(successful_entries),
            "gate_like_seen": gate_like_seen,
            "companion_seen": companion_seen,
        },
    }


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