"""Reporting engine — generates Markdown reports from agent state."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def generate_report(
    task: str,
    apk_name: str,
    findings: list[dict[str, Any]],
    patch_results: list[dict[str, Any]],
    tool_history: list[dict[str, Any]] | None = None,
    output_path: str | Path | None = None,
) -> str:
    """Generate a Markdown security/RE report.

    Args:
        task: The user's original task description.
        apk_name: Name of the APK file.
        findings: Structured findings from static analysis.
        patch_results: Results of applied patches.
        tool_history: Optional list of tool execution summaries.
        output_path: If provided, write report to this file.

    Returns:
        The report as a Markdown string.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sections: list[str] = []

    # ---- Header ----
    sections.append(f"# APK Static Analysis Report")
    sections.append(f"")
    sections.append(f"| Field | Value |")
    sections.append(f"|-------|-------|")
    sections.append(f"| **APK** | `{apk_name}` |")
    sections.append(f"| **Task** | {task} |")
    sections.append(f"| **Date** | {now} |")
    sections.append(f"| **Tool** | APK Agent v0.1.0 |")
    sections.append(f"")

    # ---- Executive Summary ----
    sections.append(f"## Executive Summary")
    sections.append(f"")
    n_findings = len(findings)
    n_patches = len(patch_results)
    n_success = sum(1 for p in patch_results if p.get("success"))
    sections.append(
        f"Static analysis of `{apk_name}` identified **{n_findings}** finding(s). "
        f"**{n_patches}** patch operation(s) were attempted, of which **{n_success}** succeeded."
    )
    sections.append(f"")

    # ---- Findings ----
    if findings:
        sections.append(f"## Findings")
        sections.append(f"")
        for i, f in enumerate(findings, 1):
            severity = f.get("severity", "INFO")
            category = f.get("category", "General")
            title = f.get("title", "Finding")
            description = f.get("description", "")
            location = f.get("location", "")
            evidence = f.get("evidence", "")

            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "ℹ️"}.get(
                severity.upper(), "ℹ️"
            )
            sections.append(f"### {icon} Finding {i}: {title}")
            sections.append(f"")
            sections.append(f"| | |")
            sections.append(f"|---|---|")
            sections.append(f"| **Severity** | {severity} |")
            sections.append(f"| **Category** | {category} |")
            if location:
                sections.append(f"| **Location** | `{location}` |")
            sections.append(f"")
            if description:
                sections.append(description)
                sections.append(f"")
            if evidence:
                sections.append("**Evidence:**")
                sections.append(f"```")
                sections.append(evidence[:2000])
                sections.append(f"```")
                sections.append(f"")

    # ---- Patches Applied ----
    if patch_results:
        sections.append(f"## Patches Applied")
        sections.append(f"")
        for i, p in enumerate(patch_results, 1):
            status = "✅" if p.get("success") else "❌"
            target = p.get("target_file", "unknown")
            tool_name = p.get("tool", "")
            header = f"`{target}`" if not tool_name else f"`{target}` ({tool_name})"
            sections.append(f"### {status} Patch {i}: {header}")
            sections.append(f"")
            if p.get("description"):
                sections.append(p["description"])
                sections.append(f"")
            sections.append(f"- Steps applied: {p.get('steps_applied', 0)}/{p.get('steps_total', 0)}")
            if p.get("errors"):
                sections.append(f"- Errors: {'; '.join(p['errors'])}")
            sections.append(f"")
            if p.get("diff_text"):
                sections.append("**Diff:**")
                sections.append(f"```diff")
                sections.append(p["diff_text"][:5000])
                sections.append(f"```")
                sections.append(f"")

    # ---- Tool Execution Log ----
    if tool_history:
        sections.append(f"## Tool Execution Log")
        sections.append(f"")
        sections.append(f"| # | Tool | Status | Duration |")
        sections.append(f"|---|------|--------|----------|")
        for i, t in enumerate(tool_history, 1):
            status = "✅" if t.get("success") else "❌"
            name = t.get("tool", "unknown")
            dur = t.get("duration", "?")
            sections.append(f"| {i} | {name} | {status} | {dur}s |")
        sections.append(f"")

    # ---- Limitations ----
    sections.append(f"## Limitations & Recommendations")
    sections.append(f"")
    sections.append(
        "- This report is based on **static analysis only**. "
        "Runtime behaviour may differ."
    )
    sections.append(
        "- Obfuscated code may produce incomplete or inaccurate findings."
    )
    sections.append(
        "- Patched APKs should be manually tested on a device/emulator "
        "to verify correct behaviour."
    )
    sections.append(
        "- Ensure you have legal authorization to reverse-engineer "
        "and modify the target APK."
    )
    sections.append(f"")
    sections.append(f"---")
    sections.append(f"*Generated by APK Agent v0.1.0*")

    report = "\n".join(sections)

    if output_path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(report, encoding="utf-8")

    return report
