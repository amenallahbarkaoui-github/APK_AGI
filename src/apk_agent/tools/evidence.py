"""Evidence Collector — forensic notebook for the agent.

Provides a persistent evidence store where the agent saves every clue,
finding, file path, and analysis result it discovers. The evidence file
lives inside the project workspace so it survives across sessions.

The agent can:
  - save_evidence()     — append a new finding/clue
  - load_evidence()     — load all saved evidence (for context recovery)
  - search_evidence()   — search within saved evidence
  - get_evidence_summary() — get a compact summary of all evidence
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _evidence_file(project_path: str | Path) -> Path:
    return Path(project_path) / "outputs" / "evidence.jsonl"


def save_evidence(
    project_path: str | Path,
    category: str,
    title: str,
    detail: str,
    severity: str = "info",
    file_path: str = "",
    line_number: int = 0,
    tags: list[str] | None = None,
    raw_data: dict | None = None,
) -> dict:
    """Append a piece of evidence to the forensic notebook.

    Categories: vuln, crypto, network, permission, component, string,
                pattern, patch, file, config, behavior, misc
    Severity: critical, high, medium, low, info
    """
    entry = {
        "id": int(time.time() * 1000),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "category": category,
        "severity": severity,
        "title": title,
        "detail": detail,
        "file_path": file_path,
        "line_number": line_number,
        "tags": tags or [],
    }
    if raw_data:
        entry["raw_data"] = raw_data

    ef = _evidence_file(project_path)
    ef.parent.mkdir(parents=True, exist_ok=True)
    with open(ef, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    return {"success": True, "evidence_id": entry["id"], "total": _count_lines(ef)}


def load_evidence(project_path: str | Path, category: str = "", severity: str = "") -> dict:
    """Load all saved evidence, optionally filtered by category/severity."""
    ef = _evidence_file(project_path)
    if not ef.is_file():
        return {"success": True, "count": 0, "evidence": []}

    entries = []
    for line in ef.read_text(encoding="utf-8").strip().splitlines():
        try:
            entry = json.loads(line)
            if category and entry.get("category") != category:
                continue
            if severity and entry.get("severity") != severity:
                continue
            entries.append(entry)
        except json.JSONDecodeError:
            continue

    return {"success": True, "count": len(entries), "evidence": entries}


def search_evidence(project_path: str | Path, query: str) -> dict:
    """Search within saved evidence by keyword."""
    ef = _evidence_file(project_path)
    if not ef.is_file():
        return {"success": True, "count": 0, "results": []}

    query_lower = query.lower()
    results = []
    for line in ef.read_text(encoding="utf-8").strip().splitlines():
        try:
            entry = json.loads(line)
            searchable = json.dumps(entry, ensure_ascii=False).lower()
            if query_lower in searchable:
                results.append(entry)
        except json.JSONDecodeError:
            continue

    return {"success": True, "count": len(results), "results": results}


def get_evidence_summary(project_path: str | Path) -> dict:
    """Get a compact summary of all evidence — counts by category and severity."""
    ef = _evidence_file(project_path)
    if not ef.is_file():
        return {"success": True, "total": 0, "by_category": {}, "by_severity": {}, "critical_findings": []}

    by_cat: dict[str, int] = {}
    by_sev: dict[str, int] = {}
    critical: list[dict] = []
    total = 0

    for line in ef.read_text(encoding="utf-8").strip().splitlines():
        try:
            entry = json.loads(line)
            total += 1
            cat = entry.get("category", "misc")
            sev = entry.get("severity", "info")
            by_cat[cat] = by_cat.get(cat, 0) + 1
            by_sev[sev] = by_sev.get(sev, 0) + 1
            if sev in ("critical", "high"):
                critical.append({
                    "title": entry.get("title", ""),
                    "severity": sev,
                    "category": cat,
                    "file_path": entry.get("file_path", ""),
                })
        except json.JSONDecodeError:
            continue

    return {
        "success": True,
        "total": total,
        "by_category": by_cat,
        "by_severity": by_sev,
        "critical_findings": critical[:30],
    }


def _count_lines(path: Path) -> int:
    if not path.is_file():
        return 0
    return sum(1 for _ in open(path, encoding="utf-8"))
