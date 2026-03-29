"""Advanced search — AI-directed multi-folder search with context and cross-references.

Pure Python.  Provides advanced search capabilities beyond basic grep:
  - Search with N lines of context (like grep -C)
  - Multi-pattern search (AND/OR logic)
  - Cross-reference search (find all callers/callees of a class/method)
  - Directory-targeted search (AI picks which dirs to search)
  - Result grouping by file, class, or package
"""

from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from apk_agent.progress import report_progress

# Shared thread pool for parallel search I/O
_ADV_SEARCH_POOL = ThreadPoolExecutor(max_workers=8)


def search_with_context(
    directory: str | Path,
    pattern: str,
    context_lines: int = 3,
    file_extensions: list[str] | None = None,
    max_results: int = 30,
    case_insensitive: bool = True,
) -> dict:
    """Search for a pattern and return matching lines with surrounding context.
    Uses parallel I/O for speed.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return {"success": False, "error": f"Directory not found: {directory}"}

    if file_extensions is None:
        file_extensions = [".java", ".kt", ".smali"]

    flags = re.IGNORECASE if case_insensitive else 0
    try:
        regex = re.compile(pattern, flags)
    except re.error as e:
        return {"success": False, "error": f"Invalid regex: {e}"}

    # Collect files
    file_list: list[Path] = []
    for root, _, files in os.walk(directory):
        for fname in files:
            if any(fname.endswith(ext) for ext in file_extensions):
                file_list.append(Path(root) / fname)

    total_files = len(file_list)
    if total_files == 0:
        return {"success": True, "files_searched": 0, "total_matches": 0,
                "truncated": False, "results": []}

    ctx = context_lines

    def _search_one(fpath: Path) -> list[dict]:
        hits = []
        try:
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return hits

        rel = str(fpath.relative_to(directory))
        for i, line in enumerate(lines):
            if regex.search(line):
                start = max(0, i - ctx)
                end = min(len(lines), i + ctx + 1)
                context = []
                for j in range(start, end):
                    prefix = ">>>" if j == i else "   "
                    context.append(f"{prefix} {j+1:5d} | {lines[j]}")
                hits.append({
                    "file": rel,
                    "line": i + 1,
                    "match": line.strip()[:300],
                    "context": "\n".join(context),
                })
        return hits

    results: list[dict] = []
    files_searched = 0

    futures = {_ADV_SEARCH_POOL.submit(_search_one, fp): fp for fp in file_list}
    for future in as_completed(futures):
        hits = future.result()
        files_searched += 1
        if hits:
            results.extend(hits)
        if files_searched % 50 == 0 or files_searched == total_files:
            pct = files_searched / total_files * 100
            report_progress(pct, f"{files_searched}/{total_files} files | {len(results)} matches")
        if len(results) >= max_results:
            break

    return {
        "success": True,
        "files_searched": files_searched,
        "total_matches": len(results),
        "truncated": len(results) >= max_results,
        "results": results[:max_results],
    }


def multi_pattern_search(
    directory: str | Path,
    patterns: list[str],
    logic: str = "OR",
    file_extensions: list[str] | None = None,
    max_results: int = 50,
) -> dict:
    """Search for multiple patterns with AND/OR logic using parallel I/O."""
    directory = Path(directory)
    if not directory.is_dir():
        return {"success": False, "error": f"Directory not found: {directory}"}

    if file_extensions is None:
        file_extensions = [".java", ".kt", ".smali"]

    compiled = []
    for p in patterns:
        try:
            compiled.append(re.compile(p, re.IGNORECASE))
        except re.error as e:
            return {"success": False, "error": f"Invalid regex '{p}': {e}"}

    logic = logic.upper()

    # Collect files
    file_list: list[Path] = []
    for root, _, files in os.walk(directory):
        for fname in files:
            if any(fname.endswith(ext) for ext in file_extensions):
                file_list.append(Path(root) / fname)

    total_files = len(file_list)

    def _scan_one(fpath: Path) -> dict | None:
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None

        lines = text.splitlines()
        matches_per_pattern: list[list[dict]] = []
        for regex in compiled:
            found = []
            for j, line in enumerate(lines, 1):
                if regex.search(line):
                    found.append({"line": j, "content": line.strip()[:200]})
            matches_per_pattern.append(found)

        has_matches = [bool(m) for m in matches_per_pattern]
        rel = str(fpath.relative_to(directory))

        if logic == "AND" and all(has_matches):
            file_result = {"file": rel, "pattern_matches": {}}
            for i, p in enumerate(patterns):
                file_result["pattern_matches"][p] = matches_per_pattern[i][:5]
            return file_result
        elif logic == "OR" and any(has_matches):
            matched_patterns = {}
            for i, p in enumerate(patterns):
                if has_matches[i]:
                    matched_patterns[p] = matches_per_pattern[i][:5]
            return {"file": rel, "pattern_matches": matched_patterns}
        return None

    results: list[dict] = []
    files_searched = 0

    futures = {_ADV_SEARCH_POOL.submit(_scan_one, fp): fp for fp in file_list}
    for future in as_completed(futures):
        hit = future.result()
        files_searched += 1
        if hit is not None:
            results.append(hit)
        if files_searched % 50 == 0 or files_searched == total_files:
            pct = files_searched / total_files * 100
            report_progress(pct, f"{files_searched}/{total_files} files | {len(results)} matched")
        if len(results) >= max_results:
            break

    return {
        "success": True,
        "logic": logic,
        "patterns": patterns,
        "files_searched": files_searched,
        "files_matched": len(results),
        "results": results,
    }


def cross_reference_search(
    directory: str | Path,
    class_or_method: str,
    search_type: str = "callers",
    file_extensions: list[str] | None = None,
    max_results: int = 50,
) -> dict:
    """Find cross-references — who calls or is called by a class/method.
    Uses parallel I/O.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return {"success": False, "error": f"Directory not found: {directory}"}

    if file_extensions is None:
        file_extensions = [".java", ".smali"]

    # Collect files
    file_list: list[Path] = []
    for root, _, files in os.walk(directory):
        for fname in files:
            if any(fname.endswith(ext) for ext in file_extensions):
                file_list.append(Path(root) / fname)

    total_files = len(file_list)
    target = class_or_method
    call_pattern = re.compile(
        r"invoke-\w+\s+.*?(L[\w/$]+;)->(\w+)|"
        r"(\w+(?:\.\w+)+)\s*\.\s*(\w+)\s*\(",
    )

    def _scan_one(fpath: Path) -> tuple[list[dict], str | None]:
        """Returns (refs, source_file_or_none)."""
        refs = []
        source = None
        try:
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return refs, source

        rel = str(fpath.relative_to(directory))

        if search_type == "callers":
            is_definition = (
                target in fpath.name
                or any(f".class " in l and target in l for l in lines[:5])
            )
            if is_definition:
                return refs, rel  # source file

            for i, line in enumerate(lines, 1):
                if target in line:
                    refs.append({
                        "file": rel, "line": i,
                        "content": line.strip()[:300], "type": "reference",
                    })
                    if len(refs) >= max_results:
                        break
        else:  # callees
            is_target = (
                target in fpath.name
                or any("class " in l and target in l for l in lines[:10])
            )
            if not is_target:
                return refs, None

            source = rel
            for i, line in enumerate(lines, 1):
                if call_pattern.search(line):
                    refs.append({
                        "file": rel, "line": i,
                        "content": line.strip()[:300], "type": "outgoing_call",
                    })
                    if len(refs) >= max_results:
                        break

        return refs, source

    results: list[dict] = []
    source_files: list[str] = []
    files_searched = 0

    futures = {_ADV_SEARCH_POOL.submit(_scan_one, fp): fp for fp in file_list}
    for future in as_completed(futures):
        refs, src = future.result()
        files_searched += 1
        if src:
            source_files.append(src)
        if refs:
            results.extend(refs)
        if files_searched % 50 == 0 or files_searched == total_files:
            pct = files_searched / total_files * 100
            report_progress(pct, f"{files_searched}/{total_files} files | {len(results)} refs")
        if len(results) >= max_results:
            break

    return {
        "success": True,
        "search_type": search_type,
        "target": class_or_method,
        "files_searched": files_searched,
        "source_files": source_files[:10],
        "total_references": len(results),
        "results": results,
    }


def directory_stats(directory: str | Path) -> dict:
    """Get statistics about a directory — file counts, sizes, types.

    Useful for the AI to decide which directories to search.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return {"success": False, "error": f"Directory not found: {directory}"}

    ext_counts: dict[str, int] = {}
    ext_sizes: dict[str, int] = {}
    total_files = 0
    total_size = 0
    top_dirs: list[dict] = []

    # Count top-level dirs
    for item in sorted(directory.iterdir()):
        if item.is_dir():
            dir_count = sum(1 for _ in item.rglob("*") if _.is_file())
            top_dirs.append({"name": item.name, "file_count": dir_count})

    for root, _, files in os.walk(directory):
        for fname in files:
            fpath = Path(root) / fname
            total_files += 1
            try:
                size = fpath.stat().st_size
            except OSError:
                size = 0
            total_size += size

            ext = fpath.suffix.lower()
            ext_counts[ext] = ext_counts.get(ext, 0) + 1
            ext_sizes[ext] = ext_sizes.get(ext, 0) + size

    return {
        "success": True,
        "directory": str(directory),
        "total_files": total_files,
        "total_size_mb": round(total_size / (1024 * 1024), 2),
        "file_types": dict(sorted(ext_counts.items(), key=lambda x: -x[1])[:20]),
        "top_directories": sorted(top_dirs, key=lambda x: -x["file_count"])[:20],
    }
