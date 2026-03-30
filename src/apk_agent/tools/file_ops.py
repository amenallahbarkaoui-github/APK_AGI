"""File operation tools — let the LLM read/search decompiled code."""

from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from apk_agent.progress import report_progress
from pathlib import Path

# Thread pool shared across searches (file I/O bound)
_SEARCH_POOL = ThreadPoolExecutor(max_workers=8)


def read_file(path: str | Path, max_lines: int = 500, start_line: int = 0, end_line: int = 0) -> dict:
    """Read a text file and return its content (truncated for LLM).
    
    Args:
        path: File path.
        max_lines: Max total lines to return (default 500). Ignored if start_line/end_line set.
        start_line: 1-based start line for reading a specific range. 0 = from beginning.
        end_line: 1-based end line for reading a specific range. 0 = to max_lines.
    """
    path = Path(path)
    if not path.is_file():
        return {"success": False, "error": f"File not found: {path}"}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        total = len(lines)

        # Range mode: specific line range
        if start_line > 0:
            s = max(0, start_line - 1)
            e = end_line if end_line > 0 else s + max_lines
            content = "\n".join(lines[s:e])
            truncated = e < total
            return {
                "success": True,
                "path": str(path),
                "total_lines": total,
                "showing": f"{s+1}-{min(e, total)}",
                "truncated": truncated,
                "content": content,
            }

        truncated = total > max_lines
        if truncated:
            content = "\n".join(lines[:max_lines])
            content += f"\n\n... [{total - max_lines} more lines truncated] ..."
        else:
            content = text
        return {
            "success": True,
            "path": str(path),
            "total_lines": total,
            "truncated": truncated,
            "content": content,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def search_in_files(
    directory: str | Path,
    pattern: str,
    file_extensions: list[str] | None = None,
    max_results: int = 50,
    case_insensitive: bool = True,
    exclude_dirs: list[str] | None = None,
    max_file_size_kb: int = 500,
) -> dict:
    """Grep-like search across files in a directory using parallel I/O.

    Args:
        directory: Root directory to search.
        pattern: Regex pattern.
        file_extensions: Extensions to include (default: code files only).
        max_results: Cap on total matches.
        case_insensitive: Case-insensitive matching (default True).
        exclude_dirs: Directory names to skip (e.g. ["build", "test", "res"]).
        max_file_size_kb: Skip files larger than this (default 500 KB). Avoids huge generated files.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return {"success": False, "error": f"Directory not found: {directory}"}

    if file_extensions is None:
        file_extensions = [".java", ".smali", ".xml", ".json", ".properties"]

    _exclude = set(exclude_dirs) if exclude_dirs else set()
    _max_bytes = max_file_size_kb * 1024

    flags = re.IGNORECASE if case_insensitive else 0
    try:
        regex = re.compile(pattern, flags)
    except re.error as e:
        return {"success": False, "error": f"Invalid regex pattern: {e}"}

    # Collect files to search
    file_list: list[Path] = []
    for root, dirs, files in os.walk(directory):
        # Prune excluded directories (mutate dirs in-place for os.walk)
        if _exclude:
            dirs[:] = [d for d in dirs if d not in _exclude]
        for fname in files:
            if any(fname.endswith(ext) for ext in file_extensions):
                fpath = Path(root) / fname
                try:
                    if fpath.stat().st_size <= _max_bytes:
                        file_list.append(fpath)
                except OSError:
                    pass

    total_files = len(file_list)
    if total_files == 0:
        return {"success": True, "pattern": pattern, "files_searched": 0,
                "total_matches": 0, "truncated": False, "matches": []}

    all_matches: list[dict] = []
    files_done = 0
    early_stop = False

    def _search_one(fpath: Path) -> list[dict]:
        hits = []
        try:
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
            for i, line in enumerate(lines, 1):
                if regex.search(line):
                    hits.append({
                        "file": str(fpath),
                        "line_number": i,
                        "line": line.strip()[:300],
                    })
        except Exception:
            pass
        return hits

    futures = {_SEARCH_POOL.submit(_search_one, fp): fp for fp in file_list}
    for future in as_completed(futures):
        if early_stop:
            break
        hits = future.result()
        files_done += 1
        if hits:
            all_matches.extend(hits)
        if files_done % 50 == 0 or files_done == total_files:
            pct = files_done / total_files * 100
            report_progress(pct, f"{files_done}/{total_files} files | {len(all_matches)} matches")
        if len(all_matches) >= max_results:
            early_stop = True

    return {
        "success": True,
        "pattern": pattern,
        "files_searched": files_done,
        "total_matches": len(all_matches),
        "truncated": len(all_matches) >= max_results,
        "matches": all_matches[:max_results],
    }


def list_directory(
    directory: str | Path,
    max_depth: int = 2,
    file_extensions: list[str] | None = None,
) -> dict:
    """List directory contents up to a max depth."""
    directory = Path(directory)
    if not directory.is_dir():
        return {"success": False, "error": f"Directory not found: {directory}"}

    entries = []
    _walk_dir(directory, directory, 0, max_depth, file_extensions, entries, max_entries=200)
    return {
        "success": True,
        "root": str(directory),
        "total_entries": len(entries),
        "entries": entries,
    }


def _walk_dir(
    root: Path,
    current: Path,
    depth: int,
    max_depth: int,
    extensions: list[str] | None,
    entries: list,
    max_entries: int,
) -> None:
    if depth > max_depth or len(entries) >= max_entries:
        return
    try:
        for item in sorted(current.iterdir()):
            if len(entries) >= max_entries:
                return
            rel = str(item.relative_to(root))
            if item.is_dir():
                entries.append({"path": rel, "type": "dir"})
                _walk_dir(root, item, depth + 1, max_depth, extensions, entries, max_entries)
            else:
                if extensions and not any(item.name.endswith(ext) for ext in extensions):
                    continue
                entries.append({
                    "path": rel,
                    "type": "file",
                    "size_kb": round(item.stat().st_size / 1024, 1),
                })
    except PermissionError:
        pass
