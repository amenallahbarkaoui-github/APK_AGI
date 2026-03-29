"""File operation tools — let the LLM read/search decompiled code."""

from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from apk_agent.progress import report_progress
from pathlib import Path

# Thread pool shared across searches (file I/O bound)
_SEARCH_POOL = ThreadPoolExecutor(max_workers=8)


def read_file(path: str | Path, max_lines: int = 500) -> dict:
    """Read a text file and return its content (truncated for LLM)."""
    path = Path(path)
    if not path.is_file():
        return {"success": False, "error": f"File not found: {path}"}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        truncated = len(lines) > max_lines
        if truncated:
            content = "\n".join(lines[:max_lines])
            content += f"\n\n... [{len(lines) - max_lines} more lines truncated] ..."
        else:
            content = text
        return {
            "success": True,
            "path": str(path),
            "total_lines": len(lines),
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
) -> dict:
    """Grep-like search across files in a directory using parallel I/O."""
    directory = Path(directory)
    if not directory.is_dir():
        return {"success": False, "error": f"Directory not found: {directory}"}

    if file_extensions is None:
        file_extensions = [".java", ".kt", ".smali"]

    flags = re.IGNORECASE if case_insensitive else 0
    try:
        regex = re.compile(pattern, flags)
    except re.error as e:
        return {"success": False, "error": f"Invalid regex pattern: {e}"}

    # Collect files to search
    file_list: list[Path] = []
    for root, _dirs, files in os.walk(directory):
        for fname in files:
            if any(fname.endswith(ext) for ext in file_extensions):
                file_list.append(Path(root) / fname)

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
