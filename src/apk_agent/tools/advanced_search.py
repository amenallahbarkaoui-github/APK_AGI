"""Advanced search — AI-directed multi-folder search with context and cross-references.

Pure Python.  Provides advanced search capabilities beyond basic grep:
  - Search with N lines of context (like grep -C)
  - Multi-pattern search (AND/OR logic)
  - Cross-reference search (find all callers/callees of a class/method)
  - Directory-targeted search (AI picks which dirs to search)
  - Result grouping by file, class, or package
  - Package-aware filtering (exclude third-party SDKs)
"""

from __future__ import annotations

import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from apk_agent.progress import report_progress

# Shared thread pool for parallel search I/O
_ADV_SEARCH_POOL = ThreadPoolExecutor(max_workers=8)

# Smart search result cache: (query, search_type, frozenset(base_dirs)) → (timestamp, result)
_smart_search_cache: dict[tuple, tuple[float, dict]] = {}
_CACHE_TTL_SECONDS = 60.0


# ---------------------------------------------------------------------------
# Third-party package blacklist — known noise sources
# ---------------------------------------------------------------------------
THIRD_PARTY_PACKAGE_DIRS = frozenset({
    # Advertising / Analytics SDKs
    "com/madme",
    "com/adjust",
    "com/appsflyer",
    "io/branch",
    "com/mopub",
    "com/inmobi",
    "com/unity3d/ads",
    "com/chartboost",
    "com/ironsource",
    "com/vungle",
    # Google SDKs
    "com/google/android/gms",
    "com/google/firebase",
    "com/google/android/material",
    "com/google/android/play",
    "com/google/android/exoplayer",
    "com/google/android/datatransport",
    "com/google/protobuf",
    "com/google/gson",
    "com/google/common",   # Guava
    "com/google/crypto",
    # Facebook/Meta
    "com/facebook",
    "com/meta",
    # AndroidX / Jetpack
    "androidx",
    "android/support",
    # Common libraries
    "com/squareup/okhttp3",
    "com/squareup/retrofit2",
    "com/squareup/moshi",
    "com/squareup/picasso",
    "com/squareup/okio",
    "com/squareup/leakcanary",
    "com/bumptech/glide",
    "com/jakewharton",
    "io/reactivex",
    "io/realm",
    "com/airbnb",
    "org/greenrobot",
    "com/crashlytics",
    "io/sentry",
    "com/newrelic",
    "com/datadog",
    "org/apache",
    "org/json",
    "org/bouncycastle",
    "kotlin",
    "kotlinx",
    "okhttp3",
    "retrofit2",
    "dagger",
    "javax/inject",
    "butterknife",
})


def _is_third_party_path(rel_path: str) -> bool:
    """Check if a relative file path belongs to a known third-party package."""
    # Normalize separators
    normalized = rel_path.replace("\\", "/")
    for pkg_dir in THIRD_PARTY_PACKAGE_DIRS:
        if f"/{pkg_dir}/" in f"/{normalized}" or normalized.startswith(pkg_dir):
            return True
    return False


def search_with_context(
    directory: str | Path,
    pattern: str,
    context_lines: int = 3,
    file_extensions: list[str] | None = None,
    max_results: int = 30,
    case_insensitive: bool = True,
    exclude_dirs: list[str] | None = None,
    max_file_size_kb: int = 500,
    exclude_packages: bool = True,
) -> dict:
    """Search for a pattern and return matching lines with surrounding context.
    Uses parallel I/O for speed.

    Args:
        exclude_dirs: Directory names to skip (e.g. ["build", "test"]).
        max_file_size_kb: Skip files larger than this (default 500 KB).
        exclude_packages: If True, skip known third-party SDK directories.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return {"success": False, "error": f"Directory not found: {directory}"}

    if file_extensions is None:
        file_extensions = [".java", ".smali", ".xml", ".kt", ".json", ".properties"]

    _exclude = set(exclude_dirs) if exclude_dirs else set()
    _max_bytes = max_file_size_kb * 1024

    flags = re.IGNORECASE if case_insensitive else 0
    try:
        regex = re.compile(pattern, flags)
    except re.error as e:
        return {"success": False, "error": f"Invalid regex: {e}"}

    # Collect files
    file_list: list[Path] = []
    skipped_by_pkg = 0
    for root, dirs, files in os.walk(directory):
        if _exclude:
            dirs[:] = [d for d in dirs if d not in _exclude]
        for fname in files:
            if any(fname.endswith(ext) for ext in file_extensions):
                fpath = Path(root) / fname
                # Package filtering
                if exclude_packages:
                    try:
                        rel = str(fpath.relative_to(directory))
                    except ValueError:
                        rel = str(fpath)
                    if _is_third_party_path(rel):
                        skipped_by_pkg += 1
                        continue
                try:
                    if fpath.stat().st_size <= _max_bytes:
                        file_list.append(fpath)
                except OSError:
                    pass

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

    result = {
        "success": True,
        "files_searched": files_searched,
        "total_matches": len(results),
        "truncated": len(results) >= max_results,
        "results": results[:max_results],
    }
    if skipped_by_pkg > 0:
        result["third_party_files_skipped"] = skipped_by_pkg
    return result


def multi_pattern_search(
    directory: str | Path,
    patterns: list[str],
    logic: str = "OR",
    file_extensions: list[str] | None = None,
    max_results: int = 50,
    exclude_dirs: list[str] | None = None,
    max_file_size_kb: int = 500,
    exclude_packages: bool = True,
) -> dict:
    """Search for multiple patterns with AND/OR logic using parallel I/O."""
    directory = Path(directory)
    if not directory.is_dir():
        return {"success": False, "error": f"Directory not found: {directory}"}

    if file_extensions is None:
        file_extensions = [".java", ".smali", ".xml", ".kt"]

    _exclude = set(exclude_dirs) if exclude_dirs else set()
    _max_bytes = max_file_size_kb * 1024

    compiled = []
    for p in patterns:
        try:
            compiled.append(re.compile(p, re.IGNORECASE))
        except re.error as e:
            return {"success": False, "error": f"Invalid regex '{p}': {e}"}

    logic = logic.upper()

    # Collect files
    file_list: list[Path] = []
    for root, dirs, files in os.walk(directory):
        if _exclude:
            dirs[:] = [d for d in dirs if d not in _exclude]
        for fname in files:
            if any(fname.endswith(ext) for ext in file_extensions):
                fpath = Path(root) / fname
                if exclude_packages:
                    try:
                        rel = str(fpath.relative_to(directory))
                    except ValueError:
                        rel = str(fpath)
                    if _is_third_party_path(rel):
                        continue
                try:
                    if fpath.stat().st_size <= _max_bytes:
                        file_list.append(fpath)
                except OSError:
                    pass

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


# ---------------------------------------------------------------------------
# filter_results — "search in search results" to narrow down previous hits
# ---------------------------------------------------------------------------

def filter_results(
    previous_results: list[dict],
    refine_pattern: str,
    case_insensitive: bool = True,
    context_lines: int = 2,
) -> dict:
    """Narrow down a previous search result by applying a second regex filter.

    Instead of re-scanning the entire codebase, this reads ONLY the files
    that appeared in previous_results and applies a tighter regex.
    Like "search in search results" — dramatically faster for refining.

    Args:
        previous_results: List of dicts with at least a "file" key (absolute or relative paths).
        refine_pattern: New regex to apply within those files only.
        case_insensitive: Case-insensitive matching (default True).
        context_lines: Lines of context around each match.

    Returns:
        Dict with filtered matches.
    """
    flags = re.IGNORECASE if case_insensitive else 0
    try:
        regex = re.compile(refine_pattern, flags)
    except re.error as e:
        return {"success": False, "error": f"Invalid regex: {e}"}

    # Deduplicate files from previous results
    seen: set[str] = set()
    file_paths: list[str] = []
    for r in previous_results:
        fp = r.get("file", "")
        if fp and fp not in seen:
            seen.add(fp)
            file_paths.append(fp)

    ctx = context_lines
    results: list[dict] = []

    for fp in file_paths:
        path = Path(fp)
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue

        for i, line in enumerate(lines):
            if regex.search(line):
                start = max(0, i - ctx)
                end = min(len(lines), i + ctx + 1)
                context = []
                for j in range(start, end):
                    prefix = ">>>" if j == i else "   "
                    context.append(f"{prefix} {j+1:5d} | {lines[j]}")
                results.append({
                    "file": fp,
                    "line": i + 1,
                    "match": line.strip()[:300],
                    "context": "\n".join(context),
                })

    return {
        "success": True,
        "original_files": len(file_paths),
        "refined_pattern": refine_pattern,
        "total_matches": len(results),
        "results": results[:100],
    }


# ---------------------------------------------------------------------------
# batch_read_methods — read multiple method signatures from multiple files
# ---------------------------------------------------------------------------

def batch_read_methods(
    file_method_pairs: list[dict],
    base_dir: str | Path = "",
) -> dict:
    """Read specific methods from multiple smali files in one call.

    Instead of calling read_file + analyze_method_deep repeatedly, this
    extracts just the method bodies the agent needs.

    Args:
        file_method_pairs: List of {"file": "path/to/File.smali", "method": "methodName"}
        base_dir: Base directory prepended to relative file paths.

    Returns:
        Dict with method bodies keyed by file:method.
    """
    base = Path(base_dir) if base_dir else None
    methods_found: list[dict] = []

    for pair in file_method_pairs[:20]:  # Cap at 20 to avoid context explosion
        fpath = pair.get("file", "")
        method_name = pair.get("method", "")
        if not fpath or not method_name:
            continue

        p = Path(fpath)
        if not p.is_absolute() and base:
            p = base / fpath

        if not p.is_file():
            methods_found.append({
                "file": fpath, "method": method_name,
                "success": False, "error": "File not found",
            })
            continue

        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception as e:
            methods_found.append({
                "file": fpath, "method": method_name,
                "success": False, "error": str(e),
            })
            continue

        # Extract method body from smali
        in_method = False
        method_lines: list[str] = []
        method_start = 0
        for i, line in enumerate(lines):
            if not in_method:
                if f" {method_name}(" in line and line.strip().startswith(".method"):
                    in_method = True
                    method_start = i + 1
                    method_lines.append(line)
            else:
                method_lines.append(line)
                if line.strip() == ".end method":
                    break

        if method_lines:
            methods_found.append({
                "file": fpath, "method": method_name,
                "success": True,
                "start_line": method_start,
                "line_count": len(method_lines),
                "body": "\n".join(method_lines[:200]),
            })
        else:
            methods_found.append({
                "file": fpath, "method": method_name,
                "success": False, "error": f"Method '{method_name}' not found in file",
            })

    return {
        "success": True,
        "requested": len(file_method_pairs),
        "found": sum(1 for m in methods_found if m.get("success")),
        "methods": methods_found,
    }


# ---------------------------------------------------------------------------
# smart_search — one-shot intelligent search with auto-extension + auto-directory
# ---------------------------------------------------------------------------

def smart_search(
    query: str,
    base_dirs: list[Path] | None = None,
    search_type: str = "code",
    max_results: int = 30,
    exclude_packages: bool = True,
) -> dict:
    """Intelligent search that picks the right files and directories based on the query type.

    Uses parallel file scanning (ThreadPoolExecutor) and a 60-second TTL cache
    to avoid redundant disk rescans for identical queries.

    Args:
        query: The regex pattern to search for.
        base_dirs: List of directories to search (jadx_dir, apktool_dir, etc.).
        search_type: "code" | "config" | "resource" | "all"
            - code: .java, .kt, .smali only
            - config: .xml, .json, .properties, .yml
            - resource: .xml in res/ only
            - all: all file types
        max_results: Max results.
        exclude_packages: If True, skip known third-party SDK directories.

    Returns:
        Dict with matches grouped by file.
    """
    # --- Cache check ---
    cache_key = (query, search_type, frozenset(str(d) for d in (base_dirs or [])))
    now = time.monotonic()
    cached = _smart_search_cache.get(cache_key)
    if cached:
        ts, cached_result = cached
        if now - ts < _CACHE_TTL_SECONDS:
            cached_result = dict(cached_result)
            cached_result["cached"] = True
            return cached_result

    _type_extensions = {
        "code": [".java", ".kt", ".smali"],
        "config": [".xml", ".json", ".properties", ".yml"],
        "resource": [".xml"],
        "all": [".java", ".kt", ".smali", ".xml", ".json", ".properties", ".yml"],
    }
    exts = _type_extensions.get(search_type, _type_extensions["code"])

    _type_excludes = {
        "code": {"res", "build", "original", "META-INF"},
        "config": set(),
        "resource": {"smali", "smali_classes2", "smali_classes3", "smali_classes4"},
        "all": set(),
    }
    excludes = _type_excludes.get(search_type, set())

    try:
        regex = re.compile(query, re.IGNORECASE)
    except re.error as e:
        return {"success": False, "error": f"Invalid regex: {e}"}

    # --- Collect files to scan ---
    files_to_scan: list[tuple[Path, Path]] = []  # (fpath, base)
    skipped_dirs: list[str] = []
    skipped_by_pkg = 0

    for base in (base_dirs or []):
        if not Path(base).is_dir():
            skipped_dirs.append(str(base))
            continue
        for root, dirs, files in os.walk(base):
            if excludes:
                dirs[:] = [d for d in dirs if d not in excludes]
            for fname in files:
                if not any(fname.endswith(ext) for ext in exts):
                    continue
                fpath = Path(root) / fname
                if exclude_packages:
                    rel = str(fpath.relative_to(base)).replace("\\", "/")
                    if _is_third_party_path(rel):
                        skipped_by_pkg += 1
                        continue
                try:
                    if fpath.stat().st_size > 500 * 1024:
                        continue
                except OSError:
                    continue
                files_to_scan.append((fpath, base))

    # --- Parallel file scanning ---
    def _scan_file(args: tuple[Path, Path]) -> list[dict]:
        fpath, _base = args
        matches = []
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []
        for i, line in enumerate(text.splitlines(), 1):
            if regex.search(line):
                matches.append({
                    "file": str(fpath),
                    "line": i,
                    "content": line.strip()[:300],
                })
                if len(matches) >= 10:  # cap per file
                    break
        return matches

    all_results: list[dict] = []
    files_searched = len(files_to_scan)

    # Use thread pool for parallel I/O (much faster on large codebases)
    futures = {_ADV_SEARCH_POOL.submit(_scan_file, f): f for f in files_to_scan}
    for future in as_completed(futures):
        try:
            matches = future.result(timeout=30)
            all_results.extend(matches)
            if len(all_results) >= max_results:
                # Cancel remaining futures
                for f in futures:
                    f.cancel()
                break
        except Exception:
            pass

    # Trim to max_results
    all_results = all_results[:max_results]

    # Group by file
    grouped: dict[str, list] = {}
    for r in all_results:
        grouped.setdefault(r["file"], []).append({"line": r["line"], "content": r["content"]})

    result = {
        "success": True,
        "search_type": search_type,
        "query": query,
        "files_searched": files_searched,
        "files_matched": len(grouped),
        "total_matches": len(all_results),
        "results_by_file": {k: v[:10] for k, v in list(grouped.items())[:30]},
    }
    if skipped_by_pkg:
        result["third_party_files_skipped"] = skipped_by_pkg
    if skipped_dirs:
        result["warning"] = f"Directories not found (skipped): {skipped_dirs}"
    if files_searched == 0 and not skipped_dirs:
        result["hint"] = "No files matched the search_type extensions. Try search_type='all' or check the directory path."
    if len(all_results) >= max_results:
        result["truncated"] = True
        result["hint_refine"] = f"Results capped at {max_results}. Refine your query for more precise results."

    # --- Cache result ---
    _smart_search_cache[cache_key] = (now, result)

    return result
