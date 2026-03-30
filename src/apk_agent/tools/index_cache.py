"""Persistent Index & Cache — survives across agent sessions.

Builds a lightweight index of ALL classes and methods after decompilation,
and caches expensive search/scan results. Eliminates redundant file scans.

Storage:
  {project.outputs_dir}/code_index.json   — class/method metadata index
  {project.outputs_dir}/search_cache.json — cached search results

The index is built ONCE after decompilation. All subsequent queries
(class lookup, method finding, string search) hit the index first.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------
_RE_CLASS = re.compile(r"^\.class\s+.*\s+(L[\w/$]+;)", re.MULTILINE)
_RE_SUPER = re.compile(r"^\.super\s+(L[\w/$]+;)", re.MULTILINE)
_RE_INTERFACE = re.compile(r"^\.implements\s+(L[\w/$]+;)", re.MULTILINE)
_RE_METHOD = re.compile(r"^\.method\s+(.*?)([\w<>$]+)\((.*?)\)(.*?)$", re.MULTILINE)
_RE_STRING = re.compile(r'const-string(?:/jumbo)?\s+\w+,\s*"(.*?)"')
_RE_FIELD = re.compile(r"^\.field\s+(.*)", re.MULTILINE)


# ---------------------------------------------------------------------------
# Build the code index
# ---------------------------------------------------------------------------

def build_code_index(
    smali_dirs: list[Path],
    jadx_dir: Path | None = None,
    progress_callback=None,
) -> dict:
    """Build a comprehensive index of all classes/methods/strings.

    Args:
        smali_dirs: All smali directories (smali/, smali_classes2/, ...).
        jadx_dir: Optional JADX source dir for Java class cataloging.
        progress_callback: fn(percent, message).

    Returns:
        Index dict ready to be saved as JSON.
    """
    index = {
        "version": 2,
        "built_at": time.time(),
        "classes": {},        # class_name -> class_info
        "packages": {},       # package_name -> [class_names]
        "strings": {},        # string_value -> [class_names that use it]
        "method_index": {},   # method_short_name -> [full_method_names]
        "stats": {},
    }

    # Normalize to Path objects
    smali_dirs = [Path(sd) for sd in smali_dirs]
    if jadx_dir is not None:
        jadx_dir = Path(jadx_dir)

    total_files = 0
    for sd in smali_dirs:
        if sd.is_dir():
            for root, _, files in os.walk(sd):
                total_files += sum(1 for f in files if f.endswith(".smali"))

    files_scanned = 0
    total_methods = 0

    for sd in smali_dirs:
        if not sd.is_dir():
            continue
        for root, _, files in os.walk(sd):
            for fname in files:
                if not fname.endswith(".smali"):
                    continue
                files_scanned += 1

                if progress_callback and files_scanned % 50 == 0:
                    pct = files_scanned / max(total_files, 1) * 100
                    progress_callback(pct, f"Indexing: {files_scanned}/{total_files}")

                fpath = Path(root) / fname
                try:
                    text = fpath.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue

                rel_path = str(fpath.relative_to(sd))
                class_match = _RE_CLASS.search(text)
                if not class_match:
                    continue

                class_name = class_match.group(1)
                super_match = _RE_SUPER.search(text)
                super_class = super_match.group(1) if super_match else ""
                interfaces = _RE_INTERFACE.findall(text)

                # Methods
                methods = []
                for m in _RE_METHOD.finditer(text):
                    access = m.group(1).strip()
                    name = m.group(2)
                    params = m.group(3)
                    ret = m.group(4)
                    full_sig = f"{name}({params}){ret}"
                    full_name = f"{class_name}->{name}"
                    methods.append({
                        "name": name,
                        "signature": full_sig,
                        "access": access,
                    })
                    total_methods += 1
                    # Method reverse index
                    index["method_index"].setdefault(name, []).append(full_name)

                # Strings (max 30 per class)
                strings = _RE_STRING.findall(text)[:30]
                for s in strings:
                    if len(s) >= 3:  # Skip tiny strings
                        index["strings"].setdefault(s[:100], []).append(class_name)

                # Fields
                fields = [f.strip()[:100] for f in _RE_FIELD.findall(text)][:20]

                # Package
                pkg = _class_to_package(class_name)

                # Store class info
                index["classes"][class_name] = {
                    "file": rel_path,
                    "super": super_class,
                    "interfaces": interfaces,
                    "methods": methods,
                    "method_count": len(methods),
                    "fields": fields[:10],
                    "field_count": len(fields),
                    "string_count": len(strings),
                    "line_count": text.count("\n"),
                    "package": pkg,
                }

                index["packages"].setdefault(pkg, []).append(class_name)

    # Also index JADX Java files (just package + class names)
    jadx_classes = 0
    if jadx_dir and jadx_dir.is_dir():
        for root, _, files in os.walk(jadx_dir):
            for fname in files:
                if fname.endswith(".java"):
                    jadx_classes += 1

    # Trim string index to avoid huge files: keep only strings referenced by <=10 classes
    trimmed_strings = {}
    for s, classes in index["strings"].items():
        if len(classes) <= 10:
            trimmed_strings[s] = classes[:5]  # Keep max 5 class refs per string
    index["strings"] = trimmed_strings

    # Trim method index: keep only unique entries up to 10 refs
    for name in list(index["method_index"]):
        refs = index["method_index"][name]
        if len(refs) > 10:
            index["method_index"][name] = refs[:10]

    index["stats"] = {
        "total_smali_files": files_scanned,
        "total_classes": len(index["classes"]),
        "total_methods": total_methods,
        "total_packages": len(index["packages"]),
        "total_unique_strings": len(index["strings"]),
        "jadx_java_files": jadx_classes,
    }

    return index


def _class_to_package(class_name: str) -> str:
    """Convert Lcom/example/Foo; -> com.example"""
    name = class_name.strip("L;").replace("/", ".")
    parts = name.rsplit(".", 1)
    return parts[0] if len(parts) > 1 else ""


# ---------------------------------------------------------------------------
# Save / Load index
# ---------------------------------------------------------------------------

def save_index(index: dict, output_path: Path) -> dict:
    """Save code index to JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, separators=(",", ":"))
    size_kb = output_path.stat().st_size / 1024
    return {
        "success": True,
        "path": str(output_path),
        "size_kb": round(size_kb, 1),
        "classes": index["stats"]["total_classes"],
        "methods": index["stats"]["total_methods"],
        "packages": index["stats"]["total_packages"],
        "strings": index["stats"]["total_unique_strings"],
    }


def load_index(index_path: Path) -> dict | None:
    """Load code index from JSON. Returns None if not found or corrupt."""
    if not index_path.is_file():
        return None
    try:
        with open(index_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


# ---------------------------------------------------------------------------
# Query functions
# ---------------------------------------------------------------------------

def lookup_class(index: dict, query: str) -> dict:
    """Find classes matching a query string (partial match)."""
    query_lower = query.lower()
    matches = []
    for cls, info in index.get("classes", {}).items():
        if query_lower in cls.lower():
            matches.append({
                "class": cls,
                "package": info.get("package", ""),
                "file": info.get("file", ""),
                "super": info.get("super", ""),
                "interfaces": info.get("interfaces", []),
                "method_count": info.get("method_count", 0),
                "line_count": info.get("line_count", 0),
                "methods": [m["name"] for m in info.get("methods", [])][:15],
            })

    matches.sort(key=lambda m: m["method_count"], reverse=True)
    return {
        "success": True,
        "query": query,
        "total_matches": len(matches),
        "classes": matches[:30],
    }


def lookup_method(index: dict, method_name: str) -> dict:
    """Find all classes that contain a method with this name."""
    # First check method_index (exact match)
    exact = index.get("method_index", {}).get(method_name, [])

    # Also do partial match
    partial = []
    method_lower = method_name.lower()
    for name, refs in index.get("method_index", {}).items():
        if method_lower in name.lower() and name != method_name:
            partial.extend(refs)

    all_refs = list(set(exact + partial))[:50]

    # Enrich with class info
    results = []
    for ref in all_refs:
        # ref is like "Lcom/Foo;->bar"
        parts = ref.split("->")
        cls = parts[0] if parts else ""
        cls_info = index.get("classes", {}).get(cls, {})
        results.append({
            "full_name": ref,
            "class": cls,
            "file": cls_info.get("file", ""),
            "package": cls_info.get("package", ""),
        })

    return {
        "success": True,
        "query": method_name,
        "exact_matches": len(exact),
        "total_matches": len(results),
        "methods": results[:30],
    }


def lookup_string(index: dict, query: str) -> dict:
    """Find classes that use a specific string constant."""
    query_lower = query.lower()
    matches = []
    for s, classes in index.get("strings", {}).items():
        if query_lower in s.lower():
            matches.append({
                "string": s,
                "used_by": classes,
            })

    matches.sort(key=lambda m: len(m["used_by"]), reverse=True)
    return {
        "success": True,
        "query": query,
        "total_matches": len(matches),
        "results": matches[:30],
    }


def lookup_package(index: dict, package_name: str) -> dict:
    """List all classes in a package."""
    pkg_lower = package_name.lower()
    matches = {}
    for pkg, classes in index.get("packages", {}).items():
        if pkg_lower in pkg.lower():
            matches[pkg] = classes[:50]

    return {
        "success": True,
        "query": package_name,
        "packages_found": len(matches),
        "packages": matches,
    }


def get_index_stats(index: dict) -> dict:
    """Get overview stats of the index."""
    return {
        "success": True,
        **index.get("stats", {}),
        "built_at": index.get("built_at", 0),
        "version": index.get("version", 0),
    }


# ---------------------------------------------------------------------------
# Search cache
# ---------------------------------------------------------------------------

class SearchCache:
    """Simple persistent cache for expensive search results."""

    def __init__(self, cache_path: Path):
        self.cache_path = cache_path
        self._cache: dict = {}
        self._load()

    def _load(self):
        if self.cache_path.is_file():
            try:
                with open(self.cache_path, "r", encoding="utf-8") as f:
                    self._cache = json.load(f)
            except (json.JSONDecodeError, OSError):
                self._cache = {}

    def _save(self):
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.cache_path, "w", encoding="utf-8") as f:
            json.dump(self._cache, f, ensure_ascii=False, separators=(",", ":"))

    def _make_key(self, tool_name: str, args: dict) -> str:
        """Create a stable cache key from tool name + args."""
        raw = f"{tool_name}:{json.dumps(args, sort_keys=True)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def get(self, tool_name: str, args: dict) -> str | None:
        """Get cached result. Returns None on miss."""
        key = self._make_key(tool_name, args)
        entry = self._cache.get(key)
        if entry is None:
            return None
        # Check TTL (default 1 hour)
        if time.time() - entry.get("ts", 0) > 3600:
            del self._cache[key]
            return None
        return entry.get("result")

    def put(self, tool_name: str, args: dict, result: str):
        """Store a result in cache."""
        key = self._make_key(tool_name, args)
        self._cache[key] = {
            "tool": tool_name,
            "ts": time.time(),
            "result": result,
        }
        # Keep cache bounded
        if len(self._cache) > 200:
            # Remove oldest entries
            sorted_keys = sorted(
                self._cache.keys(),
                key=lambda k: self._cache[k].get("ts", 0),
            )
            for k in sorted_keys[:50]:
                del self._cache[k]
        self._save()

    def clear(self):
        """Clear the cache."""
        self._cache = {}
        if self.cache_path.is_file():
            self.cache_path.unlink()

    def stats(self) -> dict:
        """Cache statistics."""
        return {
            "entries": len(self._cache),
            "path": str(self.cache_path),
            "size_kb": round(self.cache_path.stat().st_size / 1024, 1) if self.cache_path.is_file() else 0,
        }
