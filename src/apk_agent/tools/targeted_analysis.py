"""Targeted analysis tools for encrypted API payloads.

Provides focused searches for:
  - Network interceptors (OkHttp/Retrofit) that encrypt/decrypt payloads
  - Native JNI bridges that may hide crypto in .so libs
  - Dynamic code loading (Runtime DexClassLoader) that hides logic
"""

from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from apk_agent.progress import report_progress

_POOL = ThreadPoolExecutor(max_workers=8)

# ---- Code-only extensions used across all scanners ----
_CODE_EXTS = (".java", ".kt", ".smali")


# ---------------------------------------------------------------------------
# 1.  Network-layer interceptor scanner
# ---------------------------------------------------------------------------

_INTERCEPTOR_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("OkHttp Interceptor impl",    re.compile(r"implements\s+Interceptor", re.I)),
    ("chain.proceed call",         re.compile(r"chain\s*\.\s*proceed\s*\(", re.I)),
    ("RequestBody usage",          re.compile(r"RequestBody\s*\.", re.I)),
    ("ResponseBody usage",         re.compile(r"ResponseBody\s*\.", re.I)),
    ("Retrofit @Body annotation",  re.compile(r"@Body", re.I)),
    ("OkHttp addInterceptor",      re.compile(r"addInterceptor\s*\(", re.I)),
    ("OkHttp addNetworkInterceptor", re.compile(r"addNetworkInterceptor\s*\(", re.I)),
    ("OkHttpClient.Builder",       re.compile(r"OkHttpClient\s*\.\s*Builder", re.I)),
    ("HttpLoggingInterceptor",     re.compile(r"HttpLoggingInterceptor", re.I)),
    # Smali equivalents
    ("Smali Interceptor invoke",   re.compile(r"Lokhttp3/Interceptor", re.I)),
    ("Smali chain->proceed",       re.compile(r"Lokhttp3/Interceptor\$Chain;->proceed", re.I)),
    ("Smali RequestBody",          re.compile(r"Lokhttp3/RequestBody", re.I)),
    ("Smali ResponseBody",         re.compile(r"Lokhttp3/ResponseBody", re.I)),
    # Crypto inside network layer (common in payload encryption)
    ("Cipher in file",             re.compile(r"import\s+javax\.crypto\.Cipher|Ljavax/crypto/Cipher", re.I)),
    ("SecretKeySpec in file",      re.compile(r"import\s+javax\.crypto\.spec\.SecretKeySpec|Ljavax/crypto/spec/SecretKeySpec", re.I)),
    ("Base64 encode/decode",       re.compile(r"Base64\s*\.\s*(encode|decode)|Landroid/util/Base64;->", re.I)),
]


def search_network_interceptors(
    directory: str | Path,
    max_results: int = 40,
) -> dict:
    """Find OkHttp/Retrofit interceptors and network-layer encryption.

    Searches ONLY code files (.java, .kt, .smali) for interceptor patterns:
    implements Interceptor, chain.proceed(, RequestBody, ResponseBody,
    addInterceptor(), and crypto imports co-located with network code.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return {"success": False, "error": f"Directory not found: {directory}"}

    file_list = _collect_code_files(directory)
    total = len(file_list)
    if total == 0:
        return {"success": True, "files_searched": 0, "interceptors": [], "crypto_in_network": []}

    interceptor_files: list[dict] = []   # files implementing Interceptor
    crypto_network: list[dict] = []      # files with BOTH crypto + network

    def _scan(fpath: Path) -> dict | None:
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None

        rel = str(fpath.relative_to(directory))
        hits: dict[str, list[dict]] = {}
        lines = text.splitlines()

        for label, regex in _INTERCEPTOR_PATTERNS:
            for i, line in enumerate(lines, 1):
                if regex.search(line):
                    hits.setdefault(label, []).append({"line": i, "text": line.strip()[:200]})

        if not hits:
            return None

        return {"file": rel, "hits": hits}

    results: list[dict] = []
    searched = 0
    futures = {_POOL.submit(_scan, fp): fp for fp in file_list}
    for future in as_completed(futures):
        searched += 1
        r = future.result()
        if r:
            results.append(r)
        if searched % 50 == 0 or searched == total:
            report_progress(searched / total * 100, f"{searched}/{total} files")
        if len(results) >= max_results:
            break

    # Classify results
    for r in results:
        labels = set(r["hits"].keys())
        is_interceptor = any("Interceptor" in l or "chain.proceed" in l for l in labels)
        has_crypto = any("Cipher" in l or "SecretKey" in l or "Base64" in l for l in labels)
        has_network = any("RequestBody" in l or "ResponseBody" in l or "chain" in l.lower() for l in labels)

        entry = {
            "file": r["file"],
            "patterns_found": list(labels),
            "sample_hits": {k: v[:3] for k, v in r["hits"].items()},
        }

        if is_interceptor or (has_crypto and has_network):
            interceptor_files.append(entry)
        if has_crypto and has_network:
            crypto_network.append(entry)

    return {
        "success": True,
        "files_searched": searched,
        "interceptor_files": interceptor_files,
        "crypto_in_network_layer": crypto_network,
        "all_network_hits": results[:max_results],
    }


# ---------------------------------------------------------------------------
# 2.  Native / JNI bridge scanner
# ---------------------------------------------------------------------------

_NATIVE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("native method decl",         re.compile(r"\bnative\b\s+\w+", re.I)),
    ("System.loadLibrary",         re.compile(r"System\s*\.\s*loadLibrary\s*\(", re.I)),
    ("System.load",                re.compile(r"System\s*\.\s*load\s*\(", re.I)),
    ("JNI registration",          re.compile(r"RegisterNatives|JNI_OnLoad", re.I)),
    # Smali equivalents
    ("Smali native method",        re.compile(r"\.method\s+.*\bnative\b", re.I)),
    ("Smali loadLibrary",          re.compile(r"Ljava/lang/System;->loadLibrary", re.I)),
    ("Smali load",                 re.compile(r"Ljava/lang/System;->load\(", re.I)),
    # React Native / Flutter specific
    ("ReactNative module",         re.compile(r"ReactContextBaseJavaModule|ReactMethod|NativeModule", re.I)),
    ("Flutter method channel",     re.compile(r"MethodChannel|FlutterJNI", re.I)),
]


def search_native_bridges(
    directory: str | Path,
    max_results: int = 40,
) -> dict:
    """Find JNI native method declarations, System.loadLibrary calls,
    and framework bridges (React Native modules, Flutter channels).

    These indicate crypto or parsing may be hidden in compiled .so libraries.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return {"success": False, "error": f"Directory not found: {directory}"}

    file_list = _collect_code_files(directory)
    total = len(file_list)
    if total == 0:
        return {"success": True, "files_searched": 0, "native_bridges": []}

    def _scan(fpath: Path) -> dict | None:
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None

        rel = str(fpath.relative_to(directory))
        hits: dict[str, list[dict]] = {}
        lines = text.splitlines()

        for label, regex in _NATIVE_PATTERNS:
            for i, line in enumerate(lines, 1):
                if regex.search(line):
                    hits.setdefault(label, []).append({"line": i, "text": line.strip()[:200]})

        if not hits:
            return None

        # Also check for co-located crypto / parsing keywords
        has_crypto = bool(re.search(r"Cipher|encrypt|decrypt|AES|SecretKey", text, re.I))
        has_json = bool(re.search(r"JSON|parse|serialize|fromJson|toJson", text, re.I))

        return {
            "file": rel,
            "patterns_found": list(hits.keys()),
            "has_crypto_keywords": has_crypto,
            "has_json_keywords": has_json,
            "sample_hits": {k: v[:3] for k, v in hits.items()},
        }

    results: list[dict] = []
    searched = 0
    futures = {_POOL.submit(_scan, fp): fp for fp in file_list}
    for future in as_completed(futures):
        searched += 1
        r = future.result()
        if r:
            results.append(r)
        if searched % 50 == 0 or searched == total:
            report_progress(searched / total * 100, f"{searched}/{total} files")
        if len(results) >= max_results:
            break

    # Also scan for .so files in lib/ directory
    so_files: list[dict] = []
    lib_dir = directory / "lib"
    if lib_dir.is_dir():
        for root, _, files in os.walk(lib_dir):
            for fname in files:
                if fname.endswith(".so"):
                    fpath = Path(root) / fname
                    arch = fpath.parent.name
                    so_files.append({
                        "file": str(fpath.relative_to(directory)),
                        "arch": arch,
                        "size_kb": round(fpath.stat().st_size / 1024, 1),
                    })

    return {
        "success": True,
        "files_searched": searched,
        "native_bridges": results,
        "so_libraries": so_files,
        "summary": {
            "files_with_native": len(results),
            "so_library_count": len(so_files),
            "architectures": list(set(s["arch"] for s in so_files)),
        },
    }


# ---------------------------------------------------------------------------
# 3.  Dynamic code loading scanner
# ---------------------------------------------------------------------------

_DYNAMIC_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("DexClassLoader",             re.compile(r"DexClassLoader", re.I)),
    ("PathClassLoader",            re.compile(r"PathClassLoader", re.I)),
    ("InMemoryDexClassLoader",     re.compile(r"InMemoryDexClassLoader", re.I)),
    ("ClassLoader.loadClass",      re.compile(r"ClassLoader\s*[;.].*loadClass|loadClass\s*\(", re.I)),
    ("Class.forName",              re.compile(r"Class\s*\.\s*forName\s*\(", re.I)),
    ("reflection invoke",          re.compile(r"Method\s*\.\s*invoke\s*\(|\.invoke\s*\(", re.I)),
    ("DexFile",                    re.compile(r"dalvik\.system\.DexFile|DexFile\s*\.", re.I)),
    ("AssetManager open",          re.compile(r"AssetManager\s*[;.].*open|getAssets\s*\(\s*\)\s*\.\s*open", re.I)),
    # Smali equivalents
    ("Smali DexClassLoader",       re.compile(r"Ldalvik/system/DexClassLoader", re.I)),
    ("Smali loadClass",            re.compile(r"Ljava/lang/ClassLoader;->loadClass", re.I)),
    ("Smali Class.forName",        re.compile(r"Ljava/lang/Class;->forName", re.I)),
    ("Smali Method.invoke",        re.compile(r"Ljava/lang/reflect/Method;->invoke", re.I)),
    ("Smali DexFile",              re.compile(r"Ldalvik/system/DexFile", re.I)),
]


def search_dynamic_loading(
    directory: str | Path,
    max_results: int = 40,
) -> dict:
    """Find dynamic code loading patterns: DexClassLoader, Class.forName,
    reflection, runtime .dex/.jar loading.

    These indicate that crypto or security logic might be loaded at runtime
    and hidden from static decompilation.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return {"success": False, "error": f"Directory not found: {directory}"}

    file_list = _collect_code_files(directory)
    total = len(file_list)
    if total == 0:
        return {"success": True, "files_searched": 0, "dynamic_loading": []}

    def _scan(fpath: Path) -> dict | None:
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None

        rel = str(fpath.relative_to(directory))
        hits: dict[str, list[dict]] = {}
        lines = text.splitlines()

        for label, regex in _DYNAMIC_PATTERNS:
            for i, line in enumerate(lines, 1):
                if regex.search(line):
                    hits.setdefault(label, []).append({"line": i, "text": line.strip()[:200]})

        if not hits:
            return None

        # Check what's being loaded
        dex_paths: list[str] = []
        for line in lines:
            m = re.search(r'["\'](.*?\.(?:dex|jar|apk))["\']', line)
            if m:
                dex_paths.append(m.group(1))

        return {
            "file": rel,
            "patterns_found": list(hits.keys()),
            "loaded_artifacts": dex_paths[:10],
            "sample_hits": {k: v[:3] for k, v in hits.items()},
        }

    results: list[dict] = []
    searched = 0
    futures = {_POOL.submit(_scan, fp): fp for fp in file_list}
    for future in as_completed(futures):
        searched += 1
        r = future.result()
        if r:
            results.append(r)
        if searched % 50 == 0 or searched == total:
            report_progress(searched / total * 100, f"{searched}/{total} files")
        if len(results) >= max_results:
            break

    # Also look for extra .dex/.jar inside assets/
    hidden_dex: list[str] = []
    assets_dir = directory / "assets"
    if assets_dir.is_dir():
        for root, _, files in os.walk(assets_dir):
            for fname in files:
                if fname.endswith((".dex", ".jar", ".apk", ".zip")):
                    hidden_dex.append(str((Path(root) / fname).relative_to(directory)))

    return {
        "success": True,
        "files_searched": searched,
        "dynamic_loading": results,
        "hidden_dex_in_assets": hidden_dex,
        "summary": {
            "files_with_dynamic_loading": len(results),
            "hidden_dex_count": len(hidden_dex),
        },
    }


# ---------------------------------------------------------------------------
# Helper — collect code-only files
# ---------------------------------------------------------------------------

def _collect_code_files(directory: Path) -> list[Path]:
    """Collect .java, .kt, .smali files from directory tree."""
    file_list: list[Path] = []
    for root, _, files in os.walk(directory):
        for fname in files:
            if any(fname.endswith(ext) for ext in _CODE_EXTS):
                file_list.append(Path(root) / fname)
    return file_list
