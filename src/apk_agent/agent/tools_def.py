"""LangChain @tool definitions wrapping all Tool Layer functions.

These are the tools the LLM agent can call during its ReAct loop.
Each tool returns a structured JSON string so the LLM can reason about results.
All tools are wrapped with error recovery — they never crash the agent.
"""

from __future__ import annotations

import json
import traceback
import uuid
from pathlib import Path
from typing import Optional

from langchain_core.tools import tool

from apk_agent.progress import progress_manager, set_current_task

# We use a module-level config holder that gets set at graph construction time.
_config = None
_project = None

# ---------------------------------------------------------------------------
# Tool result cache — avoids re-running expensive scans with same args
# ---------------------------------------------------------------------------
_tool_cache: dict[str, str] = {}
_CACHEABLE_TOOLS = frozenset({
    "scan_vulnerabilities", "extract_strings", "search_in_code",
    "context_search", "multi_search", "xref_search",
    "scan_smali_classes", "list_vuln_patterns", "detect_protections",
    "aapt2_dump", "parse_manifest", "directory_overview",
    "find_string_decryption_patterns",
    "search_interceptors", "search_native_code", "search_dynamic_loaders",
    "refine_search", "smart_search",
    "graph_callers", "graph_callees", "graph_class_info",
    "graph_find_path", "graph_security_scan", "graph_stats",
    "index_lookup_class", "index_lookup_method",
    "index_lookup_string", "index_lookup_package",
    "unified_scan", "run_taint_analysis", "find_hardcoded_crypto",
    "analyze_manifest_deep", "scan_cloud_secrets", "smali_index_stats",
})


def set_tool_context(config, project) -> None:
    """Set the config and project for tool execution. Called once per session."""
    global _config, _project, _tool_cache, _smali_index, _scratchpad, _task_plan
    _config = config
    _project = project
    _tool_cache.clear()  # fresh cache per session
    _smali_index = None
    _scratchpad = {}
    _task_plan = []


# ---------------------------------------------------------------------------
# Module-level scratchpad and task plan (read by graph.py for state sync)
# ---------------------------------------------------------------------------
_scratchpad: dict = {}
_task_plan: list[dict] = []


def _get_scratchpad() -> dict:
    """Return the current scratchpad dict."""
    return _scratchpad


def _get_task_plan() -> list[dict]:
    """Return the current task plan list."""
    return _task_plan


def _log_file() -> Path:
    if _project:
        return Path(_project.workspace_path) / "logs" / "tools.log"
    return Path("tools.log")


def _safe_call(func, tool_name: str, *args, **kwargs) -> str:
    """Wrap any tool function with progress tracking, caching, and error recovery."""
    # Check cache for expensive idempotent tools
    cache_key = None
    if tool_name in _CACHEABLE_TOOLS:
        # Normalize paths in args to prevent cache misses from \ vs /
        norm_args = str(args).replace("\\", "/")
        norm_kwargs = str(sorted(kwargs.items())).replace("\\", "/")
        cache_key = f"{tool_name}:{norm_args}:{norm_kwargs}"
        if cache_key in _tool_cache:
            return _tool_cache[cache_key]

    task_id = f"tool_{tool_name}_{uuid.uuid4().hex[:4]}"
    set_current_task(task_id)
    progress_manager.start_task(task_id, tool_name)
    try:
        result = func(*args, **kwargs)
        progress_manager.complete_task(task_id, success=True)
        # Store in cache
        if cache_key is not None:
            _tool_cache[cache_key] = result
        return result
    except FileNotFoundError as e:
        progress_manager.complete_task(task_id, success=False, error=str(e))
        return json.dumps({
            "success": False,
            "error": f"File not found: {e}",
            "recovery_hint": "Check the file path. Use list_files or directory_overview to find correct paths.",
        })
    except PermissionError as e:
        progress_manager.complete_task(task_id, success=False, error=str(e))
        return json.dumps({
            "success": False,
            "error": f"Permission denied: {e}",
            "recovery_hint": "Check file permissions.",
        })
    except json.JSONDecodeError as e:
        progress_manager.complete_task(task_id, success=False, error=str(e))
        return json.dumps({
            "success": False,
            "error": f"Invalid JSON input: {e}",
            "recovery_hint": "Check the JSON format of your input.",
        })
    except Exception as e:
        progress_manager.complete_task(task_id, success=False, error=str(e))
        tb = traceback.format_exc()[-300:]
        return json.dumps({
            "success": False,
            "error": str(e),
            "error_type": type(e).__name__,
            "recovery_hint": "An unexpected error occurred. Try a different approach.",
            "traceback_tail": tb,
        })


def _resolve_dir(directory: str | None, default: str = "jadx") -> Path:
    """Resolve a directory argument from the LLM into an absolute path.

    Handles common aliases the LLM may use (jadx, smali, apktool, etc.)
    and ensures relative paths land under the decompiled/ subtree.
    """
    if directory is None:
        if default == "smali" or default == "apktool":
            return _project.apktool_dir
        return _project.jadx_dir

    d = directory.strip().strip("/").strip("\\")
    low = d.lower().replace("\\", "/")

    # Exact alias matching
    if low in ("jadx", "jadx_src"):
        return _project.jadx_dir
    if low == "apktool":
        return _project.apktool_dir
    if low == "smali":
        return _project.apktool_dir / "smali"

    # Handle "apktool/..." paths — strip the "apktool/" prefix and resolve
    # under the apktool_dir. Supports: "apktool/smali", "apktool/smali/com/foo",
    # "apktool/smali_classes2", "apktool/res/values", etc.
    if low.startswith("apktool/"):
        sub = d.split("/", 1)[1] if "/" in d else d.split("\\", 1)[1]
        candidate = _project.apktool_dir / sub
        if candidate.is_dir():
            return candidate
        # Maybe they wrote "apktool/smali/com/foo" but it's actually in
        # smali_classes2 or smali_classes3 — search all smali dirs
        if low.startswith("apktool/smali/"):
            inner = sub.split("/", 1)[1] if "/" in sub else ""
            if inner:
                for smali_d in _get_all_smali_dirs():
                    test = smali_d / inner
                    if test.is_dir():
                        return test
        return candidate  # return best guess even if not found

    # Handle smali_classesN aliases: "smali_classes2", "smali_classes3", etc.
    # Also handles "smali/com/foo" style paths
    if low.startswith("smali_classes") or low.startswith("smali/"):
        candidate = _project.apktool_dir / d
        if candidate.is_dir():
            return candidate
        # If "smali/com/foo" didn't work, try all smali dirs
        if low.startswith("smali/"):
            inner = d.split("/", 1)[1] if "/" in d else ""
            if inner:
                for smali_d in _get_all_smali_dirs():
                    test = smali_d / inner
                    if test.is_dir():
                        return test
        return candidate

    # Bare path like "com/psiphon3" or "B2" — check all smali dirs
    if not Path(directory).is_absolute():
        for smali_d in _get_all_smali_dirs():
            test = smali_d / d
            if test.is_dir():
                return test

    p = Path(directory)
    if p.is_absolute():
        return p

    # Try under decompiled/ first, then workspace root, then apktool subdir
    decompiled = Path(_project.workspace_path) / "decompiled" / d
    if decompiled.is_dir():
        return decompiled
    ws_dir = Path(_project.workspace_path) / d
    if ws_dir.is_dir():
        return ws_dir
    apk_sub = _project.apktool_dir / d
    if apk_sub.is_dir():
        return apk_sub
    # Default to decompiled/ (more likely correct)
    return decompiled


def _resolve_file(file_path: str) -> Path:
    """Resolve a *file* argument from the LLM into an absolute path.

    Handles common prefixes the agent may pass:
      - "smali/com/foo/Bar.smali"  → apktool_dir / smali / com/foo/Bar.smali
      - "decompiled/apktool/smali/com/foo/Bar.smali" → strip prefix
      - "B2/g0.smali" → search all smali dirs
      - absolute path → returned as-is

    Also searches all smali_classesN/ dirs when the file is missing from smali/.
    """
    p = Path(file_path)
    if p.is_absolute():
        return p

    fpath = file_path.replace("\\", "/").lstrip("/")

    # Strip accidental "decompiled/apktool/" prefix
    for prefix in ("decompiled/apktool/", "decompiled\\apktool\\", "decompiled/"):
        if fpath.startswith(prefix):
            fpath = fpath[len(prefix):]
            break

    # Try directly under apktool_dir (covers smali/..., res/..., etc.)
    candidate = _project.apktool_dir / fpath
    if candidate.is_file():
        return candidate

    # If path starts with "smali/", try other smali dirs (smali_classes2, etc.)
    if fpath.startswith("smali/"):
        inner = fpath.split("/", 1)[1]  # strip "smali/"
        for sd in _get_all_smali_dirs():
            test = sd / inner
            if test.is_file():
                return test

    # If path starts with "smali_classes", it's already under apktool_dir
    # (handled above by the direct candidate check)

    # Bare path (e.g. "B2/g0.smali", "com/foo/Bar.smali") — search ALL smali dirs
    if not fpath.startswith("smali") and fpath.endswith(".smali"):
        for sd in _get_all_smali_dirs():
            test = sd / fpath
            if test.is_file():
                return test

    # Also try bare path for Java files under jadx_src/sources
    if fpath.endswith(".java"):
        jadx_candidate = _project.jadx_dir / "sources" / fpath
        if jadx_candidate.is_file():
            return jadx_candidate
        jadx_candidate2 = _project.jadx_dir / fpath
        if jadx_candidate2.is_file():
            return jadx_candidate2

    # Fallback: try workspace root, then just return best-guess under apktool_dir
    ws_candidate = Path(_project.workspace_path) / file_path
    if ws_candidate.is_file():
        return ws_candidate

    return candidate  # return apktool_dir-based path (will surface "not found" error)


def _get_all_smali_dirs() -> list[Path]:
    """Discover all smali directories (smali/, smali_classes2/, smali_classes3/, ...).
    Returns a list of existing directories sorted by name.
    """
    apk_dir = _project.apktool_dir
    if not apk_dir.is_dir():
        return []
    dirs = []
    for child in sorted(apk_dir.iterdir()):
        if child.is_dir() and (child.name == "smali" or child.name.startswith("smali_classes")):
            dirs.append(child)
    return dirs


# ---------------------------------------------------------------------------
# Decompilation tools
# ---------------------------------------------------------------------------


@tool
def apktool_decompile() -> str:
    """Decompile the APK using apktool into smali code, resources, and AndroidManifest.
    This must be run before any smali patching or manifest analysis.
    Returns the output directory path and list of smali directories found.
    """
    from apk_agent.tools.apktool import decompile

    result = decompile(
        apktool_bin=_config.get_tool_path("apktool") or "apktool",
        apk_path=_project.apk_path,
        output_dir=_project.apktool_dir,
        log_file=_log_file(),
    )
    return result.to_llm_str()


@tool
def jadx_decompile() -> str:
    """Decompile the APK using JADX into readable Java source code.
    This provides human-readable Java code for understanding app logic.
    Returns the output directory path and discovered packages.
    """
    from apk_agent.tools.jadx import decompile

    result = decompile(
        jadx_bin=_config.get_tool_path("jadx") or "jadx",
        apk_path=_project.apk_path,
        output_dir=_project.jadx_dir,
        log_file=_log_file(),
    )
    return result.to_llm_str()


@tool
def dex2jar_convert() -> str:
    """Convert the APK's DEX files to a JAR archive using dex2jar.
    Useful for further JVM-level analysis or importing into JD-GUI.

    When to use: Prefer jadx_decompile for most analysis (produces readable Java).
    Use dex2jar only when you need a .jar file for external Java tools like JD-GUI.

    Returns: Text summary with the path to the generated JAR file on success,
    or an error message on failure.
    """
    from apk_agent.tools.dex2jar import convert

    output_jar = Path(_project.workspace_path) / "decompiled" / "classes.jar"
    result = convert(
        d2j_bin=_config.get_tool_path("dex2jar") or "d2j-dex2jar",
        input_path=_project.apk_path,
        output_jar=output_jar,
        log_file=_log_file(),
    )
    return result.to_llm_str()


# ---------------------------------------------------------------------------
# Build & Sign tools
# ---------------------------------------------------------------------------


@tool
def apktool_build() -> str:
    """Rebuild the APK from the (possibly patched) apktool decompiled project.
    Run this after applying smali patches to produce a new unsigned APK.
    Returns the path to the rebuilt APK on success.
    """
    from apk_agent.tools.apktool import build

    output_apk = Path(_project.workspace_path) / "outputs" / "patched-unsigned.apk"
    result = build(
        apktool_bin=_config.get_tool_path("apktool") or "apktool",
        project_dir=_project.apktool_dir,
        output_apk=output_apk,
        log_file=_log_file(),
    )
    return result.to_llm_str()


@tool
def zipalign_apk_tool() -> str:
    """Zip-align the rebuilt unsigned APK (required before signing with apksigner).
    Aligns uncompressed entries on 4-byte boundaries for better runtime performance.
    Run after apktool_build and before sign_apk.
    """
    from apk_agent.tools.zipalign import zipalign

    input_apk = Path(_project.workspace_path) / "outputs" / "patched-unsigned.apk"
    aligned_apk = Path(_project.workspace_path) / "outputs" / "patched-aligned.apk"
    result = zipalign(
        zipalign_bin=_config.get_tool_path("zipalign") or "zipalign",
        input_apk=input_apk,
        output_apk=aligned_apk,
        log_file=_log_file(),
    )
    return result.to_llm_str()


@tool
def sign_apk() -> str:
    """Sign the rebuilt APK to produce a final installable patched-signed.apk.
    Run this after apktool_build (and optionally zipalign_apk_tool) succeeds.
    Returns the path to the signed APK.
    """
    from apk_agent.tools.signer import sign_apk as _sign

    # Try aligned first, fall back to unsigned
    aligned = Path(_project.workspace_path) / "outputs" / "patched-aligned.apk"
    unsigned = Path(_project.workspace_path) / "outputs" / "patched-unsigned.apk"
    input_apk = aligned if aligned.is_file() else unsigned
    signed = Path(_project.workspace_path) / "outputs" / "patched-signed.apk"

    result = _sign(
        signer_bin=_config.get_tool_path("apksigner") or "apksigner",
        unsigned_apk=input_apk,
        output_apk=signed,
        keystore_path=_config.keystore.path,
        keystore_password=_config.keystore.password,
        key_alias=_config.keystore.key_alias,
        key_password=_config.keystore.key_password,
        log_file=_log_file(),
    )
    return result.to_llm_str()


# ---------------------------------------------------------------------------
# Analysis tools
# ---------------------------------------------------------------------------


@tool
def aapt2_dump() -> str:
    """Dump APK metadata using aapt2: package name, version, SDK info,
    permissions, activities, services, receivers, and providers.
    Does NOT require decompilation — works directly on the APK.
    """
    from apk_agent.tools.aapt2 import dump_badging

    result = dump_badging(
        aapt2_bin=_config.get_tool_path("aapt2") or "aapt2",
        apk_path=_project.apk_path,
        log_file=_log_file(),
    )
    return result.to_llm_str()


@tool
def extract_strings() -> str:
    """Extract printable strings from the APK's DEX files (pure Python, no binary needed).
    Automatically classifies findings into URLs, emails, API keys, AWS keys,
    Firebase URLs, bearer tokens, private keys, and base64 blobs.
    Great for finding hardcoded secrets and endpoints.
    """
    from apk_agent.tools.strings_tool import extract_strings as _extract

    def _run():
        result = _extract(str(_project.apk_path))
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "extract_strings")


@tool
def parse_manifest() -> str:
    """Parse the decoded AndroidManifest.xml from the apktool output.
    Returns structured data: package info, permissions, dangerous permissions,
    components (activities/services/receivers/providers), exported components,
    debuggable flag, allow-backup flag, and cleartext traffic flag.
    Requires apktool_decompile to have been run first.

    When to use: For basic manifest parsing and quick overview.
    For deeper semantic analysis with code cross-referencing and security findings,
    use analyze_manifest_deep instead.

    Returns: JSON with keys: package, version_code, version_name, min_sdk,
    target_sdk, permissions, dangerous_permissions, activities, services,
    receivers, providers, exported_components, debuggable, allow_backup,
    uses_cleartext_traffic.
    """
    from apk_agent.tools.manifest_parser import parse_manifest as _parse

    manifest_path = _project.apktool_dir / "AndroidManifest.xml"
    result = _parse(manifest_path)
    return json.dumps(result, ensure_ascii=False, indent=2)[:15000]


@tool
def identify_app_packages() -> str:
    """Auto-detect the app's own packages vs third-party SDKs.
    Parses AndroidManifest.xml for the main package name and scans
    component declarations (Activities, Services) to find all app-owned packages.
    Returns the target packages and a list of detected third-party SDKs.

    Run this EARLY (after apktool_decompile) to focus all searches on app code only.
    """
    from apk_agent.tools.manifest_parser import parse_manifest as _parse
    from apk_agent.tools.advanced_search import _is_third_party_path

    manifest_path = _project.apktool_dir / "AndroidManifest.xml"

    def _run():
        result = _parse(manifest_path)
        if not isinstance(result, dict) or not result.get("package"):
            return json.dumps({"success": False, "error": "Could not parse manifest"})

        main_pkg = result["package"]  # e.g. "com.comviva.nextgen.ooredoodev"
        target_pkgs = set()

        # Add the main package and its parent namespace
        target_pkgs.add(main_pkg)
        parts = main_pkg.split(".")
        if len(parts) >= 3:
            target_pkgs.add(".".join(parts[:3]))  # e.g. "com.comviva.nextgen"
        if len(parts) >= 2:
            target_pkgs.add(".".join(parts[:2]))  # e.g. "com.comviva"

        # Extract packages from component declarations
        components = []
        for key in ("activities", "services", "receivers", "providers"):
            components.extend(result.get(key, []))

        component_pkgs = set()
        for comp in components:
            name = comp if isinstance(comp, str) else (comp.get("name", "") if isinstance(comp, dict) else "")
            if not name or name.startswith("."):
                continue
            cparts = name.rsplit(".", 1)
            if len(cparts) == 2:
                pkg = cparts[0]
                # Check if this is a third-party package
                pkg_path = pkg.replace(".", "/")
                if not _is_third_party_path(pkg_path):
                    component_pkgs.add(pkg)
                    # Also add the 2-3 level prefix
                    pp = pkg.split(".")
                    if len(pp) >= 3:
                        target_pkgs.add(".".join(pp[:3]))
                    if len(pp) >= 2:
                        target_pkgs.add(".".join(pp[:2]))

        # Also scan top-level directories under smali/ for app packages
        smali_app_pkgs = set()
        third_party_found = set()
        for smali_d in _get_all_smali_dirs():
            for child in sorted(smali_d.iterdir()):
                if child.is_dir():
                    # Walk 2-3 levels to find package roots
                    for sub1 in child.iterdir():
                        if sub1.is_dir():
                            rel = f"{child.name}/{sub1.name}"
                            pkg_dot = rel.replace("/", ".")
                            if _is_third_party_path(rel):
                                third_party_found.add(pkg_dot)
                            else:
                                for sub2 in sub1.iterdir():
                                    if sub2.is_dir():
                                        rel2 = f"{rel}/{sub2.name}"
                                        pkg2 = rel2.replace("/", ".")
                                        if _is_third_party_path(rel2):
                                            third_party_found.add(pkg2)
                                        else:
                                            smali_app_pkgs.add(pkg2)

        return json.dumps({
            "success": True,
            "main_package": main_pkg,
            "target_packages": sorted(target_pkgs),
            "app_component_packages": sorted(component_pkgs),
            "app_smali_packages": sorted(list(smali_app_pkgs)[:50]),
            "third_party_detected": sorted(list(third_party_found)[:50]),
            "recommendation": (
                f"Focus analysis on: {', '.join(sorted(target_pkgs))}. "
                f"Found {len(third_party_found)} third-party SDK packages that will be auto-excluded from searches."
            ),
        }, ensure_ascii=False, indent=2)[:15000]

    return _safe_call(_run, "identify_app_packages")



# ---------------------------------------------------------------------------
# File operation tools
# ---------------------------------------------------------------------------


@tool
def read_file(file_path: str, start_line: int = 0, end_line: int = 0) -> str:
    """Read the contents of a file from the decompiled project.
    Use this to examine Java source, smali code, AndroidManifest.xml, etc.

    Args:
        file_path: Absolute path or path relative to the project workspace.
                   Partial paths like 'com/example/Foo.java' are also resolved
                   by searching under decompiled/jadx_src and decompiled/apktool.
        start_line: 1-based start line for reading a specific range.
                    0 means "from the beginning of the file".
                    Use this to read large files in chunks instead of loading everything.
        end_line: 1-based end line for reading a specific range.
                  0 means "read up to the default max (500 lines)".

    Returns: JSON with keys: success, file, total_lines, start_line, end_line,
    content (the file text), truncated (bool if output was capped).
    """
    from apk_agent.tools.file_ops import read_file as _read

    # Use _resolve_file for consistent path resolution across all tools
    p = _resolve_file(file_path)

    # If _resolve_file couldn't find it, try additional jadx fallback locations
    if not p.is_file():
        _stripped = file_path.replace("\\", "/").lstrip("/")
        for _pfx in (
            "decompiled/jadx_src/sources/",
            "decompiled/jadx_src/",
            "decompiled/apktool/",
            "decompiled/",
        ):
            if _stripped.startswith(_pfx):
                _stripped = _stripped[len(_pfx):]
                break

        candidates = [
            Path(_project.workspace_path) / "decompiled" / "jadx_src" / "sources" / _stripped,
            Path(_project.workspace_path) / "decompiled" / "jadx_src" / _stripped,
            _project.jadx_dir / _stripped,
            Path(_project.workspace_path) / file_path,
        ]
        for c in candidates:
            if c.is_file():
                p = c
                break

    result = _read(p, start_line=start_line, end_line=end_line)
    return json.dumps(result, ensure_ascii=False, indent=2)[:12000]


@tool
def write_file(file_path: str, content: str) -> str:
    """Write or overwrite a file in the decompiled project.
    Use this for direct smali edits, adding new files, or modifying XML configs.

    Args:
        file_path: Absolute path or path relative to the project workspace.
        content: The full file content to write.
    """
    p = Path(file_path)
    if not p.is_absolute():
        p = Path(_project.workspace_path) / file_path
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return json.dumps({
            "success": True,
            "path": str(p),
            "bytes_written": len(content.encode("utf-8")),
        })
    except Exception as e:
        return json.dumps({"success": False, "error": str(e)})


@tool
def search_in_code(
    pattern: str,
    directory: Optional[str] = None,
    file_extensions: Optional[str] = None,
    exclude_dirs: Optional[str] = None,
    max_results: int = 50,
) -> str:
    """Search for a text pattern (regex supported) across decompiled source files.
    Searches ONLY code files (.java, .kt, .smali) by default — no XML/JSON noise.

    When to use: For manual, precise searches with full control over extensions and directories.
    For auto-tuned search without tweaking parameters, use smart_search.
    For search with surrounding context lines, use context_search.

    Args:
        pattern: Regex pattern to search for (e.g., "CertificatePinner", "isRooted", "api[_-]?key").
            For crypto, search imports: "import javax\\.crypto\\.Cipher" rather than broad "Crypto|AES".
        directory: Directory to search in. Defaults to JADX sources dir. Can be "smali" for smali code.
        file_extensions: Comma-separated extensions (e.g., ".java,.xml"). Defaults to .java,.kt,.smali.
        exclude_dirs: Comma-separated directory names to SKIP (e.g., "build,test,res,original").
            Use this to avoid noise from generated/resource directories.
        max_results: Maximum number of matches to return (default 50). Lower = faster + less noise.

    Returns: JSON with keys: matches (array of {file, line, content}),
    total (total match count), smali_dirs_searched (when searching smali).
    """
    from apk_agent.tools.file_ops import search_in_files

    exts = None
    if file_extensions:
        exts = [e.strip() for e in file_extensions.split(",")]

    excl = None
    if exclude_dirs:
        excl = [d.strip() for d in exclude_dirs.split(",")]

    # When directory is "smali" or None with smali extensions, search ALL smali dirs
    low_dir = (directory or "").strip().lower().replace("\\", "/")
    search_all_smali = low_dir in ("smali", "apktool/smali", "apktool")

    def _run():
        if search_all_smali:
            # Search all smali dirs (smali/, smali_classes2/, smali_classes3/, ...)
            all_matches = []
            for smali_d in _get_all_smali_dirs():
                result = search_in_files(smali_d, pattern, file_extensions=exts,
                                          exclude_dirs=excl, max_results=max_results)
                if isinstance(result, dict) and result.get("matches"):
                    all_matches.extend(result["matches"])
                elif isinstance(result, list):
                    all_matches.extend(result)
            return json.dumps({"matches": all_matches[:max_results],
                              "total": len(all_matches),
                              "smali_dirs_searched": len(_get_all_smali_dirs())},
                             ensure_ascii=False, indent=2)[:15000]
        else:
            search_dir = _resolve_dir(directory, default="jadx")
            result = search_in_files(search_dir, pattern, file_extensions=exts,
                                      exclude_dirs=excl, max_results=max_results)
            return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "search_in_code")


@tool
def list_files(
    directory: Optional[str] = None,
    max_depth: int = 2,
    file_extensions: Optional[str] = None,
) -> str:
    """List files and directories in the decompiled project.
    Use this to understand the project structure.

    Args:
        directory: Directory to list. Defaults to the JADX sources directory.
        max_depth: How deep to recurse (default 2).
        file_extensions: Comma-separated extensions to filter (e.g., ".smali,.java").
            If omitted, all files are shown.
    """
    from apk_agent.tools.file_ops import list_directory

    d = _resolve_dir(directory, default="jadx")

    result = list_directory(d, max_depth=max_depth)
    # Post-filter by extension if requested
    if file_extensions and isinstance(result, dict) and "files" in result:
        exts = {e.strip().lower() for e in file_extensions.split(",")}
        result["files"] = [f for f in result["files"]
                           if any(f.lower().endswith(ext) for ext in exts)]
    return json.dumps(result, ensure_ascii=False, indent=2)[:10000]


# ---------------------------------------------------------------------------
# Patch tools
# ---------------------------------------------------------------------------


@tool
def apply_smali_patch(patch_plan_json: str) -> str:
    """Apply a smali patch to modify the APK's behaviour.
    The patch plan is a JSON object specifying the target file and operations.

    IMPORTANT: You MUST pass the full JSON plan as the patch_plan_json argument.
    Do NOT call this tool with empty arguments.

    Args:
        patch_plan_json: JSON string with this structure:
            {
                "target_file": "smali/com/example/SslPinner.smali",
                "description": "Disable SSL pinning check",
                "steps": [
                    {
                        "operation": "replace_line|replace_block|insert_before|insert_after|delete_block|delete_line",
                        "match_pattern": "exact text or regex to find",
                        "replacement": "replacement text (for replace ops)",
                        "content": "text to insert (for insert ops)",
                        "is_regex": false,
                        "description": "What this step does"
                    }
                ]
            }
    """
    from apk_agent.patch_engine import PatchEngine, PatchPlan

    if not patch_plan_json or not patch_plan_json.strip():
        return json.dumps({
            "success": False,
            "error": "patch_plan_json is empty. You must provide the full JSON patch plan.",
            "recovery_hint": "Build the JSON with target_file, description, and steps[] then call again.",
        })

    try:
        plan_data = json.loads(patch_plan_json)
    except json.JSONDecodeError as e:
        return json.dumps({"success": False, "error": f"Invalid JSON: {e}"})

    if not plan_data.get("steps"):
        return json.dumps({
            "success": False,
            "error": "Patch plan has no steps. Add at least one step with operation and match_pattern.",
        })

    plan = PatchPlan.from_dict(plan_data)
    engine = PatchEngine(
        apktool_dir=_project.apktool_dir,
        backup_dir=_project.patch_backup_dir,
        diffs_dir=_project.patch_diffs_dir,
    )
    result = engine.apply_plan(plan)
    return json.dumps({
        "success": result.success,
        "target_file": result.target_file,
        "steps_applied": result.steps_applied,
        "steps_total": result.steps_total,
        "diff_text": result.diff_text[:5000],
        "errors": result.errors,
        "backup_path": result.backup_path,
    }, ensure_ascii=False, indent=2)


@tool
def preview_smali_patch(patch_plan_json: str) -> str:
    """Preview what a smali patch would change WITHOUT actually modifying files.
    Use this to validate a patch plan before applying it.

    IMPORTANT: You MUST pass the full JSON plan as the patch_plan_json argument.
    Do NOT call this tool with empty arguments.

    Args:
        patch_plan_json: Same JSON structure as apply_smali_patch.

    Returns: Unified diff text showing what lines would change (--- a/file, +++ b/file format).
    On error, returns JSON with keys: success (false), error, recovery_hint.
    """
    from apk_agent.patch_engine import PatchEngine, PatchPlan

    if not patch_plan_json or not patch_plan_json.strip():
        return json.dumps({
            "success": False,
            "error": "patch_plan_json is empty. You must provide the full JSON patch plan.",
            "recovery_hint": "Build the JSON with target_file, description, and steps[] then call again.",
        })

    try:
        plan_data = json.loads(patch_plan_json)
    except json.JSONDecodeError as e:
        return json.dumps({
            "success": False,
            "error": f"Invalid JSON in patch_plan_json: {e}",
            "recovery_hint": "Check your JSON syntax — ensure all strings are properly quoted and brackets are balanced.",
        })

    plan = PatchPlan.from_dict(plan_data)
    engine = PatchEngine(
        apktool_dir=_project.apktool_dir,
        backup_dir=_project.patch_backup_dir,
        diffs_dir=_project.patch_diffs_dir,
    )
    return engine.preview_plan(plan)[:8000]


# ---------------------------------------------------------------------------
# Report tool
# ---------------------------------------------------------------------------


@tool
def generate_report(
    findings_json: str,
    patch_results_json: str = "[]",
) -> str:
    """Generate a Markdown security report summarizing findings and patches.

    Args:
        findings_json: JSON array of findings, each with: title, severity, category, description, location, evidence.
        patch_results_json: JSON array of patch results (optional).
    """
    from apk_agent.reporting import generate_report as _gen

    try:
        findings = json.loads(findings_json)
    except json.JSONDecodeError as e:
        return json.dumps({"success": False, "error": f"Invalid JSON in findings_json: {e}"})

    try:
        patches = json.loads(patch_results_json)
    except json.JSONDecodeError as e:
        return json.dumps({"success": False, "error": f"Invalid JSON in patch_results_json: {e}"})

    output_path = Path(_project.workspace_path) / "outputs" / "report.md"

    report = _gen(
        task=_project.apk_name,
        apk_name=_project.apk_name,
        findings=findings,
        patch_results=patches,
        output_path=output_path,
    )
    return f"Report generated at: {output_path}\n\n{report[:3000]}"


# ---------------------------------------------------------------------------
# Advanced smali analysis tools
# ---------------------------------------------------------------------------


@tool
def scan_smali_classes(directory: Optional[str] = None) -> str:
    """Scan smali directory for all classes and get a summary with crypto API usage,
    method counts, and interesting files that use security-related APIs.
    Use this for a quick overview of what the app does.

    Args:
        directory: Smali directory to scan. Defaults to apktool smali output.
    """
    from apk_agent.tools.smali_analyzer import scan_smali_directory

    d = _resolve_dir(directory, default="apktool")

    def _run():
        result = scan_smali_directory(d)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "scan_smali_classes")


@tool
def analyze_smali_class(file_path: str) -> str:
    """Deep-analyze a single smali file: parse class info, methods, fields,
    string constants, and crypto/security API findings.

    Args:
        file_path: Path to the .smali file (absolute or relative to workspace).
    """
    from apk_agent.tools.smali_analyzer import parse_smali_class

    p = _resolve_file(file_path)
    result = parse_smali_class(p)
    return json.dumps(result, ensure_ascii=False, indent=2)[:12000]


@tool
def find_string_decryption_patterns(directory: Optional[str] = None) -> str:
    """Find potential string decryption/deobfuscation patterns in smali code.
    Detects XOR loops, Base64 decoding, byte-array-to-String conversions,
    and other obfuscation techniques.

    When to use: Call this FIRST to identify files with encryption/obfuscation patterns.
    Then use reconstruct_strings on specific files to extract actual decrypted values.

    Args:
        directory: Smali directory to scan. Defaults to apktool output.

    Returns: JSON with keys: success, patterns_found (count), files_scanned,
    findings (array of {file, pattern_type, line, code_snippet, confidence}).
    """
    from apk_agent.tools.smali_analyzer import find_string_decryption

    d = _resolve_dir(directory, default="apktool")
    result = find_string_decryption(d)
    return json.dumps(result, ensure_ascii=False, indent=2)[:12000]


@tool
def find_method_xrefs(
    method_signature: str,
    directory: Optional[str] = None,
) -> str:
    """Find all call sites of a specific method across smali files.
    Use this to trace who calls a security-critical method.

    Args:
        method_signature: Full or partial method signature,
            e.g. "checkServerTrusted", "Landroid/util/Log;->d".
        directory: Smali directory. Defaults to apktool output.
    """
    from apk_agent.tools.smali_analyzer import find_method_calls

    d = _resolve_dir(directory, default="apktool")
    result = find_method_calls(d, method_signature)
    return json.dumps(result, ensure_ascii=False, indent=2)[:15000]


# ---------------------------------------------------------------------------
# Vulnerability scanner tools
# ---------------------------------------------------------------------------


@tool
def scan_vulnerabilities(
    directory: Optional[str] = None,
    severity_filter: Optional[str] = None,
) -> str:
    """Scan decompiled code for 25+ vulnerability patterns with severity ratings.
    Detects: SSL bypass, root detection, weak crypto, hardcoded secrets,
    WebView RCE, SQL injection, logging leaks, dynamic code loading, and more.
    Each finding includes CWE ID and remediation advice.

    When to use: Prefer unified_scan (IR-based, more accurate, deduplicated) if SmaliIndex is built.
    Use this as a fallback if SmaliIndex is not available or for quick JADX-source-level scanning.

    Args:
        directory: Directory to scan. Defaults to JADX sources.
            Use "smali" or "apktool" for smali code.
        severity_filter: Only show findings >= this level.
            Options: CRITICAL, HIGH, MEDIUM, LOW, INFO.

    Returns: JSON with keys: success, total_findings, files_scanned,
    findings (array of {id, name, severity, category, file, line, description, cwe, remediation}).
    """
    from apk_agent.tools.vuln_scanner import scan_directory

    d = _resolve_dir(directory, default="jadx")

    def _run():
        result = scan_directory(d, severity_filter=severity_filter)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "scan_vulnerabilities")


@tool
def list_vuln_patterns() -> str:
    """List all available vulnerability detection patterns with their IDs,
    names, severity levels, and categories.
    Use this to understand what the scanner can detect.
    """
    from apk_agent.tools.vuln_scanner import list_patterns
    patterns = list_patterns()
    return json.dumps(patterns, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Advanced search tools
# ---------------------------------------------------------------------------


@tool
def context_search(
    pattern: str,
    directory: Optional[str] = None,
    context_lines: int = 3,
    file_extensions: Optional[str] = None,
    exclude_dirs: Optional[str] = None,
) -> str:
    """Search with surrounding context lines (like grep -C N).
    Shows N lines before and after each match for better understanding.

    Args:
        pattern: Regex pattern to search for.
        directory: Directory to search in. Defaults to JADX sources.
            Use "smali" or "apktool" for smali code.
        context_lines: Lines of context before/after match (default 3).
        file_extensions: Comma-separated extensions (e.g., ".java,.smali").
        exclude_dirs: Comma-separated directory names to SKIP (e.g., "build,test,res,original").
    """
    from apk_agent.tools.advanced_search import search_with_context

    d = _resolve_dir(directory, default="jadx")

    exts = None
    if file_extensions:
        exts = [e.strip() for e in file_extensions.split(",")]

    excl = None
    if exclude_dirs:
        excl = [d_.strip() for d_ in exclude_dirs.split(",")]

    def _run():
        result = search_with_context(d, pattern, context_lines=context_lines,
                                      file_extensions=exts, exclude_dirs=excl,
                                      exclude_packages=True)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "context_search")


@tool
def multi_search(
    patterns: str,
    logic: str = "AND",
    directory: Optional[str] = None,
    exclude_dirs: Optional[str] = None,
) -> str:
    """Search for multiple patterns with AND/OR logic.
    AND = file must contain ALL patterns. OR = file must contain at least one.

    Args:
        patterns: Comma-separated regex patterns.
            Example: "CertificatePinner,checkServerTrusted,X509"
        logic: "AND" or "OR" (default AND).
        directory: Directory to search. Defaults to JADX sources.
        exclude_dirs: Comma-separated directory names to SKIP (e.g., "build,test,res").
    """
    from apk_agent.tools.advanced_search import multi_pattern_search

    d = _resolve_dir(directory, default="jadx")

    pattern_list = [p.strip() for p in patterns.split(",")]

    excl = None
    if exclude_dirs:
        excl = [d_.strip() for d_ in exclude_dirs.split(",")]

    def _run():
        result = multi_pattern_search(d, pattern_list, logic=logic, exclude_dirs=excl,
                                       exclude_packages=True)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "multi_search")


@tool
def xref_search(
    class_or_method: str,
    search_type: str = "callers",
    directory: Optional[str] = None,
) -> str:
    """Cross-reference search — find callers or callees of a class/method.

    When to use: Prefer graph_callers / graph_callees (instant, pre-built graph) if the code graph
    is built. Use xref_search only when the graph is not available or you need file-level search.

    Args:
        class_or_method: Class or method name (e.g., "SslPinningHelper",
            "checkServerTrusted").
        search_type: "callers" (who calls this?) or "callees" (what does this call?).
        directory: Directory to search. Defaults to JADX sources.

    Returns: JSON with keys: success, target, search_type, references
    (array of {file, line, caller/callee, context}).
    """
    from apk_agent.tools.advanced_search import cross_reference_search

    d = _resolve_dir(directory, default="jadx")

    def _run():
        result = cross_reference_search(d, class_or_method, search_type=search_type)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "xref_search")


@tool
def directory_overview(directory: Optional[str] = None) -> str:
    """Get statistics about a directory — file counts, sizes, types.
    Use this to decide which directories to search for analysis.

    Args:
        directory: Directory to analyze. Defaults to project root.

    Returns: JSON with keys: success, directory, total_files, total_size_mb,
    file_types (dict of extension→count), top_directories (array of {name, file_count, size_mb}).
    """
    from apk_agent.tools.advanced_search import directory_stats

    if directory:
        d = _resolve_dir(directory, default="jadx")
    else:
        d = Path(_project.workspace_path)

    def _run():
        result = directory_stats(d)
        return json.dumps(result, ensure_ascii=False, indent=2)[:10000]
    return _safe_call(_run, "directory_overview")


# ---------------------------------------------------------------------------
# Targeted analysis: network interceptors, native bridges, dynamic loading
# ---------------------------------------------------------------------------


@tool
def search_interceptors(directory: Optional[str] = None) -> str:
    """Find OkHttp/Retrofit interceptors and network-layer encryption code.
    Searches ONLY .java/.kt/.smali files for: implements Interceptor,
    chain.proceed(, RequestBody, ResponseBody, addInterceptor(), and
    crypto imports co-located with network code.

    Use this FIRST when investigating encrypted API payloads/responses.

    Args:
        directory: Directory to search. Defaults to JADX sources.
            Use "smali" or "apktool" for smali code.
    """
    from apk_agent.tools.targeted_analysis import search_network_interceptors

    d = _resolve_dir(directory, default="jadx")

    def _run():
        result = search_network_interceptors(d)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "search_interceptors")


@tool
def search_native_code(directory: Optional[str] = None) -> str:
    """Find JNI native method declarations, System.loadLibrary() calls,
    and framework bridges (React Native modules, Flutter channels).
    Also lists .so libraries in lib/ with architecture info.

    These indicate crypto or parsing logic hidden in compiled native code.

    Args:
        directory: Directory to search. Defaults to apktool output (has lib/).
    """
    from apk_agent.tools.targeted_analysis import search_native_bridges

    d = _resolve_dir(directory, default="apktool")

    def _run():
        result = search_native_bridges(d)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "search_native_code")


@tool
def search_dynamic_loaders(directory: Optional[str] = None) -> str:
    """Find dynamic code loading patterns: DexClassLoader, Class.forName,
    reflection Method.invoke, runtime .dex/.jar loading, and hidden
    DEX files in assets/.

    Crypto logic may be loaded at runtime and hidden from static analysis.

    Args:
        directory: Directory to search. Defaults to apktool output.
    """
    from apk_agent.tools.targeted_analysis import search_dynamic_loading

    d = _resolve_dir(directory, default="apktool")

    def _run():
        result = search_dynamic_loading(d)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "search_dynamic_loaders")


# ---------------------------------------------------------------------------
# NEW: Network Security Config analyzer
# ---------------------------------------------------------------------------

@tool
def analyze_network_config() -> str:
    """Analyze the network_security_config.xml for SSL/TLS settings.
    Detects: cleartext traffic permissions, custom trust anchors,
    certificate pinning configs, and domain-specific rules.
    Requires apktool_decompile to have been run first.

    Returns: JSON with keys: success, found (bool), manifest_references_config (bool),
    path (file path if found), base_config (trust settings), domain_configs
    (array of per-domain rules), findings (array of security issues found).
    """
    from apk_agent.tools.network_config import analyze_network_config as _analyze

    def _run():
        result = _analyze(_project.apktool_dir)
        return json.dumps(result, ensure_ascii=False, indent=2)[:12000]
    return _safe_call(_run, "analyze_network_config")


# ---------------------------------------------------------------------------
# NEW: Native library analyzer
# ---------------------------------------------------------------------------

@tool
def analyze_native_libs() -> str:
    """Analyze native .so libraries in the APK's lib/ directory.
    Detects: architectures, JNI methods, embedded strings (URLs, keys, crypto),
    and library sizes. Requires apktool_decompile to have been run first.

    Returns: JSON with keys: success, has_native_libs (bool), architectures (list),
    libraries (array of {name, arch, size_kb}), total_size_mb, jni_methods
    (array of detected JNI method names), interesting_strings (URLs, keys found in .so files).
    """
    from apk_agent.tools.native_analyzer import analyze_native_libs as _analyze

    def _run():
        result = _analyze(_project.apktool_dir)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "analyze_native_libs")


# ---------------------------------------------------------------------------
# NEW: Certificate analyzer
# ---------------------------------------------------------------------------

@tool
def analyze_certificate() -> str:
    """Analyze the APK's signing certificate — fingerprints, debug detection,
    signature scheme, and digest algorithm. Works directly on the APK file.

    Returns: JSON with keys: success, signing_files (list), signature_scheme,
    cert_hashes (SHA-1/SHA-256 fingerprints), is_debug_signed (bool),
    digest_algorithm, manifest_entries, findings (security issues with the certificate).
    """
    from apk_agent.tools.cert_analyzer import analyze_certificate as _analyze

    def _run():
        result = _analyze(_project.apk_path)
        return json.dumps(result, ensure_ascii=False, indent=2)[:10000]
    return _safe_call(_run, "analyze_certificate")


# ---------------------------------------------------------------------------
# NEW: Permission risk scorer
# ---------------------------------------------------------------------------

@tool
def score_permissions() -> str:
    """Score all APK permissions by risk level (CRITICAL/HIGH/MEDIUM/LOW).
    Uses aapt2 to extract permissions then applies risk scoring.

    Returns: JSON with keys: success, total_permissions, overall_risk (score string),
    risk_counts (dict of CRITICAL/HIGH/MEDIUM/LOW→count), permissions
    (array of {name, risk_level, abuse_potential description}).
    """
    from apk_agent.tools.aapt2 import dump_badging
    from apk_agent.tools.component_analyzer import score_permissions as _score

    def _run():
        # First get permissions from aapt2
        aapt2_result = dump_badging(
            aapt2_bin=_config.get_tool_path("aapt2") or "aapt2",
            apk_path=_project.apk_path,
            log_file=_log_file(),
        )
        permissions = aapt2_result.artifacts.get("permissions", [])
        if not permissions:
            return json.dumps({
                "success": True,
                "note": "No permissions found or aapt2 failed. Try parse_manifest instead.",
            })
        result = _score(permissions)
        return json.dumps(result, ensure_ascii=False, indent=2)[:12000]
    return _safe_call(_run, "score_permissions")


# ---------------------------------------------------------------------------
# NEW: Attack surface analyzer
# ---------------------------------------------------------------------------

@tool
def analyze_attack_surface() -> str:
    """Analyze the app's attack surface from AndroidManifest.xml.
    Lists exported components with risk scores, deep links, custom permissions,
    and intent filter mappings. Requires apktool_decompile first.

    Returns: JSON with keys: success, manifest_file, exported_components
    (array of {name, type, intent_filters}), deep_links (array of URI patterns),
    custom_permissions (list), findings (security issues), attack_surface_score
    (numeric risk rating: 0-100, higher = more exposed).
    """
    from apk_agent.tools.component_analyzer import analyze_attack_surface as _analyze

    def _run():
        manifest_path = _project.apktool_dir / "AndroidManifest.xml"
        result = _analyze(manifest_path)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "analyze_attack_surface")


# ---------------------------------------------------------------------------
# NEW: Evidence / forensic notebook
# ---------------------------------------------------------------------------

@tool
def save_evidence(category: str, title: str, detail: str = "", severity: str = "info", file_path: str = "", tags: str = "") -> str:
    """Save a finding/clue to the forensic evidence notebook.
    ALWAYS save important findings — vulnerabilities, suspicious patterns, file paths,
    crypto issues, hardcoded secrets, interesting method names — as evidence.
    This ensures nothing is lost even if context is compacted.

    Args:
        category: vuln|crypto|network|permission|component|string|pattern|patch|file|config|behavior|misc
        title: short title for the finding
        detail: detailed description with code snippets/evidence
        severity: critical|high|medium|low|info
        file_path: relevant file path (if any)
        tags: comma-separated tags (e.g. "ssl,pinning,bypass")
    """
    from apk_agent.tools.evidence import save_evidence as _save

    def _run():
        tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
        result = _save(
            _project.workspace_path, category, title, detail,
            severity=severity, file_path=file_path, tags=tag_list,
        )
        return json.dumps(result, ensure_ascii=False)
    return _safe_call(_run, "save_evidence")


@tool
def load_evidence(category: str = "", severity: str = "") -> str:
    """Load all saved evidence from the forensic notebook.
    Use this to review what you've found so far, especially after session resume
    or context compaction. Filter by category or severity.
    """
    from apk_agent.tools.evidence import load_evidence as _load

    def _run():
        result = _load(_project.workspace_path, category=category, severity=severity)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "load_evidence")


@tool
def search_evidence(query: str) -> str:
    """Search within saved evidence by keyword. Use to find specific findings."""
    from apk_agent.tools.evidence import search_evidence as _search

    def _run():
        result = _search(_project.workspace_path, query)
        return json.dumps(result, ensure_ascii=False, indent=2)[:10000]
    return _safe_call(_run, "search_evidence")


@tool
def get_evidence_summary() -> str:
    """Get a compact summary of all evidence — counts by category/severity and critical findings."""
    from apk_agent.tools.evidence import get_evidence_summary as _summary

    def _run():
        result = _summary(_project.workspace_path)
        return json.dumps(result, ensure_ascii=False, indent=2)
    return _safe_call(_run, "get_evidence_summary")


# ---------------------------------------------------------------------------
# NEW: Deep smali analysis (professional reversing)
# ---------------------------------------------------------------------------

@tool
def analyze_method_deep(smali_file: str, method_name: str) -> str:
    """Deep-analyze a specific method in a smali file.
    Returns full disassembly, register usage, API calls, string constants,
    branches, try/catch blocks, field access, object allocations.
    Use this for detailed understanding of how a method works.

    Args:
        smali_file: path to .smali file (relative to apktool dir or absolute)
        method_name: method name to analyze (e.g. 'checkServerTrusted', 'onCreate')

    Returns: JSON with keys: success, file, method (full signature), line_range [start, end],
    instruction_count, body (full method bytecode), registers_used (list),
    locals (register count), api_calls (array of {class, method, instruction}),
    string_constants (list), branches_and_jumps (control flow details).
    """
    from apk_agent.tools.deep_analyzer import analyze_method_deep as _analyze

    def _run():
        fpath = str(_resolve_file(smali_file))
        result = _analyze(fpath, method_name)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "analyze_method_deep")


@tool
def detect_protections() -> str:
    """Scan for ALL protection mechanisms in the APK:
    root detection, emulator detection, anti-debugging, anti-tampering,
    dynamic code loading, native layer calls, reflection, obfuscation,
    SSL pinning targets, and crypto weaknesses.
    Must run apktool_decompile first.

    When to use: Prefer unified_scan for comprehensive detection if SmaliIndex is built.
    Use this for quick protection scanning without building SmaliIndex.

    Returns: JSON with keys: success, files_scanned, total_findings,
    categories_found (list), findings (dict keyed by category name like
    ROOT_DETECTION, EMULATOR_DETECTION, ANTI_DEBUG, ANTI_TAMPER, SSL_PINNING,
    CRYPTO_WEAKNESS, etc. — each containing array of {file, line, pattern, severity}).
    """
    from apk_agent.tools.deep_analyzer import detect_protections as _detect

    def _run():
        result = _detect(str(_project.apktool_dir))
        return json.dumps(result, ensure_ascii=False, indent=2)[:20000]
    return _safe_call(_run, "detect_protections")


@tool
def trace_call_chain(target_method: str, depth: int = 3) -> str:
    """Trace the call chain TO a specific method (reverse call graph).
    Shows who calls this method, who calls the callers, etc.
    Essential for understanding how a security check is triggered.

    When to use: Prefer graph_callers (instant, pre-built graph) if code graph is built.
    Use trace_call_chain only when graph is not available — it scans files directly and is slower.

    Args:
        target_method: method name to trace (e.g. 'checkServerTrusted')
        depth: how many levels deep to trace (default: 3)

    Returns: JSON with keys: success, target, depth, call_chains
    (nested array showing caller→caller→...→target paths), total_callers.
    """
    from apk_agent.tools.deep_analyzer import trace_call_chain as _trace

    def _run():
        result = _trace(str(_project.apktool_dir), target_method, depth=depth)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "trace_call_chain")


@tool
def reconstruct_strings(smali_file: str) -> str:
    """Attempt to reconstruct hidden/encrypted strings from a smali file.
    Decodes byte arrays, char arrays, and other obfuscation patterns.

    When to use: Call this AFTER find_string_decryption_patterns identifies files with
    encryption/obfuscation. This tool extracts actual decrypted string values from a specific file.

    Args:
        smali_file: path to .smali file (relative to apktool dir or absolute)

    Returns: JSON with keys: success, file, strings_found (count), reconstructed
    (array of {original_bytes, decoded_value, method, encoding, confidence}).
    """
    from apk_agent.tools.deep_analyzer import reconstruct_strings as _reconstruct

    def _run():
        fpath = str(_resolve_file(smali_file))
        result = _reconstruct(fpath)
        return json.dumps(result, ensure_ascii=False, indent=2)[:10000]
    return _safe_call(_run, "reconstruct_strings")


# ---------------------------------------------------------------------------
# Refined / intelligent search tools
# ---------------------------------------------------------------------------


@tool
def refine_search(
    previous_results_json: str,
    refine_pattern: str,
    context_lines: int = 2,
) -> str:
    """Search WITHIN previous search results — narrows down without rescanning.
    Feed the output of search_in_code / context_search / multi_search here
    to drill deeper without re-reading the entire codebase.

    When to use: Use when a prior search returned 50+ results and you need to narrow down
    WITHOUT re-scanning all files. Much faster than running a new search_in_code.

    Args:
        previous_results_json: JSON string from a prior search result.
            Must contain a 'matches' array with objects that have 'file' keys.
        refine_pattern: New regex pattern to search for ONLY in those files.
        context_lines: Lines of context around each new match (default 2).

    Returns: JSON with keys: matches (filtered array of {file, line, content}),
    total (count of refined matches).
    """
    from apk_agent.tools.advanced_search import filter_results

    def _run():
        try:
            prev = json.loads(previous_results_json)
        except json.JSONDecodeError:
            return json.dumps({"success": False, "error": "Invalid JSON in previous_results_json"})
        result = filter_results(prev, refine_pattern, context_lines=context_lines)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "refine_search")


@tool
def batch_read_smali_methods(
    file_method_pairs_json: str,
) -> str:
    """Read multiple smali method bodies in ONE call instead of calling read_file many times.
    Extracts the full body of each requested method from each file.

    When to use: Use after graph_callees/graph_callers finds 5+ methods to examine.
    Reads all method bodies in 1 call instead of N sequential read_file calls.

    Args:
        file_method_pairs_json: JSON array of objects:
            [{"file": "smali/com/example/Foo.smali", "method": "checkCert"},
             {"file": "smali/com/example/Bar.smali", "method": "isRooted"}]
            Paths should be relative to the apktool dir.

    Returns: JSON with keys: success, results (array of {file, method, found (bool),
    body (method bytecode), line_start, line_end}), total_found.
    """
    from apk_agent.tools.advanced_search import batch_read_methods

    def _run():
        try:
            pairs = json.loads(file_method_pairs_json)
        except json.JSONDecodeError:
            return json.dumps({"success": False, "error": "Invalid JSON in file_method_pairs_json"})
        result = batch_read_methods(pairs, base_dir=str(_project.apktool_dir))
        return json.dumps(result, ensure_ascii=False, indent=2)[:20000]
    return _safe_call(_run, "batch_read_smali_methods")


@tool
def smart_search(
    query: str,
    search_type: str = "code",
    directory: Optional[str] = None,
    max_results: int = 30,
) -> str:
    """Intelligent search that auto-selects file extensions and excludes irrelevant dirs.
    Use this when you want a one-shot precise search without manually tweaking parameters.

    When to use: For auto-tuned searching when you don't want to specify extensions/exclusions.
    For manual control over file types and directories, use search_in_code instead.
    For search with surrounding context lines, use context_search.

    Args:
        query: Regex pattern to search for.
        search_type: One of:
            - "code": .java .kt .smali (excludes res, build, original, assets)
            - "config": .xml .json .properties .yml (excludes res/drawable, res/mipmap)
            - "resource": .xml in res/ only
            - "all": everything, no filtering
        directory: Base directory. Defaults to JADX + all smali dirs for "code", apktool for others.
        max_results: Maximum matches (default 30).

    Returns: JSON with keys: matches (array of {file, line, content}),
    total, dirs_searched.
    """
    from apk_agent.tools.advanced_search import smart_search as _smart

    if directory:
        base_dirs = [str(_resolve_dir(directory, default="jadx"))]
    elif search_type == "code":
        # Search BOTH jadx Java sources AND all smali directories
        base_dirs = [str(_project.jadx_dir)]
        for sd in _get_all_smali_dirs():
            base_dirs.append(str(sd))
    elif search_type == "resource":
        # Search only res/ under apktool
        res_dir = _project.apktool_dir / "res"
        base_dirs = [str(res_dir)] if res_dir.is_dir() else [str(_project.apktool_dir)]
    else:
        base_dirs = [str(_project.apktool_dir)]

    def _run():
        result = _smart(query, base_dirs, search_type=search_type, max_results=max_results,
                         exclude_packages=True)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "smart_search")


# ---------------------------------------------------------------------------
# Code Graph tools (NetworkX-powered)
# ---------------------------------------------------------------------------

# Module-level graph + index holders (loaded once per session)
_code_graph = None
_code_index = None
_smali_index = None  # SmaliIndex IR (from smali_ir module)


def _ensure_graph():
    """Load or build the code graph. Returns the graph."""
    global _code_graph
    if _code_graph is not None:
        return _code_graph

    from apk_agent.tools.code_graph import load_graph, build_code_graph, save_graph

    graph_path = Path(_project.outputs_dir) / "call_graph.pickle"
    G = load_graph(graph_path)
    if G is not None:
        _code_graph = G
        return G

    # Need to build it
    smali_dirs = _get_all_smali_dirs()
    if not smali_dirs:
        return None

    from apk_agent.progress import report_progress
    G = build_code_graph(smali_dirs, progress_callback=report_progress)
    save_graph(G, graph_path)
    _code_graph = G
    return G


def _ensure_index():
    """Load or build the code index. Returns the index dict."""
    global _code_index
    if _code_index is not None:
        return _code_index

    from apk_agent.tools.index_cache import load_index, build_code_index, save_index

    index_path = Path(_project.outputs_dir) / "code_index.json"
    idx = load_index(index_path)
    if idx is not None:
        _code_index = idx
        return idx

    # Need to build it
    smali_dirs = _get_all_smali_dirs()
    if not smali_dirs:
        return None

    from apk_agent.progress import report_progress
    idx = build_code_index(smali_dirs, jadx_dir=_project.jadx_dir,
                           progress_callback=report_progress)
    save_index(idx, index_path)
    _code_index = idx
    return idx


def _ensure_smali_index():
    """Load or build the SmaliIndex IR. Returns the SmaliIndex."""
    global _smali_index
    if _smali_index is not None:
        return _smali_index

    from apk_agent.tools.smali_ir import load_index as load_smali_index, build_index as build_smali_idx, save_index as save_smali_index

    index_path = Path(_project.outputs_dir) / "smali_index.pickle"
    idx = load_smali_index(index_path)
    if idx is not None:
        _smali_index = idx
        return idx

    # Need to build it
    smali_dirs = _get_all_smali_dirs()
    if not smali_dirs:
        return None

    from apk_agent.progress import report_progress
    idx = build_smali_idx(smali_dirs, progress_callback=report_progress)
    save_smali_index(idx, index_path)
    _smali_index = idx
    return idx


@tool
def build_graph_and_index() -> str:
    """Build (or rebuild) the code graph and class index from decompiled smali.
    Must have run apktool_decompile first. Building is automatic on first query,
    but call this explicitly after decompilation for best results.

    Creates:
    - Call graph (NetworkX): class→method→calls relationships for instant tracing
    - Code index (JSON): class/method/string lookup for instant search
    """
    global _code_graph, _code_index
    from apk_agent.tools.code_graph import build_code_graph, save_graph, get_graph_stats
    from apk_agent.tools.index_cache import build_code_index, save_index
    from apk_agent.progress import report_progress

    smali_dirs = _get_all_smali_dirs()
    if not smali_dirs:
        return json.dumps({"success": False, "error": "No smali directories found. Run apktool_decompile first."})

    def _run():
        global _code_graph, _code_index

        # Build graph
        G = build_code_graph(smali_dirs, progress_callback=report_progress)
        graph_path = Path(_project.outputs_dir) / "call_graph.pickle"
        g_stats = save_graph(G, graph_path)
        _code_graph = G

        # Build index
        idx = build_code_index(smali_dirs, jadx_dir=_project.jadx_dir,
                               progress_callback=report_progress)
        index_path = Path(_project.outputs_dir) / "code_index.json"
        i_stats = save_index(idx, index_path)
        _code_index = idx

        return json.dumps({
            "success": True,
            "graph": g_stats,
            "index": i_stats,
        }, indent=2)
    return _safe_call(_run, "build_graph_and_index")


@tool
def graph_callers(method_name: str, depth: int = 3) -> str:
    """Find all callers of a method — INSTANT, no file scanning.
    Uses the pre-built code graph. Much faster than trace_call_chain.

    Args:
        method_name: Method name to trace (e.g., "checkServerTrusted", "isRooted").
            Partial match supported.
        depth: How many levels up to trace (default 3).
    """
    from apk_agent.tools.code_graph import query_callers

    def _run():
        G = _ensure_graph()
        if G is None:
            return json.dumps({"success": False, "error": "No code graph. Run build_graph_and_index first."})
        result = query_callers(G, method_name, depth=depth)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "graph_callers")


@tool
def graph_callees(method_name: str, depth: int = 2) -> str:
    """Find all methods CALLED BY the given method — follow the forward call chain.
    Uses the pre-built code graph. Instant results.

    Args:
        method_name: Method name to trace (e.g., "processPayment", "onCreate").
        depth: How many levels deep to trace (default 2).
    """
    from apk_agent.tools.code_graph import query_callees

    def _run():
        G = _ensure_graph()
        if G is None:
            return json.dumps({"success": False, "error": "No code graph. Run build_graph_and_index first."})
        result = query_callees(G, method_name, depth=depth)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "graph_callees")


@tool
def graph_class_info(class_name: str) -> str:
    """Get full info about a class from the code graph — methods, inheritance,
    who calls it, fields. Partial match supported.

    Args:
        class_name: Class name (e.g., "SslPinningHelper", "PaymentManager").

    Returns: JSON with keys: success, found (bool), class (full name), matches
    (array of {name, super_class, interfaces, methods, fields, callers, callees,
    file_path}).
    """
    from apk_agent.tools.code_graph import query_class_info

    def _run():
        G = _ensure_graph()
        if G is None:
            return json.dumps({"success": False, "error": "No code graph. Run build_graph_and_index first."})
        result = query_class_info(G, class_name)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "graph_class_info")


@tool
def graph_find_path(source_method: str, target_method: str) -> str:
    """Find the shortest call path between two methods.
    Useful for understanding data flow: how does method A reach method B?

    Args:
        source_method: Starting method name.
        target_method: Ending method name.
    """
    from apk_agent.tools.code_graph import query_path

    def _run():
        G = _ensure_graph()
        if G is None:
            return json.dumps({"success": False, "error": "No code graph. Run build_graph_and_index first."})
        result = query_path(G, source_method, target_method)
        return json.dumps(result, ensure_ascii=False, indent=2)[:10000]
    return _safe_call(_run, "graph_find_path")


@tool
def graph_security_scan() -> str:
    """Scan the code graph for security-related methods: SSL pinning, root detection,
    crypto, anti-debug, anti-tamper, dynamic loading. Returns categorized results
    with caller counts so you know which methods are most important.
    """
    from apk_agent.tools.code_graph import find_security_methods

    def _run():
        G = _ensure_graph()
        if G is None:
            return json.dumps({"success": False, "error": "No code graph. Run build_graph_and_index first."})
        result = find_security_methods(G)
        return json.dumps(result, ensure_ascii=False, indent=2)[:20000]
    return _safe_call(_run, "graph_security_scan")


@tool
def graph_stats() -> str:
    """Get code graph statistics — total classes, methods, edges, hotspots.
    Shows the most-called methods (hotspots) which are often security-critical.
    """
    from apk_agent.tools.code_graph import get_graph_stats

    def _run():
        G = _ensure_graph()
        if G is None:
            return json.dumps({"success": False, "error": "No code graph available."})
        result = get_graph_stats(G)
        return json.dumps(result, ensure_ascii=False, indent=2)[:10000]
    return _safe_call(_run, "graph_stats")


# ---------------------------------------------------------------------------
# Code Index tools (persistent class/method/string lookup)
# ---------------------------------------------------------------------------


@tool
def index_lookup_class(query: str) -> str:
    """Look up classes by name from the persistent index — instant results.
    Partial match: "Payment" finds PaymentManager, PaymentHelper, etc.

    Args:
        query: Class name or partial match (e.g., "Payment", "Crypto", "SSL").
    """
    from apk_agent.tools.index_cache import lookup_class

    def _run():
        idx = _ensure_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No code index. Run build_graph_and_index first."})
        result = lookup_class(idx, query)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "index_lookup_class")


@tool
def index_lookup_method(method_name: str) -> str:
    """Find all classes containing a specific method — instant.
    Use this before read_file to know exactly WHERE a method lives.

    Args:
        method_name: Method name (e.g., "checkServerTrusted", "encrypt", "isRooted").
    """
    from apk_agent.tools.index_cache import lookup_method

    def _run():
        idx = _ensure_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No code index. Run build_graph_and_index first."})
        result = lookup_method(idx, method_name)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "index_lookup_method")


@tool
def index_lookup_string(query: str) -> str:
    """Find which classes use a specific string constant.
    Great for finding API endpoints, keys, URLs, error messages.

    Args:
        query: String to search for (e.g., "api_key", "https://", "/login").
    """
    from apk_agent.tools.index_cache import lookup_string

    def _run():
        idx = _ensure_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No code index. Run build_graph_and_index first."})
        result = lookup_string(idx, query)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "index_lookup_string")


@tool
def index_lookup_package(package_name: str) -> str:
    """List all classes in a Java package — instant.

    Args:
        package_name: Package name (e.g., "com.example.crypto", "payment").
    """
    from apk_agent.tools.index_cache import lookup_package

    def _run():
        idx = _ensure_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No code index. Run build_graph_and_index first."})
        result = lookup_package(idx, package_name)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "index_lookup_package")


# ---------------------------------------------------------------------------
# Automated bypass engine (APK Patcher) — high-performance batch patching
# ---------------------------------------------------------------------------


@tool
def auto_patch_bypass(
    categories: Optional[str] = None,
    custom_device_id: Optional[str] = None,
) -> str:
    """Automatically apply security bypass patches across ALL smali files at once.
    Uses parallel scanning + regex-based patching for SSL bypass, VPN bypass,
    license bypass, purchase bypass, root/tamper detection bypass, and more.

    This is a ONE-SHOT tool — it scans all smali dirs and applies all matching
    patterns in a single call. Much faster than manual patch plans.

    Args:
        categories: Comma-separated bypass categories to apply. If omitted, ALL are applied.
            Options: ssl_bypass, vpn_bypass, mock_location, license_bypass, pairip_bypass,
                     purchase_bypass, screenshot_bypass, usb_debug_bypass, device_spoof,
                     package_spoof, ads_removal
            Example: "ssl_bypass,vpn_bypass,license_bypass"
        custom_device_id: Custom Android device ID for spoofing (16 hex chars).
            Only used when device_spoof category is included.
    """
    from apk_agent.tools.apk_patcher import PatchCategory, run_smali_patches

    def _run():
        smali_dirs = _get_all_smali_dirs()
        if not smali_dirs:
            return json.dumps({"success": False, "error": "No smali directories found. Run apktool_decompile first."})

        cats = None
        if categories:
            cats = []
            for c in categories.split(","):
                c = c.strip().lower()
                try:
                    cats.append(PatchCategory(c))
                except ValueError:
                    valid = [pc.value for pc in PatchCategory]
                    return json.dumps({"success": False, "error": f"Unknown category '{c}'. Valid: {valid}"})

        from apk_agent.progress import report_progress
        stats = run_smali_patches(
            smali_dirs=smali_dirs,
            categories=cats,
            backup_dir=_project.patch_backup_dir,
            custom_device_id=custom_device_id,
        )
        return json.dumps(stats.to_dict(), ensure_ascii=False, indent=2)[:20000]
    return _safe_call(_run, "auto_patch_bypass")


@tool
def patch_flutter_ssl() -> str:
    """Patch Flutter's libflutter.so to disable SSL certificate verification.
    Uses pure Python binary hex matching — finds ssl_verify_peer_cert and
    patches it to return 0 (always succeed). No external tools needed.

    Supports arm64-v8a, armeabi-v7a, and x86_64 architectures.
    Only needed for Flutter apps — check lib/ for libflutter.so first.
    """
    from apk_agent.tools.apk_patcher import patch_flutter_ssl as _patch

    def _run():
        result = _patch(
            apktool_dir=_project.apktool_dir,
            backup_dir=_project.patch_backup_dir,
        )
        return json.dumps(result, ensure_ascii=False, indent=2)
    return _safe_call(_run, "patch_flutter_ssl")


@tool
def inject_network_security_config(cert_paths: Optional[str] = None) -> str:
    """Inject a permissive network_security_config.xml that trusts ALL certificates.
    Creates res/xml/network_security_config.xml with:
    - Cleartext traffic permitted for all domains
    - System certificates trusted with pin override
    - User-installed certificates trusted with pin override
    - Debug overrides enabled

    Also copies custom CA certificate files to res/raw/ if provided.

    Args:
        cert_paths: Optional comma-separated paths to custom CA certificate files (.pem/.crt).
            Example: "/path/to/burp_ca.pem,/path/to/mitmproxy.pem"
    """
    from apk_agent.tools.apk_patcher import inject_nsc

    def _run():
        certs = None
        if cert_paths:
            certs = [c.strip() for c in cert_paths.split(",") if c.strip()]
        result = inject_nsc(
            apktool_dir=_project.apktool_dir,
            cert_paths=certs,
        )
        return json.dumps(result, ensure_ascii=False, indent=2)
    return _safe_call(_run, "inject_network_security_config")


@tool
def patch_manifest_security() -> str:
    """Patch AndroidManifest.xml to remove security restrictions:
    - Remove split APK restrictions (splitTypes, isSplitRequired)
    - Remove Google Play license check providers
    - Remove vending/stamp metadata
    - Inject usesCleartextTraffic=true
    - Inject networkSecurityConfig reference
    - Add full storage permissions (READ/WRITE/MANAGE)
    - Downgrade targetSdkVersion to 28
    - Add requestLegacyExternalStorage=true
    - Update apktool.yml targetSdkVersion

    Run this AFTER inject_network_security_config for full effect.
    """
    from apk_agent.tools.apk_patcher import patch_manifest

    def _run():
        result = patch_manifest(apktool_dir=_project.apktool_dir)
        return json.dumps(result, ensure_ascii=False, indent=2)
    return _safe_call(_run, "patch_manifest_security")


@tool
def remove_ads() -> str:
    """Remove ad networks from the APK by patching smali code.
    Neutralizes 40+ ad networks: AdMob, Facebook, Unity, IronSource, AppLovin,
    Chartboost, Flurry, InMobi, MoPub, Tapjoy, Vungle, AppBrain, Smaato, etc.

    Patches: ad load/show calls → nop, ad status checks → false,
    loadAd methods → return-void, ad unit IDs → zeroed.

    Also applies license bypass patterns (allowAccess, connectToLicensingService).
    """
    from apk_agent.tools.apk_patcher import PatchCategory, run_smali_patches

    def _run():
        smali_dirs = _get_all_smali_dirs()
        if not smali_dirs:
            return json.dumps({"success": False, "error": "No smali directories found. Run apktool_decompile first."})

        from apk_agent.progress import report_progress
        stats = run_smali_patches(
            smali_dirs=smali_dirs,
            categories=[PatchCategory.ADS_REMOVAL, PatchCategory.LICENSE_BYPASS],
            backup_dir=_project.patch_backup_dir,
        )
        return json.dumps(stats.to_dict(), ensure_ascii=False, indent=2)[:20000]
    return _safe_call(_run, "remove_ads")


@tool
def list_bypass_categories() -> str:
    """List all available automated bypass categories with pattern counts.
    Shows what auto_patch_bypass can do and how many patterns exist per category.
    Use this to decide which categories to apply.
    """
    from apk_agent.tools.apk_patcher import list_patch_categories

    result = list_patch_categories()
    return json.dumps(result, ensure_ascii=False, indent=2)


    result = list_patch_categories()
    return json.dumps(result, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# SOTA Analysis tools (SmaliIndex IR, Unified Scanner, Data Flow, etc.)
# ---------------------------------------------------------------------------


@tool
def build_smali_index() -> str:
    """Build (or rebuild) the SmaliIndex — a full IR (Intermediate Representation)
    of every smali class, method, instruction, field, and annotation.
    Enables instant API caller lookup, string constant search, class hierarchy
    queries, and method-category classification.
    Must have run apktool_decompile first. Build this BEFORE unified_scan or taint analysis.
    """
    global _smali_index
    from apk_agent.tools.smali_ir import build_index as build_smali_idx, save_index as save_smali_idx, index_stats

    smali_dirs = _get_all_smali_dirs()
    if not smali_dirs:
        return json.dumps({"success": False, "error": "No smali directories found. Run apktool_decompile first."})

    def _run():
        global _smali_index
        from apk_agent.progress import report_progress
        idx = build_smali_idx(smali_dirs, progress_callback=report_progress)
        out_path = Path(_project.outputs_dir) / "smali_index.pickle"
        save_smali_idx(idx, out_path)
        _smali_index = idx
        stats = index_stats(idx)
        stats["success"] = True
        return json.dumps(stats, indent=2)
    return _safe_call(_run, "build_smali_index")


@tool
def smali_index_stats() -> str:
    """Get SmaliIndex statistics — total classes, methods, strings, API calls indexed.
    Useful to confirm the index is built and see its scope.

    Returns: JSON with keys: success, total_classes, total_methods,
    total_instructions, total_strings, total_api_targets,
    method_categories (dict of category→count), hierarchy_roots (int), built_at (timestamp).
    """
    from apk_agent.tools.smali_ir import index_stats

    def _run():
        idx = _ensure_smali_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No SmaliIndex. Run build_smali_index first."})
        stats = index_stats(idx)
        stats["success"] = True
        return json.dumps(stats, indent=2)
    return _safe_call(_run, "smali_index_stats")


@tool
def unified_scan(severity_filter: Optional[str] = None, max_findings: int = 500) -> str:
    """Run the unified security scanner on the SmaliIndex IR.
    Replaces and improves upon scan_vulnerabilities, detect_protections, etc.
    Checks 35+ detection rules across SSL, root, crypto, storage, WebView,
    IPC, SQL injection, dynamic class loading, reflection, cloud secrets, and more.
    Returns deduplicated, severity-ranked findings with evidence chains.

    Args:
        severity_filter: Optional — only return findings of this severity ("critical", "high", "medium", "low", "info").
        max_findings: Maximum findings to return (default 500).

    Returns: JSON with keys: success, total_findings, severity_summary (dict of level→count),
    category_summary (dict of category→count), classes_scanned, methods_scanned,
    findings (array of {id, rule, severity, category, class, method, file, line,
    description, evidence, cwe}).
    """
    from apk_agent.tools.unified_scanner import scan

    def _run():
        idx = _ensure_smali_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No SmaliIndex. Run build_smali_index first."})
        result = scan(idx, severity_filter=severity_filter, max_findings=max_findings)
        return json.dumps(result, ensure_ascii=False, indent=2)[:30000]
    return _safe_call(_run, "unified_scan")


@tool
def analyze_data_flow(class_name: str, method_name: str) -> str:
    """Analyze register-level data flow within a specific method.
    Tracks const-string values, object types, field accesses, and method return values
    through registers. Shows what each register holds at every instruction.

    Args:
        class_name: Full smali class name (e.g., "Lcom/example/CryptoHelper;").
        method_name: Method name (e.g., "encrypt", "doFinal"). First match in the class is used.

    Returns: JSON with keys: class, register_states (dict of instruction_index→register→value),
    sensitive_flows (array of data paths through crypto/security APIs),
    hardcoded_into_crypto (list of hardcoded values flowing into crypto calls),
    data_flow_summary (human-readable overview).
    """
    from apk_agent.tools.data_flow import analyze_method_flow

    def _run():
        idx = _ensure_smali_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No SmaliIndex. Run build_smali_index first."})
        cls = idx.get_class(class_name)
        if cls is None:
            # Try partial match
            matches = idx.search_classes(class_name)
            if not matches:
                return json.dumps({"success": False, "error": f"Class not found: {class_name}"})
            cls = matches[0]
        target = None
        for m in cls.methods:
            if method_name in m.name:
                target = m
                break
        if target is None:
            return json.dumps({"success": False, "error": f"Method '{method_name}' not found in {cls.name}"})
        result = analyze_method_flow(target)
        result["class"] = cls.name
        return json.dumps(result, ensure_ascii=False, indent=2)[:20000]
    return _safe_call(_run, "analyze_data_flow")


@tool
def run_taint_analysis(max_depth: int = 5, max_flows: int = 200) -> str:
    """Run inter-procedural taint analysis across the entire codebase.
    Traces data from sensitive SOURCES (device IDs, location, credentials,
    user input) to dangerous SINKS (logging, network, IPC, storage, SMS).
    Returns taint flows ranked by severity with full call chains.

    Args:
        max_depth: BFS depth for tracing flows (default 5).
        max_flows: Maximum taint flows to return (default 200).

    Returns: JSON with keys: success, total_flows, taint_sources_found (count),
    taint_type_summary (dict of source_type→count), sink_type_summary (dict of sink_type→count),
    flows (array of {source, sink, source_type, sink_type, severity, call_chain (list of method names),
    depth, description}).
    """
    from apk_agent.tools.data_flow import run_taint_analysis as _run_taint

    def _run():
        idx = _ensure_smali_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No SmaliIndex. Run build_smali_index first."})
        result = _run_taint(idx, max_depth=max_depth, max_flows=max_flows)
        return json.dumps(result, ensure_ascii=False, indent=2)[:25000]
    return _safe_call(_run, "run_taint_analysis")


@tool
def find_hardcoded_crypto() -> str:
    """Scan all crypto-related methods for hardcoded keys, IVs, and secrets.
    Uses register-level data flow to detect const-string values passed to
    SecretKeySpec, Cipher.init, IvParameterSpec, MessageDigest, etc.

    Returns: JSON with keys: success, total_crypto_methods (scanned count),
    methods_with_hardcoded (count), findings (array of {class, method, crypto_api,
    hardcoded_value, register, value_type, severity}).
    """
    from apk_agent.tools.data_flow import find_hardcoded_crypto as _find_crypto

    def _run():
        idx = _ensure_smali_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No SmaliIndex. Run build_smali_index first."})
        result = _find_crypto(idx)
        return json.dumps(result, ensure_ascii=False, indent=2)[:20000]
    return _safe_call(_run, "find_hardcoded_crypto")


@tool
def generate_bypass_plans(max_bypasses: int = 50) -> str:
    """Generate automated bypass plans (smali patches + Frida scripts) for
    detected security protections. Runs unified_scan first, then generates
    bypasses for: root detection, emulator detection, debug detection,
    SSL pinning, certificate pinning, SafetyNet, signature verification.

    Args:
        max_bypasses: Maximum bypass plans to generate (default 50).

    Returns: JSON with keys: success, total_bypasses, by_type (dict of protection_type→count),
    bypasses (array of {type, target_class, target_method, difficulty (easy/medium/hard),
    smali_patch (ready-to-apply patch plan JSON), frida_script (JavaScript hook code),
    description}).
    """
    from apk_agent.tools.unified_scanner import scan
    from apk_agent.tools.auto_bypass import generate_bypasses

    def _run():
        idx = _ensure_smali_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No SmaliIndex. Run build_smali_index first."})
        # First run the scanner to get findings
        scan_result = scan(idx)
        findings = scan_result.get("findings", [])
        if not findings:
            return json.dumps({"success": True, "bypasses": [], "message": "No security protections detected to bypass."})
        result = generate_bypasses(idx, findings, max_bypasses=max_bypasses)
        return json.dumps(result, ensure_ascii=False, indent=2)[:30000]
    return _safe_call(_run, "generate_bypass_plans")


@tool
def analyze_manifest_deep() -> str:
    """Deep semantic analysis of AndroidManifest.xml with code cross-referencing.
    Goes beyond basic parsing — checks for:
    - Backup/debuggable/cleartext misconfigurations
    - Dangerous permission combinations
    - Exported components without protection (cross-refs code for input validation)
    - Deep link attack surfaces
    - Content provider path traversal risks
    - SDK version security implications

    Returns: JSON with keys: success, package, total_findings, severity_summary
    (dict of level→count), findings (array of security issues), config_analysis,
    attack_surface (exported components/deep links), deep_links, component_summary.
    """
    from apk_agent.tools.manifest_analyzer import analyze_manifest

    def _run():
        manifest_path = _project.apktool_dir / "AndroidManifest.xml"
        if not manifest_path.exists():
            return json.dumps({"success": False, "error": "AndroidManifest.xml not found. Run apktool_decompile first."})
        # Optionally pass the SmaliIndex for code cross-referencing
        idx = _ensure_smali_index()  # May return None — that's OK
        result = analyze_manifest(str(manifest_path), index=idx)
        return json.dumps(result, ensure_ascii=False, indent=2)[:25000]
    return _safe_call(_run, "analyze_manifest_deep")


@tool
def scan_cloud_secrets() -> str:
    """Scan for hardcoded cloud credentials and API keys in the codebase.
    Detects: Firebase (RTDB, Storage, API key), AWS (access key, secret, S3),
    GCP (API key, OAuth), Azure connection strings, Slack/Telegram/Discord webhooks,
    PEM private keys, hardcoded JWTs, and generic API secrets.
    Values are auto-redacted in output for safe reporting.

    Returns: JSON with keys: success, total_findings, severity_summary (dict),
    category_summary (dict of cloud_provider→count), strings_searched (count),
    findings (array of {type, provider, value_redacted, file, line, severity, description}).
    """
    from apk_agent.tools.cloud_scanner import scan_cloud_config, scan_cloud_config_files

    def _run():
        idx = _ensure_smali_index()
        if idx is not None:
            result = scan_cloud_config(idx)
        else:
            # Fallback to file-based scanning
            apk_dir = _project.apktool_dir
            if not apk_dir.is_dir():
                return json.dumps({"success": False, "error": "No decompiled directory. Run apktool_decompile first."})
            result = scan_cloud_config_files(str(apk_dir))
        return json.dumps(result, ensure_ascii=False, indent=2)[:20000]
    return _safe_call(_run, "scan_cloud_secrets")


# ---------------------------------------------------------------------------
# Tool list for graph construction
# ---------------------------------------------------------------------------

ALL_TOOLS = [
    # Decompilation
    apktool_decompile,
    jadx_decompile,
    dex2jar_convert,
    # Quick recon (no decompilation needed)
    aapt2_dump,
    extract_strings,
    analyze_certificate,
    score_permissions,
    # Manifest & component analysis
    parse_manifest,
    identify_app_packages,
    analyze_attack_surface,
    analyze_network_config,
    analyze_native_libs,
    # Smali deep analysis
    scan_smali_classes,
    analyze_smali_class,
    find_string_decryption_patterns,
    find_method_xrefs,
    # Professional reversing tools
    analyze_method_deep,
    detect_protections,
    trace_call_chain,
    reconstruct_strings,
    # Vulnerability scanning
    scan_vulnerabilities,
    list_vuln_patterns,
    # Advanced search
    context_search,
    multi_search,
    xref_search,
    directory_overview,
    # Intelligent / refined search
    refine_search,
    batch_read_smali_methods,
    smart_search,
    # Code Graph (NetworkX) — instant call chain tracing
    build_graph_and_index,
    graph_callers,
    graph_callees,
    graph_class_info,
    graph_find_path,
    graph_security_scan,
    graph_stats,
    # Code Index — instant class/method/string lookup
    index_lookup_class,
    index_lookup_method,
    index_lookup_string,
    index_lookup_package,
    # Targeted analysis (encrypted payloads, native code, dynamic loading)
    search_interceptors,
    search_native_code,
    search_dynamic_loaders,
    # File operations
    read_file,
    write_file,
    search_in_code,
    list_files,
    # Evidence / forensic notebook
    save_evidence,
    load_evidence,
    search_evidence,
    get_evidence_summary,
    # Patching
    apply_smali_patch,
    preview_smali_patch,
    # Automated bypass engine (APK Patcher)
    auto_patch_bypass,
    patch_flutter_ssl,
    inject_network_security_config,
    patch_manifest_security,
    remove_ads,
    list_bypass_categories,
    # Build & Sign
    apktool_build,
    zipalign_apk_tool,
    sign_apk,
    # Reporting
    generate_report,
    # SOTA Analysis (SmaliIndex IR, Unified Scanner, Taint, Bypass, Cloud)
    build_smali_index,
    smali_index_stats,
    unified_scan,
    analyze_data_flow,
    run_taint_analysis,
    find_hardcoded_crypto,
    generate_bypass_plans,
    analyze_manifest_deep,
    scan_cloud_secrets,
]
