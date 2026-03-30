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

from apk_agent.progress import progress_manager, TaskStatus, set_current_task

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
    "find_entry_points", "map_hierarchy",
    "analyze_shared_prefs", "scan_assets_secrets",
})


def set_tool_context(config, project) -> None:
    """Set the config and project for tool execution. Called once per session."""
    global _config, _project, _tool_cache, _code_graph, _code_index
    _config = config
    _project = project
    _tool_cache.clear()  # fresh cache per session
    _code_graph = None   # reset graph — prevent stale data across sessions
    _code_index = None   # reset index — will be rebuilt/loaded on first use


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
    if low.startswith("smali_classes") or low.startswith("smali/"):
        candidate = _project.apktool_dir / d
        if candidate.is_dir():
            return candidate
        return candidate

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
      - absolute path → returned as-is

    Also searches all smali_classesN/ dirs when the file is missing from smali/.
    """
    p = Path(file_path)
    if p.is_absolute():
        return p

    fpath = file_path.replace("\\", "/")

    # Strip accidental "decompiled/apktool/" prefix
    for prefix in ("decompiled/apktool/", "decompiled\\apktool\\"):
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
    Returns the path to the generated JAR file.
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
        start_line: 1-based start line for reading a specific range. 0 = from beginning.
                    Use this to read large files in chunks instead of loading everything.
        end_line: 1-based end line for reading a specific range. 0 = to default max.
    """
    from apk_agent.tools.file_ops import read_file as _read

    p = Path(file_path)
    if not p.is_absolute():
        p = Path(_project.workspace_path) / file_path

    # If file doesn't exist, try common fallback locations
    if not p.is_file():
        candidates = [
            Path(_project.workspace_path) / "decompiled" / "jadx_src" / "sources" / file_path,
            Path(_project.workspace_path) / "decompiled" / "jadx_src" / file_path,
            Path(_project.workspace_path) / "decompiled" / "apktool" / file_path,
            _project.jadx_dir / file_path,
            _project.apktool_dir / file_path,
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

    Args:
        pattern: Regex pattern to search for (e.g., "CertificatePinner", "isRooted", "api[_-]?key").
            For crypto, search imports: "import javax\\.crypto\\.Cipher" rather than broad "Crypto|AES".
        directory: Directory to search in. Defaults to JADX sources dir. Can be "smali" for smali code.
        file_extensions: Comma-separated extensions (e.g., ".java,.xml"). Defaults to .java,.kt,.smali.
        exclude_dirs: Comma-separated directory names to SKIP (e.g., "build,test,res,original").
            Use this to avoid noise from generated/resource directories.
        max_results: Maximum number of matches to return (default 50). Lower = faster + less noise.
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
        return f"Invalid JSON: {e}"

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

    findings = json.loads(findings_json)
    patches = json.loads(patch_results_json)
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

    Args:
        directory: Smali directory to scan. Defaults to apktool output.
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

    Args:
        directory: Directory to scan. Defaults to JADX sources.
            Use "smali" or "apktool" for smali code.
        severity_filter: Only show findings >= this level.
            Options: CRITICAL, HIGH, MEDIUM, LOW, INFO.
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

    Args:
        class_or_method: Class or method name (e.g., "SslPinningHelper",
            "checkServerTrusted").
        search_type: "callers" (who calls this?) or "callees" (what does this call?).
        directory: Directory to search. Defaults to JADX sources.
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
    """
    from apk_agent.tools.native_analyzer import analyze_native_libs as _analyze

    def _run():
        result = _analyze(_project.apktool_dir)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "analyze_native_libs")


# ---------------------------------------------------------------------------
# Deep Analysis tools
# ---------------------------------------------------------------------------

@tool
def validate_patch(file_path: str) -> str:
    """Validate smali syntax AFTER patching — catch errors BEFORE apktool_build.
    Checks for unclosed methods, missing .end directives, unknown opcodes, etc.
    Run this after apply_smali_patch to avoid build failures.

    Args:
        file_path: Path to the .smali file to validate (absolute or relative).
    """
    from apk_agent.tools.deep_analysis import validate_smali_syntax

    p = _resolve_file(file_path)

    def _run():
        result = validate_smali_syntax(p)
        return json.dumps(result, ensure_ascii=False, indent=2)[:10000]
    return _safe_call(_run, "validate_patch")


@tool
def find_entry_points() -> str:
    """Discover ALL app entry points in execution order:
    ContentProviders (auto-init first) → Application.onCreate() →
    LauncherActivity → BootReceivers → ExportedServices.

    Start analysis from here — these are where security checks are initialized.
    """
    from apk_agent.tools.deep_analysis import find_entry_points as _find

    manifest_path = _project.apktool_dir / "AndroidManifest.xml"

    def _run():
        result = _find(manifest_path, _get_all_smali_dirs())
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "find_entry_points")


@tool
def map_hierarchy(target_class: str = "") -> str:
    """Map the class inheritance hierarchy from smali code.
    Find all parents/children of a class, or get an overview of
    security-relevant hierarchies (TrustManager, Interceptor, etc.).

    Args:
        target_class: Class to trace (e.g., "MyTrustManager", "Lcom/app/Foo;").
            If empty, returns overview of all hierarchies with security highlights.
    """
    from apk_agent.tools.deep_analysis import map_class_hierarchy

    def _run():
        result = map_class_hierarchy(_get_all_smali_dirs(), target_class=target_class)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "map_hierarchy")


@tool
def analyze_shared_prefs() -> str:
    """Find ALL SharedPreferences usage — preference files, stored keys, and
    security-sensitive values (tokens, flags, license checks).

    Identifies boolean flags that may be bypass targets (is_premium, is_rooted).
    """
    from apk_agent.tools.deep_analysis import analyze_shared_prefs as _analyze

    dirs = [_project.jadx_dir]
    for sd in _get_all_smali_dirs():
        dirs.append(sd)

    def _run():
        result = _analyze(dirs)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "analyze_shared_prefs")


@tool
def extract_native_strings(so_file: str) -> str:
    """Extract readable strings from a compiled .so native library.
    Finds: JNI method names, crypto library indicators, URLs/endpoints,
    hardcoded API keys/tokens. Like Unix 'strings' but with classification.

    Args:
        so_file: Path to the .so file (e.g., "lib/arm64-v8a/libnative.so").
    """
    from apk_agent.tools.deep_analysis import extract_strings_from_binary

    p = Path(so_file)
    if not p.is_absolute():
        p = _project.apktool_dir / so_file

    def _run():
        result = extract_strings_from_binary(p)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "extract_native_strings")


@tool
def scan_assets_secrets() -> str:
    """Scan assets/, res/raw/, res/xml/ for embedded secrets:
    API keys, Firebase URLs, AWS keys, private keys, hardcoded passwords,
    bearer tokens. WebView apps often leak keys in JavaScript assets.
    """
    from apk_agent.tools.deep_analysis import scan_assets_for_secrets

    def _run():
        result = scan_assets_for_secrets(_project.apktool_dir)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "scan_assets_secrets")


@tool
def diff_patched_file(original_backup: str, current_file: str) -> str:
    """Show exact changes between original and patched smali files.
    Use after patching to verify changes are correct before building.

    Args:
        original_backup: Path to the backup/original file.
        current_file: Path to the current (patched) file.
    """
    from apk_agent.tools.deep_analysis import diff_smali_files

    orig = _resolve_file(original_backup)
    curr = _resolve_file(current_file)

    def _run():
        result = diff_smali_files(orig, curr)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "diff_patched_file")


# ---------------------------------------------------------------------------
# NEW: Certificate analyzer
# ---------------------------------------------------------------------------

@tool
def analyze_certificate() -> str:
    """Analyze the APK's signing certificate — fingerprints, debug detection,
    signature scheme, and digest algorithm. Works directly on the APK file.
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
    Returns risk-assessed permissions with abuse potential descriptions.
    Uses aapt2 to extract permissions then applies risk scoring.
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
    Returns categorized results with file locations and severity.
    Must run apktool_decompile first.
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

    Args:
        target_method: method name to trace (e.g. 'checkServerTrusted')
        depth: how many levels deep to trace (default: 3)
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

    Args:
        smali_file: path to .smali file (relative to apktool dir or absolute)
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

    Args:
        previous_results_json: JSON string from a prior search result.
            Must contain a 'matches' array with objects that have 'file' keys.
        refine_pattern: New regex pattern to search for ONLY in those files.
        context_lines: Lines of context around each new match (default 2).
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

    Args:
        file_method_pairs_json: JSON array of objects:
            [{"file": "smali/com/example/Foo.smali", "method": "checkCert"},
             {"file": "smali/com/example/Bar.smali", "method": "isRooted"}]
            Paths should be relative to the apktool dir.
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

    Args:
        query: Regex pattern to search for.
        search_type: One of:
            - "code": .java .kt .smali (excludes res, build, original, assets)
            - "config": .xml .json .properties .yml (excludes res/drawable, res/mipmap)
            - "resource": .xml in res/ only
            - "all": everything, no filtering
        directory: Base directory. Defaults to JADX + all smali dirs for "code", apktool for others.
        max_results: Maximum matches (default 30).
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


def _ensure_graph():
    """Load or build the code graph. Returns the graph or None."""
    global _code_graph
    if _code_graph is not None:
        return _code_graph

    from apk_agent.tools.code_graph import load_graph, build_code_graph, save_graph

    graph_path = Path(_project.outputs_dir) / "call_graph.pickle"
    G = load_graph(graph_path)
    if G is not None:
        if G.number_of_nodes() == 0:
            # Stale empty graph on disk — discard and rebuild
            G = None
        else:
            _code_graph = G
            return G

    # Need to build it
    smali_dirs = _get_all_smali_dirs()
    if not smali_dirs:
        return None

    from apk_agent.progress import report_progress
    G = build_code_graph(smali_dirs, progress_callback=report_progress)
    if G.number_of_nodes() == 0:
        return None  # Don't cache empty graphs
    save_graph(G, graph_path)
    _code_graph = G
    return G


def _ensure_index():
    """Load or build the code index. Returns the index dict or None."""
    global _code_index
    if _code_index is not None:
        return _code_index

    from apk_agent.tools.index_cache import load_index, build_code_index, save_index

    index_path = Path(_project.outputs_dir) / "code_index.json"
    idx = load_index(index_path)
    if idx is not None:
        if idx.get("stats", {}).get("total_classes", 0) == 0:
            # Stale empty index on disk — discard and rebuild
            idx = None
        else:
            _code_index = idx
            return idx

    # Need to build it
    smali_dirs = _get_all_smali_dirs()
    if not smali_dirs:
        return None

    from apk_agent.progress import report_progress
    idx = build_code_index(smali_dirs, jadx_dir=_project.jadx_dir,
                           progress_callback=report_progress)
    if idx.get("stats", {}).get("total_classes", 0) == 0:
        return None  # Don't cache empty indexes
    save_index(idx, index_path)
    _code_index = idx
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
    # Deep Analysis
    validate_patch,
    find_entry_points,
    map_hierarchy,
    analyze_shared_prefs,
    extract_native_strings,
    scan_assets_secrets,
    diff_patched_file,
    # Build & Sign
    apktool_build,
    zipalign_apk_tool,
    sign_apk,
    # Reporting
    generate_report,
]
