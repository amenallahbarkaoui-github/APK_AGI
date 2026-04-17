"""LangChain @tool definitions wrapping all Tool Layer functions.

These are the tools the LLM agent can call during its ReAct loop.
Each tool returns a structured JSON string so the LLM can reason about results.
All tools are wrapped with error recovery — they never crash the agent.
"""

from __future__ import annotations

import json
import traceback
import uuid
import threading
import concurrent.futures
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
    global _config, _project, _tool_cache, _smali_index, _scratchpad, _task_plan, _patch_journal
    _config = config
    _project = project
    _tool_cache.clear()  # fresh cache per session
    _smali_index = None
    _scratchpad = {}
    _task_plan = []
    _patch_journal = []


# ---------------------------------------------------------------------------
# Module-level scratchpad and task plan (read by graph.py for state sync)
# ---------------------------------------------------------------------------
_scratchpad: dict = {}
_task_plan: list[dict] = []

# ---------------------------------------------------------------------------
# Patch journal — authoritative record of all patch operations this session.
# Used by generate_report to produce accurate patch data instead of relying
# on the LLM to reconstruct patch_results_json from memory.
# ---------------------------------------------------------------------------
_patch_journal: list[dict] = []


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


# ---------------------------------------------------------------------------
# Global tool output cap — prevents context bloat from any single tool
# ---------------------------------------------------------------------------
_TOOL_OUTPUT_CAP = 8_000  # max chars per tool result (head + tail)
_CAP_HEAD = 5_500
_CAP_TAIL = 2_000


def _cap_tool_output(result: str) -> str:
    """Truncate a tool result that exceeds the global cap.

    Keeps the head (usually JSON keys + first findings) and tail
    (usually closing braces + summary fields) so structured output
    remains parsable.
    """
    if not isinstance(result, str) or len(result) <= _TOOL_OUTPUT_CAP:
        return result
    skipped = len(result) - _CAP_HEAD - _CAP_TAIL
    return (
        result[:_CAP_HEAD]
        + f"\n\n... [{skipped} chars truncated — use more specific queries to narrow results] ...\n\n"
        + result[-_CAP_TAIL:]
    )


def _safe_call(func, tool_name: str, *args, _cache_hint: str = "", **kwargs) -> str:
    """Wrap any tool function with progress tracking, caching, error recovery, and timeout."""
    # Check cache for expensive idempotent tools
    cache_key = None
    if tool_name in _CACHEABLE_TOOLS:
        # Use explicit cache_hint when provided (closure-based tools);
        # fall back to stringified args/kwargs for direct-call tools.
        if _cache_hint:
            cache_key = f"{tool_name}:{_cache_hint}"
        else:
            norm_args = str(args).replace("\\", "/")
            norm_kwargs = str(sorted(kwargs.items())).replace("\\", "/")
            cache_key = f"{tool_name}:{norm_args}:{norm_kwargs}"
        if cache_key in _tool_cache:
            return _tool_cache[cache_key]

    task_id = f"tool_{tool_name}_{uuid.uuid4().hex[:4]}"
    set_current_task(task_id)
    progress_manager.start_task(task_id, tool_name)

    # Tool execution timeout (seconds). Most tools finish in <30s.
    # Long-running ones (auto_patch_bypass, apktool_build) may need more.
    _TOOL_TIMEOUT = 300  # 5 minutes max

    try:
        # Run tool with a timeout to prevent infinite hangs
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(func, *args, **kwargs)
            try:
                result = future.result(timeout=_TOOL_TIMEOUT)
            except concurrent.futures.TimeoutError:
                progress_manager.complete_task(task_id, success=False, error="Tool execution timed out")
                return json.dumps({
                    "success": False,
                    "error": f"Tool '{tool_name}' timed out after {_TOOL_TIMEOUT}s.",
                    "recovery_hint": "The tool took too long. Try a more targeted approach or smaller scope.",
                })
        # Global output cap — prevent any single tool from bloating context.
        # Individual tool limits ([:N]) still apply first; this is a safety net.
        result = _cap_tool_output(result)
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

    # If the LLM accidentally passed a FILE path as directory, use its parent
    _FILE_EXTS = (".smali", ".java", ".kt", ".xml", ".json", ".txt")
    if any(low.endswith(ext) for ext in _FILE_EXTS):
        d = str(Path(d).parent).replace("\\", "/")
        low = d.lower().replace("\\", "/")

    # Exact alias matching
    if low in ("jadx", "jadx_src"):
        return _project.jadx_dir
    if low == "apktool":
        return _project.apktool_dir
    if low == "smali":
        return _project.apktool_dir / "smali"

    # Handle "jadx_src/..." or "jadx/..." paths — strip prefix, resolve under jadx_dir.
    # jadx puts Java sources under jadx_src/sources/, so try with and without "sources/".
    if low.startswith("jadx_src/") or low.startswith("jadx/"):
        sub = d.split("/", 1)[1] if "/" in d else d.split("\\", 1)[1]
        # Try direct: jadx_dir / sub  (covers jadx_src/sources/com/foo)
        candidate = _project.jadx_dir / sub
        if candidate.is_dir():
            return candidate
        # Try with sources/ inserted: jadx_dir / sources / sub (covers jadx_src/com/foo → jadx_src/sources/com/foo)
        candidate_src = _project.jadx_dir / "sources" / sub
        if candidate_src.is_dir():
            return candidate_src
        return candidate  # best guess

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

    # Bare path like "com/psiphon3" or "B2" — check all smali dirs + jadx sources
    if not Path(directory).is_absolute():
        for smali_d in _get_all_smali_dirs():
            test = smali_d / d
            if test.is_dir():
                return test
        # Also check jadx sources dir (for bare Java package paths like "com/pandavpn/...")
        jadx_sources = _project.jadx_dir / "sources" / d
        if jadx_sources.is_dir():
            return jadx_sources

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
    # Try jadx_dir directly (covers "sources/com/foo" passed as directory)
    jadx_sub = _project.jadx_dir / d
    if jadx_sub.is_dir():
        return jadx_sub
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

    When to use: Run this as one of the FIRST steps in any analysis. Required before
    any smali reading, patching, manifest analysis, or SmaliIndex building.

    Returns: Text summary with the output directory path, list of smali directories found,
    and any warnings from apktool.
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

    When to use: Run alongside apktool_decompile for readable Java. JADX output
    is easier to read than smali; use it for understanding logic before patching.

    Returns: Text summary with the output directory path, discovered Java packages,
    and total files decompiled.
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
# Build integrity helpers (called automatically by apktool_build)
# ---------------------------------------------------------------------------

def _pre_build_patch_check() -> list[str]:
    """Before building, verify that patched smali files still contain our changes.

    Compares each backed-up file against its current version.  If a file has
    been overwritten or reverted (e.g. by a second decompilation), the diff
    disappears — that means our patch is gone.
    """
    warnings: list[str] = []
    try:
        backup_dir = _project.patch_backup_dir
        if not backup_dir.is_dir():
            return []
        diffs_dir = _project.patch_diffs_dir
        if not diffs_dir.is_dir():
            return []

        # Each .diff file encodes what we changed.  Read a few key lines.
        for diff_file in sorted(diffs_dir.iterdir()):
            if not diff_file.name.endswith(".diff"):
                continue
            try:
                diff_text = diff_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            # Extract the target file from the diff header (--- a/smali/...)
            import re as _re
            m = _re.search(r'^--- a/(.+)$', diff_text, _re.MULTILINE)
            if not m:
                continue
            rel_path = m.group(1)
            target = _project.apktool_dir / rel_path
            if not target.is_file():
                warnings.append(f"Patched file MISSING: {rel_path}")
                continue

            # Check that at least one "+" line from the diff is present in the file
            added_lines = [
                line[1:].strip()
                for line in diff_text.splitlines()
                if line.startswith("+") and not line.startswith("+++")
                and len(line.strip()) > 5
            ]
            if not added_lines:
                continue  # deletion-only patch, can't verify easily

            try:
                current = target.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            # Check if any of the added lines appear in the current file
            found = any(al in current for al in added_lines[:5])
            if not found:
                warnings.append(
                    f"PATCH REVERTED: {rel_path} — our added code is no longer present! "
                    f"Re-apply the patch before building."
                )
    except Exception:
        pass  # never block the build
    return warnings[:10]


def _post_build_patch_check() -> list[str]:
    """After a successful build, re-read patched files to confirm patches survived.

    apktool can silently drop changes in edge cases.  This catches that.
    """
    warnings: list[str] = []
    try:
        diffs_dir = _project.patch_diffs_dir
        if not diffs_dir.is_dir():
            return []

        import re as _re
        checked = 0
        for diff_file in sorted(diffs_dir.iterdir()):
            if checked >= 5:  # spot-check up to 5 files
                break
            if not diff_file.name.endswith(".diff"):
                continue
            try:
                diff_text = diff_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            m = _re.search(r'^--- a/(.+)$', diff_text, _re.MULTILINE)
            if not m:
                continue
            rel_path = m.group(1)
            target = _project.apktool_dir / rel_path
            if not target.is_file():
                continue

            added_lines = [
                line[1:].strip()
                for line in diff_text.splitlines()
                if line.startswith("+") and not line.startswith("+++")
                and len(line.strip()) > 5
            ]
            if not added_lines:
                continue

            try:
                current = target.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            found = any(al in current for al in added_lines[:5])
            if not found:
                warnings.append(
                    f"PATCH LOST IN BUILD: {rel_path} — patch code not found after rebuild. "
                    f"Re-apply and rebuild."
                )
            checked += 1
    except Exception:
        pass
    return warnings[:10]


# ---------------------------------------------------------------------------
# Build & Sign tools
# ---------------------------------------------------------------------------


@tool
def apktool_build() -> str:
    """Rebuild the APK from the (possibly patched) apktool decompiled project.
    Run this after applying smali patches to produce a new unsigned APK.

    When to use: After ALL patches are applied and you are ready to produce
    the modified APK. Follow with zipalign_apk_tool then sign_apk.

    Returns: Text summary with success/failure status and path to the rebuilt
    unsigned APK (outputs/patched-unsigned.apk).
    """
    import shutil as _shutil
    from apk_agent.tools.apktool import build

    # --- PRE-BUILD: verify patched files still contain our patches ---
    pre_warnings = _pre_build_patch_check()

    # Clear apktool's incremental-build cache so modified smali files
    # are always recompiled into fresh .dex.  Without this, apktool may
    # reuse stale .dex from a previous build and silently ignore patches.
    build_cache = Path(_project.apktool_dir) / "build"
    if build_cache.is_dir():
        _shutil.rmtree(build_cache, ignore_errors=True)

    output_apk = Path(_project.workspace_path) / "outputs" / "patched-unsigned.apk"
    result = build(
        apktool_bin=_config.get_tool_path("apktool") or "apktool",
        project_dir=_project.apktool_dir,
        output_apk=output_apk,
        log_file=_log_file(),
        force_all=True,
    )
    build_output = result.to_llm_str()

    # --- POST-BUILD: verify patches survived the rebuild ---
    post_warnings = []
    if result.success:
        post_warnings = _post_build_patch_check()

    # Append warnings to the build output
    if pre_warnings or post_warnings:
        build_output += "\n\n--- PATCH INTEGRITY CHECKS ---"
        for w in pre_warnings:
            build_output += f"\n⚠️ PRE-BUILD: {w}"
        for w in post_warnings:
            build_output += f"\n⚠️ POST-BUILD: {w}"
        if post_warnings:
            build_output += ("\n\n🔴 Some patches may not have survived the build! "
                            "Re-apply the missing patches and rebuild.")

    return build_output


@tool
def zipalign_apk_tool() -> str:
    """Zip-align the rebuilt unsigned APK (required before signing with apksigner).
    Aligns uncompressed entries on 4-byte boundaries for better runtime performance.
    Run after apktool_build and before sign_apk.

    When to use: ALWAYS run between apktool_build and sign_apk. Required for
    apksigner; jarsigner can work without it but alignment improves runtime performance.

    Returns: Text result with success/failure status and path to the aligned APK
    (outputs/patched-aligned.apk).
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

    When to use: LAST step in the build pipeline (after apktool_build → zipalign_apk_tool).
    Automatically uses the aligned APK if available, otherwise the unsigned APK.

    Returns: Text summary with success/failure status and path to the signed APK
    (outputs/patched-signed.apk).
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

    When to use: Run this BEFORE decompilation for a quick overview of the APK
    (package name, permissions, components). Faster than apktool_decompile.

    Returns: Text summary with package name, version code/name, SDK versions,
    permissions list, and declared components (activities, services, receivers, providers).
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

    When to use: Run early in recon to discover hardcoded secrets, API endpoints,
    and suspicious strings without decompilation.

    Returns: JSON with keys: total_strings, classified (object with url, email,
    api_key, aws_key, firebase, bearer_token, private_key, base64 arrays),
    raw_sample (first N unclassified strings).
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

    When to use: Run EARLY (right after apktool_decompile) to identify the app's
    own packages and separate them from third-party SDKs. This focuses subsequent
    searches on app code only.

    Returns: JSON with keys: success, main_package, target_packages (list of app
    package prefixes), app_component_packages, app_smali_packages,
    third_party_detected (list of SDK packages), recommendation (text guidance).
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

    When to use: When you need to see actual file contents. Use after search tools
    (index_lookup_*, search_in_code, smart_search) locate a file of interest.

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

    # If still not found, search for the filename in jadx and smali dirs
    if not p.is_file():
        fname = Path(file_path.replace("\\", "/")).name
        nearby: list[str] = []
        # Search jadx sources
        jadx_sources = _project.jadx_dir / "sources"
        if jadx_sources.is_dir():
            for hit in jadx_sources.rglob(fname):
                nearby.append(str(hit))
                if len(nearby) >= 5:
                    break
        # Search smali dirs for .smali equivalent
        if fname.endswith(".java"):
            smali_name = fname.replace(".java", ".smali")
            for sd in _get_all_smali_dirs():
                for hit in sd.rglob(smali_name):
                    nearby.append(str(hit))
                    if len(nearby) >= 8:
                        break
        if nearby:
            return json.dumps({
                "success": False,
                "error": f"File not found: {file_path}",
                "similar_files_found": nearby,
                "hint": "The exact path doesn't exist. Try one of the similar files above, "
                        "or read the .smali version instead.",
            }, ensure_ascii=False, indent=2)

    result = _read(p, start_line=start_line, end_line=end_line)
    return json.dumps(result, ensure_ascii=False, indent=2)[:12000]


@tool
def write_file(file_path: str, content: str) -> str:
    """Write or overwrite a file in the decompiled project.
    Use this for XML configs, new resource files, or small non-smali edits.

    ⚠️  DO NOT use this to rewrite entire .smali files — use apply_smali_patch
    or inject_smali_code instead. If you must write a .smali file, validity
    checks will be enforced automatically.

    When to use: For small direct edits to specific files. For structured smali patches
    with backup/diff tracking, use apply_smali_patch instead.

    Args:
        file_path: Absolute path or path relative to the project workspace.
        content: The full file content to write.

    Returns: JSON with keys: success (bool), path (absolute path written),
    bytes_written (int).
    """
    import re as _re

    p = Path(file_path)
    if not p.is_absolute():
        p = Path(_project.workspace_path) / file_path

    # --- Smali validation guard ------------------------------------------
    if p.suffix == ".smali":
        # 1. Must have a .class directive
        if not _re.search(r'^\s*\.class\s+', content, _re.MULTILINE):
            return json.dumps({"success": False,
                "error": "BLOCKED: .smali file has no .class directive — content is corrupt. "
                         "Use apply_smali_patch or inject_smali_code instead of write_file."})

        # 2. Detect broken class descriptors: bare Package/Name; without L prefix
        #    Valid: Lcom/app/Foo;  Invalid: com/app/Foo; (missing L)
        #    Look for references like ", IF0/y;" or "->field:IF0/y;" where L is missing
        broken_refs = _re.findall(
            r'(?<![L\w/])([A-Za-z]\w*/\w[^\s;]*;)', content
        )
        # Filter: only flag if it looks like a class descriptor (has / and ends with ;)
        # but doesn't start with L and isn't a known type prefix
        real_broken = []
        for ref in broken_refs:
            # Skip if it starts with a known type like Ljava, or is just a path
            if ref.startswith("L") or ref.startswith("["):
                continue
            # Must look like Package/Name; pattern (at least one /)
            if "/" in ref and ref.endswith(";"):
                real_broken.append(ref)
        if real_broken:
            examples = ", ".join(real_broken[:5])
            return json.dumps({"success": False,
                "error": f"BLOCKED: .smali file has broken class descriptors missing 'L' prefix: "
                         f"{examples}. This would corrupt the APK. "
                         f"Use apply_smali_patch or inject_smali_code instead of write_file."})

        # 3. .method / .end method must be balanced
        opens = len(_re.findall(r'^\s*\.method\s+', content, _re.MULTILINE))
        closes = len(_re.findall(r'^\s*\.end\s+method', content, _re.MULTILINE))
        if opens != closes:
            return json.dumps({"success": False,
                "error": f"BLOCKED: .smali file has unbalanced method blocks "
                         f"({opens} .method vs {closes} .end method). "
                         f"Use apply_smali_patch or inject_smali_code instead of write_file."})

        # 4. Auto-backup before overwriting existing smali
        if p.is_file():
            bak = p.with_suffix(".smali.bak")
            if not bak.exists():
                try:
                    import shutil
                    shutil.copy2(p, bak)
                except OSError:
                    pass

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

    # Auto-detect smali search: explicit "smali" dir OR .smali in extensions with no dir
    low_dir = (directory or "").strip().lower().replace("\\", "/")
    has_smali_ext = exts and any(e.strip().lower() in (".smali", "smali") for e in exts)
    search_all_smali = low_dir in ("smali", "apktool/smali", "apktool") or (
        not low_dir and has_smali_ext
    )

    def _run():
        if search_all_smali:
            # Search all smali dirs (smali/, smali_classes2/, smali_classes3/, ...)
            all_matches = []
            smali_dirs = _get_all_smali_dirs()
            for smali_d in smali_dirs:
                result = search_in_files(smali_d, pattern, file_extensions=exts,
                                          exclude_dirs=excl, max_results=max_results)
                if isinstance(result, dict) and result.get("matches"):
                    all_matches.extend(result["matches"])
                elif isinstance(result, list):
                    all_matches.extend(result)
            # Also search jadx if extensions are mixed (not smali-only)
            non_smali_exts = [e for e in (exts or []) if e.strip().lower() not in (".smali", "smali")]
            if non_smali_exts or not exts:
                try:
                    jadx_result = search_in_files(_project.jadx_dir, pattern,
                                                   file_extensions=non_smali_exts or None,
                                                   exclude_dirs=excl, max_results=max_results)
                    if isinstance(jadx_result, dict) and jadx_result.get("matches"):
                        all_matches.extend(jadx_result["matches"])
                except Exception:
                    pass
            return json.dumps({"matches": all_matches[:max_results],
                              "total": len(all_matches),
                              "smali_dirs_searched": len(smali_dirs)},
                             ensure_ascii=False, indent=2)[:15000]
        else:
            search_dir = _resolve_dir(directory, default="jadx")
            result = search_in_files(search_dir, pattern, file_extensions=exts,
                                      exclude_dirs=excl, max_results=max_results)
            return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "search_in_code", _cache_hint=f"{pattern}:{directory}:{file_extensions}:{exclude_dirs}:{max_results}")


@tool
def list_files(
    directory: Optional[str] = None,
    max_depth: int = 2,
    file_extensions: Optional[str] = None,
) -> str:
    """List files and directories in the decompiled project.
    Use this to understand the project structure.

    When to use: To explore directory layout, find specific file types, or verify
    that decompilation produced expected output. Use directory_overview for a
    high-level summary instead.

    Args:
        directory: Directory to list. Defaults to the JADX sources directory.
        max_depth: How deep to recurse (default 2).
        file_extensions: Comma-separated extensions to filter (e.g., ".smali,.java").
            If omitted, all files are shown.

    Returns: JSON with keys: root (base directory), total_files, total_dirs,
    entries (array of {name, type: file|dir, size, children: [...]}).
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
# Feature-check mapping (exhaustive premium/license detection)
# ---------------------------------------------------------------------------


@tool
def map_feature_checks(
    feature: str,
    extra_keywords: str = "",
) -> str:
    """Automatically map ALL check points for a feature (premium, license, etc.).

    This runs index lookups, SharedPrefs analysis, string searches, and graph
    queries to build a comprehensive map of every method, field, and SharedPrefs
    key that gates the specified feature.  Use the returned map to ensure you
    patch ALL check points, not just the first one you find.

    When to use: BEFORE writing any patch for a premium/license/subscription
    bypass.  This prevents the #1 failure mode: patching 1 out of 7 checks.

    Args:
        feature: The feature to map.  Examples: "premium", "pro", "subscribe",
                 "license", "trial", "ads", "vip".
        extra_keywords: Optional comma-separated extra keywords to search for
                        (e.g. "gold,diamond,elite").

    Returns: JSON with keys: boolean_getters (methods returning Z related to
    the feature), int_getters (methods returning I that may encode state),
    string_refs (hardcoded strings mentioning the feature), shared_prefs
    (SharedPreferences keys), callers (who reads these values), paywall_methods
    (UI gating methods), total_check_points (count of unique locations).
    """
    def _run():
        return _map_feature_checks_impl(feature, extra_keywords)
    return _safe_call(_run, "map_feature_checks")


def _map_feature_checks_impl(feature: str, extra_keywords: str) -> str:
    """Internal implementation of map_feature_checks."""
    import re as _re
    from apk_agent.tools.index_cache import lookup_method, lookup_string, lookup_class
    from apk_agent.tools.code_graph import query_callers as _qc
    from apk_agent.tools.deep_analysis import analyze_shared_prefs as _asp

    # Build keyword list
    keywords = [feature.strip().lower()]
    # Common synonyms
    _synonyms = {
        "premium": ["pro", "paid", "subscribe", "subscription", "licensed", "vip"],
        "pro": ["premium", "paid", "subscribe", "subscription", "licensed"],
        "license": ["licensed", "premium", "purchase", "activation"],
        "subscribe": ["subscription", "premium", "pro", "billing"],
        "ads": ["ad", "banner", "interstitial", "rewarded", "admob"],
        "trial": ["free_trial", "premium", "expire", "expiry"],
    }
    for syn in _synonyms.get(feature.lower(), []):
        if syn not in keywords:
            keywords.append(syn)
    if extra_keywords:
        for kw in extra_keywords.split(","):
            kw = kw.strip().lower()
            if kw and kw not in keywords:
                keywords.append(kw)

    # --- Step 1: Find boolean getters via index ---
    idx = _ensure_index()
    boolean_getters: list[dict] = []
    int_getters: list[dict] = []
    string_refs: list[dict] = []

    if idx:
        # Method lookup: isPremium, isPro, isSubscribed, etc.
        getter_prefixes = ["is", "get", "has", "can", "check", "should", "verify"]
        searched_methods: set[str] = set()
        for kw in keywords:
            for prefix in getter_prefixes:
                mname = f"{prefix}{kw.capitalize()}"
                if mname in searched_methods:
                    continue
                searched_methods.add(mname)
                result = lookup_method(idx, mname)
                for m in result.get("methods", []):
                    entry = {
                        "method": m.get("full_name", ""),
                        "class": m.get("class", ""),
                        "file": m.get("file", ""),
                    }
                    boolean_getters.append(entry)

            # Also do a raw keyword search for under-the-radar methods
            result = lookup_method(idx, kw)
            for m in result.get("methods", []):
                entry = {
                    "method": m.get("full_name", ""),
                    "class": m.get("class", ""),
                    "file": m.get("file", ""),
                }
                if entry not in boolean_getters and entry not in int_getters:
                    int_getters.append(entry)

        # String lookup: "premium", "pro", "FREE", "PREMIUM", etc.
        for kw in keywords:
            for variant in [kw, kw.upper(), kw.capitalize()]:
                result = lookup_string(idx, variant)
                for s in result.get("matches", result.get("string_matches", []))[:10]:
                    string_refs.append(s)

    # --- Step 2: SharedPreferences analysis ---
    shared_prefs_hits: list[dict] = []
    try:
        search_dirs = _get_all_smali_dirs()
        jadx = _project.jadx_dir
        if jadx.is_dir():
            search_dirs.append(jadx)
        sp_result = _asp(search_dirs)
        for flag in sp_result.get("boolean_flags_potential_bypass", []):
            key = flag.get("key", "").lower()
            if any(kw in key for kw in keywords):
                shared_prefs_hits.append(flag)
        for key_name, refs in sp_result.get("all_keys_sample", {}).items():
            if any(kw in key_name.lower() for kw in keywords):
                shared_prefs_hits.append({"key": key_name, "refs": refs[:3]})
    except Exception:
        pass

    # --- Step 3: Graph callers for discovered methods ---
    callers_map: list[dict] = []
    G = _ensure_graph()
    if G:
        seen: set[str] = set()
        for getter in (boolean_getters + int_getters)[:15]:
            mname = getter.get("method", "").split("->")[-1].split("(")[0] if "->" in getter.get("method", "") else ""
            if not mname or mname in seen:
                continue
            seen.add(mname)
            cr = _qc(G, mname, depth=2)
            for chain in cr.get("call_chains", [])[:5]:
                callers_map.append({
                    "target": chain.get("target", ""),
                    "caller": chain.get("caller", ""),
                    "caller_file": chain.get("caller_file", ""),
                })

    # --- Step 4: Paywall / UI gate methods ---
    paywall_methods: list[dict] = []
    if idx:
        paywall_names = ["showPaywall", "showUpgrade", "showPurchase", "showPremium",
                         "showSubscri", "openStore", "openBilling", "showPro",
                         "upgrade", "paywall", "locked"]
        for pn in paywall_names:
            result = lookup_method(idx, pn)
            for m in result.get("methods", []):
                paywall_methods.append({
                    "method": m.get("full_name", ""),
                    "file": m.get("file", ""),
                })

    # --- Step 5: BEHAVIORAL ANALYSIS — find gating methods by code patterns ---
    # This catches obfuscated methods like a()Z that perform subscription checks
    # by analyzing WHAT the code DOES, not what it's NAMED.
    behavioral_hits: list[dict] = []

    # Patterns that identify gating/check logic in method bodies
    # (defined here so Steps 5, 7 can both use them):
    _GATE_PATTERNS = [
        # Date/time comparisons (expiry checks)
        _re.compile(r'invoke-.*Calendar|invoke-.*Date|invoke-.*TimeUnit|invoke-.*before\(|invoke-.*after\(|invoke-.*compareTo\(', _re.I),
        # Boolean field reads followed by returns
        _re.compile(r'iget-boolean|sget-boolean'),
        # String equality checks (role == "TRIER", type == "FREE")
        _re.compile(r'invoke-.*equals\('),
        # Numeric comparisons (type == 0, level >= 2)
        _re.compile(r'if-(?:eq|ne|gt|ge|lt|le)\s'),
    ]

    # Collect all entity-class files found so far for behavioral scanning
    entity_files: set[str] = set()
    for g in boolean_getters + int_getters:
        f = g.get("file", "")
        if f:
            entity_files.add(f)
    # Also add classes that contain keyword strings
    for s in string_refs:
        for cls in s.get("used_by", []):
            cls_info = idx.get("classes", {}).get(cls, {}) if idx else {}
            f = cls_info.get("file", "")
            if f:
                entity_files.add(f)

    try:
        for efile in list(entity_files)[:20]:
            try:
                fpath = _project.apktool_dir / efile
                if not fpath.is_file():
                    # Try resolving differently
                    for smali_dir in _get_all_smali_dirs():
                        candidate = smali_dir / efile
                        if candidate.is_file():
                            fpath = candidate
                            break
                if not fpath.is_file():
                    continue
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            # Find all methods returning Z (boolean) or I (int)
            for m in _re.finditer(
                r'\.method\s+(.*?)([\w<>$]+)\((.*?)\)([ZI])\s*\n(.*?)\.end method',
                text, _re.DOTALL
            ):
                access = m.group(1).strip()
                mname = m.group(2)
                ret_type = m.group(4)
                body = m.group(5)

                # Skip already-found methods
                full_sig = f"{mname}({m.group(3)}){ret_type}"
                already = any(
                    mname in g.get("method", "")
                    for g in boolean_getters + int_getters
                )

                # Check if method body has gating behavior
                gate_reasons = []
                for pat in _GATE_PATTERNS:
                    if pat.search(body):
                        gate_reasons.append(pat.pattern[:50])

                if gate_reasons and not already:
                    # This is a behaviorally-detected gating method
                    behavioral_hits.append({
                        "method": full_sig,
                        "file": efile,
                        "return_type": "boolean" if ret_type == "Z" else "int",
                        "behavior": gate_reasons[:3],
                        "access": access,
                        "note": "Found by BEHAVIORAL analysis (code pattern), not by name",
                    })
    except Exception:
        pass

    # --- Step 6: STRUCTURAL ENTITY SCAN — find subscription model classes ---
    # Look at ALL classes in string_refs that have multiple boolean/int getters—
    # these are likely the subscription entity class with ALL the check fields.
    entity_methods: list[dict] = []
    try:
        entity_classes: set[str] = set()
        for g in boolean_getters + int_getters:
            c = g.get("class", "")
            if c:
                entity_classes.add(c)

        if idx:
            for cls_name in list(entity_classes)[:10]:
                cls_info = idx.get("classes", {}).get(cls_name, {})
                if not cls_info:
                    continue
                fpath_str = cls_info.get("file", "")
                if not fpath_str:
                    continue
                try:
                    fpath = _project.apktool_dir / fpath_str
                    if not fpath.is_file():
                        for sd in _get_all_smali_dirs():
                            c2 = sd / fpath_str
                            if c2.is_file():
                                fpath = c2
                                break
                    if not fpath.is_file():
                        continue
                    text = fpath.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue

                # Find ALL methods returning Z or I in this entity class
                for m in _re.finditer(
                    r'\.method\s+(.*?)([\w<>$]+)\((.*?)\)([ZI])\s*\n',
                    text
                ):
                    full = f"{m.group(2)}({m.group(3)}){m.group(4)}"
                    already_listed = any(
                        m.group(2) in g.get("method", "")
                        for g in boolean_getters + int_getters + behavioral_hits
                    )
                    if not already_listed:
                        entity_methods.append({
                            "method": full,
                            "class": cls_name,
                            "file": fpath_str,
                            "return_type": "boolean" if m.group(4) == "Z" else "int",
                            "note": "Same entity class — may also gate features",
                        })
    except Exception:
        pass

    # --- Step 7: BILLING FRAMEWORK TRACING ---
    # Find the premium system through billing API references.
    # Billing library class names are NEVER obfuscated — they're Android SDK classes.
    # This is the most reliable discovery method for obfuscated apps.
    billing_hits: list[dict] = []
    _step5_files = set(entity_files)  # Track what Step 5 already scanned
    try:
        # 7a: Find app classes that IMPLEMENT billing interfaces
        _BILLING_INTERFACES = [
            "PurchasesUpdatedListener", "BillingClientStateListener",
            "PurchasesResponseListener", "SkuDetailsResponseListener",
            "ProductDetailsResponseListener", "AcknowledgePurchaseResponseListener",
            "ConsumeResponseListener", "PurchaseHistoryResponseListener",
        ]
        if idx:
            for cls_name, cls_info in idx.get("classes", {}).items():
                ifaces = cls_info.get("interfaces", [])
                for iface in ifaces:
                    iface_short = iface.split("/")[-1].rstrip(";")
                    if iface_short in _BILLING_INTERFACES:
                        f = cls_info.get("file", "")
                        billing_hits.append({
                            "class": cls_name,
                            "file": f,
                            "implements": iface_short,
                            "note": f"Implements {iface_short} — this is the app's purchase handler",
                        })
                        if f:
                            entity_files.add(f)

        # 7b: Use graph to find APP classes that call billing API methods
        _BILLING_METHODS = [
            "queryPurchasesAsync", "queryPurchases", "launchBillingFlow",
            "acknowledgePurchase", "consumeAsync", "querySkuDetailsAsync",
            "queryProductDetailsAsync", "onPurchasesUpdated",
            "getPurchaseState", "getProducts", "getOrderId",
            "isAcknowledged", "startConnection",
            # RevenueCat
            "getCustomerInfo", "restorePurchases",
        ]
        _SDK_FILTER = frozenset({
            "billingclient", "vending", "revenuecat", "qonversion",
            "adapty", "android/billingclient", "billing/api",
        })
        G = _ensure_graph()
        if G:
            for bm in _BILLING_METHODS:
                cr = _qc(G, bm, depth=1)
                for chain in cr.get("call_chains", [])[:5]:
                    caller = chain.get("caller", "")
                    caller_file = chain.get("caller_file", "")
                    if any(sdk in caller.lower() for sdk in _SDK_FILTER):
                        continue
                    billing_hits.append({
                        "method": caller,
                        "file": caller_file,
                        "calls": bm,
                        "note": f"Calls billing API {bm} — trace to find entity class",
                    })
                    if caller_file:
                        entity_files.add(caller_file)

        # 7c: Find classes that reference billing-related CLASSES by name
        _BILLING_CLASSES = [
            "BillingClient", "Purchase", "SkuDetails", "ProductDetails",
            "BillingResult", "BillingFlowParams",
        ]
        if idx:
            for bc in _BILLING_CLASSES:
                result = lookup_class(idx, bc)
                for c in result.get("classes", [])[:3]:
                    cls_name = c.get("class", "")
                    # Skip the SDK classes themselves
                    if any(sdk in cls_name.lower() for sdk in _SDK_FILTER):
                        continue
                    f = c.get("file", "")
                    if f and f not in entity_files:
                        entity_files.add(f)
                        billing_hits.append({
                            "class": cls_name,
                            "file": f,
                            "references": bc,
                            "note": f"App class referencing {bc}",
                        })

        # 7d: Trace FIELDS in billing-connected classes to find entity classes.
        # The purchase handler often has a field like `UserInfo mUserInfo` or
        # `SubscriptionModel mSub` — tracing field types finds the entity.
        _new_entity_files: set[str] = set()
        for bfile in list(entity_files - _step5_files)[:15]:
            try:
                fpath = _project.apktool_dir / bfile
                if not fpath.is_file():
                    for sd in _get_all_smali_dirs():
                        c2 = sd / bfile
                        if c2.is_file():
                            fpath = c2
                            break
                if not fpath.is_file():
                    continue
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            # Find field types that point to app classes (potential entities)
            for fm in _re.finditer(r'\.field\s+.*?:(L[\w/$]+;)', text):
                field_type = fm.group(1)
                # Skip framework/SDK types
                if any(field_type.startswith(f"L{p}") for p in [
                    "java/", "android/", "kotlin/", "androidx/",
                    "com/google/", "com/android/billingclient/",
                ]):
                    continue
                # This is an app class field — the field type class may be the entity
                if idx:
                    fc_info = idx.get("classes", {}).get(field_type, {})
                    ff = fc_info.get("file", "")
                    if ff and ff not in entity_files:
                        _new_entity_files.add(ff)

            # Also look for invoke-* calls to app classes (not SDK) that return
            # entity-like objects — the purchase handler calls entity methods
            for inv in _re.finditer(
                r'invoke-\w+\s+\{[^}]*\},\s*(L[\w/$]+;)->([\w<>$]+)\([^)]*\)(L[\w/$]+;)',
                text
            ):
                ret_class = inv.group(3)
                if any(ret_class.startswith(f"L{p}") for p in [
                    "java/", "android/", "kotlin/", "androidx/",
                    "com/google/", "com/android/billingclient/",
                ]):
                    continue
                if idx:
                    rc_info = idx.get("classes", {}).get(ret_class, {})
                    rf = rc_info.get("file", "")
                    if rf and rf not in entity_files:
                        _new_entity_files.add(rf)

        entity_files.update(_new_entity_files)

        # 7e: Behavioral scan on ALL newly discovered files (from billing tracing)
        for bfile in list(entity_files - _step5_files)[:20]:
            try:
                fpath = _project.apktool_dir / bfile
                if not fpath.is_file():
                    for sd in _get_all_smali_dirs():
                        c2 = sd / bfile
                        if c2.is_file():
                            fpath = c2
                            break
                if not fpath.is_file():
                    continue
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            for m in _re.finditer(
                r'\.method\s+(.*?)([\w<>$]+)\((.*?)\)([ZI])\s*\n(.*?)\.end method',
                text, _re.DOTALL
            ):
                mname = m.group(2)
                ret_type = m.group(4)
                body = m.group(5)
                full_sig = f"{mname}({m.group(3)}){ret_type}"

                gate_reasons = []
                for pat in _GATE_PATTERNS:
                    if pat.search(body):
                        gate_reasons.append(pat.pattern[:50])

                if gate_reasons:
                    already = any(
                        mname in g.get("method", "")
                        for g in behavioral_hits
                    )
                    if not already:
                        behavioral_hits.append({
                            "method": full_sig,
                            "file": bfile,
                            "return_type": "boolean" if ret_type == "Z" else "int",
                            "behavior": gate_reasons[:3],
                            "access": m.group(1).strip(),
                            "note": "Found via BILLING API tracing (billing-connected class)",
                        })
    except Exception:
        pass

    # Deduplicate
    def _dedup(lst: list[dict]) -> list[dict]:
        seen_keys: set[str] = set()
        out = []
        for item in lst:
            key = json.dumps(item, sort_keys=True)
            if key not in seen_keys:
                seen_keys.add(key)
                out.append(item)
        return out

    boolean_getters = _dedup(boolean_getters)[:20]
    int_getters = _dedup(int_getters)[:20]
    string_refs = _dedup(string_refs)[:20]
    shared_prefs_hits = _dedup(shared_prefs_hits)[:15]
    callers_map = _dedup(callers_map)[:30]
    paywall_methods = _dedup(paywall_methods)[:10]
    behavioral_hits = _dedup(behavioral_hits)[:15]
    entity_methods = _dedup(entity_methods)[:15]
    billing_hits = _dedup(billing_hits)[:15]

    total = (len(boolean_getters) + len(int_getters) + len(shared_prefs_hits)
             + len(paywall_methods) + len(behavioral_hits) + len(entity_methods)
             + len(billing_hits))

    return json.dumps({
        "success": True,
        "feature": feature,
        "keywords_searched": keywords,
        "boolean_getters": boolean_getters,
        "int_getters": int_getters,
        "behavioral_checks": behavioral_hits,
        "entity_class_methods": entity_methods,
        "billing_purchase_system": billing_hits,
        "string_refs": string_refs,
        "shared_prefs": shared_prefs_hits,
        "callers": callers_map,
        "paywall_methods": paywall_methods,
        "total_check_points": total,
        "instruction": (
            f"Found {total} potential check points for '{feature}'. "
            + (f"BILLING SYSTEM ({len(billing_hits)} hits): Found the app's purchase/billing "
               f"handler classes through billing API tracing — these are the ENTRY POINTS to the "
               f"premium system. Trace their fields and callees to find the entity class. "
               if billing_hits else "")
            + (f"BEHAVIORAL checks ({len(behavioral_hits)}): Methods found by analyzing "
               f"code BEHAVIOR — these are often the REAL gating logic in obfuscated apps. "
               if behavioral_hits else "")
            + (f"Entity class methods ({len(entity_methods)}): OTHER boolean/int methods "
               f"in the same subscription entity class — check each one. "
               if entity_methods else "")
            + f"NEXT STEPS: 1) For each billing/behavioral hit, run "
              f"analyze_subscription_model(file) to deep-analyze the class. "
              f"2) Read jadx source for the same class. "
              f"3) Patch ALL gate methods. "
              f"Save: save_evidence('patch_map', <this>)."
        ),
    }, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Deep subscription/premium model analysis
# ---------------------------------------------------------------------------

@tool
def analyze_subscription_model(smali_file: str) -> str:
    """Deep-analyze a subscription/user entity class to find ALL gating methods.

    Unlike map_feature_checks (keyword-based), this tool reads a SPECIFIC class
    file and analyzes every method's BEHAVIOR to find subscription checks, expiry
    logic, role comparisons, feature flags, and cached premium state — even when
    the code is fully obfuscated with single-letter names.

    When to use: After map_feature_checks identifies a subscription entity class
    (e.g. UserInfo.smali, SubscriptionInfo.smali, AccountModel.smali), use this
    to deep-analyze that class and find ALL its gating methods. Also use when
    methods are obfuscated (a()Z, b()I) and keyword search misses them.

    Args:
        smali_file: Path to the smali file of the subscription/entity class.
                    Can be relative (e.g. "smali_classes3/com/app/UserInfo.smali")
                    or absolute.

    Returns: JSON with keys: class_name, fields (all fields with types), methods
    (every method with behavioral classification), gate_methods (methods that
    perform checks/comparisons — the ones you need to patch), field_dependencies
    (which methods read which fields), patch_plan (recommended patches for each gate).
    """
    import re as _re

    def _run():
        fpath = _resolve_file(smali_file)
        if not fpath.is_file():
            return json.dumps({"success": False, "error": f"File not found: {fpath}"})

        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

        lines = text.splitlines()

        # --- Parse class info ---
        class_name = ""
        super_class = ""
        for ln in lines[:20]:
            m = _re.match(r'\.class\s+.*?(L[\w/$]+;)', ln)
            if m:
                class_name = m.group(1)
            m = _re.match(r'\.super\s+(L[\w/$]+;)', ln)
            if m:
                super_class = m.group(1)

        # --- Parse all fields ---
        fields: list[dict] = []
        for ln in lines:
            m = _re.match(r'\.field\s+(.*?)([\w$]+):(\S+)', ln.strip())
            if m:
                fields.append({
                    "name": m.group(2),
                    "type": m.group(3),
                    "access": m.group(1).strip(),
                    "type_readable": _smali_type_name(m.group(3)),
                })

        # --- Parse and classify all methods ---
        all_methods: list[dict] = []
        gate_methods: list[dict] = []
        field_deps: dict[str, list[str]] = {}

        method_start = -1
        method_header = ""
        for i, ln in enumerate(lines):
            stripped = ln.strip()
            if stripped.startswith(".method"):
                method_start = i
                method_header = stripped
            elif stripped == ".end method" and method_start >= 0:
                body_lines = lines[method_start:i + 1]
                body = "\n".join(body_lines)

                # Parse signature
                hm = _re.search(
                    r'\.method\s+(.*?)([\w<>$]+)\((.*?)\)(\S+)', method_header
                )
                if not hm:
                    method_start = -1
                    continue

                access = hm.group(1).strip()
                mname = hm.group(2)
                params = hm.group(3)
                ret = hm.group(4)
                sig = f"{mname}({params}){ret}"

                # Skip constructors and static initializers
                if mname in ("<init>", "<clinit>"):
                    method_start = -1
                    continue

                # Classify by behavior
                behaviors: list[str] = []
                is_gate = False

                # Date/time comparison (expiry check)
                if _re.search(r'invoke-.*(?:Calendar|Date|Time|before|after|compareTo)', body):
                    behaviors.append("DATE_COMPARISON")
                    is_gate = True

                # String equality (role check: "TRIER", "FREE", "PREMIUM")
                str_consts = _re.findall(r'const-string(?:/jumbo)?\s+\w+,\s*"(.*?)"', body)
                if str_consts and _re.search(r'invoke-.*equals\(', body):
                    behaviors.append(f"STRING_EQUALITY({','.join(str_consts[:3])})")
                    is_gate = True

                # Boolean field read + return (cached flag)
                if _re.search(r'iget-boolean|sget-boolean', body) and ret == "Z":
                    behaviors.append("BOOLEAN_FIELD_READ")
                    is_gate = True

                # Integer comparison (type/level check)
                if ret in ("I", "Z") and _re.search(r'if-(?:eq|ne|gt|ge|lt|le)\s', body):
                    behaviors.append("NUMERIC_COMPARISON")
                    is_gate = True

                # Returns a boolean and has conditional logic
                if ret == "Z" and _re.search(r'if-', body):
                    if not behaviors:
                        behaviors.append("CONDITIONAL_BOOLEAN")
                    is_gate = True

                # Returns a constant directly (simple getter)
                const_ret = _re.search(r'const(?:/4|/16)?\s+v\d+,\s*(0x[0-9a-f]+|\d+)\s*\n\s*return\s', body)
                if const_ret and ret in ("Z", "I"):
                    behaviors.append(f"CONST_RETURN({const_ret.group(1)})")

                # Field reads (which fields does this method access?)
                read_fields = []
                for fm in _re.finditer(r'(?:iget|sget)[-\w]*\s+\w+,\s*\w+,\s*([\w/$]+;->[\w$]+:\S+)', body):
                    read_fields.append(fm.group(1).split("->")[-1])
                if not read_fields:
                    for fm in _re.finditer(r'(?:iget|sget)[-\w]*\s+\w+,\s*\w+,\s*\S+->([\w$]+):\S+', body):
                        read_fields.append(fm.group(1))

                # API calls
                api_calls = []
                for bln in body_lines:
                    bs = bln.strip()
                    if bs.startswith("invoke-"):
                        cm = _re.search(r'(L[\w/$]+;)->([\w<>$]+)\(', bs)
                        if cm:
                            api_calls.append(f"{cm.group(1)}->{cm.group(2)}")

                method_info: dict = {
                    "method": sig,
                    "name": mname,
                    "access": access,
                    "return_type": _smali_type_name(ret),
                    "behaviors": behaviors,
                    "fields_read": read_fields[:5],
                    "api_calls": list(set(api_calls))[:5],
                    "line_range": [method_start + 1, i + 1],
                    "instruction_count": sum(
                        1 for l in body_lines
                        if l.strip() and not l.strip().startswith(('.', '#', ':'))
                    ),
                }

                if read_fields:
                    field_deps[sig] = read_fields[:5]

                if is_gate:
                    # Build a recommended patch
                    if ret == "Z":
                        method_info["recommended_patch"] = {
                            "operation": "replace_block",
                            "match_pattern": f".method {access} {sig}",
                            "strategy": "Insert 'const/4 v0, 0x1\\n    return v0' after .locals/.registers line to force TRUE",
                            "note": "Check with jadx source if TRUE or FALSE is the 'unlocked' value",
                        }
                    elif ret == "I":
                        method_info["recommended_patch"] = {
                            "operation": "replace_block",
                            "match_pattern": f".method {access} {sig}",
                            "strategy": "Insert 'const/4 v0, 0x2\\n    return v0' (or the premium int value) after .locals line",
                            "note": "Read jadx source to determine which int value = premium",
                        }
                    gate_methods.append(method_info)
                    if str_consts:
                        method_info["string_constants"] = str_consts

                all_methods.append(method_info)
                method_start = -1

        return json.dumps({
            "success": True,
            "class_name": class_name,
            "super_class": super_class,
            "file": str(fpath.relative_to(_project.apktool_dir)) if str(fpath).startswith(str(_project.apktool_dir)) else str(fpath),
            "total_fields": len(fields),
            "fields": fields,
            "total_methods": len(all_methods),
            "gate_methods_count": len(gate_methods),
            "gate_methods": gate_methods,
            "all_methods": [m for m in all_methods if m not in gate_methods][:15],
            "field_dependencies": field_deps,
            "instruction": (
                f"Found {len(gate_methods)} GATE METHODS in {class_name} — "
                f"these are the methods that control premium/subscription access. "
                f"For each gate method: 1) Read the jadx Java source to understand the logic, "
                f"2) Determine what return value means 'unlocked', "
                f"3) Patch with apply_smali_patch. "
                f"ALSO check the fields list — fields like 'role', 'dueTime', 'type', "
                f"'expired' store subscription state. Trace who WRITES to these fields."
            ),
        }, ensure_ascii=False, indent=2)[:15000]

    return _safe_call(_run, "analyze_subscription_model")


def _smali_type_name(smali_type: str) -> str:
    """Convert smali type descriptor to readable name."""
    _map = {"Z": "boolean", "I": "int", "J": "long", "F": "float",
            "D": "double", "B": "byte", "S": "short", "C": "char", "V": "void"}
    if smali_type in _map:
        return _map[smali_type]
    if smali_type.startswith("L") and smali_type.endswith(";"):
        return smali_type[1:-1].replace("/", ".").split(".")[-1]
    if smali_type.startswith("["):
        return _smali_type_name(smali_type[1:]) + "[]"
    return smali_type


# ---------------------------------------------------------------------------
# Deep tracing + Code injection tools
# ---------------------------------------------------------------------------


@tool
def trace_field_access(
    class_descriptor: str,
    field_name: str,
) -> str:
    """Find ALL reads and writes of a specific field across the ENTIRE codebase.

    Searches every smali file for iget/iput/sget/sput operations on the given field.
    This catches DIRECT field access that bypasses getter/setter methods.

    Essential for discovering:
    - Where a field is SET (from constructors, deserialization, API responses)
    - Where a field is READ directly (bypassing getter methods you may have patched)
    - Hidden initialization code that overrides your patches

    Unlike graph_callers which traces method calls, this traces raw field-level
    access — critical when obfuscated apps read fields directly instead of
    calling getter methods.

    Args:
        class_descriptor: Smali class descriptor, e.g. 'Lcom/app/entity/UserInfo;'
        field_name: Field name to trace, e.g. 'w' or 'role'

    Returns: JSON with total_found, reads (iget operations), writes (iput operations),
    each with file, line, method_context, instruction, and access_type.
    """
    import re as _re

    def _run():
        reads = []
        writes = []
        # Build pattern: match field access like iget-object v0, p0, Lcom/...;->fieldName:
        escaped_class = _re.escape(class_descriptor)
        escaped_field = _re.escape(field_name)
        pat = _re.compile(
            rf'((?:iget|iput|sget|sput)[\w-]*)\s+.*{escaped_class}->{escaped_field}:'
        )

        for smali_dir in _get_all_smali_dirs():
            for smali_file in smali_dir.rglob("*.smali"):
                # Skip third-party libraries
                rel = str(smali_file.relative_to(smali_dir)).replace("\\", "/")
                if any(rel.startswith(p) for p in (
                    "android/", "androidx/", "com/google/", "kotlin/",
                    "kotlinx/", "io/reactivex/", "okhttp3/", "retrofit2/",
                    "com/squareup/", "org/", "io/netty/",
                )):
                    continue

                try:
                    text = smali_file.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                file_lines = text.splitlines()
                current_method = "(class-level)"
                for i, line in enumerate(file_lines):
                    s = line.strip()
                    if s.startswith(".method"):
                        current_method = s
                    elif s == ".end method":
                        current_method = "(class-level)"

                    m = pat.search(s)
                    if m:
                        op = m.group(1)
                        is_write = op.startswith(("iput", "sput"))
                        entry = {
                            "file": rel,
                            "line": i + 1,
                            "instruction": s[:120],
                            "method": current_method[:100],
                            "access_type": "write" if is_write else "read",
                        }
                        if is_write:
                            writes.append(entry)
                        else:
                            reads.append(entry)

        return json.dumps({
            "success": True,
            "class": class_descriptor,
            "field": field_name,
            "total_found": len(reads) + len(writes),
            "total_reads": len(reads),
            "total_writes": len(writes),
            "reads": reads[:40],
            "writes": writes[:40],
        }, ensure_ascii=False, indent=2)[:15000]

    return _safe_call(_run, "trace_field_access",
                      _cache_hint=f"{class_descriptor}:{field_name}")


@tool
def find_class_instantiations(class_descriptor: str) -> str:
    """Find every location where a class is instantiated, deserialized, or received.

    Searches the entire codebase for:
    - new-instance allocations (where the object is created)
    - Constructor calls (<init> invocations on this class)
    - check-cast operations (often from deserialization / JSON parsing)
    - Method return types (factory methods that produce this class)
    - Field reads that yield this class type

    Essential for understanding the full lifecycle of an entity class:
    where it's created, where data flows into it, and where it's consumed.
    Use this AFTER trace_field_access to understand the full data pipeline.

    Args:
        class_descriptor: Smali class descriptor, e.g. 'Lcom/app/entity/UserInfo;'

    Returns: JSON with instantiation_points: file, line, type (new-instance,
    check-cast, init-call, factory-call), method_context, instruction.
    """
    import re as _re

    def _run():
        results = []
        escaped = _re.escape(class_descriptor)
        patterns = [
            (_re.compile(rf'new-instance\s+\w+,\s*{escaped}'), "new-instance"),
            (_re.compile(rf'invoke-direct\s+.*{escaped}-><init>'), "init-call"),
            (_re.compile(rf'check-cast\s+\w+,\s*{escaped}'), "check-cast"),
            (_re.compile(rf'invoke-.*\).*{escaped}'), "method-returning"),
        ]

        for smali_dir in _get_all_smali_dirs():
            for smali_file in smali_dir.rglob("*.smali"):
                rel = str(smali_file.relative_to(smali_dir)).replace("\\", "/")
                if any(rel.startswith(p) for p in (
                    "android/", "androidx/", "com/google/", "kotlin/",
                    "kotlinx/", "io/reactivex/", "okhttp3/", "retrofit2/",
                    "com/squareup/", "org/", "io/netty/",
                )):
                    continue

                try:
                    text = smali_file.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                file_lines = text.splitlines()
                current_method = "(class-level)"
                for i, line in enumerate(file_lines):
                    s = line.strip()
                    if s.startswith(".method"):
                        current_method = s
                    elif s == ".end method":
                        current_method = "(class-level)"

                    for pat, ptype in patterns:
                        if pat.search(s):
                            results.append({
                                "file": rel,
                                "line": i + 1,
                                "type": ptype,
                                "instruction": s[:120],
                                "method": current_method[:100],
                            })
                            break  # one match per line

        # Deduplicate init-calls that are part of new-instance (same file+method)
        return json.dumps({
            "success": True,
            "class": class_descriptor,
            "total_found": len(results),
            "instantiation_points": results[:60],
        }, ensure_ascii=False, indent=2)[:15000]

    return _safe_call(_run, "find_class_instantiations",
                      _cache_hint=class_descriptor)


@tool
def inject_smali_code(
    smali_file: str,
    method_name: str,
    smali_code: str,
    position: str = "start",
) -> str:
    """Inject smali instructions into an existing method WITHOUT removing anything.

    Unlike apply_smali_patch which REPLACES existing instructions, this tool ADDS
    new code at the specified position. Use this to:
    - Override field values after a constructor runs (position='after_super')
    - Add initialization code at method start (position='start')
    - Force values just before a method returns (position='end' or 'before_return')

    The tool automatically bumps .locals if your injected code uses registers
    beyond the current allocation — safe and non-destructive.

    IMPORTANT: Injected code must be valid smali. Use p0 for 'this' in instance
    methods. The tool wraps your code in marker comments for traceability.

    Args:
        smali_file: path to .smali file (relative to apktool dir or absolute)
        method_name: method to inject into (e.g. '<init>', 'onCreate', 'a()Z').
            For short/ambiguous names, include signature suffix: 'a()Z'
        smali_code: smali instructions to inject, newline-separated. Example:
            'const-string v0, "SVIP"\\niput-object v0, p0, Lcom/app/E;->role:Ljava/lang/String;'
        position: where to inject:
            'start' — after .locals (first executable position)
            'end' or 'before_return' — before the last return instruction
            'after_super' — after invoke-direct {p0} <init> (for constructors)

    Returns: JSON with success, file, method, position, injected_at_line, lines_injected.
    """
    from apk_agent.tools.code_injector import inject_code_in_method
    import re as _re

    def _run():
        # --- Validate injected smali code BEFORE touching the file -----------
        # Check for broken class descriptors (missing L prefix)
        # Valid: Lcom/app/Foo;  Invalid: com/app/Foo; (missing L)
        broken = _re.findall(
            r'(?<![L\w/\[])([A-Za-z]\w*/\w[^\s,;)]*;)', smali_code
        )
        real_broken = [r for r in broken if "/" in r and r.endswith(";")
                       and not r.startswith("L") and not r.startswith("[")]
        if real_broken:
            examples = ", ".join(real_broken[:5])
            return json.dumps({"success": False,
                "error": f"BLOCKED: injected smali code has broken class descriptors "
                         f"missing 'L' prefix: {examples}. "
                         f"Fix class references to use L-prefix format (e.g. Lcom/app/Foo;)."})

        # Auto-backup the target file
        fpath = str(_resolve_file(smali_file))
        fp = Path(fpath)
        bak = fp.with_suffix(".smali.bak")
        if fp.is_file() and not bak.exists():
            try:
                import shutil
                shutil.copy2(fp, bak)
            except OSError:
                pass

        result = inject_code_in_method(fpath, method_name, smali_code, position)
        return json.dumps(result, ensure_ascii=False, indent=2)

    return _safe_call(_run, "inject_smali_code")


@tool
def generate_constructor_override(
    smali_file: str,
    class_descriptor: str,
    field_overrides_json: str,
) -> str:
    """Patch ALL constructors of a class to force-set field values after initialization.

    This DIRECTLY addresses the #1 bypass failure: patching getters is NOT enough
    when other code reads fields directly. By overriding field values at constructor
    exit, ALL downstream reads — both through getters AND direct field access — see
    the forced values.

    The tool:
    1. Finds ALL <init> constructors in the class
    2. Allocates a scratch register safely (bumps .locals)
    3. Injects field-setting instructions before each constructor's return-void
    4. Handles string, boolean, int, and long types automatically

    Args:
        smali_file: path to .smali file containing the target class
        class_descriptor: Smali class descriptor, e.g. 'Lcom/app/entity/UserInfo;'
        field_overrides_json: JSON string mapping field names to type+value. Format:
            '{"w": {"type": "Ljava/lang/String;", "value": "SVIP"},
              "u": {"type": "Z", "value": true},
              "F": {"type": "I", "value": 999}}'
            Supported types: Z (boolean), I (int), J (long), Ljava/lang/String;

    Returns: JSON with success, constructors_found, constructors_patched, fields_overridden.
    """
    from apk_agent.tools.code_injector import override_constructor_fields

    def _run():
        fpath = str(_resolve_file(smali_file))
        overrides = json.loads(field_overrides_json)
        result = override_constructor_fields(fpath, class_descriptor, overrides)
        return json.dumps(result, ensure_ascii=False, indent=2)

    return _safe_call(_run, "generate_constructor_override")


@tool
def inject_startup_hook(smali_code: str) -> str:
    """Inject smali code that executes when the app starts.

    Automatically:
    1. Finds the Application class from AndroidManifest.xml
    2. Locates its onCreate() method
    3. Injects code after super.onCreate() (position='after_super')
    4. If no Application class, falls back to the main launcher Activity

    Use this to:
    - Force SharedPreferences values at startup before any Activity reads them
    - Set static fields that control premium/license state app-wide
    - Override initialization that happens before UI loads
    - Run setup code that needs to execute once at app launch

    The injected code runs ONCE per app start, in the Application context.
    Use p0 for 'this' (the Application instance). Be careful not to reference
    classes not yet loaded at this point.

    Args:
        smali_code: smali instructions to inject (will run at app startup).
            Example: 'sget-object v0, Lcom/app/Config;->INSTANCE:Lcom/app/Config;
            const/4 v1, 0x1
            iput-boolean v1, v0, Lcom/app/Config;->isPremium:Z'

    Returns: JSON with success, entry_type (Application or LauncherActivity),
    class_name, smali_file, injected_at_line.
    """
    from apk_agent.tools.code_injector import find_startup_entry, inject_code_in_method

    def _run():
        manifest = _project.apktool_dir / "AndroidManifest.xml"
        entry = find_startup_entry(str(manifest), str(_project.apktool_dir))
        if not entry.get("success"):
            return json.dumps(entry, ensure_ascii=False, indent=2)

        smali_path = entry["smali_file"]
        entry_type = entry["entry_type"]

        if not entry.get("has_onCreate"):
            return json.dumps({
                "success": False,
                "error": f"onCreate not found in {entry['class_name']}. "
                         f"Use inject_smali_code on a specific method instead.",
                "entry_info": entry,
            }, ensure_ascii=False, indent=2)

        pos = "after_super"
        result = inject_code_in_method(smali_path, "onCreate", smali_code, pos)
        result["entry_type"] = entry_type
        result["class_name"] = entry["class_name"]
        return json.dumps(result, ensure_ascii=False, indent=2)

    return _safe_call(_run, "inject_startup_hook")


# ---------------------------------------------------------------------------
# Bulk patching + Data-flow tracing + UI gate mapping
# ---------------------------------------------------------------------------


@tool
def batch_patch_methods(patches_json: str) -> str:
    """Patch MULTIPLE methods at once — each with a different forced return value.

    Instead of calling apply_smali_patch 6+ times sequentially, call this ONCE
    with a list of methods and their desired return values. It:
    1. Groups patches by file (reads each file only once)
    2. Applies all patches in a single pass
    3. Creates backups and diffs for each file
    4. Returns a summary of successes and failures

    This is the PREFERRED tool for premium bypass — after you've analyzed the
    entity class and know which methods to patch and what values to use.

    Args:
        patches_json: JSON string with an array of patch specifications:
            [
                {"file": "smali_classes3/com/app/UserInfo.smali",
                 "method": "a()Z", "return_type": "boolean", "value": false,
                 "description": "isExpired → always false"},
                {"file": "smali_classes3/com/app/UserInfo.smali",
                 "method": "b()Z", "return_type": "boolean", "value": true,
                 "description": "isPremium → always true"},
                {"file": "smali_classes3/com/app/UserInfo.smali",
                 "method": "c()I", "return_type": "int", "value": 2,
                 "description": "getType → premium tier"},
                {"file": "smali_classes3/com/app/Dialog.smali",
                 "method": "show()V", "return_type": "void",
                 "description": "suppress upgrade dialog"}
            ]
            return_type: "boolean", "int", "void", "long"
            value: the value to return (ignored for void)

    Returns: JSON with total, succeeded, failed, and details per patch.
    """
    import re as _re
    import shutil

    def _run():
        patches = json.loads(patches_json)
        if not isinstance(patches, list) or not patches:
            return json.dumps({"success": False, "error": "patches_json must be a non-empty array"})

        # Group by file
        by_file: dict[str, list] = {}
        for p in patches:
            fkey = p.get("file", "")
            by_file.setdefault(fkey, []).append(p)

        results = []
        total_ok = 0
        total_fail = 0

        for file_rel, file_patches in by_file.items():
            fpath = _resolve_file(file_rel)
            if not fpath.is_file():
                for p in file_patches:
                    results.append({"method": p.get("method"), "file": file_rel,
                                    "success": False, "error": "File not found"})
                    total_fail += 1
                continue

            # Backup
            backup = _project.patch_backup_dir / fpath.name
            _project.patch_backup_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(fpath, backup)

            text = fpath.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()

            for p in file_patches:
                method_q = p.get("method", "")
                ret_type = p.get("return_type", "boolean")
                value = p.get("value")
                desc = p.get("description", "")

                # Find the method
                def _match(header, q, _re=_re):
                    m = _re.search(r'(\S+)\(', header)
                    if not m:
                        return False
                    name = m.group(1)
                    if '(' in q:
                        sig = header[header.index(name):]
                        return q in sig
                    return name == q

                m_start = -1
                m_end = -1
                for i, ln in enumerate(lines):
                    s = ln.strip()
                    if s.startswith(".method") and _match(s, method_q):
                        m_start = i
                    if m_start >= 0 and s == ".end method":
                        m_end = i
                        break

                if m_start < 0:
                    results.append({"method": method_q, "file": file_rel,
                                    "success": False, "error": f"Method not found: {method_q}"})
                    total_fail += 1
                    continue

                # Build replacement instructions
                if ret_type == "void":
                    inject = "    return-void"
                elif ret_type == "boolean":
                    v = "0x1" if value else "0x0"
                    inject = f"    const/4 v0, {v}\n\n    return v0"
                elif ret_type == "int":
                    iv = int(value)
                    if -8 <= iv <= 7:
                        inject = f"    const/4 v0, {hex(iv)}\n\n    return v0"
                    elif -32768 <= iv <= 32767:
                        inject = f"    const/16 v0, {hex(iv)}\n\n    return v0"
                    else:
                        inject = f"    const v0, {hex(iv)}\n\n    return v0"
                elif ret_type == "long":
                    inject = f"    const-wide v0, {hex(int(value))}\n\n    return-wide v0"
                else:
                    inject = "    const/4 v0, 0x0\n\n    return v0"

                # Find .locals or .registers line
                locals_line = -1
                for i in range(m_start + 1, min(m_start + 15, m_end)):
                    if _re.match(r'\s*\.(locals|registers)\s+\d+', lines[i]):
                        locals_line = i
                        break

                if locals_line < 0:
                    results.append({"method": method_q, "file": file_rel,
                                    "success": False, "error": "No .locals/.registers found"})
                    total_fail += 1
                    continue

                # Replace everything between locals_line+1 and m_end with our injection
                new_body = [lines[i] for i in range(m_start, locals_line + 1)]
                new_body.append("")
                new_body.append(f"    # APK-AGI batch patch: {desc}")
                new_body.append(inject)
                new_body.append("")
                new_body.append(".end method")

                # Replace in lines
                lines[m_start:m_end + 1] = new_body

                results.append({"method": method_q, "file": file_rel,
                                "success": True, "description": desc})
                total_ok += 1

                # Record to patch journal
                _patch_journal.append({
                    "success": True, "target_file": file_rel,
                    "description": desc, "steps_applied": 1, "steps_total": 1,
                    "diff_text": f"Forced {method_q} -> {ret_type}({value})",
                    "errors": [], "tool": "batch_patch_methods",
                })

            # Write once per file
            fpath.write_text("\n".join(lines) + "\n", encoding="utf-8")

        return json.dumps({
            "success": total_fail == 0,
            "total": len(patches),
            "succeeded": total_ok,
            "failed": total_fail,
            "results": results,
        }, ensure_ascii=False, indent=2)

    return _safe_call(_run, "batch_patch_methods")


@tool
def trace_data_pipeline(class_descriptor: str) -> str:
    """Trace the FULL lifecycle of an entity class through the app.

    Combines multiple analyses into a single comprehensive view:
    1. Where the class is INSTANTIATED (new-instance, deserialization, check-cast)
    2. Where each FIELD is read/written (iget/iput across entire codebase)
    3. Where the class appears as METHOD PARAMETERS or RETURN TYPES
    4. Which classes HOLD REFERENCES to it (field declarations)

    Returns a complete data-flow map showing how entity data flows from
    creation (API response / JSON parse) -> storage -> consumption (UI / logic).

    Use this to understand the full premium state pipeline and find every
    point where data needs to be patched.

    Args:
        class_descriptor: Smali class descriptor, e.g. 'Lcom/app/entity/UserInfo;'

    Returns: JSON with sections: instantiation_points, field_flow (per field
    with read/write counts and locations), reference_holders, and analysis_hint.
    """
    import re as _re

    def _run():
        escaped = _re.escape(class_descriptor)

        # 1. Parse the entity class itself to learn its fields
        fields: list[dict] = []
        entity_file = None
        for smali_dir in _get_all_smali_dirs():
            cls_path = class_descriptor.strip("L;").replace("/", "/") + ".smali"
            candidate = smali_dir / cls_path
            if candidate.is_file():
                entity_file = candidate
                text = candidate.read_text(encoding="utf-8", errors="replace")
                for line in text.splitlines():
                    m = _re.match(r'\.field\s+(.+?)\s+([\w$]+):(\S+)', line.strip())
                    if m:
                        fields.append({
                            "access": m.group(1),
                            "name": m.group(2),
                            "type": m.group(3),
                        })
                break

        if not entity_file:
            return json.dumps({"success": False,
                               "error": f"Entity class file not found for {class_descriptor}"})

        # 2. Scan codebase for instantiations, field access, references
        instantiations = []
        field_reads: dict[str, list] = {f["name"]: [] for f in fields}
        field_writes: dict[str, list] = {f["name"]: [] for f in fields}
        reference_holders = []

        inst_pats = [
            (_re.compile(rf'new-instance\s+\w+,\s*{escaped}'), "new-instance"),
            (_re.compile(rf'invoke-direct\s+.*{escaped}-><init>'), "constructor-call"),
            (_re.compile(rf'check-cast\s+\w+,\s*{escaped}'), "deserialization"),
        ]
        field_pat = _re.compile(
            rf'((?:iget|iput|sget|sput)[\w-]*)\s+.*{escaped}->([\w$]+):'
        )
        ref_pat = _re.compile(rf'\.field\s+.*:{escaped}')

        for smali_dir in _get_all_smali_dirs():
            for smali_file in smali_dir.rglob("*.smali"):
                rel = str(smali_file.relative_to(smali_dir)).replace("\\", "/")
                if any(rel.startswith(p) for p in (
                    "android/", "androidx/", "com/google/", "kotlin/",
                    "kotlinx/", "io/reactivex/", "okhttp3/", "retrofit2/",
                    "com/squareup/", "org/", "io/netty/",
                )):
                    continue

                try:
                    text = smali_file.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                file_lines = text.splitlines()
                current_method = "(class-level)"

                for i, line in enumerate(file_lines):
                    s = line.strip()
                    if s.startswith(".method"):
                        current_method = s[:80]
                    elif s == ".end method":
                        current_method = "(class-level)"

                    # (a) instantiations
                    for pat, ptype in inst_pats:
                        if pat.search(s):
                            instantiations.append({
                                "file": rel, "line": i + 1, "type": ptype,
                                "method": current_method,
                            })
                            break

                    # (b) field access
                    fm = field_pat.search(s)
                    if fm:
                        op = fm.group(1)
                        fname = fm.group(2)
                        is_write = op.startswith(("iput", "sput"))
                        entry = {"file": rel, "line": i + 1,
                                 "method": current_method, "op": op}
                        if is_write and fname in field_writes:
                            field_writes[fname].append(entry)
                        elif fname in field_reads:
                            field_reads[fname].append(entry)

                    # (c) reference holders
                    if s.startswith(".field") and class_descriptor in s:
                        if ref_pat.match(s):
                            reference_holders.append({
                                "file": rel, "field_decl": s[:100],
                            })

        # Build field summary
        field_summary = []
        for f in fields:
            fn = f["name"]
            field_summary.append({
                "field": fn,
                "type": f["type"],
                "read_count": len(field_reads.get(fn, [])),
                "write_count": len(field_writes.get(fn, [])),
                "readers": [r["file"] + ":" + str(r["line"]) for r in field_reads.get(fn, [])[:10]],
                "writers": [w["file"] + ":" + str(w["line"]) for w in field_writes.get(fn, [])[:10]],
            })

        return json.dumps({
            "success": True,
            "class": class_descriptor,
            "entity_file": str(entity_file),
            "total_fields": len(fields),
            "total_instantiations": len(instantiations),
            "total_reference_holders": len(reference_holders),
            "instantiation_points": instantiations[:30],
            "field_flow": field_summary,
            "reference_holders": reference_holders[:20],
            "analysis_hint": (
                "Fields with write_count > 0 from external classes indicate data "
                "being SET from API/deserialization. Override these with "
                "generate_constructor_override. Fields with read_count > 0 from "
                "external classes indicate direct field access bypassing getters."
            ),
        }, ensure_ascii=False, indent=2)[:15000]

    return _safe_call(_run, "trace_data_pipeline",
                      _cache_hint=class_descriptor)


@tool
def map_ui_gates(search_terms: str) -> str:
    """Map UI elements to the code that controls them — find ALL premium UI gates.

    Given search terms related to premium/upgrade UI, this tool:
    1. Searches string resources (res/values/strings.xml) for matching text
    2. Finds the resource IDs for those strings
    3. Searches layouts (res/layout/) for views using those IDs
    4. Traces from resource IDs to Java/smali code that references them
    5. Returns a map: UI string -> resource ID -> layout file -> controlling code

    This finds upgrade dialogs, paywall screens, locked feature overlays,
    and premium-only buttons that need to be suppressed or bypassed.

    Args:
        search_terms: Comma-separated terms to search for in string resources and layouts.
            e.g. 'upgrade,premium,pro,subscribe,unlock,purchase,vip'

    Returns: JSON with ui_gates array: each with string_value, resource_id,
    layout_files, code_references (smali files that use the ID).
    """
    import re as _re
    import xml.etree.ElementTree as ET

    def _run():
        terms = [t.strip().lower() for t in search_terms.split(",") if t.strip()]
        if not terms:
            return json.dumps({"success": False, "error": "No search terms provided"})

        apk_dir = _project.apktool_dir

        # 1. Search string resources
        string_matches: dict[str, str] = {}  # name -> value
        for sf in sorted(apk_dir.glob("res/values*/strings.xml")):
            try:
                tree = ET.parse(str(sf))  # noqa: S314
                for elem in tree.getroot():
                    if elem.tag == "string" and elem.text:
                        name = elem.get("name", "")
                        val = elem.text.strip()
                        if name not in string_matches and any(
                            t in val.lower() or t in name.lower() for t in terms
                        ):
                            string_matches[name] = val
            except ET.ParseError:
                pass

        # 2. Find resource IDs from public.xml
        res_ids: dict[str, str] = {}  # name -> hex id
        public_xml = apk_dir / "res" / "values" / "public.xml"
        if public_xml.is_file():
            try:
                tree = ET.parse(str(public_xml))  # noqa: S314
                for elem in tree.getroot():
                    name = elem.get("name", "")
                    if name in string_matches:
                        res_ids[name] = elem.get("id", "")
            except ET.ParseError:
                pass

        # 3. Search layouts for resource references
        layout_refs: dict[str, list[str]] = {}
        if (apk_dir / "res").is_dir():
            for lf in (apk_dir / "res").rglob("*.xml"):
                if "layout" not in lf.parent.name:
                    continue
                try:
                    content = lf.read_text(encoding="utf-8", errors="replace").lower()
                except OSError:
                    continue
                for rname in string_matches:
                    if f"@string/{rname.lower()}" in content or rname.lower() in content:
                        layout_refs.setdefault(rname, []).append(
                            str(lf.relative_to(apk_dir)).replace("\\", "/")
                        )

        # 4. Search smali code for resource ID references and term strings
        code_refs: dict[str, list[dict]] = {}
        id_to_name = {v: k for k, v in res_ids.items()}
        all_search = set()
        for name in string_matches:
            all_search.add(name)
        for hex_id in id_to_name:
            if hex_id:
                all_search.add(hex_id)
        for t in terms:
            all_search.add(t)

        if all_search:
            combined = "|".join(_re.escape(p) for p in all_search if p)
            if combined:
                pat = _re.compile(combined, _re.IGNORECASE)
                for smali_dir in _get_all_smali_dirs():
                    for smali_file in smali_dir.rglob("*.smali"):
                        rel = str(smali_file.relative_to(smali_dir)).replace("\\", "/")
                        if any(rel.startswith(p) for p in (
                            "android/", "androidx/", "com/google/", "kotlin/",
                            "kotlinx/", "io/reactivex/", "okhttp3/",
                        )):
                            continue
                        try:
                            text = smali_file.read_text(encoding="utf-8", errors="replace")
                        except OSError:
                            continue
                        current_method = ""
                        for i, line in enumerate(text.splitlines()):
                            s = line.strip()
                            if s.startswith(".method"):
                                current_method = s[:80]
                            elif s == ".end method":
                                current_method = ""
                            if pat.search(s):
                                matched_name = "unknown"
                                for name in string_matches:
                                    if name.lower() in s.lower():
                                        matched_name = name
                                        break
                                if matched_name == "unknown":
                                    for hex_id, name in id_to_name.items():
                                        if hex_id in s:
                                            matched_name = name
                                            break
                                if matched_name == "unknown":
                                    for t in terms:
                                        if t.lower() in s.lower():
                                            matched_name = f"term:{t}"
                                            break
                                code_refs.setdefault(matched_name, []).append({
                                    "file": rel, "line": i + 1,
                                    "method": current_method,
                                    "instruction": s[:100],
                                })

        # Build output
        ui_gates = []
        all_names = set(string_matches.keys()) | {
            k for k in code_refs if k.startswith("term:")}
        for name in sorted(all_names):
            ui_gates.append({
                "resource_name": name,
                "string_value": string_matches.get(name, ""),
                "resource_id": res_ids.get(name, ""),
                "layout_files": layout_refs.get(name, []),
                "code_references": code_refs.get(name, [])[:10],
            })

        return json.dumps({
            "success": True,
            "search_terms": terms,
            "total_string_matches": len(string_matches),
            "total_ui_gates": len(ui_gates),
            "ui_gates": ui_gates[:30],
            "hint": (
                "For each code_reference, use analyze_method_deep to understand "
                "the gating logic, then patch with batch_patch_methods to suppress."
            ),
        }, ensure_ascii=False, indent=2)[:15000]

    return _safe_call(_run, "map_ui_gates", _cache_hint=search_terms)


@tool
def patch_shared_prefs_reads(
    pref_key: str,
    forced_value: str,
    value_type: str = "boolean",
) -> str:
    """Find ALL SharedPreferences reads for a specific key and patch them to return a forced value.

    Many apps store premium/license state in SharedPreferences. This tool:
    1. Searches the entire codebase for getString/getBoolean/getInt calls
       with the target key as a const-string argument
    2. For each call site, patches the code to ignore the SharedPreferences read
       and use the forced value instead
    3. Reports all patch locations

    This is more thorough than inject_startup_hook for prefs because it patches
    EVERY read site individually.

    Args:
        pref_key: The SharedPreferences key to intercept, e.g. 'is_premium', 'sub_type'
        forced_value: The value to force. For boolean: 'true'/'false'. For int: '1'.
            For string: the literal string value.
        value_type: Type of the preference: 'boolean', 'int', 'string', 'long', 'float'

    Returns: JSON with total_sites_found, total_patched, details per patch site.
    """
    import re as _re
    import shutil

    def _run():
        escaped_key = _re.escape(pref_key)
        getter_map = {
            "boolean": "getBoolean", "int": "getInt", "string": "getString",
            "long": "getLong", "float": "getFloat",
        }
        getter_name = getter_map.get(value_type, "getBoolean")

        sites_found = []
        sites_patched = []

        for smali_dir in _get_all_smali_dirs():
            for smali_file in smali_dir.rglob("*.smali"):
                rel = str(smali_file.relative_to(smali_dir)).replace("\\", "/")
                if any(rel.startswith(p) for p in (
                    "android/", "androidx/", "com/google/", "kotlin/",
                    "kotlinx/", "io/reactivex/",
                )):
                    continue

                try:
                    text = smali_file.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                if pref_key not in text:
                    continue

                lines = text.splitlines()
                modified = False
                current_method = ""

                for i, line in enumerate(lines):
                    s = line.strip()
                    if s.startswith(".method"):
                        current_method = s[:80]
                    elif s == ".end method":
                        current_method = ""

                    km = _re.match(
                        rf'const-string(?:/jumbo)?\s+(\w+),\s*"{escaped_key}"', s
                    )
                    if not km:
                        continue

                    sites_found.append({
                        "file": rel, "line": i + 1, "method": current_method,
                    })

                    # Look ahead for the SharedPreferences getter call
                    for j in range(i + 1, min(i + 20, len(lines))):
                        sj = lines[j].strip()
                        if ("invoke-" in sj and
                                (getter_name in sj or "SharedPreferences" in sj)):
                            for k in range(j + 1, min(j + 5, len(lines))):
                                sk = lines[k].strip()
                                mr = _re.match(r'move-result(?:-object|-wide)?\s+(\w+)', sk)
                                if mr:
                                    result_reg = mr.group(1)
                                    if not modified:
                                        _project.patch_backup_dir.mkdir(parents=True, exist_ok=True)
                                        shutil.copy2(smali_file,
                                                     _project.patch_backup_dir / smali_file.name)

                                    if value_type == "boolean":
                                        v = "0x1" if forced_value.lower() == "true" else "0x0"
                                        lines[k] = f"    const/4 {result_reg}, {v}  # APK-AGI: forced {pref_key}={forced_value}"
                                    elif value_type == "int":
                                        iv = int(forced_value)
                                        if -8 <= iv <= 7:
                                            lines[k] = f"    const/4 {result_reg}, {hex(iv)}  # APK-AGI: forced {pref_key}"
                                        else:
                                            lines[k] = f"    const/16 {result_reg}, {hex(iv)}  # APK-AGI: forced {pref_key}"
                                    elif value_type == "string":
                                        lines[k] = f'    const-string {result_reg}, "{forced_value}"  # APK-AGI: forced {pref_key}'
                                    elif value_type == "long":
                                        lines[k] = f"    const-wide {result_reg}, {hex(int(forced_value))}  # APK-AGI: forced {pref_key}"

                                    modified = True
                                    sites_patched.append({
                                        "file": rel, "line": k + 1,
                                        "method": current_method,
                                        "original": sk,
                                    })
                                    break
                            break

                if modified:
                    smali_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    _patch_journal.append({
                        "success": True, "target_file": rel,
                        "description": f"Forced SharedPrefs '{pref_key}'={forced_value}",
                        "steps_applied": len([s for s in sites_patched if s["file"] == rel]),
                        "steps_total": len([s for s in sites_found if s["file"] == rel]),
                        "diff_text": f"SharedPrefs {pref_key} -> {forced_value} ({value_type})",
                        "errors": [], "tool": "patch_shared_prefs_reads",
                    })

        return json.dumps({
            "success": len(sites_patched) > 0,
            "pref_key": pref_key,
            "forced_value": forced_value,
            "value_type": value_type,
            "total_sites_found": len(sites_found),
            "total_patched": len(sites_patched),
            "sites_found": sites_found[:30],
            "sites_patched": sites_patched[:30],
        }, ensure_ascii=False, indent=2)[:15000]

    return _safe_call(_run, "patch_shared_prefs_reads")


@tool
def identify_server_checks() -> str:
    """Map ALL network/API calls that may enforce server-side premium validation.

    Scans the codebase for:
    1. HTTP client usage (OkHttp, Retrofit, HttpURLConnection, Volley, Ktor)
    2. API endpoint URLs and paths (from const-string and annotations)
    3. Response handling code that sets premium/license state
    4. Server-side verification callbacks

    Returns a map of network calls with their endpoints, response handlers,
    and which entity fields they populate — showing WHERE server responses
    flow into the premium state pipeline.

    Returns: JSON with network_clients (detected HTTP libraries), api_endpoints
    (URL strings found), response_handlers (code that processes API responses).
    """
    import re as _re

    def _run():
        http_patterns = {
            "okhttp": _re.compile(r'Lokhttp3/|Lcom/squareup/okhttp/'),
            "retrofit": _re.compile(r'Lretrofit2/|Lretrofit/'),
            "httpurlconnection": _re.compile(r'Ljava/net/HttpURLConnection;|Ljava/net/URL;'),
            "volley": _re.compile(r'Lcom/android/volley/'),
            "ktor": _re.compile(r'Lio/ktor/'),
        }

        response_patterns = [
            _re.compile(r'onResponse|onSuccess|onNext|onComplete', _re.IGNORECASE),
            _re.compile(r'parseResponse|handleResponse|processResponse', _re.IGNORECASE),
            _re.compile(r'fromJson|deserialize|decode', _re.IGNORECASE),
        ]

        url_pat = _re.compile(r'const-string.*"(https?://[^"]+|/api/[^"]+|/v\d+/[^"]+)"')
        path_pat = _re.compile(
            r'const-string.*"(/(?:user|auth|license|premium|subscribe|purchase|'
            r'billing|account|verify|validate|check|status|plan|membership|order|pay)[^"]*)"',
            _re.IGNORECASE
        )
        retrofit_annot = _re.compile(
            r'value\s*=\s*"([^"]*(?:user|auth|license|premium|subscribe|purchase|'
            r'billing|account|verify|status|plan|membership)[^"]*)"',
            _re.IGNORECASE
        )

        network_clients: dict[str, int] = {}
        api_endpoints: list[dict] = []
        response_handlers: list[dict] = []
        seen_urls: set[str] = set()

        for smali_dir in _get_all_smali_dirs():
            for smali_file in smali_dir.rglob("*.smali"):
                rel = str(smali_file.relative_to(smali_dir)).replace("\\", "/")
                if any(rel.startswith(p) for p in (
                    "android/", "androidx/", "com/google/", "kotlin/",
                    "kotlinx/", "io/reactivex/", "okhttp3/", "retrofit2/",
                    "com/squareup/", "org/", "io/netty/",
                )):
                    continue

                try:
                    text = smali_file.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                for name, pat in http_patterns.items():
                    if pat.search(text):
                        network_clients[name] = network_clients.get(name, 0) + 1

                lines = text.splitlines()
                current_method = ""
                for i, line in enumerate(lines):
                    s = line.strip()
                    if s.startswith(".method"):
                        current_method = s[:80]
                    elif s == ".end method":
                        current_method = ""

                    for pat in (url_pat, path_pat):
                        um = pat.search(s)
                        if um and um.group(1) not in seen_urls:
                            seen_urls.add(um.group(1))
                            api_endpoints.append({
                                "url": um.group(1), "file": rel,
                                "line": i + 1, "method": current_method,
                            })

                    am = retrofit_annot.search(s)
                    if am and am.group(1) not in seen_urls:
                        seen_urls.add(am.group(1))
                        api_endpoints.append({
                            "url": am.group(1), "file": rel,
                            "line": i + 1, "method": current_method,
                            "type": "retrofit_annotation",
                        })

                    for rpat in response_patterns:
                        if rpat.search(s) and "invoke" in s:
                            response_handlers.append({
                                "file": rel, "line": i + 1,
                                "method": current_method,
                                "instruction": s[:100],
                            })
                            break

        return json.dumps({
            "success": True,
            "network_clients": network_clients,
            "total_api_endpoints": len(api_endpoints),
            "total_response_handlers": len(response_handlers),
            "api_endpoints": api_endpoints[:40],
            "response_handlers": response_handlers[:30],
            "analysis_hint": (
                "Look at api_endpoints with premium/license/billing paths. "
                "Trace their response handlers to find where server data flows "
                "into entity classes. Use trace_data_pipeline on the entity class."
            ),
        }, ensure_ascii=False, indent=2)[:15000]

    return _safe_call(_run, "identify_server_checks", _cache_hint="server_checks")


# ---------------------------------------------------------------------------
# Cross-reference map — complete x-ref for any class/method
# ---------------------------------------------------------------------------


@tool
def cross_reference_map(target: str) -> str:
    """Build a comprehensive cross-reference map for a class or method.
    Given a class descriptor (e.g. 'Lcom/app/Premium;') or a method name
    (e.g. 'isPremium'), returns: incoming calls, outgoing calls, field reads,
    field writes, string constants used, and resource references — all in one call.

    When to use: When you need a **complete picture** of how a class or method
    is used across the entire codebase. Replaces multiple graph_callers +
    graph_callees + trace_field_access calls. Use this as the first deep-dive
    after identifying the entity class.

    Args:
        target: A class descriptor (Lcom/...; format) or method name.

    Returns: JSON — incoming_calls, outgoing_calls, field_reads, field_writes,
    string_constants, resource_refs, summary.
    """
    def _run():
        apk_dir = _project.apktool_dir
        smali_dirs = [d for d in apk_dir.iterdir() if d.is_dir() and d.name.startswith("smali")]
        if not smali_dirs:
            return json.dumps({"success": False, "error": "No smali directories. Run apktool_decompile first."})

        is_class = target.startswith("L") and target.endswith(";")
        incoming_calls: list[dict] = []
        outgoing_calls: list[dict] = []
        field_reads: list[dict] = []
        field_writes: list[dict] = []
        string_constants: list[str] = []
        resource_refs: list[dict] = []

        # Patterns
        if is_class:
            class_prefix = target[1:-1]  # e.g. com/app/Premium
            pat_invoke = re.compile(r"invoke-\w+.*" + re.escape(target) + r"->")
            pat_field_r = re.compile(r"[is]get-\w+.*" + re.escape(target) + r"->")
            pat_field_w = re.compile(r"[is]put-\w+.*" + re.escape(target) + r"->")
        else:
            pat_invoke = re.compile(r"invoke-\w+.*->" + re.escape(target) + r"\(")
            pat_field_r = None
            pat_field_w = None

        target_file_found = False
        target_outgoing: list[str] = []

        for sd in smali_dirs:
            for sf in sd.rglob("*.smali"):
                try:
                    content = sf.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                lines = content.splitlines()
                rel = str(sf.relative_to(apk_dir))
                current_method = ""
                in_target = False

                for i, line in enumerate(lines):
                    s = line.strip()

                    if s.startswith(".method"):
                        current_method = s
                        # Check if we're reading the target class's own file
                        if is_class and class_prefix in rel.replace("\\", "/"):
                            in_target = True
                            target_file_found = True
                        elif not is_class and target in s:
                            in_target = True
                            target_file_found = True
                        else:
                            in_target = False

                    elif s.startswith(".end method"):
                        in_target = False

                    # Collect outgoing calls FROM the target
                    if in_target and "invoke-" in s:
                        target_outgoing.append(s[:120])

                    if in_target and s.startswith("const-string"):
                        parts = s.split('"')
                        if len(parts) >= 2:
                            string_constants.append(parts[1])

                    # Incoming references TO the target from other files
                    if not in_target:
                        if pat_invoke.search(s):
                            incoming_calls.append({"file": rel, "line": i + 1, "method": current_method[:80], "instruction": s[:120]})
                        if pat_field_r and pat_field_r.search(s):
                            field_reads.append({"file": rel, "line": i + 1, "method": current_method[:60], "instruction": s[:120]})
                        if pat_field_w and pat_field_w.search(s):
                            field_writes.append({"file": rel, "line": i + 1, "method": current_method[:60], "instruction": s[:120]})

                    # Resource references (R$ patterns)
                    if in_target and "sget" in s and "/R$" in s:
                        resource_refs.append({"line": i + 1, "instruction": s[:120]})

        # Deduplicate outgoing by call target
        seen_out = set()
        for inv in target_outgoing:
            # Extract the called method signature
            arrow_idx = inv.find("->")
            if arrow_idx >= 0:
                call_target = inv[inv.rfind(" ", 0, arrow_idx) + 1:]
                if call_target not in seen_out:
                    seen_out.add(call_target)
                    outgoing_calls.append({"instruction": call_target[:120]})

        string_constants = list(set(string_constants))

        return json.dumps({
            "success": True,
            "target": target,
            "target_file_found": target_file_found,
            "summary": {
                "incoming_calls": len(incoming_calls),
                "outgoing_calls": len(outgoing_calls),
                "field_reads": len(field_reads),
                "field_writes": len(field_writes),
                "string_constants": len(string_constants),
                "resource_refs": len(resource_refs),
            },
            "incoming_calls": incoming_calls[:50],
            "outgoing_calls": outgoing_calls[:50],
            "field_reads": field_reads[:30],
            "field_writes": field_writes[:30],
            "string_constants": string_constants[:30],
            "resource_refs": resource_refs[:20],
        }, ensure_ascii=False, indent=2)[:25000]

    return _safe_call(_run, "cross_reference_map")


# ---------------------------------------------------------------------------
# Deobfuscation helper — auto-suggest meaningful names
# ---------------------------------------------------------------------------


@tool
def deobfuscate_names(class_descriptor: str) -> str:
    """Analyze an obfuscated class and suggest human-readable names for it and its methods.
    Based on: Android API calls made, string constants used, field types, return types,
    and common patterns (e.g. boolean getters named isPremium, void setters, etc.).

    When to use: When the target class has obfuscated names (single-letter classes like
    'La/b/c;' or methods like 'a()', 'b(Z)V'). Run this early to understand what
    obfuscated classes actually DO, then refer to them by suggested names in your analysis.

    Args:
        class_descriptor: Full smali descriptor e.g. 'Lcom/app/a;'

    Returns: JSON — class_suggested_name, method_suggestions (list of {original, suggested,
    reason}), field_suggestions, confidence.
    """
    def _run():
        apk_dir = _project.apktool_dir
        class_path = class_descriptor[1:-1]  # Remove L and ;
        smali_file = None
        for sd in apk_dir.iterdir():
            if sd.is_dir() and sd.name.startswith("smali"):
                candidate = sd / (class_path + ".smali")
                if candidate.is_file():
                    smali_file = candidate
                    break

        if not smali_file:
            return json.dumps({"success": False, "error": f"Class file not found for {class_descriptor}"})

        content = smali_file.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()

        # Analyze methods
        methods: list[dict] = []
        current_method = ""
        method_body: list[str] = []
        fields: list[dict] = []

        for line in lines:
            s = line.strip()
            if s.startswith(".field"):
                # Parse field type
                parts = s.split()
                if len(parts) >= 3:
                    fname = parts[-1].split(":")[0] if ":" in parts[-1] else parts[-1]
                    ftype = parts[-1].split(":")[-1] if ":" in parts[-1] else ""
                    fields.append({"name": fname, "type": ftype, "declaration": s[:100]})
            elif s.startswith(".method"):
                current_method = s
                method_body = []
            elif s.startswith(".end method"):
                if current_method:
                    methods.append({"signature": current_method, "body": method_body})
                current_method = ""
            elif current_method:
                method_body.append(s)

        # Suggest names based on patterns
        method_suggestions: list[dict] = []
        android_api_hints: list[str] = []
        class_behavior_signals: list[str] = []

        for m in methods:
            sig = m["signature"]
            body = m["body"]
            body_text = "\n".join(body)

            # Extract method name
            name_match = re.search(r"(\w+)\(", sig)
            method_name = name_match.group(1) if name_match else ""

            # Skip constructors and well-named methods
            if method_name in ("<init>", "<clinit>") or len(method_name) > 3:
                continue

            suggestion = None
            reason = ""

            # Detect return type
            ret_type = sig.rsplit(")", 1)[-1].strip() if ")" in sig else ""

            # Pattern: boolean return + field check → "isSomething"
            if ret_type == "Z":
                for b in body:
                    if "iget-boolean" in b:
                        field_ref = b.split("->")[-1] if "->" in b else ""
                        field_name = field_ref.split(":")[0]
                        suggestion = f"is{field_name.capitalize()}" if len(field_name) <= 3 else f"is_{field_name}"
                        reason = f"boolean getter reading field {field_name}"
                        break

            # Pattern: void + SharedPreferences
            if not suggestion and "SharedPreferences" in body_text:
                if "putBoolean" in body_text or "putString" in body_text or "putInt" in body_text:
                    suggestion = "savePreferences"
                    reason = "writes to SharedPreferences"
                    class_behavior_signals.append("preferences_writer")
                elif "getBoolean" in body_text or "getString" in body_text:
                    suggestion = "loadPreferences"
                    reason = "reads from SharedPreferences"
                    class_behavior_signals.append("preferences_reader")

            # Pattern: invoke on billing/purchase classes
            if not suggestion:
                for b in body:
                    if "billing" in b.lower() or "purchase" in b.lower() or "BillingClient" in b:
                        suggestion = "handlePurchase"
                        reason = "interacts with billing API"
                        class_behavior_signals.append("billing_handler")
                        break
                    if "HttpURLConnection" in b or "OkHttpClient" in b or "Retrofit" in b:
                        suggestion = "makeNetworkCall"
                        reason = "performs network request"
                        class_behavior_signals.append("network_client")
                        break

            # Pattern: Android API calls
            for b in body:
                if "invoke-" in b:
                    if "Landroid/content/Intent;" in b:
                        android_api_hints.append("intent_handler")
                    elif "Landroid/app/AlertDialog" in b or "Landroid/app/Dialog" in b:
                        android_api_hints.append("dialog_builder")
                    elif "Landroid/widget/Toast" in b:
                        android_api_hints.append("toast_shower")
                    elif "Landroid/view/View" in b:
                        android_api_hints.append("view_manipulator")

            if suggestion:
                method_suggestions.append({
                    "original": method_name,
                    "signature": sig[:80],
                    "suggested": suggestion,
                    "reason": reason,
                })

        # Field suggestions
        field_suggestions: list[dict] = []
        for f in fields:
            if len(f["name"]) <= 2:
                ftype = f["type"]
                suggestion = None
                if ftype == "Z":
                    suggestion = "isEnabled"
                elif ftype == "Ljava/lang/String;":
                    suggestion = "textValue"
                elif ftype == "I":
                    suggestion = "intValue"
                elif ftype == "J":
                    suggestion = "timestamp"
                elif "List" in ftype:
                    suggestion = "itemList"
                if suggestion:
                    field_suggestions.append({"original": f["name"], "type": ftype, "suggested": suggestion})

        # Class name suggestion
        class_name = class_path.split("/")[-1]
        class_suggestion = None
        if len(class_name) <= 3:
            if "billing_handler" in class_behavior_signals:
                class_suggestion = "BillingManager"
            elif "network_client" in class_behavior_signals:
                class_suggestion = "NetworkHelper"
            elif "preferences_writer" in class_behavior_signals or "preferences_reader" in class_behavior_signals:
                class_suggestion = "PreferencesManager"
            elif "dialog_builder" in android_api_hints:
                class_suggestion = "DialogHelper"
            elif any("iget-boolean" in "\n".join(m["body"]) for m in methods):
                class_suggestion = "StateEntity"

        return json.dumps({
            "success": True,
            "class_descriptor": class_descriptor,
            "class_name": class_name,
            "class_suggested_name": class_suggestion,
            "total_methods": len(methods),
            "total_fields": len(fields),
            "method_suggestions": method_suggestions[:20],
            "field_suggestions": field_suggestions[:20],
            "android_api_hints": list(set(android_api_hints))[:10],
            "behavior_signals": list(set(class_behavior_signals))[:10],
            "confidence": "high" if len(method_suggestions) >= 3 else ("medium" if method_suggestions else "low"),
        }, ensure_ascii=False, indent=2)

    return _safe_call(_run, "deobfuscate_names")


# ---------------------------------------------------------------------------
# Dynamic lifecycle checks — find runtime re-validation
# ---------------------------------------------------------------------------


@tool
def find_dynamic_checks() -> str:
    """Find premium/license re-validation that happens at Android lifecycle points.
    Many apps re-check premium status in onResume(), onStart(), onWindowFocusChanged(),
    onAttachedToWindow(), or periodic timers. These dynamic checks can UNDO patched
    values when the user navigates back to the screen.

    When to use: After patching premium getters, if the app REVERTS to free mode when
    backgrounded/resumed or after a few seconds. This tool finds the lifecycle hooks
    that re-validate, so you can patch them too.

    Returns: JSON — lifecycle_checks (array with file, method, lifecycle_hook,
    premium_indicator, line), timer_checks, broadcast_checks.
    """
    def _run():
        apk_dir = _project.apktool_dir
        smali_dirs = [d for d in apk_dir.iterdir() if d.is_dir() and d.name.startswith("smali")]
        if not smali_dirs:
            return json.dumps({"success": False, "error": "No smali directories."})

        lifecycle_hooks = [
            "onResume", "onStart", "onRestart", "onWindowFocusChanged",
            "onAttachedToWindow", "onConfigurationChanged", "onNewIntent",
        ]
        premium_indicators = re.compile(
            r"premium|isPro|isVip|isPaid|isTrial|isExpired|isFree|"
            r"subscription|license|purchas|billing|getType|getPlan|"
            r"TRIER|TRIAL|FREE|PREMIUM|PRO|VIP",
            re.IGNORECASE,
        )
        timer_patterns = re.compile(
            r"Handler|Runnable|postDelayed|scheduleAtFixedRate|Timer|"
            r"CountDownTimer|AlarmManager|WorkManager",
        )
        broadcast_patterns = re.compile(
            r"BroadcastReceiver|onReceive|registerReceiver|"
            r"PACKAGE_REPLACED|MY_PACKAGE_REPLACED",
        )

        lifecycle_checks: list[dict] = []
        timer_checks: list[dict] = []
        broadcast_checks: list[dict] = []

        for sd in smali_dirs:
            for sf in sd.rglob("*.smali"):
                try:
                    content = sf.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue

                lines = content.splitlines()
                rel = str(sf.relative_to(apk_dir))
                current_method = ""

                for i, line in enumerate(lines):
                    s = line.strip()

                    if s.startswith(".method"):
                        current_method = s
                    elif s.startswith(".end method"):
                        current_method = ""

                    if not current_method:
                        continue

                    # Check lifecycle hooks
                    for hook in lifecycle_hooks:
                        if hook in current_method:
                            # Look for premium indicators in the next 30 lines
                            window = "\n".join(lines[i:i + 30])
                            prem_matches = premium_indicators.findall(window)
                            if prem_matches:
                                lifecycle_checks.append({
                                    "file": rel,
                                    "line": i + 1,
                                    "method": current_method[:80],
                                    "lifecycle_hook": hook,
                                    "premium_indicators": list(set(prem_matches))[:5],
                                })
                            break

                    # Timer-based checks
                    if timer_patterns.search(s) and premium_indicators.search(
                        "\n".join(lines[max(0, i - 5):i + 10])
                    ):
                        timer_checks.append({
                            "file": rel, "line": i + 1,
                            "method": current_method[:80],
                            "instruction": s[:100],
                        })

                    # Broadcast receiver checks
                    if broadcast_patterns.search(s) and premium_indicators.search(
                        "\n".join(lines[max(0, i - 5):i + 10])
                    ):
                        broadcast_checks.append({
                            "file": rel, "line": i + 1,
                            "method": current_method[:80],
                            "instruction": s[:100],
                        })

        return json.dumps({
            "success": True,
            "total_lifecycle_checks": len(lifecycle_checks),
            "total_timer_checks": len(timer_checks),
            "total_broadcast_checks": len(broadcast_checks),
            "lifecycle_checks": lifecycle_checks[:30],
            "timer_checks": timer_checks[:20],
            "broadcast_checks": broadcast_checks[:10],
            "analysis_hint": (
                "Lifecycle checks (especially onResume) can reset premium state. "
                "Patch them to skip the re-validation call, or patch the underlying "
                "field/method they call. Timer-based checks are periodic — patch the "
                "scheduled method or remove the timer registration."
            ),
        }, ensure_ascii=False, indent=2)[:15000]

    return _safe_call(_run, "find_dynamic_checks")


# ---------------------------------------------------------------------------
# Extract ALL URLs/endpoints from the APK
# ---------------------------------------------------------------------------


@tool
def extract_all_urls() -> str:
    """Extract ALL URLs and API endpoints from the entire APK codebase.
    Searches: const-string URLs, Retrofit @GET/@POST annotations, WebView.loadUrl
    calls, deeplinks from manifest, and resource XML URLs.
    Each URL is mapped to its code location (file + line + method).

    When to use: For a complete map of all network endpoints. Use early for recon,
    or after patching to find server-side validation endpoints you may have missed.

    Returns: JSON — total_urls, urls (array of {url, file, line, method, type}),
    url_domains (unique domain list), deeplinks (from manifest).
    """
    def _run():
        apk_dir = _project.apktool_dir
        url_pattern = re.compile(r'https?://[^\s"<>\')]+', re.IGNORECASE)
        retrofit_pattern = re.compile(r'@(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(\s*"([^"]+)"')
        webview_pattern = re.compile(r'const-string\s+\w+,\s*"(https?://[^"]+)"')

        urls: list[dict] = []
        seen_urls: set[str] = set()
        deeplinks: list[dict] = []

        # --- Scan smali files ---
        smali_dirs = [d for d in apk_dir.iterdir() if d.is_dir() and d.name.startswith("smali")]
        for sd in smali_dirs:
            for sf in sd.rglob("*.smali"):
                try:
                    content = sf.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                lines = content.splitlines()
                rel = str(sf.relative_to(apk_dir))
                current_method = ""
                for i, line in enumerate(lines):
                    s = line.strip()
                    if s.startswith(".method"):
                        current_method = s.split()[-1] if s.split() else s
                    elif s.startswith(".end method"):
                        current_method = ""

                    if s.startswith("const-string"):
                        # Extract the string value
                        quote_start = s.find('"')
                        quote_end = s.rfind('"')
                        if quote_start != -1 and quote_end > quote_start:
                            val = s[quote_start + 1:quote_end]
                            url_match = url_pattern.match(val)
                            if url_match and val not in seen_urls:
                                seen_urls.add(val)
                                url_type = "api_endpoint"
                                if "loadUrl" in "\n".join(lines[max(0, i):i + 5]):
                                    url_type = "webview"
                                elif any(kw in val.lower() for kw in ("api", "v1", "v2", "graphql", "rest")):
                                    url_type = "api_endpoint"
                                elif any(kw in val.lower() for kw in (".js", ".css", ".html", ".htm")):
                                    url_type = "web_resource"
                                urls.append({
                                    "url": val[:200],
                                    "file": rel,
                                    "line": i + 1,
                                    "method": current_method[:60],
                                    "type": url_type,
                                })

        # --- Scan manifest for deeplinks ---
        manifest = apk_dir / "AndroidManifest.xml"
        if manifest.is_file():
            try:
                mftext = manifest.read_text(encoding="utf-8", errors="replace")
                # Find intent-filter data elements with scheme+host
                import xml.etree.ElementTree as ET
                root = ET.fromstring(mftext)
                ns = {"android": "http://schemas.android.com/apk/res/android"}
                for data in root.iter("data"):
                    scheme = data.get(f"{{{ns['android']}}}scheme", "")
                    host = data.get(f"{{{ns['android']}}}host", "")
                    path = data.get(f"{{{ns['android']}}}path", "")
                    pathPrefix = data.get(f"{{{ns['android']}}}pathPrefix", "")
                    if scheme:
                        deeplink_url = f"{scheme}://{host}{path or pathPrefix}"
                        deeplinks.append({"url": deeplink_url, "scheme": scheme, "host": host})
            except Exception:
                pass

        # --- Scan resource XMLs for URLs ---
        res_dir = apk_dir / "res"
        if res_dir.is_dir():
            for xml_file in res_dir.rglob("*.xml"):
                try:
                    xml_text = xml_file.read_text(encoding="utf-8", errors="replace")
                    for m in url_pattern.finditer(xml_text):
                        u = m.group()
                        if u not in seen_urls and not u.startswith("http://schemas."):
                            seen_urls.add(u)
                            urls.append({
                                "url": u[:200],
                                "file": str(xml_file.relative_to(apk_dir)),
                                "line": 0,
                                "method": "",
                                "type": "resource_xml",
                            })
                except Exception:
                    continue

        # Unique domains
        domains: set[str] = set()
        for u in urls:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(u["url"])
                if parsed.hostname:
                    domains.add(parsed.hostname)
            except Exception:
                pass

        return json.dumps({
            "success": True,
            "total_urls": len(urls),
            "total_domains": len(domains),
            "total_deeplinks": len(deeplinks),
            "url_domains": sorted(domains)[:30],
            "urls": urls[:80],
            "deeplinks": deeplinks[:20],
        }, ensure_ascii=False, indent=2)[:25000]

    return _safe_call(_run, "extract_all_urls", _cache_hint="all_urls")


# ---------------------------------------------------------------------------
# Verify bypass completeness — post-patch verification
# ---------------------------------------------------------------------------


@tool
def verify_bypass_completeness() -> str:
    """Post-patch verification: re-scan the codebase for REMAINING premium/license
    gates that are NOT yet patched. Checks: boolean premium getters still returning
    dynamic values, SharedPreferences premium reads, entity field assignments to
    non-premium values, and UI gate methods (showing upgrade/paywall dialogs).

    When to use: After all patches are applied, BEFORE building the APK.
    This is the final quality gate — any remaining gates it finds MUST be patched.

    Returns: JSON — remaining_gates (array), remaining_prefs_checks, remaining_ui_gates,
    patch_coverage_pct, verdict (PASS/FAIL).
    """
    def _run():
        apk_dir = _project.apktool_dir
        smali_dirs = [d for d in apk_dir.iterdir() if d.is_dir() and d.name.startswith("smali")]
        if not smali_dirs:
            return json.dumps({"success": False, "error": "No smali directories."})

        premium_method_pat = re.compile(
            r"\.method\s+.*(?:isPremium|isPro|isVip|isPaid|isTrial|isExpired|isFree|"
            r"isSubscribed|hasSubscription|checkLicense|validateLicense|isLicensed|"
            r"canAccess|isUnlocked|isActivated)",
            re.IGNORECASE,
        )
        prefs_premium_pat = re.compile(
            r'const-string\s+\w+,\s*"(?:is_premium|is_pro|premium|vip|paid|'
            r'license_status|subscription_type|plan_type|user_type|account_type)"',
            re.IGNORECASE,
        )
        ui_gate_pat = re.compile(
            r"(?:upgrade|paywall|subscribe|go_pro|buy_premium|"
            r"premium_required|locked_feature|trial_expired)",
            re.IGNORECASE,
        )

        remaining_gates: list[dict] = []
        remaining_prefs: list[dict] = []
        remaining_ui: list[dict] = []
        patched_methods: set[str] = set()

        for sd in smali_dirs:
            for sf in sd.rglob("*.smali"):
                try:
                    content = sf.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue
                lines = content.splitlines()
                rel = str(sf.relative_to(apk_dir))
                current_method = ""
                method_start = 0

                for i, line in enumerate(lines):
                    s = line.strip()

                    if s.startswith(".method"):
                        current_method = s
                        method_start = i
                    elif s.startswith(".end method"):
                        # Check if this premium method was ALREADY patched
                        if premium_method_pat.search(current_method):
                            method_body = "\n".join(lines[method_start:i])
                            # A patched method typically has const/4 + return as first instructions
                            is_patched = bool(re.search(
                                r"\.locals\s+\d+\s*\n\s*const(?:/4|/16)?\s+v0",
                                method_body,
                            ))
                            if not is_patched:
                                remaining_gates.append({
                                    "file": rel,
                                    "line": method_start + 1,
                                    "method": current_method[:80],
                                    "status": "NOT_PATCHED",
                                })
                            else:
                                patched_methods.add(f"{rel}:{current_method[:60]}")
                        current_method = ""
                        continue

                    # SharedPreferences premium reads
                    if prefs_premium_pat.search(s):
                        # Check if there's a const override right after
                        lookahead = "\n".join(lines[i:i + 5])
                        if "move-result" in lookahead and "const" not in "\n".join(lines[i + 1:i + 3]):
                            remaining_prefs.append({
                                "file": rel, "line": i + 1,
                                "method": current_method[:60],
                                "instruction": s[:100],
                            })

                    # UI gate strings
                    if s.startswith("const-string") and ui_gate_pat.search(s):
                        remaining_ui.append({
                            "file": rel, "line": i + 1,
                            "method": current_method[:60],
                            "instruction": s[:100],
                        })

        total_gates = len(remaining_gates) + len(patched_methods)
        patched_count = len(patched_methods)
        coverage = (patched_count / total_gates * 100) if total_gates > 0 else 100.0
        verdict = "PASS" if not remaining_gates and not remaining_prefs else "FAIL"

        return json.dumps({
            "success": True,
            "verdict": verdict,
            "patch_coverage_pct": round(coverage, 1),
            "patched_methods": patched_count,
            "remaining_gates": remaining_gates[:20],
            "remaining_prefs_checks": remaining_prefs[:15],
            "remaining_ui_gates": remaining_ui[:15],
            "summary": (
                f"Coverage: {coverage:.0f}%. "
                f"{'ALL gates patched!' if verdict == 'PASS' else f'{len(remaining_gates)} methods + {len(remaining_prefs)} prefs reads still need patching.'}"
            ),
        }, ensure_ascii=False, indent=2)[:15000]

    return _safe_call(_run, "verify_bypass_completeness")


# ---------------------------------------------------------------------------
# Patch tools
# ---------------------------------------------------------------------------


@tool
def apply_smali_patch(patch_plan_json: str) -> str:
    """Apply a smali patch to modify the APK's behaviour.
    The patch plan is a JSON object specifying the target file and operations.

    When to use: For precise, tracked smali modifications with backup and diff.
    Use preview_smali_patch first to verify changes. For bulk automated bypasses,
    use auto_patch_bypass instead.

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

    Returns: JSON with keys: success (bool), target_file, steps_applied (int),
    steps_total (int), diff_text (unified diff of changes), errors (list),
    backup_path (path to original file backup).
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

    if not (plan_data.get("target_file") or plan_data.get("file") or plan_data.get("smali_file")):
        return json.dumps({
            "success": False,
            "error": "Missing 'target_file' in patch plan JSON.",
            "recovery_hint": 'Add "target_file": "smali_classes3/com/example/Foo.smali" to your JSON.',
        })

    try:
        plan = PatchPlan.from_dict(plan_data)
    except (ValueError, KeyError) as e:
        return json.dumps({"success": False, "error": str(e)})

    engine = PatchEngine(
        apktool_dir=_project.apktool_dir,
        backup_dir=_project.patch_backup_dir,
        diffs_dir=_project.patch_diffs_dir,
    )
    result = engine.apply_plan(plan)

    out: dict = {
        "success": result.success,
        "target_file": result.target_file,
        "steps_applied": result.steps_applied,
        "steps_total": result.steps_total,
        "diff_text": result.diff_text[:5000],
        "errors": result.errors,
        "backup_path": result.backup_path,
    }

    # --- AUTO-PROPAGATION CHECK ---
    # After a successful patch, query the code graph for callers of the
    # patched method.  This surfaces cached-result fields, AND-combined
    # conditions, alternate read paths, and startup-only calls that the
    # agent must also patch to get full coverage.
    if result.success:
        try:
            propagation = _propagation_check(result.target_file, result.diff_text)
            if propagation:
                out["propagation_warnings"] = propagation
        except Exception:
            pass  # never let propagation check break the patch result

    # Record to patch journal for accurate report generation
    _patch_journal.append({
        "success": result.success,
        "target_file": result.target_file,
        "description": plan_data.get("description", ""),
        "steps_applied": result.steps_applied,
        "steps_total": result.steps_total,
        "diff_text": result.diff_text[:3000],
        "errors": result.errors,
        "tool": "apply_smali_patch",
    })

    return json.dumps(out, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Propagation check helper (called automatically after successful patches)
# ---------------------------------------------------------------------------

def _propagation_check(target_file: str, diff_text: str) -> list[str]:
    """Analyse callers of the patched method and return actionable warnings.

    Runs silently inside apply_smali_patch — never raises.
    """
    from apk_agent.tools.code_graph import query_callers as _qc

    G = _ensure_graph()
    if G is None:
        return []

    # Extract patched method names from the diff (look for .method lines)
    import re as _re
    method_names: list[str] = []
    for line in diff_text.splitlines():
        # Lines starting with - or context (unchanged) that declare a .method
        m = _re.search(r'\.method\s+.*?([\w<>$]+)\(', line)
        if m:
            method_names.append(m.group(1))

    # Also try to infer from target_file: com/Foo/Bar.smali -> look for class methods
    class_name = target_file.replace("\\", "/").split("/")[-1].replace(".smali", "")
    if class_name and not method_names:
        method_names.append(class_name)  # fallback: search by class

    warnings: list[str] = []
    seen_callers: set[str] = set()

    for mname in dict.fromkeys(method_names):  # dedupe, preserve order
        result = _qc(G, mname, depth=2)
        if not result.get("found"):
            continue
        chains = result.get("call_chains", [])[:30]
        for chain in chains:
            caller = chain.get("caller", "")
            if caller in seen_callers:
                continue
            seen_callers.add(caller)

            caller_file = chain.get("caller_file", "")
            # Read a few lines around the call site to detect common patterns
            if caller_file:
                try:
                    fpath = _project.apktool_dir / caller_file
                    if not fpath.is_file():
                        continue
                    src = fpath.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue

                lower_src = src.lower()
                # Pattern 1: result cached in an instance field (iput-boolean, sput)
                if any(kw in lower_src for kw in ("iput-boolean", "sput-boolean", "iput ", "sput ")):
                    if mname.lower() in lower_src:
                        warnings.append(
                            f"CACHED RESULT: {caller} stores the result of {mname} in a field. "
                            f"Patch the field initialisation too (file: {caller_file})."
                        )
                # Pattern 2: AND-combined condition (if-eqz after invoke → another if-eqz)
                # Heuristic: two invoke+if-eqz within 20 lines
                lines = src.splitlines()
                for i, ln in enumerate(lines):
                    if mname in ln and "invoke" in ln:
                        window = "\n".join(lines[max(0,i-3):min(len(lines),i+15)])
                        if window.count("if-eqz") >= 2 or window.count("if-nez") >= 2:
                            warnings.append(
                                f"AND-CONDITION: {caller} combines {mname} with another check. "
                                f"Find and patch the second condition too (file: {caller_file}, ~line {i+1})."
                            )
                            break

    # Dedupe and cap
    return list(dict.fromkeys(warnings))[:10]


@tool
def preview_smali_patch(patch_plan_json: str) -> str:
    """Preview what a smali patch would change WITHOUT actually modifying files.
    Use this to validate a patch plan before applying it.

    When to use: ALWAYS preview before apply_smali_patch to verify the patch
    targets the right code and makes the intended change.

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

    if not (plan_data.get("target_file") or plan_data.get("file") or plan_data.get("smali_file")):
        return json.dumps({
            "success": False,
            "error": "Missing 'target_file' in patch plan JSON.",
            "recovery_hint": 'Add "target_file": "smali_classes3/com/example/Foo.smali" to your JSON.',
        })

    try:
        plan = PatchPlan.from_dict(plan_data)
    except (ValueError, KeyError) as e:
        return json.dumps({"success": False, "error": str(e)})

    engine = PatchEngine(
        apktool_dir=_project.apktool_dir,
        backup_dir=_project.patch_backup_dir,
        diffs_dir=_project.patch_diffs_dir,
    )
    return engine.preview_plan(plan)[:8000]


@tool
def restore_smali_backup(smali_file: str) -> str:
    """Restore a smali file to its ORIGINAL state (before any patches).

    When a previous patch corrupted a file or caused unintended changes,
    use this to undo ALL patches on that file and start fresh.

    The backup is created automatically the FIRST time apply_smali_patch
    touches a file — it preserves the original pre-patch version.

    Args:
        smali_file: path to the smali file to restore (same format as
            target_file in apply_smali_patch, e.g. 'smali_classes3/R5/a.smali')

    Returns: JSON with success, restored_file (the path that was restored),
    backup_source (the backup file used).
    """
    from apk_agent.patch_engine import PatchEngine

    def _run():
        engine = PatchEngine(
            apktool_dir=_project.apktool_dir,
            backup_dir=_project.patch_backup_dir,
            diffs_dir=_project.patch_diffs_dir,
        )
        result = engine.restore_backup(smali_file)
        return json.dumps(result, ensure_ascii=False, indent=2)

    return _safe_call(_run, "restore_smali_backup")


# ---------------------------------------------------------------------------
# Report tool
# ---------------------------------------------------------------------------


@tool
def generate_report(
    findings_json: str,
    patch_results_json: str = "[]",
) -> str:
    """Generate a Markdown security report summarizing findings and patches.

    When to use: At the END of analysis, after all findings and patches are collected.
    Pass the complete findings array. Patch results are auto-collected from the
    patch journal — you do NOT need to provide patch_results_json.

    Args:
        findings_json: JSON array of findings, each with: title, severity, category, description, location, evidence.
        patch_results_json: JSON array of patch results (optional — auto-filled from patch journal if omitted).

    Returns: Text with the report file path and a preview of the first 3000 characters
    of the generated Markdown report. Full report saved to outputs/report.md.
    """
    from apk_agent.reporting import generate_report as _gen

    try:
        findings = json.loads(findings_json)
    except json.JSONDecodeError as e:
        return json.dumps({"success": False, "error": f"Invalid JSON in findings_json: {e}"})

    # Use module-level patch journal as authoritative source (never loses data).
    # Fall back to LLM-provided JSON only if the journal is empty.
    if _patch_journal:
        patches = list(_patch_journal)
    else:
        try:
            patches = json.loads(patch_results_json)
        except json.JSONDecodeError:
            patches = []

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

    When to use: Early recon after decompilation — get class counts, crypto API usage,
    and security-related files. Prefer index_lookup_* or graph tools for targeted queries.

    Args:
        directory: Smali directory to scan. Defaults to apktool smali output.

    Returns: JSON with keys: total_classes, total_methods, crypto_apis (list of
    classes using crypto), security_apis (list), interesting_files (list of paths
    with security-related code).
    """
    from apk_agent.tools.smali_analyzer import scan_smali_directory

    d = _resolve_dir(directory, default="apktool")

    def _run():
        result = scan_smali_directory(d)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "scan_smali_classes", _cache_hint=str(directory))


@tool
def analyze_smali_class(file_path: str) -> str:
    """Deep-analyze a single smali file: parse class info, methods, fields,
    string constants, and crypto/security API findings.

    When to use: After identifying a target file via search/index tools. Gives full
    structural breakdown of a single class. For method-level analysis, use read_file
    or batch_read_smali_methods.

    Args:
        file_path: Path to the .smali file (absolute or relative to workspace).

    Returns: JSON with keys: class_name, super_class, interfaces, access_flags,
    methods (array with name, access, params, return_type), fields (array),
    strings (array of constant values), crypto_findings, security_api_usage.
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

    When to use: When you know a method name and need to find every caller.
    For faster results on large codebases, prefer graph_callers (requires graph to be built).

    Args:
        method_signature: Full or partial method signature,
            e.g. "checkServerTrusted", "Landroid/util/Log;->d".
        directory: Smali directory. Defaults to apktool output.

    Returns: JSON with keys: method, total_refs, files (array of {file, line, code}
    for each call site found).
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
    return _safe_call(_run, "scan_vulnerabilities", _cache_hint=f"{directory}:{severity_filter}")


@tool
def list_vuln_patterns() -> str:
    """List all available vulnerability detection patterns with their IDs,
    names, severity levels, and categories.
    Use this to understand what the scanner can detect.

    When to use: Before running scan_vulnerabilities to understand available patterns,
    or when the user asks what security checks are supported.

    Returns: JSON array of patterns, each with: id, name, severity (critical/high/medium/low),
    category, description, and regex pattern used for detection.
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

    When to use: When you need to see code AROUND a match (method body, class structure).
    For exact matches without context, use search_in_code. For multi-pattern filtering,
    use multi_search.

    Args:
        pattern: Regex pattern to search for.
        directory: Directory to search in. Defaults to JADX sources.
            Use "smali" or "apktool" for smali code.
        context_lines: Lines of context before/after match (default 3).
        file_extensions: Comma-separated extensions (e.g., ".java,.smali").
        exclude_dirs: Comma-separated directory names to SKIP (e.g., "build,test,res,original").

    Returns: JSON with keys: pattern, total_matches, files_matched,
    results (array of {file, matches: [{line, text, context_before, context_after}]}).
    """
    from apk_agent.tools.advanced_search import search_with_context

    exts = None
    if file_extensions:
        exts = [e.strip() for e in file_extensions.split(",")]

    excl = None
    if exclude_dirs:
        excl = [d_.strip() for d_ in exclude_dirs.split(",")]

    # Auto-detect smali: if extensions include .smali and no dir given,
    # search all smali dirs instead of just jadx
    low_dir = (directory or "").strip().lower().replace("\\", "/")
    has_smali_ext = exts and any(e.strip().lower() in (".smali", "smali") for e in exts)
    search_all_smali = low_dir in ("smali", "apktool/smali", "apktool") or (
        not low_dir and has_smali_ext
    )

    def _run():
        if search_all_smali:
            all_results = []
            total = 0
            files_searched = 0
            for smali_d in _get_all_smali_dirs():
                result = search_with_context(smali_d, pattern, context_lines=context_lines,
                                              file_extensions=exts, exclude_dirs=excl,
                                              exclude_packages=True)
                if isinstance(result, dict):
                    all_results.extend(result.get("results", []))
                    total += result.get("total_matches", 0)
                    files_searched += result.get("files_searched", 0)
            return json.dumps({
                "success": True,
                "files_searched": files_searched,
                "total_matches": total,
                "truncated": len(all_results) > 50,
                "results": all_results[:50],
            }, ensure_ascii=False, indent=2)[:15000]
        else:
            d = _resolve_dir(directory, default="jadx")
            result = search_with_context(d, pattern, context_lines=context_lines,
                                          file_extensions=exts, exclude_dirs=excl,
                                          exclude_packages=True)
            return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "context_search", _cache_hint=f"{pattern}:{directory}:{context_lines}:{file_extensions}:{exclude_dirs}")


@tool
def multi_search(
    patterns: str,
    logic: str = "AND",
    directory: Optional[str] = None,
    exclude_dirs: Optional[str] = None,
) -> str:
    """Search for multiple patterns with AND/OR logic.
    AND = file must contain ALL patterns. OR = file must contain at least one.

    When to use: When you need files matching multiple criteria (e.g. find files with
    BOTH SSL pinning AND certificate validation). For single-pattern search, use
    search_in_code or context_search.

    Args:
        patterns: Comma-separated regex patterns.
            Example: "CertificatePinner,checkServerTrusted,X509"
        logic: "AND" or "OR" (default AND).
        directory: Directory to search. Defaults to JADX sources.
        exclude_dirs: Comma-separated directory names to SKIP (e.g., "build,test,res").

    Returns: JSON with keys: patterns, logic, total_matches, files_matched,
    results (array of {file, matched_patterns: [pattern1, pattern2, ...]}).
    """
    from apk_agent.tools.advanced_search import multi_pattern_search

    pattern_list = [p.strip() for p in patterns.split(",")]

    excl = None
    if exclude_dirs:
        excl = [d_.strip() for d_ in exclude_dirs.split(",")]

    def _run():
        # Search both jadx AND all smali dirs for code searches
        all_results = []
        dirs_to_search = [_project.jadx_dir]
        low_dir = (directory or "").strip().lower().replace("\\", "/")
        if directory and low_dir not in ("", "jadx"):
            dirs_to_search = [_resolve_dir(directory, default="jadx")]
        else:
            # Also add all smali dirs for broader coverage
            dirs_to_search.extend(_get_all_smali_dirs())

        for d in dirs_to_search:
            result = multi_pattern_search(d, pattern_list, logic=logic, exclude_dirs=excl,
                                           exclude_packages=True)
            if isinstance(result, dict) and result.get("results"):
                all_results.extend(result["results"])

        return json.dumps({
            "patterns": pattern_list,
            "logic": logic,
            "total_matches": len(all_results),
            "results": all_results[:50],
        }, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "multi_search", _cache_hint=f"{patterns}:{logic}:{directory}:{exclude_dirs}")


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

    def _run():
        all_refs = []
        low_dir = (directory or "").strip().lower().replace("\\", "/")
        if directory and low_dir not in ("", "jadx"):
            dirs = [_resolve_dir(directory, default="jadx")]
        else:
            dirs = [_project.jadx_dir] + _get_all_smali_dirs()

        for d in dirs:
            result = cross_reference_search(d, class_or_method, search_type=search_type)
            if isinstance(result, dict) and result.get("references"):
                all_refs.extend(result["references"])

        return json.dumps({
            "success": True,
            "target": class_or_method,
            "search_type": search_type,
            "references": all_refs[:50],
        }, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "xref_search", _cache_hint=f"{class_or_method}:{search_type}:{directory}")


@tool
def directory_overview(directory: Optional[str] = None) -> str:
    """Get statistics about a directory — file counts, sizes, types.
    Use this to decide which directories to search for analysis.

    When to use: For orientation — understand the project structure, find
    where code lives, and decide which directories to focus on.

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
    return _safe_call(_run, "directory_overview", _cache_hint=str(directory))


# ---------------------------------------------------------------------------
# Targeted analysis: network interceptors, native bridges, dynamic loading
# ---------------------------------------------------------------------------


@tool
def search_interceptors(directory: Optional[str] = None) -> str:
    """Find OkHttp/Retrofit interceptors and network-layer encryption code.
    Searches ONLY .java/.kt/.smali files for: implements Interceptor,
    chain.proceed(, RequestBody, ResponseBody, addInterceptor(), and
    crypto imports co-located with network code.

    When to use: FIRST tool when investigating encrypted API payloads/responses.
    Finds interceptor classes and crypto-in-network patterns.

    Args:
        directory: Directory to search. Defaults to JADX sources.
            Use "smali" or "apktool" for smali code.

    Returns: JSON with keys: total_interceptors, interceptor_files (array of
    {file, class_name, type}), crypto_in_network (array of files with both
    crypto and network imports), request_body_handlers (array).
    """
    from apk_agent.tools.targeted_analysis import search_network_interceptors

    d = _resolve_dir(directory, default="jadx")

    def _run():
        result = search_network_interceptors(d)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "search_interceptors", _cache_hint=str(directory))


@tool
def search_native_code(directory: Optional[str] = None) -> str:
    """Find JNI native method declarations, System.loadLibrary() calls,
    and framework bridges (React Native modules, Flutter channels).
    Also lists .so libraries in lib/ with architecture info.

    These indicate crypto or parsing logic hidden in compiled native code.

    When to use: When you suspect crypto/security logic is in native .so libraries
    rather than Java/Kotlin code. Also useful to detect React Native or Flutter apps.

    Args:
        directory: Directory to search. Defaults to apktool output (has lib/).

    Returns: JSON with keys: native_methods (array of {class, method, signature}),
    load_library_calls (array of {file, library_name}), so_libraries (array of
    {path, arch, size}), framework_bridges (array of detected RN/Flutter modules).
    """
    from apk_agent.tools.targeted_analysis import search_native_bridges

    d = _resolve_dir(directory, default="apktool")

    def _run():
        result = search_native_bridges(d)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "search_native_code", _cache_hint=str(directory))


@tool
def search_dynamic_loaders(directory: Optional[str] = None) -> str:
    """Find dynamic code loading patterns: DexClassLoader, Class.forName,
    reflection Method.invoke, runtime .dex/.jar loading, and hidden
    DEX files in assets/.

    Crypto logic may be loaded at runtime and hidden from static analysis.

    When to use: When statically visible code doesn't explain observed behavior,
    or when you need to find hidden/dynamically loaded modules.

    Args:
        directory: Directory to search. Defaults to apktool output.

    Returns: JSON with keys: class_loaders (array of {file, type, pattern}),
    reflection_calls (array of {file, method}), hidden_dex (array of {path, size}
    for .dex/.jar files in assets/), total_findings.
    """
    from apk_agent.tools.targeted_analysis import search_dynamic_loading

    d = _resolve_dir(directory, default="apktool")

    def _run():
        result = search_dynamic_loading(d)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "search_dynamic_loaders", _cache_hint=str(directory))


# ---------------------------------------------------------------------------
# NEW: Network Security Config analyzer
# ---------------------------------------------------------------------------

@tool
def analyze_network_config() -> str:
    """Analyze the network_security_config.xml for SSL/TLS settings.
    Detects: cleartext traffic permissions, custom trust anchors,
    certificate pinning configs, and domain-specific rules.
    Requires apktool_decompile to have been run first.

    When to use: Specifically for understanding the app’s network security posture.
    Shows pinning, trust anchors, and cleartext settings before deciding on patches.

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

    When to use: When the APK contains native libraries. Check for JNI bridges,
    hardcoded strings, and determine if security checks are in native code.

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

    When to use: During recon to check if APK is debug-signed, identify the signer,
    and detect weak signature schemes.

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

    When to use: Early in analysis to identify dangerous permissions and assess
    overall risk level. Run after aapt2_dump or parse_manifest.

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

    When to use: After decompilation to assess external entry points (exported
    activities, services, receivers, providers, deep links).

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

    When to use: EVERY TIME you discover something important. Save findings as you go
    so they survive context compaction and session restarts.

    Args:
        category: vuln|crypto|network|permission|component|string|pattern|patch|file|config|behavior|misc
        title: short title for the finding
        detail: detailed description with code snippets/evidence
        severity: critical|high|medium|low|info
        file_path: relevant file path (if any)
        tags: comma-separated tags (e.g. "ssl,pinning,bypass")

    Returns: JSON with keys: success (bool), id (evidence entry ID),
    total_evidence (total count after saving).
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

    When to use: After session resume to recall previous findings, or periodically
    to review accumulated evidence before writing a report.

    Returns: JSON with keys: total (int), evidence (array of {id, category, title,
    detail, severity, file_path, tags, timestamp}).
    """
    from apk_agent.tools.evidence import load_evidence as _load

    def _run():
        result = _load(_project.workspace_path, category=category, severity=severity)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "load_evidence")


@tool
def search_evidence(query: str) -> str:
    """Search within saved evidence by keyword.

    When to use: When you need to find specific evidence entries matching a term
    (e.g. "ssl", "root detection"). Faster than load_evidence + manual filtering.

    Args:
        query: Keyword to search for in evidence titles, details, and tags.

    Returns: JSON with keys: query, total_matches, results (array of matching
    evidence entries with id, category, title, detail, severity).
    """
    from apk_agent.tools.evidence import search_evidence as _search

    def _run():
        result = _search(_project.workspace_path, query)
        return json.dumps(result, ensure_ascii=False, indent=2)[:10000]
    return _safe_call(_run, "search_evidence")


@tool
def get_evidence_summary() -> str:
    """Get a compact summary of all evidence — counts by category/severity and critical findings.

    When to use: Quick overview of evidence collection progress. Useful before
    generating the final report to ensure all categories are covered.

    Returns: JSON with keys: total_evidence, by_category (dict of category→count),
    by_severity (dict of severity→count), critical_findings (array of the most
    important entries).
    """
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

    When to use: After locating a suspicious method (via graph tools, search, or
    unified_scan), use this for full bytecode-level analysis of that specific method.

    Args:
        smali_file: path to .smali file (relative to apktool dir or absolute)
        method_name: method name to analyze (e.g. 'checkServerTrusted', 'onCreate').
            For short/ambiguous names in obfuscated code, include the signature
            suffix for precision: e.g. 'a()Z' instead of just 'a'.

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
    return _safe_call(_run, "refine_search", _cache_hint=f"{refine_pattern}:{context_lines}:{hash(previous_results_json)}")


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
    return _safe_call(_run, "smart_search", _cache_hint=f"{query}:{search_type}:{directory}:{max_results}")


# ---------------------------------------------------------------------------
# Code Graph tools (NetworkX-powered)
# ---------------------------------------------------------------------------

# Module-level graph + index holders (loaded once per session)
_code_graph = None
_code_index = None
_smali_index = None  # SmaliIndex IR (from smali_ir module)
_auto_mode = False   # Set by CLI when /auto is active


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

    When to use: Run once after apktool_decompile. Enables all graph_* and index_*
    tools. Re-run only if you decompile a different APK.

    Returns: JSON with keys: success, graph ({nodes, edges, components}),
    index ({classes, methods, strings, packages}).
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

    When to use: Primary tool for reverse call tracing. Use this instead of
    trace_call_chain when the code graph is built.

    Args:
        method_name: Method name to trace (e.g., "checkServerTrusted", "isRooted").
            Partial match supported.
        depth: How many levels up to trace (default 3).

    Returns: JSON with keys: success, method, total_callers, callers
    (nested array of {method, class, file, depth, callers (recursive)}).
    """
    from apk_agent.tools.code_graph import query_callers

    def _run():
        G = _ensure_graph()
        if G is None:
            return json.dumps({"success": False, "error": "No code graph. Run build_graph_and_index first."})
        result = query_callers(G, method_name, depth=depth)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "graph_callers", _cache_hint=f"{method_name}:{depth}")


@tool
def graph_callees(method_name: str, depth: int = 2) -> str:
    """Find all methods CALLED BY the given method — follow the forward call chain.
    Uses the pre-built code graph. Instant results.

    When to use: To understand what a method does by seeing what it calls.
    Complement to graph_callers (reverse direction).

    Args:
        method_name: Method name to trace (e.g., "processPayment", "onCreate").
        depth: How many levels deep to trace (default 2).

    Returns: JSON with keys: success, method, total_callees, callees
    (nested array of {method, class, file, depth, callees (recursive)}).
    """
    from apk_agent.tools.code_graph import query_callees

    def _run():
        G = _ensure_graph()
        if G is None:
            return json.dumps({"success": False, "error": "No code graph. Run build_graph_and_index first."})
        result = query_callees(G, method_name, depth=depth)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "graph_callees", _cache_hint=f"{method_name}:{depth}")


@tool
def graph_class_info(class_name: str) -> str:
    """Get full info about a class from the code graph — methods, inheritance,
    who calls it, fields. Partial match supported.

    When to use: When you need a complete overview of a specific class — its
    methods, inheritance, fields, and who interacts with it.

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
    return _safe_call(_run, "graph_class_info", _cache_hint=class_name)


@tool
def graph_find_path(source_method: str, target_method: str) -> str:
    """Find the shortest call path between two methods.
    Useful for understanding data flow: how does method A reach method B?

    When to use: When you need to understand how data flows from one method
    to another, or trace the execution path between two points.

    Args:
        source_method: Starting method name.
        target_method: Ending method name.

    Returns: JSON with keys: success, source, target, path_found (bool),
    path (array of method names from source to target), path_length (int).
    """
    from apk_agent.tools.code_graph import query_path

    def _run():
        G = _ensure_graph()
        if G is None:
            return json.dumps({"success": False, "error": "No code graph. Run build_graph_and_index first."})
        result = query_path(G, source_method, target_method)
        return json.dumps(result, ensure_ascii=False, indent=2)[:10000]
    return _safe_call(_run, "graph_find_path", _cache_hint=f"{source_method}:{target_method}")


@tool
def graph_security_scan() -> str:
    """Scan the code graph for security-related methods: SSL pinning, root detection,
    crypto, anti-debug, anti-tamper, dynamic loading. Returns categorized results
    with caller counts so you know which methods are most important.

    When to use: After building the code graph, use this for a quick security-focused
    overview. Identifies high-value targets sorted by caller count.

    Returns: JSON with keys: success, total_security_methods, categories
    (dict of category→array of {method, class, file, caller_count, callers}).
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

    When to use: Quick check on graph size and health after building it.
    Hotspots reveal the most-referenced methods worth investigating.

    Returns: JSON with keys: success, total_classes, total_methods, total_edges,
    connected_components, hotspots (array of {method, class, caller_count}).
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

    When to use: When you know a class name (or fragment) and need its full path
    and package. Faster than grep-based search.

    Args:
        query: Class name or partial match (e.g., "Payment", "Crypto", "SSL").

    Returns: JSON with keys: success, query, total_matches, matches
    (array of {class_name, package, file_path, methods (list)}).
    """
    from apk_agent.tools.index_cache import lookup_class

    def _run():
        idx = _ensure_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No code index. Run build_graph_and_index first."})
        result = lookup_class(idx, query)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "index_lookup_class", _cache_hint=query)


@tool
def index_lookup_method(method_name: str) -> str:
    """Find all classes containing a specific method — instant.
    Use this before read_file to know exactly WHERE a method lives.

    When to use: When you know a method name but not which class contains it.
    Results tell you the file path so you can read_file directly.

    Args:
        method_name: Method name (e.g., "checkServerTrusted", "encrypt", "isRooted").

    Returns: JSON with keys: success, method, total_matches, matches
    (array of {class_name, file_path, method_signature}).
    """
    from apk_agent.tools.index_cache import lookup_method

    def _run():
        idx = _ensure_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No code index. Run build_graph_and_index first."})
        result = lookup_method(idx, method_name)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "index_lookup_method", _cache_hint=method_name)


@tool
def index_lookup_string(query: str) -> str:
    """Unified index search — finds string constants, method references, AND class names.
    Automatically detects query type: smali references (Lm0$e;->g), method names,
    class names, string constants (API keys, URLs, error messages).
    Instant results from pre-built index.

    When to use: First choice for ANY index lookup. Handles all query types —
    no need to pick between class/method/string lookup. Use this when you want
    to find where something is referenced, what class contains a method, or
    which classes use a specific string.

    Args:
        query: Any search term — smali ref (e.g. "Lm0$e;->e"), method name
               (e.g. "checkLicense"), class (e.g. "m0$e"), or string constant
               (e.g. "api_key", "https://").

    Returns:
        JSON with string_results (const-string matches), method_results
        (method reference matches), class_results (class name matches).
        If nothing found, includes a hint for alternative search tools.
    """
    from apk_agent.tools.index_cache import lookup_string

    def _run():
        idx = _ensure_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No code index. Run build_graph_and_index first."})
        result = lookup_string(idx, query)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "index_lookup_string", _cache_hint=query)


@tool
def index_lookup_package(package_name: str) -> str:
    """List all classes in a Java package — instant.

    When to use: When you want to enumerate all classes in a specific package
    to understand its structure or find relevant targets.

    Args:
        package_name: Package name (e.g., "com.example.crypto", "payment").

    Returns: JSON with keys: success, package, total_classes, classes
    (array of {class_name, file_path, method_count}).
    """
    from apk_agent.tools.index_cache import lookup_package

    def _run():
        idx = _ensure_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No code index. Run build_graph_and_index first."})
        result = lookup_package(idx, package_name)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]
    return _safe_call(_run, "index_lookup_package", _cache_hint=package_name)


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

    When to use: Primary patching tool for bulk automated bypasses. Use this
    instead of manual apply_smali_patch when standard bypass patterns apply.
    Run list_bypass_categories first to see available categories.

    Args:
        categories: Comma-separated bypass categories to apply. If omitted, ALL are applied.
            Options: ssl_bypass, vpn_bypass, mock_location, license_bypass, pairip_bypass,
                     purchase_bypass, screenshot_bypass, usb_debug_bypass, device_spoof,
                     package_spoof, ads_removal
            Example: "ssl_bypass,vpn_bypass,license_bypass"
        custom_device_id: Custom Android device ID for spoofing (16 hex chars).
            Only used when device_spoof category is included.

    Returns: JSON with keys: success, total_files_scanned, total_patches_applied,
    categories_applied (list), per_category_stats (dict of category→{files_patched, patches}),
    patched_files (list of modified file paths), errors (list).
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
        report_progress(2, "Starting auto-patch…")
        stats = run_smali_patches(
            smali_dirs=smali_dirs,
            categories=cats,
            backup_dir=_project.patch_backup_dir,
            custom_device_id=custom_device_id,
        )
        d = stats.to_dict()
        # Record to patch journal
        _patch_journal.append({
            "success": d.get("success", False) and d.get("total_patches_applied", 0) > 0,
            "target_file": f"{len(d.get('patched_files') or [])} files",
            "description": f"Auto-bypass: {', '.join(str(c) for c in (d.get('categories_applied') or [])[:6])} — {d.get('total_patches_applied', 0)} patches",
            "steps_applied": d.get("total_patches_applied", 0),
            "steps_total": d.get("total_patches_applied", 0),
            "errors": d.get("errors", []),
            "tool": "auto_patch_bypass",
        })
        return json.dumps(d, ensure_ascii=False, indent=2)[:4000]
    return _safe_call(_run, "auto_patch_bypass")


@tool
def patch_flutter_ssl() -> str:
    """Patch Flutter's libflutter.so to disable SSL certificate verification.
    Uses pure Python binary hex matching — finds ssl_verify_peer_cert and
    patches it to return 0 (always succeed). No external tools needed.

    Supports arm64-v8a, armeabi-v7a, and x86_64 architectures.
    Only needed for Flutter apps — check lib/ for libflutter.so first.

    When to use: Only for Flutter apps. Check for lib/*/libflutter.so in the
    decompiled APK. For non-Flutter apps, use auto_patch_bypass with ssl_bypass.

    Returns: JSON with keys: success, architectures_patched (list), patches_applied (int),
    details (array of {arch, offset, status}).
    """
    from apk_agent.tools.apk_patcher import patch_flutter_ssl as _patch

    def _run():
        result = _patch(
            apktool_dir=_project.apktool_dir,
            backup_dir=_project.patch_backup_dir,
        )
        # Record to patch journal
        _patch_journal.append({
            "success": result.get("success", False),
            "target_file": "libflutter.so",
            "description": f"Flutter SSL pin bypass — {result.get('patches_applied', 0)} arch(s) patched",
            "steps_applied": result.get("patches_applied", 0),
            "steps_total": result.get("patches_applied", 0),
            "errors": result.get("errors", []),
            "tool": "patch_flutter_ssl",
        })
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

    When to use: Run BEFORE patch_manifest_security to enable traffic interception.
    Required for Burp/mitmproxy to intercept HTTPS traffic on Android 7+.

    Args:
        cert_paths: Optional comma-separated paths to custom CA certificate files (.pem/.crt).
            Example: "/path/to/burp_ca.pem,/path/to/mitmproxy.pem"

    Returns: JSON with keys: success, config_path (path to created XML),
    certs_copied (list of cert files added to res/raw/), changes_made (list).
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
        # Record to patch journal
        changes = result.get("changes_made") or []
        _patch_journal.append({
            "success": result.get("success", False),
            "target_file": "res/xml/network_security_config.xml",
            "description": f"Injected permissive network security config ({len(changes)} changes)",
            "steps_applied": len(changes),
            "steps_total": len(changes),
            "errors": [],
            "tool": "inject_network_security_config",
        })
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

    When to use: Run AFTER inject_network_security_config. Completes the manifest
    preparation for traffic interception and removes Play Store protections.

    Returns: JSON with keys: success, changes_made (list of modifications applied),
    warnings (list), manifest_path.
    """
    from apk_agent.tools.apk_patcher import patch_manifest

    def _run():
        result = patch_manifest(apktool_dir=_project.apktool_dir)
        # Record to patch journal
        changes = result.get("changes_made") or []
        _patch_journal.append({
            "success": result.get("success", False),
            "target_file": "AndroidManifest.xml",
            "description": f"Manifest security patches ({len(changes)} changes)",
            "steps_applied": len(changes),
            "steps_total": len(changes),
            "errors": result.get("warnings", []),
            "tool": "patch_manifest_security",
        })
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

    When to use: When the user wants ads removed. This is a specialized subset of
    auto_patch_bypass focused on ADS_REMOVAL + LICENSE_BYPASS categories.

    Returns: JSON with keys: success, total_files_scanned, total_patches_applied,
    categories_applied, per_category_stats, patched_files (list), errors (list).
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
        d = stats.to_dict()
        # Record to patch journal
        _patch_journal.append({
            "success": d.get("success", False) and d.get("total_patches_applied", 0) > 0,
            "target_file": f"{len(d.get('patched_files') or [])} files",
            "description": f"Ads removal + license bypass — {d.get('total_patches_applied', 0)} patches",
            "steps_applied": d.get("total_patches_applied", 0),
            "steps_total": d.get("total_patches_applied", 0),
            "errors": d.get("errors", []),
            "tool": "remove_ads",
        })
        return json.dumps(d, ensure_ascii=False, indent=2)[:20000]
    return _safe_call(_run, "remove_ads")


@tool
def list_bypass_categories() -> str:
    """List all available automated bypass categories with pattern counts.
    Shows what auto_patch_bypass can do and how many patterns exist per category.

    When to use: Before calling auto_patch_bypass, to see available categories
    and pattern counts so you can choose which to apply.

    Returns: JSON with keys: categories (array of {name, description, pattern_count}).
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

    When to use: Run once after apktool_decompile. Required for unified_scan,
    analyze_data_flow, run_taint_analysis, find_hardcoded_crypto, and generate_bypass_plans.

    Returns: JSON with keys: success, total_classes, total_methods,
    total_instructions, total_strings, total_api_targets,
    method_categories (dict of category→count), built_at (timestamp).
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

    When to use: Quick check after build_smali_index to verify it completed
    and see what’s indexed. Also useful to confirm index availability before
    running unified_scan or taint analysis.

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

    When to use: Primary vulnerability scanner. Prefer over scan_vulnerabilities
    and detect_protections (which are legacy). Requires build_smali_index first.

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
    return _safe_call(_run, "unified_scan", _cache_hint=f"{severity_filter}:{max_findings}")


@tool
def analyze_data_flow(class_name: str, method_name: str) -> str:
    """Analyze register-level data flow within a specific method.
    Tracks const-string values, object types, field accesses, and method return values
    through registers. Shows what each register holds at every instruction.

    When to use: When you need to understand exactly what values flow through
    a crypto, auth, or security method. Use after finding a suspicious method
    via unified_scan or graph tools.

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

    When to use: For finding data leaks and privacy violations. Run after
    build_smali_index. Best for identifying source→sink flows (e.g., device ID
    being sent to a server, credentials logged to logcat).

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
    return _safe_call(_run, "run_taint_analysis", _cache_hint=f"{max_depth}:{max_flows}")


@tool
def find_hardcoded_crypto() -> str:
    """Scan all crypto-related methods for hardcoded keys, IVs, and secrets.
    Uses register-level data flow to detect const-string values passed to
    SecretKeySpec, Cipher.init, IvParameterSpec, MessageDigest, etc.

    When to use: When investigating cryptographic implementations. Specifically
    finds hardcoded keys/IVs that are security vulnerabilities.

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

    When to use: After unified_scan identifies protections, use this to get
    ready-to-apply smali patches and Frida scripts. Fully automated — just
    apply the generated patches via apply_smali_patch.

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

    When to use: For thorough manifest security analysis. Prefer over parse_manifest
    which only extracts data without security analysis. Optionally uses SmaliIndex
    for cross-referencing if available.

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

    When to use: For finding leaked API keys and cloud credentials. Uses SmaliIndex
    if available for deeper analysis; falls back to file-based scanning otherwise.

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
    # Feature-check mapping
    map_feature_checks,
    analyze_subscription_model,
    # Deep tracing + Code injection
    trace_field_access,
    find_class_instantiations,
    inject_smali_code,
    generate_constructor_override,
    inject_startup_hook,
    # Bulk patching + Data-flow tracing + UI gate mapping
    batch_patch_methods,
    trace_data_pipeline,
    map_ui_gates,
    patch_shared_prefs_reads,
    identify_server_checks,
    # Cross-reference + Deobfuscation + Dynamic checks + URL extraction + Verification
    cross_reference_map,
    deobfuscate_names,
    find_dynamic_checks,
    extract_all_urls,
    verify_bypass_completeness,
    # Patching
    apply_smali_patch,
    preview_smali_patch,
    restore_smali_backup,
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
