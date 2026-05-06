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
from contextvars import copy_context
from pathlib import Path
from typing import Any, Optional

from langchain_core.tools import tool

from apk_agent.agent.execution_context import (
    CONFIG_PROXY,
    PATCH_JOURNAL_PROXY,
    PROJECT_PROXY,
    SCRATCHPAD_PROXY,
    TASK_PLAN_PROXY,
    TOOL_CACHE_PROXY,
    clear_runtime_slots,
    get_active_execution_context,
    get_runtime_slot,
    set_active_execution_context,
    set_runtime_slot,
)
from apk_agent.progress import progress_manager, set_current_task

# We use a module-level config holder that gets set at graph construction time.
_config = CONFIG_PROXY
_project = PROJECT_PROXY

# ---------------------------------------------------------------------------
# Tool result cache — avoids re-running expensive scans with same args
# ---------------------------------------------------------------------------
_tool_cache = TOOL_CACHE_PROXY
_CACHEABLE_TOOLS = frozenset({
    "scan_vulnerabilities", "extract_strings", "search_in_code",
    "context_search", "multi_search", "xref_search",
    "scan_smali_classes", "list_vuln_patterns", "detect_protections",
    "aapt2_dump", "parse_manifest", "directory_overview",
    "find_string_decryption_patterns",
    "search_interceptors", "search_native_code", "search_dynamic_loaders",
    "analyze_native_re_core", "plan_native_patch_targets", "route_reverse_engineering_workflow",
    "refine_search", "smart_search",
    "graph_callers", "graph_callees", "graph_class_info",
    "graph_find_path", "graph_security_scan", "graph_stats",
    "index_lookup_class", "index_lookup_method",
    "index_lookup_string", "index_lookup_package",
    "unified_scan", "run_taint_analysis", "find_hardcoded_crypto",
    "analyze_manifest_deep", "scan_cloud_secrets", "smali_index_stats",
    "map_semantic_architecture", "recover_hidden_state_model",
    "profile_guard_and_revalidation_surface",
    "summarize_app_knowledge",
    "summarize_behavior_graph",
    "query_behavior_graph",
    "locate_feature_controls",
    "recover_state_transitions",
    "map_security_surfaces",
    "plan_runtime_hooks",
    "analyze_network_behavior",
    "recover_semantic_symbols",
})


def set_tool_context(config, project) -> None:
    """Set the config and project for tool execution. Called once per session."""
    set_active_execution_context(config, project)
    _tool_cache.clear()  # fresh cache per session
    clear_runtime_slots(
        "code_graph",
        "code_index",
        "smali_index",
        "app_knowledge_pack",
        "behavior_graph_pack",
        "semantic_architecture_cache",
        "hidden_state_model_cache",
        "guard_surface_profile_cache",
        "architecture_context_cache",
    )
    _scratchpad.clear()
    _task_plan.clear()
    _patch_journal.clear()


def invalidate_graph_caches() -> None:
    """Clear graph/index-derived runtime caches.

    Kept as a compatibility helper for older graph/orchestrator code paths that
    still import this symbol directly from tools_def.
    """
    _tool_cache.clear()
    clear_runtime_slots(
        "code_graph",
        "code_index",
        "smali_index",
        "app_knowledge_pack",
        "behavior_graph_pack",
        "semantic_architecture_cache",
        "hidden_state_model_cache",
        "guard_surface_profile_cache",
        "architecture_context_cache",
    )


# ---------------------------------------------------------------------------
# Module-level scratchpad and task plan (read by graph.py for state sync)
# ---------------------------------------------------------------------------
_scratchpad = SCRATCHPAD_PROXY
_task_plan = TASK_PLAN_PROXY

# ---------------------------------------------------------------------------
# Patch journal — authoritative record of all patch operations this session.
# Used by generate_report to produce accurate patch data instead of relying
# on the LLM to reconstruct patch_results_json from memory.
# ---------------------------------------------------------------------------
_patch_journal = PATCH_JOURNAL_PROXY


def _get_scratchpad() -> dict:
    """Return the current scratchpad dict."""
    return dict(get_active_execution_context().scratchpad)


def _get_task_plan() -> list[dict]:
    """Return the current task plan list."""
    return list(get_active_execution_context().task_plan)


_TASK_PLAN_STATUS_ALIASES = {
    "pending": "pending",
    "todo": "pending",
    "not-started": "pending",
    "not_started": "pending",
    "planned": "pending",
    "open": "pending",
    "in_progress": "in_progress",
    "in-progress": "in_progress",
    "progress": "in_progress",
    "doing": "in_progress",
    "active": "in_progress",
    "started": "in_progress",
    "working": "in_progress",
    "done": "done",
    "completed": "done",
    "complete": "done",
    "finished": "done",
    "closed": "done",
}


def _normalize_task_plan_status(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return "pending"
    return _TASK_PLAN_STATUS_ALIASES.get(normalized, "pending")


def _normalize_task_plan_items(raw_items: list[Any], *, existing: list[dict] | None = None) -> list[dict]:
    used_ids: set[int] = set()
    for item in list(existing or []):
        if not isinstance(item, dict):
            continue
        existing_id = item.get("id")
        if isinstance(existing_id, int) and existing_id > 0:
            used_ids.add(existing_id)
        elif isinstance(existing_id, str) and existing_id.isdigit() and int(existing_id) > 0:
            used_ids.add(int(existing_id))
    next_id = max(used_ids, default=0) + 1
    normalized_items: list[dict] = []

    for raw in raw_items:
        if isinstance(raw, dict):
            text = str(
                raw.get("desc")
                or raw.get("label")
                or raw.get("task")
                or raw.get("title")
                or ""
            ).strip()
            raw_id = raw.get("id")
            status = _normalize_task_plan_status(str(raw.get("status", "pending")))
        else:
            text = str(raw or "").strip()
            raw_id = None
            status = "pending"

        if not text:
            continue

        task_id: int | None = None
        if isinstance(raw_id, int) and raw_id > 0 and raw_id not in used_ids:
            task_id = raw_id
        elif isinstance(raw_id, str) and raw_id.isdigit() and int(raw_id) > 0 and int(raw_id) not in used_ids:
            task_id = int(raw_id)

        if task_id is None:
            while next_id in used_ids:
                next_id += 1
            task_id = next_id

        used_ids.add(task_id)
        next_id = max(next_id, task_id + 1)
        normalized_items.append({
            "id": task_id,
            "desc": text,
            "label": text,
            "task": text,
            "status": status,
        })

    return normalized_items


def _task_plan_summary(plan: list[dict]) -> dict[str, int]:
    return {
        "total": len(plan),
        "pending": sum(1 for item in plan if item.get("status") == "pending"),
        "in_progress": sum(1 for item in plan if item.get("status") == "in_progress"),
        "done": sum(1 for item in plan if item.get("status") == "done"),
    }


def _find_task_plan_index(plan: list[dict], *, task_id: int = 0, task_text: str = "") -> int:
    if task_id > 0:
        for idx, item in enumerate(plan):
            if int(item.get("id", 0) or 0) == task_id:
                return idx
    needle = str(task_text or "").strip().lower()
    if needle:
        for idx, item in enumerate(plan):
            haystack = " ".join(
                str(item.get(field, ""))
                for field in ("desc", "label", "task")
            ).lower()
            if needle in haystack:
                return idx
    return -1


@tool
def update_scratchpad(key: str, value: str = "", mode: str = "set") -> str:
    """Persist free-form working notes, hypotheses, and runtime discoveries.

    Use this when you want to save your own hypothesis, a suspicious class,
    a recovered field, a patch decision, or any other free-form note that
    should survive context compaction.

    Args:
        key: Scratchpad entry name, e.g. "planner_context" or "state_model"
        value: Any free-form text to store.
        mode: "set", "append", or "delete"

    Returns: JSON with the updated entry and a compact scratchpad summary.
    """
    key = key.strip()
    mode = mode.strip().lower()

    def _run():
        if not key:
            return json.dumps({"success": False, "error": "key must not be empty"})

        scratchpad = get_active_execution_context().scratchpad

        if mode == "set":
            scratchpad[key] = value
        elif mode == "append":
            existing = str(scratchpad.get(key, "")).strip()
            addition = value.strip()
            scratchpad[key] = f"{existing}\n{addition}".strip() if existing and addition else (addition or existing)
        elif mode == "delete":
            scratchpad.pop(key, None)
        else:
            return json.dumps({
                "success": False,
                "error": f"Unsupported mode: {mode}",
                "supported_modes": ["set", "append", "delete"],
            }, ensure_ascii=False, indent=2)

        current_value = scratchpad.get(key)
        scratchpad_preview = dict(list(scratchpad.items())[:20])
        return json.dumps({
            "success": True,
            "mode": mode,
            "key": key,
            "value": current_value,
            "scratchpad_size": len(scratchpad),
            "scratchpad_preview": scratchpad_preview,
        }, ensure_ascii=False, indent=2)[:12000]

    return _safe_call(_run, "update_scratchpad")


@tool
def update_task_plan(plan_json: str, mode: str = "replace") -> str:
    """Create or update the durable multi-step task plan.

    Args:
        plan_json: JSON array of task items, or an object containing
            `task_plan`, `items`, or `tasks`.
        mode: `replace`, `append`, or `clear`.

    Returns: JSON with the normalized plan and status counts.
    """
    mode = str(mode or "replace").strip().lower()

    def _run():
        task_plan = get_active_execution_context().task_plan

        if mode == "clear":
            task_plan.clear()
            return json.dumps({
                "success": True,
                "mode": mode,
                "task_plan": [],
                "summary": _task_plan_summary(task_plan),
            }, ensure_ascii=False, indent=2)

        try:
            payload = json.loads(plan_json)
        except json.JSONDecodeError as exc:
            return json.dumps({"success": False, "error": f"Invalid JSON: {exc}"}, ensure_ascii=False, indent=2)

        if isinstance(payload, list):
            raw_items = payload
        elif isinstance(payload, dict):
            raw_items = payload.get("task_plan") or payload.get("items") or payload.get("tasks") or []
        else:
            raw_items = []

        if mode not in {"replace", "append"}:
            return json.dumps({
                "success": False,
                "error": f"Unsupported mode: {mode}",
                "supported_modes": ["replace", "append", "clear"],
            }, ensure_ascii=False, indent=2)

        normalized = _normalize_task_plan_items(raw_items, existing=task_plan if mode == "append" else None)
        if not normalized and raw_items:
            return json.dumps({
                "success": False,
                "error": "No valid task items were found in plan_json.",
            }, ensure_ascii=False, indent=2)

        if mode == "replace":
            task_plan.clear()
        task_plan.extend(normalized)

        return json.dumps({
            "success": True,
            "mode": mode,
            "task_plan": list(task_plan),
            "summary": _task_plan_summary(task_plan),
        }, ensure_ascii=False, indent=2)[:16000]

    return _safe_call(_run, "update_task_plan")


@tool
def edit_task_plan(task_id: int = 0, task_text: str = "", new_text: str = "", new_status: str = "", delete: bool = False) -> str:
    """Edit or delete one task-plan item by id or matching text."""

    def _run():
        task_plan = get_active_execution_context().task_plan
        index = _find_task_plan_index(task_plan, task_id=task_id, task_text=task_text)
        if index < 0:
            return json.dumps({
                "success": False,
                "error": "Task-plan item not found.",
                "task_id": task_id,
                "task_text": task_text,
            }, ensure_ascii=False, indent=2)

        item = dict(task_plan[index])
        if delete:
            removed = task_plan.pop(index)
            return json.dumps({
                "success": True,
                "mode": "delete",
                "removed": removed,
                "task_plan": list(task_plan),
                "summary": _task_plan_summary(task_plan),
            }, ensure_ascii=False, indent=2)[:16000]

        if str(new_text or "").strip():
            text = str(new_text).strip()
            item["desc"] = text
            item["label"] = text
            item["task"] = text
        if str(new_status or "").strip():
            item["status"] = _normalize_task_plan_status(new_status)

        task_plan[index] = item
        return json.dumps({
            "success": True,
            "mode": "edit",
            "updated": item,
            "task_plan": list(task_plan),
            "summary": _task_plan_summary(task_plan),
        }, ensure_ascii=False, indent=2)[:16000]

    return _safe_call(_run, "edit_task_plan")


@tool
def mark_task_done(task_id: int = 0, task_text: str = "") -> str:
    """Mark one task-plan item as done by id or matching text."""

    def _run():
        task_plan = get_active_execution_context().task_plan
        index = _find_task_plan_index(task_plan, task_id=task_id, task_text=task_text)
        if index < 0:
            return json.dumps({
                "success": False,
                "error": "Task-plan item not found.",
                "task_id": task_id,
                "task_text": task_text,
            }, ensure_ascii=False, indent=2)

        item = dict(task_plan[index])
        item["status"] = "done"
        task_plan[index] = item
        return json.dumps({
            "success": True,
            "updated": item,
            "task_plan": list(task_plan),
            "summary": _task_plan_summary(task_plan),
        }, ensure_ascii=False, indent=2)[:16000]

    return _safe_call(_run, "mark_task_done")


def _log_file() -> Path:
    if _project:
        return Path(_project.workspace_path) / "logs" / "tools.log"
    return Path("tools.log")


def _project_workspace_root() -> Path | None:
    if not _project:
        return None
    workspace_path = getattr(_project, "workspace_path", "")
    if not workspace_path:
        return None
    return Path(workspace_path)


def _project_outputs_dir() -> Path:
    if not _project:
        raise RuntimeError("Project context not set.")
    outputs_dir = getattr(_project, "outputs_dir", None)
    if outputs_dir:
        path = Path(outputs_dir)
        path.mkdir(parents=True, exist_ok=True)
        return path
    workspace_root = _project_workspace_root()
    if workspace_root is None:
        raise AttributeError("outputs_dir")
    path = workspace_root / "outputs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _project_jadx_dir() -> Path | None:
    if not _project:
        return None
    jadx_dir = getattr(_project, "jadx_dir", None)
    if jadx_dir:
        return Path(jadx_dir)
    workspace_root = _project_workspace_root()
    if workspace_root is None:
        return None
    return workspace_root / "decompiled" / "jadx_src"


# ---------------------------------------------------------------------------
# Large tool output handling — preserve full data without flooding the model
# ---------------------------------------------------------------------------
_TOOL_OUTPUT_SPILL_THRESHOLD = 16_000
_TOOL_OUTPUT_TEXT_PREVIEW = 3_800
_TOOL_OUTPUT_TEXT_TAIL_PREVIEW = 2_200


def _tool_payload_dir() -> Path:
    if _project:
        payload_dir = _project_outputs_dir() / "tool_payloads"
    else:
        payload_dir = Path("tool_payloads")
    payload_dir.mkdir(parents=True, exist_ok=True)
    return payload_dir


def _json_scalar_preview(data: dict) -> dict:
    preview: dict = {}
    for key, value in data.items():
        if isinstance(value, str):
            preview[key] = value[:160]
        elif isinstance(value, (int, float, bool)) or value is None:
            preview[key] = value
    return preview


def _preview_json_item(value):
    if isinstance(value, dict):
        preview = _json_scalar_preview(value)
        nested_sizes = {
            key: len(item)
            for key, item in value.items()
            if isinstance(item, (list, dict))
        }
        if nested_sizes:
            preview["collection_sizes"] = nested_sizes
        return preview or {"type": "dict", "keys": list(value.keys())[:12]}
    if isinstance(value, list):
        return {"type": "list", "items": len(value)}
    if isinstance(value, str):
        return value[:160]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return {"type": type(value).__name__}


def _important_json_preview(data) -> dict:
    if isinstance(data, dict):
        preview: dict = {}
        priority_keys = (
            "findings", "vulnerabilities", "matches", "results", "methods",
            "classes", "entity_classes", "candidate_state_fields", "surfaces",
            "controls", "transitions", "runtime_hooks", "paths", "changes_made",
            "patched_files", "gate_methods", "boolean_getters", "int_getters",
            "billing_purchase_system", "behavioral_checks", "ir_behavioral_gates",
            "summary", "instruction", "target_file", "target_class", "helper_file",
            "app_packages", "target_packages", "excluded_packages",
        )
        for key in priority_keys:
            if key not in data:
                continue
            value = data[key]
            if isinstance(value, list):
                preview[key] = [_preview_json_item(item) for item in value[:4]]
                if len(value) > 4:
                    preview[f"{key}_omitted"] = len(value) - 4
            elif isinstance(value, dict):
                preview[key] = _json_scalar_preview(value)
                if not preview[key]:
                    preview[key] = {"keys": list(value.keys())[:12]}
            else:
                preview[key] = _preview_json_item(value)

        if preview:
            return preview

        for key, value in list(data.items())[:4]:
            preview[key] = _preview_json_item(value)
        return preview

    if isinstance(data, list):
        return {
            "items_preview": [_preview_json_item(item) for item in data[:4]],
            "items_omitted": max(0, len(data) - 4),
        }

    return {}


def _summarize_spilled_json(data) -> dict:
    if isinstance(data, dict):
        collection_sizes = {}
        for key, value in data.items():
            if isinstance(value, (list, dict)):
                collection_sizes[key] = len(value)
        summary = {
            "type": "dict",
            "top_level_keys": list(data.keys())[:80],
        }
        scalar_preview = _json_scalar_preview(data)
        if scalar_preview:
            summary["scalar_preview"] = scalar_preview
        if collection_sizes:
            summary["collection_sizes"] = collection_sizes
        return summary

    if isinstance(data, list):
        summary = {
            "type": "list",
            "items": len(data),
        }
        if data:
            first = data[0]
            if isinstance(first, dict):
                summary["first_item_keys"] = list(first.keys())[:40]
            else:
                summary["first_item_type"] = type(first).__name__
        return summary

    return {"type": type(data).__name__}


def _materialize_tool_output(tool_name: str, result: str) -> str:
    """Preserve oversized tool results losslessly and return a compact reference.

    Instead of blindly truncating head/tail, store the exact full payload on
    disk and return a small envelope with a summary and a file path that the
    agent can inspect later via read_file().
    """
    if not isinstance(result, str) or len(result) <= _TOOL_OUTPUT_SPILL_THRESHOLD:
        return result

    try:
        suffix = ".json" if result.lstrip().startswith(("{", "[")) else ".txt"
        output_path = _tool_payload_dir() / f"{tool_name}_{uuid.uuid4().hex[:10]}{suffix}"
        output_path.write_text(result, encoding="utf-8")
    except OSError:
        return result

    envelope = {
        "tool_output_spilled": True,
        "tool_name": tool_name,
        "output_file": str(output_path.resolve()),
        "output_chars": len(result),
        "output_lines": result.count("\n") + 1,
        "recovery_hint": (
            "Full output preserved on disk. The preview is only a teaser. "
            "Use read_file(output_file, start_line, end_line) to inspect any slice, "
            "or search_in_code(pattern, directory=\"outputs/tool_payloads\", file_extensions=\".json,.txt\") "
            "(or the parent directory of output_file) to search the full spilled payload."
        ),
    }

    try:
        data = json.loads(result)
        envelope["content_format"] = "json"
        envelope["summary"] = _summarize_spilled_json(data)
        important_preview = _important_json_preview(data)
        if important_preview:
            envelope["important_preview"] = important_preview
        if isinstance(data, dict) and "success" in data:
            envelope["success"] = bool(data.get("success"))
    except json.JSONDecodeError:
        envelope["content_format"] = "text"
        envelope["preview"] = result[:_TOOL_OUTPUT_TEXT_PREVIEW]
        if len(result) > (_TOOL_OUTPUT_TEXT_PREVIEW + _TOOL_OUTPUT_TEXT_TAIL_PREVIEW):
            envelope["preview_tail"] = result[-_TOOL_OUTPUT_TEXT_TAIL_PREVIEW:]

    return json.dumps(envelope, ensure_ascii=False, indent=2)


_DEFAULT_TOOL_TIMEOUT = 3000
_TOOL_TIMEOUT_OVERRIDES: dict[str, int | None] = {
    # Heavy full-project precomputation can legitimately take a very long time.
    "apktool_decompile": 3600,
    "apktool_build": 3600,
    "build_graph_and_index": 5400,
    "build_smali_index": 7200,
    "unified_scan": 1800,
    "analyze_data_flow": 1800,
    "run_taint_analysis": 1800,
    # These whole-project verification passes can legitimately run for a long time.
    # `None` disables the timeout completely.
    "find_dynamic_checks": None,
    "verify_bypass_completeness": None,
}


def _tool_timeout_seconds(tool_name: str) -> int | None:
    return _TOOL_TIMEOUT_OVERRIDES.get(tool_name, _DEFAULT_TOOL_TIMEOUT)


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

    timeout_seconds = _tool_timeout_seconds(tool_name)

    try:
        # Run tool with a timeout to prevent the caller from blocking forever.
        # A daemon worker lets the turn continue even if the tool ignores the timeout.
        run_context = copy_context()
        result_holder: dict[str, str] = {}
        worker_exception: BaseException | None = None
        finished = threading.Event()

        def _run_in_worker():
            # report_progress() uses thread-local task binding, so the worker
            # thread must register the current tool task before executing.
            nonlocal worker_exception
            try:
                set_current_task(task_id)
                result_holder["result"] = func(*args, **kwargs)
            except BaseException as exc:  # propagate the original failure on the caller thread
                worker_exception = exc
            finally:
                finished.set()

        worker = threading.Thread(
            target=run_context.run,
            args=(_run_in_worker,),
            name=f"apk-agent-tool-{tool_name}",
            daemon=True,
        )
        worker.start()

        if not finished.wait(timeout_seconds):
            progress_manager.complete_task(task_id, success=False, error="Tool execution timed out")
            return json.dumps({
                "success": False,
                "error": f"Tool '{tool_name}' timed out after {timeout_seconds}s.",
                "recovery_hint": "The tool took too long. Try a more targeted approach or smaller scope.",
            })

        if worker_exception is not None:
            raise worker_exception

        result = result_holder.get("result", "")
        # Preserve full oversized results on disk and give the LLM a compact reference.
        result = _materialize_tool_output(tool_name, result)
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

    remapped_smali_dir = _resolve_across_smali_roots(d)
    if remapped_smali_dir is not None and remapped_smali_dir.is_dir():
        return remapped_smali_dir

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
        return _rebase_stale_absolute_path(p)

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


def _resolve_across_smali_roots(path_value: str | Path) -> Path | None:
    """Try the same relative tail under every discovered smali root.

    This lets callers pass an incorrect root like ``smali_classes2/...`` and
    still resolve the real file or directory when it actually lives under a
    different dex split such as ``smali`` or ``smali_classes3``.
    """
    rel_path = Path(str(path_value).replace("\\", "/").lstrip("/"))
    parts = list(rel_path.parts)
    if not parts:
        return None

    first = parts[0].lower()
    if first != "smali" and not first.startswith("smali_classes"):
        return None

    inner = Path(*parts[1:]) if len(parts) > 1 else Path()
    for smali_dir in _get_all_smali_dirs():
        candidate = smali_dir / inner
        if candidate.exists():
            return candidate
    return None


def _rebase_stale_absolute_path(path: Path) -> Path:
    """Rebase an absolute path from an old workspace/session onto the current project.

    Some tool calls may carry absolute paths from a previous workspace instance
    (for example an old `.../decompiled/apktool/...` tree). If that exact path no
    longer exists, try to preserve the relative tail and remap it into the
    current project's apktool/jadx/decompiled roots.
    """
    if not path.is_absolute() or path.exists() or _project is None:
        return path

    normalized = str(path).replace("\\", "/")
    lowered = normalized.lower()
    workspace_root = Path(_project.workspace_path)
    candidate_bases = (
        ("decompiled/apktool/", _project.apktool_dir),
        ("decompiled/jadx_src/sources/", _project.jadx_dir / "sources"),
        ("decompiled/jadx_src/", _project.jadx_dir),
        ("decompiled/", workspace_root / "decompiled"),
        ("apktool/", _project.apktool_dir),
        ("jadx_src/sources/", _project.jadx_dir / "sources"),
        ("jadx_src/", _project.jadx_dir),
    )

    for marker, base in candidate_bases:
        idx = lowered.find(marker)
        if idx < 0:
            continue
        rel = normalized[idx + len(marker):].lstrip("/")
        candidate = base / Path(rel)
        if candidate.exists():
            return candidate
        if base == _project.apktool_dir:
            remapped = _resolve_across_smali_roots(rel)
            if remapped is not None:
                return remapped

    return path


def _resolve_project_path(path_value: str) -> Path:
    """Resolve file or directory paths, including stale absolute paths."""
    p = Path(path_value)
    if p.is_absolute():
        return _rebase_stale_absolute_path(p)

    resolved = _resolve_file(path_value)
    if resolved.exists():
        return resolved

    dir_resolved = _resolve_dir(path_value, default="apktool")
    if dir_resolved.exists():
        return dir_resolved

    return Path(_project.workspace_path) / path_value


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
        return _rebase_stale_absolute_path(p)

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

    remapped_smali_file = _resolve_across_smali_roots(fpath)
    if remapped_smali_file is not None and remapped_smali_file.is_file():
        return remapped_smali_file

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

    def _run() -> str:
        result = decompile(
            apktool_bin=_config.get_tool_path("apktool") or "apktool",
            apk_path=_project.apk_path,
            output_dir=_project.apktool_dir,
            log_file=_log_file(),
        )
        return result.to_llm_str()

    return _safe_call(_run, "apktool_decompile")


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

    def _run() -> str:
        result = decompile(
            jadx_bin=_config.get_tool_path("jadx") or "jadx",
            apk_path=_project.apk_path,
            output_dir=_project.jadx_dir,
            log_file=_log_file(),
        )
        return result.to_llm_str()

    return _safe_call(_run, "jadx_decompile")


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

    SYNTAX:
    - Call exactly: `apktool_build()`
    - This tool takes NO arguments.
    - Do NOT invent `/force build`, `apktool_build(force=true)`,
      `apktool_build(rebuild=true)`, or `apktool_build(clean=true)`.

    FORCE-REBUILD BEHAVIOR:
    - Every call already performs a forced rebuild.
    - It deletes apktool's `build/` cache before compiling.
    - It calls apktool with `--force-all` internally.
    - To retry a failed build, fix the reported problem and call `apktool_build()` again.

    When to use: After ALL patches are applied and you are ready to produce
    the modified APK. Follow with zipalign_apk_tool then sign_apk.

    Returns: Text summary with success/failure status and path to the rebuilt
    unsigned APK (outputs/patched-unsigned.apk).
    """
    import shutil as _shutil
    from apk_agent.tools.apktool import build
    from apk_agent.tools.base import ToolResult
    from apk_agent.tools.validation_pipeline import run_patch_validation_pipeline

    validation_result = run_patch_validation_pipeline(
        project_root=Path(_project.workspace_path),
        apktool_dir=_project.apktool_dir,
        backup_dir=_project.patch_backup_dir,
        patch_journal=list(_patch_journal),
    )
    syntax = validation_result.get("syntax", {}) if isinstance(validation_result, dict) else {}
    invalid_smali_count = int(syntax.get("invalid_smali_count", 0) or 0)

    if invalid_smali_count > 0:
        failure = ToolResult(
            success=False,
            exit_code=-4,
            stdout="",
            stderr="Pre-build syntax validation failed. Refusing to rebuild until patched smali is valid.",
            command="apktool_build()",
            artifacts={
                "invalid_smali_count": invalid_smali_count,
            },
        )
        return (
            failure.to_llm_str()
            + "\n\n--- pre-build validation ---\n"
            + json.dumps(validation_result, ensure_ascii=False, indent=2)[:12000]
        )

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
    build_output += (
        "\n\n--- pre-build validation ---\n"
        f"mode={validation_result.get('prebuild_mode', 'syntax_only')}  "
        f"invalid_smali={invalid_smali_count}  "
        f"patched_files={validation_result.get('patched_files_count', 0)}"
    )

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
    """Sign the rebuilt APK and, for XAPK projects, rebuild the final XAPK bundle.
    Run this after apktool_build (and optionally zipalign_apk_tool) succeeds.

    When to use: LAST step in the build pipeline (after apktool_build → zipalign_apk_tool).
    Automatically uses a fresh aligned APK when possible, auto-zipaligning the
    latest unsigned build if the aligned copy is missing or stale. Produces a
    verified v1+v2+v3 signature before reporting success.

    Returns: Text summary with success/failure status and path to the signed APK,
    or the rebuilt XAPK bundle when the original input was an XAPK.
    """
    from apk_agent.tools.base import ToolResult
    from apk_agent.tools.cert_analyzer import analyze_certificate as _analyze_certificate
    from apk_agent.tools.signer import sign_apk as _sign
    from apk_agent.tools.zipalign import verify_alignment, zipalign
    from apk_agent.workspace import get_final_artifact_path, package_signed_output, validate_apk

    aligned = Path(_project.workspace_path) / "outputs" / "patched-aligned.apk"
    unsigned = Path(_project.workspace_path) / "outputs" / "patched-unsigned.apk"
    signed = Path(_project.workspace_path) / "outputs" / "patched-signed.apk"
    zipalign_bin = _config.get_tool_path("zipalign") or "zipalign"
    input_apk = aligned if aligned.is_file() else unsigned
    alignment_note = ""

    if not unsigned.is_file() and not aligned.is_file():
        return ToolResult(
            success=False,
            exit_code=-5,
            stdout="",
            stderr="No rebuilt APK found. Run apktool_build() successfully before sign_apk().",
            command="sign_apk()",
        ).to_llm_str()

    if unsigned.is_file():
        aligned_is_fresh = aligned.is_file()
        if aligned_is_fresh:
            try:
                aligned_is_fresh = aligned.stat().st_mtime >= unsigned.stat().st_mtime
            except OSError:
                aligned_is_fresh = False

        if not aligned_is_fresh:
            align_result = zipalign(
                zipalign_bin=zipalign_bin,
                input_apk=unsigned,
                output_apk=aligned,
                log_file=_log_file(),
            )
            if not (align_result.success and aligned.is_file()):
                return (
                    ToolResult(
                        success=False,
                        exit_code=-6,
                        stdout="",
                        stderr="Zipalign failed. Refusing to sign an unaligned APK because Android may reject it as an invalid package.",
                        command="sign_apk()",
                    ).to_llm_str()
                    + "\n\n--- zipalign details ---\n"
                    + align_result.to_llm_str()
                )
            alignment_note = "Auto-zipaligned the latest unsigned APK before signing.\n"
        input_apk = aligned

    if input_apk == aligned:
        alignment_check = verify_alignment(
            zipalign_bin=zipalign_bin,
            apk_path=aligned,
            log_file=_log_file(),
        )
        if not alignment_check.success:
            return (
                ToolResult(
                    success=False,
                    exit_code=-7,
                    stdout="",
                    stderr="Aligned APK failed zipalign verification. Refusing to sign because the final package may install as invalid.",
                    command="sign_apk()",
                ).to_llm_str()
                + "\n\n--- alignment verification ---\n"
                + alignment_check.to_llm_str()
            )
        alignment_note += "Zipalign verification passed before signing.\n"

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
    if not result.success:
        return alignment_note + result.to_llm_str()

    signed_path = Path(result.artifacts.get("signed_apk", signed)).resolve()
    apk_errors = validate_apk(signed_path, _config.max_apk_size_mb)
    cert_info = _analyze_certificate(signed_path)
    verified_schemes_raw = str(result.artifacts.get("signature_schemes", "") or "").strip()
    verified_schemes = {
        part.strip().lower() for part in verified_schemes_raw.split(",") if part.strip()
    }
    if verified_schemes_raw:
        cert_info["signature_verified"] = bool(result.artifacts.get("signature_verified", False))
        cert_info["signature_schemes"] = verified_schemes_raw
        cert_info["signature_scheme"] = verified_schemes_raw
        cert_info["signature_scheme_source"] = "apksigner verify"
        scheme_details = result.artifacts.get("signature_scheme_details")
        if isinstance(scheme_details, dict) and scheme_details:
            cert_info["signature_scheme_details"] = scheme_details
    has_v1_signature = "v1" in verified_schemes or (
        bool(cert_info.get("signing_files")) and "v1" in str(cert_info.get("signature_scheme", "")).lower()
    )

    if apk_errors or not has_v1_signature:
        failure = ToolResult(
            success=False,
            exit_code=-8,
            stdout="",
            stderr="Final signed APK failed installability checks. Refusing to report success because Android may reject it as an invalid package.",
            command="sign_apk()",
            artifacts={
                "signed_apk": str(signed_path),
                "apk_structure_errors": apk_errors,
                "v1_signature_detected": has_v1_signature,
            },
        )
        return (
            alignment_note
            + failure.to_llm_str()
            + "\n\n--- certificate analysis ---\n"
            + json.dumps(cert_info, ensure_ascii=False, indent=2)[:5000]
        )

    xapk_note = ""
    if str(getattr(_project, "source_type", "apk") or "apk").lower() == "xapk":
        try:
            final_artifact = package_signed_output(_project, signed_path)
        except Exception as exc:
            failure = ToolResult(
                success=False,
                exit_code=-9,
                stdout="",
                stderr=f"Signed base APK was created, but rebuilding the final XAPK bundle failed: {exc}",
                command="sign_apk()",
                artifacts={
                    "signed_apk": str(signed_path),
                    "expected_xapk": str(get_final_artifact_path(_project)),
                },
            )
            return (
                alignment_note
                + failure.to_llm_str()
                + "\n\n--- certificate analysis ---\n"
                + json.dumps(cert_info, ensure_ascii=False, indent=2)[:5000]
            )

        xapk_errors = validate_apk(final_artifact, _config.max_apk_size_mb)
        if xapk_errors:
            failure = ToolResult(
                success=False,
                exit_code=-10,
                stdout="",
                stderr="Final signed XAPK failed structural checks.",
                command="sign_apk()",
                artifacts={
                    "signed_apk": str(signed_path),
                    "signed_xapk": str(final_artifact),
                    "xapk_structure_errors": xapk_errors,
                },
            )
            return (
                alignment_note
                + failure.to_llm_str()
                + "\n\n--- certificate analysis ---\n"
                + json.dumps(cert_info, ensure_ascii=False, indent=2)[:5000]
            )

        xapk_note = (
            "\n\n--- xapk bundle ---\n"
            + json.dumps({
                "success": True,
                "signed_apk": str(signed_path),
                "final_artifact": str(final_artifact),
                "split_apks": list(getattr(_project, "xapk_split_apk_entries", []) or []),
                "obb_files": list(getattr(_project, "xapk_obb_entries", []) or []),
            }, ensure_ascii=False, indent=2)[:5000]
        )

    return (
        alignment_note
        + result.to_llm_str()
        + "\n\n--- certificate analysis ---\n"
        + json.dumps(cert_info, ensure_ascii=False, indent=2)[:5000]
        + xapk_note
    )


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
# Resource-aware tools
# ---------------------------------------------------------------------------


@tool
def find_resource_colors(color_family: str = "", exclude_third_party: bool = True) -> str:
    """Parse Android color resources and return structured color mappings.

    Understands `res/values*/colors.xml` instead of treating resource files as raw text.

    Args:
        color_family: Optional hue family filter: red, orange, yellow, green,
            cyan, blue, purple, pink.
        exclude_third_party: If true, skip common third-party resource prefixes.

    Returns: JSON with extracted color entries, hue info, and file locations.
    """
    from apk_agent.tools.resource_tools import find_app_colors as _find

    def _run():
        result = _find(
            _project.apktool_dir,
            color_family=color_family.strip() or None,
            exclude_third_party=exclude_third_party,
        )
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]

    return _safe_call(_run, "find_resource_colors", _cache_hint=f"{color_family}:{exclude_third_party}")


@tool
def find_resource_styles(exclude_third_party: bool = True) -> str:
    """Parse Android style/theme resources and extract color-related attributes.

    Useful for patching themes intentionally instead of editing styles.xml blindly.

    Args:
        exclude_third_party: If true, skip known third-party/material library themes.

    Returns: JSON with styles/themes and their color attributes.
    """
    from apk_agent.tools.resource_tools import find_app_styles as _find

    def _run():
        result = _find(_project.apktool_dir, exclude_third_party=exclude_third_party)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]

    return _safe_call(_run, "find_resource_styles", _cache_hint=str(exclude_third_party))


@tool
def replace_resource_colors(color_map_json: str) -> str:
    """Bulk replace color hex values across Android resource XML files.

    Applies structured color replacement across colors.xml, styles/themes,
    layout XMLs, and drawable XMLs under `res/`.

    Args:
        color_map_json: JSON object mapping old hex colors to new hex colors.
            Example: {"#FF6200EE": "#FF1F7A8C"}

    Returns: JSON with files modified and replacement counts.
    """
    from apk_agent.tools.resource_tools import replace_colors as _replace

    def _run():
        try:
            color_map = json.loads(color_map_json)
        except json.JSONDecodeError as e:
            return json.dumps({"success": False, "error": f"Invalid JSON: {e}"})
        if not isinstance(color_map, dict):
            return json.dumps({"success": False, "error": "color_map_json must be a JSON object."})
        result = _replace(_project.apktool_dir, color_map)
        return json.dumps(result, ensure_ascii=False, indent=2)

    return _safe_call(_run, "replace_resource_colors")


@tool
def list_resource_drawables(color_filter: str = "") -> str:
    """List drawable XML resources, optionally filtered by embedded hex color.

    Args:
        color_filter: Optional hex color like `#FF0000`.

    Returns: JSON with drawable files and discovered inline colors.
    """
    from apk_agent.tools.resource_tools import list_drawables as _list

    def _run():
        result = _list(_project.apktool_dir, color_filter=color_filter.strip() or None)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]

    return _safe_call(_run, "list_resource_drawables", _cache_hint=color_filter)





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

        # --- Smart jadx path resolution ---
        # jadx renames conflicting packages: "ui" → "p297ui", "a" → "a.1", etc.
        # When the agent passes "jadx_src/sources/com/app/ui/Foo.java" but the
        # real path is "jadx_src/sources/com/app/p297ui/Foo.java", a simple
        # filename search gives too many false positives.  Instead, walk the
        # requested path segments and try to find the closest existing directory
        # at each level, tolerating jadx renames.
        jadx_sources = _project.jadx_dir / "sources"
        if jadx_sources.is_dir() and fname.endswith(".java"):
            # Extract the package path the agent intended (e.g. "com/app/ui")
            _stripped2 = file_path.replace("\\", "/").lstrip("/")
            for _pfx2 in (
                "decompiled/jadx_src/sources/",
                "decompiled/jadx_src/",
                "jadx_src/sources/",
                "jadx_src/",
            ):
                if _stripped2.startswith(_pfx2):
                    _stripped2 = _stripped2[len(_pfx2):]
                    break
            parts = _stripped2.split("/")
            _cur = jadx_sources
            _resolved = True
            for i, seg in enumerate(parts[:-1]):  # all segments except filename
                child = _cur / seg
                if child.is_dir():
                    _cur = child
                else:
                    # Try jadx-renamed variants: "ui" → "p*ui", "a" → "a.1"
                    _found_alt = False
                    if _cur.is_dir():
                        for d in _cur.iterdir():
                            if not d.is_dir():
                                continue
                            # Match "pNNNseg" pattern (jadx prefix rename)
                            dname = d.name
                            if dname.endswith(seg) and len(dname) > len(seg) and dname[0] == "p" and dname[1:-len(seg)].isdigit():
                                _cur = d
                                _found_alt = True
                                break
                            # Match "seg.N" pattern (jadx collision suffix)
                            if dname.startswith(seg + ".") and dname[len(seg)+1:].isdigit():
                                _cur = d
                                _found_alt = True
                                break
                    if not _found_alt:
                        _resolved = False
                        break
            if _resolved:
                _final = _cur / parts[-1]
                if _final.is_file():
                    p = _final

    # If still not found, fall back to filename-based search
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
            # If we have exactly 1 match, auto-resolve it instead of erroring
            if len(nearby) == 1:
                p = Path(nearby[0])
            else:
                return json.dumps({
                    "success": False,
                    "error": f"File not found: {file_path}",
                    "similar_files_found": nearby,
                    "hint": "The exact path doesn't exist. Try one of the similar files above, "
                            "or read the .smali version instead.",
                }, ensure_ascii=False, indent=2)

    result = _read(p, start_line=start_line, end_line=end_line)
    return json.dumps(result, ensure_ascii=False, indent=2)[:12000]


def _find_broken_smali_descriptors(content: str) -> list[str]:
    """Return descriptor fragments that look like object refs missing the `L` prefix.

    This intentionally scans descriptor-shaped contexts only so valid method
    signatures like `JLjava/...;` and string literals like `"application/json;"`
    are not misclassified as broken smali.
    """
    import re as _re

    sanitized = _re.sub(r'"(?:\\.|[^"\\])*"', '""', content)
    broken: list[str] = []
    seen: set[str] = set()

    def _record(ref: str) -> None:
        ref = ref.strip()
        if ref and ref not in seen:
            seen.add(ref)
            broken.append(ref)

    def _scan_descriptor_sequence(descriptor: str, *, allow_void: bool = False, single: bool = False) -> None:
        descriptor = descriptor.strip()
        if not descriptor:
            return

        index = 0
        consumed = False

        def _missing_l_fragment(start: int) -> str | None:
            end = descriptor.find(";", start)
            if end == -1:
                return None
            fragment = descriptor[start : end + 1].strip()
            return fragment if "/" in fragment else None

        while index < len(descriptor):
            while index < len(descriptor) and descriptor[index] == "[":
                index += 1

            if index >= len(descriptor):
                break

            ch = descriptor[index]
            if ch == "L":
                end = descriptor.find(";", index + 1)
                if end == -1:
                    break
                index = end + 1
                consumed = True
                continue

            if ch == "V" and allow_void and index == 0:
                index += 1
                consumed = True
                continue

            if ch in "ZBCSIJFD":
                index += 1
                consumed = True
                if single and index < len(descriptor):
                    tail = _missing_l_fragment(index)
                    if tail is not None:
                        _record(descriptor)
                        return
                continue

            fragment = _missing_l_fragment(index)
            if fragment is not None:
                _record(descriptor if single else fragment)
            return

        if not consumed:
            fragment = _missing_l_fragment(0)
            if fragment is not None:
                _record(descriptor if single else fragment)

    for raw_line in sanitized.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        if line.startswith((".class", ".super", ".implements")):
            _scan_descriptor_sequence(line.split()[-1], single=True)

        field_def = _re.search(r'^\.field\b.*?:\s*([^=\s]+)', line)
        if field_def:
            _scan_descriptor_sequence(field_def.group(1), single=True)

        method_def = _re.search(r'^\.method\b[^\(]*\(([^)]*)\)([^\s#]+)', line)
        if method_def:
            _scan_descriptor_sequence(method_def.group(1))
            _scan_descriptor_sequence(method_def.group(2), allow_void=True, single=True)

        if "->" not in line:
            continue

        for class_ref in _re.finditer(r'([^\s,{}()]+)->', line):
            _scan_descriptor_sequence(class_ref.group(1), single=True)

        for field_ref in _re.finditer(r'->[\w<>$-]+:([^\s,}#]+)', line):
            _scan_descriptor_sequence(field_ref.group(1), single=True)

        for method_ref in _re.finditer(r'->[\w<>$-]+\(([^)]*)\)([^\s,}#]+)', line):
            _scan_descriptor_sequence(method_ref.group(1))
            _scan_descriptor_sequence(method_ref.group(2), allow_void=True, single=True)

    return broken


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
        p = _resolve_file(file_path)

    # --- Smali validation guard ------------------------------------------
    if p.suffix == ".smali":
        # 1. Must have a .class directive
        if not _re.search(r'^\s*\.class\s+', content, _re.MULTILINE):
            return json.dumps({"success": False,
                "error": "BLOCKED: .smali file has no .class directive — content is corrupt. "
                         "Use apply_smali_patch or inject_smali_code instead of write_file."})

        # 2. Detect broken class descriptors in descriptor-shaped contexts only.
        real_broken = _find_broken_smali_descriptors(content)
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
    from apk_agent.progress import report_progress
    from apk_agent.tools.index_cache import lookup_method, lookup_string, lookup_class
    from apk_agent.tools.code_graph import query_callers as _qc
    from apk_agent.tools.deep_analysis import analyze_shared_prefs as _asp

    def _emit_progress(start_pct: float, end_pct: float, current: int, total: int, detail: str) -> None:
        if total <= 0:
            report_progress(end_pct, detail)
            return
        interval = max(1, total // 20)
        if current == total or current % interval == 0:
            pct = start_pct + (current / total) * (end_pct - start_pct)
            report_progress(pct, detail)

    report_progress(2, f"Preparing feature map for '{feature}'")

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

    report_progress(6, f"Keyword expansion complete: {len(keywords)} search terms")

    search_smali_dirs = _get_all_smali_dirs()

    def _resolve_analysis_file(relative_path: str):
        if not relative_path:
            return None
        candidate = _project.apktool_dir / relative_path
        if candidate.is_file():
            return candidate
        for smali_dir in search_smali_dirs:
            alt = smali_dir / relative_path
            if alt.is_file():
                return alt
        return None

    # --- Step 1: Find boolean getters via index ---
    report_progress(8, "Loading code index for feature discovery")
    idx = _ensure_index()
    boolean_getters: list[dict] = []
    int_getters: list[dict] = []
    string_refs: list[dict] = []

    if idx:
        # Method lookup: isPremium, isPro, isSubscribed, etc.
        getter_prefixes = ["is", "get", "has", "can", "check", "should", "verify"]
        searched_methods: set[str] = set()
        report_progress(12, f"Index getter lookup across {len(keywords)} keywords")
        for kw_index, kw in enumerate(keywords, start=1):
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

            _emit_progress(
                12,
                20,
                kw_index,
                len(keywords),
                f"Getter lookup: {kw_index}/{len(keywords)} keywords | {len(boolean_getters)} boolean + {len(int_getters)} fallback methods",
            )

        # String lookup: "premium", "pro", "FREE", "PREMIUM", etc.
        report_progress(21, f"Index string lookup across {len(keywords)} keywords")
        for kw_index, kw in enumerate(keywords, start=1):
            for variant in [kw, kw.upper(), kw.capitalize()]:
                result = lookup_string(idx, variant)
                for s in result.get("matches", result.get("string_matches", []))[:10]:
                    string_refs.append(s)
            _emit_progress(
                21,
                28,
                kw_index,
                len(keywords),
                f"String lookup: {kw_index}/{len(keywords)} keywords | {len(string_refs)} refs",
            )
    else:
        report_progress(28, "Code index unavailable; skipping index lookups")

    # --- Step 2: SharedPreferences analysis ---
    shared_prefs_hits: list[dict] = []
    report_progress(30, "Analyzing SharedPreferences and local flags")
    try:
        search_dirs = list(search_smali_dirs)
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
    report_progress(38, f"SharedPreferences analysis complete: {len(shared_prefs_hits)} matching keys")

    # --- Step 3: Graph callers for discovered methods ---
    callers_map: list[dict] = []
    report_progress(40, "Loading code graph for caller tracing")
    G = _ensure_graph()
    if G:
        seen: set[str] = set()
        getters_to_trace = (boolean_getters + int_getters)[:15]
        report_progress(44, f"Tracing callers for {len(getters_to_trace)} getter methods")
        for getter_index, getter in enumerate(getters_to_trace, start=1):
            mname = getter.get("method", "").split("->")[-1].split("(")[0] if "->" in getter.get("method", "") else ""
            if not mname or mname in seen:
                _emit_progress(
                    44,
                    52,
                    getter_index,
                    len(getters_to_trace),
                    f"Caller tracing: {getter_index}/{len(getters_to_trace)} methods | {len(callers_map)} call chains",
                )
                continue
            seen.add(mname)
            cr = _qc(G, mname, depth=2)
            for chain in cr.get("call_chains", [])[:5]:
                callers_map.append({
                    "target": chain.get("target", ""),
                    "caller": chain.get("caller", ""),
                    "caller_file": chain.get("caller_file", ""),
                })
            _emit_progress(
                44,
                52,
                getter_index,
                len(getters_to_trace),
                f"Caller tracing: {getter_index}/{len(getters_to_trace)} methods | {len(callers_map)} call chains",
            )
    else:
        report_progress(52, "Code graph unavailable; skipping caller tracing")

    # --- Step 4: Paywall / UI gate methods ---
    paywall_methods: list[dict] = []
    if idx:
        paywall_names = ["showPaywall", "showUpgrade", "showPurchase", "showPremium",
                         "showSubscri", "openStore", "openBilling", "showPro",
                         "upgrade", "paywall", "locked"]
        report_progress(54, f"Scanning {len(paywall_names)} paywall/UI gate patterns")
        for paywall_index, pn in enumerate(paywall_names, start=1):
            result = lookup_method(idx, pn)
            for m in result.get("methods", []):
                paywall_methods.append({
                    "method": m.get("full_name", ""),
                    "file": m.get("file", ""),
                })
            _emit_progress(
                54,
                60,
                paywall_index,
                len(paywall_names),
                f"Paywall lookup: {paywall_index}/{len(paywall_names)} patterns | {len(paywall_methods)} hits",
            )

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
        behavioral_files = list(entity_files)[:20]
        report_progress(62, f"Behavioral scan across {len(behavioral_files)} candidate entity files")
        for file_index, efile in enumerate(behavioral_files, start=1):
            try:
                fpath = _resolve_analysis_file(efile)
                if fpath is None:
                    _emit_progress(
                        62,
                        70,
                        file_index,
                        len(behavioral_files),
                        f"Behavioral scan: {file_index}/{len(behavioral_files)} files | {len(behavioral_hits)} gate-like methods",
                    )
                    continue
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                _emit_progress(
                    62,
                    70,
                    file_index,
                    len(behavioral_files),
                    f"Behavioral scan: {file_index}/{len(behavioral_files)} files | {len(behavioral_hits)} gate-like methods",
                )
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
            _emit_progress(
                62,
                70,
                file_index,
                len(behavioral_files),
                f"Behavioral scan: {file_index}/{len(behavioral_files)} files | {len(behavioral_hits)} gate-like methods",
            )
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
            structural_classes = list(entity_classes)[:10]
            report_progress(71, f"Structural scan across {len(structural_classes)} entity classes")
            for class_index, cls_name in enumerate(structural_classes, start=1):
                cls_info = idx.get("classes", {}).get(cls_name, {})
                if not cls_info:
                    _emit_progress(
                        71,
                        76,
                        class_index,
                        len(structural_classes),
                        f"Structural scan: {class_index}/{len(structural_classes)} classes | {len(entity_methods)} extra methods",
                    )
                    continue
                fpath_str = cls_info.get("file", "")
                if not fpath_str:
                    _emit_progress(
                        71,
                        76,
                        class_index,
                        len(structural_classes),
                        f"Structural scan: {class_index}/{len(structural_classes)} classes | {len(entity_methods)} extra methods",
                    )
                    continue
                try:
                    fpath = _resolve_analysis_file(fpath_str)
                    if fpath is None:
                        _emit_progress(
                            71,
                            76,
                            class_index,
                            len(structural_classes),
                            f"Structural scan: {class_index}/{len(structural_classes)} classes | {len(entity_methods)} extra methods",
                        )
                        continue
                    text = fpath.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    _emit_progress(
                        71,
                        76,
                        class_index,
                        len(structural_classes),
                        f"Structural scan: {class_index}/{len(structural_classes)} classes | {len(entity_methods)} extra methods",
                    )
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
                _emit_progress(
                    71,
                    76,
                    class_index,
                    len(structural_classes),
                    f"Structural scan: {class_index}/{len(structural_classes)} classes | {len(entity_methods)} extra methods",
                )
    except Exception:
        pass

    # --- Step 7: BILLING FRAMEWORK TRACING ---
    # Find the premium system through billing API references.
    # Billing library class names are NEVER obfuscated — they're Android SDK classes.
    # This is the most reliable discovery method for obfuscated apps.
    billing_hits: list[dict] = []
    _step5_files = set(entity_files)  # Track what Step 5 already scanned
    try:
        report_progress(77, "Tracing billing framework entry points and purchase handlers")
        # 7a: Find app classes that IMPLEMENT billing interfaces
        _BILLING_INTERFACES = [
            "PurchasesUpdatedListener", "BillingClientStateListener",
            "PurchasesResponseListener", "SkuDetailsResponseListener",
            "ProductDetailsResponseListener", "AcknowledgePurchaseResponseListener",
            "ConsumeResponseListener", "PurchaseHistoryResponseListener",
        ]
        if idx:
            idx_classes = list(idx.get("classes", {}).items())
            for class_index, (cls_name, cls_info) in enumerate(idx_classes, start=1):
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
                _emit_progress(
                    77,
                    80,
                    class_index,
                    len(idx_classes),
                    f"Billing interface scan: {class_index}/{len(idx_classes)} classes | {len(billing_hits)} hits",
                )

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
        if G:
            report_progress(81, f"Tracing {len(_BILLING_METHODS)} billing API methods through the code graph")
            for method_index, bm in enumerate(_BILLING_METHODS, start=1):
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
                _emit_progress(
                    81,
                    84,
                    method_index,
                    len(_BILLING_METHODS),
                    f"Billing graph trace: {method_index}/{len(_BILLING_METHODS)} APIs | {len(billing_hits)} hits",
                )

        # 7c: Find classes that reference billing-related CLASSES by name
        _BILLING_CLASSES = [
            "BillingClient", "Purchase", "SkuDetails", "ProductDetails",
            "BillingResult", "BillingFlowParams",
        ]
        if idx:
            for class_index, bc in enumerate(_BILLING_CLASSES, start=1):
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
                _emit_progress(
                    84,
                    86,
                    class_index,
                    len(_BILLING_CLASSES),
                    f"Billing class lookup: {class_index}/{len(_BILLING_CLASSES)} patterns | {len(billing_hits)} hits",
                )

        # 7d: Trace FIELDS in billing-connected classes to find entity classes.
        # The purchase handler often has a field like `UserInfo mUserInfo` or
        # `SubscriptionModel mSub` — tracing field types finds the entity.
        _new_entity_files: set[str] = set()
        new_billing_files = list(entity_files - _step5_files)[:15]
        for file_index, bfile in enumerate(new_billing_files, start=1):
            try:
                fpath = _resolve_analysis_file(bfile)
                if fpath is None:
                    _emit_progress(
                        86,
                        88,
                        file_index,
                        len(new_billing_files),
                        f"Billing field trace: {file_index}/{len(new_billing_files)} files | {len(_new_entity_files)} new entity files",
                    )
                    continue
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                _emit_progress(
                    86,
                    88,
                    file_index,
                    len(new_billing_files),
                    f"Billing field trace: {file_index}/{len(new_billing_files)} files | {len(_new_entity_files)} new entity files",
                )
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
            _emit_progress(
                86,
                88,
                file_index,
                len(new_billing_files),
                f"Billing field trace: {file_index}/{len(new_billing_files)} files | {len(_new_entity_files)} new entity files",
            )

        entity_files.update(_new_entity_files)

        # 7e: Behavioral scan on ALL newly discovered files (from billing tracing)
        billing_behavior_files = list(entity_files - _step5_files)[:20]
        for file_index, bfile in enumerate(billing_behavior_files, start=1):
            try:
                fpath = _resolve_analysis_file(bfile)
                if fpath is None:
                    _emit_progress(
                        88,
                        90,
                        file_index,
                        len(billing_behavior_files),
                        f"Billing behavioral scan: {file_index}/{len(billing_behavior_files)} files | {len(behavioral_hits)} behavioral hits",
                    )
                    continue
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                _emit_progress(
                    88,
                    90,
                    file_index,
                    len(billing_behavior_files),
                    f"Billing behavioral scan: {file_index}/{len(billing_behavior_files)} files | {len(behavioral_hits)} behavioral hits",
                )
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
            _emit_progress(
                88,
                90,
                file_index,
                len(billing_behavior_files),
                f"Billing behavioral scan: {file_index}/{len(billing_behavior_files)} files | {len(behavioral_hits)} behavioral hits",
            )
    except Exception:
        pass

    # --- Step 8: SMALI-IR BEHAVIORAL SCAN — find gate methods by INSTRUCTION PATTERNS ---
    # Uses the SmaliIndex (parsed IR with typed instructions) to find methods
    # that BEHAVE like gates, regardless of their names.
    # This is the MOST powerful step for obfuscated apps where a()Z = isPremium.
    ir_behavioral_hits: list[dict] = []
    try:
        report_progress(91, "Loading SmaliIndex for instruction-level behavioral scan")
        si = _ensure_smali_index()
        if si:
            # Collect class names from entity_files for targeted deep scan
            _entity_class_names: set[str] = set()
            for g in boolean_getters + int_getters:
                c = g.get("class", "")
                if c:
                    _entity_class_names.add(c)
            # Also add classes found through billing tracing
            for bh in billing_hits:
                c = bh.get("class", "")
                if c:
                    _entity_class_names.add(c)

            # Scan entity classes (known) + classes with keyword strings (discovered)
            _scan_classes: set[str] = set(_entity_class_names)

            # Also find classes that contain feature-related strings via SmaliIndex
            for kw in keywords[:5]:
                for variant in [kw, kw.upper(), kw.capitalize()]:
                    for file_path, _line in si.find_string_usages(variant):
                        # Find which class this file belongs to
                        for cls_name, cls_obj in si.classes.items():
                            if cls_obj.file_path == file_path:
                                _scan_classes.add(cls_name)
                                break

            # Now analyze each candidate class using SmaliIndex IR
            _already_found = set()
            for g in boolean_getters + int_getters + behavioral_hits:
                m = g.get("method", "")
                if m:
                    _already_found.add(m.split("(")[0])  # Just method name

            scan_classes = list(_scan_classes)[:30]
            for class_index, cls_name in enumerate(scan_classes, start=1):
                cls_obj = si.get_class(cls_name)
                if cls_obj is None:
                    _emit_progress(
                        91,
                        97,
                        class_index,
                        len(scan_classes),
                        f"SmaliIR scan: {class_index}/{len(scan_classes)} classes | {len(ir_behavioral_hits)} IR gate hits",
                    )
                    continue

                for method in cls_obj.methods:
                    if method.name in ("<init>", "<clinit>"):
                        continue
                    if method.return_type not in ("Z", "I"):
                        continue
                    if method.name in _already_found:
                        continue

                    # Analyze instructions for gate BEHAVIOR
                    has_field_read = False
                    has_branch = False
                    has_boolean_field = False
                    has_date_comparison = False
                    has_string_equality = False
                    field_names_read: list[str] = []

                    for instr in method.instructions:
                        if instr.is_field_access and instr.opcode.startswith(("iget", "sget")):
                            has_field_read = True
                            if instr.opcode in ("iget-boolean", "sget-boolean"):
                                has_boolean_field = True
                            if instr.target_field:
                                field_names_read.append(instr.target_field.split("->")[-1] if "->" in instr.target_field else instr.target_field)
                        if instr.is_branch and instr.opcode.startswith("if-"):
                            has_branch = True
                        if instr.is_invoke:
                            tc = instr.target_class.lower() if instr.target_class else ""
                            tm = instr.target_method.lower() if instr.target_method else ""
                            if any(d in tc or d in tm for d in ("calendar", "date", "time", "before", "after", "compareto")):
                                has_date_comparison = True
                            if tm == "equals":
                                has_string_equality = True

                    # Classify as gate if it reads fields + has conditional logic
                    gate_reasons = []
                    if has_boolean_field and has_branch:
                        gate_reasons.append("BOOLEAN_FIELD_READ+BRANCH")
                    if has_date_comparison:
                        gate_reasons.append("DATE_COMPARISON")
                    if has_string_equality and has_branch:
                        gate_reasons.append("STRING_EQUALITY+BRANCH")
                    if has_field_read and has_branch and method.return_type == "Z" and method.complexity >= 2:
                        if not gate_reasons:
                            gate_reasons.append("COMPLEX_CONDITIONAL_BOOLEAN")

                    if gate_reasons:
                        _already_found.add(method.name)
                        ir_behavioral_hits.append({
                            "method": method.signature,
                            "class": cls_name,
                            "file": cls_obj.file_path,
                            "return_type": "boolean" if method.return_type == "Z" else "int",
                            "behavior": gate_reasons,
                            "fields_read": field_names_read[:5],
                            "complexity": method.complexity,
                            "note": "Found by SmaliIR INSTRUCTION-LEVEL analysis (survives obfuscation)",
                        })
                _emit_progress(
                    91,
                    97,
                    class_index,
                    len(scan_classes),
                    f"SmaliIR scan: {class_index}/{len(scan_classes)} classes | {len(ir_behavioral_hits)} IR gate hits",
                )
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
    ir_behavioral_hits = _dedup(ir_behavioral_hits)[:20]

    total = (len(boolean_getters) + len(int_getters) + len(shared_prefs_hits)
             + len(paywall_methods) + len(behavioral_hits) + len(entity_methods)
             + len(billing_hits) + len(ir_behavioral_hits))

    report_progress(100, f"map_feature_checks complete: {total} checkpoints across {len(keywords)} keywords")

    return json.dumps({
        "success": True,
        "feature": feature,
        "keywords_searched": keywords,
        "boolean_getters": boolean_getters,
        "int_getters": int_getters,
        "behavioral_checks": behavioral_hits,
        "ir_behavioral_gates": ir_behavioral_hits,
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
            + (f"SmaliIR GATES ({len(ir_behavioral_hits)}): Methods found by INSTRUCTION-LEVEL "
               f"behavioral analysis — these are gate methods detected by code structure (field read + "
               f"branch), NOT by name. Works on fully obfuscated code. "
               if ir_behavioral_hits else "")
            + (f"BEHAVIORAL checks ({len(behavioral_hits)}): Methods found by analyzing "
               f"code BEHAVIOR — these are often the REAL gating logic in obfuscated apps. "
               if behavioral_hits else "")
            + (f"Entity class methods ({len(entity_methods)}): OTHER boolean/int methods "
               f"in the same subscription entity class — check each one. "
               if entity_methods else "")
            + f"NEXT STEPS: 1) For each billing/behavioral/IR-gate hit, run "
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
                    # Build a recommended patch with SEMANTIC AWARENESS
                    # Determine if the method semantics are POSITIVE (isPremium → force TRUE)
                    # or NEGATIVE (isExpired, isTrial, isFree → force FALSE)
                    _NEGATIVE_SEMANTICS = (
                        "expire", "trial", "free", "locked", "restrict", "limit",
                        "block", "disable", "invalid", "revoke", "cancel", "trier",
                        "unpaid", "demo", "basic", "lite",
                    )
                    _POSITIVE_SEMANTICS = (
                        "premium", "pro", "vip", "paid", "active", "valid", "unlock",
                        "enable", "subscrib", "license", "purchased", "own", "lifetime",
                        "svip", "gold", "diamond", "elite",
                    )
                    # Check method name and string constants for semantic hints
                    name_lower = mname.lower()
                    str_lower = " ".join(str_consts).lower() if str_consts else ""
                    combined_text = f"{name_lower} {str_lower}"

                    is_negative = any(neg in combined_text for neg in _NEGATIVE_SEMANTICS)
                    is_positive = any(pos in combined_text for pos in _POSITIVE_SEMANTICS)

                    # If STRING_EQUALITY, check the compared string for semantics
                    if "STRING_EQUALITY" in str(behaviors) and str_consts:
                        for sc in str_consts:
                            sc_lower = sc.lower()
                            if any(neg in sc_lower for neg in ("trier", "free", "trial", "basic", "lite", "demo")):
                                is_negative = True
                            if any(pos in sc_lower for pos in ("svip", "vip", "pro", "premium", "gold")):
                                is_positive = True

                    if ret == "Z":
                        if is_negative and not is_positive:
                            force_value = "0x0"
                            force_label = "FALSE"
                            reason = "Negative semantic (expiry/trial/free check) → force FALSE to negate restriction"
                        elif is_positive and not is_negative:
                            force_value = "0x1"
                            force_label = "TRUE"
                            reason = "Positive semantic (premium/pro/active check) → force TRUE to affirm privilege"
                        else:
                            # Ambiguous or obfuscated — default TRUE but flag for jadx verification
                            force_value = "0x1"
                            force_label = "TRUE"
                            reason = "Ambiguous semantics — VERIFY with jadx source whether TRUE or FALSE means 'unlocked'"
                        method_info["recommended_patch"] = {
                            "operation": "replace_block",
                            "match_pattern": f".method {access} {sig}",
                            "strategy": f"Insert 'const/4 v0, {force_value}\\n    return v0' after .locals/.registers line to force {force_label}",
                            "note": reason,
                            "semantic_hint": "negative" if is_negative else ("positive" if is_positive else "ambiguous"),
                        }
                    elif ret == "I":
                        method_info["recommended_patch"] = {
                            "operation": "replace_block",
                            "match_pattern": f".method {access} {sig}",
                            "strategy": "Insert 'const/4 v0, 0x2\\n    return v0' (or the premium int value) after .locals line",
                            "note": "Read jadx source to determine which int value = premium tier",
                        }
                    gate_methods.append(method_info)
                    if str_consts:
                        method_info["string_constants"] = str_consts

                all_methods.append(method_info)
                method_start = -1

        # --- SmaliIndex hierarchy scan ---
        # Use SmaliIndex to find subclasses and parent class that may override
        # or inherit gate methods. Catches polymorphic gate bypass failures.
        hierarchy_gates: list[dict] = []
        try:
            si = _ensure_smali_index()
            if si and class_name:
                # Check parent class for gate methods
                parent_cls = si.get_class(super_class) if super_class else None
                # Check child classes that override gate methods
                child_names = si.get_subclasses(class_name)

                _already_gate_names = {g["name"] for g in gate_methods}

                related_classes: list[tuple[str, str]] = []  # (class_name, relation)
                if parent_cls:
                    related_classes.append((super_class, "parent"))
                for cn in child_names[:10]:
                    related_classes.append((cn, "child"))

                for rel_cls_name, relation in related_classes:
                    rel_cls = si.get_class(rel_cls_name)
                    if rel_cls is None:
                        continue
                    for method in rel_cls.methods:
                        if method.name in ("<init>", "<clinit>"):
                            continue
                        if method.return_type not in ("Z", "I"):
                            continue
                        # Check if this method is behaviorally a gate
                        has_field_read = any(
                            i.is_field_access and i.opcode.startswith(("iget", "sget"))
                            for i in method.instructions
                        )
                        has_branch = any(
                            i.is_branch and i.opcode.startswith("if-")
                            for i in method.instructions
                        )
                        if has_field_read and has_branch:
                            hierarchy_gates.append({
                                "method": method.signature,
                                "class": rel_cls_name,
                                "file": rel_cls.file_path,
                                "relation": relation,
                                "return_type": _smali_type_name(method.return_type),
                                "note": f"{relation.upper()} class gate — may override or inherit subscription logic",
                            })
        except Exception:
            pass

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
            "hierarchy_gates": hierarchy_gates,
            "all_methods": [m for m in all_methods if m not in gate_methods][:15],
            "field_dependencies": field_deps,
            "instruction": (
                f"Found {len(gate_methods)} GATE METHODS in {class_name}"
                + (f" + {len(hierarchy_gates)} in parent/child classes" if hierarchy_gates else "")
                + " — these are the methods that control premium/subscription access. "
                f"For each gate method: 1) Read the jadx Java source to understand the logic, "
                f"2) Determine what return value means 'unlocked', "
                f"3) Patch with apply_smali_patch. "
                + (f"⚠️ HIERARCHY WARNING: {len(hierarchy_gates)} gate methods found in "
                   f"{'parent' if any(h['relation'] == 'parent' for h in hierarchy_gates) else 'child'} "
                   f"classes — these MUST also be patched or they will override your patches. "
                   if hierarchy_gates else "")
                + f"ALSO check the fields list — fields like 'role', 'dueTime', 'type', "
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

        # --- SmaliIndex hierarchy scan: also patch CHILD class constructors ---
        # Child classes that extend this entity class inherit its fields,
        # so their constructors also need field overrides.
        hierarchy_patches: list[dict] = []
        try:
            si = _ensure_smali_index()
            if si:
                child_classes = si.get_subclasses(class_descriptor)
                for child_name in child_classes[:10]:
                    child_cls = si.get_class(child_name)
                    if child_cls is None or not child_cls.abs_path:
                        continue
                    # Check if this child class has constructors
                    has_init = any(m.name == "<init>" for m in child_cls.methods)
                    if has_init:
                        try:
                            child_result = override_constructor_fields(
                                child_cls.abs_path, child_name, overrides
                            )
                            hierarchy_patches.append({
                                "class": child_name,
                                "file": child_cls.file_path,
                                "success": child_result.get("success", False),
                                "constructors_patched": child_result.get("constructors_patched", 0),
                            })
                        except Exception as e:
                            hierarchy_patches.append({
                                "class": child_name,
                                "file": child_cls.file_path,
                                "success": False,
                                "error": str(e)[:100],
                            })
        except Exception:
            pass

        if hierarchy_patches:
            result["hierarchy_patches"] = hierarchy_patches
            result["note"] = (
                f"Also patched {sum(1 for h in hierarchy_patches if h.get('success'))} "
                f"child class constructors (inheriting fields from {class_descriptor})"
            )

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

    Use this only for simple constant-return body rewrites AFTER you have
    verified the exact target methods. For risky or unclear methods, prefer
    preview_smali_patch + apply_smali_patch one-by-one.

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
    from tempfile import NamedTemporaryFile

    from apk_agent.tools.deep_analysis import validate_smali_syntax as _validate_smali_syntax

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

        def _extract_method_name(query: str) -> str:
            query = str(query or "").strip()
            if not query:
                return ""
            match = _re.match(r'([\w<>$-]+)\(', query)
            if match:
                return match.group(1)
            return query.split()[-1] if query.split() else ""

        def _extract_return_type(query: str) -> str:
            query = str(query or "").strip()
            if ')' not in query:
                return ""
            return query.rsplit(')', 1)[-1].strip()

        def _count_param_slots(method_header: str) -> int:
            match = _re.search(r'\((.*?)\)', method_header)
            if not match:
                return 0
            params = match.group(1)
            count = 0
            idx = 0
            while idx < len(params):
                token = params[idx]
                if token in 'ZBCSIF':
                    count += 1
                    idx += 1
                elif token in 'JD':
                    count += 2
                    idx += 1
                elif token == 'L':
                    count += 1
                    idx = params.index(';', idx) + 1
                elif token == '[':
                    idx += 1
                else:
                    idx += 1
            if 'static' not in method_header.lower().split('(')[0]:
                count += 1
            return count

        def _extract_param_descriptors(method_header: str) -> list[str]:
            match = _re.search(r'\((.*?)\)', method_header)
            if not match:
                return []
            params = match.group(1)
            descriptors: list[str] = []
            idx = 0
            while idx < len(params):
                token = params[idx]
                start = idx
                if token == '[':
                    while idx < len(params) and params[idx] == '[':
                        idx += 1
                    if idx < len(params) and params[idx] == 'L':
                        end = params.index(';', idx)
                        idx = end + 1
                    else:
                        idx += 1
                    descriptors.append(params[start:idx])
                elif token == 'L':
                    end = params.index(';', idx)
                    idx = end + 1
                    descriptors.append(params[start:idx])
                else:
                    idx += 1
                    descriptors.append(token)
            return descriptors

        def _find_param_register(method_header: str, descriptor: str) -> str:
            params = _extract_param_descriptors(method_header)
            slot = 0 if 'static' in method_header.lower().split('(')[0] else 1
            for param in params:
                if param == descriptor:
                    return f"p{slot}"
                slot += 2 if param in {'J', 'D'} else 1
            return ""

        def _actual_return_type(method_header: str) -> str:
            match = _re.search(r'\)(\S+)', method_header)
            if not match:
                return ""
            return match.group(1).strip()

        def _promise_bridge_compatible(method_header: str, expected_return: str) -> bool:
            if not expected_return or _actual_return_type(method_header) != 'V':
                return False
            if not _find_param_register(method_header, 'Lcom/facebook/react/bridge/Promise;'):
                return False
            return expected_return in {'Z', 'I', 'J'}

        def _ensure_method_registers(lines: list[str], locals_line: int, method_header: str, needed_locals: int) -> None:
            locals_match = _re.match(r'(\s*)\.locals\s+(\d+)', lines[locals_line])
            if locals_match:
                current = int(locals_match.group(2))
                if current < needed_locals:
                    lines[locals_line] = f"{locals_match.group(1)}.locals {needed_locals}"
                return

            registers_match = _re.match(r'(\s*)\.registers\s+(\d+)', lines[locals_line])
            if registers_match:
                current = int(registers_match.group(2))
                param_slots = _count_param_slots(method_header)
                required = max(current, param_slots + needed_locals)
                if required != current:
                    lines[locals_line] = f"{registers_match.group(1)}.registers {required}"

        def _strip_bodyless_flags(method_header: str) -> str:
            parts = method_header.strip().split()
            if not parts or parts[0] != '.method':
                return method_header.strip()
            filtered = [parts[0]] + [part for part in parts[1:] if part not in {'native', 'abstract'}]
            return ' '.join(filtered)

        def _match_method(header: str, query: str) -> bool:
            """Match a method header against a query string.
            Supports both name-only ('isPremium') and signature ('isPremium()Z') queries.
            """
            m = _re.search(r'(\S+)\(', header)
            if not m:
                return False
            name = m.group(1)
            if '(' in query:
                # Signature match: extract from method name to end
                try:
                    sig = header[header.index(name):]
                    return query in sig
                except ValueError:
                    return False
            return name == query

        def _find_method_index(method_ranges: list[tuple[int, int, str]], patched_indices: set[int], query: str) -> tuple[int, str]:
            for midx, (_m_start, _m_end, m_header) in enumerate(method_ranges):
                if midx in patched_indices:
                    continue
                if _match_method(m_header, query):
                    return midx, "exact"

            method_name = _extract_method_name(query)
            if not method_name:
                return -1, "not_found"

            expected_return = _extract_return_type(query)
            fuzzy_candidates: list[int] = []
            for midx, (_m_start, _m_end, m_header) in enumerate(method_ranges):
                if midx in patched_indices:
                    continue
                match = _re.search(r'(\S+)\((.*?)\)(\S+)', m_header)
                if not match:
                    continue
                if match.group(1) != method_name:
                    continue
                if expected_return and match.group(3).strip() != expected_return:
                    continue
                fuzzy_candidates.append(midx)

            if len(fuzzy_candidates) == 1:
                return fuzzy_candidates[0], "unique_name_fallback"
            if len(fuzzy_candidates) > 1:
                return -1, "ambiguous_name_fallback"

            promise_bridge_candidates: list[int] = []
            for midx, (_m_start, _m_end, m_header) in enumerate(method_ranges):
                if midx in patched_indices:
                    continue
                match = _re.search(r'(\S+)\((.*?)\)(\S+)', m_header)
                if not match:
                    continue
                if match.group(1) != method_name:
                    continue
                if _promise_bridge_compatible(m_header, expected_return):
                    promise_bridge_candidates.append(midx)

            if len(promise_bridge_candidates) == 1:
                return promise_bridge_candidates[0], "promise_bridge_fallback"
            if len(promise_bridge_candidates) > 1:
                return -1, "ambiguous_name_fallback"
            return -1, "not_found"

        def _build_patch_instructions(requested_return_type: str, value, method_header: str) -> tuple[str, int, str]:
            actual_return = _actual_return_type(method_header)
            promise_reg = _find_param_register(method_header, 'Lcom/facebook/react/bridge/Promise;')

            if actual_return == 'V' and promise_reg and requested_return_type in {'boolean', 'int', 'long', 'void'}:
                if requested_return_type == 'void':
                    return (
                        f"    const/4 v0, 0x0\n\n"
                        f"    invoke-interface {{{promise_reg}, v0}}, Lcom/facebook/react/bridge/Promise;->resolve(Ljava/lang/Object;)V\n\n"
                        f"    return-void",
                        1,
                        'promise_resolve_rewrite',
                    )
                if requested_return_type == 'boolean':
                    v = '0x1' if value else '0x0'
                    return (
                        f"    const/4 v0, {v}\n\n"
                        f"    invoke-static {{v0}}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;\n\n"
                        f"    move-result-object v0\n\n"
                        f"    invoke-interface {{{promise_reg}, v0}}, Lcom/facebook/react/bridge/Promise;->resolve(Ljava/lang/Object;)V\n\n"
                        f"    return-void",
                        1,
                        'promise_resolve_rewrite',
                    )
                if requested_return_type == 'int':
                    iv = int(value)
                    if -8 <= iv <= 7:
                        load = f"    const/4 v0, {hex(iv)}"
                    elif -32768 <= iv <= 32767:
                        load = f"    const/16 v0, {hex(iv)}"
                    else:
                        load = f"    const v0, {hex(iv)}"
                    return (
                        f"{load}\n\n"
                        f"    invoke-static {{v0}}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;\n\n"
                        f"    move-result-object v0\n\n"
                        f"    invoke-interface {{{promise_reg}, v0}}, Lcom/facebook/react/bridge/Promise;->resolve(Ljava/lang/Object;)V\n\n"
                        f"    return-void",
                        1,
                        'promise_resolve_rewrite',
                    )
                return (
                    f"    const-wide v0, {hex(int(value))}\n\n"
                    f"    invoke-static {{v0, v1}}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;\n\n"
                    f"    move-result-object v0\n\n"
                    f"    invoke-interface {{{promise_reg}, v0}}, Lcom/facebook/react/bridge/Promise;->resolve(Ljava/lang/Object;)V\n\n"
                    f"    return-void",
                    2,
                    'promise_resolve_rewrite',
                )

            if requested_return_type == "void":
                return "    return-void", 0, "body_rewrite"
            if requested_return_type == "boolean":
                v = "0x1" if value else "0x0"
                return f"    const/4 v0, {v}\n\n    return v0", 1, "body_rewrite"
            if requested_return_type == "int":
                iv = int(value)
                if -8 <= iv <= 7:
                    inject = f"    const/4 v0, {hex(iv)}\n\n    return v0"
                elif -32768 <= iv <= 32767:
                    inject = f"    const/16 v0, {hex(iv)}\n\n    return v0"
                else:
                    inject = f"    const v0, {hex(iv)}\n\n    return v0"
                return inject, 1, "body_rewrite"
            if requested_return_type == "long":
                return f"    const-wide v0, {hex(int(value))}\n\n    return-wide v0", 2, "body_rewrite"
            return "    const/4 v0, 0x0\n\n    return v0", 1, "body_rewrite"

        def _validate_generated_smali(candidate_lines: list[str]) -> dict:
            temp_path: Path | None = None
            try:
                with NamedTemporaryFile("w", encoding="utf-8", suffix=".smali", delete=False) as handle:
                    handle.write("\n".join(candidate_lines) + "\n")
                    temp_path = Path(handle.name)
                return _validate_smali_syntax(temp_path)
            finally:
                if temp_path is not None:
                    try:
                        temp_path.unlink()
                    except OSError:
                        pass

        for file_rel, file_patches in by_file.items():
            fpath = _resolve_file(file_rel)
            if not fpath.is_file():
                for p in file_patches:
                    results.append({"method": p.get("method"), "file": file_rel,
                                    "success": False, "error": "File not found"})
                    total_fail += 1
                continue

            text = fpath.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
            original_lines = list(lines)
            file_results: list[dict | None] = [None] * len(file_patches)
            file_journal_entries: list[dict] = []
            file_failures = 0

            # Pre-index ALL methods in the file to avoid index-shift problems.
            # We collect (start, end, header) for every method.
            method_ranges: list[tuple[int, int, str]] = []
            cur_start = -1
            cur_header = ""
            for i, ln in enumerate(lines):
                s = ln.strip()
                if s.startswith(".method"):
                    cur_start = i
                    cur_header = s
                elif s == ".end method" and cur_start >= 0:
                    method_ranges.append((cur_start, i, cur_header))
                    cur_start = -1
                    cur_header = ""

            # Track already-patched method indices to avoid double-patching
            patched_indices: set[int] = set()
            planned_patches: list[dict] = []

            for request_index, p in enumerate(file_patches):
                method_q = p.get("method", "")
                ret_type = p.get("return_type", "boolean")
                value = p.get("value")
                desc = p.get("description", "")

                found_idx, resolution = _find_method_index(method_ranges, patched_indices, method_q)

                if found_idx < 0:
                    error = f"Method not found: {method_q}"
                    if resolution == "ambiguous_name_fallback":
                        error = f"Method match was ambiguous: {method_q}"
                    file_results[request_index] = {"method": method_q, "file": file_rel,
                                                   "success": False, "error": error}
                    file_failures += 1
                    continue

                patched_indices.add(found_idx)
                m_start_orig, m_end_orig, original_header = method_ranges[found_idx]

                inject, needed_locals, rewrite_mode = _build_patch_instructions(ret_type, value, original_header)
                file_results[request_index] = {"method": method_q, "file": file_rel,
                                               "success": True, "description": desc,
                                               "resolution": resolution, "rewrite_mode": rewrite_mode}
                planned_patches.append({
                    "request_index": request_index,
                    "method_q": method_q,
                    "ret_type": ret_type,
                    "value": value,
                    "description": desc,
                    "resolution": resolution,
                    "rewrite_mode": rewrite_mode,
                    "m_start_orig": m_start_orig,
                    "m_end_orig": m_end_orig,
                    "original_header": original_header,
                    "inject": inject,
                    "needed_locals": needed_locals,
                })

            normalized_file_results = [
                entry if entry is not None else {
                    "method": file_patches[idx].get("method", ""),
                    "file": file_rel,
                    "success": False,
                    "error": "Internal batch patch planning failure",
                }
                for idx, entry in enumerate(file_results)
            ]

            if file_failures:
                abort_error = (
                    f"Aborted file-level batch patch for {file_rel}: "
                    f"{file_failures} requested method(s) failed, so no changes were written."
                )
                for entry in normalized_file_results:
                    committed = entry.get("success", False) and "error" not in entry
                    entry["success"] = False
                    if committed:
                        entry["error"] = abort_error
                        entry["aborted"] = True
                results.extend(normalized_file_results)
                total_fail += len(normalized_file_results)
                lines = original_lines
                continue

            for planned in sorted(planned_patches, key=lambda item: item["m_start_orig"], reverse=True):
                m_start = planned["m_start_orig"]
                m_end = planned["m_end_orig"]

                locals_line = -1
                for i in range(m_start + 1, min(m_start + 15, m_end)):
                    if _re.match(r'\s*\.(locals|registers)\s+\d+', lines[i]):
                        locals_line = i
                        break

                final_rewrite_mode = planned["rewrite_mode"]
                if locals_line < 0:
                    final_rewrite_mode = "bodyless_method_rewrite"
                    patched_header = _strip_bodyless_flags(lines[m_start])
                    new_body = [patched_header, f"    .locals {planned['needed_locals']}"]
                else:
                    _ensure_method_registers(lines, locals_line, planned["original_header"], planned["needed_locals"])
                    new_body = [lines[i] for i in range(m_start, locals_line + 1)]

                new_body.append("")
                new_body.append(f"    # APK-AGI batch patch: {planned['description']}")
                new_body.append(planned["inject"])
                new_body.append("")
                new_body.append(".end method")

                lines[m_start:m_end + 1] = new_body
                normalized_file_results[planned["request_index"]]["rewrite_mode"] = final_rewrite_mode

            validation = _validate_generated_smali(lines)
            if not validation.get("valid", False):
                validation_errors = "; ".join(
                    f"line {err.get('line', 0)}: {err.get('message', 'unknown error')}"
                    for err in validation.get("errors", [])[:3]
                ) or "unknown smali validation error"
                abort_error = (
                    f"Generated smali failed validation for {file_rel}; no changes were written: "
                    f"{validation_errors}"
                )
                for entry in normalized_file_results:
                    entry["success"] = False
                    entry["error"] = abort_error
                    entry["aborted"] = True
                results.extend(normalized_file_results)
                total_fail += len(normalized_file_results)
                lines = original_lines
                continue

            for planned in planned_patches:
                file_journal_entries.append({
                    "success": True, "target_file": file_rel,
                    "description": planned["description"], "steps_applied": 1, "steps_total": 1,
                    "diff_text": f"Forced {planned['method_q']} -> {planned['ret_type']}({planned['value']})",
                    "errors": [], "tool": "batch_patch_methods",
                })

            # Backup — preserve the original file using the canonical relative path
            # so restore_smali_backup can locate it later.
            # Only create it once we know the entire file batch will commit.
            backup = _project.patch_backup_dir / file_rel.replace("\\", "/")
            _project.patch_backup_dir.mkdir(parents=True, exist_ok=True)
            backup.parent.mkdir(parents=True, exist_ok=True)
            if not backup.exists():
                shutil.copy2(fpath, backup)

            # Write once per file after every requested method in the file succeeded.
            fpath.write_text("\n".join(lines) + "\n", encoding="utf-8")
            results.extend(normalized_file_results)
            total_ok += len(normalized_file_results)
            _patch_journal.extend(file_journal_entries)

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
        import re

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
        hierarchy_info: dict = {}

        # --- FAST PATH: Use SmaliIndex if available (instant lookups) ---
        si = _ensure_smali_index()
        if si and is_class:
            cls_obj = si.get_class(target)
            if cls_obj:
                # Outgoing calls + strings from the class's own methods
                for method in cls_obj.methods:
                    for api in method.api_calls:
                        outgoing_calls.append({"instruction": api[:120], "from_method": method.signature[:60]})
                    for s in method.string_constants:
                        string_constants.append(s)

                # Incoming calls via api_callers index (INSTANT — no file scan)
                for method in cls_obj.methods:
                    full_sig_prefix = f"{target}->{method.name}"
                    callers = si.find_api_callers(full_sig_prefix)
                    for caller_sig in callers[:20]:
                        caller_method = si.get_method(caller_sig)
                        incoming_calls.append({
                            "caller": caller_sig[:120],
                            "file": caller_method.full_signature.split("->")[0] if caller_method else "",
                            "calls": method.signature[:60],
                        })

                # Field reads/writes via instruction scanning across ALL methods
                target_escaped = target.replace("$", "\\$")
                for method_sig, method_obj in si.methods.items():
                    if target in method_sig:
                        continue  # Skip self
                    for instr in method_obj.instructions:
                        if instr.is_field_access and target[1:-1] in (instr.target_field or ""):
                            entry = {
                                "method": method_sig[:80],
                                "instruction": instr.raw[:120],
                                "line": instr.line,
                            }
                            if instr.opcode.startswith(("iget", "sget")):
                                field_reads.append(entry)
                            elif instr.opcode.startswith(("iput", "sput")):
                                field_writes.append(entry)

                # Hierarchy info
                subclasses = si.get_subclasses(target)
                implementors = []
                for iface in cls_obj.interfaces:
                    implementors.extend(si.get_implementors(iface))
                if subclasses or cls_obj.super_class or implementors:
                    hierarchy_info = {
                        "super_class": cls_obj.super_class,
                        "subclasses": subclasses[:10],
                        "interface_implementors": implementors[:10],
                    }

                string_constants = list(set(string_constants))

                return json.dumps({
                    "success": True,
                    "target": target,
                    "target_file_found": True,
                    "source": "smali_index",
                    "hierarchy": hierarchy_info,
                    "summary": {
                        "incoming_calls": len(incoming_calls),
                        "outgoing_calls": len(outgoing_calls),
                        "field_reads": len(field_reads),
                        "field_writes": len(field_writes),
                        "string_constants": len(string_constants),
                        "resource_refs": 0,
                    },
                    "incoming_calls": incoming_calls[:50],
                    "outgoing_calls": outgoing_calls[:50],
                    "field_reads": field_reads[:30],
                    "field_writes": field_writes[:30],
                    "string_constants": string_constants[:30],
                }, ensure_ascii=False, indent=2)[:25000]

        # --- FALLBACK: File-scan path (for method targets or when SmaliIndex unavailable) ---

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
        import re

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
        import re

        apk_dir = _project.apktool_dir
        smali_dirs = [d for d in apk_dir.iterdir() if d.is_dir() and d.name.startswith("smali")]
        if not smali_dirs:
            return json.dumps({"success": False, "error": "No smali directories."})

        lifecycle_hooks = [
            "onResume", "onStart", "onRestart", "onWindowFocusChanged",
            "onAttachedToWindow", "onConfigurationChanged", "onNewIntent",
        ]
        # Named premium indicators (for non-obfuscated code)
        premium_indicators = re.compile(
            r"premium|isPro|isVip|isPaid|isTrial|isExpired|isFree|"
            r"subscription|license|purchas|billing|getType|getPlan|"
            r"TRIER|TRIAL|FREE|PREMIUM|PRO|VIP",
            re.IGNORECASE,
        )
        # Behavioral premium indicators (for obfuscated code)
        # These catch calls to known entity classes or billing APIs inside lifecycle hooks
        behavioral_indicators = re.compile(
            r"BillingClient|Purchase|SharedPreferences|getBoolean|getString|getInt|"
            r"invoke-.*->(?:a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v|w|x|y|z)\(\)Z",
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
                            # Look for premium indicators in a wider window (50 lines)
                            window = "\n".join(lines[i:i + 50])
                            prem_matches = premium_indicators.findall(window)
                            # Also check behavioral indicators for obfuscated code
                            behavioral_matches = behavioral_indicators.findall(window)
                            if prem_matches or behavioral_matches:
                                all_indicators = list(set(prem_matches))[:5]
                                if behavioral_matches and not prem_matches:
                                    all_indicators = ["[behavioral:" + m[:30] + "]" for m in behavioral_matches[:3]]
                                lifecycle_checks.append({
                                    "file": rel,
                                    "line": i + 1,
                                    "method": current_method[:80],
                                    "lifecycle_hook": hook,
                                    "premium_indicators": all_indicators,
                                    "detection_type": "named" if prem_matches else "behavioral",
                                })
                            break

                    # Timer-based checks (wider window: ±10/+15 lines)
                    if timer_patterns.search(s) and (
                        premium_indicators.search("\n".join(lines[max(0, i - 10):i + 15]))
                        or behavioral_indicators.search("\n".join(lines[max(0, i - 10):i + 15]))
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
        import re

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
    non-premium values, UI gate methods (showing upgrade/paywall dialogs), and
    behavioral gate methods in known entity classes (catches obfuscated code).

    When to use: After all patches are applied, BEFORE building the APK.
    This is the final quality gate — any remaining gates it finds MUST be patched.

    Returns: JSON — remaining_gates (array), remaining_prefs_checks, remaining_ui_gates,
    behavioral_remaining (obfuscated gates), patch_coverage_pct, verdict (PASS/FAIL).
    """
    def _run():
        import re

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

        # Behavioral gate patterns (for obfuscated code detection)
        _BEHAVIORAL_GATE = [
            re.compile(r'invoke-.*(?:Calendar|Date|TimeUnit|before\(|after\(|compareTo\()', re.I),
            re.compile(r'iget-boolean|sget-boolean'),
            re.compile(r'const-string.*invoke-.*equals\(', re.DOTALL),
        ]

        remaining_gates: list[dict] = []
        remaining_prefs: list[dict] = []
        remaining_ui: list[dict] = []
        behavioral_remaining: list[dict] = []
        patched_methods: set[str] = set()

        # Collect files that were patched (from patch journal) to check their
        # entity classes for remaining obfuscated gates
        patched_files: set[str] = set()
        for entry in _patch_journal:
            tf = entry.get("target_file", "")
            if tf:
                patched_files.add(tf)

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

                # Skip library code
                rel_fwd = rel.replace("\\", "/")
                parts = rel_fwd.split("/")
                if len(parts) > 1:
                    top = parts[1] if parts[0].startswith("smali") else parts[0]
                    if top in ("android", "androidx", "com", "kotlin", "kotlinx",
                               "org", "io", "java", "javax", "dalvik", "sun"):
                        # Check more specifically for com/
                        if top == "com" and len(parts) > 2:
                            sub = parts[2] if parts[0].startswith("smali") else parts[1]
                            if sub in ("google", "facebook", "squareup", "adjust",
                                       "android", "crashlytics", "firebase"):
                                continue
                        elif top != "com":
                            continue

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
                                r"\.locals\s+\d+\s*\n\s*(?:#[^\n]*\n\s*)?const(?:/4|/16)?\s+v0",
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

                        # Behavioral check for OBFUSCATED gate methods in entity classes
                        # (files that we've already patched — these are likely entity classes
                        # with remaining unpatched methods)
                        elif rel in patched_files or any(pf in rel for pf in patched_files):
                            # Check if this Z/I-returning method has gate behavior
                            ret_match = re.search(r'\)([ZI])\s*$', current_method)
                            if ret_match:
                                method_body = "\n".join(lines[method_start:i])
                                is_patched = bool(re.search(
                                    r"\.locals\s+\d+\s*\n\s*(?:#[^\n]*\n\s*)?const(?:/4|/16)?\s+v0",
                                    method_body,
                                ))
                                if not is_patched:
                                    has_gate_behavior = any(
                                        pat.search(method_body) for pat in _BEHAVIORAL_GATE
                                    )
                                    if has_gate_behavior:
                                        behavioral_remaining.append({
                                            "file": rel,
                                            "line": method_start + 1,
                                            "method": current_method[:80],
                                            "return_type": "boolean" if ret_match.group(1) == "Z" else "int",
                                            "status": "BEHAVIORAL_GATE_NOT_PATCHED",
                                            "hint": "Obfuscated method with gate behavior in a known entity class",
                                        })

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
        # Include behavioral gates in verdict — if entity classes have unpatched gates, FAIL
        verdict = "PASS" if not remaining_gates and not remaining_prefs and not behavioral_remaining else "FAIL"

        return json.dumps({
            "success": True,
            "verdict": verdict,
            "patch_coverage_pct": round(coverage, 1),
            "patched_methods": patched_count,
            "remaining_gates": remaining_gates[:20],
            "behavioral_remaining": behavioral_remaining[:15],
            "remaining_prefs_checks": remaining_prefs[:15],
            "remaining_ui_gates": remaining_ui[:15],
            "summary": (
                f"Coverage: {coverage:.0f}%. "
                + ("ALL named gates patched. " if not remaining_gates else f"{len(remaining_gates)} named methods still need patching. ")
                + (f"⚠️ {len(behavioral_remaining)} OBFUSCATED gate methods detected in entity classes — patch these too! " if behavioral_remaining else "")
                + (f"{len(remaining_prefs)} prefs reads still need patching. " if remaining_prefs else "")
                + ("Verdict: " + verdict)
            ),
        }, ensure_ascii=False, indent=2)[:15000]

    return _safe_call(_run, "verify_bypass_completeness")


# ---------------------------------------------------------------------------
# Patch tools
# ---------------------------------------------------------------------------

_BINARY_PATCH_SUFFIXES = {
    ".apk", ".apks", ".dex", ".so", ".arsc", ".bin",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
    ".ttf", ".otf", ".woff", ".woff2", ".mp3", ".ogg",
    ".wav", ".mp4", ".pdf",
}


def _looks_binary_patch_target(target_file: str) -> bool:
    return Path(str(target_file or "")).suffix.lower() in _BINARY_PATCH_SUFFIXES


@tool
def apply_text_patch(patch_plan_json: str) -> str:
    """Apply a structured patch to any TEXT file inside the apktool project.

    Use this for AndroidManifest.xml, resource XML, network_security_config.xml,
    apktool.yml, JSON/properties/text assets, and other non-binary files.

    IMPORTANT:
    - This is for TEXT files only. For binary files such as .so or .dex, use patch_binary_hex.
    - For smali bytecode logic changes, prefer apply_smali_patch.

    Args:
        patch_plan_json: Same JSON structure used by apply_smali_patch:
            {
                "target_file": "AndroidManifest.xml",
                "description": "Enable exported activity",
                "steps": [
                    {
                        "operation": "replace_line|replace_block|replace_all|insert_before|insert_after|delete_block|delete_line",
                        "match_pattern": "exact text or regex to find",
                        "replacement": "replacement text (for replace ops)",
                        "content": "text to insert (for insert ops)",
                        "is_regex": false,
                        "description": "What this step does"
                    }
                ]
            }

    Returns: JSON with keys: success, target_file, steps_applied, steps_total,
    diff_text, errors, backup_path.
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
            "recovery_hint": 'Add "target_file": "AndroidManifest.xml" (or another apktool text file) to your JSON.',
        })

    try:
        plan = PatchPlan.from_dict(plan_data)
    except (ValueError, KeyError) as e:
        return json.dumps({"success": False, "error": str(e)})

    if _looks_binary_patch_target(plan.target_file):
        return json.dumps({
            "success": False,
            "error": f"Binary target not allowed with apply_text_patch: {plan.target_file}",
            "recovery_hint": "Use patch_binary_hex for .so/.dex and other binary files.",
        })

    engine = PatchEngine(
        apktool_dir=_project.apktool_dir,
        backup_dir=_project.patch_backup_dir,
        diffs_dir=_project.patch_diffs_dir,
    )
    result = engine.apply_plan(plan)

    out = {
        "success": result.success,
        "target_file": result.target_file,
        "steps_applied": result.steps_applied,
        "steps_total": result.steps_total,
        "diff_text": result.diff_text[:5000],
        "errors": result.errors,
        "backup_path": result.backup_path,
    }

    _patch_journal.append({
        "success": result.success,
        "target_file": result.target_file,
        "description": plan_data.get("description", ""),
        "steps_applied": result.steps_applied,
        "steps_total": result.steps_total,
        "diff_text": result.diff_text[:3000],
        "errors": result.errors,
        "tool": "apply_text_patch",
    })

    return json.dumps(out, ensure_ascii=False, indent=2)


@tool
def preview_text_patch(patch_plan_json: str) -> str:
    """Preview a structured TEXT patch without modifying files.

    Use this before apply_text_patch when editing AndroidManifest.xml,
    resource XML, apktool.yml, JSON, or other text files in the apktool tree.

    Args:
        patch_plan_json: Same JSON structure as apply_text_patch.

    Returns: Unified diff text, or JSON with success=false on validation errors.
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
            "recovery_hint": 'Add "target_file": "AndroidManifest.xml" (or another apktool text file) to your JSON.',
        })

    try:
        plan = PatchPlan.from_dict(plan_data)
    except (ValueError, KeyError) as e:
        return json.dumps({"success": False, "error": str(e)})

    if _looks_binary_patch_target(plan.target_file):
        return json.dumps({
            "success": False,
            "error": f"Binary target not allowed with preview_text_patch: {plan.target_file}",
            "recovery_hint": "Use patch_binary_hex for .so/.dex and other binary files.",
        })

    engine = PatchEngine(
        apktool_dir=_project.apktool_dir,
        backup_dir=_project.patch_backup_dir,
        diffs_dir=_project.patch_diffs_dir,
    )
    return engine.preview_plan(plan)[:8000]


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
                        "operation": "replace_line|replace_block|replace_all|insert_before|insert_after|delete_block|delete_line",
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


@tool
def patch_binary_hex(
    file_path: str,
    search_hex: str,
    replace_hex: str,
    occurrence: int = 1,
    replace_all: bool = False,
) -> str:
    """Patch a binary file by exact hex replacement.

    This enables controlled patching of binary assets such as `.so` libraries,
    raw `.dex` files (when available), and other non-text blobs.

    Safety rules:
    - `search_hex` and `replace_hex` must be the same byte length.
    - The tool performs exact byte matching only; it does NOT disassemble binaries.
    - A backup is created before the first successful write.

    Args:
        file_path: Absolute path or path relative to the apktool project/workspace.
        search_hex: Hex byte pattern to search for. Spaces, `0x`, and `\\x` are ignored.
        replace_hex: Replacement hex pattern. Must be the same length as search_hex.
        occurrence: 1-based occurrence number to patch when replace_all=false.
        replace_all: If true, patch every occurrence in the file.

    Returns: JSON with keys: success, path, matches_found, patched_occurrences,
    offsets, backup_path.
    """

    def _normalize_hex(value: str) -> bytes:
        cleaned = str(value or "")
        cleaned = cleaned.replace("\\x", "").replace("0x", "")
        cleaned = "".join(cleaned.split())
        if not cleaned:
            raise ValueError("hex pattern is empty")
        if len(cleaned) % 2 != 0:
            raise ValueError("hex pattern has an odd number of characters")
        return bytes.fromhex(cleaned)

    def _nth_offset(data: bytes, needle: bytes, n: int) -> int:
        start = 0
        for _ in range(n):
            idx = data.find(needle, start)
            if idx < 0:
                return -1
            start = idx + len(needle)
        return idx

    def _run():
        p = Path(file_path)
        if not p.is_absolute():
            resolved = _resolve_file(file_path)
            if resolved.exists():
                p = resolved
            else:
                p = Path(_project.workspace_path) / file_path

        if not p.is_file():
            return json.dumps({"success": False, "error": f"File not found: {p}"})

        try:
            search = _normalize_hex(search_hex)
            replace = _normalize_hex(replace_hex)
        except ValueError as e:
            return json.dumps({"success": False, "error": str(e)})

        if len(search) != len(replace):
            return json.dumps({
                "success": False,
                "error": "search_hex and replace_hex must have the same byte length.",
                "search_len": len(search),
                "replace_len": len(replace),
            })

        if occurrence < 1:
            return json.dumps({"success": False, "error": "occurrence must be >= 1"})

        original = p.read_bytes()
        matches_found = original.count(search)
        if matches_found == 0:
            return json.dumps({
                "success": False,
                "error": "search_hex pattern was not found in the target file.",
                "path": str(p),
            })

        offsets: list[str] = []
        if replace_all:
            idx = 0
            while True:
                idx = original.find(search, idx)
                if idx < 0:
                    break
                offsets.append(f"0x{idx:x}")
                idx += len(search)
            patched = original.replace(search, replace)
        else:
            idx = _nth_offset(original, search, occurrence)
            if idx < 0:
                return json.dumps({
                    "success": False,
                    "error": f"Occurrence {occurrence} not found. Total matches: {matches_found}",
                    "path": str(p),
                })
            offsets.append(f"0x{idx:x}")
            patched = original[:idx] + replace + original[idx + len(search):]

        backup_key = None
        try:
            backup_key = str(p.relative_to(_project.apktool_dir)).replace("\\", "/")
        except ValueError:
            try:
                backup_key = str(p.relative_to(_project.workspace_path)).replace("\\", "/")
            except ValueError:
                backup_key = p.name
        backup_name = backup_key.replace("/", "_").replace("\\", "_") + ".bak"
        backup_path = _project.patch_backup_dir / backup_name
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        if not backup_path.exists():
            backup_path.write_bytes(original)

        if p.exists():
            p.chmod(p.stat().st_mode | 0o200)
        p.write_bytes(patched)

        _patch_journal.append({
            "success": True,
            "target_file": str(p),
            "description": f"Binary hex patch ({len(offsets)} occurrence(s))",
            "steps_applied": len(offsets),
            "steps_total": len(offsets),
            "diff_text": f"search={search.hex()} replace={replace.hex()} offsets={', '.join(offsets[:10])}",
            "errors": [],
            "tool": "patch_binary_hex",
        })

        return json.dumps({
            "success": True,
            "path": str(p),
            "matches_found": matches_found,
            "patched_occurrences": len(offsets),
            "offsets": offsets[:50],
            "backup_path": str(backup_path),
        }, ensure_ascii=False, indent=2)

    return _safe_call(_run, "patch_binary_hex")


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
# NEW: Resource-aware Android resource tools
# ---------------------------------------------------------------------------


@tool
def search_binary_strings(
    file_path: str,
    query: str = "",
    categories: str = "",
    min_length: int = 4,
    max_results: int = 100,
) -> str:
    """Search embedded printable strings in a binary file or directory such as `lib/`, `assets/`, `.so`, or `.dex`.

    This is a semantic search layer over binary string tables/constants, returning
    exact offsets to plan safe native/DEX patches. If you pass a directory, the
    tool scans matching files recursively and returns the file path for each hit.

    Args:
        file_path: Target binary file OR directory. Can be absolute or relative to apktool/workspace.
        query: Optional regex or plain-text query to filter returned strings.
        categories: Optional comma-separated categories such as `url,api_key,jni_native,class_descriptor`.
        min_length: Minimum printable string length to extract.
        max_results: Maximum returned matches.

    Returns: JSON with matched strings, offsets, categories, and patching rules.
    """
    from apk_agent.tools.binary_patch import search_binary_strings as _search

    def _run():
        p = _resolve_project_path(file_path)
        category_list = [c.strip() for c in categories.split(",") if c.strip()]
        result = _search(
            p,
            query=query,
            categories=category_list,
            min_length=min_length,
            max_results=max_results,
        )
        return json.dumps(result, ensure_ascii=False, indent=2)[:20000]
    return _safe_call(_run, "search_binary_strings", _cache_hint=f"{file_path}:{query}:{categories}:{min_length}:{max_results}")


@tool
def analyze_dart_aot(file_path: str) -> str:
    """Fingerprint a Flutter/Dart AOT native library such as libapp.so.

    This tool does not reconstruct Dart symbols. It verifies ELF/arch support,
    checks for Flutter/Dart markers, and identifies likely code/data ranges to
    inspect before planning bounded native patches.

    Args:
        file_path: Absolute path or project-relative path to a native library,
            typically `lib/arm64-v8a/libapp.so`.

    Returns: JSON with support_level, arch, ELF section names, string hint
    counts, candidate_snapshot_ranges, and notes about analysis confidence.
    """
    from apk_agent.tools.dart_aot import analyze_dart_aot as _analyze

    def _run():
        p = _resolve_project_path(file_path)
        result = _analyze(p)
        return json.dumps(result, ensure_ascii=False, indent=2)[:20000]

    return _safe_call(_run, "analyze_dart_aot", _cache_hint=str(file_path))


@tool
def build_dart_aot_index(file_path: str) -> str:
    """Build a searchable Dart AOT anchor index for a Flutter native library.

    The index stores printable strings, hint-matched anchors, ELF sections, and
    fingerprint metadata in the project's outputs directory.

    Args:
        file_path: Absolute or project-relative path to `libapp.so` or another
            target native library.

    Returns: JSON with stats and an `output_file` pointing to the saved index.
    """
    from apk_agent.tools.dart_aot import build_dart_aot_index as _build

    def _run():
        p = _resolve_project_path(file_path)
        output = _project.outputs_dir / "dart_aot_index.json"
        result = _build(p, output_path=output)
        return json.dumps(result, ensure_ascii=False, indent=2)[:20000]

    return _safe_call(_run, "build_dart_aot_index", _cache_hint=str(file_path))


@tool
def locate_dart_aot_candidates(
    file_path: str,
    query: str = "",
    anchors_json: str = "[]",
    index_file: str = "",
    window_bytes: int = 4096,
    max_matches: int = 25,
) -> str:
    """Locate candidate Dart AOT patch regions using string anchors and hints.

    Use this after `build_dart_aot_index()` or directly on a `libapp.so` path.
    The tool returns bounded windows/offsets rather than pretending to recover
    full Dart symbols.

    Args:
        file_path: Target library path. Used when index_file is empty.
        query: Free-form search text such as `wallet,purchase,paywall`.
        anchors_json: JSON array of exact string anchors to match.
        index_file: Optional saved index file from build_dart_aot_index.
        window_bytes: Nearby window to report around a matched anchor.
        max_matches: Max returned candidate regions.

    Returns: JSON with candidate offsets, confidence, nearby strings, and a
    suggested patch kind.
    """
    from apk_agent.tools.dart_aot import locate_dart_aot_candidates as _locate

    def _run():
        try:
            anchors = json.loads(anchors_json)
        except json.JSONDecodeError as exc:
            return json.dumps({"success": False, "error": f"Invalid anchors_json: {exc}"})

        if anchors and not isinstance(anchors, list):
            return json.dumps({"success": False, "error": "anchors_json must decode to a JSON array."})

        source = _resolve_project_path(index_file) if index_file.strip() else _resolve_project_path(file_path)
        result = _locate(
            source,
            query=query,
            anchors=[str(item) for item in (anchors or [])],
            window_bytes=window_bytes,
            max_matches=max_matches,
        )
        return json.dumps(result, ensure_ascii=False, indent=2)[:25000]

    return _safe_call(
        _run,
        "locate_dart_aot_candidates",
        _cache_hint=f"{file_path}:{index_file}:{query}:{anchors_json}:{window_bytes}:{max_matches}",
    )



@tool
def preview_dart_aot_patch(file_path: str, patch_plan_json: str) -> str:
    '''Preview a byte-level patch on a Dart AOT binary without writing to disk.

    Args:
        file_path: Target library path inside the project.
        patch_plan_json: JSON object with 'offset', 'replace_hex', and 'expected_original_hex'.

    Returns: JSON describing the planned patch sizes, hex differences, and safety notes.
    '''
    from apk_agent.tools.dart_aot import preview_dart_aot_patch as _preview
    import json
    
    def _run():
        try:
            plan = json.loads(patch_plan_json)
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})
        
        result = _preview(_resolve_project_path(file_path), plan)
        return json.dumps(result, indent=2)
    return _safe_call(_run, "preview_dart_aot_patch", _cache_hint=f"{file_path}:{patch_plan_json}")

@tool
def apply_dart_aot_patch(file_path: str, patch_plan_json: str) -> str:
    '''Apply a byte-level patch to a Dart AOT binary and record it to the patch journal.

    Args:
        file_path: Target library path inside the project.
        patch_plan_json: JSON object with 'offset', 'replace_hex', and optionally 'description'.

    Returns: JSON indicating success and backup details.
    '''
    from apk_agent.tools.dart_aot import apply_dart_aot_patch as _apply
    import json
    
    def _run():
        try:
            plan = json.loads(patch_plan_json)
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})
            
        real_path = _resolve_project_path(file_path)
        backup_dir = _project.patch_diffs_dir
        result = _apply(real_path, plan, backup_dir=backup_dir)
        
        if result.get("success"):
            # Try to log to the global journal
            try:
                _patch_journal.append({
                    "target_file": str(file_path),
                    "description": plan.get("description", "Dart AOT binary patch"),
                    "steps_applied": 1,
                    "steps_total": 1,
                    "diff_text": f"OFFSET: {result.get('offset_hex')} \nORIGINAL: {result.get('original_hex')}\nREPLACE:  {result.get('replace_hex')}",
                    "tool": "apply_dart_aot_patch",
                    "errors": []
                })
            except Exception:
                pass
                
        return json.dumps(result, indent=2)
    return _safe_call(_run, "apply_dart_aot_patch")

@tool
def validate_dart_aot_patch(file_path: str, offset: int, expected_hex: str) -> str:
    '''Check if exact bytes are present at an offset in a file. Use this post-patch.

    Args:
        file_path: Path to the modified library.
        offset: The integer offset in the binary.
        expected_hex: Hex string of bytes that should be there.

    Returns: JSON indicating validation success or mismatch.
    '''
    from apk_agent.tools.dart_aot import validate_dart_aot_patch as _valid
    import json
    
    def _run():
        result = _valid(_resolve_project_path(file_path), offset=offset, expected_hex=expected_hex)
        return json.dumps(result, indent=2)
    return _safe_call(_run, "validate_dart_aot_patch", _cache_hint=f"{file_path}:{offset}:{expected_hex}")


@tool
def patch_binary_strings(file_path: str, replacements_json: str) -> str:
    """Patch embedded strings in `.so`, `.dex`, `.bundle`, and similar files.

    This is safer and more semantic than blind hex patching because it matches
    string constants by value and enforces file-type-specific length rules.

    Safety rules:
    - `.dex` / `.cdex`: replacement must have identical UTF-8 byte length.
    - `.bundle` / `.jsbundle`: direct UTF-8 text replacement, no NUL padding.
    - Other binaries: replacement may be shorter and will be NUL-padded.
    - Longer replacements are rejected for bounded binary files.

    Args:
        file_path: Target binary file. Can be absolute or relative.
        replacements_json: JSON array like:
            [
              {"old_string": "https://api.old.com", "new_string": "https://api.new.io", "occurrence": 1},
              {"old_string": "frida", "new_string": "frixa", "replace_all": true}
            ]

    Returns: JSON with patched offsets, backup path, and per-replacement results.
    """
    from apk_agent.tools.binary_patch import patch_binary_strings as _patch

    def _run():
        try:
            replacements = json.loads(replacements_json)
        except json.JSONDecodeError as e:
            return json.dumps({"success": False, "error": f"Invalid JSON: {e}"})
        if not isinstance(replacements, list) or not replacements:
            return json.dumps({"success": False, "error": "replacements_json must be a non-empty JSON array."})

        p = _resolve_project_path(file_path)

        backup_name = str(p.name) + ".binpatch.bak"
        backup_path = _project.patch_backup_dir / backup_name
        result = _patch(p, replacements, backup_path=backup_path)

        if result.get("success"):
            _patch_journal.append({
                "success": True,
                "target_file": str(p),
                "description": f"Semantic binary string patch — {result.get('patched_operations', 0)} replacements",
                "steps_applied": result.get("patched_operations", 0),
                "steps_total": result.get("patched_operations", 0),
                "diff_text": json.dumps(result.get("replacements", [])[:5], ensure_ascii=False),
                "errors": [],
                "tool": "patch_binary_strings",
            })

        return json.dumps(result, ensure_ascii=False, indent=2)[:20000]
    return _safe_call(_run, "patch_binary_strings")


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
        return json.dumps(result, ensure_ascii=False, indent=2)[:25000]
    return _safe_call(_run, "analyze_native_libs")


@tool
def analyze_native_re_core(file_path: str) -> str:
    """Deep ELF/JNI analysis for one native library.

    This native reverse-engineering core parses ELF sections, symbol tables,
    imported/exported functions, DT_NEEDED dependencies, JNI exports,
    heuristic function boundaries, and ranked patch targets.
    """
    from apk_agent.tools.native_re_core import analyze_native_binary as _analyze

    def _run():
        result = _analyze(_resolve_project_path(file_path))
        return json.dumps(result, ensure_ascii=False, indent=2)[:30000]

    return _safe_call(_run, "analyze_native_re_core", _cache_hint=str(file_path))


@tool
def plan_native_patch_targets(file_path: str, focus_hint: str = "", max_results: int = 12) -> str:
    """Rank concrete native patch targets for a library before editing bytes."""
    from apk_agent.tools.native_re_core import plan_native_patch_targets as _plan

    def _run():
        result = _plan(_resolve_project_path(file_path), focus_hint=focus_hint, max_results=max_results)
        return json.dumps(result, ensure_ascii=False, indent=2)[:25000]

    return _safe_call(
        _run,
        "plan_native_patch_targets",
        _cache_hint=f"{file_path}:{focus_hint}:{max_results}",
    )


@tool
def route_reverse_engineering_workflow(objective: str = "", focus_hint: str = "") -> str:
    """Classify the current app and return the best RE workflow/tool route."""
    from apk_agent.tools.orchestration_router import route_reverse_engineering_workflow as _route

    def _run():
        result = _route(
            _project.apktool_dir,
            jadx_dir=getattr(_project, "jadx_dir", None),
            objective=objective,
            focus_hint=focus_hint,
        )
        return json.dumps(result, ensure_ascii=False, indent=2)[:25000]

    return _safe_call(
        _run,
        "route_reverse_engineering_workflow",
        _cache_hint=f"{objective}:{focus_hint}",
    )


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


@tool
def find_entry_points() -> str:
    """Discover the full Android entry surface across all DEX files.

    Finds the Application class, launcher activities, services, receivers, and
    other execution entry points in order to recover how the app starts.
    """
    from apk_agent.tools.deep_analysis import find_entry_points as _find

    def _run():
        manifest_path = _project.apktool_dir / "AndroidManifest.xml"
        result = _find(manifest_path, _get_all_smali_dirs())
        return json.dumps(result, ensure_ascii=False, indent=2)[:20000]

    return _safe_call(_run, "find_entry_points")


@tool
def map_hierarchy(target_class: str = "") -> str:
    """Map class inheritance and interface implementation relationships.

    Useful for obfuscated apps where framework interfaces survive renaming and
    help locate the real app-owned implementations.
    """
    from apk_agent.tools.deep_analysis import map_class_hierarchy as _map

    def _run():
        result = _map(_get_all_smali_dirs(), target_class=target_class.strip())
        return json.dumps(result, ensure_ascii=False, indent=2)[:20000]

    return _safe_call(_run, "map_hierarchy", _cache_hint=target_class)


@tool
def validate_patch(file_path: str) -> str:
    """Validate smali syntax for a patched file before build.

    Use after any smali edit to catch invalid opcodes, broken directives, or
    malformed method bodies before running apktool_build.
    """
    from apk_agent.tools.deep_analysis import validate_smali_syntax as _validate

    def _run():
        target = _resolve_file(file_path)
        result = _validate(target)
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]

    return _safe_call(_run, "validate_patch", _cache_hint=file_path)


@tool
def diff_patched_file(original_file: str, patched_file: str) -> str:
    """Show the exact diff between an original file and its patched version."""
    from apk_agent.tools.deep_analysis import diff_smali_files as _diff

    def _run():
        original = _resolve_file(original_file)
        patched = _resolve_file(patched_file)
        result = _diff(original, patched)
        return json.dumps(result, ensure_ascii=False, indent=2)[:20000]

    return _safe_call(_run, "diff_patched_file", _cache_hint=f"{original_file}:{patched_file}")


@tool
def analyze_shared_prefs() -> str:
    """Analyze SharedPreferences usage and likely boolean bypass flags."""
    from apk_agent.tools.deep_analysis import analyze_shared_prefs as _analyze

    def _run():
        search_dirs = [_project.jadx_dir, *_get_all_smali_dirs()]
        result = _analyze(search_dirs)
        return json.dumps(result, ensure_ascii=False, indent=2)[:20000]

    return _safe_call(_run, "analyze_shared_prefs")


@tool
def extract_native_strings(so_file: str, min_length: int = 6) -> str:
    """Extract and classify readable strings from a native `.so` library."""
    from apk_agent.tools.deep_analysis import extract_strings_from_binary as _extract

    def _run():
        target = _resolve_file(so_file)
        result = _extract(target, min_length=min_length)
        return json.dumps(result, ensure_ascii=False, indent=2)[:20000]

    return _safe_call(_run, "extract_native_strings", _cache_hint=f"{so_file}:{min_length}")


@tool
def scan_assets_secrets() -> str:
    """Scan assets and raw/xml resources for embedded secrets and keys."""
    from apk_agent.tools.deep_analysis import scan_assets_for_secrets as _scan

    def _run():
        result = _scan(_project.apktool_dir)
        return json.dumps(result, ensure_ascii=False, indent=2)[:20000]

    return _safe_call(_run, "scan_assets_secrets")


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
        resolved_dir = _resolve_project_path(directory)
        if resolved_dir.is_file():
            resolved_dir = resolved_dir.parent
        base_dirs = [str(resolved_dir)]
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

# Module-level mode flags kept for backwards compatibility.
_auto_mode = False   # Set by CLI when /auto is active
_human_mode = False  # Set by CLI/TG when /human is active (step-by-step)


def _ensure_graph():
    """Load or build the code graph. Returns the graph."""
    cached_graph = get_runtime_slot("code_graph")
    if cached_graph is not None:
        return cached_graph

    from apk_agent.tools.code_graph import load_graph, build_code_graph, save_graph
    from apk_agent.progress import report_progress

    graph_path = _project_outputs_dir() / "call_graph.pickle"
    report_progress(6, "Loading cached code graph")
    G = load_graph(graph_path)
    if G is not None:
        set_runtime_slot("code_graph", G)
        report_progress(18, f"Code graph loaded: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
        return G

    smali_dirs = _get_all_smali_dirs()
    if not smali_dirs:
        return None

    report_progress(8, "Cached graph missing; building code graph")
    G = build_code_graph(smali_dirs, progress_callback=report_progress)
    save_graph(G, graph_path)
    set_runtime_slot("code_graph", G)
    report_progress(18, f"Code graph built: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G


def _ensure_index():
    """Load or build the code index. Returns the index dict."""
    cached_index = get_runtime_slot("code_index")
    if cached_index is not None:
        return cached_index

    from apk_agent.tools.index_cache import load_index, build_code_index, save_index
    from apk_agent.progress import report_progress

    index_path = _project_outputs_dir() / "code_index.json"
    report_progress(6, "Loading cached code index")
    idx = load_index(index_path)
    if idx is not None:
        set_runtime_slot("code_index", idx)
        stats = idx.get("stats", {}) if isinstance(idx, dict) else {}
        report_progress(
            18,
            f"Code index loaded: {stats.get('total_classes', 0)} classes, {stats.get('total_methods', 0)} methods",
        )
        return idx

    smali_dirs = _get_all_smali_dirs()
    if not smali_dirs:
        return None

    report_progress(8, "Cached index missing; building code index")
    idx = build_code_index(smali_dirs, jadx_dir=_project_jadx_dir(),
                           progress_callback=report_progress)
    save_index(idx, index_path)
    set_runtime_slot("code_index", idx)
    stats = idx.get("stats", {}) if isinstance(idx, dict) else {}
    report_progress(
        18,
        f"Code index built: {stats.get('total_classes', 0)} classes, {stats.get('total_methods', 0)} methods",
    )
    return idx


def _ensure_smali_index():
    """Load or build the SmaliIndex IR. Returns the SmaliIndex."""
    cached_smali_index = get_runtime_slot("smali_index")
    if cached_smali_index is not None:
        return cached_smali_index

    from apk_agent.tools.smali_ir import load_index as load_smali_index, build_index as build_smali_idx, save_index as save_smali_index
    from apk_agent.progress import report_progress

    index_path = _project_outputs_dir() / "smali_index.pickle"
    report_progress(6, "Loading cached SmaliIndex")
    idx = load_smali_index(index_path)
    if idx is not None:
        clear_runtime_slots(
            "semantic_architecture_cache",
            "hidden_state_model_cache",
            "guard_surface_profile_cache",
            "architecture_context_cache",
        )
        set_runtime_slot("smali_index", idx)
        report_progress(18, f"SmaliIndex loaded: {len(idx.classes)} classes, {len(idx.methods)} methods")
        return idx

    smali_dirs = _get_all_smali_dirs()
    if not smali_dirs:
        return None

    report_progress(8, "Cached SmaliIndex missing; building SmaliIndex")
    idx = build_smali_idx(smali_dirs, progress_callback=report_progress)
    clear_runtime_slots(
        "semantic_architecture_cache",
        "hidden_state_model_cache",
        "guard_surface_profile_cache",
        "architecture_context_cache",
    )
    set_runtime_slot("smali_index", idx)
    save_smali_index(idx, index_path)
    report_progress(18, f"SmaliIndex built: {len(idx.classes)} classes, {len(idx.methods)} methods")
    return idx


def _app_knowledge_pack_path() -> Path:
    return _project_outputs_dir() / "app_knowledge_pack.json"


def _ensure_app_knowledge_pack(*, auto_build: bool = True, focus_hint: str = ""):
    """Load or build the persisted application knowledge pack."""
    cached_pack = get_runtime_slot("app_knowledge_pack")
    if cached_pack is not None:
        return cached_pack

    from apk_agent.tools.app_knowledge import (
        build_app_knowledge_pack as _build_app_knowledge_pack,
        load_app_knowledge_pack,
        save_app_knowledge_pack,
    )

    pack_path = _app_knowledge_pack_path()
    pack = load_app_knowledge_pack(pack_path)
    if pack is not None:
        set_runtime_slot("app_knowledge_pack", pack)
        return pack

    if not auto_build:
        return None

    idx = _ensure_smali_index()
    if idx is None:
        return None

    pack = _build_app_knowledge_pack(
        idx,
        focus_hint=focus_hint,
        package_name=str(getattr(_project, "package_name", "") or ""),
        app_label=str(getattr(_project, "apk_name", "") or ""),
    )
    save_app_knowledge_pack(pack, pack_path)
    set_runtime_slot("app_knowledge_pack", pack)
    return pack


def _behavior_graph_path() -> Path:
    return _project_outputs_dir() / "behavior_graph.json"


def _ensure_behavior_graph_pack(*, auto_build: bool = True, focus_hint: str = ""):
    """Load or build the persisted unified behavior graph pack."""
    cached_pack = get_runtime_slot("behavior_graph_pack")
    if cached_pack is not None:
        return cached_pack

    from apk_agent.tools.behavior_engine import (
        build_behavior_graph as _build_behavior_graph,
        load_behavior_graph,
        save_behavior_graph,
    )

    pack_path = _behavior_graph_path()
    pack = load_behavior_graph(pack_path)
    if pack is not None:
        set_runtime_slot("behavior_graph_pack", pack)
        return pack

    if not auto_build:
        return None

    idx = _ensure_smali_index()
    if idx is None:
        return None

    graph = _ensure_graph()
    pack = _build_behavior_graph(
        idx,
        graph=graph,
        focus_hint=focus_hint,
        package_name=str(getattr(_project, "package_name", "") or ""),
        app_label=str(getattr(_project, "apk_name", "") or ""),
    )
    save_behavior_graph(pack, pack_path)
    set_runtime_slot("behavior_graph_pack", pack)
    return pack


@tool
def build_graph_and_index() -> str:
    """Build (or rebuild) the code graph and class index from decompiled smali.
    Must have run apktool_decompile first. Building is automatic on first query,
    but call this explicitly after decompilation for best results.

    Creates:
    - Call graph (NetworkX): class→method→calls relationships for instant tracing
    - Code index (JSON): class/method/string lookup for instant search

    NOTE: This does NOT build SmaliIndex. For behavioral analysis tools
    (discover_entity_classes, detect_gate_chain, smart_entity_patch, etc.)
    run build_smali_index separately.

    When to use: Run once after apktool_decompile. Enables all graph_* and index_*
    tools. Re-run only if you decompile a different APK.

    Returns: JSON with keys: success, graph ({nodes, edges, components}),
    index ({classes, methods, strings, packages}).
    """
    from concurrent.futures import ThreadPoolExecutor
    from apk_agent.tools.code_graph import build_code_graph, save_graph
    from apk_agent.tools.index_cache import build_code_index, save_index
    from apk_agent.progress import report_progress

    smali_dirs = _get_all_smali_dirs()
    if not smali_dirs:
        return json.dumps({"success": False, "error": "No smali directories found. Run apktool_decompile first."})

    def _run():
        outputs_dir = _project_outputs_dir()
        jadx_dir = _project_jadx_dir()

        def _build_graph():
            G = build_code_graph(smali_dirs, progress_callback=report_progress)
            graph_path = outputs_dir / "call_graph.pickle"
            g_stats = save_graph(G, graph_path)
            return G, g_stats

        def _build_index():
            idx = build_code_index(
                smali_dirs,
                jadx_dir=jadx_dir,
                progress_callback=report_progress,
            )
            index_path = outputs_dir / "code_index.json"
            i_stats = save_index(idx, index_path)
            return idx, i_stats

        with ThreadPoolExecutor(max_workers=2) as pool:
            graph_future = pool.submit(_build_graph)
            index_future = pool.submit(_build_index)
            G, g_stats = graph_future.result()
            idx, i_stats = index_future.result()

        set_runtime_slot("code_graph", G)
        set_runtime_slot("code_index", idx)

        return json.dumps({
            "success": True,
            "graph": g_stats,
            "index": i_stats,
            "hint": "For SmaliIndex-powered tools (discover_entity_classes, detect_gate_chain, smart_entity_patch), run build_smali_index separately.",
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
    from apk_agent.progress import report_progress
    from apk_agent.tools.code_graph import find_security_methods

    def _run():
        report_progress(2, "Loading or building code graph")
        G = _ensure_graph()
        if G is None:
            return json.dumps({"success": False, "error": "No code graph. Run build_graph_and_index first."})

        report_progress(10, f"Code graph ready: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

        def _scan_progress(pct: float, detail: str) -> None:
            mapped_pct = 10 + max(0.0, min(100.0, pct)) * 0.88
            report_progress(mapped_pct, detail)

        result = find_security_methods(G, progress_callback=_scan_progress)
        total_hits = int(result.get("total_hits", 0) or 0)
        report_progress(
            100,
            f"graph_security_scan complete: {total_hits} hits in {result.get('categories_found', 0)} categories",
        )
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
    from apk_agent.progress import report_progress

    def _run():
        report_progress(2, f"Preparing class index lookup for '{query}'")
        idx = _ensure_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No code index. Run build_graph_and_index first."})
        report_progress(80, f"Searching class index for '{query}'")
        result = lookup_class(idx, query)
        report_progress(100, f"index_lookup_class complete: {result.get('total_matches', 0)} matches")
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
    from apk_agent.progress import report_progress

    def _run():
        report_progress(2, f"Preparing method index lookup for '{method_name}'")
        idx = _ensure_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No code index. Run build_graph_and_index first."})
        report_progress(80, f"Searching method index for '{method_name}'")
        result = lookup_method(idx, method_name)
        report_progress(100, f"index_lookup_method complete: {result.get('total_matches', 0)} matches")
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
    from apk_agent.progress import report_progress

    def _run():
        report_progress(2, f"Preparing unified index lookup for '{query}'")
        idx = _ensure_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No code index. Run build_graph_and_index first."})
        report_progress(80, f"Searching unified index for '{query}'")
        result = lookup_string(idx, query)
        report_progress(100, f"index_lookup_string complete: {result.get('total_matches', 0)} matches")
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
def rename_package_identity(new_package: str, old_package: str = "") -> str:
    """Rename the install-time Android package identity for side-by-side clones.

    Unlike a manifest-only package edit, this also rewrites app-owned provider
    authorities, custom permissions, task affinity, process names, and other
    manifest identifiers that keep conflicting with the original installed app.

    It also normalizes relative component class references to absolute names
    under the original code package so the APK still launches after the new
    install identity is applied.
    """
    from apk_agent.tools.package_renamer import rename_package_identity as _rename

    def _run():
        result = _rename(
            apktool_dir=_project.apktool_dir,
            new_package=new_package.strip(),
            old_package=(old_package.strip() or None),
        )
        changes = result.get("changes_applied") or []
        _patch_journal.append({
            "success": result.get("success", False),
            "target_file": "AndroidManifest.xml",
            "description": f"Package identity rename: {result.get('old_package', '')} -> {result.get('new_package', '')}",
            "steps_applied": len(changes),
            "steps_total": len(changes),
            "errors": [] if result.get("success", False) else [result.get("error", "rename_package_identity failed")],
            "tool": "rename_package_identity",
        })
        return json.dumps(result, ensure_ascii=False, indent=2)
    return _safe_call(_run, "rename_package_identity")


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
# SmaliIndex-powered analysis tools (Tier 1 & 2)
# ---------------------------------------------------------------------------


@tool
def discover_entity_classes(keywords_json: str = '["premium","subscription","license","vip","pro","trial","purchase","billing","paid","plan"]') -> str:
    """Discover ALL entity/model classes related to premium/subscription/licensing.

    Uses SmaliIndex string_index, class/method/field behavior, hidden-state
    recovery, and semantic architecture roles to find likely premium/source-of-
    truth classes. This is the BEST starting point — call this BEFORE
    map_feature_checks or cross_reference_map.

    Much more thorough than text search because it:
    1. Searches string constants inside bytecode (not just class/method names)
    2. Walks class hierarchy to find child classes of known entities
    3. Categorizes each class by role (entity, manager, UI, network, etc.)
    4. Returns classes ranked by relevance (most gate methods first)

    Args:
        keywords_json: JSON array of search keywords. Default covers premium/subscription.

    Returns: JSON with ranked entity_classes, each with class name, file, fields,
    gate_method_count, category, and relevance_score.
    """
    def _run():
        from apk_agent.progress import report_progress
        from apk_agent.tools.advanced_search import _is_third_party_path
        from apk_agent.tools.app_knowledge import query_app_knowledge as _query_app_knowledge
        from apk_agent.tools.behavior_engine import query_behavior_graph as _query_behavior_graph
        from apk_agent.tools.semantic_cache import (
            get_cached_hidden_state_model as _recover_hidden_state_model,
            get_cached_semantic_architecture as _map_semantic_architecture,
        )

        report_progress(2, "Loading SmaliIndex for entity discovery")
        si = _ensure_smali_index()
        if not si:
            return json.dumps({"success": False, "error": "SmaliIndex not available. Run build_graph_and_index first."})

        report_progress(
            8,
            f"SmaliIndex ready: {len(si.classes)} classes, {len(si.string_index)} string literals",
        )

        try:
            raw_keywords = json.loads(keywords_json)
        except json.JSONDecodeError as exc:
            return json.dumps({"success": False, "error": f"Invalid keywords_json: {exc}"})

        focus_terms = [str(keyword).strip().lower() for keyword in raw_keywords if str(keyword).strip()]
        if not focus_terms:
            return json.dumps({"success": False, "error": "No keywords provided."})
        query_blob = " ".join(focus_terms)

        def _emit_progress(start_pct: float, end_pct: float, current: int, total: int, detail: str) -> None:
            if total <= 0:
                report_progress(end_pct, detail)
                return
            interval = max(1, total // 20)
            if current == total or current % interval == 0:
                pct = start_pct + (current / total) * (end_pct - start_pct)
                report_progress(pct, detail)

        candidate_classes: dict[str, dict] = {}
        file_to_classes: dict[str, list[str]] = {}

        def _normalize_path(path_value: str) -> str:
            return path_value.replace("\\", "/").strip()

        def _append_unique(items: list, value, limit: int = 8) -> None:
            if not value:
                return
            if value not in items and len(items) < limit:
                items.append(value)

        def _append_hidden_state_field(entry: dict, field_candidate: dict) -> None:
            field_name = field_candidate.get("field", "") or field_candidate.get("name", "")
            if not field_name:
                return
            payload = {
                "field": field_name,
                "type": field_candidate.get("type", ""),
                "semantic_guess": field_candidate.get("semantic_guess", "state_value"),
                "likely_unlocked_value": field_candidate.get("likely_unlocked_value"),
                "suggested_unlocked_value": field_candidate.get("suggested_unlocked_value"),
                "value_origin": field_candidate.get("value_origin", "semantic_guess"),
                "safe_for_auto_override": field_candidate.get("safe_for_auto_override", False),
                "exact_value_candidates": field_candidate.get("exact_value_candidates", [])[:3],
                "confidence": field_candidate.get("confidence", 0),
            }
            if len(entry["hidden_state_fields"]) < 8 and payload not in entry["hidden_state_fields"]:
                entry["hidden_state_fields"].append(payload)

        def _class_blob(cls_obj) -> str:
            parts: list[str] = [
                cls_obj.name,
                cls_obj.super_class,
                cls_obj.source_file,
                cls_obj.file_path,
                " ".join(cls_obj.interfaces),
            ]
            for field in cls_obj.fields[:24]:
                parts.append(field.name)
                parts.append(field.type)
            for method in cls_obj.methods[:80]:
                parts.append(method.name)
                parts.append(method.signature)
                if method.api_calls:
                    parts.append(" ".join(method.api_calls[:24]))
                if method.string_constants:
                    parts.append(" ".join(method.string_constants[:12]))
            return " ".join(part for part in parts if part).lower()

        def _ensure_candidate(cls_name: str) -> dict | None:
            cls_obj = si.get_class(cls_name)
            if cls_obj is None or _is_third_party_path(cls_obj.file_path):
                return None
            entry = candidate_classes.setdefault(cls_name, {
                "keywords": set(),
                "string_hits": 0,
                "string_examples": [],
                "gate_methods": 0,
                "gate_method_names": [],
                "architecture_roles": set(),
                "architecture_evidence": [],
                "semantic_guesses": set(),
                "hidden_state_fields": [],
                "reader_tags": set(),
                "writer_tags": set(),
                "notes": [],
                "ranking_boost": 0.0,
            })
            entry.setdefault("file", cls_obj.file_path)
            entry.setdefault("super_class", cls_obj.super_class)
            entry.setdefault("fields", [{"name": field.name, "type": field.type} for field in cls_obj.fields[:20]])
            entry.setdefault("total_methods", len(cls_obj.methods))
            return entry

        for cls_name, cls_obj in si.classes.items():
            if _is_third_party_path(cls_obj.file_path):
                continue
            file_to_classes.setdefault(_normalize_path(cls_obj.file_path), []).append(cls_name)

        pack_seeded_classes: set[str] = set()

        try:
            behavior_pack = _ensure_behavior_graph_pack(auto_build=False, focus_hint=query_blob)
        except RuntimeError:
            behavior_pack = None
        if behavior_pack:
            symbol_hints_by_class = {
                item.get("class", ""): item
                for item in behavior_pack.get("behavior", {}).get("symbol_hints", [])
                if item.get("class")
            }
            controls_by_class: dict[str, list[dict]] = {}
            for control in behavior_pack.get("behavior", {}).get("feature_controls", []):
                cls_name = control.get("class", "")
                if cls_name:
                    controls_by_class.setdefault(cls_name, []).append(control)

            behavior_hits = _query_behavior_graph(
                behavior_pack,
                query_blob,
                feature=query_blob,
                max_results=24,
            )
            for match in behavior_hits.get("matches", []):
                cls_name = match.get("class", "")
                entry = _ensure_candidate(cls_name)
                if entry is None:
                    continue
                pack_seeded_classes.add(cls_name)
                hint = symbol_hints_by_class.get(cls_name, {})
                entry["architecture_roles"].update(hint.get("roles", []))
                entry["semantic_guesses"].update(hint.get("semantic_guesses", []))
                entry["ranking_boost"] += float(match.get("match_score", 0) or 0) + float(hint.get("score", 0) or 0)
                for reason in (match.get("evidence", []) or [])[:4]:
                    _append_unique(entry["architecture_evidence"], reason)
                if hint.get("suggested_name"):
                    _append_unique(entry["notes"], f"Behavior hint: {hint.get('suggested_name')}")
                gate_methods = [
                    control.get("method", "")
                    for control in controls_by_class.get(cls_name, [])
                    if control.get("method")
                ]
                if gate_methods:
                    entry["gate_methods"] = max(entry.get("gate_methods", 0), len(gate_methods))
                    entry["gate_method_names"] = gate_methods[:10]
            if pack_seeded_classes:
                report_progress(9, f"Loaded persisted behavior graph seeds: {len(pack_seeded_classes)} classes")

        try:
            app_pack = _ensure_app_knowledge_pack(auto_build=False, focus_hint=query_blob)
        except RuntimeError:
            app_pack = None
        if app_pack:
            entities_by_class = {
                item.get("class", ""): item
                for item in app_pack.get("knowledge", {}).get("entities", [])
                if item.get("class")
            }
            state_fields_by_class: dict[str, list[dict]] = {}
            for field in app_pack.get("knowledge", {}).get("state_fields", []):
                cls_name = field.get("class", "")
                if cls_name:
                    state_fields_by_class.setdefault(cls_name, []).append(field)

            app_hits = _query_app_knowledge(
                app_pack,
                query_blob,
                feature=query_blob,
                max_results=24,
            )
            seeded_before = len(pack_seeded_classes)
            for match in app_hits.get("matches", []):
                cls_name = match.get("class", "")
                entry = _ensure_candidate(cls_name)
                if entry is None:
                    continue
                pack_seeded_classes.add(cls_name)
                entity = entities_by_class.get(cls_name, {})
                entry["architecture_roles"].update(entity.get("roles", []))
                entry["architecture_roles"].update(entity.get("dominant_roles", []))
                entry["ranking_boost"] += float(match.get("match_score", 0) or 0) + float(entity.get("score", 0) or 0)
                for evidence in entity.get("evidence", [])[:4]:
                    _append_unique(entry["architecture_evidence"], evidence)
                for field_candidate in state_fields_by_class.get(cls_name, [])[:6]:
                    entry["semantic_guesses"].add(field_candidate.get("semantic_guess", "state_value"))
                    entry["reader_tags"].update(field_candidate.get("reader_tags", []))
                    entry["writer_tags"].update(field_candidate.get("writer_tags", []))
                    _append_hidden_state_field(entry, field_candidate)
            seeded_now = len(pack_seeded_classes) - seeded_before
            if seeded_now > 0:
                report_progress(9.5, f"Loaded persisted application knowledge seeds: {len(pack_seeded_classes)} classes")

        # 1. Search all string constants by substring instead of exact-key lookup.
        #    SmaliIndex stores usages as (file, line) tuples, not method signatures.
        total_literals = len(si.string_index)
        report_progress(10, f"Scanning {total_literals} string literals for {len(focus_terms)} focus terms")
        for literal_index, (literal, usages) in enumerate(si.string_index.items(), start=1):
            literal_lower = literal.lower()
            matched_terms = [term for term in focus_terms if term in literal_lower]
            if not matched_terms:
                _emit_progress(
                    10,
                    28,
                    literal_index,
                    total_literals,
                    f"String scan: {literal_index}/{total_literals} literals | {len(candidate_classes)} candidates",
                )
                continue
            for file_path, line_number in usages:
                for cls_name in file_to_classes.get(_normalize_path(file_path), []):
                    entry = _ensure_candidate(cls_name)
                    if entry is None:
                        continue
                    entry["string_hits"] += 1
                    entry["ranking_boost"] += 3 + len(matched_terms)
                    entry["keywords"].update(matched_terms)
                    if len(entry["string_examples"]) < 8:
                        entry["string_examples"].append({
                            "literal": literal[:140],
                            "line": line_number,
                            "matched_terms": matched_terms,
                        })
            _emit_progress(
                10,
                28,
                literal_index,
                total_literals,
                f"String scan: {literal_index}/{total_literals} literals | {len(candidate_classes)} candidates",
            )

        # 2. Scan app-owned classes for keyword, billing, and gate-density signals.
        total_classes = len(si.classes)
        report_progress(30, f"Scanning {total_classes} classes for structural gate signals")
        for class_index, (cls_name, cls_obj) in enumerate(si.classes.items(), start=1):
            if _is_third_party_path(cls_obj.file_path):
                _emit_progress(
                    30,
                    52,
                    class_index,
                    total_classes,
                    f"Class scan: {class_index}/{total_classes} | {len(candidate_classes)} seeded candidates",
                )
                continue

            blob = _class_blob(cls_obj)
            matched_terms = [term for term in focus_terms if term in blob]
            billing_context = any(token in blob for token in ("billingclient", "querypurchases", "subscription", "purchase", "entitlement", "revenuecat", "qonversion"))
            serialization_context = any(token in blob for token in ("gson", "moshi", "jackson", "fromjson", "tojson", "org/json", "jsonobject"))

            gate_names: list[str] = []
            compact_getters = 0
            for method in cls_obj.methods:
                if method.name in ("<init>", "<clinit>"):
                    continue
                if method.return_type not in ("Z", "I"):
                    continue
                has_field = any(instr.is_field_access for instr in method.instructions)
                has_branch = any(instr.is_branch for instr in method.instructions)
                if has_field and has_branch:
                    gate_names.append(method.signature)
                elif method.return_type == "Z" and has_field:
                    compact_getters += 1

            structural_score = 0.0
            if matched_terms:
                structural_score += 4 + len(matched_terms) * 2
            if gate_names:
                structural_score += len(gate_names) * 9
            if compact_getters:
                structural_score += compact_getters * 2
            if 2 <= len(cls_obj.fields) <= 40:
                structural_score += 2
            if billing_context:
                structural_score += 6
            if serialization_context and len(cls_obj.fields) >= 3:
                structural_score += 4

            if structural_score < 6:
                _emit_progress(
                    30,
                    52,
                    class_index,
                    total_classes,
                    f"Class scan: {class_index}/{total_classes} | {len(candidate_classes)} seeded candidates",
                )
                continue

            entry = _ensure_candidate(cls_name)
            if entry is None:
                _emit_progress(
                    30,
                    52,
                    class_index,
                    total_classes,
                    f"Class scan: {class_index}/{total_classes} | {len(candidate_classes)} seeded candidates",
                )
                continue
            entry["keywords"].update(matched_terms)
            entry["ranking_boost"] += structural_score
            entry["gate_methods"] = max(entry.get("gate_methods", 0), len(gate_names))
            if gate_names:
                entry["gate_method_names"] = gate_names[:10]
            if billing_context:
                entry["architecture_roles"].add("billing_flow")
            if serialization_context:
                entry["architecture_roles"].add("serialization_layer")
            _emit_progress(
                30,
                52,
                class_index,
                total_classes,
                f"Class scan: {class_index}/{total_classes} | {len(candidate_classes)} seeded candidates",
            )

        has_direct_keyword_signal = any(
            info.get("string_hits", 0) > 0 or info.get("keywords")
            for info in candidate_classes.values()
        )
        should_run_deep_fallback = not (pack_seeded_classes or has_direct_keyword_signal)
        architecture_result: dict = {"recommended_next_targets": []}
        hidden_state_result: dict = {"summary": {}}
        discovery_mode = "string_plus_structure"

        if should_run_deep_fallback:
            discovery_mode = "string_plus_architecture_plus_state_model"
            # 3. Pull in semantic architecture roles for obfuscated/hardened apps.
            report_progress(55, f"Running semantic architecture recovery for {len(candidate_classes)} seeded classes")
            architecture_result = _map_semantic_architecture(si, focus_hint=",".join(focus_terms), max_per_role=10)
            architecture_hits = 0
            for role, ranked in architecture_result.get("architecture_layers", {}).items():
                if role not in {"state_models", "billing_flow", "serialization_layer", "network_layer", "ui_gate_controllers"}:
                    continue
                architecture_hits += len(ranked)
                for item in ranked:
                    entry = _ensure_candidate(item.get("class", ""))
                    if entry is None:
                        continue
                    entry["architecture_roles"].add(role)
                    entry["ranking_boost"] += float(item.get("score", 0) or 0)
                    for evidence in item.get("evidence", [])[:4]:
                        if evidence not in entry["architecture_evidence"]:
                            entry["architecture_evidence"].append(evidence)
            report_progress(68, f"Semantic architecture recovery complete: {architecture_hits} ranked hits")

            # 4. Pull in hidden-state candidates even when obvious keywords are missing.
            report_progress(70, f"Running hidden-state recovery across {len(si.classes)} classes")
            hidden_state_result = _recover_hidden_state_model(si, focus_hint=",".join(focus_terms), max_candidates=60)
            for model in hidden_state_result.get("candidate_models", [])[:20]:
                entry = _ensure_candidate(model.get("class", ""))
                if entry is None:
                    continue
                entry["architecture_roles"].add("state_models")
                entry["ranking_boost"] += float(model.get("score", 0) or 0)
                for evidence in model.get("evidence", [])[:4]:
                    if evidence not in entry["architecture_evidence"]:
                        entry["architecture_evidence"].append(evidence)

            for field_candidate in hidden_state_result.get("candidate_state_fields", [])[:60]:
                entry = _ensure_candidate(field_candidate.get("class", ""))
                if entry is None:
                    continue
                entry["architecture_roles"].add("state_models")
                entry["semantic_guesses"].add(field_candidate.get("semantic_guess", "state_value"))
                entry["reader_tags"].update(field_candidate.get("reader_tags", []))
                entry["writer_tags"].update(field_candidate.get("writer_tags", []))
                entry["ranking_boost"] += float(field_candidate.get("score", 0) or 0) + float(field_candidate.get("confidence", 0) or 0) * 8
                _append_hidden_state_field(entry, field_candidate)
            report_progress(
                84,
                "Hidden-state recovery complete: "
                f"{len(hidden_state_result.get('candidate_models', []))} models, "
                f"{len(hidden_state_result.get('candidate_state_fields', []))} field candidates",
            )
        else:
            if pack_seeded_classes:
                discovery_mode = "pack_plus_string_plus_structure"
            report_progress(
                84,
                "Fast-path discovery sufficient; skipping whole-project semantic fallback",
            )

        # 5. Expand subclasses of strong state candidates.
        seeded_classes = list(candidate_classes.keys())
        report_progress(86, f"Expanding subclasses from {len(seeded_classes)} seeded classes")
        for seed_index, cls_name in enumerate(seeded_classes, start=1):
            parent_info = candidate_classes.get(cls_name, {})
            for sub in si.get_subclasses(cls_name)[:5]:
                sub_entry = _ensure_candidate(sub)
                if sub_entry is None:
                    continue
                sub_entry["keywords"].update(parent_info.get("keywords", set()))
                sub_entry["ranking_boost"] += max(float(parent_info.get("ranking_boost", 0)) * 0.25, 2)
                if "state_models" in parent_info.get("architecture_roles", set()):
                    sub_entry["architecture_roles"].add("state_models")
                note = f"Child class of {cls_name}"
                if note not in sub_entry["notes"]:
                    sub_entry["notes"].append(note)
            _emit_progress(
                86,
                92,
                seed_index,
                len(seeded_classes),
                f"Subclass expansion: {seed_index}/{len(seeded_classes)} seeds | {len(candidate_classes)} candidates",
            )

        # 6. Categorize and rank.
        results = []
        ranked_candidates = list(candidate_classes.items())
        report_progress(93, f"Ranking {len(ranked_candidates)} candidate entity classes")
        for rank_index, (cls_name, info) in enumerate(ranked_candidates, start=1):
            roles = set(info.get("architecture_roles", set()))
            name_lower = cls_name.lower()
            if "state_models" in roles:
                category = "entity"
            elif "billing_flow" in roles and ("network_layer" in roles or "serialization_layer" in roles):
                category = "manager"
            elif any(w in name_lower for w in ("activity", "fragment", "view", "adapter", "dialog")):
                category = "UI"
            elif any(w in name_lower for w in ("manager", "helper", "util", "service", "handler")):
                category = "manager"
            elif any(w in name_lower for w in ("api", "request", "response", "client", "network")):
                category = "network"
            elif any(w in name_lower for w in ("entity", "model", "bean", "dto", "info", "data")):
                category = "entity"
            else:
                category = "other"

            score = (
                info.get("gate_methods", 0) * 10
                + info.get("string_hits", 0) * 2
                + len(info.get("keywords", set())) * 3
                + float(info.get("ranking_boost", 0))
            )
            if category == "entity":
                score += 5
            if "billing_flow" in roles:
                score += 4
            if "network_layer" in roles and "serialization_layer" in roles:
                score += 3

            results.append({
                "class": cls_name,
                "file": info.get("file", ""),
                "category": category,
                "relevance_score": round(score, 2),
                "gate_methods": info.get("gate_methods", 0),
                "gate_method_names": info.get("gate_method_names", []),
                "keywords_matched": sorted(info.get("keywords", set())),
                "string_hits": info.get("string_hits", 0),
                "string_examples": info.get("string_examples", []),
                "fields": info.get("fields", [])[:10],
                "super_class": info.get("super_class", ""),
                "architecture_roles": sorted(roles),
                "architecture_evidence": info.get("architecture_evidence", [])[:6],
                "semantic_guesses": sorted(info.get("semantic_guesses", set())),
                "hidden_state_fields": info.get("hidden_state_fields", [])[:6],
                "reader_tags": sorted(info.get("reader_tags", set())),
                "writer_tags": sorted(info.get("writer_tags", set())),
                "notes": info.get("notes", [])[:6],
            })
            _emit_progress(
                93,
                99,
                rank_index,
                len(ranked_candidates),
                f"Ranking candidates: {rank_index}/{len(ranked_candidates)}",
            )

        results.sort(key=lambda x: (-x["relevance_score"], -x["gate_methods"], x["class"]))
        report_progress(100, f"discover_entity_classes complete: {len(results)} ranked classes")

        return json.dumps({
            "success": True,
            "discovery_mode": discovery_mode,
            "total_entity_classes": len(results),
            "architecture_summary": architecture_result.get("recommended_next_targets", [])[:4],
            "hidden_state_summary": hidden_state_result.get("summary", {}),
            "entity_classes": results[:30],
            "instruction": (
                f"Found {len(results)} subscription/premium-related classes. "
                "Prioritize classes with state_models/billing_flow roles and hidden_state_fields before patching UI symptoms. "
                "For each top class: 1) cross_reference_map to see full usage, 2) analyze_subscription_model to find gate methods, "
                "3) smart_entity_patch(mode='preview') or generate_constructor_override to plan the root-cause bypass."
            ),
        }, ensure_ascii=False, indent=2)[:20000]

    return _safe_call(_run, "discover_entity_classes")


@tool
def detect_gate_chain(start_class: str) -> str:
    """Detect and trace the full CHAIN of gate methods from an entity class.

    Follows call chains across classes to find ALL methods that ultimately
    control a feature gate. For example: Activity.checkPremium() -> Manager.isPro()
    -> Entity.getType() -> field read. ALL methods in this chain must be patched.

    Uses SmaliIndex api_callers to build the REVERSE call graph, then walks
    UP from entity gate methods to find every caller chain.

    Args:
        start_class: Smali class descriptor of the entity class, e.g. 'Lcom/app/UserInfo;'

    Returns: JSON with gate_chains — each chain shows the path from UI down to
    the entity gate, with file locations and patch recommendations.
    """
    def _run():
        si = _ensure_smali_index()
        if not si:
            return json.dumps({"success": False, "error": "SmaliIndex not available. Run build_graph_and_index first."})

        cls_obj = si.get_class(start_class)
        if not cls_obj:
            return json.dumps({"success": False, "error": f"Class {start_class} not found in SmaliIndex."})

        # Find gate methods in this class
        gate_methods = []
        for method in cls_obj.methods:
            if method.name in ("<init>", "<clinit>"):
                continue
            if method.return_type not in ("Z", "I", "Ljava/lang/String;"):
                continue
            has_field = any(i.is_field_access for i in method.instructions)
            has_branch = any(i.is_branch and i.opcode.startswith("if-") for i in method.instructions)
            if has_field and (has_branch or method.return_type == "Z"):
                gate_methods.append(method)

        chains: list[dict] = []

        for gate in gate_methods[:15]:
            # Build call chain upward from this gate method
            full_sig = f"{start_class}->{gate.signature}"
            chain: list[dict] = [{"method": full_sig, "class": start_class, "depth": 0, "type": "gate_source"}]

            visited = {full_sig}
            frontier = [full_sig]
            depth = 0

            while frontier and depth < 4:
                depth += 1
                next_frontier = []
                for method_sig in frontier:
                    callers = si.find_api_callers(method_sig)
                    for caller in callers[:10]:
                        if caller in visited:
                            continue
                        visited.add(caller)
                        caller_cls = caller.split("->")[0] if "->" in caller else ""
                        caller_method = si.get_method(caller)
                        chain.append({
                            "method": caller[:120],
                            "class": caller_cls,
                            "depth": depth,
                            "type": "caller",
                            "file": caller_method.full_signature if caller_method else "",
                        })
                        next_frontier.append(caller)
                frontier = next_frontier

            if len(chain) > 1:
                chains.append({
                    "gate_method": gate.signature,
                    "gate_return_type": gate.return_type,
                    "chain_length": len(chain),
                    "chain": chain[:20],
                    "patch_all": [c["method"] for c in chain if c["type"] == "caller"][:10],
                })

        return json.dumps({
            "success": True,
            "start_class": start_class,
            "total_gates": len(gate_methods),
            "chains_found": len(chains),
            "gate_chains": chains[:20],
            "instruction": (
                f"Found {len(chains)} gate chains from {start_class}. "
                f"CRITICAL: Each chain shows every method between UI and the entity gate. "
                f"You must patch the gate_source AND any intermediate caller that also checks "
                f"the return value. Use batch_patch_methods with all methods from 'patch_all'."
            ),
        }, ensure_ascii=False, indent=2)[:20000]

    return _safe_call(_run, "detect_gate_chain")


@tool
def trace_field_writers(class_descriptor: str, field_name: str) -> str:
    """Trace ALL code that WRITES to a specific field across the entire codebase.

    Uses SmaliIndex to find every iput/sput instruction targeting a field,
    then traces back to understand WHAT VALUE is being written and WHERE
    the write originates (constructor, setter, deserializer, network callback).

    More powerful than trace_field_access because it:
    1. Uses SmaliIndex for instant lookup (no file scanning)
    2. Analyzes the VALUE being written (constant, parameter, method result)
    3. Identifies the write CONTEXT (constructor init, setter, JSON parse, etc.)

    Args:
        class_descriptor: Smali class descriptor, e.g. 'Lcom/app/UserInfo;'
        field_name: Name of the field to trace, e.g. 'isPremium' or 'w'

    Returns: JSON with writers — each shows the writing method, value analysis,
    and context (is it a constructor, setter, deserializer, etc.).
    """
    def _run():
        si = _ensure_smali_index()
        if not si:
            return json.dumps({"success": False, "error": "SmaliIndex not available. Run build_graph_and_index first."})

        target_field = f"{class_descriptor}->{field_name}"
        writers: list[dict] = []
        readers: list[dict] = []

        for method_sig, method_obj in si.methods.items():
            for instr in method_obj.instructions:
                if not instr.is_field_access:
                    continue
                if field_name not in (instr.target_field or ""):
                    continue
                if class_descriptor[1:-1] not in (instr.target_field or ""):
                    continue

                entry = {
                    "method": method_sig[:120],
                    "opcode": instr.opcode,
                    "line": instr.line,
                    "raw": instr.raw[:120],
                }

                # Determine write context
                method_name = method_sig.split("->")[1] if "->" in method_sig else ""
                if "<init>" in method_name:
                    entry["context"] = "constructor"
                elif "set" in method_name.lower() or "put" in method_name.lower():
                    entry["context"] = "setter"
                elif any(w in method_name.lower() for w in ("parse", "deserialize", "from", "read", "decode")):
                    entry["context"] = "deserializer"
                elif any(w in method_name.lower() for w in ("on", "callback", "handle", "receive")):
                    entry["context"] = "callback"
                else:
                    entry["context"] = "other"

                # Analyze what's being written (look at preceding instructions)
                if instr.opcode.startswith(("iput", "sput")):
                    # Check if a const was loaded just before
                    idx = method_obj.instructions.index(instr)
                    if idx > 0:
                        prev = method_obj.instructions[idx - 1]
                        if prev.const_value is not None:
                            entry["written_value"] = str(prev.const_value)
                        elif prev.string_value:
                            entry["written_value"] = prev.string_value
                        elif prev.is_invoke:
                            entry["written_value"] = f"return of {prev.target_method or prev.raw[:60]}"
                    writers.append(entry)
                elif instr.opcode.startswith(("iget", "sget")):
                    readers.append(entry)

        return json.dumps({
            "success": True,
            "target_field": target_field,
            "total_writers": len(writers),
            "total_readers": len(readers),
            "writers": writers[:30],
            "readers": readers[:20],
            "instruction": (
                f"Found {len(writers)} write sites for {target_field}. "
                + (f"CRITICAL: {sum(1 for w in writers if w['context'] == 'deserializer')} writes come from "
                   f"deserializers — these will OVERWRITE your patches when data refreshes from server. "
                   f"You MUST also patch the deserializer or intercept the network response."
                   if any(w["context"] == "deserializer" for w in writers) else
                   f"Patch the field initialization in constructors AND any setter methods.")
            ),
        }, ensure_ascii=False, indent=2)[:15000]

    return _safe_call(_run, "trace_field_writers")


@tool
def validate_patch_completeness(target_class: str) -> str:
    """Validate that ALL gate methods for a class have been successfully patched.

    Reads the current state of smali files and checks:
    1. Every gate method has patch markers (APK-AGI comments)
    2. No gate methods were MISSED
    3. Child class gates are also patched
    4. Field writers that could overwrite patches are handled
    5. Dynamic checks (reflection, class loading) are neutralized

    Run this AFTER patching to ensure nothing was missed.

    Args:
        target_class: Smali class descriptor, e.g. 'Lcom/app/UserInfo;'

    Returns: JSON with validation results — patched_methods, unpatched_methods,
    unpatched_child_gates, field_write_risks, overall_score.
    """
    def _run():
        si = _ensure_smali_index()
        cls_obj = si.get_class(target_class) if si else None

        apk_dir = _project.apktool_dir
        patched_methods: list[dict] = []
        unpatched_methods: list[dict] = []

        # Check the target class file
        if cls_obj and cls_obj.abs_path:
            try:
                content = Path(cls_obj.abs_path).read_text(encoding="utf-8", errors="replace")
            except Exception:
                content = ""
        else:
            # Find by class name
            class_path = target_class[1:-1] + ".smali"
            smali_dirs = [d for d in apk_dir.iterdir() if d.is_dir() and d.name.startswith("smali")]
            content = ""
            for sd in smali_dirs:
                f = sd / class_path
                if f.exists():
                    content = f.read_text(encoding="utf-8", errors="replace")
                    break

        # Parse methods and check for patches
        import re
        methods_in_file = re.findall(r'\.method\s+(.+?)$', content, re.MULTILINE)
        for method_sig in methods_in_file:
            # Find this method's body
            pat = re.compile(rf'\.method\s+{re.escape(method_sig)}.*?\.end method', re.DOTALL)
            m = pat.search(content)
            if not m:
                continue
            body = m.group(0)
            is_gate = ("return" in body) and any(rt in method_sig for rt in ("Z", ")I"))
            has_patch = "APK-AGI" in body or "apk-agi" in body.lower()

            if is_gate:
                info = {"method": method_sig[:80], "patched": has_patch}
                if has_patch:
                    patched_methods.append(info)
                else:
                    # Check if it's actually a gate (boolean return with field/branch)
                    has_field_access = bool(re.search(r'[is]get-\w+', body))
                    has_branch = bool(re.search(r'if-\w+', body))
                    if has_field_access and has_branch:
                        info["is_gate"] = True
                        unpatched_methods.append(info)

        # Check child classes
        unpatched_children: list[dict] = []
        if si:
            children = si.get_subclasses(target_class)
            for child in children[:10]:
                child_cls = si.get_class(child)
                if child_cls and child_cls.abs_path:
                    try:
                        child_content = Path(child_cls.abs_path).read_text(encoding="utf-8", errors="replace")
                        child_gates = re.findall(r'\.method\s+(.*?(?:Z|I)\s*)$', child_content, re.MULTILINE)
                        for cg in child_gates:
                            if "APK-AGI" not in child_content:
                                unpatched_children.append({"class": child, "method": cg[:80]})
                    except Exception:
                        pass

        total_gates = len(patched_methods) + len(unpatched_methods)
        score = (len(patched_methods) / total_gates * 100) if total_gates > 0 else 0

        return json.dumps({
            "success": True,
            "target_class": target_class,
            "total_gate_methods": total_gates,
            "patched_count": len(patched_methods),
            "unpatched_count": len(unpatched_methods),
            "patched_methods": patched_methods,
            "unpatched_methods": unpatched_methods,
            "unpatched_child_gates": unpatched_children[:20],
            "completeness_score": round(score, 1),
            "instruction": (
                f"Patch completeness: {score:.0f}% ({len(patched_methods)}/{total_gates} gates patched). "
                + (f"⚠️ {len(unpatched_methods)} UNPATCHED gate methods remain — patch these NOW. "
                   if unpatched_methods else "All gate methods in this class are patched. ")
                + (f"⚠️ {len(unpatched_children)} CHILD CLASS gates unpatched — these can override your patches!"
                   if unpatched_children else "")
            ),
        }, ensure_ascii=False, indent=2)[:15000]

    return _safe_call(_run, "validate_patch_completeness")


@tool
def smart_entity_patch(
    class_descriptor: str,
    mode: str = "auto",
    planner_context: str = "",
) -> str:
    """One-shot intelligent patching of an entity class and all its gates.

    Combines discover + analyze + patch in a single call:
    1. Finds all gate methods (boolean/int return with field+branch)
    2. Determines the correct return value for each (using NEGATIVE/POSITIVE semantics)
    3. Generates and applies patches for ALL gates at once
    4. Also patches child class constructors to force field values
    5. Validates the result

    This is the FASTEST way to bypass an entity class — one tool call instead of 5+.
    Use mode='preview' to see what would be patched without applying.

    Args:
        class_descriptor: Smali class descriptor, e.g. 'Lcom/app/UserInfo;'
        mode: 'auto' (apply all patches), 'preview' (show what would be patched)
        planner_context: Optional free-form hypothesis from the agent. This is
            not a keyword list; it can be any runtime note about server sync,
            lifecycle revalidation, account creation, overwritten fields, etc.

    Returns: JSON with patches_applied or patches_preview, validation results.
    """
    def _run():
        from apk_agent.tools.semantic_graph import find_enforcement_surfaces as _find_surfaces
        from apk_agent.tools.semantic_cache import get_cached_hidden_state_model as _recover_hidden_state_model
        from apk_agent.tools.api_response_patcher import patch_api_response_flow as _patch_api_response_flow

        import re

        si = _ensure_smali_index()
        cls_obj = si.get_class(class_descriptor) if si else None
        graph = _ensure_graph()

        if not cls_obj:
            return json.dumps({"success": False, "error": f"Class {class_descriptor} not found. Run build_graph_and_index first."})
        assert si is not None

        # Semantic keywords for determining positive vs negative
        _NEGATIVE = {"expired", "expire", "isexpired", "istrial", "istrialing",
                      "isblocked", "banned", "disabled", "locked", "restricted",
                      "isads", "showads", "hasads", "needpay", "shouldpay"}
        _POSITIVE = {"ispremium", "ispro", "isvip", "issvip", "issubscribed",
                      "isactivated", "isunlocked", "ispurchased", "haslicense",
                      "ispaid", "isgold", "isplatinum", "unlimited"}
        _ROLE_PRIORITY = {
            "gate_method": 0,
            "revalidation_boundary": 1,
            "state_mutator": 2,
            "gate_accessor": 3,
            "candidate": 4,
            "legacy_gate": 5,
        }
        _EXECUTION_PRIORITY = {
            "revalidation_boundary": 0,
            "state_mutator": 1,
            "gate_method": 2,
            "gate_accessor": 3,
            "candidate": 4,
            "legacy_gate": 5,
        }

        def _runtime_planner_context() -> str:
            parts: list[str] = []
            if planner_context.strip():
                parts.append(planner_context.strip())
            scratchpad = _get_scratchpad()
            for key in (
                "planner_context",
                "analysis_hypothesis",
                "feature_hypothesis",
                "revalidation_hypothesis",
                "server_state_notes",
                "target_state_model",
            ):
                value = scratchpad.get(key)
                if isinstance(value, str) and value.strip():
                    parts.append(value.strip())
            deduped: list[str] = []
            seen: set[str] = set()
            for part in parts:
                lowered = part.lower()
                if lowered in seen:
                    continue
                seen.add(lowered)
                deduped.append(part)
            return " | ".join(deduped)[:600]

        def _response_override_plan() -> tuple[dict[str, dict], list[dict], dict, list[dict]]:
            hidden_state_result = _recover_hidden_state_model(
                si,
                focus_hint=_runtime_planner_context(),
                max_candidates=60,
            )
            if not hidden_state_result.get("success"):
                return {}, [], hidden_state_result, []

            candidates: list[dict] = []
            suppressed_guess_only: list[dict] = []
            for item in hidden_state_result.get("candidate_state_fields", []):
                if item.get("class") != class_descriptor:
                    continue
                if not bool(item.get("safe_for_auto_override", False)):
                    if item.get("suggested_unlocked_value") is not None or item.get("likely_unlocked_value") is not None:
                        suppressed_guess_only.append(item)
                    continue
                if item.get("likely_unlocked_value") is None:
                    continue
                confidence = float(item.get("confidence", 0) or 0)
                if confidence < 0.45:
                    continue
                writer_tags = {str(tag) for tag in item.get("writer_tags", [])}
                strategy = str(item.get("recommended_patch_strategy", ""))
                if strategy != "constructor_or_response_override" and not (writer_tags & {"network", "serialization", "billing"}):
                    continue
                candidates.append(item)

            candidates.sort(
                key=lambda item: (
                    -float(item.get("confidence", 0) or 0),
                    -float(item.get("score", 0) or 0),
                    str(item.get("field", "")),
                )
            )

            field_overrides: dict[str, dict] = {}
            override_preview: list[dict] = []
            for item in candidates:
                field_name = str(item.get("field", "")).strip()
                if not field_name or field_name in field_overrides:
                    continue
                field_overrides[field_name] = {
                    "type": item.get("type", ""),
                    "value": item.get("likely_unlocked_value"),
                }
                override_preview.append({
                    "field": field_name,
                    "type": item.get("type", ""),
                    "value": item.get("likely_unlocked_value"),
                    "suggested_unlocked_value": item.get("suggested_unlocked_value"),
                    "semantic_guess": item.get("semantic_guess", "state_value"),
                    "confidence": item.get("confidence", 0),
                    "value_origin": item.get("value_origin", "semantic_guess"),
                    "safe_for_auto_override": item.get("safe_for_auto_override", False),
                    "exact_value_candidates": item.get("exact_value_candidates", [])[:3],
                    "recommended_patch_strategy": item.get("recommended_patch_strategy", ""),
                    "writer_tags": item.get("writer_tags", []),
                    "reader_tags": item.get("reader_tags", []),
                })
                if len(field_overrides) >= 8:
                    break

            return field_overrides, override_preview, hidden_state_result, suppressed_guess_only

        class_package = ""
        if class_descriptor.startswith("L") and "/" in class_descriptor:
            class_package = class_descriptor[1:class_descriptor.rfind("/")]

        def _surface_links_to_class(surface: dict) -> bool:
            for caller in surface.get("direct_callers", []):
                if class_descriptor in caller.get("method", ""):
                    return True
            for callee in surface.get("direct_callees", []):
                if class_descriptor == callee.get("class", "") or class_descriptor in callee.get("method", ""):
                    return True
            surface_class = str(surface.get("class", ""))
            return bool(class_package and surface_class.startswith(f"L{class_package}"))

        semantic_context = _runtime_planner_context()
        semantic_result = _find_surfaces(si, semantic_context, graph=graph, max_results=160)
        semantic_surfaces = semantic_result.get("surfaces", []) if semantic_result.get("success") else []
        same_class_surfaces: dict[str, dict] = {}
        companion_by_method: dict[str, dict] = {}

        for surface in semantic_surfaces:
            if surface.get("third_party_path"):
                continue
            method_sig = surface.get("method", "")
            if not method_sig:
                continue
            if surface.get("class") == class_descriptor:
                same_class_surfaces[method_sig] = surface
                continue
            if surface.get("surface_role") not in {"revalidation_boundary", "state_mutator"}:
                continue
            if not _surface_links_to_class(surface):
                continue
            companion_by_method[method_sig] = {
                "method": method_sig,
                "class": surface.get("class", ""),
                "file": surface.get("file", ""),
                "surface_role": surface.get("surface_role", "candidate"),
                "score": surface.get("score", 0),
                "api_categories": surface.get("api_categories", []),
                "reasons": surface.get("reasons", [])[:3],
                "recommended_tool": (
                    "patch_api_response_flow"
                    if surface.get("surface_role") == "revalidation_boundary"
                    else "trace_field_access"
                ),
            }

        companion_surfaces = sorted(
            companion_by_method.values(),
            key=lambda item: (_EXECUTION_PRIORITY.get(item["surface_role"], 99), -int(item.get("score", 0)), item["method"]),
        )[:8]
        response_field_overrides, response_override_preview, hidden_state_result, suppressed_guess_only = _response_override_plan()
        auto_response_flow = {
            "eligible": bool(companion_surfaces and response_field_overrides),
            "attempted": False,
            "applied": False,
            "recommended_tool": "patch_api_response_flow",
            "field_overrides": response_field_overrides,
            "override_preview": response_override_preview,
            "suppressed_guess_only_fields": [str(item.get("field", "")).strip() for item in suppressed_guess_only if str(item.get("field", "")).strip()],
            "hidden_state_summary": hidden_state_result.get("summary", {}) if isinstance(hidden_state_result, dict) else {},
        }
        if companion_surfaces and not response_field_overrides:
            if suppressed_guess_only:
                auto_response_flow["reason"] = (
                    "Companion revalidation/state writers were found, but only heuristic field suggestions were recovered. "
                    "Automatic response-boundary overrides were disabled to avoid inventing server-facing enum/tier/string values. "
                    "Trace field writers or compare accepted literals before patching constructors or response handlers."
                )
            else:
                auto_response_flow["reason"] = (
                    "Companion revalidation/state writers were found, but hidden-state recovery did not yield "
                    "high-confidence response-boundary field overrides for this class."
                )

        gates: list[dict] = []
        patches: list[dict] = []

        for method in cls_obj.methods:
            if method.name in ("<init>", "<clinit>"):
                continue
            if method.return_type not in ("Z", "I"):
                continue

            has_field = any(i.is_field_access for i in method.instructions)
            has_branch = any(i.is_branch and i.opcode.startswith("if-") for i in method.instructions)
            if not (has_field and has_branch):
                # Also catch simple boolean getters (field read + return)
                if method.return_type == "Z" and has_field:
                    pass  # Still treat as gate
                else:
                    continue

            # Determine correct return value using semantics
            name_lower = method.name.lower()
            if name_lower in _NEGATIVE or any(neg in name_lower for neg in ("expire", "block", "disable", "ban", "ads", "trial")):
                target_value = 0  # Negative semantics → return false/0
                semantics = "NEGATIVE"
            elif name_lower in _POSITIVE or any(pos in name_lower for pos in ("premium", "pro", "vip", "subscribe", "license", "unlock", "paid", "purchase")):
                target_value = 1  # Positive semantics → return true/1
                semantics = "POSITIVE"
            else:
                target_value = 1  # Default: return true (most gates are "isPremium"-style)
                semantics = "DEFAULT_POSITIVE"

            surface = same_class_surfaces.get(method.full_signature)
            if surface is None and same_class_surfaces and semantics == "DEFAULT_POSITIVE":
                # Semantic surfaces already identified stronger root-cause targets for this class.
                # Skip neutral fallback gates unless the semantic planner explicitly selected them.
                continue

            surface_role = surface.get("surface_role", "legacy_gate") if surface else "legacy_gate"
            selection_source = "semantic_surface" if surface else "legacy_gate_fallback"
            semantic_score = int(surface.get("score", 0)) if surface else None
            patch_priority = (
                0 if selection_source == "semantic_surface" else 1,
                _ROLE_PRIORITY.get(surface_role, 99),
                -int(semantic_score or 0),
                method.signature,
            )

            gate_info = {
                "method": method.signature,
                "return_type": method.return_type,
                "semantics": semantics,
                "target_value": target_value,
                "complexity": method.complexity,
                "surface_role": surface_role,
                "selection_source": selection_source,
                "semantic_score": semantic_score,
                "semantic_reasons": surface.get("reasons", [])[:3] if surface else [],
                "plan_tier": "primary" if selection_source == "semantic_surface" else "fallback",
                "_sort_key": patch_priority,
            }
            gates.append(gate_info)

            # Generate smali patch
            if method.return_type == "Z":
                patch_code = f"    const/4 v0, {hex(target_value)}  # APK-AGI: smart_entity_patch ({semantics})\n    return v0"
            else:
                patch_code = f"    const/4 v0, {hex(target_value)}  # APK-AGI: smart_entity_patch ({semantics})\n    return v0"

            patches.append({
                "file": cls_obj.abs_path or cls_obj.file_path,
                "method": method.signature,
                "patch_code": patch_code,
                "semantics": semantics,
                "target_value": target_value,
                "surface_role": surface_role,
                "selection_source": selection_source,
                "semantic_score": semantic_score,
                "semantic_reasons": surface.get("reasons", [])[:3] if surface else [],
                "plan_tier": "primary" if selection_source == "semantic_surface" else "fallback",
                "_sort_key": patch_priority,
            })

        gates.sort(key=lambda item: item["_sort_key"])
        patches.sort(key=lambda item: item["_sort_key"])
        for gate in gates:
            gate.pop("_sort_key", None)
        for patch in patches:
            patch.pop("_sort_key", None)

        execution_order = [
            {
                "phase": "pre_gate_followup",
                "surface_role": surface["surface_role"],
                "recommended_tool": surface["recommended_tool"],
                "method": surface["method"],
                "class": surface["class"],
                "score": surface["score"],
                "why": surface["reasons"],
            }
            for surface in companion_surfaces
        ]
        execution_order.extend(
            {
                "phase": "gate_patch",
                "surface_role": patch["surface_role"],
                "recommended_tool": "smart_entity_patch",
                "method": patch["method"],
                "class": class_descriptor,
                "score": patch["semantic_score"],
                "why": patch["semantic_reasons"],
            }
            for patch in patches
        )

        semantic_plan = {
            "planner_mode": "revalidation_first_semantic_surface",
            "planner_context": semantic_context,
            "same_class_semantic_hits": len(same_class_surfaces),
            "primary_patch_targets": [
                {
                    "method": patch["method"],
                    "surface_role": patch["surface_role"],
                    "semantic_score": patch["semantic_score"],
                    "selection_source": patch["selection_source"],
                    "target_value": patch["target_value"],
                    "semantics": patch["semantics"],
                    "reasons": patch["semantic_reasons"],
                }
                for patch in patches
                if patch["selection_source"] == "semantic_surface"
            ],
            "fallback_gate_targets": [
                {
                    "method": patch["method"],
                    "surface_role": patch["surface_role"],
                    "selection_source": patch["selection_source"],
                    "target_value": patch["target_value"],
                    "semantics": patch["semantics"],
                }
                for patch in patches
                if patch["selection_source"] != "semantic_surface"
            ],
            "companion_followups": companion_surfaces,
            "execution_order": execution_order,
            "preferred_first_action": execution_order[0] if execution_order else None,
            "requires_companion_followups_before_build": bool(companion_surfaces),
            "role_summary": semantic_result.get("role_summary", {}) if semantic_result.get("success") else {},
            "auto_response_flow": auto_response_flow,
            "recommended_followups": (
                [
                    "Start with linked revalidation_boundary methods via patch_api_response_flow before relying on gate patches if server/account sync rewrites state.",
                    "Trace companion state_mutator field writers/readers before build if cached or lifecycle state keeps reverting.",
                ]
                if companion_surfaces else
                []
            ),
        }

        preview_instruction = f"Preview: {len(patches)} patches ready. Call again with mode='auto' to apply."
        if auto_response_flow["eligible"]:
            preview_instruction = (
                f"Semantic planner found {len(companion_surfaces)} linked revalidation/state writers and recovered "
                f"{len(response_field_overrides)} state field override(s) for this class. "
                "Auto mode will run patch_api_response_flow before gate-only patches so server/account creation cannot restore the free/default state. "
            ) + preview_instruction
        elif companion_surfaces and suppressed_guess_only:
            preview_instruction = (
                f"Semantic planner found {len(companion_surfaces)} linked revalidation/state writers, but recovered only heuristic field suggestions "
                f"for {len(suppressed_guess_only)} field(s). Auto mode will not synthesize enum/tier/string values that were not proven by code evidence. "
            ) + preview_instruction + (
                " Recover exact accepted values first via field writers/readers before patching constructors or response handlers."
            )
        elif companion_surfaces:
            preview_instruction = (
                f"Semantic planner ranked {len(companion_surfaces)} linked revalidation/state writers ahead of direct gate patches. "
                "Start with companion_followups or execution_order[0] before relying on gate-only patches. "
            ) + preview_instruction + (
                " Use patch_api_response_flow or trace_field_access before building if server/account creation can overwrite state."
            )

        if mode == "preview":
            return json.dumps({
                "success": True,
                "mode": "preview",
                "class": class_descriptor,
                "total_gates": len(gates),
                "gates": gates,
                "semantic_plan": semantic_plan,
                "patches_preview": patches,
                "instruction": preview_instruction,
            }, ensure_ascii=False, indent=2)[:15000]

        # Apply patches
        applied = []
        failed = []
        response_flow_result = None

        if auto_response_flow["eligible"]:
            auto_response_flow["attempted"] = True
            response_flow_result = _patch_api_response_flow(
                si,
                _project.apktool_dir,
                class_descriptor,
                response_field_overrides,
                strategy="full_pipeline",
                backup_dir=_project.patch_backup_dir,
                max_factory_methods=max(8, len(companion_surfaces) * 2),
                dry_run=False,
            )
            auto_response_flow["patch_result"] = response_flow_result
            auto_response_flow["applied"] = bool(response_flow_result.get("success"))
            if response_flow_result.get("success"):
                _patch_journal.append({
                    "success": True,
                    "target_file": str(cls_obj.abs_path or cls_obj.file_path),
                    "description": (
                        f"smart_entity_patch: response/state-boundary normalization for {class_descriptor} "
                        f"({len(response_field_overrides)} fields)"
                    ),
                    "diff_text": (
                        f"patch_api_response_flow applied {response_flow_result.get('patches_applied', 0)} response/model-boundary patches"
                    ),
                })

        for patch in patches:
            try:
                fpath = Path(patch["file"])
                if not fpath.exists():
                    # Try resolving
                    fpath = _resolve_file(patch["file"])
                content = fpath.read_text(encoding="utf-8", errors="replace")

                # Find the method and replace its body
                method_name = patch["method"].split("(")[0] if "(" in patch["method"] else patch["method"]
                # Build pattern to find the method
                pat = re.compile(
                    rf'(\.method\s+[^\n]*{re.escape(method_name)}\([^\n]*\n)'
                    rf'(.*?)'
                    rf'(\.end method)',
                    re.DOTALL
                )
                m = pat.search(content)
                if m:
                    header = m.group(1)
                    old_body = m.group(2)
                    # Determine required locals
                    locals_match = re.search(r'\.locals\s+(\d+)', old_body)
                    locals_val = max(int(locals_match.group(1)), 1) if locals_match else 1
                    new_body = f"    .locals {locals_val}\n\n{patch['patch_code']}\n"
                    new_content = content[:m.start()] + header + new_body + m.group(3) + content[m.end():]
                    fpath.write_text(new_content, encoding="utf-8")

                    _patch_journal.append({
                        "success": True,
                        "target_file": str(fpath),
                        "description": f"smart_entity_patch: {method_name} → {patch['target_value']} ({patch['semantics']})",
                        "diff_text": f"Body replaced with const/{patch['target_value']} return",
                    })
                    applied.append(patch["method"])
                else:
                    failed.append({"method": patch["method"], "reason": "method not found in file"})
            except Exception as e:
                failed.append({"method": patch["method"], "reason": str(e)[:100]})

        return json.dumps({
            "success": True,
            "mode": "auto",
            "class": class_descriptor,
            "total_gates": len(gates),
            "applied": len(applied),
            "failed": len(failed),
            "applied_methods": applied,
            "failed_methods": failed,
            "gates": gates,
            "semantic_plan": semantic_plan,
            "response_flow": response_flow_result,
            "instruction": (
                f"Applied {len(applied)}/{len(gates)} gate patches to {class_descriptor}. "
                + (
                    f"Response/model-boundary normalization applied {response_flow_result.get('patches_applied', 0)} patch(es). "
                    if response_flow_result and response_flow_result.get("success") else
                    (
                        "⚠️ Response/model-boundary normalization did not apply cleanly. "
                        if auto_response_flow["attempted"] else
                        ""
                    )
                )
                + (f"⚠️ {len(failed)} patches failed — manually patch these." if failed else "")
                + (" Review companion_followups/execution_order and patch linked revalidation/state writers before build if server or lifecycle code can revert the state." if companion_surfaces else "")
                + " Now run validate_patch_completeness to verify, then check child classes."
            ),
        }, ensure_ascii=False, indent=2)[:15000]

    return _safe_call(_run, "smart_entity_patch")


@tool
def frida_script_generator(class_descriptor: str) -> str:
    """Generate a Frida hook script to dynamically bypass ALL gate methods of a class.

    Creates a ready-to-use Frida JavaScript that:
    1. Hooks every gate method in the class
    2. Forces the correct return value (using NEGATIVE/POSITIVE semantics)
    3. Includes logging to see when each gate is called
    4. Handles overloaded methods correctly

    Use this when static patching fails (e.g., the APK uses integrity checks,
    code obfuscation, or native protection). The generated script works with
    frida -U -l script.js -f <package>.

    Args:
        class_descriptor: Smali class descriptor, e.g. 'Lcom/app/UserInfo;'

    Returns: JSON with the generated Frida script and a list of hooked methods.
    """
    def _run():
        si = _ensure_smali_index()
        cls_obj = si.get_class(class_descriptor) if si else None

        if not cls_obj:
            return json.dumps({"success": False, "error": f"Class {class_descriptor} not found."})

        java_class = class_descriptor[1:-1].replace("/", ".")

        _NEGATIVE = {"expired", "expire", "isexpired", "istrial",
                      "isblocked", "banned", "disabled", "locked",
                      "isads", "showads", "needpay"}
        _POSITIVE = {"ispremium", "ispro", "isvip", "issubscribed",
                      "isactivated", "isunlocked", "ispurchased",
                      "haslicense", "ispaid"}

        hooks: list[dict] = []
        script_lines = [
            f'// Frida hook script for {java_class}',
            f'// Generated by APK-AGI smart_entity_patch',
            f'// Usage: frida -U -l script.js -f <package_name>',
            '',
            'Java.perform(function() {',
            f'    var cls = Java.use("{java_class}");',
            '',
        ]

        for method in cls_obj.methods:
            if method.name in ("<init>", "<clinit>"):
                continue
            if method.return_type not in ("Z", "I"):
                continue

            has_field = any(i.is_field_access for i in method.instructions)
            if not has_field:
                continue

            name_lower = method.name.lower()
            if name_lower in _NEGATIVE or any(n in name_lower for n in ("expire", "block", "disable", "ads", "trial")):
                ret_val = "false" if method.return_type == "Z" else "0"
                semantics = "NEGATIVE"
            elif name_lower in _POSITIVE or any(p in name_lower for p in ("premium", "pro", "vip", "subscribe", "license", "unlock")):
                ret_val = "true" if method.return_type == "Z" else "1"
                semantics = "POSITIVE"
            else:
                ret_val = "true" if method.return_type == "Z" else "1"
                semantics = "DEFAULT"

            # Parse parameter types for overload
            param_part = method.signature.split("(")[1].split(")")[0] if "(" in method.signature else ""
            java_params = []
            i = 0
            while i < len(param_part):
                if param_part[i] == "L":
                    end = param_part.index(";", i)
                    java_params.append('"' + param_part[i + 1:end].replace("/", ".") + '"')
                    i = end + 1
                elif param_part[i] == "[":
                    java_params.append('"[TODO]"')
                    i += 2
                elif param_part[i] == "Z":
                    java_params.append('"boolean"')
                    i += 1
                elif param_part[i] == "I":
                    java_params.append('"int"')
                    i += 1
                elif param_part[i] == "J":
                    java_params.append('"long"')
                    i += 1
                else:
                    i += 1

            overload = f'.overload({", ".join(java_params)})' if java_params else ""

            script_lines.append(f'    // {semantics}: {method.signature}')
            script_lines.append(f'    cls.{method.name}{overload}.implementation = function() {{')
            script_lines.append(f'        console.log("[APK-AGI] {method.name} called → returning {ret_val}");')
            script_lines.append(f'        return {ret_val};')
            script_lines.append(f'    }};')
            script_lines.append('')

            hooks.append({
                "method": method.name,
                "signature": method.signature,
                "return_value": ret_val,
                "semantics": semantics,
            })

        script_lines.append('    console.log("[APK-AGI] All hooks installed for ' + java_class + '");')
        script_lines.append('});')

        script_text = "\n".join(script_lines)

        # Save to outputs
        out_dir = _project.workspace_path / "outputs"
        out_dir.mkdir(exist_ok=True)
        safe_name = java_class.replace(".", "_")
        script_file = out_dir / f"frida_hook_{safe_name}.js"
        script_file.write_text(script_text, encoding="utf-8")

        return json.dumps({
            "success": True,
            "class": class_descriptor,
            "java_class": java_class,
            "hooks_count": len(hooks),
            "hooks": hooks,
            "script_file": str(script_file),
            "script_preview": script_text[:3000],
            "instruction": (
                f"Generated Frida script with {len(hooks)} hooks for {java_class}. "
                f"Saved to {script_file.name}. "
                f"Run with: frida -U -l {script_file.name} -f <package_name>"
            ),
        }, ensure_ascii=False, indent=2)[:15000]

    return _safe_call(_run, "frida_script_generator")


@tool
def diff_apk_variants(apk_path_1: str, apk_path_2: str) -> str:
    """Compare two APK files (e.g., free vs premium) to find subscription differences.

    Decompiles both APKs with apktool and diffs the smali code to find:
    1. Classes that only exist in the premium version
    2. Methods that differ between versions
    3. Field values that change (hardcoded premium flags)
    4. Resource differences (layouts, strings, feature toggles)

    This is the ULTIMATE reverse engineering shortcut — by comparing free and paid
    versions you can see EXACTLY what the developers change for premium.

    Args:
        apk_path_1: Path to first APK (e.g., free version)
        apk_path_2: Path to second APK (e.g., premium version)

    Returns: JSON with diffs — added_classes, removed_classes, changed_methods,
    changed_fields, changed_resources.
    """
    def _run():
        import subprocess
        import tempfile

        apk1 = Path(apk_path_1)
        apk2 = Path(apk_path_2)
        if not apk1.exists():
            return json.dumps({"success": False, "error": f"APK not found: {apk_path_1}"})
        if not apk2.exists():
            return json.dumps({"success": False, "error": f"APK not found: {apk_path_2}"})

        # Decompile both to temp dirs
        tmp1 = Path(tempfile.mkdtemp(prefix="apk_diff_1_"))
        tmp2 = Path(tempfile.mkdtemp(prefix="apk_diff_2_"))

        apktool_jar = _project.workspace_path.parent.parent / "tools" / "bin" / "apktool.jar"
        for apk_path, out_dir in [(apk1, tmp1), (apk2, tmp2)]:
            cmd = ["java", "-jar", str(apktool_jar), "d", str(apk_path), "-o", str(out_dir), "-f", "--no-res"]
            try:
                subprocess.run(cmd, capture_output=True, timeout=120, check=True)
            except Exception as e:
                return json.dumps({"success": False, "error": f"Failed to decompile {apk_path.name}: {e}"})

        # Collect all smali files from both
        def get_smali_files(base: Path) -> dict[str, Path]:
            files = {}
            for sd in base.iterdir():
                if sd.is_dir() and sd.name.startswith("smali"):
                    for f in sd.rglob("*.smali"):
                        rel = str(f.relative_to(base)).replace("\\", "/")
                        files[rel] = f
            return files

        files1 = get_smali_files(tmp1)
        files2 = get_smali_files(tmp2)

        only_in_2 = [k for k in files2 if k not in files1]  # Added in premium
        only_in_1 = [k for k in files1 if k not in files2]  # Removed in premium
        common = [k for k in files1 if k in files2]

        # Diff common files
        changed_methods: list[dict] = []
        changed_fields: list[dict] = []

        for rel in common[:500]:
            try:
                c1 = files1[rel].read_text(encoding="utf-8", errors="replace")
                c2 = files2[rel].read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            if c1 == c2:
                continue

            # Find differing methods
            import re
            methods1 = {m.group(1): m.group(0) for m in re.finditer(r'\.method\s+(.*?)\n(.*?)\.end method', c1, re.DOTALL)}
            methods2 = {m.group(1): m.group(0) for m in re.finditer(r'\.method\s+(.*?)\n(.*?)\.end method', c2, re.DOTALL)}

            for method_sig in methods1:
                if method_sig in methods2 and methods1[method_sig] != methods2[method_sig]:
                    changed_methods.append({
                        "file": rel,
                        "method": method_sig[:80],
                        "size_diff": len(methods2[method_sig]) - len(methods1[method_sig]),
                    })

            # Find differing field declarations
            fields1 = set(re.findall(r'\.field\s+(.+)', c1))
            fields2 = set(re.findall(r'\.field\s+(.+)', c2))
            for f in fields2 - fields1:
                changed_fields.append({"file": rel, "field": f[:80], "change": "added_in_v2"})
            for f in fields1 - fields2:
                changed_fields.append({"file": rel, "field": f[:80], "change": "removed_in_v2"})

        # Clean up temp dirs
        import shutil
        try:
            shutil.rmtree(tmp1)
            shutil.rmtree(tmp2)
        except Exception:
            pass

        # Filter to app classes only
        only_in_2_filtered = [f for f in only_in_2 if not any(
            f.startswith(f"smali/{p}") for p in ("android/", "androidx/", "com/google/", "kotlin/")
        )][:50]

        return json.dumps({
            "success": True,
            "apk1": apk1.name,
            "apk2": apk2.name,
            "total_files_apk1": len(files1),
            "total_files_apk2": len(files2),
            "classes_only_in_apk2": only_in_2_filtered[:30],
            "classes_only_in_apk1": only_in_1[:10],
            "changed_methods": changed_methods[:50],
            "changed_fields": changed_fields[:30],
            "instruction": (
                f"Compared {apk1.name} vs {apk2.name}: "
                f"{len(only_in_2_filtered)} classes only in v2, "
                f"{len(changed_methods)} method diffs, {len(changed_fields)} field diffs. "
                f"Focus on changed methods with boolean/int returns — these are likely the premium gates."
            ),
        }, ensure_ascii=False, indent=2)[:20000]

    return _safe_call(_run, "diff_apk_variants")


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
    from apk_agent.tools.smali_ir import build_index as build_smali_idx, save_index as save_smali_idx, index_stats

    smali_dirs = _get_all_smali_dirs()
    if not smali_dirs:
        return json.dumps({"success": False, "error": "No smali directories found. Run apktool_decompile first."})

    def _run():
        from apk_agent.progress import report_progress
        idx = build_smali_idx(smali_dirs, progress_callback=report_progress)
        clear_runtime_slots(
            "semantic_architecture_cache",
            "hidden_state_model_cache",
            "guard_surface_profile_cache",
            "architecture_context_cache",
        )
        set_runtime_slot("smali_index", idx)
        out_path = _project_outputs_dir() / "smali_index.pickle"
        save_result = save_smali_idx(idx, out_path)
        stats = index_stats(idx)
        stats["success"] = True
        stats["persisted"] = save_result.get("success", False)
        if not save_result.get("success", True):
            stats["persistence_warning"] = save_result.get("recovery_hint", "SmaliIndex was built but not persisted to disk.")
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
def get_threat_model() -> str:
    """Classify the APK's threat level based on unified scanner findings.
    Returns: basic (no protections), obfuscated (name-mangling, string encryption),
    or hardened (anti-tamper, anti-debug, native guards + obfuscation).

    When to use: After running unified_scan, call this to understand the APK's
    overall security posture and decide which analysis branches are needed.
    Requires build_smali_index and unified_scan to have run first.

    Returns: JSON with threat_level, category_signals, recommendation.
    """
    from apk_agent.tools.unified_scanner import scan, classify_threat_model, ThreatLevel

    def _run():
        idx = _ensure_smali_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No SmaliIndex. Run build_smali_index first."})
        result = scan(idx, max_findings=200)
        if not result.get("success"):
            return json.dumps({"success": False, "error": "Scan failed"})

        # Reconstruct Finding objects from dicts for classification
        from apk_agent.tools.unified_scanner import Finding
        findings_objs = []
        for fd in result.get("findings", []):
            findings_objs.append(Finding(
                id=fd["id"], rule_id=fd["rule_id"],
                severity=fd["severity"], category=fd["category"],
                title=fd["title"], description=fd.get("description", ""),
                cwe=fd.get("cwe", ""),
                tags=fd.get("tags", []),
            ))

        threat = classify_threat_model(findings_objs)

        # Build recommendation
        recs = {
            ThreatLevel.BASIC: "Standard static analysis + patching. No special bypass needed.",
            ThreatLevel.OBFUSCATED: "Use deep_analysis tools + string decryption. Consider targeted deobfuscation before patching.",
            ThreatLevel.HARDENED: "Full anti-tamper bypass required. Use auto_bypass_plan, analyze native libs, and consider Frida hooks for runtime validation.",
        }

        cats = {fd["category"] for fd in result.get("findings", [])}
        return json.dumps({
            "success": True,
            "threat_level": threat.value,
            "category_signals": sorted(cats),
            "total_findings": result["total_findings"],
            "severity_summary": result.get("severity_summary", {}),
            "recommendation": recs.get(threat, ""),
        }, indent=2)
    return _safe_call(_run, "get_threat_model")


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
def generate_bypass_plans(
    max_bypasses: int = 50,
    premium_semantic_feature: str = "",
    max_premium_classes: int = 3,
) -> str:
    """Generate automated bypass plans (smali patches + Frida scripts) for
    detected security protections. Runs unified_scan first, then generates
    bypasses for: root detection, emulator detection, debug detection,
    SSL pinning, certificate pinning, SafetyNet, signature verification.

    When to use: After unified_scan identifies protections, use this to get
    ready-to-apply smali patches and Frida scripts. Fully automated — just
    apply the generated patches via apply_smali_patch.

    Args:
        max_bypasses: Maximum bypass plans to generate (default 50).
        premium_semantic_feature: Optional premium/license feature context to
            augment the output with the same semantic planner used by
            smart_entity_patch. Leave empty to preserve the current behavior.
        max_premium_classes: Maximum candidate entity/state classes to include
            when premium_semantic_feature is enabled.

    Returns: JSON with keys: success, total_bypasses, by_type (dict of protection_type→count),
    bypasses (array of {type, target_class, target_method, difficulty (easy/medium/hard),
    smali_patch (ready-to-apply patch plan JSON), frida_script (JavaScript hook code),
    description}). When premium_semantic_feature is enabled, the response also
    includes premium_semantic_summary and premium_semantic_workflows without
    changing the default security bypass behavior.
    """
    from apk_agent.tools.unified_scanner import scan
    from apk_agent.tools.auto_bypass import generate_bypasses
    from apk_agent.tools.semantic_cache import get_cached_hidden_state_model as _recover_hidden_state_model

    def _build_premium_semantic_workflows(index) -> dict:
        feature = premium_semantic_feature.strip()
        if not feature:
            return {"enabled": False, "workflows": []}

        hidden_state_result = _recover_hidden_state_model(
            index,
            focus_hint=feature,
            max_candidates=max(24, max_premium_classes * 8),
        )
        if not hidden_state_result.get("success"):
            return {
                "enabled": True,
                "feature": feature,
                "workflow_count": 0,
                "hidden_state_summary": {},
                "ranked_classes": [],
                "errors": [hidden_state_result.get("error", "recover_hidden_state_model failed")],
                "workflows": [],
            }

        ranked_classes: dict[str, dict] = {}
        for model in hidden_state_result.get("candidate_models", []):
            class_name = str(model.get("class", "")).strip()
            if not class_name:
                continue
            ranked_classes[class_name] = {
                "class": class_name,
                "file": model.get("file", ""),
                "ranking_score": float(model.get("score", 0) or 0),
                "best_field_confidence": 0.0,
                "semantic_guesses": set(),
                "field_candidates": [],
            }

        for field in hidden_state_result.get("candidate_state_fields", []):
            class_name = str(field.get("class", "")).strip()
            if not class_name:
                continue
            entry = ranked_classes.setdefault(class_name, {
                "class": class_name,
                "file": field.get("file", ""),
                "ranking_score": 0.0,
                "best_field_confidence": 0.0,
                "semantic_guesses": set(),
                "field_candidates": [],
            })
            confidence = float(field.get("confidence", 0) or 0)
            entry["ranking_score"] += float(field.get("score", 0) or 0) + confidence * 10
            entry["best_field_confidence"] = max(entry["best_field_confidence"], confidence)
            semantic_guess = str(field.get("semantic_guess", "")).strip()
            if semantic_guess:
                entry["semantic_guesses"].add(semantic_guess)
            if len(entry["field_candidates"]) < 6:
                entry["field_candidates"].append({
                    "field": field.get("field", ""),
                    "type": field.get("type", ""),
                    "semantic_guess": field.get("semantic_guess", "state_value"),
                    "likely_unlocked_value": field.get("likely_unlocked_value"),
                    "suggested_unlocked_value": field.get("suggested_unlocked_value"),
                    "value_origin": field.get("value_origin", "semantic_guess"),
                    "safe_for_auto_override": field.get("safe_for_auto_override", False),
                    "exact_value_candidates": field.get("exact_value_candidates", [])[:3],
                    "confidence": confidence,
                    "recommended_patch_strategy": field.get("recommended_patch_strategy", ""),
                    "writer_tags": field.get("writer_tags", []),
                    "reader_tags": field.get("reader_tags", []),
                })

        ranked = sorted(
            ranked_classes.values(),
            key=lambda item: (-item["ranking_score"], -item["best_field_confidence"], item["class"]),
        )[:max(1, max_premium_classes)]

        workflows: list[dict] = []
        errors: list[str] = []
        for entry in ranked:
            preview_raw = smart_entity_patch.invoke({
                "class_descriptor": entry["class"],
                "mode": "preview",
                "planner_context": feature,
            })
            try:
                preview = json.loads(preview_raw)
            except json.JSONDecodeError:
                errors.append(f"smart_entity_patch preview returned invalid JSON for {entry['class']}")
                continue
            if not preview.get("success"):
                errors.append(f"{entry['class']}: {preview.get('error', 'smart_entity_patch preview failed')}")
                continue
            workflows.append({
                "class": entry["class"],
                "file": entry["file"],
                "ranking_score": round(float(entry["ranking_score"]), 2),
                "best_field_confidence": round(float(entry["best_field_confidence"]), 3),
                "semantic_guesses": sorted(entry["semantic_guesses"]),
                "field_candidates": entry["field_candidates"],
                "semantic_plan": preview.get("semantic_plan", {}),
                "patches_preview": preview.get("patches_preview", []),
                "instruction": preview.get("instruction", ""),
            })

        return {
            "enabled": True,
            "feature": feature,
            "workflow_count": len(workflows),
            "hidden_state_summary": hidden_state_result.get("summary", {}),
            "ranked_classes": [
                {
                    "class": entry["class"],
                    "file": entry["file"],
                    "ranking_score": round(float(entry["ranking_score"]), 2),
                    "best_field_confidence": round(float(entry["best_field_confidence"]), 3),
                    "semantic_guesses": sorted(entry["semantic_guesses"]),
                }
                for entry in ranked
            ],
            "errors": errors[:10],
            "workflows": workflows,
        }

    def _run():
        idx = _ensure_smali_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No SmaliIndex. Run build_smali_index first."})
        premium_semantic = _build_premium_semantic_workflows(idx)
        # First run the scanner to get findings
        scan_result = scan(idx)
        findings = scan_result.get("findings", [])
        if not findings and not premium_semantic.get("enabled"):
            return json.dumps({"success": True, "bypasses": [], "message": "No security protections detected to bypass."})
        result = generate_bypasses(idx, findings, max_bypasses=max_bypasses) if findings else {
            "success": True,
            "total_bypasses": 0,
            "by_type": {},
            "bypasses": [],
        }
        if premium_semantic.get("enabled"):
            result["premium_semantic_summary"] = {
                key: value for key, value in premium_semantic.items() if key != "workflows"
            }
            result["premium_semantic_workflows"] = premium_semantic.get("workflows", [])
            if not findings:
                if premium_semantic.get("workflow_count", 0) > 0:
                    result["message"] = (
                        "No auto-patchable security protections were detected, but optional premium semantic workflows were generated."
                    )
                else:
                    result["message"] = (
                        "No security protections detected to bypass, and the optional premium semantic planner did not find usable workflows."
                    )
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


@tool
def semantic_method_slice(class_name: str, method_name: str, max_depth: int = 2) -> str:
    """Build a graph-aware semantic slice for one method.

    Uses SmaliIndex + the call graph + CFG info together. This is more context-aware
    than plain search because it combines:
      - method body semantics
      - direct callers / direct callees
      - branch blocks / gate signals
      - field-backed and network-backed enforcement hints

    When to use: After identifying a suspicious method and BEFORE patching it.
    Prefer this over raw file reading when you need to understand whether the
    method is a true enforcement point or just a helper.
    """
    from apk_agent.tools.semantic_graph import semantic_method_slice as _semantic_slice

    def _run():
        idx = _ensure_smali_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No SmaliIndex. Run build_smali_index first."})
        graph = _ensure_graph()
        result = _semantic_slice(idx, class_name, method_name, graph=graph, max_depth=max_depth)
        return json.dumps(result, ensure_ascii=False, indent=2)[:25000]
    return _safe_call(_run, "semantic_method_slice", _cache_hint=f"{class_name}:{method_name}:{max_depth}")


@tool
def find_enforcement_surfaces(feature: str = "", extra_keywords: str = "", max_results: int = 25) -> str:
    """Find likely enforcement surfaces using architecture/state/revalidation scoring.

    This complements `map_feature_checks` instead of replacing it:
      - `map_feature_checks` is broad and exhaustive
      - `find_enforcement_surfaces` ranks the most likely REAL enforcement methods

    When to use: Before writing patches for premium/license/root/anti-tamper paths,
    especially when there are too many hits and you need the most likely
    enforcement surfaces first.

    Notes:
      - `feature` is optional and may be blank.
      - `feature` and `extra_keywords` are free-form agent context, not a fixed keyword list.
      - You may pass your own runtime hypothesis (symptoms, lifecycle guess, API names,
        server overwrite suspicion, account creation notes, etc.) or leave both empty.
    """
    from apk_agent.tools.semantic_graph import find_enforcement_surfaces as _find_surfaces

    def _run():
        idx = _ensure_smali_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No SmaliIndex. Run build_smali_index first."})
        graph = _ensure_graph()
        result = _find_surfaces(
            idx,
            feature,
            graph=graph,
            extra_keywords=extra_keywords,
            max_results=max_results,
        )
        return json.dumps(result, ensure_ascii=False, indent=2)[:25000]

    return _safe_call(_run, "find_enforcement_surfaces", _cache_hint=f"{feature}:{extra_keywords}:{max_results}")


@tool
def validate_patch_pipeline(target_class: str = "", include_global_gate_check: bool = False) -> str:
    """Run layered patch validation without replacing the old validators.

    This is a pipeline wrapper over the existing validation stack:
      1. patch journal / backup discovery of touched files
      2. syntax validation of patched smali
            3. optional class-level completeness (`validate_patch_completeness`)
            4. optional global gate scan (`verify_bypass_completeness`)

    It complements `validate_patch`, `validate_patch_completeness`, and
    `verify_bypass_completeness`; it does NOT remove or replace them.
    """
    from apk_agent.tools.validation_pipeline import run_patch_validation_pipeline

    def _run():
        result = run_patch_validation_pipeline(
            project_root=Path(_project.workspace_path),
            apktool_dir=_project.apktool_dir,
            backup_dir=_project.patch_backup_dir,
            patch_journal=list(_patch_journal),
        )

        if target_class:
            try:
                class_check_raw = validate_patch_completeness.invoke({"target_class": target_class})
                result["class_completeness"] = json.loads(class_check_raw)
            except Exception as exc:
                result["class_completeness"] = {"success": False, "error": f"validate_patch_completeness failed: {exc}"}

        if include_global_gate_check:
            try:
                global_check_raw = verify_bypass_completeness.invoke({})
                result["global_gate_check"] = json.loads(global_check_raw)
            except Exception as exc:
                result["global_gate_check"] = {"success": False, "error": f"verify_bypass_completeness failed: {exc}"}

        return json.dumps(result, ensure_ascii=False, indent=2)[:30000]
    return _safe_call(_run, "validate_patch_pipeline", _cache_hint=f"{target_class}:{include_global_gate_check}:{len(_patch_journal)}")


@tool
def generate_runtime_validation_plan(task: str = "") -> str:
    """Generate a structured runtime validation checklist from patch history.

    This is intentionally additive and safe: it does not execute anything on the
    host or device. It turns the current patch history into a concrete runtime
    test checklist so dynamic verification can be done consistently.
    """
    from apk_agent.tools.validation_pipeline import generate_runtime_validation_plan as _runtime_plan

    def _run():
        result = _runtime_plan(patch_journal=list(_patch_journal), task=task)
        return json.dumps(result, ensure_ascii=False, indent=2)[:20000]
    return _safe_call(_run, "generate_runtime_validation_plan", _cache_hint=f"{task}:{len(_patch_journal)}")


@tool
def map_semantic_architecture(focus_hint: str = "", max_per_role: int = 12) -> str:
    """Build a semantic architecture map from SmaliIndex behavior.

    Identifies high-value layers such as entry points, network boundaries,
    serialization, state models, state stores, UI gate controllers, security
    guards, dynamic/native boundaries, and billing flow.
    """
    from apk_agent.tools.semantic_cache import get_cached_semantic_architecture as _map

    def _run():
        idx = _ensure_smali_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No SmaliIndex. Run build_smali_index first."})
        result = _map(idx, focus_hint=focus_hint, max_per_role=max_per_role)
        return json.dumps(result, ensure_ascii=False, indent=2)[:25000]

    return _safe_call(_run, "map_semantic_architecture", _cache_hint=f"{focus_hint}:{max_per_role}")


@tool
def recover_hidden_state_model(focus_hint: str = "", max_candidates: int = 30) -> str:
    """Recover hidden state/entity fields using behavioral signals.

    Works on obfuscated APKs by inferring field meaning from read/write context,
    network and serialization boundaries, billing adjacency, and UI consumers.
    """
    from apk_agent.tools.semantic_cache import get_cached_hidden_state_model as _recover

    def _run():
        idx = _ensure_smali_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No SmaliIndex. Run build_smali_index first."})
        result = _recover(idx, focus_hint=focus_hint, max_candidates=max_candidates)
        return json.dumps(result, ensure_ascii=False, indent=2)[:25000]

    return _safe_call(_run, "recover_hidden_state_model", _cache_hint=f"{focus_hint}:{max_candidates}")


@tool
def profile_guard_and_revalidation_surface(focus_hint: str = "", max_clusters: int = 30) -> str:
    """Profile guard clusters, runtime revalidation, and state overwrite points."""
    from apk_agent.tools.semantic_cache import get_cached_guard_surface_profile as _profile

    def _run():
        idx = _ensure_smali_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No SmaliIndex. Run build_smali_index first."})
        result = _profile(idx, focus_hint=focus_hint, max_clusters=max_clusters)
        return json.dumps(result, ensure_ascii=False, indent=2)[:25000]

    return _safe_call(_run, "profile_guard_and_revalidation_surface", _cache_hint=f"{focus_hint}:{max_clusters}")


@tool
def build_app_knowledge_pack(
    focus_hint: str = "",
    max_state_fields: int = 40,
    max_guard_clusters: int = 40,
) -> str:
    """Build and persist the additive Application Knowledge Pack for the current APK.

    This does not replace any existing tool. It composes semantic architecture,
    hidden state recovery, and guard/revalidation profiling into one reusable,
    evidence-backed knowledge layer for later queries.
    """
    from apk_agent.tools.app_knowledge import (
        build_app_knowledge_pack as _build_app_knowledge_pack,
        save_app_knowledge_pack,
        summarize_app_knowledge_pack,
    )

    def _run():
        idx = _ensure_smali_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No SmaliIndex. Run build_smali_index first."})

        pack = _build_app_knowledge_pack(
            idx,
            focus_hint=focus_hint,
            package_name=str(getattr(_project, "package_name", "") or ""),
            app_label=str(getattr(_project, "apk_name", "") or ""),
            max_state_fields=max_state_fields,
            max_guard_clusters=max_guard_clusters,
        )
        pack_path = _app_knowledge_pack_path()
        save_result = save_app_knowledge_pack(pack, pack_path)
        set_runtime_slot("app_knowledge_pack", pack)
        return json.dumps({
            "success": True,
            "output_path": str(pack_path),
            "persisted": save_result.get("success", False),
            "persist_result": save_result,
            "summary": summarize_app_knowledge_pack(pack).get("summary", {}),
            "identity": pack.get("identity", {}),
            "workflows": pack.get("knowledge", {}).get("workflows", []),
            "warnings": pack.get("warnings", []),
        }, ensure_ascii=False, indent=2)[:25000]

    return _safe_call(
        _run,
        "build_app_knowledge_pack",
        _cache_hint=f"{focus_hint}:{max_state_fields}:{max_guard_clusters}",
    )


@tool
def summarize_app_knowledge() -> str:
    """Return a compact summary of the persisted Application Knowledge Pack."""
    from apk_agent.tools.app_knowledge import summarize_app_knowledge_pack as _summarize_app_knowledge_pack

    def _run():
        pack = _ensure_app_knowledge_pack(auto_build=True)
        if pack is None:
            return json.dumps({"success": False, "error": "Application Knowledge Pack unavailable. Build it first."})
        result = _summarize_app_knowledge_pack(pack)
        result["output_path"] = str(_app_knowledge_pack_path())
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]

    return _safe_call(_run, "summarize_app_knowledge")


@tool
def query_app_knowledge(
    query: str,
    feature: str = "",
    class_name: str = "",
    method_name: str = "",
    max_results: int = 8,
) -> str:
    """Query the additive Application Knowledge Pack for deep, app-specific answers.

    Use this when you want app-level understanding rather than another raw file
    search. The tool searches the persisted knowledge records built from the
    current analyzers and returns ranked evidence-backed matches.
    """
    from apk_agent.tools.app_knowledge import query_app_knowledge as _query_app_knowledge

    def _run():
        pack = _ensure_app_knowledge_pack(auto_build=True, focus_hint=feature or query)
        if pack is None:
            return json.dumps({"success": False, "error": "Application Knowledge Pack unavailable. Run build_app_knowledge_pack first."})
        result = _query_app_knowledge(
            pack,
            query=query,
            feature=feature,
            class_name=class_name,
            method_name=method_name,
            max_results=max_results,
        )
        result["output_path"] = str(_app_knowledge_pack_path())
        return json.dumps(result, ensure_ascii=False, indent=2)[:25000]

    return _safe_call(
        _run,
        "query_app_knowledge",
        _cache_hint=f"{query}:{feature}:{class_name}:{method_name}:{max_results}",
    )


@tool
def build_behavior_graph(
    focus_hint: str = "",
    max_surfaces: int = 25,
    max_controls: int = 40,
    max_transitions: int = 80,
) -> str:
    """Build and persist the unified behavior graph for the current APK.

    This consolidates control-flow reasoning, state recovery, enforcement
    surfaces, runtime revalidation, network-to-state boundaries, and semantic
    symbol hints into one reusable pack.
    """
    from apk_agent.tools.behavior_engine import (
        build_behavior_graph as _build_behavior_graph,
        save_behavior_graph,
        summarize_behavior_graph,
    )

    def _run():
        idx = _ensure_smali_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No SmaliIndex. Run build_smali_index first."})

        graph = _ensure_graph()
        pack = _build_behavior_graph(
            idx,
            graph=graph,
            focus_hint=focus_hint,
            package_name=str(getattr(_project, "package_name", "") or ""),
            app_label=str(getattr(_project, "apk_name", "") or ""),
            max_surfaces=max_surfaces,
            max_controls=max_controls,
            max_transitions=max_transitions,
        )
        pack_path = _behavior_graph_path()
        save_result = save_behavior_graph(pack, pack_path)
        set_runtime_slot("behavior_graph_pack", pack)
        return json.dumps({
            "success": True,
            "output_path": str(pack_path),
            "persisted": save_result.get("success", False),
            "persist_result": save_result,
            "summary": summarize_behavior_graph(pack).get("summary", {}),
            "identity": pack.get("identity", {}),
            "warnings": pack.get("warnings", []),
        }, ensure_ascii=False, indent=2)[:25000]

    return _safe_call(
        _run,
        "build_behavior_graph",
        _cache_hint=f"{focus_hint}:{max_surfaces}:{max_controls}:{max_transitions}",
    )


@tool
def summarize_behavior_graph() -> str:
    """Return a compact summary of the persisted unified behavior graph."""
    from apk_agent.tools.behavior_engine import summarize_behavior_graph as _summarize_behavior_graph

    def _run():
        pack = _ensure_behavior_graph_pack(auto_build=True)
        if pack is None:
            return json.dumps({"success": False, "error": "Behavior graph unavailable. Build it first."})
        result = _summarize_behavior_graph(pack)
        result["output_path"] = str(_behavior_graph_path())
        return json.dumps(result, ensure_ascii=False, indent=2)[:15000]

    return _safe_call(_run, "summarize_behavior_graph")


@tool
def query_behavior_graph(
    query: str,
    feature: str = "",
    class_name: str = "",
    method_name: str = "",
    record_type: str = "",
    max_results: int = 10,
) -> str:
    """Run a graph-aware semantic query over the unified behavior graph."""
    from apk_agent.tools.behavior_engine import query_behavior_graph as _query_behavior_graph

    def _run():
        pack = _ensure_behavior_graph_pack(auto_build=True, focus_hint=feature or query)
        if pack is None:
            return json.dumps({"success": False, "error": "Behavior graph unavailable. Run build_behavior_graph first."})
        result = _query_behavior_graph(
            pack,
            query=query,
            feature=feature,
            class_name=class_name,
            method_name=method_name,
            record_type=record_type,
            max_results=max_results,
        )
        result["output_path"] = str(_behavior_graph_path())
        return json.dumps(result, ensure_ascii=False, indent=2)[:25000]

    return _safe_call(
        _run,
        "query_behavior_graph",
        _cache_hint=f"{query}:{feature}:{class_name}:{method_name}:{record_type}:{max_results}",
    )


@tool
def locate_feature_controls(feature: str = "", class_name: str = "", method_name: str = "", max_results: int = 12) -> str:
    """Locate activation, deactivation, and real enforcement controls for a feature."""
    from apk_agent.tools.behavior_engine import locate_feature_controls as _locate_feature_controls

    def _run():
        pack = _ensure_behavior_graph_pack(auto_build=True, focus_hint=feature)
        if pack is None:
            return json.dumps({"success": False, "error": "Behavior graph unavailable. Run build_behavior_graph first."})
        result = _locate_feature_controls(
            pack,
            feature=feature,
            class_name=class_name,
            method_name=method_name,
            max_results=max_results,
        )
        result["output_path"] = str(_behavior_graph_path())
        return json.dumps(result, ensure_ascii=False, indent=2)[:25000]

    return _safe_call(
        _run,
        "locate_feature_controls",
        _cache_hint=f"{feature}:{class_name}:{method_name}:{max_results}",
    )


@tool
def recover_state_transitions(class_name: str = "", field_name: str = "", max_results: int = 20) -> str:
    """Recover state transitions and source-to-gate propagation paths."""
    from apk_agent.tools.behavior_engine import recover_state_transitions as _recover_state_transitions

    def _run():
        pack = _ensure_behavior_graph_pack(auto_build=True, focus_hint=class_name or field_name)
        if pack is None:
            return json.dumps({"success": False, "error": "Behavior graph unavailable. Run build_behavior_graph first."})
        result = _recover_state_transitions(
            pack,
            class_name=class_name,
            field_name=field_name,
            max_results=max_results,
        )
        result["output_path"] = str(_behavior_graph_path())
        return json.dumps(result, ensure_ascii=False, indent=2)[:25000]

    return _safe_call(
        _run,
        "recover_state_transitions",
        _cache_hint=f"{class_name}:{field_name}:{max_results}",
    )


@tool
def map_security_surfaces(focus_hint: str = "", class_name: str = "", max_results: int = 20) -> str:
    """Map validation, crypto/TLS, API, and runtime security surfaces."""
    from apk_agent.tools.behavior_engine import map_security_surfaces as _map_security_surfaces

    def _run():
        pack = _ensure_behavior_graph_pack(auto_build=True, focus_hint=focus_hint or class_name)
        if pack is None:
            return json.dumps({"success": False, "error": "Behavior graph unavailable. Run build_behavior_graph first."})
        result = _map_security_surfaces(
            pack,
            focus_hint=focus_hint,
            class_name=class_name,
            max_results=max_results,
        )
        result["output_path"] = str(_behavior_graph_path())
        return json.dumps(result, ensure_ascii=False, indent=2)[:25000]

    return _safe_call(
        _run,
        "map_security_surfaces",
        _cache_hint=f"{focus_hint}:{class_name}:{max_results}",
    )


@tool
def plan_runtime_hooks(focus_hint: str = "", class_name: str = "", max_results: int = 12) -> str:
    """Plan smart runtime hook points for revalidation and hardened flows."""
    from apk_agent.tools.behavior_engine import plan_runtime_hooks as _plan_runtime_hooks

    def _run():
        pack = _ensure_behavior_graph_pack(auto_build=True, focus_hint=focus_hint or class_name)
        if pack is None:
            return json.dumps({"success": False, "error": "Behavior graph unavailable. Run build_behavior_graph first."})
        result = _plan_runtime_hooks(
            pack,
            focus_hint=focus_hint,
            class_name=class_name,
            max_results=max_results,
        )
        result["output_path"] = str(_behavior_graph_path())
        return json.dumps(result, ensure_ascii=False, indent=2)[:25000]

    return _safe_call(
        _run,
        "plan_runtime_hooks",
        _cache_hint=f"{focus_hint}:{class_name}:{max_results}",
    )


@tool
def plan_runtime_menu_workflow(
    focus_hint: str = "",
    class_name: str = "",
    overlay_mode: str = "in_app",
    max_results: int = 6,
    start_collapsed: bool = True,
) -> str:
    """Plan a step-by-step runtime-menu workflow for the current APK project.

    This is a non-injecting orchestration helper for the agent. It keeps the
    runtime-menu flow explicit and staged instead of collapsing everything into
    one action.

    The returned JSON includes:
    - `tool_chain`: the recommended ordered tool sequence
    - `spec_json`: the current floating-menu draft when hook planning succeeds
    - `binding_hints` / `unsupported_bindings`: any hook targets that still need manual follow-up
    - `recommended_next_tool` / `recommended_next_args`: the immediate next step
    """
    from apk_agent.tools.behavior_engine import plan_runtime_hooks as _plan_runtime_hooks
    from apk_agent.tools.runtime_menu import build_runtime_menu_spec_from_hook_plan as _build_runtime_menu_spec_from_hook_plan

    def _step(num: int, tool_name: str, purpose: str, args: dict[str, Any], *, when: str = "") -> dict[str, Any]:
        item = {
            "step": num,
            "tool": tool_name,
            "purpose": purpose,
            "args": args,
        }
        if when:
            item["when"] = when
        return item

    def _run():
        overlay_requires_manifest = overlay_mode in {"system_overlay", "hybrid"}
        tool_chain = [
            _step(
                1,
                "plan_runtime_hooks",
                "Identify runtime revalidation points and candidate hook methods before building the menu.",
                {
                    "focus_hint": focus_hint,
                    "class_name": class_name,
                    "max_results": max_results,
                },
            ),
            _step(
                2,
                "draft_runtime_menu_from_hooks",
                "Draft the floating menu spec from runtime-hook candidates and resolve supported static bindings.",
                {
                    "focus_hint": focus_hint,
                    "class_name": class_name,
                    "overlay_mode": overlay_mode,
                    "max_results": max_results,
                    "start_collapsed": start_collapsed,
                },
            ),
            _step(
                3,
                "inject_runtime_menu_scaffold",
                "Generate the actual draggable runtime menu inside the APK using the draft spec_json.",
                {
                    "spec_json": "<use top-level spec_json from this tool result>",
                    "overlay_mode": overlay_mode,
                    "reapply_on_resume": True,
                },
            ),
            _step(
                4,
                "configure_runtime_menu_manifest",
                "Declare overlay/service permissions only when the chosen mode really needs them.",
                {
                    "overlay_mode": overlay_mode,
                    "add_overlay_permission": overlay_requires_manifest,
                    "require_foreground_service": overlay_mode == "hybrid",
                },
                when="Only when overlay_mode is system_overlay or hybrid.",
            ),
            _step(
                5,
                "generate_runtime_validation_plan",
                "Prepare a focused post-injection validation checklist for the floating menu and its runtime actions.",
                {
                    "task": "runtime menu hooks, floating launcher, and reapply behavior",
                },
            ),
        ]

        pack = _ensure_behavior_graph_pack(auto_build=True, focus_hint=focus_hint or class_name)
        if pack is None:
            return json.dumps({
                "success": True,
                "workflow_mode": "step_by_step_runtime_menu",
                "behavior_graph_ready": False,
                "overlay_mode": overlay_mode,
                "tool_chain": [
                    _step(
                        0,
                        "build_behavior_graph",
                        "Build the behavior graph first so runtime hooks and menu drafts can be derived automatically.",
                        {"focus_hint": focus_hint or class_name},
                    ),
                    *tool_chain,
                ],
                "recommended_next_tool": "build_behavior_graph",
                "recommended_next_args": {"focus_hint": focus_hint or class_name},
                "notes": [
                    "Behavior graph data is unavailable, so no automatic runtime-menu draft was produced yet.",
                    "After build_behavior_graph succeeds, rerun this helper to get a resolved spec_json and binding hints.",
                ],
            }, ensure_ascii=False, indent=2)[:30000]

        hook_plan = _plan_runtime_hooks(
            pack,
            focus_hint=focus_hint,
            class_name=class_name,
            max_results=max_results,
        )
        draft = _build_runtime_menu_spec_from_hook_plan(
            hook_plan,
            title=(f"{class_name} Runtime Hooks" if class_name else "Runtime Hook Menu"),
            overlay_mode=overlay_mode,
            start_collapsed=start_collapsed,
            apktool_dir=_project.apktool_dir,
        )
        spec = draft.get("spec") or {}
        spec_json = draft.get("spec_json", "")
        buttons = list(spec.get("buttons") or [])
        unsupported = list(draft.get("unsupported_bindings") or [])

        recommended_next_tool = "inject_runtime_menu_scaffold" if buttons else "draft_runtime_menu_from_hooks"
        recommended_next_args = {
            "spec_json": spec_json,
            "overlay_mode": overlay_mode,
            "reapply_on_resume": True,
        } if buttons else {
            "focus_hint": focus_hint,
            "class_name": class_name,
            "overlay_mode": overlay_mode,
            "max_results": max_results,
            "start_collapsed": start_collapsed,
        }

        result = {
            "success": True,
            "workflow_mode": "step_by_step_runtime_menu",
            "behavior_graph_ready": True,
            "focus_hint": hook_plan.get("focus_hint", focus_hint),
            "class_name": hook_plan.get("class_name", class_name),
            "overlay_mode": overlay_mode,
            "tool_chain": tool_chain,
            "hook_plan_summary": {
                "hook_count": len(hook_plan.get("runtime_hooks") or []),
                "focus_hint": hook_plan.get("focus_hint", focus_hint),
                "class_name": hook_plan.get("class_name", class_name),
            },
            "draft_summary": {
                "draft_mode": draft.get("draft_mode", ""),
                "resolved_bindings": int(draft.get("resolved_bindings", 0) or 0),
                "unsupported_binding_count": len(unsupported),
                "button_count": len(buttons),
                "start_collapsed": bool(spec.get("start_collapsed", start_collapsed)),
                "launcher_label": str(spec.get("launcher_label", "HOOK")),
            },
            "spec_json": spec_json,
            "binding_hints": list(draft.get("binding_hints") or []),
            "unsupported_bindings": unsupported,
            "recommended_next_tool": recommended_next_tool,
            "recommended_next_args": recommended_next_args,
            "output_path": str(_behavior_graph_path()),
            "notes": [
                "This helper is planning-only: it does not inject files or change the manifest.",
                "Edit or extend spec_json before injection if you want extra manual buttons, sections, or shared_pref/static_field actions.",
                "Run configure_runtime_menu_manifest only when the final mode actually needs overlay/service permissions.",
            ],
        }
        return json.dumps(result, ensure_ascii=False, indent=2)[:30000]

    return _safe_call(
        _run,
        "plan_runtime_menu_workflow",
        _cache_hint=f"{focus_hint}:{class_name}:{overlay_mode}:{max_results}:{start_collapsed}",
    )


@tool
def inject_runtime_menu_scaffold(
        spec_json: str,
        overlay_mode: str = "in_app",
        reapply_on_resume: bool = True,
        dry_run: bool = False,
) -> str:
        """Inject a first-pass runtime mod-menu scaffold into the current APK project.

        The current implementation generates a draggable floating menu attached to the
        foreground Activity or a system overlay service, depending on overlay_mode.
        Controls can be buttons, toggles, or sliders, and each control can trigger one
        of these runtime action kinds:
            - shared_pref
            - static_field
            - invoke_static
            - dispatcher

        Example spec_json:
            {
                "title": "Premium Runtime Menu",
                "buttons": [
                    {
                        "id": "premium_pref",
                        "label": "Force Premium Pref",
                        "kind": "shared_pref",
                        "prefs_name": "user_state",
                        "key": "is_premium",
                        "type": "boolean",
                        "value": true,
                        "persist_on_resume": true
                    },
                    {
                        "id": "premium_toggle",
                        "label": "Premium Toggle",
                        "ui_kind": "toggle",
                        "kind": "dispatcher",
                        "method_descriptor": "Lcom/example/Hooks;->setPremiumEnabled(Landroid/content/Context;Z)V",
                        "persist_on_resume": true
                    },
                    {
                        "id": "speed_slider",
                        "label": "Speed Level",
                        "ui_kind": "slider",
                        "kind": "dispatcher",
                        "method_descriptor": "Lcom/example/Hooks;->setSpeedLevel(Landroid/content/Context;I)V",
                        "min_value": 1,
                        "max_value": 5,
                        "initial_value": 3
                    },
                    {
                        "label": "Call Premium Hook",
                        "kind": "invoke_static",
                        "method_descriptor": "Lcom/example/Hooks;->enableVip(Landroid/content/Context;)V"
                    }
                ]
            }

        Notes:
        - The scaffold creates real helper classes, drag listeners, dispatcher bindings,
            and startup bootstrap code.
        - Top-level `launcher_label` customizes the floating bubble text, and
            `start_collapsed=true` starts from the launcher icon instead of an open panel.
        - Action-level `section` strings insert grouped headers inside the panel.
        - `kind="dispatcher"` binds buttons/toggles/sliders directly to static runtime
            hook methods.
        - The generated menu is inside the app window itself in `in_app` mode, so no overlay permission
            is required for overlay_mode='in_app'.
        - If overlay_mode='system_overlay' or 'hybrid' is requested, the tool generates
            a real WindowManager overlay service and explicit Tier B requirements/warnings.
        - Persistent actions and control states are re-applied on later resumes/attaches until the
            generated reset button is pressed.
        """
        from apk_agent.tools.runtime_menu import inject_runtime_menu_scaffold as _inject_runtime_menu_scaffold

        def _run():
                try:
                        spec = json.loads(spec_json)
                except json.JSONDecodeError as exc:
                        return json.dumps({"success": False, "error": f"Invalid JSON: {exc}"})

                result = _inject_runtime_menu_scaffold(
                        _project.apktool_dir,
                        spec,
                        overlay_mode=overlay_mode,
                        backup_dir=_project.patch_backup_dir,
                        reapply_on_resume=reapply_on_resume,
                        dry_run=dry_run,
                )
                if result.get("success") and not dry_run:
                        _patch_journal.append({
                                "success": True,
                                "target_file": result.get("files_modified", ["runtime menu scaffold"])[0],
                                "description": (
                            f"Injected runtime menu scaffold requested={result.get('requested_overlay_mode', overlay_mode)} "
                            f"effective={result.get('effective_overlay_mode', overlay_mode)} "
                                        f"with {result.get('user_buttons', 0)} user buttons"
                                ),
                                "steps_applied": len(result.get("files_modified", [])),
                                "steps_total": len(result.get("files_modified", [])),
                                "errors": result.get("errors", [])[:5],
                                "tool": "inject_runtime_menu_scaffold",
                        })
                return json.dumps(result, ensure_ascii=False, indent=2)[:30000]

        return _safe_call(_run, "inject_runtime_menu_scaffold")


@tool
def draft_runtime_menu_from_hooks(
    focus_hint: str = "",
    class_name: str = "",
    overlay_mode: str = "in_app",
    max_results: int = 6,
    start_collapsed: bool = True,
) -> str:
    """Draft a grouped floating-menu spec from behavior-graph runtime hook candidates.

    This is an agent-side planning helper. It turns `plan_runtime_hooks(...)`
    results into a grouped runtime-menu spec with a floating launcher bubble and
    real dispatcher bindings when the candidate method resolves to a supported
    static smali method in the current apktool tree.

    Notes:
    - The returned `spec_json` is a draft, not an injected patch.
    - Supported static hook methods are rebound automatically via generated
        `RuntimeHookBindings`; unresolved hooks remain listed in `binding_hints`.
    - The draft groups hook candidates by runtime strategy section.
    """
    from apk_agent.tools.behavior_engine import plan_runtime_hooks as _plan_runtime_hooks
    from apk_agent.tools.runtime_menu import build_runtime_menu_spec_from_hook_plan as _build_runtime_menu_spec_from_hook_plan

    def _run():
        pack = _ensure_behavior_graph_pack(auto_build=True, focus_hint=focus_hint or class_name)
        if pack is None:
            return json.dumps({"success": False, "error": "Behavior graph unavailable. Run build_behavior_graph first."})
        plan = _plan_runtime_hooks(
            pack,
            focus_hint=focus_hint,
            class_name=class_name,
            max_results=max_results,
        )
        draft = _build_runtime_menu_spec_from_hook_plan(
            plan,
            title=(f"{class_name} Runtime Hooks" if class_name else "Runtime Hook Menu"),
            overlay_mode=overlay_mode,
            start_collapsed=start_collapsed,
            apktool_dir=_project.apktool_dir,
        )
        draft["output_path"] = str(_behavior_graph_path())
        return json.dumps(draft, ensure_ascii=False, indent=2)[:30000]

    return _safe_call(
        _run,
        "draft_runtime_menu_from_hooks",
        _cache_hint=f"{focus_hint}:{class_name}:{overlay_mode}:{max_results}:{start_collapsed}",
    )


@tool
def configure_runtime_menu_manifest(
        overlay_mode: str = "in_app",
        add_overlay_permission: bool = False,
        require_foreground_service: bool = False,
) -> str:
        """Ensure AndroidManifest.xml declares the permissions needed by runtime menu modes.

        Use this after planning a runtime menu when you need system-overlay or
        foreground-service support.

        Notes:
        - in_app mode usually needs no extra permissions.
        - system_overlay / hybrid modes typically need SYSTEM_ALERT_WINDOW.
        - Foreground-service flows may also need FOREGROUND_SERVICE and, on newer
            targets, POST_NOTIFICATIONS.
        - This tool declares permissions only; Android may still require an explicit
            runtime approval flow before overlays can draw.
        - Tier B should be treated as high-risk/high-friction: permission friction,
            higher detectability, and more OEM/API-specific crash risk.
        """
        from apk_agent.tools.runtime_menu import configure_runtime_menu_manifest as _configure_runtime_menu_manifest

        def _run():
                result = _configure_runtime_menu_manifest(
                        _project.apktool_dir,
                        overlay_mode=overlay_mode,
                        backup_dir=_project.patch_backup_dir,
                        add_overlay_permission=add_overlay_permission,
                        require_foreground_service=require_foreground_service,
                )
                if result.get("success") and (result.get("permissions_added") or result.get("components_added")):
                        _patch_journal.append({
                                "success": True,
                                "target_file": result.get("manifest_file", "AndroidManifest.xml"),
                                "description": (
                            f"Configured runtime menu manifest requested={result.get('requested_overlay_mode', overlay_mode)} "
                            f"effective={result.get('effective_overlay_mode', overlay_mode)} "
                            f"with permissions/components: {', '.join(result.get('permissions_added', []) + result.get('components_added', []))}"
                                ),
                        "steps_applied": len(result.get("permissions_added", [])) + len(result.get("components_added", [])),
                        "steps_total": len(result.get("permissions_added", [])) + len(result.get("components_added", [])),
                                "errors": [],
                                "tool": "configure_runtime_menu_manifest",
                        })
                return json.dumps(result, ensure_ascii=False, indent=2)[:20000]

        return _safe_call(_run, "configure_runtime_menu_manifest")


@tool
def analyze_network_behavior(focus_hint: str = "", max_results: int = 20) -> str:
    """Analyze network-to-state behavior boundaries in the unified behavior graph."""
    from apk_agent.tools.behavior_engine import analyze_network_behavior as _analyze_network_behavior

    def _run():
        pack = _ensure_behavior_graph_pack(auto_build=True, focus_hint=focus_hint)
        if pack is None:
            return json.dumps({"success": False, "error": "Behavior graph unavailable. Run build_behavior_graph first."})
        result = _analyze_network_behavior(
            pack,
            focus_hint=focus_hint,
            max_results=max_results,
        )
        result["output_path"] = str(_behavior_graph_path())
        return json.dumps(result, ensure_ascii=False, indent=2)[:25000]

    return _safe_call(
        _run,
        "analyze_network_behavior",
        _cache_hint=f"{focus_hint}:{max_results}",
    )


@tool
def recover_semantic_symbols(class_name: str = "", max_results: int = 12) -> str:
    """Recover semantic symbol hints for likely obfuscated high-value classes."""
    from apk_agent.tools.behavior_engine import recover_semantic_symbols as _recover_semantic_symbols

    def _run():
        pack = _ensure_behavior_graph_pack(auto_build=True, focus_hint=class_name)
        if pack is None:
            return json.dumps({"success": False, "error": "Behavior graph unavailable. Run build_behavior_graph first."})
        result = _recover_semantic_symbols(
            pack,
            class_name=class_name,
            max_results=max_results,
        )
        result["output_path"] = str(_behavior_graph_path())
        return json.dumps(result, ensure_ascii=False, indent=2)[:25000]

    return _safe_call(
        _run,
        "recover_semantic_symbols",
        _cache_hint=f"{class_name}:{max_results}",
    )


@tool
def patch_api_response_flow(
    target_class: str,
    field_overrides_json: str,
    endpoint_hint: str = "",
    strategy: str = "auto",
    max_factory_methods: int = 8,
    dry_run: bool = False,
) -> str:
    """Patch the response-to-model boundary for a target entity class.

    Applies targeted overrides to constructors, setter-like methods, and
    response/factory methods that return the entity, so server-derived values
    enter the app already normalized to the desired state.
    """
    from apk_agent.tools.api_response_patcher import patch_api_response_flow as _patch

    def _run():
        idx = _ensure_smali_index()
        if idx is None:
            return json.dumps({"success": False, "error": "No SmaliIndex. Run build_smali_index first."})
        overrides = json.loads(field_overrides_json)
        if not isinstance(overrides, dict) or not overrides:
            return json.dumps({"success": False, "error": "field_overrides_json must be a non-empty JSON object."})

        result = _patch(
            idx,
            _project.apktool_dir,
            target_class,
            overrides,
            endpoint_hint=endpoint_hint,
            strategy=strategy,
            backup_dir=_project.patch_backup_dir,
            max_factory_methods=max_factory_methods,
            dry_run=dry_run,
        )
        _patch_journal.append({
            "success": result.get("success", False),
            "target_file": result.get("target_file", target_class),
            "description": f"API response flow patch for {target_class} — {result.get('patches_applied', 0)} patch units",
            "steps_applied": result.get("patches_applied", 0),
            "steps_total": result.get("patches_applied", 0),
            "errors": result.get("errors", [])[:5],
            "tool": "patch_api_response_flow",
        })
        return json.dumps(result, ensure_ascii=False, indent=2)[:30000]

    return _safe_call(_run, "patch_api_response_flow")


@tool
def inject_runtime_override_layer(rules_json: str, reapply_on_resume: bool = False) -> str:
    """Inject an in-APK runtime override helper and bootstrap hook.

    Supported rule kinds:
      - shared_pref
      - static_field
    """
    from apk_agent.tools.runtime_override import inject_runtime_override_layer as _inject

    def _run():
        rules = json.loads(rules_json)
        if not isinstance(rules, list) or not rules:
            return json.dumps({"success": False, "error": "rules_json must be a non-empty JSON array."})

        result = _inject(
            _project.apktool_dir,
            rules,
            backup_dir=_project.patch_backup_dir,
            reapply_on_resume=reapply_on_resume,
        )
        _patch_journal.append({
            "success": result.get("success", False),
            "target_file": result.get("helper_file", "runtime override layer"),
            "description": f"Injected runtime override layer with {result.get('rules_applied', 0)} rules",
            "steps_applied": result.get("rules_applied", 0),
            "steps_total": result.get("rules_applied", 0),
            "errors": result.get("errors", [])[:5],
            "tool": "inject_runtime_override_layer",
        })
        return json.dumps(result, ensure_ascii=False, indent=2)[:25000]

    return _safe_call(_run, "inject_runtime_override_layer")


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
    rename_package_identity,
    find_resource_colors,
    find_resource_styles,
    replace_resource_colors,
    list_resource_drawables,
    analyze_native_libs,
    analyze_native_re_core,
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
    find_entry_points,
    map_hierarchy,
    validate_patch,
    diff_patched_file,
    analyze_shared_prefs,
    extract_native_strings,
    scan_assets_secrets,
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
    route_reverse_engineering_workflow,
    search_binary_strings,
    analyze_dart_aot,
    build_dart_aot_index,
    locate_dart_aot_candidates,
    preview_dart_aot_patch,
    apply_dart_aot_patch,
    validate_dart_aot_patch,
    patch_binary_strings,
    plan_native_patch_targets,
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
    # Working memory and planning
    update_task_plan,
    edit_task_plan,
    mark_task_done,
    update_scratchpad,
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
    # SmaliIndex-powered analysis (Tier 1 & 2)
    discover_entity_classes,
    detect_gate_chain,
    trace_field_writers,
    validate_patch_completeness,
    smart_entity_patch,
    frida_script_generator,
    diff_apk_variants,
    # Patching
    apply_text_patch,
    preview_text_patch,
    apply_smali_patch,
    preview_smali_patch,
    restore_smali_backup,
    patch_binary_hex,
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
    get_threat_model,
    analyze_data_flow,
    run_taint_analysis,
    find_hardcoded_crypto,
    generate_bypass_plans,
    analyze_manifest_deep,
    scan_cloud_secrets,
    map_semantic_architecture,
    recover_hidden_state_model,
    profile_guard_and_revalidation_surface,
    build_app_knowledge_pack,
    summarize_app_knowledge,
    query_app_knowledge,
    build_behavior_graph,
    summarize_behavior_graph,
    query_behavior_graph,
    locate_feature_controls,
    recover_state_transitions,
    map_security_surfaces,
    plan_runtime_hooks,
    plan_runtime_menu_workflow,
    analyze_network_behavior,
    recover_semantic_symbols,
    draft_runtime_menu_from_hooks,
    inject_runtime_menu_scaffold,
    configure_runtime_menu_manifest,
    patch_api_response_flow,
    inject_runtime_override_layer,
    semantic_method_slice,
    find_enforcement_surfaces,
    validate_patch_pipeline,
    generate_runtime_validation_plan,
]
