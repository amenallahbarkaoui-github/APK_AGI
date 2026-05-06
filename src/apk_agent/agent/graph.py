"""LangGraph graph construction — ReAct agent with HITL support.

The graph implements the Think → Act → Observe → Re-plan loop:

    ┌──────────┐      tool_call       ┌───────────┐
    │  agent   │ ──────────────────▶  │  tools    │
    │  (LLM)   │ ◀──────────────────  │  (exec)   │
    └──────────┘     observation       └───────────┘
         │
         │  needs_human / done
         ▼
    ┌──────────┐
    │  human   │  (interrupt → resume)
    │  review  │
    └──────────┘
         │
         ▼
       agent (continues with human feedback)
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Literal

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.types import interrupt, Command

from apk_agent.agent.prompts import SYSTEM_PROMPT
from apk_agent.agent.state import AgentState
from apk_agent.agent.tools_def import ALL_TOOLS, set_tool_context, _get_all_smali_dirs, _project, _get_scratchpad, _get_task_plan
from apk_agent.compactor import Compactor, count_message_tokens
from apk_agent.config import AppConfig
from apk_agent.llm.provider import get_llm, is_quota_exhausted_error, is_retryable_api_error
from apk_agent.workspace import Project

logger = logging.getLogger("apk_agent.graph")

# Module-level compactor instance (initialised in build_graph)
_compactor: Compactor | None = None

# ---------------------------------------------------------------------------
# Tool call loop detector — prevents infinite repeated tool calls
# ---------------------------------------------------------------------------
# Per-session tracking.  Keyed by thread_id so sessions don't interfere.
_session_tool_trackers: dict[str, dict[str, int]] = {}
_session_nudge_counts: dict[str, int] = {}
_LOOP_WARN_THRESHOLD = 6   # inject warning after this many repetitions
_LOOP_BLOCK_THRESHOLD = 15  # force different approach after this many

# Tools that should NEVER be blocked — only warned.  Build/sign/patch
# tools legitimately need retries when the agent fixes smali errors.
_NEVER_BLOCK_TOOLS: set[str] = {
    "apktool_build", "apktool_decode", "sign_apk", "zipalign_apk",
    "apply_smali_patch", "apply_multi_patch", "batch_patch_methods",
    "inject_smali_code", "override_constructor_field", "add_startup_hook",
    "patch_api_response_flow", "inject_runtime_override_layer",
    "write_file", "read_file",
}

_DURABLE_STATE_MAX_CHARS = 2600
_DURABLE_STATE_TOOL_HISTORY_LIMIT = 6
_DURABLE_STATE_REGISTRY_LIMIT = 6
_DURABLE_STATE_SCRATCHPAD_LIMIT = 8
_DURABLE_STATE_FINDING_LIMIT = 3

# The active thread_id, set by build_graph / the CLI before each run
_active_thread_id: str = "__default__"


def set_active_thread(thread_id: str) -> None:
    """Set the active thread/session id for loop tracking."""
    global _active_thread_id
    _active_thread_id = thread_id


def _get_tool_tracker() -> dict[str, int]:
    """Return the tool-call tracker for the active session."""
    if _active_thread_id not in _session_tool_trackers:
        _session_tool_trackers[_active_thread_id] = defaultdict(int)
    return _session_tool_trackers[_active_thread_id]


def _get_nudge_count() -> int:
    """Return the consecutive-no-tool count for the active session."""
    return _session_nudge_counts.get(_active_thread_id, 0)


def _set_nudge_count(n: int) -> None:
    """Set the consecutive-no-tool count for the active session."""
    _session_nudge_counts[_active_thread_id] = n


def _hash_tool_args(args: dict) -> str:
    """Produce a short stable hash of tool call arguments for dedup detection."""
    raw = json.dumps(args, sort_keys=True, default=str)
    return hashlib.md5(raw.encode()).hexdigest()[:12]


def _check_tool_loops(tool_calls: list[Any]) -> str | None:
    """Track tool calls and return a warning message if loops detected."""
    tracker = _get_tool_tracker()
    warnings = []
    for tc in tool_calls:
        name = tc.get("name", "")
        args_hash = _hash_tool_args(tc.get("args", {}))
        key = f"{name}:{args_hash}"
        tracker[key] += 1
        count = tracker[key]

        if count >= _LOOP_BLOCK_THRESHOLD and name not in _NEVER_BLOCK_TOOLS:
            warnings.append(
                f"🚫 BLOCKED: You have called `{name}` with the same/similar arguments "
                f"{count} times and got the same results each time. "
                f"STOP calling this tool. Try a COMPLETELY DIFFERENT tool or approach. "
                f"For example: if smart_search isn't finding colors, use find_app_colors() "
                f"or read_file on res/values/colors.xml directly."
            )
        elif count >= _LOOP_WARN_THRESHOLD:
            warnings.append(
                f"⚠️ WARNING: `{name}` called {count} times with similar args. "
                f"Results are unlikely to change. Consider a different approach."
            )

    return "\n".join(warnings) if warnings else None


def _clip_durable_state_lines(lines: list[str], max_chars: int = _DURABLE_STATE_MAX_CHARS) -> str:
    selected: list[str] = []
    used = 0
    total_lines = len(lines)

    for idx, line in enumerate(lines):
        normalized = str(line or "").rstrip()
        if not normalized:
            continue
        line_cost = len(normalized) + 1
        if selected and used + line_cost > max_chars:
            remaining = total_lines - idx
            omission = f"... [{remaining} durable-state lines omitted]"
            omission_cost = len(omission) + 1
            while selected and used + omission_cost > max_chars:
                removed = selected.pop()
                used -= len(removed) + 1
            if used + omission_cost <= max_chars:
                selected.append(omission)
            break
        selected.append(normalized)
        used += line_cost

    return "\n".join(selected)


def _select_patch_registry_entries(registry: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for entry in reversed(registry):
        entry_id = str(entry.get("id", ""))
        if entry.get("status") not in {"user_rejected", "retrying", "failed"}:
            continue
        if entry_id in seen_ids:
            continue
        selected.append(entry)
        seen_ids.add(entry_id)
        if len(selected) >= _DURABLE_STATE_REGISTRY_LIMIT:
            break

    for entry in reversed(registry):
        if len(selected) >= _DURABLE_STATE_REGISTRY_LIMIT:
            break
        entry_id = str(entry.get("id", ""))
        if entry_id in seen_ids:
            continue
        selected.append(entry)
        seen_ids.add(entry_id)

    selected.reverse()
    return selected


# ---------------------------------------------------------------------------
# Graph node functions
# ---------------------------------------------------------------------------


def agent_node(state: AgentState) -> dict:
    """LLM reasoning node — decides next action (tool call or final answer).

    Also checks for auto-compact: if the conversation exceeds the token
    threshold, it compacts old messages into a summary before calling the LLM.
    """
    from apk_agent.agent.graph import _llm_with_tools, _compactor  # noqa: lazy ref
    from apk_agent.agent.orchestrator import _sanitize_messages
    from langchain_core.messages import RemoveMessage

    messages = list(state["messages"])
    # Track which message IDs existed before compaction so we can persist
    # the compaction by emitting RemoveMessage entries for the old ones.
    _pre_compact_ids: list[str] = []
    _compact_summary_msgs: list[BaseMessage] = []

    # ── User feedback → patch registry updates ─────────────────────
    # Scan the latest user message for patch-failure keywords and update
    # the registry accordingly.  This lets the agent learn from user
    # feedback even after compaction.
    registry = list(state.get("patch_registry") or [])
    _registry_dirty = False
    if registry:
        # Find the latest HumanMessage (the one the user just sent)
        _latest_human = None
        for _m in reversed(messages):
            if isinstance(_m, HumanMessage):
                _latest_human = _m
                break
        if _latest_human:
            _htxt = (str(_latest_human.content) or "").lower()
            _REJECT_KW = (
                "didn't work", "لم تنجح", "لم تعمل", "ما زال", "لا يزال",
                "still ", "not working", "failed", "doesn't work",
                "patch failed", "ads still", "لا تزال", "ما نجح",
                "redo", "re-do", "try again", "أعد", "جرب مرة",
                "broken", "crash", "لم ينجح", "not fixed", "ما اشتغل",
            )
            if any(kw in _htxt for kw in _REJECT_KW):
                # Mark the most recent 'applied' patches as user_rejected
                for _entry in reversed(registry):
                    if _entry.get("status") == "applied":
                        _entry["status"] = "user_rejected"
                        _entry["user_feedback"] = str(_latest_human.content)[:200]
                        _registry_dirty = True
                        break  # Only reject the latest one per message

    # Inject system prompt if not already present
    if not messages or not isinstance(messages[0], SystemMessage):
        messages.insert(0, SystemMessage(content=SYSTEM_PROMPT))

    _total_tool_msgs_so_far = sum(1 for m in state["messages"] if isinstance(m, ToolMessage))
    if _total_tool_msgs_so_far == 0:
        messages.insert(
            1,
            HumanMessage(
                content=(
                    "[DYNAMIC TOOL CATALOG]\n"
                    "Additional strategic tools available beyond the base static reference:\n"
                    "- Entry/recovery: find_entry_points, map_hierarchy, analyze_shared_prefs, extract_native_strings, scan_assets_secrets\n"
                    "- Native RE core: analyze_native_re_core, plan_native_patch_targets for ELF/JNI/import/export/function-anchor recovery\n"
                    "- Validation: validate_patch, diff_patched_file, validate_patch_pipeline, generate_runtime_validation_plan\n"
                    "- Architecture recovery: map_semantic_architecture, recover_hidden_state_model, profile_guard_and_revalidation_surface, find_enforcement_surfaces, semantic_method_slice\n"
                    "- Flutter/Dart AOT: analyze_dart_aot, build_dart_aot_index, locate_dart_aot_candidates for libapp.so anchor recovery before bounded native patching\n"
                    "- Routing: route_reverse_engineering_workflow to classify the current app into java/native/flutter/unity/react-native/dynamic-loader workflows before diving in\n"
                    "- Task planning: update_task_plan, edit_task_plan, mark_task_done to keep a concrete multi-step plan and update it as work progresses\n"
                    "- Runtime/response control: patch_api_response_flow, inject_runtime_override_layer, plan_runtime_menu_workflow, draft_runtime_menu_from_hooks, inject_runtime_menu_scaffold, configure_runtime_menu_manifest\n"
                    "- Runtime menu workflow: plan_runtime_menu_workflow -> draft_runtime_menu_from_hooks -> inject_runtime_menu_scaffold -> configure_runtime_menu_manifest (overlay only)\n"
                    "- Working memory: update_scratchpad (save any free-form hypothesis, suspicious class, state field, or server-overwrite note for later turns)\n"
                    "- Text/resource/binary patching: apply_text_patch, preview_text_patch, patch_binary_hex, find_resource_colors, find_resource_styles, replace_resource_colors, list_resource_drawables\n"
                    "- Clone/install identity: rename_package_identity\n"
                    "- Advanced scanning/memory: unified_scan, analyze_data_flow, run_taint_analysis, find_hardcoded_crypto, generate_bypass_plans, save_evidence, load_evidence, search_evidence, get_evidence_summary\n"
                    "- Large outputs are lossless: if a tool returns tool_output_spilled/output_file, inspect the FULL saved payload with read_file(output_file, ...) or search_in_code in outputs/tool_payloads instead of relying on the preview."
                )
            ),
        )

    # Inject durable findings summary as a reminder (survives compaction)
    findings = state.get("findings") or []
    patches = state.get("patch_results") or []
    graph_ready = state.get("graph_ready", False)
    target_pkgs = state.get("target_packages") or []
    excluded_pkgs = state.get("excluded_packages") or []

    # Always inject state awareness (even without findings)
    summary_parts = []

    # Graph / index status — critical for tool selection
    if graph_ready:
        summary_parts.append(
            "⚡ Code graph + index: READY — use graph_callers, graph_callees, "
            "graph_security_scan, graph_find_path, index_lookup_* for instant results. "
            "These are 100x faster than search tools."
        )
    else:
        summary_parts.append(
            "⏳ Code graph: NOT BUILT YET — run apktool_decompile first (it auto-builds the graph)."
        )

    summary_parts.append(
        "📦 Oversized tool results may be spilled to outputs/tool_payloads with output_file. "
        "That preview is not truncation of the real data: read_file(output_file, ...) or search_in_code() on the payload directory to inspect/search the full saved content."
    )

    # Package scope — critical for avoiding third-party SDK noise
    if target_pkgs:
        summary_parts.append(f"🎯 App packages (YOUR SCOPE): {', '.join(target_pkgs)}")
    if excluded_pkgs:
        summary_parts.append(f"🚫 Excluded SDKs: {len(excluded_pkgs)} third-party packages auto-filtered")

    if findings:
        by_sev: dict[str, int] = {}
        for f in findings:
            s = f.get("severity", "info")
            by_sev[s] = by_sev.get(s, 0) + 1
        summary_parts.append(f"📋 Findings: {dict(by_sev)} ({len(findings)} total)")
        # Show top critical/high (capped to avoid bloat)
        critical = [f for f in findings if f.get("severity") in ("CRITICAL", "critical", "HIGH", "high")]
        for c in critical[:_DURABLE_STATE_FINDING_LIMIT]:
            summary_parts.append(
                "  • "
                f"[{c.get('severity', '')}] "
                f"{_shorten_state_text(c.get('name', ''), max_chars=72)}: "
                f"{_shorten_state_text(c.get('file', ''), max_chars=72)}"
            )
    if patches:
        ok = sum(1 for p in patches if p.get("success"))
        summary_parts.append(f"🔧 Patches applied: {ok}/{len(patches)}")

    tool_history = state.get("tool_history") or []
    if tool_history:
        summary_parts.append("🧰 Recent tool results:")
        for entry in tool_history[-_DURABLE_STATE_TOOL_HISTORY_LIMIT:]:
            icon = "✅" if entry.get("success", True) else "❌"
            summary_parts.append(
                f"  {icon} {entry.get('tool', '?')}: "
                f"{_shorten_state_text(entry.get('summary', ''), max_chars=120)}"
            )

    # Task plan — multi-objective decomposition
    task_plan = state.get("task_plan") or []
    if task_plan:
        summary_parts.append("📋 Task Plan:")
        for t in task_plan[:8]:
            status = t.get("status", "pending")
            icon = "✅" if status == "done" else "🔄" if status == "in_progress" else "⬜"
            summary_parts.append(f"  {icon} [{t.get('id', '?')}] {_shorten_state_text(t.get('desc', ''), max_chars=110)}")

    planning_started = bool(state.get("planning_started", False) or task_plan)
    if planning_started or state.get("patch_plan_ready") or state.get("prebuild_validation_ready") or state.get("runtime_validation_ready"):
        summary_parts.append("🧭 Planning Readiness:")
        summary_parts.append(
            "  "
            f"{'✅' if planning_started else '⬜'} plan  "
            f"{'✅' if state.get('analysis_complete_for_patching', False) else '⬜'} analysis  "
            f"{'✅' if state.get('patch_plan_ready', False) else '⬜'} patch-plan  "
            f"{'✅' if state.get('prebuild_validation_ready', False) else '⬜'} prebuild-validation  "
            f"{'✅' if state.get('runtime_validation_ready', False) else '⬜'} runtime-validation"
        )

    # Patch registry — full journal of every patch attempt (survives compaction)
    # (uses local `registry` which may have user-feedback updates from above)
    if registry:
        display_reg = _select_patch_registry_entries(registry)
        summary_parts.append(f"\n🗂️ PATCH REGISTRY (showing {len(display_reg)}/{len(registry)}) — DO NOT re-apply patches that already succeeded:")
        for entry in display_reg:
            pid = entry.get("id", "?")
            tool = entry.get("tool", "?")
            target = entry.get("target", "?")
            pattern_desc = _shorten_state_text(entry.get("pattern", ""), max_chars=40)
            status = entry.get("status", "?")
            feedback = entry.get("user_feedback", "")

            status_icon = {"applied": "✅", "failed": "❌", "user_rejected": "🔄", "retrying": "🔄", "verified": "✔️"}.get(status, "❓")
            line = f"  {status_icon} #{pid} [{tool}] {target} — {pattern_desc}"
            if feedback:
                line += f" | USER: {_shorten_state_text(feedback, max_chars=28)}"
            summary_parts.append(line)

        # Highlight patches the user rejected (need re-doing)
        rejected = [e for e in registry if e.get("status") in ("user_rejected", "retrying")]
        if rejected:
            summary_parts.append(f"\n  ⚠️ {len(rejected)} patch(es) need re-work based on user feedback!")
            for e in rejected[:5]:
                summary_parts.append(f"    → #{e['id']} {e['target']}: {e.get('user_feedback', '')[:60]}")

    # Scratchpad — persistent working memory that survives compaction
    scratchpad = state.get("scratchpad") or {}
    if scratchpad:
        summary_parts.append("📝 Scratchpad (working memory):")
        for k, v in list(scratchpad.items())[:_DURABLE_STATE_SCRATCHPAD_LIMIT]:
            val_str = _shorten_state_text(v, max_chars=90)
            summary_parts.append(f"  • {k}: {val_str}")

    if summary_parts:
        state_msg = _clip_durable_state_lines(summary_parts)
        # Insert after system prompt
        insert_idx = 1 if isinstance(messages[0], SystemMessage) else 0

        # Count total tool calls so far (rough proxy for analysis depth)
        _total_tool_msgs = sum(1 for m in state["messages"] if isinstance(m, ToolMessage))
        _total_patches = len(patches)

        # Build a depth-enforcement reminder based on current state
        depth_reminder = "⚡ REMINDER: Execute tools NOW. Batch independent tools in parallel."
        if _total_patches == 0 and _total_tool_msgs < 15:
            depth_reminder = (
                "🔴 DEPTH CHECK: You have made only {tc} tool calls and 0 patches. "
                "You MUST complete thorough analysis (15+ tool calls) BEFORE your first patch. "
                "Use map_feature_checks, analyze_subscription_model, trace_field_access, "
                "cross_reference_map, and READ JADX SOURCE for every target class. "
                "DO NOT RUSH. Discover the FULL architecture first."
            ).format(tc=_total_tool_msgs)
        elif _total_patches > 0 and _total_tool_msgs < 20:
            depth_reminder = (
                "⚠️ DEPTH WARNING: You started patching after only {tc} tool calls. "
                "Make sure you have mapped ALL check points — not just the first one you found. "
                "Use verify_bypass_completeness() BEFORE building."
            ).format(tc=_total_tool_msgs)

        messages.insert(insert_idx, HumanMessage(
            content=f"[DURABLE STATE — graph, scope, findings, patches & memory]\n{state_msg}\n\n{depth_reminder}"
        ))

    # --- Auto-compact check ---
    if _compactor is not None and _compactor.should_compact(messages):
        logger.info(
            "Context too large (~%d tokens). Running auto-compact...",
            _compactor.last_token_count,
        )
        # Get the raw LLM (without tools) for compaction
        from apk_agent.agent.graph import _raw_llm

        # Remember ALL existing message IDs before compaction
        _pre_compact_ids = [
            str(m.id) for m in state["messages"] if getattr(m, "id", None)
        ]

        compacted = _compactor.compact(messages, _raw_llm, agent_state=dict(state))
        if compacted is not messages:
            messages = compacted
            logger.info(
                "Compacted to %d messages (~%d tokens)",
                len(messages),
                count_message_tokens(messages),
            )

            # Collect only the NEW messages created by compaction (compact summary).
            # These have id=None since they were just created, not from the checkpoint.
            # Recent messages that survived compaction already have IDs in the checkpoint
            # and don't need to be re-added.
            _compact_summary_msgs = [
                m for m in compacted
                if getattr(m, "id", None) is None
                and not isinstance(m, SystemMessage)
            ]

            # Inject auto-continue instruction so the agent doesn't stop
            auto_continue = HumanMessage(
                content=(
                    "[SYSTEM] Context was auto-compacted. Read the summary above carefully, "
                    "then CONTINUE working on the original task without asking. "
                    "Do NOT repeat already-completed tool calls. Execute the NEXT step immediately."
                )
            )
            messages.append(auto_continue)
            _compact_summary_msgs.append(auto_continue)

    # Compute survived IDs NOW (before sanitization which may create new
    # message objects without preserving the original .id attribute).
    _compacted_survived_ids: set[str] = set()
    if _pre_compact_ids:
        _compacted_survived_ids = {
            str(m.id) for m in messages if getattr(m, "id", None)
        }

    # Sanitize: prevent content block arrays > 5 elements (API proxy limit)
    messages = _sanitize_messages(messages)

    # Truncate large tool results in OLD messages only (preserve recent ones)
    # Keep head + tail so we don't lose summary headers or final findings
    _MAX_CHARS = 4500
    _HEAD = 3000
    _TAIL = 1200
    _RECENT = 10  # never truncate the last N messages (covers current tool batch)
    cutoff = len(messages) - _RECENT
    for i, msg in enumerate(messages):
        if i >= cutoff:
            break
        if isinstance(msg, ToolMessage) and isinstance(msg.content, str):
            if len(msg.content) > _MAX_CHARS:
                head = msg.content[:_HEAD]
                tail = msg.content[-_TAIL:]
                skipped = len(msg.content) - _HEAD - _TAIL
                messages[i] = ToolMessage(
                    content=f"{head}\n\n... [{skipped} chars omitted] ...\n\n{tail}",
                    tool_call_id=msg.tool_call_id,
                    name=getattr(msg, "name", None) or "unknown_tool",
                )

    # --- Final safety: ensure no orphaned tool_call_ids remain ---
    # Build set of all valid tool_call ids from AIMessages (check BOTH
    # .tool_calls AND additional_kwargs["tool_calls"] — LangChain uses
    # additional_kwargs as fallback when .tool_calls is empty, so both
    # must be consistent)
    _valid_tc_ids: set[str] = set()
    for msg in messages:
        if isinstance(msg, AIMessage):
            # Collect from .tool_calls
            for tc in (msg.tool_calls or []):
                tid = tc.get("id") or ""
                if tid:
                    _valid_tc_ids.add(tid)
            # Also collect from additional_kwargs (the raw API format)
            for tc in msg.additional_kwargs.get("tool_calls", []):
                tid = tc.get("id") or ""
                if tid:
                    _valid_tc_ids.add(tid)

    # Sync additional_kwargs["tool_calls"] with .tool_calls on every AIMessage
    # to prevent ghost tool_calls from leaking into the API payload
    for msg in messages:
        if isinstance(msg, AIMessage):
            ak_tcs = msg.additional_kwargs.get("tool_calls")
            if ak_tcs is not None:
                # Keep only entries whose id is in the current .tool_calls
                current_ids = {tc.get("id") for tc in (msg.tool_calls or [])}
                msg.additional_kwargs["tool_calls"] = [
                    tc for tc in ak_tcs if tc.get("id") in current_ids
                ]
                # If .tool_calls was emptied (e.g. by loop detector), clear ak too
                if not msg.tool_calls:
                    msg.additional_kwargs.pop("tool_calls", None)

    # Rebuild valid IDs after sync
    _valid_tc_ids = set()
    for msg in messages:
        if isinstance(msg, AIMessage):
            for tc in (msg.tool_calls or []):
                tid = tc.get("id") or ""
                if tid:
                    _valid_tc_ids.add(tid)

    # Drop any ToolMessage whose tool_call_id is missing or not in any AIMessage
    messages = [
        msg for msg in messages
        if not isinstance(msg, ToolMessage)
        or (msg.tool_call_id and msg.tool_call_id in _valid_tc_ids)
    ]

    # Retry with exponential backoff for transient API errors
    max_retries = 3
    for attempt in range(max_retries + 1):
        try:
            response = _llm_with_tools.invoke(messages)
            break
        except Exception as e:
            err_str = str(e).lower()
            is_retryable = is_retryable_api_error(e)
            # On "tool_call_id is not found" errors, re-sanitize to drop orphans
            if "tool_call_id" in err_str and "not found" in err_str:
                logger.warning("Orphaned tool_call_id error — re-sanitizing messages...")
                messages = _sanitize_messages(messages)
            # On "tool name is required" errors, re-sanitize before retry
            if "tool name is required" in err_str:
                logger.warning("Gemini tool-name error — re-sanitizing messages...")
                messages = _sanitize_messages(messages)
                # Also strip any AIMessage tool_calls that still have no name
                for _m in messages:
                    if isinstance(_m, AIMessage) and _m.tool_calls:
                        _m.tool_calls = [tc for tc in _m.tool_calls if tc.get("name")]
            # On "must be in json format" errors — the LLM produced malformed
            # tool call arguments (commonly from multi-line code strings).
            # Strip the last AIMessage with bad tool_calls and tell the LLM
            # to retry with simpler arguments.
            if "must be in json format" in err_str or "invalidparameter" in err_str:
                logger.warning("Malformed tool-call JSON — stripping bad AI message and retrying...")
                # Remove the last AIMessage that had broken tool_calls
                while messages and isinstance(messages[-1], AIMessage):
                    messages.pop()
                messages.append(HumanMessage(
                    content=(
                        "[SYSTEM] Your previous tool call failed because the arguments "
                        "were not valid JSON. This usually happens with multi-line code "
                        "in execute_custom_code. RULES FOR RETRY:\n"
                        "1. Keep code SHORT — prefer using existing tools instead of execute_custom_code\n"
                        "2. If you must use execute_custom_code, use SIMPLE one-liner code\n"
                        "3. Avoid triple-quotes, backslashes, and special chars in code strings\n"
                        "4. Use semicolons to join statements on one line\n"
                        "5. Prefer read_file, smart_search, context_search over custom code\n"
                        "Now proceed with your task using a different approach."
                    )
                ))
            if is_quota_exhausted_error(e):
                logger.error("API quota exhausted — stopping retries: %s", str(e)[:160])
            if not is_retryable or attempt >= max_retries:
                raise
            wait = 2 ** attempt * 5  # 5s, 10s, 20s
            logger.warning(
                "API error (attempt %d/%d): %s — retrying in %ds...",
                attempt + 1, max_retries, str(e)[:120], wait,
            )
            time.sleep(wait)

    # --- Tool call loop detection ---
    # Check if the LLM is repeating the same tools with same args
    result_messages = [response]
    if isinstance(response, AIMessage) and response.tool_calls:
        loop_warning = _check_tool_loops(response.tool_calls)
        if loop_warning:
            logger.warning("Loop detected: %s", loop_warning[:200])
            # Inject a warning BEFORE the tool calls so the agent sees it next turn
            result_messages.append(HumanMessage(
                content=f"[SYSTEM — LOOP DETECTOR]\n{loop_warning}"
            ))
            # If any tool is at block threshold, strip those tool_calls entirely
            tracker = _get_tool_tracker()
            filtered_calls = []
            for tc in response.tool_calls:
                args_hash = _hash_tool_args(tc.get("args", {}))
                key = f"{tc.get('name', '')}:{args_hash}"
                tc_name = tc.get('name', '')
                if tc_name in _NEVER_BLOCK_TOOLS or tracker.get(key, 0) < _LOOP_BLOCK_THRESHOLD:
                    filtered_calls.append(tc)
            if not filtered_calls:
                # All calls blocked — strip tool_calls, force agent to rethink
                response.tool_calls = []
                result_messages = [response, HumanMessage(
                    content=f"[SYSTEM — LOOP DETECTOR]\n{loop_warning}\n"
                    "All your requested tool calls were blocked because they are duplicates. "
                    "You MUST choose a different strategy now."
                )]
            else:
                response.tool_calls = filtered_calls

    # Persist compaction: prepend removals + compact summary before result.
    # Without this, the checkpoint keeps the full uncompacted history and
    # every future turn would re-compact (wasting time and tokens).
    if _pre_compact_ids:
        removals = [
            RemoveMessage(id=mid)
            for mid in _pre_compact_ids
            if mid not in _compacted_survived_ids
        ]
        if removals:
            logger.info(
                "Persisting compaction: removing %d old messages, adding %d summary messages",
                len(removals), len(_compact_summary_msgs),
            )
            # Order: removals first, then compact summary msgs, then LLM response
            result_messages = removals + _compact_summary_msgs + result_messages

    result = {"messages": result_messages}
    if _registry_dirty:
        result["patch_registry"] = registry
    return result


# Track consecutive text-only (no tool calls) responses for nudge logic
_MAX_NUDGES = 2  # max times we'll nudge the agent to call tools before allowing __end__
_TASK_PLAN_TOOL_NAMES = frozenset({"update_task_plan", "edit_task_plan", "mark_task_done"})
_PLAN_REQUIRED_PATCH_TOOLS = frozenset({
    "apply_smali_patch",
    "apply_text_patch",
    "patch_binary_hex",
    "smart_entity_patch",
    "patch_api_response_flow",
    "patch_shared_prefs_reads",
    "inject_smali_code",
    "generate_constructor_override",
    "inject_startup_hook",
    "inject_runtime_override_layer",
    "inject_runtime_menu_scaffold",
    "configure_runtime_menu_manifest",
    "auto_patch_bypass",
    "patch_flutter_ssl",
    "inject_network_security_config",
    "patch_manifest_security",
    "remove_ads",
    "apply_dart_aot_patch",
})
_BUILD_AND_SIGN_TOOLS = frozenset({"apktool_build", "zipalign_apk_tool", "sign_apk"})
_STRATEGIC_ANALYSIS_TOOLS = frozenset({
    "map_semantic_architecture",
    "recover_hidden_state_model",
    "profile_guard_and_revalidation_surface",
    "find_enforcement_surfaces",
    "build_app_knowledge_pack",
    "summarize_app_knowledge",
    "build_behavior_graph",
    "summarize_behavior_graph",
    "query_behavior_graph",
    "locate_feature_controls",
    "recover_state_transitions",
    "map_security_surfaces",
    "semantic_method_slice",
    "analyze_network_behavior",
    "recover_semantic_symbols",
})


def _tool_call_name(tool_call: dict[str, Any]) -> str:
    return str(tool_call.get("name", "") or "")


def _tool_call_args(tool_call: dict[str, Any]) -> dict[str, Any]:
    args = tool_call.get("args")
    return args if isinstance(args, dict) else {}


def _is_patch_planning_call(tool_call: dict[str, Any]) -> bool:
    name = _tool_call_name(tool_call)
    args = _tool_call_args(tool_call)
    if name in _TASK_PLAN_TOOL_NAMES:
        return True
    if name in _STRATEGIC_ANALYSIS_TOOLS:
        return True
    if name in {"validate_patch_pipeline", "generate_runtime_validation_plan", "preview_smali_patch", "preview_text_patch"}:
        return True
    if name == "smart_entity_patch":
        return str(args.get("mode", "preview") or "preview").strip().lower() != "auto"
    if name == "patch_api_response_flow":
        return bool(args.get("dry_run"))
    return False


def _is_mutating_patch_call(tool_call: dict[str, Any]) -> bool:
    name = _tool_call_name(tool_call)
    if name not in _PLAN_REQUIRED_PATCH_TOOLS:
        return False
    return not _is_patch_planning_call(tool_call)


def _planning_blockers_for_tool_calls(state: AgentState, tool_calls: list[dict[str, Any]]) -> list[str]:
    blockers: list[str] = []
    mutating_patch_calls = [tc for tc in tool_calls if _is_mutating_patch_call(tc)]
    build_calls = [tc for tc in tool_calls if _tool_call_name(tc) in _BUILD_AND_SIGN_TOOLS]
    has_patch_workflow = bool(
        state.get("patch_plan_ready")
        or state.get("patch_registry")
        or state.get("patch_results")
    )

    if mutating_patch_calls:
        if not (state.get("task_plan") or []):
            blockers.append("task_plan")
        if not bool(state.get("analysis_complete_for_patching", False)):
            blockers.append("analysis_complete_for_patching")
        if not bool(state.get("patch_plan_ready", False)):
            blockers.append("patch_plan_ready")

    if build_calls and has_patch_workflow:
        if not bool(state.get("prebuild_validation_ready", False)):
            blockers.append("prebuild_validation_ready")
        if not bool(state.get("runtime_validation_ready", False)):
            blockers.append("runtime_validation_ready")

    return blockers


def _planning_guidance_text(blockers: list[str]) -> str:
    guidance: list[str] = []
    if "task_plan" in blockers:
        guidance.append("Consider recording a concrete multi-step task plan with update_task_plan.")
    if "analysis_complete_for_patching" in blockers:
        guidance.append("Consider running evidence-first analysis such as map_semantic_architecture, recover_hidden_state_model, profile_guard_and_revalidation_surface, or find_enforcement_surfaces.")
    if "patch_plan_ready" in blockers:
        guidance.append("Consider producing a patch preview first via smart_entity_patch(mode='preview'), patch_api_response_flow(dry_run=true), preview_smali_patch, or preview_text_patch.")
    if "prebuild_validation_ready" in blockers:
        guidance.append("Consider running validate_patch_pipeline before rebuild/sign so syntax and consistency risks are explicit.")
    if "runtime_validation_ready" in blockers:
        guidance.append("Consider generating a runtime checklist with generate_runtime_validation_plan before shipping the final APK.")
    return " ".join(guidance).strip()


def _tool_result_success(data: Any, content: str) -> bool:
    if isinstance(data, dict):
        if data.get("success") is False:
            return False
        if data.get("error") and data.get("success") is not True:
            return False
        return True
    lower = str(content or "").strip().lower()
    return '"success": false' not in lower and '"error"' not in lower[:160] and not lower.startswith("error")


def _validation_pipeline_passed(result: Any) -> bool:
    if not isinstance(result, dict) or not result.get("success", False):
        return False

    syntax = result.get("syntax")
    if isinstance(syntax, dict) and int(syntax.get("invalid_smali_count", 0) or 0) > 0:
        return False

    class_check = result.get("class_completeness")
    if isinstance(class_check, dict) and class_check.get("success") is False:
        return False

    global_check = result.get("global_gate_check")
    if isinstance(global_check, dict) and global_check.get("success") is False:
        return False

    return True


def should_continue(state: AgentState) -> Literal["tools", "human_review", "nudge", "__end__"]:
    """Route after agent node: tool call → tools, text-only → nudge or end."""

    if not state["messages"]:
        _set_nudge_count(0)
        return "__end__"

    last_msg = state["messages"][-1]

    if not isinstance(last_msg, AIMessage):
        _set_nudge_count(0)
        return "__end__"

    # If the LLM wants to call tools
    if last_msg.tool_calls:
        _set_nudge_count(0)
        # Check if any tool call is a high-risk patch (apply_smali_patch)
        for tc in last_msg.tool_calls:
            if tc["name"] == "apply_smali_patch":
                return "human_review"
        return "tools"

    # No tool calls — check if this is an "announcing" message that
    # should be nudged to actually call tools, or a genuine final answer
    # Extract text from both str and list content formats
    raw = last_msg.content
    if isinstance(raw, str):
        content = (raw or "").strip().lower()
    elif isinstance(raw, list):
        _parts = []
        for _blk in raw:
            if isinstance(_blk, str):
                _parts.append(_blk)
            elif isinstance(_blk, dict) and _blk.get("type") == "text":
                _parts.append(_blk.get("text", ""))
        content = " ".join(_parts).strip().lower()
    else:
        content = ""

    # Detect announcement patterns (agent says "I'll do X" but doesn't do it)
    is_announcing = any(phrase in content for phrase in [
        "let me", "i'll ", "i will", "i'm going to", "phase ", "step ",
        "first,", "next,", "now i", "starting", "let's ", "i need to",
        "going to ", "begin by", "start by", "proceed to", "kick off",
    ])

    task_plan = state.get("task_plan") or []
    pending_statuses = {"pending", "in_progress", "in-progress", "not-started", "not_started"}
    has_pending_plan = any(
        str(item.get("status", "")).strip().lower() in pending_statuses
        for item in task_plan
    )
    looks_final = any(phrase in content for phrase in [
        "task completed", "completed successfully", "final answer", "final report",
        "report generated", "signed apk", "all requested work", "finished",
    ])

    nudge_count = _get_nudge_count()
    if not content and nudge_count < _MAX_NUDGES:
        _set_nudge_count(nudge_count + 1)
        return "nudge"

    if has_pending_plan and not looks_final and nudge_count < _MAX_NUDGES:
        _set_nudge_count(nudge_count + 1)
        return "nudge"

    if is_announcing and nudge_count < _MAX_NUDGES:
        _set_nudge_count(nudge_count + 1)
        return "nudge"

    # Genuine final answer or max nudges reached
    _set_nudge_count(0)
    return "__end__"


def nudge_node(state: AgentState) -> dict:
    """Inject a system message telling the agent to call tools instead of just talking."""
    return {
        "messages": [
            HumanMessage(
                content=(
                    "[SYSTEM] You just announced what you plan to do but didn't call any tools. "
                    "DO NOT announce phases — call the tools NOW in your next response. "
                    "Include tool calls for every action you mentioned. "
                    "Batch independent tools in parallel."
                )
            )
        ]
    }


def planning_guard_node(state: AgentState) -> dict:
    """Generate advisory guidance for missing planning and validation signals."""
    last_msg = state["messages"][-1]
    if not isinstance(last_msg, AIMessage):
        return {"messages": []}

    blockers = _planning_blockers_for_tool_calls(state, list(last_msg.tool_calls))
    if not blockers:
        return {"messages": []}

    guidance_text = _planning_guidance_text(blockers)
    return {
        "messages": [
            HumanMessage(
                content=(
                    "[SYSTEM] Advisory only — planning or validation signals are incomplete. "
                    f"Missing signals: {', '.join(blockers)}. {guidance_text} "
                    "Execution remains allowed; treat any resulting patch/build/sign outcome as lower-confidence until the followups are checked."
                )
            )
        ]
    }


def _build_execution_advisory_message(state: AgentState) -> HumanMessage | None:
    messages = list(state.get("messages") or [])
    idx = len(messages) - 1
    while idx >= 0 and isinstance(messages[idx], ToolMessage):
        idx -= 1
    if idx < 0 or not isinstance(messages[idx], AIMessage):
        return None

    tool_calls = list(messages[idx].tool_calls or [])
    if not tool_calls:
        return None

    blockers = _planning_blockers_for_tool_calls(state, tool_calls)
    if not blockers:
        return None

    if not any(_is_mutating_patch_call(tc) or _tool_call_name(tc) in _BUILD_AND_SIGN_TOOLS for tc in tool_calls):
        return None

    guidance_text = _planning_guidance_text(blockers)
    return HumanMessage(
        content=(
            "[SYSTEM] Advisory only — the last execution continued despite incomplete planning/validation signals. "
            f"Missing signals: {', '.join(blockers)}. {guidance_text} "
            "Use these as risk annotations and suggested followups, not as mandatory blockers."
        )
    )


def human_review_node(state: AgentState) -> dict:
    """HITL node — interrupts execution to ask user for confirmation.

    Uses LangGraph's interrupt() to pause the graph.
    The CLI will collect user input and resume with a Command.
    In auto mode, patches are approved instantly without interrupt.
    """
    import apk_agent.agent.tools_def as _td

    last_msg = state["messages"][-1]
    if not isinstance(last_msg, AIMessage):
        return {"messages": [], "human_feedback": "rejected"}

    # Build a summary of what the agent wants to do
    patch_summaries = []
    other_tool_calls = []
    has_empty_patch = False
    for tc in last_msg.tool_calls:
        if tc["name"] == "apply_smali_patch":
            plan_json = tc["args"].get("patch_plan_json", "")
            if not plan_json or not plan_json.strip():
                has_empty_patch = True
                continue
            try:
                plan = json.loads(plan_json)
                target = plan.get("target_file", "unknown")
                desc = plan.get("description", "No description")
                steps = len(plan.get("steps", []))
                patch_summaries.append(
                    f"  📝 Patch: {target}\n"
                    f"     Description: {desc}\n"
                    f"     Steps: {steps}"
                )
            except (json.JSONDecodeError, KeyError):
                patch_summaries.append(f"  📝 Patch: (could not parse plan)")
        else:
            other_tool_calls.append(tc)

    # Auto-reject if patch_plan_json is empty — don't waste human's time
    if has_empty_patch and not patch_summaries:
        reject_msgs = []
        for tc in last_msg.tool_calls:
            if tc["name"] == "apply_smali_patch":
                reject_msgs.append(
                    ToolMessage(
                        content=json.dumps({
                            "success": False,
                            "error": "patch_plan_json was empty. You MUST provide the full JSON with target_file, description, and steps[].",
                            "recovery_hint": "Build the complete JSON patch plan, then call apply_smali_patch again.",
                        }),
                        tool_call_id=tc["id"],
                        name="apply_smali_patch",
                    )
                )
        return {"messages": reject_msgs, "human_feedback": "rejected"}

    # Auto mode: approve immediately without interrupt — saves API requests
    if getattr(_td, '_auto_mode', False):
        return {"messages": [], "human_feedback": "approved"}

    prompt_parts = [
        "🔒 **Human Review Required**",
        "",
        "The agent wants to apply the following patch(es):",
        "",
    ]
    prompt_parts.extend(patch_summaries)
    prompt_parts.extend([
        "",
        "Do you want to proceed? (yes/no/modify)",
        "  - **yes**: Apply the patch(es) as planned",
        "  - **no**: Skip this patch and continue",
        "  - **modify**: Let me explain what to change",
    ])

    prompt_text = "\n".join(prompt_parts)

    # Interrupt — execution pauses here until resumed
    human_response = interrupt(prompt_text)

    # Process human response
    response_lower = str(human_response).strip().lower()

    if response_lower in ("yes", "y", "proceed", "ok"):
        # User approved → pass tool calls through to tool node
        return {"messages": [], "human_feedback": "approved"}

    elif response_lower in ("no", "n", "skip"):
        # User rejected → create fake tool responses saying "skipped by user"
        rejection_messages = []
        passthrough_calls = []
        for tc in last_msg.tool_calls:
            if tc["name"] == "apply_smali_patch":
                rejection_messages.append(
                    ToolMessage(
                        content="⏭️ Patch skipped by user.",
                        tool_call_id=tc["id"],
                        name="apply_smali_patch",
                    )
                )
            else:
                passthrough_calls.append(tc)
        if passthrough_calls:
            last_msg.tool_calls = passthrough_calls
            ak_tcs = last_msg.additional_kwargs.get("tool_calls")
            if ak_tcs is not None:
                passthrough_ids = {tc.get("id") for tc in passthrough_calls}
                last_msg.additional_kwargs["tool_calls"] = [
                    tc for tc in ak_tcs if tc.get("id") in passthrough_ids
                ]
            return {"messages": rejection_messages, "human_feedback": "approved"}
        # Also add a human message explaining
        rejection_messages.append(
            HumanMessage(content=f"User chose to skip the proposed patches. Reason: {human_response}")
        )
        return {"messages": rejection_messages, "human_feedback": "rejected"}

    else:
        # User wants to modify → add their instructions as a human message
        modify_messages = []
        # Cancel the pending tool calls
        for tc in last_msg.tool_calls:
            if tc["name"] == "apply_smali_patch":
                modify_messages.append(
                    ToolMessage(
                        content="⏸️ Patch paused for user modification.",
                        tool_call_id=tc["id"],
                        name="apply_smali_patch",
                    )
                )
        modify_messages.append(
            HumanMessage(
                content=f"I want to modify the patch plan. Here are my instructions: {human_response}"
            )
        )
        return {"messages": modify_messages, "human_feedback": "modify"}


def human_review_router(state: AgentState) -> Literal["tools", "agent"]:
    """Route after human review: if approved go to tools, else back to agent."""
    feedback = state.get("human_feedback", "")
    if feedback == "approved":
        return "tools"
    return "agent"


# ---------------------------------------------------------------------------
# Human Thinking mode — step-by-step control
# ---------------------------------------------------------------------------

def human_step_node(state: AgentState) -> dict:
    """Pause after each tool cycle so the user decides the next step.

    Active only in Human Thinking mode.  Summarises what the last tool
    batch produced, then calls ``interrupt()`` so the CLI / Telegram can
    collect the user's next instruction.
    """
    from langchain_core.messages import ToolMessage as _TM

    # Summarise the last tool results (walk backwards to the preceding AI message)
    tool_summaries: list[str] = []
    for msg in reversed(state["messages"]):
        if isinstance(msg, _TM):
            name = getattr(msg, "name", None) or "tool"
            # Try to extract a short status from JSON content
            brief = ""
            try:
                data = json.loads(msg.content) if isinstance(msg.content, str) else None
                if isinstance(data, dict):
                    if data.get("success") is True:
                        brief = "✅"
                    elif data.get("success") is False:
                        brief = "❌"
                    elif "error" in data:
                        brief = "❌"
                    else:
                        brief = "✅"
                else:
                    brief = "✅"
            except Exception:
                brief = "✅"
            tool_summaries.append(f"  {brief} {name}")
        elif isinstance(msg, AIMessage):
            break

    summary_lines = ["🔄 Step completed."]
    if tool_summaries:
        summary_lines.append("")
        summary_lines.extend(reversed(tool_summaries))
    summary_lines.append("\n💬 What should I do next?")
    prompt = "\n".join(summary_lines)

    # Pause — the user's reply comes back as the resume value
    user_instruction = interrupt(prompt)

    return {"messages": [HumanMessage(content=str(user_instruction))]}


def _tools_post_router(state: AgentState) -> Literal["agent", "human_step"]:
    """After tools_post, decide whether to continue autonomously or pause for user."""
    import apk_agent.agent.tools_def as _td
    if getattr(_td, "_human_mode", False):
        return "human_step"
    return "agent"


def _auto_build_graph_and_index(progress_task_id: str | None = None):
    """Automatically build code graph + index after decompilation.
    Runs graph and index builds in parallel threads for ~2x speedup.
    Each build internally uses ThreadPoolExecutor for file I/O parallelism.
    """
    try:
        from concurrent.futures import ThreadPoolExecutor
        from threading import Lock
        from apk_agent.agent.execution_context import set_runtime_slot
        from apk_agent.tools.code_graph import build_code_graph, save_graph
        from apk_agent.tools.index_cache import build_code_index, save_index
        from apk_agent.progress import progress_manager, report_progress, set_current_task

        smali_dirs = _get_all_smali_dirs()
        if not smali_dirs:
            return

        outputs_dir = _project.outputs_dir if _project else None
        if not outputs_dir:
            return

        jadx_dir = _project.jadx_dir if _project else None

        # Build graph and index in PARALLEL (each also uses internal threading)
        logger.info("Auto-building code graph + index in parallel after decompilation...")

        progress_lock = Lock()
        progress_state = {
            "graph": 0.0,
            "index": 0.0,
            "overall": 20.0,
        }

        def _emit_build_progress(kind: str, pct: float, detail: str = "") -> None:
            pct_value = max(0.0, min(100.0, float(pct or 0.0)))
            if not progress_task_id:
                report_progress(pct_value, detail)
                return

            with progress_lock:
                prior = float(progress_state.get(kind, 0.0))
                if pct_value < prior:
                    pct_value = prior
                progress_state[kind] = pct_value
                combined_pct = (float(progress_state["graph"]) + float(progress_state["index"])) / 2.0
                overall_pct = 20.0 + (combined_pct / 100.0) * 65.0
                overall_pct = max(float(progress_state["overall"]), min(85.0, overall_pct))
                progress_state["overall"] = overall_pct
                graph_pct = int(round(float(progress_state["graph"])))
                index_pct = int(round(float(progress_state["index"])))

            compact_detail = " ".join(str(detail or "").split())
            if len(compact_detail) > 72:
                compact_detail = compact_detail[:69].rstrip() + "..."
            summary = f"Graph {graph_pct}% | Index {index_pct}%"
            if compact_detail:
                label = "Graph" if kind == "graph" else "Index"
                summary += f" | {label}: {compact_detail}"
            progress_manager.update_task(progress_task_id, progress_pct=overall_pct, detail=summary)

        def _build_graph():
            if progress_task_id:
                set_current_task(progress_task_id)
            G = build_code_graph(
                smali_dirs,
                progress_callback=lambda pct, detail="": _emit_build_progress("graph", pct, detail),
            )
            if G.number_of_nodes() == 0:
                raise RuntimeError("Code graph build produced 0 nodes — decompilation may have failed")
            graph_path = outputs_dir / "call_graph.pickle"
            save_graph(G, graph_path)
            _emit_build_progress(
                "graph",
                100,
                f"Graph built: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges",
            )
            return G

        def _build_index():
            if progress_task_id:
                set_current_task(progress_task_id)
            idx = build_code_index(
                smali_dirs,
                jadx_dir=jadx_dir,
                progress_callback=lambda pct, detail="": _emit_build_progress("index", pct, detail),
            )
            index_path = outputs_dir / "code_index.json"
            save_index(idx, index_path)
            stats = idx.get("stats", {}) if isinstance(idx, dict) else {}
            _emit_build_progress(
                "index",
                100,
                f"Index built: {stats.get('total_classes', '?')} classes, {stats.get('total_methods', '?')} methods",
            )
            return idx

        with ThreadPoolExecutor(max_workers=2) as pool:
            graph_future = pool.submit(_build_graph)
            index_future = pool.submit(_build_index)

            G = graph_future.result()
            set_runtime_slot("code_graph", G)
            logger.info(f"Code graph built: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

            idx = index_future.result()
            set_runtime_slot("code_index", idx)
            logger.info(f"Code index built: {idx['stats']['total_classes']} classes, {idx['stats']['total_methods']} methods")
            if progress_task_id:
                progress_manager.update_task(
                    progress_task_id,
                    progress_pct=85,
                    detail="Graph 100% | Index 100% | Graph and index build complete",
                )

    except ImportError as e:
        logger.error(f"CRITICAL: Skipping graph build (missing dependency): {e}")
        raise  # Let caller know graph build failed
    except Exception as e:
        logger.error(f"CRITICAL: Graph/index build failed: {e}")
        raise  # Let caller know graph build failed


def _shorten_state_text(value: Any, max_chars: int = 180) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3].rstrip() + "..."


def _collect_tool_refs(value: Any, refs: list[str]) -> None:
    if len(refs) >= 6:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"file", "target_file", "path", "class", "method", "package"}:
                text = _shorten_state_text(item, max_chars=80)
                if text and text not in refs:
                    refs.append(text)
                    if len(refs) >= 6:
                        return
            _collect_tool_refs(item, refs)
            if len(refs) >= 6:
                return
    elif isinstance(value, list):
        for item in value[:8]:
            _collect_tool_refs(item, refs)
            if len(refs) >= 6:
                return


def _summarize_tool_result(tool_name: str, content: str, timestamp: str) -> dict[str, Any]:
    normalized = str(content or "").strip()
    lower = normalized[:400].lower()
    success = (
        '"success": false' not in lower
        and '"error"' not in lower[:160]
        and not lower.startswith("error")
    )
    summary = _shorten_state_text(normalized)

    try:
        data = json.loads(normalized)
    except (json.JSONDecodeError, TypeError):
        data = None

    if isinstance(data, dict):
        fragments: list[str] = []
        scalar_keys = [
            "summary", "description", "verdict", "package", "target_file",
            "target_class", "target_method", "helper_file", "error",
        ]
        for key in scalar_keys:
            value = data.get(key)
            if value:
                fragments.append(f"{key}={_shorten_state_text(value, max_chars=80)}")

        count_keys = [
            "findings", "vulnerabilities", "matches", "results", "methods",
            "classes", "gate_methods", "boolean_getters", "int_getters",
            "shared_prefs", "callers", "paywall_methods", "patched_files",
            "changes_made", "remaining_gates", "behavioral_hits", "billing_hits",
        ]
        for key in count_keys:
            value = data.get(key)
            if isinstance(value, (list, dict)) and value:
                fragments.append(f"{key}={len(value)}")

        refs: list[str] = []
        _collect_tool_refs(data, refs)
        if refs:
            fragments.append("refs=" + ", ".join(refs[:4]))

        if fragments:
            summary = "; ".join(fragments)
    elif isinstance(data, list) and data:
        refs: list[str] = []
        _collect_tool_refs(data, refs)
        pieces = [f"items={len(data)}"]
        if refs:
            pieces.append("refs=" + ", ".join(refs[:4]))
        summary = "; ".join(pieces)

    return {
        "tool": tool_name,
        "success": success,
        "summary": _shorten_state_text(summary, max_chars=260),
        "timestamp": timestamp,
    }


def _resolve_tool_postprocess_content(content: str) -> str:
    """Return compact postprocess content for tool results.

    Spilled outputs keep the full payload on disk, but postprocess should work
    from the compact preview to avoid expensive file reads right after the tool
    batch completes.
    """
    normalized = str(content or "")
    if not normalized:
        return normalized

    try:
        data = json.loads(normalized)
    except (json.JSONDecodeError, TypeError):
        return normalized

    if not isinstance(data, dict) or not data.get("tool_output_spilled"):
        return normalized

    important_preview = data.get("important_preview")
    if not isinstance(important_preview, dict) or not important_preview:
        return normalized

    compact_payload = dict(important_preview)
    compact_payload["tool_output_spilled"] = True
    if "success" in data and "success" not in compact_payload:
        compact_payload["success"] = data["success"]
    output_file = str(data.get("output_file", "") or "").strip()
    if output_file:
        compact_payload["output_file"] = output_file
    spill_summary = data.get("summary")
    if spill_summary:
        compact_payload["spill_summary"] = spill_summary
    return json.dumps(compact_payload, ensure_ascii=False)


def tools_postprocess(state: AgentState) -> dict:
    """Extract findings and patch results from tool messages into durable state.

    This ensures critical analysis data survives context compaction.
    Also maintains the **patch_registry** — a durable journal of every patch
    attempt with tool, target, pattern, status, and user feedback.
    """
    from apk_agent.progress import get_current_task, progress_manager, set_current_task

    postprocess_task_id = f"tools_post_{time.time_ns()}"
    previous_task_id = get_current_task() or ""
    progress_manager.start_task(postprocess_task_id, "updating agent state")
    set_current_task(postprocess_task_id)
    progress_manager.update_task(
        postprocess_task_id,
        progress_pct=5,
        detail="Syncing recent tool outputs into durable state",
    )

    updates: dict = {}
    new_findings: list[dict] = []
    new_patches: list[dict] = []
    new_registry_entries: list[dict] = []
    new_tool_history: list[dict[str, Any]] = []
    planning_started = bool(state.get("planning_started", False))
    analysis_complete_for_patching = bool(state.get("analysis_complete_for_patching", False))
    patch_plan_ready = bool(state.get("patch_plan_ready", False))
    prebuild_validation_ready = bool(state.get("prebuild_validation_ready", False))
    runtime_validation_ready = bool(state.get("runtime_validation_ready", False))

    import time as _time
    _ts = _time.strftime("%Y-%m-%d %H:%M:%S")

    # Patch tool names that produce registry entries
    _PATCH_TOOLS = {
        "apply_smali_patch", "auto_patch_bypass", "patch_flutter_ssl",
        "inject_network_security_config", "patch_manifest_security",
        "rename_package_identity", "remove_ads", "patch_api_response_flow", "inject_runtime_override_layer",
    }

    try:
        # Only look at the most recent tool messages (from last tool call batch)
        for msg in reversed(state["messages"]):
            if not isinstance(msg, ToolMessage):
                break
            tool_name = getattr(msg, "name", "") or ""
            raw_content = msg.content if isinstance(msg.content, str) else ""
            content = _resolve_tool_postprocess_content(raw_content)
            try:
                parsed = json.loads(content)
            except (json.JSONDecodeError, TypeError):
                parsed = None
            success = _tool_result_success(parsed, content)
            new_tool_history.append(_summarize_tool_result(tool_name, content, _ts))

            if tool_name in _STRATEGIC_ANALYSIS_TOOLS and success:
                analysis_complete_for_patching = True

            if tool_name in _PLAN_REQUIRED_PATCH_TOOLS and success and not (
                tool_name == "smart_entity_patch" and isinstance(parsed, dict) and str(parsed.get("mode", "preview") or "preview").strip().lower() != "auto"
            ) and not (
                tool_name == "patch_api_response_flow" and isinstance(parsed, dict) and bool(parsed.get("dry_run"))
            ):
                prebuild_validation_ready = False
                runtime_validation_ready = False

            if tool_name == "smart_entity_patch" and isinstance(parsed, dict) and success:
                mode = str(parsed.get("mode", "") or "").strip().lower()
                semantic_plan = parsed.get("semantic_plan") if isinstance(parsed.get("semantic_plan"), dict) else {}
                if mode == "preview" and (
                    parsed.get("patches_preview")
                    or semantic_plan.get("execution_order")
                    or semantic_plan.get("preferred_first_action")
                ):
                    analysis_complete_for_patching = True
                    patch_plan_ready = True
            elif tool_name == "patch_api_response_flow" and isinstance(parsed, dict) and success:
                analysis_complete_for_patching = True
                if parsed.get("selected_strategy") or parsed.get("validation") or parsed.get("files_modified") or parsed.get("patches_applied"):
                    patch_plan_ready = True
            elif tool_name in {"preview_smali_patch", "preview_text_patch"} and isinstance(parsed, dict) and success:
                patch_plan_ready = True
            elif tool_name == "validate_patch_pipeline":
                prebuild_validation_ready = _validation_pipeline_passed(parsed)
            elif tool_name == "generate_runtime_validation_plan":
                runtime_validation_ready = bool(success and isinstance(parsed, dict) and parsed.get("scenarios"))

            # Extract vulnerability findings
            if tool_name in ("scan_vulnerabilities", "detect_protections"):
                try:
                    data = json.loads(content)
                    if isinstance(data, dict) and data.get("findings"):
                        for f in data["findings"][:30]:
                            new_findings.append({
                                "tool": tool_name,
                                "id": f.get("id", ""),
                                "name": f.get("name", ""),
                                "severity": f.get("severity", ""),
                                "file": f.get("file", ""),
                                "category": f.get("category", ""),
                            })
                except (json.JSONDecodeError, KeyError):
                    pass

            # Extract unified_scan findings with enriched fields
            if tool_name == "unified_scan":
                try:
                    data = json.loads(content)
                    if isinstance(data, dict) and data.get("findings"):
                        for f in data["findings"][:50]:
                            new_findings.append({
                                "tool": tool_name,
                                "id": f.get("id", ""),
                                "rule_id": f.get("rule_id", ""),
                                "severity": f.get("severity", ""),
                                "category": f.get("category", ""),
                                "title": f.get("title", ""),
                                "cwe": f.get("cwe", ""),
                                "class": f.get("class", ""),
                                "method": f.get("method", ""),
                                "exploitability": f.get("exploitability", ""),
                                "confidence_score": f.get("confidence_score", 0.0),
                                "risk_score": f.get("risk_score", 0.0),
                                "evidence_strength": f.get("evidence_strength", "single"),
                                "validation_state": f.get("validation_state", "pending"),
                                "threat_level": f.get("threat_level", "basic"),
                                "auto_patchable": f.get("auto_patchable", False),
                            })
                except (json.JSONDecodeError, KeyError):
                    pass

            # Extract app package scope from identify_app_packages
            if tool_name == "identify_app_packages":
                try:
                    data = json.loads(content)
                    if isinstance(data, dict):
                        app_pkgs = data.get("app_packages") or data.get("target_packages") or []
                        excluded = data.get("excluded_packages") or data.get("third_party_packages") or []
                        if app_pkgs:
                            updates["target_packages"] = app_pkgs
                        if excluded:
                            updates["excluded_packages"] = excluded
                except (json.JSONDecodeError, KeyError):
                    pass

            # ── Patch registry: record every patch attempt ──────────────
            if tool_name in _PATCH_TOOLS:
                try:
                    data = json.loads(content)
                    if not isinstance(data, dict):
                        continue
                except (json.JSONDecodeError, KeyError):
                    continue

                if tool_name == "apply_smali_patch":
                # Legacy patch_results extraction (keep for backwards compat)
                    new_patches.append({
                        "success": data.get("success", False),
                        "target_file": data.get("target_file", ""),
                        "steps_applied": data.get("steps_applied", 0),
                        "errors": data.get("errors", []),
                    })
                    # Rich registry entry
                    new_registry_entries.append({
                        "id": len(state.get("patch_registry") or []) + len(new_registry_entries) + 1,
                        "tool": tool_name,
                        "target": data.get("target_file", ""),
                        "pattern": data.get("diff_text", "")[:300] or "(no diff)",
                        "steps_applied": data.get("steps_applied", 0),
                        "steps_total": data.get("steps_total", 0),
                        "tool_success": data.get("success", False),
                        "status": "applied" if data.get("success") else "failed",
                        "errors": data.get("errors", [])[:3],
                        "remediates": data.get("remediates", []),
                        "user_feedback": "",
                        "timestamp": _ts,
                    })

                elif tool_name == "auto_patch_bypass":
                # auto_patch_bypass returns per-category stats
                    categories = data.get("categories_applied") or []
                    total_applied = data.get("total_patches_applied", 0)
                    patched_files = data.get("patched_files") or []
                    success = data.get("success", False) and total_applied > 0
                    new_registry_entries.append({
                        "id": len(state.get("patch_registry") or []) + len(new_registry_entries) + 1,
                        "tool": tool_name,
                        "target": f"{len(patched_files)} files",
                        "pattern": f"categories={','.join(str(c) for c in categories[:6])}; {total_applied} patches",
                        "steps_applied": total_applied,
                        "steps_total": total_applied,
                        "tool_success": success,
                        "status": "applied" if success else "failed",
                        "errors": data.get("errors", [])[:3],
                        "remediates": data.get("remediates", []),
                        "user_feedback": "",
                        "timestamp": _ts,
                    })

                elif tool_name == "patch_flutter_ssl":
                    new_registry_entries.append({
                        "id": len(state.get("patch_registry") or []) + len(new_registry_entries) + 1,
                        "tool": tool_name,
                        "target": "libflutter.so",
                        "pattern": "binary ssl_verify_peer_cert patch",
                        "steps_applied": data.get("patches_applied", 0),
                        "steps_total": data.get("patches_applied", 0),
                        "tool_success": data.get("success", False),
                        "status": "applied" if data.get("success") else "failed",
                        "errors": data.get("errors", [])[:3] if data.get("errors") else [],
                        "remediates": data.get("remediates", []),
                        "user_feedback": "",
                        "timestamp": _ts,
                    })

                elif tool_name == "inject_network_security_config":
                    new_registry_entries.append({
                        "id": len(state.get("patch_registry") or []) + len(new_registry_entries) + 1,
                        "tool": tool_name,
                        "target": "res/xml/network_security_config.xml",
                        "pattern": "inject permissive NSC (trust all certs)",
                        "steps_applied": len(data.get("changes_made") or []),
                        "steps_total": len(data.get("changes_made") or []),
                        "tool_success": data.get("success", False),
                        "status": "applied" if data.get("success") else "failed",
                        "errors": [],
                        "remediates": data.get("remediates", []),
                        "user_feedback": "",
                        "timestamp": _ts,
                    })

                elif tool_name == "patch_manifest_security":
                    changes = data.get("changes_made") or []
                    new_registry_entries.append({
                        "id": len(state.get("patch_registry") or []) + len(new_registry_entries) + 1,
                        "tool": tool_name,
                        "target": "AndroidManifest.xml",
                        "pattern": f"{len(changes)} manifest changes",
                        "steps_applied": len(changes),
                        "steps_total": len(changes),
                        "tool_success": data.get("success", False),
                        "status": "applied" if data.get("success") else "failed",
                        "errors": data.get("warnings", [])[:3],
                        "remediates": data.get("remediates", []),
                        "user_feedback": "",
                        "timestamp": _ts,
                    })

                elif tool_name == "rename_package_identity":
                    changes = data.get("changes_applied") or []
                    new_registry_entries.append({
                        "id": len(state.get("patch_registry") or []) + len(new_registry_entries) + 1,
                        "tool": tool_name,
                        "target": f"{data.get('old_package', '')} -> {data.get('new_package', '')}",
                        "pattern": f"package identity rewrite; {len(changes)} manifest updates",
                        "steps_applied": len(changes),
                        "steps_total": len(changes),
                        "tool_success": data.get("success", False),
                        "status": "applied" if data.get("success") else "failed",
                        "errors": data.get("errors", [])[:3] if isinstance(data.get("errors"), list) else [],
                        "remediates": data.get("remediates", []),
                        "user_feedback": "",
                        "timestamp": _ts,
                    })

                elif tool_name == "remove_ads":
                    total_applied = data.get("total_patches_applied", 0)
                    new_registry_entries.append({
                        "id": len(state.get("patch_registry") or []) + len(new_registry_entries) + 1,
                        "tool": tool_name,
                        "target": f"{len(data.get('patched_files') or [])} files",
                        "pattern": f"ads_removal+license_bypass; {total_applied} patches",
                        "steps_applied": total_applied,
                        "steps_total": total_applied,
                        "tool_success": data.get("success", False) and total_applied > 0,
                        "status": "applied" if (data.get("success", False) and total_applied > 0) else "failed",
                        "errors": data.get("errors", [])[:3],
                        "remediates": data.get("remediates", []),
                        "user_feedback": "",
                        "timestamp": _ts,
                    })

                elif tool_name == "patch_api_response_flow":
                    total_applied = int(data.get("patches_applied", 0) or 0)
                    new_registry_entries.append({
                        "id": len(state.get("patch_registry") or []) + len(new_registry_entries) + 1,
                        "tool": tool_name,
                        "target": data.get("target_class", data.get("target_file", "response-flow")),
                        "pattern": f"response-flow override; {total_applied} patch units",
                        "steps_applied": total_applied,
                        "steps_total": total_applied,
                        "tool_success": data.get("success", False),
                        "status": "applied" if data.get("success") else "failed",
                        "errors": data.get("errors", [])[:3],
                        "remediates": data.get("remediates", []),
                        "user_feedback": "",
                        "timestamp": _ts,
                    })

                elif tool_name == "inject_runtime_override_layer":
                    rules_applied = int(data.get("rules_applied", 0) or 0)
                    new_registry_entries.append({
                        "id": len(state.get("patch_registry") or []) + len(new_registry_entries) + 1,
                        "tool": tool_name,
                        "target": data.get("helper_file", "runtime override layer"),
                        "pattern": f"runtime override layer; {rules_applied} rules",
                        "steps_applied": rules_applied,
                        "steps_total": rules_applied,
                        "tool_success": data.get("success", False),
                        "status": "applied" if data.get("success") else "failed",
                        "errors": data.get("errors", [])[:3],
                        "remediates": data.get("remediates", []),
                        "user_feedback": "",
                        "timestamp": _ts,
                    })

            # Auto-build code graph + index after decompilation completes
            if tool_name == "apktool_decompile":
                try:
                    progress_manager.update_task(
                        postprocess_task_id,
                        progress_pct=20,
                        detail="Starting graph and index build after decompilation",
                    )
                    _auto_build_graph_and_index(progress_task_id=postprocess_task_id)
                    updates["graph_ready"] = True
                    # Inject a visible message so the agent KNOWS graph is ready
                    from apk_agent.agent.execution_context import get_runtime_slot

                    g = get_runtime_slot("code_graph")
                    idx = get_runtime_slot("code_index")
                    graph_info = ""
                    if g:
                        graph_info += f"{g.number_of_nodes()} nodes, {g.number_of_edges()} edges"
                    if idx and isinstance(idx, dict) and "stats" in idx:
                        s = idx["stats"]
                        graph_info += f", {s.get('total_classes', '?')} classes, {s.get('total_methods', '?')} methods indexed"
                    notify_msg = HumanMessage(content=(
                        f"[SYSTEM] ⚡ Code graph + index built successfully ({graph_info}). "
                        "You MUST now use graph tools (graph_callers, graph_callees, graph_security_scan, "
                        "graph_find_path, graph_class_info, index_lookup_*) instead of slow search tools. "
                        "They are 100x faster and give better results."
                    ))
                    # Append notification to messages via state update
                    updates.setdefault("messages", []).append(notify_msg)
                except Exception as e:
                    logger.error(f"Auto graph/index build FAILED: {e}")
                    updates["graph_ready"] = False

        if new_findings:
            existing = list(state.get("findings") or [])
            existing.extend(new_findings)
            updates["findings"] = existing
        if new_patches:
            existing = list(state.get("patch_results") or [])
            existing.extend(new_patches)
            updates["patch_results"] = existing
        if new_registry_entries:
            existing = list(state.get("patch_registry") or [])
            existing.extend(new_registry_entries)
            updates["patch_registry"] = existing
        if new_tool_history:
            existing = list(state.get("tool_history") or [])
            existing.extend(reversed(new_tool_history))
            updates["tool_history"] = existing[-60:]

        execution_advisory = _build_execution_advisory_message(state)
        if execution_advisory is not None:
            updates.setdefault("messages", []).append(execution_advisory)

        progress_manager.update_task(
            postprocess_task_id,
            progress_pct=90,
            detail="Persisting task plan, scratchpad, and validation flags",
        )

        # Sync working memory from module-level storage into durable state
        updates["scratchpad"] = _get_scratchpad()
        synced_task_plan = _get_task_plan()
        updates["task_plan"] = synced_task_plan

        planning_started = bool(synced_task_plan)
        if not planning_started:
            analysis_complete_for_patching = False
            patch_plan_ready = False
            prebuild_validation_ready = False
            runtime_validation_ready = False
        elif patch_plan_ready:
            analysis_complete_for_patching = True

        updates["planning_started"] = planning_started
        updates["analysis_complete_for_patching"] = analysis_complete_for_patching
        updates["patch_plan_ready"] = patch_plan_ready
        updates["prebuild_validation_ready"] = prebuild_validation_ready
        updates["runtime_validation_ready"] = runtime_validation_ready

        progress_manager.complete_task(postprocess_task_id, success=True)
        return updates
    except Exception as exc:
        progress_manager.complete_task(postprocess_task_id, success=False, error=str(exc))
        raise
    finally:
        set_current_task(previous_task_id)


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

# Module-level LLM reference (set during build_graph)
_llm_with_tools = None
_raw_llm = None


def build_graph(config: AppConfig, project: Project, checkpointer=None):
    """Construct and compile the LangGraph agent graph.

    Args:
        config: Application configuration.
        project: The active project.
        checkpointer: Optional LangGraph checkpointer (e.g. SqliteSaver).
                      If None, a default in-memory MemorySaver is used.

    Returns (compiled_graph, checkpointer).
    """
    global _llm_with_tools, _raw_llm, _compactor

    # Reset loop detector for fresh session
    thread_id = project.id or "__default__"
    set_active_thread(thread_id)
    # Clear trackers for this specific thread
    _session_tool_trackers.pop(thread_id, None)
    _session_nudge_counts.pop(thread_id, None)

    # Set tool context
    set_tool_context(config, project)

    # Create LLM with tools bound
    llm = get_llm(config)
    _raw_llm = llm  # keep a reference without tools for compaction
    _llm_with_tools = llm.bind_tools(ALL_TOOLS)

    # Initialize compactor with dynamic threshold based on context window
    from apk_agent.llm.provider import _FALLBACK_CONTEXT_WINDOW
    ctx_window = config.context_window if config.context_window > 0 else _FALLBACK_CONTEXT_WINDOW
    if config.context_window <= 0:
        logger.warning(
            "CONTEXT_WINDOW not set — using fallback %s tokens. "
            "Set it via CONTEXT_WINDOW env var, --context-window CLI flag, or /context in Telegram.",
            _FALLBACK_CONTEXT_WINDOW,
        )

    # Fixed ratio: compact at 50% of context window
    COMPACTION_RATIO = 0.50
    compaction_threshold = int(ctx_window * COMPACTION_RATIO)
    _compactor = Compactor(token_threshold=compaction_threshold, keep_recent=20)

    # Build tool node
    tool_node = ToolNode(ALL_TOOLS)

    # Build graph
    graph = StateGraph(AgentState)

    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.add_node("tools_post", tools_postprocess)
    graph.add_node("human_review", human_review_node)
    graph.add_node("human_step", human_step_node)
    graph.add_node("nudge", nudge_node)

    graph.set_entry_point("agent")

    graph.add_conditional_edges(
        "agent",
        should_continue,
        {
            "tools": "tools",
            "human_review": "human_review",
            "nudge": "nudge",
            "__end__": END,
        },
    )

    # After tools execute → postprocess to extract findings
    graph.add_edge("tools", "tools_post")

    # After postprocess → back to agent OR pause for human step
    graph.add_conditional_edges(
        "tools_post",
        _tools_post_router,
        {
            "agent": "agent",
            "human_step": "human_step",
        },
    )

    # After human step → back to agent with user's next instruction
    graph.add_edge("human_step", "agent")

    # After nudge → back to agent to retry with tool calls
    graph.add_edge("nudge", "agent")

    # After human review → route based on feedback
    graph.add_conditional_edges(
        "human_review",
        human_review_router,
        {
            "tools": "tools",
            "agent": "agent",
        },
    )

    # Use provided checkpointer or default to in-memory
    if checkpointer is None:
        checkpointer = MemorySaver()

    compiled = graph.compile(checkpointer=checkpointer)

    return compiled, checkpointer
