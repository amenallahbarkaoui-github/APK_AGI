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
from typing import Any, Literal

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.types import interrupt, Command

from apk_agent.agent.prompts import SYSTEM_PROMPT
from apk_agent.agent.state import AgentState
from apk_agent.agent.tools_def import ALL_TOOLS, set_tool_context, _get_all_smali_dirs, _project, _get_scratchpad, _get_task_plan
from apk_agent.compactor import Compactor, count_message_tokens
from apk_agent.config import AppConfig
from apk_agent.llm.provider import get_llm
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
_LOOP_WARN_THRESHOLD = 3   # inject warning after this many repetitions
_LOOP_BLOCK_THRESHOLD = 5  # force different approach after this many

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


def _check_tool_loops(tool_calls: list[dict]) -> str | None:
    """Track tool calls and return a warning message if loops detected."""
    tracker = _get_tool_tracker()
    warnings = []
    for tc in tool_calls:
        name = tc.get("name", "")
        args_hash = _hash_tool_args(tc.get("args", {}))
        key = f"{name}:{args_hash}"
        tracker[key] += 1
        count = tracker[key]

        if count >= _LOOP_BLOCK_THRESHOLD:
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
        for c in critical[:5]:
            summary_parts.append(f"  • [{c.get('severity','')}] {c.get('name','')}: {c.get('file','')}")
    if patches:
        ok = sum(1 for p in patches if p.get("success"))
        summary_parts.append(f"🔧 Patches applied: {ok}/{len(patches)}")

    # Patch registry — full journal of every patch attempt (survives compaction)
    # (uses local `registry` which may have user-feedback updates from above)
    # Cap at last 15 entries to prevent context bloat on long sessions.
    if registry:
        display_reg = registry[-15:] if len(registry) > 15 else registry
        summary_parts.append(f"\n🗂️ PATCH REGISTRY (showing {len(display_reg)}/{len(registry)}) — DO NOT re-apply patches that already succeeded:")
        for entry in display_reg:
            pid = entry.get("id", "?")
            tool = entry.get("tool", "?")
            target = entry.get("target", "?")
            pattern_desc = entry.get("pattern", "")[:60]
            status = entry.get("status", "?")
            feedback = entry.get("user_feedback", "")

            status_icon = {"applied": "✅", "failed": "❌", "user_rejected": "🔄", "retrying": "🔄", "verified": "✔️"}.get(status, "❓")
            line = f"  {status_icon} #{pid} [{tool}] {target} — {pattern_desc}"
            if feedback:
                line += f" | USER: {feedback[:40]}"
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
        for k, v in list(scratchpad.items())[:15]:
            val_str = str(v)[:120]
            summary_parts.append(f"  • {k}: {val_str}")

    # Task plan — multi-objective decomposition
    task_plan = state.get("task_plan") or []
    if task_plan:
        summary_parts.append("📋 Task Plan:")
        for t in task_plan:
            status = t.get("status", "pending")
            icon = "✅" if status == "done" else "🔄" if status == "in_progress" else "⬜"
            summary_parts.append(f"  {icon} [{t.get('id', '?')}] {t.get('desc', '')}")

    if summary_parts:
        state_msg = "\n".join(summary_parts)
        # Insert after system prompt
        insert_idx = 1 if isinstance(messages[0], SystemMessage) else 0
        messages.insert(insert_idx, HumanMessage(
            content=f"[DURABLE STATE — graph, scope, findings, patches & memory]\n{state_msg}\n\n⚡ REMINDER: Execute tools NOW. Do NOT send text-only messages announcing phases. Call tools in EVERY response. Batch independent tools in parallel."
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
            m.id for m in state["messages"] if getattr(m, "id", None)
        ]

        compacted = _compactor.compact(messages, _raw_llm, agent_state=state)
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
            m.id for m in messages if getattr(m, "id", None)
        }

    # Sanitize: prevent content block arrays > 5 elements (API proxy limit)
    messages = _sanitize_messages(messages)

    # Truncate large tool results in OLD messages only (preserve recent ones)
    # Keep head + tail so we don't lose summary headers or final findings
    _MAX_CHARS = 2500
    _HEAD = 1500
    _TAIL = 800
    _RECENT = 6  # never truncate the last N messages (covers current tool batch)
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
            is_retryable = any(k in err_str for k in [
                "429", "rate_limit", "rate limit",
                "503", "service unavailable", "overloaded",
                "500", "internal server error",
                "tool name is required",
                "must be in json format", "invalidparameter",
                "invalid_parameter_error",
                "tool_call_id", "is not found",
            ])
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
            # 403 "API key limit" = quota exhausted, not retryable
            if not is_retryable or attempt >= max_retries:
                raise
            wait = 2 ** attempt * 3  # 3s, 6s, 12s
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
                if tracker.get(key, 0) < _LOOP_BLOCK_THRESHOLD:
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
    content = (last_msg.content or "").strip().lower() if isinstance(last_msg.content, str) else ""

    # Detect announcement patterns (agent says "I'll do X" but doesn't do it)
    is_announcing = any(phrase in content for phrase in [
        "let me", "i'll ", "i will", "i'm going to", "phase ", "step ",
        "first,", "next,", "now i", "starting", "let's ", "i need to",
        "going to ", "begin by", "start by", "proceed to", "kick off",
    ])

    nudge_count = _get_nudge_count()
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


def human_review_node(state: AgentState) -> dict:
    """HITL node — interrupts execution to ask user for confirmation.

    Uses LangGraph's interrupt() to pause the graph.
    The CLI will collect user input and resume with a Command.
    In auto mode, patches are approved instantly without interrupt.
    """
    import apk_agent.agent.tools_def as _td

    last_msg = state["messages"][-1]

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
                # Non-patch tools still go through
                pass
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


def _auto_build_graph_and_index():
    """Automatically build code graph + index after decompilation.
    Runs graph and index builds in parallel threads for ~2x speedup.
    Each build internally uses ThreadPoolExecutor for file I/O parallelism.
    """
    try:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        from apk_agent.tools.code_graph import build_code_graph, save_graph
        from apk_agent.tools.index_cache import build_code_index, save_index
        from apk_agent.agent.tools_def import _code_graph, _code_index
        import apk_agent.agent.tools_def as td
        from apk_agent.progress import report_progress

        smali_dirs = _get_all_smali_dirs()
        if not smali_dirs:
            return

        outputs_dir = _project.outputs_dir if _project else None
        if not outputs_dir:
            return

        jadx_dir = _project.jadx_dir if _project else None

        # Build graph and index in PARALLEL (each also uses internal threading)
        logger.info("Auto-building code graph + index in parallel after decompilation...")

        def _build_graph():
            G = build_code_graph(smali_dirs, progress_callback=report_progress)
            if G.number_of_nodes() == 0:
                raise RuntimeError("Code graph build produced 0 nodes — decompilation may have failed")
            graph_path = outputs_dir / "call_graph.pickle"
            save_graph(G, graph_path)
            return G

        def _build_index():
            idx = build_code_index(smali_dirs, jadx_dir=jadx_dir,
                                   progress_callback=report_progress)
            index_path = outputs_dir / "code_index.json"
            save_index(idx, index_path)
            return idx

        with ThreadPoolExecutor(max_workers=2) as pool:
            graph_future = pool.submit(_build_graph)
            index_future = pool.submit(_build_index)

            G = graph_future.result()
            td._code_graph = G
            logger.info(f"Code graph built: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

            idx = index_future.result()
            td._code_index = idx
            logger.info(f"Code index built: {idx['stats']['total_classes']} classes, {idx['stats']['total_methods']} methods")

    except ImportError as e:
        logger.error(f"CRITICAL: Skipping graph build (missing dependency): {e}")
        raise  # Let caller know graph build failed
    except Exception as e:
        logger.error(f"CRITICAL: Graph/index build failed: {e}")
        raise  # Let caller know graph build failed


def tools_postprocess(state: AgentState) -> dict:
    """Extract findings and patch results from tool messages into durable state.

    This ensures critical analysis data survives context compaction.
    Also maintains the **patch_registry** — a durable journal of every patch
    attempt with tool, target, pattern, status, and user feedback.
    """
    updates: dict = {}
    new_findings: list[dict] = []
    new_patches: list[dict] = []
    new_registry_entries: list[dict] = []

    import time as _time
    _ts = _time.strftime("%Y-%m-%d %H:%M:%S")

    # Patch tool names that produce registry entries
    _PATCH_TOOLS = {
        "apply_smali_patch", "auto_patch_bypass", "patch_flutter_ssl",
        "inject_network_security_config", "patch_manifest_security",
        "remove_ads",
    }

    # Only look at the most recent tool messages (from last tool call batch)
    for msg in reversed(state["messages"]):
        if not isinstance(msg, ToolMessage):
            break
        tool_name = getattr(msg, "name", "") or ""
        content = msg.content if isinstance(msg.content, str) else ""

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
                    "user_feedback": "",
                    "timestamp": _ts,
                })

            elif tool_name == "auto_patch_bypass":
                # auto_patch_bypass returns per-category stats
                categories = data.get("categories_applied") or []
                total_applied = data.get("total_patches_applied", 0)
                patched_files = data.get("patched_files") or []
                per_cat = data.get("per_category_stats") or {}
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
                    "user_feedback": "",
                    "timestamp": _ts,
                })

        # Auto-build code graph + index after decompilation completes
        if tool_name == "apktool_decompile":
            try:
                _auto_build_graph_and_index()
                updates["graph_ready"] = True
                # Inject a visible message so the agent KNOWS graph is ready
                from apk_agent.agent.tools_def import _code_graph, _code_index
                import apk_agent.agent.tools_def as td
                g = td._code_graph
                idx = td._code_index
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

    # Sync working memory from module-level storage into durable state
    updates["scratchpad"] = _get_scratchpad()
    updates["task_plan"] = _get_task_plan()

    return updates


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

    # Initialize compactor (GLM-5.1: 204k context window)
    # token_threshold: start compacting well before the context fills up
    # keep_recent: preserve only the last few exchanges (each exchange =
    #   AIMessage + ToolMessages can be 5-15 messages for parallel tool calls)
    _compactor = Compactor(token_threshold=100_000, keep_recent=14)

    # Build tool node
    tool_node = ToolNode(ALL_TOOLS)

    # Build graph
    graph = StateGraph(AgentState)

    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.add_node("tools_post", tools_postprocess)
    graph.add_node("human_review", human_review_node)
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

    # After tools execute → postprocess to extract findings → back to agent
    graph.add_edge("tools", "tools_post")
    graph.add_edge("tools_post", "agent")

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
