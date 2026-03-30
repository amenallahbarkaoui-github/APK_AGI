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

import json
import logging
import time
from typing import Any, Literal

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.types import interrupt, Command

from apk_agent.agent.prompts import SYSTEM_PROMPT
from apk_agent.agent.state import AgentState
from apk_agent.agent.tools_def import ALL_TOOLS, set_tool_context, _get_all_smali_dirs, _project
from apk_agent.compactor import Compactor, count_message_tokens
from apk_agent.config import AppConfig
from apk_agent.llm.provider import get_llm
from apk_agent.workspace import Project

logger = logging.getLogger("apk_agent.graph")

# Module-level compactor instance (initialised in build_graph)
_compactor: Compactor | None = None


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

    messages = list(state["messages"])

    # Inject system prompt if not already present
    if not messages or not isinstance(messages[0], SystemMessage):
        messages.insert(0, SystemMessage(content=SYSTEM_PROMPT))

    # Inject durable findings summary as a reminder (survives compaction)
    findings = state.get("findings") or []
    patches = state.get("patch_results") or []
    if findings or patches:
        summary_parts = []
        if findings:
            by_sev: dict[str, int] = {}
            for f in findings:
                s = f.get("severity", "info")
                by_sev[s] = by_sev.get(s, 0) + 1
            summary_parts.append(f"📋 Findings: {dict(by_sev)}")
            # Show top critical/high
            critical = [f for f in findings if f.get("severity") in ("CRITICAL", "critical", "HIGH", "high")]
            for c in critical[:8]:
                summary_parts.append(f"  • [{c.get('severity','')}] {c.get('name','')}: {c.get('file','')}")
        if patches:
            ok = sum(1 for p in patches if p.get("success"))
            summary_parts.append(f"🔧 Patches applied: {ok}/{len(patches)}")
        findings_msg = "\n".join(summary_parts)
        # Insert after system prompt
        insert_idx = 1 if isinstance(messages[0], SystemMessage) else 0
        messages.insert(insert_idx, HumanMessage(
            content=f"[DURABLE STATE — findings & patches so far]\n{findings_msg}"
        ))

    # --- Auto-compact check ---
    if _compactor is not None and _compactor.should_compact(messages):
        logger.info(
            "Context too large (~%d tokens). Running auto-compact...",
            _compactor.last_token_count,
        )
        # Get the raw LLM (without tools) for compaction
        from apk_agent.agent.graph import _raw_llm

        compacted = _compactor.compact(messages, _raw_llm)
        if compacted is not messages:
            messages = compacted
            logger.info(
                "Compacted to %d messages (~%d tokens)",
                len(messages),
                count_message_tokens(messages),
            )
            # Inject auto-continue instruction so the agent doesn't stop
            messages.append(HumanMessage(
                content=(
                    "[SYSTEM] Context was auto-compacted. Read the summary above carefully, "
                    "then CONTINUE working on the original task without asking. "
                    "Do NOT repeat already-completed tool calls. Execute the NEXT step immediately."
                )
            ))

    # Sanitize: prevent content block arrays > 5 elements (API proxy limit)
    messages = _sanitize_messages(messages)

    # Truncate large tool results in OLD messages only (preserve recent ones)
    # Keep head + tail so we don't lose summary headers or final findings
    _MAX_CHARS = 4000
    _HEAD = 2500
    _TAIL = 1200
    _RECENT = 6  # never truncate the last N messages
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
                    name=getattr(msg, "name", None),
                )

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
            ])
            # 403 "API key limit" = quota exhausted, not retryable
            if not is_retryable or attempt >= max_retries:
                raise
            wait = 2 ** attempt * 3  # 3s, 6s, 12s
            logger.warning(
                "API error (attempt %d/%d): %s — retrying in %ds...",
                attempt + 1, max_retries, str(e)[:120], wait,
            )
            time.sleep(wait)
    # If we compacted, return the full new message list + response
    if _compactor is not None and _compactor.compact_count > 0:
        # Only replace messages if we actually compacted this turn
        pass
    return {"messages": [response]}


def should_continue(state: AgentState) -> Literal["tools", "human_review", "__end__"]:
    """Route after agent node: tool call → tools, else → end."""
    last_msg = state["messages"][-1]

    if not isinstance(last_msg, AIMessage):
        return "__end__"

    # If the LLM wants to call tools
    if last_msg.tool_calls:
        # Check if any tool call is a high-risk patch (apply_smali_patch)
        for tc in last_msg.tool_calls:
            if tc["name"] == "apply_smali_patch":
                return "human_review"
        return "tools"

    # No tool calls → agent is done
    return "__end__"


def human_review_node(state: AgentState) -> dict:
    """HITL node — interrupts execution to ask user for confirmation.

    Uses LangGraph's interrupt() to pause the graph.
    The CLI will collect user input and resume with a Command.
    """
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
                    )
                )
        return {"messages": reject_msgs, "human_feedback": "rejected"}

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
    Runs in the background-ish (blocking but fast). Errors are logged, not raised.
    """
    try:
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

        # Build graph
        logger.info("Auto-building code graph after decompilation...")
        G = build_code_graph(smali_dirs, progress_callback=report_progress)
        if G.number_of_nodes() == 0:
            logger.error("Code graph is EMPTY — no classes/methods found in smali dirs")
            raise RuntimeError("Code graph build produced 0 nodes — decompilation may have failed")
        graph_path = outputs_dir / "call_graph.pickle"
        save_graph(G, graph_path)
        td._code_graph = G
        logger.info(f"Code graph built: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

        # Build index
        logger.info("Auto-building code index...")
        jadx_dir = _project.jadx_dir if _project else None
        idx = build_code_index(smali_dirs, jadx_dir=jadx_dir,
                               progress_callback=report_progress)
        index_path = outputs_dir / "code_index.json"
        save_index(idx, index_path)
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
    """
    updates: dict = {}
    new_findings: list[dict] = []
    new_patches: list[dict] = []

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

        # Extract patch results
        if tool_name == "apply_smali_patch":
            try:
                data = json.loads(content)
                if isinstance(data, dict):
                    new_patches.append({
                        "success": data.get("success", False),
                        "target_file": data.get("target_file", ""),
                        "steps_applied": data.get("steps_applied", 0),
                        "errors": data.get("errors", []),
                    })
            except (json.JSONDecodeError, KeyError):
                pass

        # Auto-build code graph + index after decompilation completes
        if tool_name == "apktool_decompile":
            try:
                _auto_build_graph_and_index()
                updates["graph_ready"] = True
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

    # Set tool context
    set_tool_context(config, project)

    # Create LLM with tools bound
    llm = get_llm(config)
    _raw_llm = llm  # keep a reference without tools for compaction
    _llm_with_tools = llm.bind_tools(ALL_TOOLS)

    # Initialize compactor
    _compactor = Compactor(token_threshold=90_000, keep_recent=20)

    # Build tool node
    tool_node = ToolNode(ALL_TOOLS)

    # Build graph
    graph = StateGraph(AgentState)

    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.add_node("tools_post", tools_postprocess)
    graph.add_node("human_review", human_review_node)

    graph.set_entry_point("agent")

    graph.add_conditional_edges(
        "agent",
        should_continue,
        {
            "tools": "tools",
            "human_review": "human_review",
            "__end__": END,
        },
    )

    # After tools execute → postprocess to extract findings → back to agent
    graph.add_edge("tools", "tools_post")
    graph.add_edge("tools_post", "agent")

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
