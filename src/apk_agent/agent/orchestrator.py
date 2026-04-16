"""Orchestrator mode — manages sub-agents for parallel APK analysis.

The orchestrator:
1. Breaks down user tasks into sub-tasks
2. Assigns each sub-task to a specialized sub-agent
3. Runs independent sub-agents in parallel (threads)
4. Consolidates results and reports back
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.prebuilt import ToolNode

from apk_agent.agent.prompts import SYSTEM_PROMPT
from apk_agent.agent.state import AgentState
from apk_agent.agent.sub_agents import SUB_AGENT_CATALOG, SubAgentDef
from apk_agent.agent.tools_def import ALL_TOOLS, set_tool_context
from apk_agent.config import AppConfig
from apk_agent.llm.provider import get_llm
from apk_agent.progress import ProgressManager, TaskStatus, progress_manager
from apk_agent.workspace import Project

logger = logging.getLogger("apk_agent.orchestrator")

# Max content array elements allowed by the API (aimlapi.com proxy limit)
_MAX_CONTENT_BLOCKS = 5


# ---------------------------------------------------------------------------
# Message sanitizer — fix API-breaking message patterns
# ---------------------------------------------------------------------------

def _sanitize_messages(messages: list) -> list:
    """Fix message sequences that would cause API errors.

    Handles four issues:
    0. Null content fields (API requires string or array, never null/None)
    0b. Missing/empty tool names (Gemini requires non-empty name on every
        tool_call and every ToolMessage)
    1. Content array > _MAX_CONTENT_BLOCKS elements (aimlapi.com proxy limit)
    2. Orphaned tool_use without matching tool_result (happens on session resume
       when interrupted mid-tool-execution — Anthropic API requires every
       tool_use to have a corresponding tool_result in the next message)
    """
    # --- Pass 0: Fix null content ---
    # LangChain sometimes creates messages with content=None (e.g. tool-only
    # AI responses). The API rejects null — must be string or array.
    for msg in messages:
        if msg.content is None:
            if isinstance(msg, AIMessage):
                msg.content = ""
            elif isinstance(msg, ToolMessage):
                msg.content = '{"error": "No content returned"}'
            else:
                msg.content = ""

    # --- Pass 0b: Fix empty/missing tool names and ids ---
    # APIs reject tool_calls or ToolMessages with empty name or id.
    _tool_id_to_name: dict[str, str] = {}
    # First sub-pass: collect name mappings from AIMessage tool_calls
    for msg in messages:
        if isinstance(msg, AIMessage) and msg.tool_calls:
            for tc in msg.tool_calls:
                name = tc.get("name") or ""
                tid = tc.get("id") or ""
                if name and tid:
                    _tool_id_to_name[tid] = name
    # Second sub-pass: fix empty names, strip tool_calls with empty ids,
    # and sync additional_kwargs["tool_calls"] to prevent ghost entries
    for msg in messages:
        if isinstance(msg, AIMessage) and msg.tool_calls:
            # Remove tool_calls that have no id — API cannot match them
            msg.tool_calls = [
                tc for tc in msg.tool_calls if tc.get("id")
            ]
            for tc in msg.tool_calls:
                if not tc.get("name"):
                    tc["name"] = _tool_id_to_name.get(tc.get("id", ""), "unknown_tool")
            # Also fix invalid_tool_calls if present
            if hasattr(msg, "invalid_tool_calls") and msg.invalid_tool_calls:
                msg.invalid_tool_calls = [
                    tc for tc in msg.invalid_tool_calls if tc.get("id")
                ]
            # Sync additional_kwargs["tool_calls"] with .tool_calls
            # LangChain falls back to additional_kwargs when .tool_calls is empty,
            # which can leak ghost tool_call_ids to the API
            ak_tcs = msg.additional_kwargs.get("tool_calls")
            if ak_tcs is not None:
                current_ids = {tc.get("id") for tc in msg.tool_calls}
                msg.additional_kwargs["tool_calls"] = [
                    tc for tc in ak_tcs if tc.get("id") in current_ids
                ]
        if isinstance(msg, AIMessage) and not msg.tool_calls:
            # If tool_calls was fully emptied, also clear additional_kwargs
            msg.additional_kwargs.pop("tool_calls", None)
        if isinstance(msg, ToolMessage):
            if not getattr(msg, "name", None):
                msg.name = _tool_id_to_name.get(msg.tool_call_id, "unknown_tool")

    # --- Pass 1: Fix content array size ---
    pass1 = []
    dropped_tool_ids: set[str] = set()

    for msg in messages:
        if isinstance(msg, AIMessage) and isinstance(msg.content, list):
            if len(msg.content) > _MAX_CONTENT_BLOCKS:
                text_blocks = [
                    b for b in msg.content
                    if isinstance(b, dict) and b.get("type") == "text"
                ]
                tool_blocks = [
                    b for b in msg.content
                    if isinstance(b, dict) and b.get("type") == "tool_use"
                ]

                max_tools = _MAX_CONTENT_BLOCKS - max(1, len(text_blocks))
                kept_tools = tool_blocks[:max_tools]
                dropped = tool_blocks[max_tools:]

                for t in dropped:
                    tid = t.get("id", "")
                    if tid:
                        dropped_tool_ids.add(tid)

                new_content = (text_blocks + kept_tools)[:_MAX_CONTENT_BLOCKS]
                kept_tool_ids = {t.get("id") for t in kept_tools}
                new_tool_calls = [
                    tc for tc in (msg.tool_calls or [])
                    if tc.get("id") in kept_tool_ids
                ] if msg.tool_calls else []

                for tc in (msg.tool_calls or []):
                    if tc.get("id") not in kept_tool_ids:
                        dropped_tool_ids.add(tc["id"])

                new_msg = AIMessage(
                    content=new_content,
                    tool_calls=new_tool_calls,
                    id=msg.id,
                    additional_kwargs=msg.additional_kwargs,
                )
                pass1.append(new_msg)
                if dropped:
                    logger.info(
                        "Sanitized AIMessage: dropped %d tool_use blocks (limit %d)",
                        len(dropped), _MAX_CONTENT_BLOCKS,
                    )
                continue

        # Drop ToolMessages whose tool_call was removed
        if isinstance(msg, ToolMessage):
            if msg.tool_call_id in dropped_tool_ids:
                continue

        pass1.append(msg)

    # --- Pass 2: Fix orphaned tool_use without tool_result ---
    # Collect all tool_call_ids that have matching ToolMessages
    existing_tool_result_ids: set[str] = set()
    for msg in pass1:
        if isinstance(msg, ToolMessage):
            existing_tool_result_ids.add(msg.tool_call_id)

    # Find AIMessages with tool_calls that lack matching ToolMessages
    sanitized = []
    for i, msg in enumerate(pass1):
        sanitized.append(msg)

        if isinstance(msg, AIMessage) and msg.tool_calls:
            orphaned_calls = [
                tc for tc in msg.tool_calls
                if tc.get("id") and tc["id"] not in existing_tool_result_ids
            ]
            if orphaned_calls:
                # Inject synthetic ToolMessages for orphaned tool_calls
                # This happens when session was interrupted mid-tool-execution
                logger.info(
                    "Injecting %d synthetic tool_results for orphaned tool_calls "
                    "(session was interrupted mid-execution)",
                    len(orphaned_calls),
                )
                for tc in orphaned_calls:
                    synthetic = ToolMessage(
                        content=(
                            '{"success": false, "error": "Session was interrupted before '
                            'this tool completed. Please re-run this tool."}'
                        ),
                        tool_call_id=tc["id"],
                        name=tc.get("name", "unknown"),
                    )
                    sanitized.append(synthetic)
                    existing_tool_result_ids.add(tc["id"])

    # --- Pass 3: Drop orphaned ToolMessages without matching AIMessage tool_call ---
    # After compaction or session resume, ToolMessages may reference tool_call_ids
    # that no longer exist in any AIMessage. The API rejects these.
    all_ai_tool_ids: set[str] = set()
    for msg in sanitized:
        if isinstance(msg, AIMessage) and msg.tool_calls:
            for tc in msg.tool_calls:
                tid = tc.get("id") or ""
                if tid:
                    all_ai_tool_ids.add(tid)

    pass3 = []
    for msg in sanitized:
        if isinstance(msg, ToolMessage):
            tid = msg.tool_call_id or ""
            if not tid or tid not in all_ai_tool_ids:
                logger.debug(
                    "Dropping orphaned ToolMessage (tool_call_id=%r not in any AIMessage)",
                    tid[:20] if tid else "<empty>",
                )
                continue
        pass3.append(msg)

    return pass3


# ---------------------------------------------------------------------------
# Sub-agent runner
# ---------------------------------------------------------------------------

def _build_sub_agent_graph(agent_def: SubAgentDef, config: AppConfig, project: Project):
    """Build a minimal LangGraph for a sub-agent with its restricted tool set."""
    from apk_agent.agent.tools_def import ALL_TOOLS as all_tools

    # Filter tools for this sub-agent
    tool_map = {t.name: t for t in all_tools}
    agent_tools = [tool_map[n] for n in agent_def.tool_names if n in tool_map]

    if not agent_tools:
        raise ValueError(f"No tools found for sub-agent '{agent_def.name}'")

    llm = get_llm(config, temperature=1.0)
    llm_with_tools = llm.bind_tools(agent_tools)

    _sub_llm_store = {"llm": llm_with_tools}

    # --- Running notebook: compact memory that survives message trimming ---
    _notebook: dict[str, Any] = {"iteration": 0, "findings": [], "files_seen": [], "notes": []}

    def _build_notebook_summary() -> str:
        """Build a compact string from the notebook for injection into context."""
        if not _notebook["findings"] and not _notebook["notes"]:
            return ""
        parts = ["📓 NOTEBOOK (accumulated findings so far):"]
        for f in _notebook["findings"][-15:]:  # last 15 findings max
            parts.append(f"  • {f}")
        if _notebook["files_seen"]:
            parts.append(f"  Files analyzed: {', '.join(_notebook['files_seen'][-10:])}")
        for n in _notebook["notes"][-5:]:
            parts.append(f"  Note: {n}")
        return "\n".join(parts)

    def _extract_findings_from_response(content: str) -> None:
        """Extract key findings from AI response into the notebook."""
        if not content:
            return
        # Extract lines that look like findings/vulnerabilities/results
        for line in content.split("\n"):
            line_s = line.strip()
            if not line_s or len(line_s) < 15:
                continue
            low = line_s.lower()
            # Capture lines that mention security-relevant findings
            if any(kw in low for kw in [
                "found", "detected", "vulnerability", "insecure", "hardcoded",
                "ssl", "pinning", "certificate", "trust", "encrypt", "decrypt",
                "aes", "rsa", "md5", "sha1", "key", "secret", "token",
                "bypass", "patch", "root detect", "emulator",
            ]):
                # Deduplicate
                short = line_s[:120]
                if short not in _notebook["findings"]:
                    _notebook["findings"].append(short)

    def agent_node(state: AgentState) -> dict:
        _notebook["iteration"] += 1
        messages = list(state["messages"])
        if not messages or not isinstance(messages[0], SystemMessage):
            sub_prompt = (
                f"You are the {agent_def.role}.\n\n"
                f"{agent_def.system_prompt_extra}\n\n"
                f"You have access to these tools: {', '.join(agent_def.tool_names)}\n\n"
                f"Project: {project.apk_name} at {project.workspace_path}\n"
                f"APK path: {project.apk_path}\n"
                f"Apktool dir: {project.apktool_dir}\n"
                f"JADX dir: {project.jadx_dir}\n"
            )
            messages.insert(0, SystemMessage(content=sub_prompt))

        # --- Mini-compaction: after iteration 3, drop old messages but keep notebook ---
        if _notebook["iteration"] > 3 and len(messages) > 8:
            system_msg = messages[0]
            recent = messages[-6:]  # keep last 6 messages (3 tool cycles)
            notebook_text = _build_notebook_summary()
            if notebook_text:
                bridge = HumanMessage(
                    content=(
                        f"[Previous {len(messages) - 7} messages trimmed to save context]\n\n"
                        f"{notebook_text}\n\n"
                        f"Continue your analysis. Use the findings above as reference."
                    )
                )
                messages = [system_msg, bridge] + recent
            else:
                messages = [system_msg] + recent

        # Sanitize to prevent content array > 5 elements (API limit)
        messages = _sanitize_messages(messages)

        # Truncate large tool results in OLD messages only (preserve recent ones)
        _MAX_CHARS = 3000
        _HEAD = 1800
        _TAIL = 1000
        _RECENT = 4  # never truncate the last N messages
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

        # --- Final safety: sync additional_kwargs and drop orphaned ToolMessages ---
        for msg in messages:
            if isinstance(msg, AIMessage):
                ak_tcs = msg.additional_kwargs.get("tool_calls")
                if ak_tcs is not None:
                    current_ids = {tc.get("id") for tc in (msg.tool_calls or [])}
                    msg.additional_kwargs["tool_calls"] = [
                        tc for tc in ak_tcs if tc.get("id") in current_ids
                    ]
                    if not msg.tool_calls:
                        msg.additional_kwargs.pop("tool_calls", None)
        _valid_tc_ids: set[str] = set()
        for msg in messages:
            if isinstance(msg, AIMessage):
                for tc in (msg.tool_calls or []):
                    tid = tc.get("id") or ""
                    if tid:
                        _valid_tc_ids.add(tid)
        messages = [
            msg for msg in messages
            if not isinstance(msg, ToolMessage)
            or (msg.tool_call_id and msg.tool_call_id in _valid_tc_ids)
        ]

        # Retry with exponential backoff for transient API errors
        max_retries = 3
        for attempt in range(max_retries + 1):
            try:
                response = _sub_llm_store["llm"].invoke(messages)
                break
            except Exception as e:
                err_str = str(e).lower()
                is_retryable = any(k in err_str for k in [
                    "429", "rate_limit", "rate limit",
                    "503", "service unavailable", "overloaded",
                    "500", "internal server error",
                    "tool name is required",
                    "must be in json format", "invalidparameter",
                    "tool_call_id", "is not found",
                ])
                if "tool_call_id" in err_str and "not found" in err_str:
                    logger.warning("Sub-agent orphaned tool_call_id — re-sanitizing...")
                    messages = _sanitize_messages(messages)
                if "tool name is required" in err_str:
                    messages = _sanitize_messages(messages)
                    for _m in messages:
                        if isinstance(_m, AIMessage) and _m.tool_calls:
                            _m.tool_calls = [tc for tc in _m.tool_calls if tc.get("name")]
                if not is_retryable or attempt >= max_retries:
                    raise
                wait = 2 ** attempt * 3
                logger.warning(
                    "Sub-agent API error (attempt %d/%d): %s — retrying in %ds...",
                    attempt + 1, max_retries, str(e)[:120], wait,
                )
                time.sleep(wait)

        # Extract key findings from the response into the notebook
        if hasattr(response, "content") and response.content:
            _extract_findings_from_response(response.content)

        return {"messages": [response]}

    def should_continue(state: AgentState):
        last = state["messages"][-1]
        if not isinstance(last, AIMessage):
            return "__end__"
        if last.tool_calls:
            return "tools"
        return "__end__"

    tool_node = ToolNode(agent_tools)
    graph = StateGraph(AgentState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.set_entry_point("agent")
    graph.add_conditional_edges("agent", should_continue, {"tools": "tools", "__end__": END})
    graph.add_edge("tools", "agent")

    checkpointer = MemorySaver()
    return graph.compile(checkpointer=checkpointer)


def run_sub_agent(
    agent_def: SubAgentDef,
    task: str,
    config: AppConfig,
    project: Project,
    progress: ProgressManager | None = None,
) -> dict:
    """Run a sub-agent to completion and return its results.

    This is designed to be called from a thread pool.
    """
    task_id = f"sub_{agent_def.name}_{uuid.uuid4().hex[:6]}"

    if progress:
        progress.start_task(task_id, agent_def.role, task)

    try:
        # Ensure tool context is set (thread-safe since it's global state set once)
        set_tool_context(config, project)

        graph = _build_sub_agent_graph(agent_def, config, project)
        thread_id = str(uuid.uuid4())
        graph_config = {"configurable": {"thread_id": thread_id}}

        input_state = {
            "messages": [HumanMessage(content=task)],
            "project_id": project.id,
            "project_path": project.workspace_path,
            "apk_name": project.apk_name,
            "apktool_dir": str(project.apktool_dir),
            "jadx_dir": str(project.jadx_dir),
            "task": task,
            "findings": [],
            "patch_results": [],
            "patch_registry": [],
            "patch_plans": [],
            "tool_history": [],
            "current_plan": "",
            "plan_step_index": 0,
            "human_feedback": "",
            "graph_ready": False,
            "target_packages": [],
            "excluded_packages": [],
            "scratchpad": {},
            "task_plan": [],
        }

        # Run the graph
        final_state = None
        iterations = 0
        max_iter = agent_def.max_iterations
        all_ai_messages: list = []
        all_tool_messages: list = []

        for event in graph.stream(input_state, config=graph_config, stream_mode="updates"):
            iterations += 1
            if progress:
                pct = min(95, (iterations / max_iter) * 100)
                progress.update_task(task_id, progress_pct=pct)

            # Collect ALL AI messages and tool results for post-loop extraction
            for node_name, output in event.items():
                if node_name == "agent":
                    messages = output.get("messages", [])
                    for msg in messages:
                        if isinstance(msg, AIMessage):
                            all_ai_messages.append(msg)
                elif node_name == "tools":
                    messages = output.get("messages", [])
                    for msg in messages:
                        if isinstance(msg, ToolMessage):
                            all_tool_messages.append(msg)

            if iterations >= max_iter:
                break

        # Extract the last meaningful AI response (search backwards)
        for msg in reversed(all_ai_messages):
            content = msg.content
            # Handle content that can be a string or a list of blocks
            if isinstance(content, list):
                text_parts = []
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text_parts.append(block.get("text", ""))
                    elif isinstance(block, str):
                        text_parts.append(block)
                content = "\n".join(text_parts)
            if isinstance(content, str) and content.strip():
                final_state = content.strip()
                break

        # -----------------------------------------------------------------
        # Fallback: force a summary call when no text content was captured.
        # This happens when the agent hit max_iterations while still calling
        # tools (every AIMessage had only tool_calls with empty content).
        # We call the LLM one more time WITHOUT tools so it MUST produce text.
        # -----------------------------------------------------------------
        if not final_state and all_tool_messages:
            logger.info(
                "Sub-agent %s produced no text after %d iterations — "
                "forcing summary call with %d tool results",
                agent_def.name, iterations, len(all_tool_messages),
            )
            tool_context_parts = []
            for tmsg in all_tool_messages:
                name = getattr(tmsg, "name", "tool")
                tc = tmsg.content if isinstance(tmsg.content, str) else str(tmsg.content)
                if len(tc) > 2500:
                    tc = tc[:1800] + f"\n... [{len(tc) - 2300} chars omitted] ...\n" + tc[-500:]
                tool_context_parts.append(f"### {name}\n{tc}")

            summary_prompt = (
                f"You are the {agent_def.role}.\n"
                f"You were tasked with: {task}\n\n"
                f"Below are ALL the results from the tools you used during analysis.\n"
                f"Provide a thorough, structured summary of your findings.\n"
                f"Include specific class names, file paths, code patterns, "
                f"vulnerabilities, and actionable details.\n\n"
                + "\n\n".join(tool_context_parts[-12:])
            )
            try:
                raw_llm = get_llm(config, temperature=1.0)
                summary_resp = raw_llm.invoke([HumanMessage(content=summary_prompt)])
                if summary_resp.content and isinstance(summary_resp.content, str) and summary_resp.content.strip():
                    final_state = summary_resp.content.strip()
                elif isinstance(summary_resp.content, list):
                    parts = []
                    for block in summary_resp.content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            parts.append(block.get("text", ""))
                        elif isinstance(block, str):
                            parts.append(block)
                    joined = "\n".join(parts).strip()
                    if joined:
                        final_state = joined
            except Exception as e:
                logger.warning("Summary call failed for %s: %s", agent_def.name, e)

        if progress:
            progress.complete_task(task_id, success=True)

        # Last-resort fallback: list tool usage
        if not final_state:
            tool_summaries = []
            for msg in all_ai_messages:
                if msg.tool_calls:
                    for tc in msg.tool_calls:
                        tool_summaries.append(f"- Used tool: {tc.get('name', '?')}")
            if tool_summaries:
                final_state = (
                    f"Sub-agent completed {iterations} iterations using tools:\n"
                    + "\n".join(tool_summaries[:20])
                )

        return {
            "agent": agent_def.name,
            "role": agent_def.role,
            "task": task,
            "iterations": iterations,
            "result": final_state or "Sub-agent completed but produced no text summary.",
            "success": True,
        }

    except Exception as e:
        logger.error("Sub-agent %s failed: %s", agent_def.name, e)
        if progress:
            progress.complete_task(task_id, success=False, error=str(e))
        return {
            "agent": agent_def.name,
            "role": agent_def.role,
            "task": task,
            "iterations": 0,
            "result": f"Error: {e}",
            "success": False,
        }


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class Orchestrator:
    """High-level orchestrator that plans and dispatches sub-agent tasks.

    Supports two interaction modes:
    - dispatch: break task into sub-agents and run them in parallel
    - chat: answer conversationally using previous results as context
    """

    # Class-level storage for results across turns so follow-up questions work
    _previous_results: list[dict] = []
    _conversation_history: list[dict] = []  # [{"role":"user","content":...}, ...]

    def __init__(self, config: AppConfig, project: Project, max_parallel: int = 3):
        self.config = config
        self.project = project
        self.max_parallel = max_parallel
        self.progress = progress_manager
        self.results: list[dict] = []

    def route_message(self, user_input: str) -> str:
        """Classify user input: 'dispatch' (needs sub-agents) or 'chat' (conversational).

        Returns 'dispatch' or 'chat'.
        """
        # If no previous results, always dispatch (nothing to chat about)
        if not Orchestrator._previous_results:
            return "dispatch"

        llm = get_llm(self.config, temperature=0.0)
        route_prompt = (
            "You are a router for an APK security analysis orchestrator.\n"
            "The user is in orchestrator mode. Previous analysis results exist.\n\n"
            "Classify the user's message into ONE of these categories:\n"
            "- DISPATCH: The user wants NEW analysis, scanning, patching, or a task "
            "that requires running tools and sub-agents (e.g., 'scan for SSL issues', "
            "'find crypto algorithms', 'bypass root detection', 'do a full audit').\n"
            "- CHAT: The user is asking a question, requesting clarification, "
            "discussing previous results, asking for a summary, or having a conversation "
            "that does NOT require new sub-agent work (e.g., 'what did you find?', "
            "'explain the crypto issue', 'show me the results', 'what is AES?', "
            "'which classes are vulnerable?').\n\n"
            f"Previous analysis agents used: "
            f"{', '.join(r.get('role', '?') for r in Orchestrator._previous_results)}\n\n"
            f"User message: {user_input}\n\n"
            "Reply with ONLY one word: DISPATCH or CHAT"
        )
        try:
            response = llm.invoke([HumanMessage(content=route_prompt)])
            answer = response.content.strip().upper()
            if "CHAT" in answer:
                return "chat"
        except Exception as e:
            logger.warning("Route classification failed: %s — defaulting to dispatch", e)

        return "dispatch"

    def chat(self, user_input: str) -> str:
        """Answer conversationally using previous results as context."""
        llm = get_llm(self.config, temperature=1.0)

        # Build context from previous results
        context_parts = []
        for r in Orchestrator._previous_results:
            result_text = r.get("result", "")
            role = r.get("role", "unknown")
            if len(result_text) > 4000:
                result_text = result_text[:3000] + "\n...\n" + result_text[-1000:]
            context_parts.append(f"### {role}\n{result_text}")

        # Build conversation history
        history_msgs = []
        for entry in Orchestrator._conversation_history[-6:]:  # last 6 turns
            if entry["role"] == "user":
                history_msgs.append(f"User: {entry['content']}")
            else:
                history_msgs.append(f"Assistant: {entry['content'][:500]}")
        history_text = "\n".join(history_msgs) if history_msgs else "(no prior conversation)"

        chat_prompt = (
            f"You are an APK security analysis expert assistant.\n"
            f"The user is in orchestrator mode and has already run analysis on: "
            f"{self.project.apk_name}\n\n"
            f"## Previous Analysis Results\n\n"
            f"{''.join(context_parts)}\n\n"
            f"## Recent Conversation\n{history_text}\n\n"
            f"## User's Current Message\n{user_input}\n\n"
            f"Answer the user's question based on the analysis results above. "
            f"Be specific — reference exact class names, file paths, algorithms, "
            f"and findings from the results. If the user asks for something that "
            f"requires new analysis, tell them you'll need to run sub-agents and "
            f"suggest they phrase it as a task."
        )
        try:
            response = llm.invoke([HumanMessage(content=chat_prompt)])
            content = response.content
            if isinstance(content, list):
                parts = []
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        parts.append(block.get("text", ""))
                    elif isinstance(block, str):
                        parts.append(block)
                content = "\n".join(parts)
            answer = content.strip() if isinstance(content, str) else str(content)
        except Exception as e:
            logger.error("Chat failed: %s", e)
            answer = f"Error generating response: {e}"

        # Update conversation history
        Orchestrator._conversation_history.append({"role": "user", "content": user_input})
        Orchestrator._conversation_history.append({"role": "assistant", "content": answer})

        return answer

    def plan_and_execute(self, user_task: str, callback=None) -> list[dict]:
        """Plan sub-tasks from the user's request and execute them.

        Args:
            user_task: The user's high-level request
            callback: Optional function called with (event, data) for UI updates

        Returns:
            List of sub-agent results
        """
        self.progress.set_overall_task(user_task)

        # Use LLM to create an execution plan
        plan = self._create_plan(user_task)

        if callback:
            callback("plan_created", plan)

        # Separate parallel and sequential phases
        parallel_tasks = plan.get("parallel", [])
        sequential_tasks = plan.get("sequential", [])

        results = []

        # Execute parallel tasks
        if parallel_tasks:
            if callback:
                callback("phase_start", {"phase": "parallel", "tasks": parallel_tasks})
            parallel_results = self._run_parallel(parallel_tasks)
            results.extend(parallel_results)

        # Execute sequential tasks (they may depend on parallel results)
        for task_info in sequential_tasks:
            if callback:
                callback("phase_start", {"phase": "sequential", "task": task_info})

            # Inject context from previous results — structured summary, not raw truncation
            enriched_task = task_info["task"]
            if results:
                context_parts = []
                for r in results:
                    if not r.get("success"):
                        continue
                    result_text = r.get("result", "")
                    # Extract key findings from result (structured)
                    agent_name = r.get("agent", "unknown")
                    role = r.get("role", "")
                    # Smart truncation: keep first 3000 + last 1500 for important tail info
                    if len(result_text) > 5000:
                        head = result_text[:3000]
                        tail = result_text[-1500:]
                        result_text = f"{head}\n... [{len(result_text) - 4500} chars omitted] ...\n{tail}"
                    context_parts.append(f"[{role} ({agent_name}) findings]:\n{result_text}")
                context = "\n\n".join(context_parts)
                enriched_task = f"{task_info['task']}\n\nContext from previous agents:\n{context}"

            agent_def = SUB_AGENT_CATALOG.get(task_info["agent"])
            if agent_def:
                result = run_sub_agent(
                    agent_def, enriched_task, self.config, self.project, self.progress
                )
                results.append(result)

        self.results = results
        # Store results at class level so follow-up messages can reference them
        Orchestrator._previous_results = results
        Orchestrator._conversation_history.append(
            {"role": "user", "content": user_task}
        )
        Orchestrator._conversation_history.append(
            {"role": "assistant", "content": f"[Dispatched {len(results)} sub-agents]"}
        )
        return results

    def _create_plan(self, user_task: str) -> dict:
        """Use LLM to create an execution plan mapping task to sub-agents."""
        llm = get_llm(self.config, temperature=1.0)

        plan_prompt = f"""You are an orchestrator planning how to analyze an Android APK.

Available sub-agents:
{json.dumps({name: {"role": a.role, "description": a.description} for name, a in SUB_AGENT_CATALOG.items()}, indent=2)}

User task: {user_task}
APK: {self.project.apk_name}

Create an execution plan as JSON with this structure:
{{
    "parallel": [
        {{"agent": "agent_name", "task": "specific task description"}},
        ...
    ],
    "sequential": [
        {{"agent": "agent_name", "task": "specific task (may depend on parallel results)"}},
        ...
    ]
}}

Rules:
- "recon" should almost always run first (in parallel with vuln_scanner if decompilation is already done)
- "vuln_scanner" and "crypto_analyst" can run in parallel after decompilation
- "patcher" must run sequentially after analysis
- "reporter" always runs last
- Only include agents that are needed for the user's task

Return ONLY the JSON, no markdown formatting."""

        response = llm.invoke([HumanMessage(content=plan_prompt)])
        content = response.content.strip()

        # Parse the plan
        try:
            # Try to extract JSON from markdown code blocks
            if "```" in content:
                parts = content.split("```")
                if len(parts) >= 3:
                    json_block = parts[1]
                else:
                    json_block = parts[1] if len(parts) > 1 else content
                json_block = json_block.strip()
                # Strip language tag (json, JSON, etc.)
                if json_block.lower().startswith("json"):
                    json_block = json_block[4:].strip()
                content = json_block
            plan = json.loads(content)
        except (json.JSONDecodeError, IndexError):
            # Try to find a JSON object anywhere in the response
            import re
            json_match = re.search(r'\{[\s\S]*\}', content)
            if json_match:
                try:
                    plan = json.loads(json_match.group())
                except json.JSONDecodeError:
                    logger.warning("Could not parse LLM plan, using default")
                    plan = self._default_plan(user_task)
            else:
                logger.warning("Could not parse LLM plan, using default")
                plan = self._default_plan(user_task)

        return plan

    def _default_plan(self, user_task: str) -> dict:
        """Fallback execution plan."""
        task_lower = user_task.lower()

        if any(w in task_lower for w in ["patch", "bypass", "remove", "disable"]):
            return {
                "parallel": [
                    {"agent": "recon", "task": f"Gather APK metadata for: {user_task}"},
                ],
                "sequential": [
                    {"agent": "vuln_scanner", "task": f"Find relevant vulnerabilities for: {user_task}"},
                    {"agent": "patcher", "task": user_task},
                    {"agent": "reporter", "task": "Generate final report"},
                ],
            }
        elif any(w in task_lower for w in ["scan", "audit", "review", "analyze"]):
            return {
                "parallel": [
                    {"agent": "recon", "task": f"Gather APK metadata for: {user_task}"},
                    {"agent": "vuln_scanner", "task": f"Scan for vulnerabilities: {user_task}"},
                ],
                "sequential": [
                    {"agent": "crypto_analyst", "task": f"Analyze cryptography: {user_task}"},
                    {"agent": "reporter", "task": "Generate comprehensive security report"},
                ],
            }
        else:
            return {
                "parallel": [
                    {"agent": "recon", "task": user_task},
                ],
                "sequential": [
                    {"agent": "vuln_scanner", "task": user_task},
                    {"agent": "reporter", "task": "Generate report"},
                ],
            }

    def _run_parallel(self, tasks: list[dict]) -> list[dict]:
        """Run multiple sub-agents in parallel using ThreadPoolExecutor."""
        results = []

        with ThreadPoolExecutor(max_workers=self.max_parallel) as executor:
            futures = {}
            for task_info in tasks:
                agent_def = SUB_AGENT_CATALOG.get(task_info["agent"])
                if not agent_def:
                    logger.warning("Unknown sub-agent: %s", task_info["agent"])
                    continue

                future = executor.submit(
                    run_sub_agent,
                    agent_def,
                    task_info["task"],
                    self.config,
                    self.project,
                    self.progress,
                )
                futures[future] = task_info

            for future in as_completed(futures):
                task_info = futures[future]
                try:
                    result = future.result(timeout=600)
                    results.append(result)
                except Exception as e:
                    logger.error("Parallel task failed: %s", e)
                    results.append({
                        "agent": task_info["agent"],
                        "task": task_info["task"],
                        "result": f"Error: {e}",
                        "success": False,
                    })

        return results
