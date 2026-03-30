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

    Handles three issues:
    0. Null content fields (API requires string or array, never null/None)
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

    return sanitized


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

        response = _sub_llm_store["llm"].invoke(messages)

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
            "patch_plans": [],
            "patch_results": [],
            "tool_history": [],
            "current_plan": [],
            "plan_step_index": 0,
            "human_feedback": "",
        }

        # Run the graph
        final_state = None
        iterations = 0
        max_iter = agent_def.max_iterations
        all_ai_messages: list = []

        for event in graph.stream(input_state, config=graph_config, stream_mode="updates"):
            iterations += 1
            if progress:
                pct = min(95, (iterations / max_iter) * 100)
                progress.update_task(task_id, progress_pct=pct)

            # Collect ALL AI messages for post-loop extraction
            for node_name, output in event.items():
                if node_name == "agent":
                    messages = output.get("messages", [])
                    for msg in messages:
                        if isinstance(msg, AIMessage):
                            all_ai_messages.append(msg)

            if iterations >= max_iter:
                break

        # Extract the last meaningful AI response (search backwards)
        for msg in reversed(all_ai_messages):
            content = msg.content
            # Handle content that can be a string or a list of blocks
            if isinstance(content, list):
                # Extract text from content blocks (e.g. [{"type":"text","text":"..."}])
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

        if progress:
            progress.complete_task(task_id, success=True)

        # If no text content was found, try to build a summary from tool results
        if not final_state:
            # Gather non-empty ToolMessage contents as a fallback summary
            tool_summaries = []
            for msg in all_ai_messages:
                # AI messages with tool_calls still may have partial content
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
    """High-level orchestrator that plans and dispatches sub-agent tasks."""

    def __init__(self, config: AppConfig, project: Project, max_parallel: int = 3):
        self.config = config
        self.project = project
        self.max_parallel = max_parallel
        self.progress = progress_manager
        self.results: list[dict] = []

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
            # Try to extract JSON from the response
            if "```" in content:
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
            plan = json.loads(content)
        except (json.JSONDecodeError, IndexError):
            # Fallback: default plan
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
