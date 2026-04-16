"""Agent state definition for LangGraph."""

from __future__ import annotations

from typing import Annotated, Any, Sequence

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages
from typing_extensions import TypedDict


class AgentState(TypedDict):
    """Full state flowing through the LangGraph agent.

    Uses LangGraph's `add_messages` reducer so that tool messages
    are automatically appended to the conversation.
    """

    # ---- conversation ----
    messages: Annotated[Sequence[BaseMessage], add_messages]

    # ---- project context ----
    project_id: str
    project_path: str
    apk_name: str
    apktool_dir: str
    jadx_dir: str

    # ---- task ----
    task: str  # user's high-level request

    # ---- scope / targeting (prevents third-party SDK distraction) ----
    target_packages: list[str]       # app's own packages (e.g. ["com.comviva.nextgen", "tn.com.tunisiana"])
    excluded_packages: list[str]     # third-party noise to ignore (e.g. ["com.google", "com.facebook", "com.madme"])

    # ---- graph / index readiness ----
    graph_ready: bool                # True after code graph + index built successfully

    # ---- analysis results ----
    findings: list[dict[str, Any]]

    # ---- patch tracking ----
    patch_results: list[dict[str, Any]]

    # ---- HITL ----
    human_feedback: str  # populated when resuming from an interrupt

    # ---- working memory (survives compaction via state reminder injection) ----
    scratchpad: dict[str, Any]  # key→value pairs the agent can store for durable context

    # ---- task decomposition ----
    task_plan: list[dict[str, Any]]  # [{id, desc, status: pending|in_progress|done}, ...]
