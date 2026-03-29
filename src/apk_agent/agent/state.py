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

    # ---- analysis results ----
    findings: list[dict[str, Any]]

    # ---- patch tracking ----
    patch_plans: list[dict[str, Any]]
    patch_results: list[dict[str, Any]]

    # ---- tool history (for reporting & awareness) ----
    tool_history: list[dict[str, Any]]

    # ---- dynamic plan ----
    current_plan: list[str]  # LLM can rewrite this after each observation
    plan_step_index: int

    # ---- HITL ----
    human_feedback: str  # populated when resuming from an interrupt
