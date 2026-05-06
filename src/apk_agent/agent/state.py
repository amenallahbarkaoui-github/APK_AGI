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
    smali_index_ready: bool          # True after SmaliIndex IR is built (build_smali_index tool)

    # ---- analysis results ----
    findings: list[dict[str, Any]]

    # ---- patch tracking ----
    patch_results: list[dict[str, Any]]
    patch_plans: list[dict[str, Any]]  # saved patch plans for replay / auditing
    patch_registry: list[dict[str, Any]]  # durable patch journal — every patch attempt with full details

    # ---- execution history ----
    tool_history: list[dict[str, Any]]  # [{tool, success, summary, timestamp}, ...]

    # ---- plan execution ----
    current_plan: str   # name/description of the currently executing plan
    plan_step_index: int  # current step index within the active plan

    # ---- HITL ----
    human_feedback: str  # populated when resuming from an interrupt

    # ---- working memory (survives compaction via state reminder injection) ----
    scratchpad: dict[str, Any]  # key→value pairs the agent can store for durable context

    # ---- task decomposition ----
    task_plan: list[dict[str, Any]]  # [{id, desc, status: pending|in_progress|done}, ...]

    # ---- planning readiness ----
    planning_started: bool  # True once a concrete task plan exists
    analysis_complete_for_patching: bool  # True after evidence-first analysis has run
    patch_plan_ready: bool  # True after a concrete patch preview/plan exists
    prebuild_validation_ready: bool  # True after validate_patch_pipeline passes
    runtime_validation_ready: bool  # True after a runtime validation checklist exists
