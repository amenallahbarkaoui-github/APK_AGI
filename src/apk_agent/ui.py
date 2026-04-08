"""Rich console UI helpers for the chat CLI — v4 with live status bar + token tracking."""

from __future__ import annotations

import threading
import time
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# Custom theme
APK_THEME = Theme({
    "ai": "bold cyan",
    "user": "bold green",
    "tool": "dim yellow",
    "error": "bold red",
    "warning": "bold yellow",
    "success": "bold green",
    "info": "bold blue",
    "hitl": "bold magenta",
    "progress": "bold white",
    "dim": "dim white",
})

console = Console(theme=APK_THEME)


# ---------------------------------------------------------------------------
# Welcome / Startup
# ---------------------------------------------------------------------------

def print_welcome(project_id: str | None = None, apk_name: str | None = None) -> None:
    """Print the welcome banner with project info."""
    banner = Table(show_header=False, show_edge=False, padding=(0, 1), expand=False)
    banner.add_column(style="bold cyan", justify="center")
    banner.add_row("╔════════════════════════════════════════════════════╗")
    banner.add_row("║     🔬 APK Agent v4.0.0 — SOTA Analysis Engine   ║")
    banner.add_row("║     Interactive APK Reverse Engineering           ║")
    banner.add_row("║     72 tools • Taint Analysis • Auto-Bypass      ║")
    banner.add_row("╚════════════════════════════════════════════════════╝")
    console.print(banner)

    if project_id and apk_name:
        console.print(f"  📦 Project: [bold]{project_id}[/]  APK: [bold]{apk_name}[/]")
    console.print()
    console.print("[dim]Modes: normal chat | /orchestrator (parallel sub-agents) | /auto (one-shot)[/]")
    console.print("[dim]Commands: /status /tokens /progress /plan /help[/]")
    console.print("[dim]Type your task (e.g., 'full security audit', 'bypass SSL pinning')[/]")
    console.print()


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------

def print_ai_message(content: str) -> None:
    """Render an AI response as a styled panel with Markdown."""
    try:
        md = Markdown(content)
        console.print(Panel(md, title="🤖 AI Agent", border_style="cyan", padding=(0, 1)))
    except Exception:
        console.print(Panel(content, title="🤖 AI Agent", border_style="cyan", padding=(0, 1)))


def print_tool_output(tool_name: str, content: str, success: bool = True) -> None:
    """Render a tool execution result with smart truncation."""
    icon = "✅" if success else "❌"
    style = "green" if success else "red"
    title = f"{icon} {tool_name}"

    # Smart truncation — preserve start and end
    if len(content) > 3000:
        lines = content.splitlines()
        if len(lines) > 40:
            head = "\n".join(lines[:20])
            tail = "\n".join(lines[-15:])
            content = f"{head}\n\n... ({len(lines) - 35} lines omitted) ...\n\n{tail}"
        else:
            content = content[:3000] + "\n... (truncated)"

    console.print(
        Panel(content, title=title, border_style=style, padding=(0, 1), expand=False)
    )


def print_tool_start(tool_name: str, args_summary: str = "") -> None:
    """Show that a tool is starting execution."""
    args_text = f" ({args_summary})" if args_summary else ""
    console.print(f"  [dim]🔧 Running: [bold]{tool_name}[/]{args_text}...[/]")


# ---------------------------------------------------------------------------
# Live progress listener — prints real-time updates during tool execution
# ---------------------------------------------------------------------------

_last_progress_print: dict[str, float] = {}
_MIN_PRINT_INTERVAL = 1.5  # seconds between progress prints per task


def _live_progress_listener(event: str, task) -> None:
    """Listener registered on ProgressManager to print live updates.

    Prints intermediate progress from long-running tools like
    scan_smali_classes, scan_vulnerabilities, detect_protections, etc.
    Throttled to max one print every 1.5 seconds per task.
    """
    if event != "update":
        return

    detail = task.metadata.get("detail", "")
    if not detail:
        return

    now = time.time()
    last = _last_progress_print.get(task.id, 0)
    if now - last < _MIN_PRINT_INTERVAL:
        return
    _last_progress_print[task.id] = now

    pct = task.progress_pct
    # Build a mini progress bar
    filled = int(pct / 5)  # 20 chars wide
    bar = "█" * filled + "░" * (20 - filled)
    elapsed = task.elapsed

    console.print(
        f"    [dim]⏳ {task.name}: [{bar}] {pct:.0f}% — {detail} ({elapsed:.1f}s)[/]"
    )


def enable_live_progress() -> None:
    """Register the live progress listener on the global progress_manager.

    Call once at CLI startup.
    """
    from apk_agent.progress import progress_manager
    progress_manager.add_listener(_live_progress_listener)


def print_hitl_prompt(prompt_text: str) -> None:
    """Render a human-in-the-loop prompt."""
    # Detect if this is a question from ask_user or a patch approval
    if prompt_text.startswith("❓"):
        title = "❓ Agent Needs Your Input"
    else:
        title = "🔒 Human Review Required"
    console.print(Panel(
        prompt_text,
        title=title,
        border_style="magenta",
        padding=(1, 2),
    ))


def print_user_message(content: str) -> None:
    """Render a user message."""
    console.print(f"\n[bold green]You:[/] {content}")


def print_error(message: str) -> None:
    """Print an error message."""
    console.print(f"[bold red]❌ Error:[/] {message}")


def print_warning(message: str) -> None:
    """Print a warning."""
    console.print(f"[bold yellow]⚠️  Warning:[/] {message}")


def print_success(message: str) -> None:
    """Print a success message."""
    console.print(f"[bold green]✅ {message}[/]")


def print_info(message: str) -> None:
    """Print an info message."""
    console.print(f"[bold blue]ℹ️  {message}[/]")


# ---------------------------------------------------------------------------
# Status & Progress
# ---------------------------------------------------------------------------

def print_status(
    project_id: str,
    apk_name: str,
    status: str,
    current_step: str = "",
) -> None:
    """Print project status."""
    console.print(Panel(
        f"Project: [bold]{project_id}[/]\n"
        f"APK: [bold]{apk_name}[/]\n"
        f"Status: [bold]{status}[/]\n"
        + (f"Current: [bold]{current_step}[/]" if current_step else ""),
        title="📊 Status",
        border_style="blue",
    ))


def print_task_plan(plan: list[dict]) -> None:
    """Display the agent's current task plan in a compact table."""
    if not plan:
        return

    status_icons = {
        "pending": "[dim]⏳[/]",
        "in_progress": "[yellow]🔄[/]",
        "done": "[green]✅[/]",
        "failed": "[red]❌[/]",
        "skipped": "[dim]⏭️[/]",
    }

    table = Table(
        title="📋 Task Plan",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        padding=(0, 1),
    )
    table.add_column("#", style="bold", width=3)
    table.add_column("Task", min_width=30)
    table.add_column("Status", width=14)

    done = 0
    total = len(plan)
    for t in plan:
        tid = str(t.get("id", "?"))
        desc = t.get("desc", t.get("description", "—"))
        status = t.get("status", "pending")
        icon = status_icons.get(status, f"[dim]{status}[/]")
        if status == "done":
            done += 1
            style = "dim green"
        elif status == "in_progress":
            style = "bold yellow"
        elif status == "failed":
            style = "red"
        else:
            style = ""
        table.add_row(tid, f"[{style}]{desc}[/]" if style else desc, icon)

    console.print(table)
    console.print(f"  [dim]Progress: {done}/{total} completed[/]")


def print_progress_summary(summary: dict) -> None:
    """Print a progress summary from the ProgressManager."""
    elapsed = summary.get("elapsed", 0)
    total = summary.get("total", 0)
    completed = summary.get("completed", 0)
    failed = summary.get("failed", 0)
    running = summary.get("running", 0)

    # Build progress table
    table = Table(title="📊 Task Progress", show_header=True, header_style="bold cyan")
    table.add_column("Task", style="white", min_width=25)
    table.add_column("Status", style="white", width=12)
    table.add_column("Time", style="dim", width=8)
    table.add_column("Progress", style="white", width=10)

    status_icons = {
        "pending": "⏳",
        "running": "🔄",
        "success": "✅",
        "failed": "❌",
        "skipped": "⏭️",
        "retrying": "🔁",
    }

    for task in summary.get("tasks", []):
        icon = status_icons.get(task["status"], "?")
        status_style = {
            "success": "green",
            "failed": "red",
            "running": "yellow",
            "retrying": "yellow",
        }.get(task["status"], "dim")

        pct = f"{task['progress_pct']:.0f}%"
        time_str = f"{task['elapsed']:.1f}s" if task["elapsed"] > 0 else "-"
        retry_note = f" (retry {task['retries']})" if task["retries"] > 0 else ""

        table.add_row(
            task["name"],
            f"[{status_style}]{icon} {task['status']}{retry_note}[/]",
            time_str,
            pct,
        )

    console.print(table)
    console.print(
        f"  Overall: {completed}/{total} done | {failed} failed | {running} running | "
        f"Elapsed: {elapsed:.1f}s"
    )


def print_orchestrator_plan(plan: dict) -> None:
    """Display the orchestrator's execution plan."""
    console.print(Panel(
        _format_plan(plan),
        title="🎯 Orchestrator Execution Plan",
        border_style="cyan",
        padding=(1, 2),
    ))


def _format_plan(plan: dict) -> str:
    """Format an orchestrator plan for display."""
    lines = []

    parallel = plan.get("parallel", [])
    sequential = plan.get("sequential", [])

    if parallel:
        lines.append("[bold]Phase 1 — Parallel Execution:[/]")
        for i, task in enumerate(parallel, 1):
            lines.append(f"  {i}. [{task['agent']}] {task['task'][:80]}")
        lines.append("")

    if sequential:
        phase = 2 if parallel else 1
        lines.append(f"[bold]Phase {phase} — Sequential Execution:[/]")
        for i, task in enumerate(sequential, 1):
            lines.append(f"  {i}. [{task['agent']}] {task['task'][:80]}")

    return "\n".join(lines)


def print_sub_agent_result(result: dict) -> None:
    """Display a sub-agent's result."""
    icon = "✅" if result.get("success") else "❌"
    style = "green" if result.get("success") else "red"
    role = result.get("role", "Unknown Agent")
    iterations = result.get("iterations", 0)
    content = result.get("result", "No result")

    if len(content) > 2000:
        content = content[:2000] + "\n... (truncated)"

    try:
        md = Markdown(content)
        display = md
    except Exception:
        display = content

    console.print(Panel(
        display,
        title=f"{icon} {role} ({iterations} steps)",
        border_style=style,
        padding=(0, 1),
    ))


# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

def print_help() -> None:
    """Print help text for available commands."""
    help_text = """
[bold]Available Commands:[/]
  [cyan]/new <apk_path>[/]    — Create a new project from an APK/XAPK file
  [cyan]/open <id>[/]         — Open an existing project by ID
  [cyan]/list[/]               — List all projects
  [cyan]/status[/]             — Show current project status
  [cyan]/tokens[/]             — Show current context token usage
  [cyan]/logs[/]               — Show recent tool logs
  [cyan]/report[/]             — Generate/show the report
  [cyan]/progress[/]           — Show task progress summary
  [cyan]/plan[/]               — Show the agent's current task plan
  [cyan]/auto[/]               — Full auto mode (no confirmations, one-shot deep run)
  [cyan]/orchestrator[/]       — Switch to orchestrator mode (parallel sub-agents)
  [cyan]/normal[/]             — Switch back to normal chat mode
  [cyan]/stop[/]               — Stop the current operation
  [cyan]/help[/]               — Show this help text
  [cyan]/quit[/]               — Exit APK Agent

[bold]Session Commands:[/]
  [cyan]/session[/]            — Show session info (thread ID, messages, tokens)
  [cyan]/compact[/]            — Show compaction status
  [cyan]/reset[/]              — Delete session history (start fresh)

[bold]SOTA Analysis Tools (NEW):[/]
  The agent now has 72 tools including:
  • [cyan]SmaliIndex IR[/]     — Full parsed representation of all smali code
  • [cyan]Unified Scanner[/]   — 36-rule single-pass security scanner
  • [cyan]Taint Analysis[/]    — Source→Sink data flow tracing
  • [cyan]Auto-Bypass[/]       — Smali patches + Frida scripts for 8 protection types
  • [cyan]Manifest Analyzer[/] — Deep semantic analysis with code cross-referencing
  • [cyan]Cloud Scanner[/]     — Firebase/AWS/GCP/Azure credential detection

[bold]Auto Mode:[/]
  In auto mode, patches are auto-approved and agent questions are
  auto-answered. Best for one-shot full analysis runs.

[bold]Orchestrator Mode:[/]
  Complex tasks are broken into sub-tasks for parallel execution.

[bold]Example Tasks:[/]
  • "full security audit of this APK"
  • "bypass SSL pinning statically"
  • "find hardcoded API keys and secrets"
  • "run taint analysis to find data leaks"
  • "scan for cloud misconfigurations"
  • "generate Frida scripts for all protections"
"""
    console.print(Panel(help_text, title="📖 Help", border_style="blue"))


# ---------------------------------------------------------------------------
# Token Usage Tracking
# ---------------------------------------------------------------------------

class TokenTracker:
    """Thread-safe tracker for LLM token usage across the session."""

    def __init__(self):
        self._lock = threading.Lock()
        self.total_prompt_tokens: int = 0
        self.total_completion_tokens: int = 0
        self.total_calls: int = 0
        self.turn_prompt_tokens: int = 0
        self.turn_completion_tokens: int = 0
        self.turn_calls: int = 0
        self.turn_start: float = 0.0
        self._active_tool: str = ""
        self._active_tool_start: float = 0.0

    def start_turn(self) -> None:
        with self._lock:
            self.turn_prompt_tokens = 0
            self.turn_completion_tokens = 0
            self.turn_calls = 0
            self.turn_start = time.time()

    def record_call(self, prompt_tokens: int = 0, completion_tokens: int = 0) -> None:
        with self._lock:
            self.total_prompt_tokens += prompt_tokens
            self.total_completion_tokens += completion_tokens
            self.total_calls += 1
            self.turn_prompt_tokens += prompt_tokens
            self.turn_completion_tokens += completion_tokens
            self.turn_calls += 1

    def set_active_tool(self, name: str) -> None:
        with self._lock:
            self._active_tool = name
            self._active_tool_start = time.time()

    def clear_active_tool(self) -> None:
        with self._lock:
            self._active_tool = ""

    @property
    def active_tool(self) -> str:
        return self._active_tool

    @property
    def active_tool_elapsed(self) -> float:
        if not self._active_tool:
            return 0
        return time.time() - self._active_tool_start

    @property
    def turn_elapsed(self) -> float:
        if not self.turn_start:
            return 0
        return time.time() - self.turn_start

    @property
    def total_tokens(self) -> int:
        return self.total_prompt_tokens + self.total_completion_tokens

    def format_status_line(self) -> str:
        """Build a compact status line for display at the bottom."""
        parts = []
        # Active tool
        if self._active_tool:
            elapsed = self.active_tool_elapsed
            parts.append(f"🔧 {self._active_tool} ({elapsed:.1f}s)")
        # Turn stats
        if self.turn_start:
            turn_t = self.turn_elapsed
            parts.append(f"⏱ {turn_t:.0f}s")
            if self.turn_calls:
                parts.append(f"📡 {self.turn_calls} calls")
        # Total tokens
        if self.total_tokens:
            total_k = self.total_tokens / 1000
            parts.append(f"🪙 {total_k:.1f}k tokens")
        return " │ ".join(parts) if parts else ""


# Global token tracker
token_tracker = TokenTracker()


def print_status_bar() -> None:
    """Print a compact status bar with current token usage and tool state."""
    line = token_tracker.format_status_line()
    if line:
        console.print(f"[dim]─── {line} ───[/]")


def print_turn_summary() -> None:
    """Print a summary at the end of each agent turn."""
    tt = token_tracker
    if not tt.turn_start:
        return

    elapsed = tt.turn_elapsed
    parts = [f"[dim]── Turn: {elapsed:.1f}s"]
    if tt.turn_calls:
        parts.append(f"{tt.turn_calls} LLM calls")
    if tt.turn_prompt_tokens or tt.turn_completion_tokens:
        parts.append(f"{tt.turn_prompt_tokens:,}→{tt.turn_completion_tokens:,} tokens")
    if tt.total_tokens:
        total_k = tt.total_tokens / 1000
        parts.append(f"session total: {total_k:.1f}k")

    # Context usage from compactor
    try:
        from apk_agent.agent.graph import _compactor
        if _compactor and _compactor.last_token_count > 0:
            ctx_pct = (_compactor.last_token_count / _compactor.token_threshold) * 100
            parts.append(f"context: {ctx_pct:.0f}%")
    except Exception:
        pass

    console.print(" │ ".join(parts) + " ──[/]")

