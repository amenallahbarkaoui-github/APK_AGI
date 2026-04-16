"""Rich console UI helpers for the chat CLI — v4 with real-time live status bar."""

from __future__ import annotations

import threading
import time
from typing import Optional

from rich.columns import Columns
from rich.console import Console, Group
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
    if project_id and apk_name:
        console.print(f"  [bold bright_cyan]📦[/] [bold]{apk_name}[/]  [dim]({project_id[:12]}…)[/]")
    console.print()
    console.print("[dim]Modes: normal chat │ /orchestrator (parallel) │ /auto (one-shot) │ /thinking (toggle reasoning)[/]")
    console.print("[dim]Commands: /status /tokens /progress /plan /session /help[/]")
    console.print("[dim]Type your task (e.g., 'full security audit', 'bypass SSL pinning')[/]")
    console.print()


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------

def print_ai_message(content: str) -> None:
    """Render an AI response as a styled panel with Markdown."""
    try:
        md = Markdown(content)
        console.print(Panel(md, title="[bold bright_cyan]🤖 AI Agent[/]", border_style="bright_cyan", padding=(0, 1)))
    except Exception:
        console.print(Panel(content, title="[bold bright_cyan]🤖 AI Agent[/]", border_style="bright_cyan", padding=(0, 1)))


def print_tool_output(tool_name: str, content: str, success: bool = True) -> None:
    """Render a tool execution result with smart truncation."""
    icon = "✅" if success else "❌"
    style = "green" if success else "red"
    title = f"{icon} {tool_name}"

    # Smart truncation — preserve start and end for context
    if len(content) > 3000:
        lines = content.splitlines()
        if len(lines) > 40:
            head = "\n".join(lines[:18])
            tail = "\n".join(lines[-12:])
            omitted = len(lines) - 30
            content = f"{head}\n\n[dim]  ··· {omitted} lines omitted ···[/dim]\n\n{tail}"
        else:
            content = content[:2800] + "\n[dim]  ··· truncated ···[/dim]"

    console.print(
        Panel(content, title=title, border_style=style, padding=(0, 1), expand=False)
    )


def print_tool_start(tool_name: str, args_summary: str = "") -> None:
    """Show that a tool is starting execution — compact inline format."""
    args_text = f" [dim]({args_summary})[/]" if args_summary else ""
    console.print(f"  [dim]🔧[/] [bold dim]{tool_name}[/]{args_text}[dim]...[/]")


# ---------------------------------------------------------------------------
# Real-time Live Status Bar — always-visible at bottom during agent turns
# ---------------------------------------------------------------------------


class TokenTracker:
    """Thread-safe tracker for LLM token usage across the session."""

    def __init__(self):
        self._lock = threading.Lock()
        self.total_prompt_tokens: int = 0
        self.total_completion_tokens: int = 0
        self.total_cached_tokens: int = 0
        self.total_calls: int = 0
        self.turn_prompt_tokens: int = 0
        self.turn_completion_tokens: int = 0
        self.turn_cached_tokens: int = 0
        self.turn_calls: int = 0
        self.turn_start: float = 0.0
        self._active_tool: str = ""
        self._active_tool_start: float = 0.0
        self._tool_progress_pct: float = 0.0
        self._tool_progress_detail: str = ""
        self._tools_completed_this_turn: int = 0
        self._last_tool_completed: str = ""

    def start_turn(self) -> None:
        with self._lock:
            self.turn_prompt_tokens = 0
            self.turn_completion_tokens = 0
            self.turn_cached_tokens = 0
            self.turn_calls = 0
            self.turn_start = time.time()
            self._tools_completed_this_turn = 0
            self._last_tool_completed = ""

    def record_call(self, prompt_tokens: int = 0, completion_tokens: int = 0, cached_tokens: int = 0) -> None:
        with self._lock:
            self.total_prompt_tokens += prompt_tokens
            self.total_completion_tokens += completion_tokens
            self.total_cached_tokens += cached_tokens
            self.total_calls += 1
            self.turn_prompt_tokens += prompt_tokens
            self.turn_completion_tokens += completion_tokens
            self.turn_cached_tokens += cached_tokens
            self.turn_calls += 1

    def set_active_tool(self, name: str) -> None:
        with self._lock:
            self._active_tool = name
            self._active_tool_start = time.time()
            self._tool_progress_pct = 0.0
            self._tool_progress_detail = ""

    def update_tool_progress(self, pct: float, detail: str = "") -> None:
        with self._lock:
            self._tool_progress_pct = pct
            if detail:
                self._tool_progress_detail = detail

    def clear_active_tool(self) -> None:
        with self._lock:
            if self._active_tool:
                self._last_tool_completed = self._active_tool
                self._tools_completed_this_turn += 1
            self._active_tool = ""
            self._tool_progress_pct = 0.0
            self._tool_progress_detail = ""

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


# Global token tracker
token_tracker = TokenTracker()


class LiveStatusBar:
    """A real-time status bar rendered at the bottom of the terminal.

    Uses Rich Live display to continuously update a compact bar showing:
    - Active tool name + spinner + elapsed time
    - Tool progress bar (when tools report progress)
    - Turn elapsed time + LLM call count
    - Session token usage
    - Context window usage %

    The bar appears automatically when a tool starts and stays visible
    throughout the agent turn, refreshing every 0.3s.
    """

    def __init__(self):
        self._live: Live | None = None
        self._active = False
        self._lock = threading.Lock()
        self._spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self._frame_idx = 0

    def start(self) -> None:
        """Start the live status bar display."""
        with self._lock:
            if self._active:
                return
            self._active = True
            self._live = Live(
                self,
                console=console,
                refresh_per_second=4,
                transient=True,  # bar disappears when stopped — clean output
            )
            self._live.start()

    def stop(self) -> None:
        """Stop the live status bar."""
        with self._lock:
            if not self._active:
                return
            self._active = False
            if self._live:
                try:
                    self._live.stop()
                except Exception:
                    pass
                self._live = None

    def update(self) -> None:
        """Force a refresh of the status bar content."""
        with self._lock:
            if self._active and self._live:
                try:
                    self._live.refresh()
                except Exception:
                    pass

    def __rich_console__(self, console, options):
        """Rich protocol — called by Live's background thread on every refresh tick."""
        yield self._render()

    def _render(self) -> Text:
        """Build the status bar content as a Rich Text object."""
        tt = token_tracker
        self._frame_idx = (self._frame_idx + 1) % len(self._spinner_frames)
        spinner = self._spinner_frames[self._frame_idx]

        parts: list[str] = []

        # ── Active tool with spinner + progress ──
        if tt._active_tool:
            elapsed = tt.active_tool_elapsed
            tool_str = f"{spinner} [bold cyan]{tt._active_tool}[/bold cyan]"
            if tt._tool_progress_pct > 0:
                pct = tt._tool_progress_pct
                bar_width = 15
                filled = int(pct / 100 * bar_width)
                bar = "━" * filled + "[dim]━[/dim]" * (bar_width - filled)
                tool_str += f" [{bar}] {pct:.0f}%"
            tool_str += f" {elapsed:.1f}s"
            if tt._tool_progress_detail:
                detail = tt._tool_progress_detail
                if len(detail) > 40:
                    detail = detail[:37] + "..."
                tool_str += f" [dim]│ {detail}[/dim]"
            parts.append(tool_str)
        elif tt._tools_completed_this_turn > 0:
            parts.append(f"[green]✓[/green] {tt._tools_completed_this_turn} tools done")

        # ── Turn timing ──
        if tt.turn_start:
            turn_t = tt.turn_elapsed
            parts.append(f"[dim]⏱[/dim] {turn_t:.0f}s")

        # ── LLM calls this turn ──
        if tt.turn_calls:
            parts.append(f"[dim]📡[/dim] {tt.turn_calls}")

        # ── Token usage ──
        if tt.total_tokens:
            in_k = tt.turn_prompt_tokens / 1000
            out_k = tt.turn_completion_tokens / 1000
            token_str = f"[dim]🪙[/dim] ↑{in_k:.1f}k ↓{out_k:.1f}k"
            if tt.total_calls > 1:
                total_k = tt.total_tokens / 1000
                token_str += f" [dim]Σ{total_k:.0f}k[/dim]"
            if tt.turn_cached_tokens > 0:
                cache_pct = (tt.turn_cached_tokens / max(tt.turn_prompt_tokens, 1)) * 100
                token_str += f" [green]⚡{cache_pct:.0f}%cache[/green]"
            parts.append(token_str)

        # ── Context window % ──
        try:
            from apk_agent.agent.graph import _compactor
            if _compactor and _compactor.last_token_count > 0:
                ctx_pct = (_compactor.last_token_count / _compactor.token_threshold) * 100
                if ctx_pct < 60:
                    color = "green"
                elif ctx_pct < 85:
                    color = "yellow"
                else:
                    color = "red"
                parts.append(f"[{color}]ctx {ctx_pct:.0f}%[/{color}]")
        except Exception:
            pass

        if not parts:
            return Text("")

        separator = " │ "
        line = separator.join(parts)
        return Text.from_markup(f"[dim]───[/dim] {line} [dim]───[/dim]")

    @property
    def is_active(self) -> bool:
        return self._active


# Global live status bar
live_bar = LiveStatusBar()


def _live_progress_listener(event: str, task) -> None:
    """Listener on ProgressManager — feeds tool progress into the live bar.

    Replaces old print-based listener. Now updates the token_tracker's
    tool progress and triggers a bar refresh.
    """
    if event == "start":
        token_tracker.set_active_tool(task.name)
        live_bar.update()
    elif event == "update":
        pct = task.progress_pct
        detail = task.metadata.get("detail", "")
        token_tracker.update_tool_progress(pct, detail)
        live_bar.update()
    elif event == "complete":
        token_tracker.clear_active_tool()
        live_bar.update()


def enable_live_progress() -> None:
    """Register the live progress listener on the global progress_manager.

    Call once at CLI startup.
    """
    from apk_agent.progress import progress_manager
    progress_manager.add_listener(_live_progress_listener)


def print_hitl_prompt(prompt_text: str) -> None:
    """Render a human-in-the-loop prompt with distinct styling."""
    if prompt_text.startswith("❓"):
        title = "❓ Agent Needs Your Input"
        style = "bright_magenta"
    else:
        title = "🔒 Human Review Required"
        style = "yellow"
    console.print(Panel(
        prompt_text,
        title=f"[bold]{title}[/]",
        border_style=style,
        padding=(1, 2),
    ))


def print_user_message(content: str) -> None:
    """Render a user message."""
    console.print(f"\n[bold green]▶ You:[/] {content}")


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
[bold cyan]━━━ Project ━━━[/]
  [cyan]/new <apk_path>[/]    — Create a new project from an APK/XAPK file
  [cyan]/open <id>[/]         — Open an existing project by ID
  [cyan]/list[/]               — List all projects

[bold cyan]━━━ Info ━━━[/]
  [cyan]/status[/]             — Show current project status
  [cyan]/session[/]            — Show session info (thread ID, messages, tokens)
  [cyan]/tokens[/]             — Show current context & token usage
  [cyan]/logs[/]               — Show recent tool logs
  [cyan]/report[/]             — Show the generated report
  [cyan]/progress[/]           — Show task progress summary
  [cyan]/plan[/]               — Show the agent's current task plan

[bold cyan]━━━ Modes ━━━[/]
  [cyan]/thinking[/]           — Toggle LLM deep thinking/reasoning mode [bold](🧠)[/]
  [cyan]/auto[/]               — Toggle auto mode (no confirmations, one-shot)
  [cyan]/orchestrator[/]       — Switch to orchestrator mode (parallel sub-agents)
  [cyan]/normal[/]             — Switch back to normal chat mode

[bold cyan]━━━ Control ━━━[/]
  [cyan]/compact[/]            — Show compaction status
  [cyan]/reset[/]              — Delete session history (start fresh)
  [cyan]/stop[/]               — Stop the current operation
  [cyan]/quit[/]               — Exit APK Agent

[bold cyan]━━━ CLI Flags ━━━[/]
  [dim]--thinking / --no-thinking[/]  — Enable/disable thinking at launch
  [dim]--model / -m MODEL[/]         — Override LLM model name
  [dim]--auto[/]                      — Start in auto mode
  [dim]--verbose / -v[/]             — Enable debug logging

[bold]SOTA Analysis Tools:[/]
  [dim]SmaliIndex IR · Unified Scanner · Taint Analysis · Auto-Bypass
  Manifest Analyzer · Cloud Scanner · Code Graph · 72 tools total[/]

[bold]Example Tasks:[/]
  • [dim]"full security audit of this APK"[/]
  • [dim]"bypass SSL pinning statically"[/]
  • [dim]"find hardcoded API keys and secrets"[/]
  • [dim]"run taint analysis to find data leaks"[/]
"""
    console.print(Panel(help_text.strip(), title="📖 Help", border_style="bright_cyan", padding=(0, 1)))


# ---------------------------------------------------------------------------
# Print helpers that use the new TokenTracker / LiveStatusBar
# ---------------------------------------------------------------------------


def print_status_bar() -> None:
    """Print a one-shot snapshot of the current token/tool state.

    For the `/tokens` command — NOT the persistent bar.
    """
    tt = token_tracker
    table = Table(
        title="🪙 Token Usage",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        padding=(0, 1),
    )
    table.add_column("Metric", style="bold")
    table.add_column("This Turn", justify="right")
    table.add_column("Session", justify="right")

    table.add_row(
        "Prompt tokens",
        f"{tt.turn_prompt_tokens:,}",
        f"{tt.total_prompt_tokens:,}",
    )
    table.add_row(
        "Completion tokens",
        f"{tt.turn_completion_tokens:,}",
        f"{tt.total_completion_tokens:,}",
    )
    table.add_row(
        "Total tokens",
        f"{tt.turn_prompt_tokens + tt.turn_completion_tokens:,}",
        f"{tt.total_tokens:,}",
    )
    table.add_row(
        "LLM calls",
        str(tt.turn_calls),
        str(tt.total_calls),
    )
    table.add_row(
        "Cached tokens",
        f"{tt.turn_cached_tokens:,}",
        f"{tt.total_cached_tokens:,}",
    )
    if tt.total_cached_tokens > 0:
        save_pct = (tt.total_cached_tokens / max(tt.total_prompt_tokens, 1)) * 100
        table.add_row(
            "Cache hit rate",
            "",
            f"[green]⚡ {save_pct:.0f}%[/green]",
        )

    console.print(table)

    # Context window
    try:
        from apk_agent.agent.graph import _compactor
        if _compactor and _compactor.last_token_count > 0:
            ctx_pct = (_compactor.last_token_count / _compactor.token_threshold) * 100
            bar_w = 30
            filled = int(ctx_pct / 100 * bar_w)
            color = "green" if ctx_pct < 60 else ("yellow" if ctx_pct < 85 else "red")
            bar_str = f"[{color}]{'━' * filled}[/{color}][dim]{'━' * (bar_w - filled)}[/dim]"
            console.print(
                f"  Context window: [{bar_str}] [{color}]{ctx_pct:.0f}%[/{color}]"
            )
    except Exception:
        pass


def print_turn_summary() -> None:
    """Print a compact summary line at the end of an agent turn."""
    tt = token_tracker
    if not tt.turn_start:
        return

    elapsed = tt.turn_elapsed
    parts = []
    parts.append(f"{elapsed:.1f}s")
    if tt.turn_calls:
        parts.append(f"{tt.turn_calls} calls")
    if tt.turn_prompt_tokens or tt.turn_completion_tokens:
        in_k = tt.turn_prompt_tokens / 1000
        out_k = tt.turn_completion_tokens / 1000
        parts.append(f"↑{in_k:.1f}k ↓{out_k:.1f}k")
    if tt.turn_cached_tokens:
        cache_pct = (tt.turn_cached_tokens / max(tt.turn_prompt_tokens, 1)) * 100
        parts.append(f"⚡{cache_pct:.0f}%")
    if tt._tools_completed_this_turn:
        parts.append(f"{tt._tools_completed_this_turn} tools")

    # Context usage
    try:
        from apk_agent.agent.graph import _compactor
        if _compactor and _compactor.last_token_count > 0:
            ctx_pct = (_compactor.last_token_count / _compactor.token_threshold) * 100
            color = "green" if ctx_pct < 60 else ("yellow" if ctx_pct < 85 else "red")
            parts.append(f"[{color}]ctx {ctx_pct:.0f}%[/{color}]")
    except Exception:
        pass

    if tt.total_tokens:
        total_k = tt.total_tokens / 1000
        parts.append(f"Σ{total_k:.1f}k")

    separator = " │ "
    console.print(f"[dim]╰── {separator.join(parts)} ──╯[/]")

