"""Rich console UI helpers for the chat CLI — v4 with real-time live status bar."""

from __future__ import annotations

import threading
import time
from typing import Optional

from rich.columns import Columns
from rich.console import Console, Group
from rich.live import Live
from rich.markdown import Markdown
from rich.markup import escape as _escape_markup
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
    console.print("[dim]Modes: normal chat │ /orchestrator (parallel) │ /auto (one-shot) │ /human (step-by-step)[/]")
    console.print("[dim]Commands: /dashboard /findings /patches /tools /status /session /tokens /help[/]")
    console.print("[dim]More: /progress /plan /report /logs /context[/]")
    console.print("[dim]Type your task (e.g., 'full security audit', 'bypass premium', 'remove ads')[/]")
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


def print_thinking(content: str) -> None:
    """Render model reasoning/thinking in a blue panel."""
    try:
        md = Markdown(content)
        console.print(Panel(md, title="[bold bright_blue]💭 Thinking[/]", border_style="bright_blue", padding=(0, 1)))
    except Exception:
        console.print(Panel(content, title="[bold bright_blue]💭 Thinking[/]", border_style="bright_blue", padding=(0, 1)))


def print_tool_output(tool_name: str, content: str, success: bool = True) -> None:
    """Render a tool execution result with smart truncation and severity coloring."""
    icon = "✅" if success else "❌"

    # Auto-detect severity/importance from content
    content_lower = content[:500].lower()
    if not success:
        style = "red"
    elif '"verdict": "fail"' in content_lower or '"remaining_gates"' in content_lower:
        style = "yellow"
        icon = "⚠️ "
    elif '"verdict": "pass"' in content_lower:
        style = "bright_green"
        icon = "✅"
    elif any(k in content_lower for k in ('"critical"', '"severity": "high"')):
        style = "bright_red"
    elif tool_name in ("verify_bypass_completeness", "batch_patch_methods"):
        style = "bright_cyan"
    else:
        style = "green"

    title = f"{icon} {tool_name}"

    # Escape Rich markup in tool output (smali text has [/;] etc.)
    content = _escape_markup(content)

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
        self._active_tool_names: list[str] = []
        self._active_tool_start: float = 0.0
        self._running_tools: int = 0
        self._tool_progress_pct: float = 0.0
        self._tool_progress_detail: str = ""
        self._tools_completed_this_turn: int = 0
        self._last_tool_completed: str = ""
        self._completed_tool_names: list[str] = []
        self._agent_phase: str = ""
        self._agent_phase_start: float = 0.0

    def start_turn(self) -> None:
        with self._lock:
            self.turn_prompt_tokens = 0
            self.turn_completion_tokens = 0
            self.turn_cached_tokens = 0
            self.turn_calls = 0
            self.turn_start = time.time()
            self._active_tool = ""
            self._active_tool_names = []
            self._active_tool_start = 0.0
            self._running_tools = 0
            self._tool_progress_pct = 0.0
            self._tool_progress_detail = ""
            self._tools_completed_this_turn = 0
            self._last_tool_completed = ""
            self._completed_tool_names = []
            self._agent_phase = ""
            self._agent_phase_start = 0.0

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
            normalized = str(name or "").strip()
            if not normalized:
                return
            if normalized not in self._active_tool_names:
                self._active_tool_names.append(normalized)
            label = normalized if len(self._active_tool_names) == 1 else f"{len(self._active_tool_names)} tools running"
            if self._active_tool != label:
                self._active_tool_start = time.time()
            self._active_tool = label
            if self._running_tools <= 0:
                self._running_tools = len(self._active_tool_names) or 1
            self._tool_progress_pct = 0.0
            self._tool_progress_detail = ""
            self._agent_phase = ""
            self._agent_phase_start = 0.0

    def sync_running_tools(self, names: list[str]) -> None:
        with self._lock:
            active_names = [str(name) for name in names if str(name).strip()]
            self._active_tool_names = active_names
            self._running_tools = len(active_names)
            if not active_names:
                self._active_tool = ""
                self._active_tool_start = 0.0
                self._tool_progress_pct = 0.0
                self._tool_progress_detail = ""
                return

            label = active_names[0] if len(active_names) == 1 else f"{len(active_names)} tools running"
            if self._active_tool != label:
                self._active_tool_start = time.time()
                if len(active_names) > 1:
                    self._tool_progress_pct = 0.0
                    self._tool_progress_detail = ""
            self._active_tool = label
            self._agent_phase = ""
            self._agent_phase_start = 0.0

    def update_tool_progress(self, pct: float, detail: str = "") -> None:
        with self._lock:
            self._tool_progress_pct = pct
            if detail:
                self._tool_progress_detail = detail

    def clear_active_tool(self, completed_name: str = "") -> None:
        with self._lock:
            completed_label = completed_name.strip()
            if completed_label:
                self._last_tool_completed = completed_label
                self._tools_completed_this_turn += 1
                self._active_tool_names = [name for name in self._active_tool_names if name != completed_label]
                if completed_label not in self._completed_tool_names:
                    self._completed_tool_names.append(completed_label)
                    self._completed_tool_names = self._completed_tool_names[-6:]
            elif self._active_tool and not self._active_tool.endswith("tools running"):
                self._last_tool_completed = self._active_tool
                self._tools_completed_this_turn += 1
            if self._running_tools > 0:
                self._running_tools -= 1
            if self._active_tool_names:
                self._active_tool = self._active_tool_names[0] if len(self._active_tool_names) == 1 else f"{len(self._active_tool_names)} tools running"
            else:
                self._active_tool = ""
            self._active_tool_start = 0.0
            self._tool_progress_pct = 0.0
            self._tool_progress_detail = ""

    def set_agent_phase(self, label: str) -> None:
        normalized = str(label or "").strip()
        with self._lock:
            if not normalized:
                self._agent_phase = ""
                self._agent_phase_start = 0.0
                return
            if self._agent_phase != normalized:
                self._agent_phase_start = time.time()
            self._agent_phase = normalized

    def clear_agent_phase(self) -> None:
        with self._lock:
            self._agent_phase = ""
            self._agent_phase_start = 0.0

    @property
    def active_tool(self) -> str:
        return self._active_tool

    @property
    def active_tool_elapsed(self) -> float:
        if not self._active_tool:
            return 0
        return time.time() - self._active_tool_start

    @property
    def agent_phase_elapsed(self) -> float:
        if not self._agent_phase or not self._agent_phase_start:
            return 0
        return time.time() - self._agent_phase_start

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
        if tt._active_tool_names:
            elapsed = tt.active_tool_elapsed
            if len(tt._active_tool_names) == 1:
                tool_label = tt._active_tool_names[0]
            else:
                names = tt._active_tool_names[:4]
                suffix = "" if len(tt._active_tool_names) <= 4 else f", +{len(tt._active_tool_names) - 4} more"
                tool_label = f"{len(tt._active_tool_names)} tools: {', '.join(names)}{suffix}"
            tool_str = f"{spinner} [bold cyan]{tool_label}[/bold cyan]"
            if tt._tool_progress_pct > 0 and len(tt._active_tool_names) <= 1:
                pct = tt._tool_progress_pct
                bar_width = 15
                filled = int(pct / 100 * bar_width)
                bar = "━" * filled + "[dim]━[/dim]" * (bar_width - filled)
                tool_str += f" [{bar}] {pct:.0f}%"
            tool_str += f" {elapsed:.1f}s"
            if tt._tool_progress_detail and len(tt._active_tool_names) <= 1:
                detail = tt._tool_progress_detail
                if len(detail) > 40:
                    detail = detail[:37] + "..."
                tool_str += f" [dim]│ {detail}[/dim]"
            parts.append(tool_str)
        elif tt._agent_phase:
            parts.append(
                f"{spinner} [bold blue]{tt._agent_phase}[/bold blue] {tt.agent_phase_elapsed:.1f}s"
            )

        if tt._completed_tool_names:
            done_names = tt._completed_tool_names[-4:]
            suffix = "" if tt._tools_completed_this_turn <= 4 else f", +{tt._tools_completed_this_turn - 4} more"
            parts.append(f"[green]✓[/green] done: {', '.join(done_names)}{suffix}")
        elif tt._tools_completed_this_turn > 0:
            parts.append(f"[green]✓[/green] {tt._tools_completed_this_turn} tools done")

        # ── Turn timing ──
        if tt.turn_start:
            turn_t = tt.turn_elapsed
            parts.append(f"[dim]⏱ turn[/dim] {turn_t:.0f}s")

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
    from apk_agent.progress import progress_manager

    active_names = [t.name for t in progress_manager.get_active_tasks()]

    if event == "start":
        token_tracker.sync_running_tools(active_names or [task.name])
        live_bar.update()
    elif event == "update":
        token_tracker.sync_running_tools(active_names or [task.name])
        pct = task.progress_pct
        detail = task.metadata.get("detail", "")
        token_tracker.update_tool_progress(pct, detail)
        live_bar.update()
    elif event == "complete":
        token_tracker.clear_active_tool(task.name)
        token_tracker.sync_running_tools(active_names)
        if not active_names:
            token_tracker.set_agent_phase("processing tool results")
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
    console.print(f"\n[bold green]▶ You:[/] {_escape_markup(content)}")


def print_error(message: str) -> None:
    """Print an error message."""
    console.print(f"[bold red]❌ Error:[/] {_escape_markup(message)}")


def print_warning(message: str) -> None:
    """Print a warning."""
    console.print(f"[bold yellow]⚠️  Warning:[/] {_escape_markup(message)}")


def print_success(message: str) -> None:
    """Print a success message."""
    console.print(f"[bold green]✅ {_escape_markup(message)}[/]")


def print_info(message: str) -> None:
    """Print an info message."""
    console.print(f"[bold blue]ℹ️  {_escape_markup(message)}[/]")


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
    # Get actual tool count
    try:
        from apk_agent.agent.tools_def import ALL_TOOLS
        tool_count = str(len(ALL_TOOLS))
    except Exception:
        tool_count = "90"

    help_text = f"""
[bold cyan]━━━ Project ━━━[/]
    [cyan]/new <apk_path>[/]    — Create another project from an APK/XAPK file
  [cyan]/list[/]               — List all projects
    [dim]Open an existing project:[/] restart with [cyan]--project <id>[/]

[bold cyan]━━━ Dashboard & Info ━━━[/]
  [cyan]/dashboard[/]          — Full overview: findings, patches, context, progress
  [cyan]/findings[/]           — List all findings with severity highlighting
  [cyan]/patches[/]            — List all patches with status & coverage
  [cyan]/tools[/]              — Show all {tool_count} tools grouped by category
  [cyan]/status[/]             — Show current project status
  [cyan]/session[/]            — Show session info (thread ID, messages, tokens)
  [cyan]/tokens[/]             — Show current context & token usage
  [cyan]/logs[/]               — Show recent tool logs
  [cyan]/report[/]             — Show the generated report
  [cyan]/progress[/]           — Show task progress summary
  [cyan]/plan[/]               — Show the agent's current task plan

[bold cyan]━━━ Modes ━━━[/]
  [cyan]/auto[/]               — Toggle auto mode (no confirmations, one-shot)
  [cyan]/human[/]              — Toggle Human Thinking mode (you guide each step)
  [cyan]/orchestrator[/]       — Switch to orchestrator mode (parallel sub-agents)
  [cyan]/normal[/]             — Switch back to normal chat mode

[bold cyan]━━━ Control ━━━[/]
  [cyan]/context[/]            — View/set context window (e.g. /context 1000000)
  [cyan]/compact[/]            — Show compaction status
  [cyan]/reset[/]              — Delete session history (start fresh)
  [cyan]/stop[/]               — Stop the current operation
  [cyan]/quit[/]               — Exit APK Agent

[bold cyan]━━━ CLI Flags ━━━[/]
    [dim]--project / -p ID[/]         — Start directly in an existing project
  [dim]--model / -m MODEL[/]         — Override LLM model name
  [dim]--context-window / -c N[/]    — Set context window in tokens (0=auto)
    [dim]--telegram / --no-telegram[/] — Start/skip the Telegram bridge
  [dim]--auto[/]                      — Start in auto mode
  [dim]--verbose / -v[/]             — Enable debug logging

[bold]SOTA Analysis ({tool_count} tools):[/]
  [dim]SmaliIndex IR · Code Graph · Taint Analysis · Auto-Bypass · Deobfuscation
  Cross-Reference · Dynamic Checks · URL Extraction · Bypass Verification
  Deep Injection · Batch Patching · UI Gate Mapping · Cloud Scanner[/]

[bold]Example Tasks:[/]
  • [dim]"full security audit of this APK"[/]
  • [dim]"bypass premium — unlock all features"[/]
  • [dim]"find hardcoded API keys and secrets"[/]
  • [dim]"run taint analysis to find data leaks"[/]
  • [dim]"remove all ads and tracking"[/]
"""
    console.print(Panel(help_text.strip(), title="📖 Help", border_style="bright_cyan", padding=(0, 1)))


_TOOL_CATEGORY_ORDER = [
    "Planning & Memory",
    "Decompilation & Build",
    "Manifest & Components",
    "Smali Analysis",
    "Graph, Index & Architecture",
    "Search & Discovery",
    "Security & Scanning",
    "Feature & Bypass",
    "Deep Tracing & Injection",
    "File & Evidence",
    "Patching & Validation",
    "Other & Unsorted",
]

_TOOL_CATEGORY_ICONS = {
    "Planning & Memory": "🧠",
    "Decompilation & Build": "🔨",
    "Manifest & Components": "📋",
    "Smali Analysis": "🔬",
    "Graph, Index & Architecture": "🕸️ ",
    "Search & Discovery": "🔍",
    "Security & Scanning": "🛡️ ",
    "Feature & Bypass": "🔓",
    "Deep Tracing & Injection": "💉",
    "File & Evidence": "📁",
    "Patching & Validation": "🩹",
    "Other & Unsorted": "📦",
}


def _categorize_tool_name(name: str) -> str:
    if name in {"update_task_plan", "edit_task_plan", "mark_task_done", "update_scratchpad"}:
        return "Planning & Memory"
    if name in {"apktool_decompile", "jadx_decompile", "dex2jar_convert", "aapt2_dump", "apktool_build", "zipalign_apk_tool", "sign_apk"}:
        return "Decompilation & Build"
    if name in {
        "parse_manifest", "identify_app_packages", "analyze_attack_surface", "analyze_network_config",
        "rename_package_identity", "find_resource_colors", "find_resource_styles", "replace_resource_colors",
        "list_resource_drawables", "analyze_native_libs", "analyze_native_re_core", "analyze_manifest_deep",
        "score_permissions", "analyze_certificate",
    }:
        return "Manifest & Components"
    if name in {
        "scan_smali_classes", "analyze_smali_class", "find_string_decryption_patterns", "find_method_xrefs",
        "analyze_method_deep", "detect_protections", "trace_call_chain", "reconstruct_strings",
    }:
        return "Smali Analysis"
    if name.startswith("graph_") or name.startswith("index_") or name in {
        "build_graph_and_index", "build_smali_index", "smali_index_stats", "semantic_method_slice",
        "find_enforcement_surfaces", "map_semantic_architecture", "recover_hidden_state_model",
        "profile_guard_and_revalidation_surface", "build_app_knowledge_pack", "summarize_app_knowledge",
        "query_app_knowledge", "build_behavior_graph", "summarize_behavior_graph", "query_behavior_graph",
        "recover_state_transitions", "map_security_surfaces", "analyze_network_behavior",
        "recover_semantic_symbols", "build_dart_aot_index",
    }:
        return "Graph, Index & Architecture"
    if name in {
        "context_search", "multi_search", "xref_search", "directory_overview", "refine_search",
        "batch_read_smali_methods", "smart_search", "extract_strings", "search_in_code", "search_interceptors",
        "search_native_code", "search_dynamic_loaders", "route_reverse_engineering_workflow", "find_entry_points",
        "map_hierarchy", "analyze_shared_prefs", "extract_native_strings", "scan_assets_secrets", "search_binary_strings",
        "analyze_dart_aot", "locate_dart_aot_candidates", "plan_native_patch_targets",
    }:
        return "Search & Discovery"
    if name in {
        "scan_vulnerabilities", "list_vuln_patterns", "unified_scan", "get_threat_model", "analyze_data_flow",
        "run_taint_analysis", "find_hardcoded_crypto", "scan_cloud_secrets",
    }:
        return "Security & Scanning"
    if name in {
        "map_feature_checks", "analyze_subscription_model", "auto_patch_bypass", "patch_flutter_ssl",
        "inject_network_security_config", "patch_manifest_security", "remove_ads", "list_bypass_categories",
        "generate_bypass_plans", "locate_feature_controls", "discover_entity_classes", "detect_gate_chain",
        "trace_field_writers", "validate_patch_completeness", "smart_entity_patch", "frida_script_generator",
        "diff_apk_variants",
    }:
        return "Feature & Bypass"
    if name in {
        "trace_field_access", "find_class_instantiations", "inject_smali_code", "generate_constructor_override",
        "inject_startup_hook", "batch_patch_methods", "trace_data_pipeline", "map_ui_gates",
        "patch_shared_prefs_reads", "identify_server_checks", "cross_reference_map", "deobfuscate_names",
        "find_dynamic_checks", "extract_all_urls", "verify_bypass_completeness", "plan_runtime_hooks",
        "plan_runtime_menu_workflow", "draft_runtime_menu_from_hooks", "inject_runtime_menu_scaffold",
        "configure_runtime_menu_manifest", "inject_runtime_override_layer",
    }:
        return "Deep Tracing & Injection"
    if name in {
        "read_file", "write_file", "list_files", "save_evidence", "load_evidence", "search_evidence",
        "get_evidence_summary", "generate_report",
    }:
        return "File & Evidence"
    if name in {
        "validate_patch", "diff_patched_file", "apply_text_patch", "preview_text_patch", "apply_smali_patch",
        "preview_smali_patch", "restore_smali_backup", "patch_binary_hex", "patch_binary_strings",
        "patch_api_response_flow", "validate_patch_pipeline", "generate_runtime_validation_plan",
        "preview_dart_aot_patch", "apply_dart_aot_patch", "validate_dart_aot_patch",
    }:
        return "Patching & Validation"
    return "Other & Unsorted"


def _build_tool_categories(tool_names: list[str]) -> dict[str, list[str]]:
    categories = {category: [] for category in _TOOL_CATEGORY_ORDER}
    for name in tool_names:
        categories[_categorize_tool_name(name)].append(name)
    return categories


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


# ---------------------------------------------------------------------------
# Dashboard — rich multi-panel overview
# ---------------------------------------------------------------------------


def print_dashboard(state: dict | None = None) -> None:
    """Print a rich multi-panel dashboard showing overall analysis state.

    Args:
        state: The agent's current state dict (from graph checkpoint).
    """
    if not state:
        console.print("[dim]No state available. Run an analysis first.[/]")
        return

    findings = state.get("findings") or []
    patches = state.get("patch_results") or []
    patch_registry = state.get("patch_registry") or []
    task_plan = state.get("task_plan") or []
    scratchpad = state.get("scratchpad") or {}
    graph_ready = state.get("graph_ready", False)
    target_pkgs = state.get("target_packages") or []

    # ── Findings summary panel ──
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    findings_lines = []
    colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}
    icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "ℹ️ "}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = severity_counts[sev]
        if count > 0:
            findings_lines.append(f"  {icons[sev]} [{colors[sev]}]{sev}: {count}[/{colors[sev]}]")
    if not findings_lines:
        findings_lines.append("  [dim]No findings yet[/]")

    findings_panel = Panel(
        "\n".join(findings_lines),
        title=f"[bold]🔍 Findings ({len(findings)})[/]",
        border_style="cyan",
        padding=(0, 1),
    )

    # ── Patches summary panel ──
    patch_ok = sum(1 for p in patches if p.get("success"))
    patch_fail = sum(1 for p in patches if not p.get("success"))
    reg_status = {"applied": 0, "verified": 0, "failed": 0, "user_rejected": 0}
    for r in patch_registry:
        st = r.get("status", "unknown")
        reg_status[st] = reg_status.get(st, 0) + 1

    patch_lines = []
    if patches:
        patch_lines.append(f"  [green]✅ {patch_ok} applied[/]  [red]❌ {patch_fail} failed[/]")
    if reg_status.get("verified"):
        patch_lines.append(f"  [bold green]✔️  {reg_status['verified']} verified[/]")
    if reg_status.get("user_rejected"):
        patch_lines.append(f"  [yellow]🔄 {reg_status['user_rejected']} user rejected[/]")
    if not patch_lines:
        patch_lines.append("  [dim]No patches yet[/]")

    patches_panel = Panel(
        "\n".join(patch_lines),
        title=f"[bold]🔧 Patches ({len(patches)})[/]",
        border_style="green",
        padding=(0, 1),
    )

    # ── Progress panel ──
    progress_lines = []
    if task_plan:
        done = sum(1 for t in task_plan if t.get("status") == "done")
        total = len(task_plan)
        bar_w = 20
        filled = int(done / max(total, 1) * bar_w)
        bar = f"[green]{'█' * filled}[/][dim]{'░' * (bar_w - filled)}[/]"
        progress_lines.append(f"  Plan: [{bar}] {done}/{total}")
    if scratchpad:
        progress_lines.append(f"  Scratchpad: {len(scratchpad)} entries")
    if target_pkgs:
        progress_lines.append(f"  Scope: {', '.join(target_pkgs[:3])}")
    if graph_ready:
        progress_lines.append("  Code Graph: [green]● loaded[/]")
    if not progress_lines:
        progress_lines.append("  [dim]No progress data yet[/]")

    progress_panel = Panel(
        "\n".join(progress_lines),
        title="[bold]📊 Progress[/]",
        border_style="yellow",
        padding=(0, 1),
    )

    # ── Context panel ──
    tt = token_tracker
    ctx_lines = []
    if tt.total_tokens:
        ctx_lines.append(f"  Tokens: {tt.total_tokens:,}  ({tt.total_calls} calls)")
    try:
        from apk_agent.agent.graph import _compactor
        if _compactor and _compactor.last_token_count > 0:
            ctx_pct = (_compactor.last_token_count / _compactor.token_threshold) * 100
            bar_w = 20
            filled = int(ctx_pct / 100 * bar_w)
            color = "green" if ctx_pct < 60 else ("yellow" if ctx_pct < 85 else "red")
            bar = f"[{color}]{'━' * filled}[/{color}][dim]{'━' * (bar_w - filled)}[/dim]"
            ctx_lines.append(f"  Context: [{bar}] [{color}]{ctx_pct:.0f}%[/{color}]")
            ctx_lines.append(f"  Compactions: {_compactor.compact_count}")
    except Exception:
        pass
    if tt.total_cached_tokens > 0:
        cache_pct = (tt.total_cached_tokens / max(tt.total_prompt_tokens, 1)) * 100
        ctx_lines.append(f"  Cache hit: [green]⚡ {cache_pct:.0f}%[/green]")
    if not ctx_lines:
        ctx_lines.append("  [dim]No data yet[/]")

    context_panel = Panel(
        "\n".join(ctx_lines),
        title="[bold]🪙 Context[/]",
        border_style="magenta",
        padding=(0, 1),
    )

    # Layout: 2x2 grid
    console.print(Columns([findings_panel, patches_panel], equal=True, expand=True))
    console.print(Columns([progress_panel, context_panel], equal=True, expand=True))


def print_findings_list(findings: list[dict]) -> None:
    """Print all findings with severity highlighting in a rich table."""
    if not findings:
        console.print("[dim]No findings recorded yet.[/]")
        return

    colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}
    icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "ℹ️ "}

    table = Table(
        title=f"🔍 Findings ({len(findings)})",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        padding=(0, 1),
        expand=True,
    )
    table.add_column("#", style="bold", width=4, justify="center")
    table.add_column("Sev", width=10)
    table.add_column("Category", width=16)
    table.add_column("Title", min_width=30)
    table.add_column("Location", style="dim", width=30)

    for i, f in enumerate(findings, 1):
        sev = (f.get("severity") or "INFO").upper()
        icon = icons.get(sev, "ℹ️ ")
        color = colors.get(sev, "dim")
        category = f.get("category", "—")
        title = f.get("title", "Finding")
        location = f.get("location", "")
        if len(title) > 50:
            title = title[:47] + "..."
        if len(location) > 30:
            location = "…" + location[-28:]
        table.add_row(
            str(i),
            f"[{color}]{icon} {sev}[/{color}]",
            category,
            title,
            location,
        )

    console.print(table)

    # Severity summary
    sev_summary = {}
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        sev_summary[sev] = sev_summary.get(sev, 0) + 1
    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev_summary.get(sev, 0) > 0:
            color = colors.get(sev, "dim")
            parts.append(f"[{color}]{sev}: {sev_summary[sev]}[/{color}]")
    if parts:
        console.print(f"  {' │ '.join(parts)}")


def print_patches_list(patches: list[dict], registry: list[dict] | None = None) -> None:
    """Print all patches with status in a rich table."""
    if not patches and not registry:
        console.print("[dim]No patches applied yet.[/]")
        return

    table = Table(
        title=f"🔧 Patches ({len(patches)})",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        padding=(0, 1),
        expand=True,
    )
    table.add_column("#", style="bold", width=4, justify="center")
    table.add_column("Status", width=12)
    table.add_column("Tool", width=18)
    table.add_column("Target", min_width=30)
    table.add_column("Steps", width=8, justify="center")

    status_icons = {
        True: "[green]✅ OK[/]",
        False: "[red]❌ FAIL[/]",
    }

    for i, p in enumerate(patches, 1):
        success = p.get("success", False)
        status = status_icons.get(success, "[dim]?[/]")
        tool_name = p.get("tool", "—")
        target = p.get("target_file", "—")
        if len(target) > 35:
            target = "…" + target[-33:]
        steps = f"{p.get('steps_applied', 0)}/{p.get('steps_total', 0)}"
        table.add_row(str(i), status, tool_name, target, steps)

    console.print(table)

    # Coverage from registry
    if registry:
        ok = sum(1 for r in registry if r.get("status") in ("applied", "verified"))
        failed = sum(1 for r in registry if r.get("status") == "failed")
        rejected = sum(1 for r in registry if r.get("status") == "user_rejected")
        total = len(registry)
        coverage = (ok / max(total, 1)) * 100
        color = "green" if coverage >= 80 else ("yellow" if coverage >= 50 else "red")
        console.print(
            f"  Registry: {total} entries │ "
            f"[green]{ok} applied[/] │ [red]{failed} failed[/] │ [yellow]{rejected} rejected[/] │ "
            f"Coverage: [{color}]{coverage:.0f}%[/{color}]"
        )


def print_tools_list() -> None:
    """Print all tools grouped by category in a compact display."""
    try:
        from apk_agent.agent.tools_def import ALL_TOOLS
    except Exception:
        console.print("[dim]Could not load tools.[/]")
        return

    categories = _build_tool_categories([tool.name for tool in ALL_TOOLS])

    total = len(ALL_TOOLS)
    console.print(f"\n[bold bright_cyan]🧰 APK Agent Tools — {total} total[/]\n")

    for cat_name, tools in categories.items():
        if not tools:
            continue
        icon = _TOOL_CATEGORY_ICONS.get(cat_name, "📦")
        tools_str = ", ".join(f"[cyan]{t}[/]" for t in tools)
        console.print(f"  {icon} [bold]{cat_name}[/] [dim]({len(tools)})[/]")
        console.print(f"     {tools_str}")
        console.print()

