"""Interactive Chat CLI — the main entry point for APK Agent.

Usage:
    python -m apk_agent.cli                      — Launch interactive mode
    python -m apk_agent.cli "path/to/app.apk"    — Start with an APK directly
"""

from __future__ import annotations

import json
import logging
import sys
import uuid
from pathlib import Path

import click
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from apk_agent.config import AppConfig
from apk_agent.session import (
    SessionMeta,
    delete_session,
    get_sqlite_checkpointer,
    has_session,
    load_session_meta,
    save_session_meta,
)
from apk_agent.ui import (
    console,
    live_bar,
    print_ai_message,
    print_error,
    print_help,
    print_hitl_prompt,
    print_info,
    print_success,
    print_status,
    print_tool_output,
    print_tool_start,
    print_user_message,
    print_warning,
    print_welcome,
    enable_live_progress,
    print_status_bar,
    print_turn_summary,
    token_tracker,
)
from apk_agent.workspace import Project, ProjectManager


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        handlers=[logging.StreamHandler()],
    )


# ---------------------------------------------------------------------------
# Pretty startup banner
# ---------------------------------------------------------------------------

def _print_startup() -> None:
    """Print the full-screen startup banner with gradient style."""
    console.print()
    console.print("[bold bright_cyan]╔══════════════════════════════════════════════════════════╗[/]")
    console.print("[bold bright_cyan]║[/]                                                          [bold bright_cyan]║[/]")
    console.print("[bold bright_cyan]║[/]   [bold white]🔬  A P K   A G E N T[/]   [dim]v4.0[/]                         [bold bright_cyan]║[/]")
    console.print("[bold bright_cyan]║[/]   [bold bright_white]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/]                     [bold bright_cyan]║[/]")
    console.print("[bold bright_cyan]║[/]   [dim italic]AI-Powered Android APK Reverse Engineering[/]          [bold bright_cyan]║[/]")
    console.print("[bold bright_cyan]║[/]   [dim]72 Tools • Taint Analysis • Auto-Bypass • Patching[/] [bold bright_cyan]║[/]")
    console.print("[bold bright_cyan]║[/]                                                          [bold bright_cyan]║[/]")
    console.print("[bold bright_cyan]╚══════════════════════════════════════════════════════════╝[/]")
    console.print()


def _print_tools_status(config: AppConfig) -> None:
    """Show which tools are available in a compact grid."""
    tools = {
        "apktool": config.get_tool_path("apktool"),
        "jadx": config.get_tool_path("jadx"),
        "dex2jar": config.get_tool_path("dex2jar"),
        "aapt2": config.get_tool_path("aapt2"),
        "zipalign": config.get_tool_path("zipalign"),
        "apksigner": config.get_tool_path("apksigner"),
    }
    from rich.table import Table
    table = Table(
        show_header=False, show_edge=False, padding=(0, 1),
        expand=False, border_style="dim",
    )
    table.add_column(style="bold", width=14)
    table.add_column(width=14)
    table.add_column(width=14)

    # Arrange tools in 3 columns
    tool_items = list(tools.items())
    rows = [tool_items[i:i+3] for i in range(0, len(tool_items), 3)]
    for row in rows:
        cells = []
        for name, path in row:
            if path:
                cells.append(f"[green]● {name}[/]")
            else:
                cells.append(f"[yellow]○ {name}[/]")
        while len(cells) < 3:
            cells.append("")
        table.add_row(*cells)

    console.print("[bold dim]Tools:[/]")
    console.print(table)

    # Show thinking mode and model
    model_display = config.model_name.split("/")[-1] if "/" in config.model_name else config.model_name
    thinking_icon = "[bold green]●[/] ON" if config.thinking_enabled else "[bold red]○[/] OFF"
    console.print(f"[dim]Model:[/] [bold]{model_display}[/]  │  [dim]Thinking:[/] {thinking_icon}")
    console.print()


# ---------------------------------------------------------------------------
# Interactive project picker
# ---------------------------------------------------------------------------

def _pick_or_create_project(pm: ProjectManager, config: AppConfig, apk_path: str | None = None) -> Project | None:
    """Interactively pick an existing project or create a new one."""

    # If APK path was provided, just create the project
    if apk_path:
        apk_p = Path(apk_path.strip().strip('"').strip("'"))
        if not apk_p.is_file():
            print_error(f"APK file not found: {apk_p}")
            return None
        try:
            project = pm.create_project(str(apk_p), config.max_apk_size_mb)
            print_success(f"Project created: {project.id}")
            print_info(f"APK: {project.apk_name}")
            return project
        except ValueError as e:
            print_error(str(e))
            return None

    # Show existing projects
    projects = pm.list_projects()

    if projects:
        console.print("[bold]📦 Your projects:[/]\n")
        from rich.table import Table
        table = Table(show_header=True, header_style="bold cyan", border_style="dim",
                      padding=(0, 1), expand=False)
        table.add_column("#", style="bold cyan", width=4, justify="center")
        table.add_column("APK Name", min_width=30)
        table.add_column("ID", style="dim", width=10)
        table.add_column("Status", width=12)

        for i, p in enumerate(projects, 1):
            status_style = "green" if p.status == "active" else "dim"
            status_icon = "●" if p.status == "active" else "○"
            table.add_row(
                str(i),
                p.apk_name,
                f"{p.id[:8]}…",
                f"[{status_style}]{status_icon} {p.status}[/]",
            )

        console.print(table)
        console.print(f"\n  [bold cyan][0][/] 📁 Load a new APK file\n")

        choice = console.input("[bold green]➜ Select a project (number): [/]").strip()

        if choice == "0" or not choice:
            return _ask_for_apk(pm, config)
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(projects):
                    project = projects[idx]
                    print_success(f"Opened: {project.apk_name} ({project.id[:8]}…)")
                    return project
                else:
                    print_error("Invalid selection.")
                    return None
            except ValueError:
                print_error("Please enter a number.")
                return None
    else:
        console.print("[bold]📦 No projects yet![/]\n")
        return _ask_for_apk(pm, config)


def _ask_for_apk(pm: ProjectManager, config: AppConfig) -> Project | None:
    """Ask the user for an APK file path and create a project."""

    # Auto-detect APK files in common locations (deep scan)
    search_dirs: list[Path] = []
    search_dirs.append(Path.cwd())
    # Project root (where the source code lives)
    project_root = Path(__file__).resolve().parent.parent.parent
    if project_root not in search_dirs:
        search_dirs.append(project_root)
    # Workspace root
    ws = config.workspace_path
    if ws.is_dir() and ws not in search_dirs:
        search_dirs.append(ws)
    # Also scan common user directories
    home = Path.home()
    for candidate in [home / "Desktop", home / "Downloads", home / "Documents"]:
        if candidate.is_dir() and candidate not in search_dirs:
            search_dirs.append(candidate)

    found_apks: list[Path] = []
    seen: set[str] = set()  # normalized resolved path strings for robust dedup
    for d in search_dirs:
        if not d.is_dir():
            continue
        # Scan top-level files
        try:
            for f in sorted(d.iterdir()):
                if f.is_file() and f.suffix.lower() in (".apk", ".xapk"):
                    resolved = f.resolve()
                    key = str(resolved).casefold()
                    if key not in seen:
                        seen.add(key)
                        found_apks.append(f)
        except PermissionError:
            continue
        # Also scan one level deeper (common: Downloads/subfolder/app.apk)
        try:
            for sub in d.iterdir():
                if sub.is_dir():
                    try:
                        for f in sorted(sub.iterdir()):
                            if f.is_file() and f.suffix.lower() in (".apk", ".xapk"):
                                resolved = f.resolve()
                                key = str(resolved).casefold()
                                if key not in seen:
                                    seen.add(key)
                                    found_apks.append(f)
                    except PermissionError:
                        continue
        except PermissionError:
            continue

    if found_apks:
        console.print("[bold]📱 APK files detected:[/]\n")
        from rich.table import Table
        table = Table(show_header=True, header_style="bold cyan", border_style="dim",
                      padding=(0, 1), expand=False)
        table.add_column("#", style="bold cyan", width=4, justify="center")
        table.add_column("File Name", min_width=35)
        table.add_column("Size", style="dim", width=10, justify="right")

        for i, apk in enumerate(found_apks, 1):
            size_mb = apk.stat().st_size / (1024 * 1024)
            table.add_row(str(i), apk.name, f"{size_mb:.1f} MB")

        console.print(table)
        console.print(f"\n  [bold cyan][0][/] 📂 Enter a custom path\n")

        choice = console.input("[bold green]➜ Select APK (number): [/]").strip()

        if choice and choice != "0":
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(found_apks):
                    apk_p = found_apks[idx]
                    try:
                        project = pm.create_project(str(apk_p), config.max_apk_size_mb)
                        print_success(f"Project created: {project.id}")
                        print_info(f"APK: {project.apk_name}")
                        return project
                    except ValueError as e:
                        print_error(str(e))
                        return None
                else:
                    print_error("Invalid selection.")
                    return None
            except ValueError:
                print_error("Please enter a number.")
                return None

    # Manual path entry
    console.print("[dim]Tip: drag & drop an APK file into this terminal, or paste the full path[/]")
    apk_input = console.input("[bold green]➜ APK file path: [/]").strip()

    if not apk_input:
        print_error("No path provided.")
        return None

    # Clean up path — handle drag-and-drop quotes and whitespace
    apk_input = apk_input.strip().strip('"').strip("'")

    apk_p = Path(apk_input)
    if not apk_p.is_file():
        print_error(f"File not found: {apk_p}")
        return None

    if not apk_p.name.lower().endswith(".apk"):
        print_warning("File doesn't end in .apk — trying anyway...")

    try:
        project = pm.create_project(str(apk_p), config.max_apk_size_mb)
        print_success(f"Project created: {project.id}")
        print_info(f"APK: {project.apk_name}")
        return project
    except ValueError as e:
        print_error(str(e))
        return None


# ---------------------------------------------------------------------------
# Main entry — single interactive command
# ---------------------------------------------------------------------------

@click.command()
@click.argument("apk_path", required=False, default=None)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.option("--project", "-p", "project_id", default=None, help="Open project by ID")
@click.option("--thinking/--no-thinking", "thinking_enabled", default=None,
              help="Enable/disable LLM deep thinking mode (default: from .env or ON)")
@click.option("--model", "-m", "model_name", default=None,
              help="Override model name (e.g. 'anthropic/claude-sonnet-4-6-20260218')")
@click.option("--auto", "auto_mode", is_flag=True, help="Start in auto mode (no confirmations)")
def main(apk_path: str | None, verbose: bool, project_id: str | None,
         thinking_enabled: bool | None, model_name: str | None, auto_mode: bool) -> None:
    """🔬 APK Agent — Interactive Static Android APK Reverse Engineering

    Run without arguments for the interactive menu.
    Or pass an APK path directly:

        python -m apk_agent.cli "path/to/app.apk"
    """
    _setup_logging(verbose)

    # Load config
    config = AppConfig.load()

    # CLI overrides
    if thinking_enabled is not None:
        config.thinking_enabled = thinking_enabled
    if model_name is not None:
        config.model_name = model_name

    warnings = config.validate()

    # Startup
    _print_startup()
    _print_tools_status(config)

    for w in warnings:
        if "not found" not in w.lower():  # Don't spam optional tool warnings
            print_warning(w)

    pm = ProjectManager(config.workspace_path)
    project: Project | None = None

    # Open by project ID
    if project_id:
        try:
            project = pm.open_project(project_id)
            print_success(f"Opened: {project.apk_name}")
        except FileNotFoundError:
            print_error(f"Project {project_id} not found.")
            sys.exit(1)
    else:
        # Interactive project picker (or use provided APK path)
        project = _pick_or_create_project(pm, config, apk_path)

    if not project:
        console.print("[dim]No project selected. Goodbye! 👋[/]")
        return

    # ------------------------------------------------------------------
    # Session restoration — check for existing session on this project
    # ------------------------------------------------------------------
    session_meta: SessionMeta | None = None
    resumed = False

    if has_session(project.workspace_path):
        session_meta = load_session_meta(project.workspace_path)
        if session_meta and session_meta.status == "active":
            console.print()
            console.print("[bold yellow]📂 Previous session found[/]")
            from rich.table import Table
            tbl = Table(show_header=False, padding=(0, 1), border_style="dim", expand=False)
            tbl.add_column(style="dim", width=14)
            tbl.add_column()
            tbl.add_row("Thread", f"{session_meta.thread_id[:12]}…")
            tbl.add_row("Messages", str(session_meta.message_count))
            tbl.add_row("Last active", session_meta.last_active_at[:19] if session_meta.last_active_at else "—")
            if session_meta.last_user_input:
                tbl.add_row("Last input", f"{session_meta.last_user_input[:60]}…")
            console.print(tbl)
            console.print()
            choice = console.input(
                "[bold green]➜ Resume session? (yes/no): [/]"
            ).strip().lower()
            if choice in ("yes", "y", ""):
                resumed = True
                console.print("[bold green]✅ Session restored — continuing from where you left off.[/]")
            else:
                # User wants a fresh start
                delete_session(project.workspace_path)
                session_meta = None
                console.print("[dim]Starting fresh session.[/]")

    # Create session meta if new
    if session_meta is None or not resumed:
        from datetime import datetime, timezone
        session_meta = SessionMeta(
            thread_id=str(uuid.uuid4()),
            project_id=project.id,
            created_at=datetime.now(timezone.utc).isoformat(),
            last_active_at=datetime.now(timezone.utc).isoformat(),
            thinking_mode=config.thinking_enabled,
            auto_mode=auto_mode,
        )
        save_session_meta(session_meta, project.workspace_path)
    else:
        # Sync thinking mode from session to config (in case user toggled last time)
        config.thinking_enabled = session_meta.thinking_mode

    # Build the agent graph with SQLite checkpointer for persistence
    console.print()
    print_info("Initializing agent...")

    # Enable live progress updates for long-running tools
    enable_live_progress()

    try:
        from apk_agent.agent.graph import build_graph

        checkpointer = get_sqlite_checkpointer(project.workspace_path)
        graph, _ = build_graph(config, project, checkpointer=checkpointer)
    except Exception as e:
        print_error(f"Failed to initialize agent: {e}")
        import traceback
        traceback.print_exc()
        return

    print_welcome(project.id, project.apk_name)

    # Thread config for LangGraph (uses persistent thread_id)
    thread_id = session_meta.thread_id
    graph_config = {"configurable": {"thread_id": thread_id}}

    # Ensure loop/nudge trackers are scoped to this session
    from apk_agent.agent.graph import set_active_thread
    set_active_thread(thread_id)

    if resumed:
        # Sync message count from checkpoint (more accurate than metadata counter)
        try:
            ckpt = graph.get_state(graph_config)
            if ckpt and ckpt.values and ckpt.values.get("messages"):
                actual_count = len(ckpt.values["messages"])
                session_meta.message_count = actual_count

                # Show restored state summary
                findings = ckpt.values.get("findings") or []
                patches = ckpt.values.get("patch_results") or []
                scratchpad = ckpt.values.get("scratchpad") or {}
                task_plan = ckpt.values.get("task_plan") or []
                graph_ready = ckpt.values.get("graph_ready", False)
                target_pkgs = ckpt.values.get("target_packages") or []

                parts = [f"{actual_count} messages"]
                if findings:
                    parts.append(f"{len(findings)} findings")
                if patches:
                    ok = sum(1 for p in patches if p.get("success"))
                    parts.append(f"{ok}/{len(patches)} patches")
                if scratchpad:
                    parts.append(f"{len(scratchpad)} scratchpad entries")
                if task_plan:
                    done = sum(1 for t in task_plan if t.get("status") == "done")
                    parts.append(f"plan {done}/{len(task_plan)} done")
                if target_pkgs:
                    parts.append(f"scope: {', '.join(target_pkgs[:3])}")
                if graph_ready:
                    parts.append("graph ✓")

                console.print(
                    f"[bold cyan]🔄 Session restored — {' │ '.join(parts)}. "
                    f"Compacted {session_meta.compact_count} time(s).[/]"
                )
        except Exception:
            console.print(
                f"[bold cyan]🔄 Session resumed — {session_meta.message_count} messages in history.[/]"
            )
        console.print("[dim]Type your next message to continue, or /help for commands.[/]")
        console.print()

    # Chat loop
    _chat_loop(graph, graph_config, project, pm, config, session_meta)


# ---------------------------------------------------------------------------
# Hot-reload LLM with new thinking setting
# ---------------------------------------------------------------------------

def _rebuild_llm_if_needed(graph, config: AppConfig, project) -> None:
    """Rebuild the LLM instance when thinking mode is toggled mid-session."""
    try:
        import apk_agent.agent.graph as _graph_mod
        from apk_agent.llm.provider import get_llm
        from apk_agent.agent.tools_def import ALL_TOOLS

        llm = get_llm(config)
        _graph_mod._raw_llm = llm
        _graph_mod._llm_with_tools = llm.bind_tools(ALL_TOOLS)

        status = "[green]ON[/]" if config.thinking_enabled else "[red]OFF[/]"
        console.print(f"[bold]🧠 Thinking mode: {status}[/] — LLM reconfigured.")
    except Exception as e:
        print_error(f"Failed to reconfigure LLM: {e}")


# ---------------------------------------------------------------------------
# Chat loop
# ---------------------------------------------------------------------------

def _chat_loop(
    graph, graph_config: dict, project: Project,
    pm: ProjectManager, config: AppConfig,
    session_meta: SessionMeta,
) -> None:
    """Main interactive chat loop with normal and orchestrator modes."""
    orchestrator_mode = session_meta.orchestrator_mode
    auto_mode = session_meta.auto_mode

    while True:
        try:
            # Build mode indicator
            mode_parts = []
            if auto_mode:
                mode_parts.append("[bold yellow]auto[/]")
            if orchestrator_mode:
                mode_parts.append("[bold magenta]orchestrator[/]")
            if config.thinking_enabled:
                mode_parts.append("[green]🧠[/]")

            mode_tag = f" [{', '.join(mode_parts)}]" if mode_parts else ""
            user_input = console.input(f"\n[bold green]You{mode_tag} ➜ [/]").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Goodbye! 👋[/]")
            # Save session before exit
            session_meta.status = "active"
            session_meta.touch()
            save_session_meta(session_meta, project.workspace_path)
            break

        if not user_input:
            continue

        # Handle commands
        if user_input.startswith("/"):
            result = _handle_command(user_input, project, pm, config, session_meta)
            if result == "quit":
                # Save session on quit
                session_meta.status = "active"
                session_meta.touch()
                save_session_meta(session_meta, project.workspace_path)
                break
            elif result == "orchestrator_on":
                orchestrator_mode = True
                session_meta.orchestrator_mode = True
                print_success("Switched to Orchestrator mode — tasks will use parallel sub-agents")
                continue
            elif result == "orchestrator_off":
                orchestrator_mode = False
                session_meta.orchestrator_mode = False
                print_success("Switched to Normal chat mode")
                continue
            elif result == "auto_on":
                auto_mode = True
                session_meta.auto_mode = True
                print_success(
                    "Switched to Auto mode — patches auto-approved, "
                    "agent questions auto-answered. Full one-shot execution."
                )
                continue
            elif result == "auto_off":
                auto_mode = False
                session_meta.auto_mode = False
                print_success("Auto mode disabled — back to interactive confirmations.")
                continue
            elif result == "thinking_on":
                config.thinking_enabled = True
                session_meta.thinking_mode = True
                # Rebuild LLM with thinking enabled
                _rebuild_llm_if_needed(graph, config, project)
                continue
            elif result == "thinking_off":
                config.thinking_enabled = False
                session_meta.thinking_mode = False
                # Rebuild LLM with thinking disabled
                _rebuild_llm_if_needed(graph, config, project)
                continue
            if result is not None:
                continue

        # Send to agent
        print_user_message(user_input)

        # Update session metadata
        session_meta.message_count += 1
        session_meta.last_user_input = user_input
        session_meta.touch()

        if orchestrator_mode:
            _run_orchestrator_turn(user_input, project, config)
        else:
            _run_agent_turn(graph, graph_config, user_input, project, session_meta, auto_mode=auto_mode)

        # Save session after each turn
        save_session_meta(session_meta, project.workspace_path)


def _handle_command(
    cmd: str, project: Project, pm: ProjectManager,
    config: AppConfig, session_meta: SessionMeta,
) -> str | None:
    """Handle / commands. Returns 'quit' to exit, mode changes, or None."""
    parts = cmd.split(maxsplit=1)
    command = parts[0].lower()
    arg = parts[1] if len(parts) > 1 else ""

    match command:
        case "/help":
            print_help()
        case "/status":
            print_status(project.id, project.apk_name, project.status)
        case "/session":
            _show_session_info(session_meta, project)
        case "/reset":
            confirm = console.input(
                "[bold red]⚠️  This will delete the session history. Are you sure? (yes/no): [/]"
            ).strip().lower()
            if confirm in ("yes", "y"):
                delete_session(project.workspace_path)
                print_success("Session cleared. Restart the app for a fresh session.")
            else:
                print_info("Reset cancelled.")
        case "/compact":
            _manual_compact(session_meta)
        case "/tokens":
            _show_token_count()
        case "/logs":
            log_file = Path(project.workspace_path) / "logs" / "tools.log"
            if log_file.is_file():
                lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
                tail = "\n".join(lines[-50:])
                console.print(f"[dim]{tail}[/]")
            else:
                print_info("No logs yet.")
        case "/report":
            report_file = Path(project.workspace_path) / "outputs" / "report.md"
            if report_file.is_file():
                from rich.markdown import Markdown
                console.print(Markdown(report_file.read_text(encoding="utf-8")))
            else:
                print_info("No report generated yet.")
        case "/progress":
            from apk_agent.progress import progress_manager
            from apk_agent.ui import print_progress_summary
            summary = progress_manager.get_summary()
            if summary["total"] > 0:
                print_progress_summary(summary)
            else:
                print_info("No tasks tracked yet.")
        case "/plan":
            from apk_agent.agent.tools_def import _get_task_plan
            from apk_agent.ui import print_task_plan
            plan = _get_task_plan()
            if plan:
                print_task_plan(plan)
            else:
                print_info("No task plan created yet. The agent creates one when starting a complex task.")
        case "/orchestrator":
            return "orchestrator_on"
        case "/normal":
            return "orchestrator_off"
        case "/auto":
            if session_meta.auto_mode:
                return "auto_off"
            return "auto_on"
        case "/thinking":
            if session_meta.thinking_mode:
                return "thinking_off"
            return "thinking_on"
        case "/stop":
            print_info("Operation stopped.")
        case "/quit" | "/exit" | "/q":
            console.print("[dim]Goodbye! 👋[/]")
            return "quit"
        case "/new":
            if arg:
                new_path = arg.strip().strip('"').strip("'")
                try:
                    new_project = pm.create_project(new_path, config.max_apk_size_mb)
                    print_success(f"New project: {new_project.id} ({new_project.apk_name})")
                except ValueError as e:
                    print_error(str(e))
            else:
                print_error("Usage: /new <apk_path>")
        case "/list":
            projects = pm.list_projects()
            if projects:
                for p in projects:
                    console.print(f"  [cyan]{p.id[:8]}…[/]  {p.apk_name:30s}  [{p.status}]")
            else:
                print_info("No projects.")
        case _:
            print_warning(f"Unknown command: {command}. Type /help for help.")

    return None


# ---------------------------------------------------------------------------
# Agent turn (normal mode)
# ---------------------------------------------------------------------------

def _run_agent_turn(graph, graph_config: dict, user_input: str, project: Project, session_meta: SessionMeta, *, auto_mode: bool = False) -> None:
    """Run one turn of the agent with streaming output and error recovery."""
    # Set auto_mode flag at graph/tool level so interrupts are skipped entirely
    import apk_agent.agent.tools_def as _td
    _td._auto_mode = auto_mode

    from apk_agent.progress import progress_manager
    progress_manager.set_overall_task(user_input)

    # Start turn tracking
    token_tracker.start_turn()

    # ── Build input state ──────────────────────────────────────────────
    # Only send the new message + task + project context (idempotent).
    # Do NOT send empty lists/dicts for accumulated state fields like
    # findings, scratchpad, task_plan, etc. — those must survive across
    # turns via the checkpointer. Overwriting them with [] would wipe
    # everything the agent discovered so far.
    input_state: dict = {
        "messages": [HumanMessage(content=user_input)],
        "task": user_input,
        "human_feedback": "",
        # Project context — always set, idempotent
        "project_id": project.id,
        "project_path": project.workspace_path,
        "apk_name": project.apk_name,
        "apktool_dir": str(project.apktool_dir),
        "jadx_dir": str(project.jadx_dir),
    }

    # Only initialize accumulated fields on the very first turn
    # (no checkpoint yet). On subsequent turns / resumed sessions,
    # the checkpoint preserves findings, scratchpad, patches, etc.
    try:
        existing = graph.get_state(graph_config)
        is_first_turn = (
            not existing
            or not existing.values
            or not existing.values.get("messages")
        )
    except Exception:
        is_first_turn = True

    if is_first_turn:
        input_state.update({
            "findings": [],
            "patch_results": [],
            "graph_ready": False,
            "target_packages": [],
            "excluded_packages": [],
            "scratchpad": {},
            "task_plan": [],
        })

    max_consecutive_errors = 3
    error_count = 0

    try:
        # Start the live status bar
        live_bar.start()

        # ── Flat interrupt loop ────────────────────────────────────────
        # Each graph.stream() is fully consumed before starting the next.
        # This prevents nested SQLite transactions that cause WinError 32.
        from langgraph.types import Command
        stream_input = input_state
        is_resume = False

        while True:
            interrupt_info = None

            try:
                if is_resume:
                    events = graph.stream(
                        Command(resume=stream_input),
                        config=graph_config,
                        stream_mode="updates",
                    )
                else:
                    events = graph.stream(
                        stream_input,
                        config=graph_config,
                        stream_mode="updates",
                    )

                for event in events:
                    try:
                        result = _process_stream_event(event, graph, graph_config, auto_mode=auto_mode)
                        error_count = 0
                        if result and result.get("interrupt"):
                            interrupt_info = result
                            break  # exit for-loop, let generator close
                    except Exception as e:
                        error_count += 1
                        print_warning(f"Stream processing error ({error_count}/{max_consecutive_errors}): {e}")
                        if error_count >= max_consecutive_errors:
                            print_error("Too many consecutive errors. Stopping this turn.")
                            break

            except OSError as oe:
                if getattr(oe, 'winerror', 0) == 32:
                    print_warning(f"File lock during checkpoint — retrying: {oe}")
                    import time as _t; _t.sleep(0.5)
                    continue  # retry the same stream_input
                raise

            if error_count >= max_consecutive_errors:
                break

            if interrupt_info is None:
                break  # no interrupt — turn finished normally

            # Resume with user's response
            stream_input = interrupt_info["response"]
            is_resume = True
            live_bar.start()  # restart bar after user input

    except KeyboardInterrupt:
        print_warning("Operation interrupted by user.")
    except Exception as e:
        error_str = str(e)
        err_lower = error_str.lower()
        if "rate_limit" in err_lower or "429" in error_str:
            print_warning("Rate limited by API. Wait a moment and try again.")
        elif "api key limit" in err_lower or ("403" in error_str and "limit" in err_lower):
            print_error("API quota exhausted. Top up your API credits or wait for reset.")
        elif "timeout" in err_lower:
            print_warning("API timeout. The request took too long. Try a simpler query.")
        elif "authentication" in err_lower or "401" in error_str:
            print_error("API authentication failed. Check your API_KEY in .env")
        elif "must be in json format" in err_lower or "invalidparameter" in err_lower:
            print_warning(
                "LLM produced malformed tool arguments (JSON error). "
                "This is transient — try again. If it persists, try a simpler prompt."
            )
        else:
            print_error(f"Agent error: {e}")
            import traceback
            traceback.print_exc()

    # Update session with compact info
    try:
        from apk_agent.agent.graph import _compactor
        if _compactor and _compactor.compact_count > session_meta.compact_count:
            old_count = session_meta.compact_count
            session_meta.compact_count = _compactor.compact_count
            console.print(
                f"[bold yellow]📋 Auto-compact triggered "
                f"(#{session_meta.compact_count}) — context was summarized "
                f"to stay within limits.[/]"
            )
    except Exception:
        pass

    # Stop the live status bar before printing final summary
    live_bar.stop()

    # Print turn summary with token usage
    token_tracker.clear_active_tool()
    print_turn_summary()


# ---------------------------------------------------------------------------
# Session info helpers
# ---------------------------------------------------------------------------


def _show_session_info(session_meta: SessionMeta, project: Project) -> None:
    """Display current session information."""
    from rich.table import Table

    table = Table(title="📂 Session Info", show_header=False, padding=(0, 2))
    table.add_column("Key", style="bold cyan")
    table.add_column("Value")
    table.add_row("Thread ID", session_meta.thread_id[:16] + "…")
    table.add_row("Project", session_meta.project_id)
    table.add_row("Created", session_meta.created_at)
    table.add_row("Last Active", session_meta.last_active_at)
    table.add_row("Messages", str(session_meta.message_count))
    table.add_row("Auto-compacts", str(session_meta.compact_count))
    mode_parts = []
    if session_meta.orchestrator_mode:
        mode_parts.append("Orchestrator")
    if session_meta.auto_mode:
        mode_parts.append("Auto")
    if not mode_parts:
        mode_parts.append("Normal")
    table.add_row("Mode", " + ".join(mode_parts))
    thinking_str = "[green]● ON[/]" if session_meta.thinking_mode else "[red]○ OFF[/]"
    table.add_row("Thinking", thinking_str)
    table.add_row("Status", session_meta.status)

    # Token usage
    tt = token_tracker
    if tt.total_tokens:
        table.add_row("Total Tokens", f"{tt.total_tokens:,}")
        table.add_row("LLM Calls", str(tt.total_calls))

    # Context window
    try:
        from apk_agent.compactor import count_message_tokens, DEFAULT_TOKEN_THRESHOLD
        from apk_agent.agent.graph import _compactor
        if _compactor and _compactor.last_token_count > 0:
            token_pct = (_compactor.last_token_count / _compactor.token_threshold) * 100
            color = "green" if token_pct < 60 else ("yellow" if token_pct < 85 else "red")
            table.add_row(
                "Context Usage",
                f"[{color}]~{_compactor.last_token_count:,} tokens ({token_pct:.0f}%)[/]",
            )
    except Exception:
        pass

    console.print(table)


def _manual_compact(session_meta: SessionMeta) -> None:
    """Manually trigger a compaction."""
    console.print("[bold yellow]Manual compact is not yet supported from the CLI.[/]")
    console.print("[dim]Auto-compact triggers automatically when context exceeds 200K tokens.[/]")
    try:
        from apk_agent.agent.graph import _compactor
        if _compactor:
            console.print(
                f"[dim]Current usage: ~{_compactor.last_token_count:,} tokens | "
                f"Threshold: {_compactor.token_threshold:,} tokens | "
                f"Compactions so far: {_compactor.compact_count}[/]"
            )
    except Exception:
        pass


def _show_token_count() -> None:
    """Show the current estimated token count."""
    from rich.table import Table

    table = Table(title="📊 Token Usage", show_header=False, padding=(0, 2))
    table.add_column("Key", style="bold cyan")
    table.add_column("Value")

    # Session totals from token tracker
    tt = token_tracker
    table.add_row("Session Prompt Tokens", f"{tt.total_prompt_tokens:,}")
    table.add_row("Session Completion Tokens", f"{tt.total_completion_tokens:,}")
    table.add_row("Session Total", f"[bold]{tt.total_tokens:,}[/]")
    table.add_row("LLM Calls", str(tt.total_calls))

    # Context window usage from compactor
    try:
        from apk_agent.agent.graph import _compactor
        if _compactor and _compactor.last_token_count > 0:
            ctx_pct = (_compactor.last_token_count / _compactor.token_threshold) * 100
            bar_len = 20
            filled = int(ctx_pct / 100 * bar_len)
            bar = "█" * filled + "░" * (bar_len - filled)
            color = "green" if ctx_pct < 60 else ("yellow" if ctx_pct < 85 else "red")
            table.add_row("Context Window", f"[{color}][{bar}] {ctx_pct:.0f}%[/]")
            table.add_row("Context Tokens", f"~{_compactor.last_token_count:,} / {_compactor.token_threshold:,}")
            table.add_row("Auto-Compactions", str(_compactor.compact_count))
    except Exception:
        pass

    console.print(table)


# ---------------------------------------------------------------------------
# Orchestrator turn
# ---------------------------------------------------------------------------

def _run_orchestrator_turn(user_input: str, project, config) -> None:
    """Run an orchestrator turn — either dispatch sub-agents or chat."""
    from apk_agent.agent.orchestrator import Orchestrator
    from apk_agent.ui import print_orchestrator_plan, print_progress_summary, print_sub_agent_result

    orchestrator = Orchestrator(config, project, max_parallel=3)

    # Route: does this need sub-agents or is it a conversational message?
    route = orchestrator.route_message(user_input)

    if route == "chat":
        # Conversational response using previous results
        console.print("[dim]💬 Answering from previous results...[/]")
        try:
            answer = orchestrator.chat(user_input)
            from apk_agent.ui import print_ai_message
            print_ai_message(answer)
        except Exception as e:
            print_error(f"Chat error: {e}")
        return

    def _callback(event: str, data):
        if event == "plan_created":
            print_orchestrator_plan(data)
        elif event == "phase_start":
            phase = data.get("phase", "")
            if phase == "parallel":
                tasks = data.get("tasks", [])
                agents = ", ".join(t["agent"] for t in tasks)
                print_info(f"Starting parallel phase: {agents}")
            elif phase == "sequential":
                task = data.get("task", {})
                print_info(f"Starting: {task.get('agent', 'unknown')} — {task.get('task', '')[:60]}")

    try:
        console.print("[bold cyan]🎯 Orchestrator analyzing task and creating execution plan...[/]")
        results = orchestrator.plan_and_execute(user_input, callback=_callback)

        console.print()
        console.print("[bold cyan]═══ Orchestrator Results ═══[/]")
        for result in results:
            print_sub_agent_result(result)

        # Show final progress
        from apk_agent.progress import progress_manager
        summary = progress_manager.get_summary()
        if summary["total"] > 0:
            print_progress_summary(summary)

    except KeyboardInterrupt:
        print_warning("Orchestrator interrupted by user.")
    except Exception as e:
        err_str = str(e).lower()
        if "403" in err_str and ("api key limit" in err_str or "forbidden" in err_str):
            print_error("API quota exhausted. Top up your API credits or wait for reset.")
        elif "429" in err_str or "rate_limit" in err_str:
            print_error("Rate limited by API. Wait a moment and try again.")
        elif "401" in err_str or "auth" in err_str:
            print_error("Authentication failed. Check your API key.")
        else:
            print_error(f"Orchestrator error: {e}")
            import traceback
            traceback.print_exc()


def _process_stream_event(event: dict, graph, graph_config: dict, *, auto_mode: bool = False) -> dict | None:
    """Process a single stream event from the LangGraph agent.

    Returns None normally, or a dict with interrupt info:
        {"interrupt": True, "response": "<user response>"}
    The caller must handle the interrupt by resuming graph.stream().
    """
    from apk_agent.ui import print_tool_start

    for node_name, node_output in event.items():
        if node_name == "agent":
            # Agent node produced messages
            messages = node_output.get("messages", [])
            for msg in messages:
                if isinstance(msg, AIMessage):
                    # Track token usage from response metadata
                    usage = getattr(msg, "usage_metadata", None) or getattr(msg, "response_metadata", {}).get("token_usage", {})
                    if usage:
                        prompt_t = usage.get("input_tokens", 0) or usage.get("prompt_tokens", 0)
                        compl_t = usage.get("output_tokens", 0) or usage.get("completion_tokens", 0)
                        # Z.AI reports cached tokens in prompt_tokens_details
                        cached_t = 0
                        if isinstance(usage, dict):
                            ptd = usage.get("prompt_tokens_details") or {}
                            cached_t = ptd.get("cached_tokens", 0)
                        elif hasattr(usage, "get"):
                            ptd = usage.get("prompt_tokens_details") or {}
                            cached_t = ptd.get("cached_tokens", 0)
                        if prompt_t or compl_t:
                            token_tracker.record_call(prompt_t, compl_t, cached_t)
                            live_bar.update()

                    # Print text content
                    if msg.content and isinstance(msg.content, str) and msg.content.strip():
                        print_ai_message(msg.content)
                    # Show tool calls being made with args summary
                    if msg.tool_calls:
                        n_calls = len(msg.tool_calls)
                        if n_calls > 1:
                            console.print(f"[dim]  ⚡ {n_calls} tools in parallel[/]")
                        for tc in msg.tool_calls:
                            args = tc.get("args", {})
                            arg_summary = ""
                            if args:
                                parts = []
                                for k, v in list(args.items())[:2]:
                                    v_str = str(v)[:40]
                                    parts.append(f"{k}={v_str}")
                                arg_summary = ", ".join(parts)
                            print_tool_start(tc['name'], arg_summary)
                            token_tracker.set_active_tool(tc['name'])
                            live_bar.update()

        elif node_name == "tools":
            # Tool node produced results
            messages = node_output.get("messages", [])
            for msg in messages:
                if isinstance(msg, ToolMessage):
                    token_tracker.clear_active_tool()
                    live_bar.update()
                    # Better success detection
                    content_start = msg.content[:100].lower()
                    success = (
                        '"success": false' not in content_start
                        and "❌" not in content_start
                        and '"error"' not in content_start[:50]
                    )
                    print_tool_output(msg.name or "tool", msg.content, success=success)

                    # Show task plan whenever it changes
                    if msg.name in ("update_task_plan", "mark_task_done", "edit_task_plan"):
                        try:
                            from apk_agent.agent.tools_def import _get_task_plan
                            from apk_agent.ui import print_task_plan
                            plan = _get_task_plan()
                            if plan:
                                print_task_plan(plan)
                        except Exception:
                            pass

        elif node_name == "human_review":
            pass

        elif node_name == "nudge":
            # Agent announced intent without calling tools — auto-nudging
            console.print("[dim]⚡ Auto-nudging agent to execute tools...[/]")

        elif node_name == "__interrupt__":
            # Signal interrupt back to caller — do NOT start graph.stream() here.
            # The caller handles resume in a flat loop to avoid nested SQLite locks.
            live_bar.stop()
            interrupts = node_output
            if isinstance(interrupts, (list, tuple)):
                for intr in interrupts:
                    value = intr.value if hasattr(intr, 'value') else str(intr)

                    if auto_mode:
                        value_str = str(value)
                        if "❓" in value_str:
                            human_response = "Proceed with your best judgment."
                            console.print("[dim]⚡ Auto-mode: agent question auto-answered[/]")
                        else:
                            human_response = "yes"
                            console.print("[dim]⚡ Auto-mode: patch auto-approved[/]")
                    else:
                        print_hitl_prompt(str(value))
                        human_response = console.input("[bold magenta]Your response: [/]").strip()

                    return {"interrupt": True, "response": human_response}

    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()
