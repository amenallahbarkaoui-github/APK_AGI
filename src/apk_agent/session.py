"""Session persistence — save and restore agent sessions per project.

Each project gets a persistent session stored as:
    <project_dir>/session/session.json   — metadata (thread_id, timestamps, etc.)
    <project_dir>/session/checkpoints.db — SQLite LangGraph checkpoints

When the user restarts the app and picks the same project, the session
is auto-restored with full conversation history.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("apk_agent.session")


@dataclass
class SessionMeta:
    """Metadata for a persistent session."""

    thread_id: str
    project_id: str
    created_at: str = ""
    last_active_at: str = ""
    message_count: int = 0
    compact_count: int = 0  # how many times auto-compact has run
    last_user_input: str = ""
    orchestrator_mode: bool = False
    auto_mode: bool = False
    status: str = "active"  # active | paused | completed

    def touch(self) -> None:
        """Update last_active_at to now."""
        self.last_active_at = datetime.now(timezone.utc).isoformat()


def _session_dir(project_path: str | Path) -> Path:
    """Return the session directory for a project."""
    return Path(project_path) / "session"


def _meta_path(project_path: str | Path) -> Path:
    return _session_dir(project_path) / "session.json"


def _db_path(project_path: str | Path) -> Path:
    return _session_dir(project_path) / "checkpoints.db"


# ---------------------------------------------------------------------------
# Save / Load session metadata
# ---------------------------------------------------------------------------


def save_session_meta(meta: SessionMeta, project_path: str | Path) -> None:
    """Persist session metadata to disk."""
    sdir = _session_dir(project_path)
    sdir.mkdir(parents=True, exist_ok=True)
    _meta_path(project_path).write_text(
        json.dumps(asdict(meta), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def load_session_meta(project_path: str | Path) -> Optional[SessionMeta]:
    """Load session metadata from disk.  Returns None if no session exists."""
    mp = _meta_path(project_path)
    if not mp.is_file():
        return None
    try:
        data = json.loads(mp.read_text(encoding="utf-8"))
        # Backwards compatibility: strip unknown fields and apply defaults
        # for fields added after initial release (e.g. auto_mode)
        import dataclasses
        valid_fields = {f.name for f in dataclasses.fields(SessionMeta)}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return SessionMeta(**filtered)
    except Exception as e:
        logger.warning("Failed to load session meta: %s", e)
        return None


def has_session(project_path: str | Path) -> bool:
    """Check whether a project has a saved session."""
    return _meta_path(project_path).is_file() and _db_path(project_path).is_file()


def delete_session(project_path: str | Path) -> None:
    """Delete a project's session data (start fresh)."""
    import shutil
    sdir = _session_dir(project_path)
    if sdir.is_dir():
        shutil.rmtree(sdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# SQLite checkpointer helpers
# ---------------------------------------------------------------------------


def get_sqlite_checkpointer(project_path: str | Path):
    """Create a LangGraph SqliteSaver backed by the project's session DB.

    The returned saver persists checkpoints to:
        <project_path>/session/checkpoints.db

    This allows the conversation to resume from exactly where it stopped.
    """
    from langgraph.checkpoint.sqlite import SqliteSaver

    sdir = _session_dir(project_path)
    sdir.mkdir(parents=True, exist_ok=True)
    db_file = str(_db_path(project_path))

    conn = sqlite3.connect(db_file, check_same_thread=False)
    saver = SqliteSaver(conn)
    saver.setup()  # create tables if needed
    return saver


# ---------------------------------------------------------------------------
# Conversation history export (for compact summaries)
# ---------------------------------------------------------------------------


def export_messages_text(messages: list) -> str:
    """Convert a list of LangChain messages to a readable text log.

    Used by the compactor to build a summary prompt.
    """
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

    lines: list[str] = []
    for msg in messages:
        if isinstance(msg, SystemMessage):
            continue  # skip system prompt in export
        elif isinstance(msg, HumanMessage):
            lines.append(f"[USER]: {msg.content}")
        elif isinstance(msg, AIMessage):
            text = msg.content or ""
            if msg.tool_calls:
                tools = ", ".join(tc["name"] for tc in msg.tool_calls)
                text += f" [called tools: {tools}]"
            if text.strip():
                lines.append(f"[ASSISTANT]: {text}")
        elif isinstance(msg, ToolMessage):
            # Truncate long tool outputs
            content = str(msg.content)
            if len(content) > 500:
                content = content[:250] + "\n...[truncated]...\n" + content[-250:]
            lines.append(f"[TOOL {msg.name}]: {content}")
    return "\n".join(lines)
