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
    thinking_mode: bool = True  # whether LLM deep thinking is enabled
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


class _RetryConnection:
    """Wrapper around sqlite3.Connection that retries on WinError 32.

    On Windows, antivirus / file indexer / VSCode can briefly lock the
    .db / .db-wal files.  SQLite's ``busy_timeout`` only handles
    SQLite-level locks, not OS-level ``ERROR_SHARING_VIOLATION`` (32).
    This wrapper intercepts ``execute``, ``executemany``, and ``commit``
    and retries with back-off on that specific error.
    """

    _MAX_RETRIES = 5
    _BASE_DELAY = 0.15  # seconds

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    # Forward all attribute access to the real connection
    def __getattr__(self, name):
        return getattr(self._conn, name)

    # ── Context manager must return *self* (the wrapper), not the real conn ──
    def __enter__(self):
        self._conn.__enter__()
        return self  # critical: keeps wrapper in scope for execute/commit

    def __exit__(self, *args):
        return self._conn.__exit__(*args)

    def _retry(self, method, *args, **kwargs):
        import time
        for attempt in range(self._MAX_RETRIES):
            try:
                return method(*args, **kwargs)
            except OSError as e:
                if getattr(e, "winerror", 0) == 32 and attempt < self._MAX_RETRIES - 1:
                    time.sleep(self._BASE_DELAY * (attempt + 1))
                else:
                    raise

    def execute(self, *args, **kwargs):
        return self._retry(self._conn.execute, *args, **kwargs)

    def executemany(self, *args, **kwargs):
        return self._retry(self._conn.executemany, *args, **kwargs)

    def executescript(self, *args, **kwargs):
        return self._retry(self._conn.executescript, *args, **kwargs)

    def commit(self):
        return self._retry(self._conn.commit)

    def rollback(self):
        return self._retry(self._conn.rollback)

    def close(self):
        return self._conn.close()

    def cursor(self):
        """Return a cursor whose execute/executemany also retry."""
        real_cursor = self._conn.cursor()
        return _RetryCursor(real_cursor, self._MAX_RETRIES, self._BASE_DELAY)


class _RetryCursor:
    """Cursor wrapper that retries execute calls on WinError 32."""

    def __init__(self, cursor, max_retries: int, base_delay: float):
        self._cursor = cursor
        self._max = max_retries
        self._delay = base_delay

    def __getattr__(self, name):
        return getattr(self._cursor, name)

    def __iter__(self):
        return iter(self._cursor)

    def _retry(self, method, *args, **kwargs):
        import time
        for attempt in range(self._max):
            try:
                return method(*args, **kwargs)
            except OSError as e:
                if getattr(e, "winerror", 0) == 32 and attempt < self._max - 1:
                    time.sleep(self._delay * (attempt + 1))
                else:
                    raise

    def execute(self, *args, **kwargs):
        return self._retry(self._cursor.execute, *args, **kwargs)

    def executemany(self, *args, **kwargs):
        return self._retry(self._cursor.executemany, *args, **kwargs)


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

    conn = sqlite3.connect(db_file, check_same_thread=False, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")       # WAL mode prevents WinError 32 file locks
    conn.execute("PRAGMA busy_timeout=5000")      # wait up to 5s if DB is locked
    conn.execute("PRAGMA synchronous=NORMAL")     # safe with WAL, reduces fsync contention

    # Wrap with retry logic for OS-level file locks (Windows antivirus/indexer)
    wrapped = _RetryConnection(conn)
    saver = SqliteSaver(wrapped)
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
