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
import os
import sqlite3
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from langgraph.checkpoint.sqlite import SqliteSaver

logger = logging.getLogger("apk_agent.session")

_CORRUPT_CHECKPOINT_DIR = "corrupt_checkpoints"


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
    human_mode: bool = False
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
    meta_exists = _meta_path(project_path).is_file()
    db_exists = _db_path(project_path).is_file()
    if not meta_exists or not db_exists:
        return False
    quarantined = _repair_malformed_checkpoint_db(_db_path(project_path))
    return not quarantined and _db_path(project_path).is_file()


def delete_session(project_path: str | Path) -> None:
    """Delete a project's session data (start fresh)."""
    import shutil
    sdir = _session_dir(project_path)
    if sdir.is_dir():
        shutil.rmtree(sdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Active session — workspace-level shared state between CLI & Telegram
# ---------------------------------------------------------------------------

_ACTIVE_SESSION_FILE = ".active_session.json"


@dataclass
class ActiveSession:
    """Tracks which project is currently active across ALL interfaces.

    Stored at ``<workspace_root>/.active_session.json`` so both the CLI
    process and the Telegram bot process can see the same state.
    """

    project_id: str
    apk_name: str = ""
    started_by: str = ""          # "cli" | "telegram"
    started_at: str = ""
    status: str = "idle"          # idle | running | completed
    phase: str = ""               # current high-level phase
    last_tool: str = ""           # last tool that ran
    pid: int = 0                  # OS process ID of the owner
    workspace_root: str = ""      # absolute path to workspace — for cross-process lookup


def _active_session_path(workspace_root: str | Path) -> Path:
    return Path(workspace_root) / _ACTIVE_SESSION_FILE


def save_active_session(workspace_root: str | Path, active: ActiveSession) -> None:
    """Atomically write the active session file."""
    target = _active_session_path(workspace_root)
    tmp = target.with_suffix(".tmp")
    tmp.write_text(
        json.dumps(asdict(active), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    tmp.replace(target)  # atomic on same filesystem


def load_active_session(workspace_root: str | Path) -> ActiveSession | None:
    """Load the active session.  Returns None if no session file or stale."""
    p = _active_session_path(workspace_root)
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        import dataclasses as _dc
        valid = {f.name for f in _dc.fields(ActiveSession)}
        filtered = {k: v for k, v in data.items() if k in valid}
        active = ActiveSession(**filtered)
        # Check if the owning process is still alive
        if active.pid and not _pid_alive(active.pid):
            active.status = "idle"
            active.phase = "owner process exited"
        return active
    except Exception as e:
        logger.warning("Failed to load active session: %s", e)
        return None


def clear_active_session(workspace_root: str | Path) -> None:
    """Remove the active session file."""
    p = _active_session_path(workspace_root)
    try:
        p.unlink(missing_ok=True)
    except OSError:
        pass


def update_active_session(workspace_root: str | Path, **fields) -> None:
    """Update specific fields of the active session without rewriting everything."""
    active = load_active_session(workspace_root)
    if active is None:
        return
    for k, v in fields.items():
        if hasattr(active, k):
            setattr(active, k, v)
    save_active_session(workspace_root, active)


def _pid_alive(pid: int) -> bool:
    """Check if a process with the given PID is still running (cross-platform)."""
    if not pid:
        return False
    try:
        if os.name == "nt":
            # Windows: use ctypes to check without side effects
            import ctypes
            kernel32 = ctypes.windll.kernel32
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if handle:
                kernel32.CloseHandle(handle)
                return True
            return False
        else:
            os.kill(pid, 0)
            return True
    except (OSError, ProcessLookupError, PermissionError):
        return False


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


def _is_malformed_db_error(exc: BaseException) -> bool:
    if not isinstance(exc, sqlite3.DatabaseError):
        return False
    message = str(exc).lower()
    return (
        "database disk image is malformed" in message
        or "file is not a database" in message
        or "malformed" in message
    )


def _open_checkpoint_connection(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), check_same_thread=False, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _quarantine_checkpoint_files(db_path: str | Path) -> list[Path]:
    source = Path(db_path)
    if not source.parent.exists():
        return []

    quarantine_dir = source.parent / _CORRUPT_CHECKPOINT_DIR
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    moved: list[Path] = []

    for candidate in (source, Path(str(source) + "-wal"), Path(str(source) + "-shm")):
        if not candidate.exists():
            continue
        destination = quarantine_dir / f"{stamp}_{candidate.name}"
        counter = 1
        while destination.exists():
            destination = quarantine_dir / f"{stamp}_{counter}_{candidate.name}"
            counter += 1
        candidate.replace(destination)
        moved.append(destination)

    return moved


def _repair_malformed_checkpoint_db(db_path: str | Path) -> list[Path]:
    db_file = Path(db_path)
    if not db_file.is_file():
        return []

    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(str(db_file), check_same_thread=False, timeout=5)
        row = conn.execute("PRAGMA quick_check(1)").fetchone()
        status = str(row[0]).strip().lower() if row else ""
        if status == "ok":
            return []
        logger.warning("Checkpoint DB integrity check failed for %s: %s", db_file, status or "unknown error")
    except sqlite3.DatabaseError as exc:
        if not _is_malformed_db_error(exc):
            raise
        logger.warning("Checkpoint DB is malformed for %s: %s", db_file, exc)
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass

    return _quarantine_checkpoint_files(db_file)


class _ResilientSqliteSaver(SqliteSaver):
    """SqliteSaver that recreates a clean checkpoint DB on corruption once."""

    def __init__(self, db_path: str | Path):
        self._db_path = Path(db_path)
        super().__init__(_RetryConnection(_open_checkpoint_connection(self._db_path)))

    def _recover_from_malformed_db(self, exc: sqlite3.DatabaseError) -> None:
        try:
            self.conn.close()
        except OSError:
            pass
        quarantined = _quarantine_checkpoint_files(self._db_path)
        logger.warning(
            "Recovered malformed checkpoint DB at %s after SQLite error: %s. Quarantined files: %s",
            self._db_path,
            exc,
            [str(path) for path in quarantined],
        )
        self.conn = _RetryConnection(_open_checkpoint_connection(self._db_path))
        self.is_setup = False

    def _run_with_recovery(self, operation):
        try:
            return operation()
        except sqlite3.DatabaseError as exc:
            if not _is_malformed_db_error(exc):
                raise
            self._recover_from_malformed_db(exc)
            return operation()

    def get_tuple(self, config):
        parent_get_tuple = super().get_tuple
        return self._run_with_recovery(lambda: parent_get_tuple(config))

    def list(self, config, *, filter=None, before=None, limit=None) -> Iterator:
        parent_list = super().list
        items = self._run_with_recovery(
            lambda: list(parent_list(config, filter=filter, before=before, limit=limit))
        )
        yield from items

    def put(self, config, checkpoint, metadata, new_versions):
        parent_put = super().put
        return self._run_with_recovery(
            lambda: parent_put(config, checkpoint, metadata, new_versions)
        )

    def put_writes(self, config, writes, task_id, task_path=""):
        parent_put_writes = super().put_writes
        return self._run_with_recovery(
            lambda: parent_put_writes(config, writes, task_id, task_path)
        )

    def delete_thread(self, thread_id: str) -> None:
        parent_delete_thread = super().delete_thread
        self._run_with_recovery(lambda: parent_delete_thread(thread_id))


def get_sqlite_checkpointer(project_path: str | Path):
    """Create a LangGraph SqliteSaver backed by the project's session DB.

    The returned saver persists checkpoints to:
        <project_path>/session/checkpoints.db

    This allows the conversation to resume from exactly where it stopped.
    """
    sdir = _session_dir(project_path)
    sdir.mkdir(parents=True, exist_ok=True)
    db_file = _db_path(project_path)

    quarantined = _repair_malformed_checkpoint_db(db_file)
    if quarantined:
        logger.warning(
            "Recovered corrupt checkpoint DB for %s before opening session. Quarantined files: %s",
            db_file,
            [str(path) for path in quarantined],
        )

    saver = _ResilientSqliteSaver(db_file)
    saver.setup()  # create tables if needed
    return saver


# ---------------------------------------------------------------------------
# Conversation history export (for compact summaries)
# ---------------------------------------------------------------------------


def _message_content_to_text(content: Any) -> str:
    """Normalize LangChain message content to readable plain text.

    Providers may return content as either a string or a list of content
    blocks. The compactor needs a stable text export for both forms.
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                if block.strip():
                    parts.append(block)
                continue
            if not isinstance(block, dict):
                continue
            text = (
                block.get("text")
                or block.get("thinking")
                or block.get("reasoning")
                or ""
            )
            if str(text).strip():
                parts.append(str(text))
        return "\n".join(parts)
    return str(content or "")


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
            content = _message_content_to_text(msg.content)
            if content.strip():
                lines.append(f"[USER]: {content}")
        elif isinstance(msg, AIMessage):
            text = _message_content_to_text(msg.content)
            if msg.tool_calls:
                tools = ", ".join(tc["name"] for tc in msg.tool_calls)
                text += f" [called tools: {tools}]"
            if text.strip():
                lines.append(f"[ASSISTANT]: {text}")
        elif isinstance(msg, ToolMessage):
            # Truncate long tool outputs
            content = _message_content_to_text(msg.content)
            if len(content) > 500:
                content = content[:250] + "\n...[truncated]...\n" + content[-250:]
            lines.append(f"[TOOL {msg.name}]: {content}")
    return "\n".join(lines)
