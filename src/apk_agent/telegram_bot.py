"""Telegram bot bridge for APK Agent.

Runs as a separate process so the Telegram workflow can reuse the same agent
engine and persistent sessions without colliding with the interactive CLI's
module-level graph/tool globals.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import click
import httpx
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langgraph.types import Command

from apk_agent.config import AppConfig
from apk_agent.parallelism import build_langgraph_run_config
from apk_agent.session import (
    SessionMeta,
    get_sqlite_checkpointer,
    load_active_session,
    load_session_meta,
    save_active_session,
    save_session_meta,
    update_active_session,
)
from apk_agent.workspace import Project, ProjectManager, get_final_artifact_path

logger = logging.getLogger("apk_agent.telegram")

_PROCESS_STATUS_FILE = ".telegram-bot-process.json"
_LOCK_FILE = ".telegram-bot.lock"
_STATE_FILE = ".telegram-bot-state.json"
_MAX_TEXT_CHARS = 3500
_MAX_DOWNLOADABLE_TELEGRAM_FILE_BYTES = 20 * 1_000_000
_MAX_SENDABLE_DOCUMENT_BYTES = 49 * 1024 * 1024
_MAX_STATUS_EVENTS = 8
_STATUS_TEXT_LIMIT = 3900
_OUTBOUND_DEDUPE_WINDOW_SEC = 6.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        handlers=[logging.StreamHandler()],
    )


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def _pid_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        # os.kill(pid, 0) can hang on Windows — use ctypes instead
        import ctypes
        kernel32 = ctypes.windll.kernel32
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        kernel32.CloseHandle(handle)
        return True
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _status_file(workspace_root: Path) -> Path:
    return workspace_root / _PROCESS_STATUS_FILE


def _lock_file(workspace_root: Path) -> Path:
    return workspace_root / _LOCK_FILE


def _state_file(workspace_root: Path) -> Path:
    return workspace_root / _STATE_FILE


def _read_process_status(workspace_root: Path) -> dict[str, Any]:
    path = _status_file(workspace_root)
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _write_process_status(workspace_root: Path, payload: dict[str, Any]) -> None:
    path = _status_file(workspace_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _read_lock_pid(lock_path: Path) -> int:
    if not lock_path.is_file():
        return 0
    try:
        return int(lock_path.read_text(encoding="utf-8").strip() or 0)
    except Exception:
        return 0


def _active_bridge_pid(workspace_root: Path) -> int:
    lock_pid = _read_lock_pid(_lock_file(workspace_root))
    if lock_pid and _pid_is_alive(lock_pid):
        return lock_pid

    status = _read_process_status(workspace_root)
    status_pid = int(status.get("pid", 0) or 0)
    if status_pid and _pid_is_alive(status_pid):
        return status_pid
    return 0


@dataclass
class TelegramProcessLock:
    path: Path
    fd: int
    owner_pid: int

    def release(self) -> None:
        try:
            os.close(self.fd)
        except OSError:
            pass

        try:
            if _read_lock_pid(self.path) == self.owner_pid:
                self.path.unlink(missing_ok=True)
        except Exception:
            pass


def _acquire_process_lock(workspace_root: Path) -> TelegramProcessLock:
    lock_path = _lock_file(workspace_root)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR

    while True:
        try:
            fd = os.open(str(lock_path), flags)
        except FileExistsError:
            existing_pid = _read_lock_pid(lock_path)
            if existing_pid and _pid_is_alive(existing_pid):
                raise RuntimeError(f"Telegram bridge already running (PID {existing_pid}).")
            try:
                lock_path.unlink()
            except FileNotFoundError:
                continue
            except PermissionError as exc:
                active_pid = _active_bridge_pid(workspace_root)
                if active_pid and _pid_is_alive(active_pid):
                    raise RuntimeError(f"Telegram bridge already running (PID {active_pid}).") from exc
                raise RuntimeError("Telegram bridge already running (lock file is in use).") from exc
            except OSError as exc:
                raise RuntimeError(f"Could not clear stale Telegram lock: {exc}") from exc
            continue
        break

    os.write(fd, str(os.getpid()).encode("utf-8"))
    return TelegramProcessLock(path=lock_path, fd=fd, owner_pid=os.getpid())


def ensure_telegram_bot_running(config: AppConfig, *, verbose: bool = False) -> tuple[bool, str]:
    """Ensure the Telegram bot bridge background process is running."""
    if not config.telegram_enabled:
        return False, "Telegram bridge is not configured."

    pid = _active_bridge_pid(config.workspace_path)
    if pid and _pid_is_alive(pid):
        return False, f"Telegram bridge already running (PID {pid})."

    log_path = config.workspace_path / "telegram-bot.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_handle = open(log_path, "a", encoding="utf-8")

    creationflags = 0
    if sys.platform.startswith("win"):
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

    process = subprocess.Popen(
        [sys.executable, "-m", "apk_agent.telegram_bot", "--run"],
        cwd=str(_repo_root()),
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        creationflags=creationflags,
        env={**os.environ, "WORKSPACE_ROOT": str(config.workspace_path)},
    )

    _write_process_status(
        config.workspace_path,
        {
            "pid": process.pid,
            "started_at": _now_iso(),
            "workspace_root": str(config.workspace_path),
            "status": "starting",
        },
    )
    return True, f"Telegram bridge started in background (PID {process.pid})."


@dataclass
class TelegramChatState:
    current_project_id: str = ""
    auto_mode: bool = False
    human_mode: bool = False
    pending_interrupt: bool = False
    awaiting_mode_choice: bool = False
    busy: bool = False
    last_artifact_path: str = ""
    last_artifact_mtime: float = 0.0
    status_message_id: int = 0
    status_text: str = ""
    status_recent_events: list[str] = field(default_factory=list)
    # Progress tracking
    task_start_time: float = 0.0
    tools_run: int = 0
    tools_failed: int = 0
    findings_count: int = 0
    patches_count: int = 0
    current_phase: str = ""
    last_tool_name: str = ""
    # Token tracking
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cached_tokens: int = 0


class TelegramStateStore:
    """Small JSON store for chat-local Telegram bridge state."""

    def __init__(self, workspace_root: Path):
        self._path = _state_file(workspace_root)
        self._lock = threading.Lock()
        self._data = self._load()

    def _load(self) -> dict[str, Any]:
        if not self._path.is_file():
            return {"last_update_id": 0, "chats": {}}
        try:
            return json.loads(self._path.read_text(encoding="utf-8"))
        except Exception:
            return {"last_update_id": 0, "chats": {}}

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps(self._data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def get_last_update_id(self) -> int:
        with self._lock:
            return int(self._data.get("last_update_id", 0) or 0)

    def set_last_update_id(self, update_id: int) -> None:
        with self._lock:
            self._data["last_update_id"] = update_id
            self._save()

    def get_chat(self, chat_id: int, _default_thinking: bool = True) -> TelegramChatState:
        with self._lock:
            raw = (self._data.get("chats") or {}).get(str(chat_id)) or {}
            if not raw:
                return TelegramChatState()
            return TelegramChatState(
                current_project_id=raw.get("current_project_id", ""),
                auto_mode=raw.get("auto_mode", False),
                human_mode=raw.get("human_mode", False),
                pending_interrupt=raw.get("pending_interrupt", False),
                awaiting_mode_choice=raw.get("awaiting_mode_choice", False),
                busy=raw.get("busy", False),
                last_artifact_path=raw.get("last_artifact_path", ""),
                last_artifact_mtime=float(raw.get("last_artifact_mtime", 0.0) or 0.0),
                status_message_id=int(raw.get("status_message_id", 0) or 0),
                status_text=str(raw.get("status_text", "") or ""),
                status_recent_events=list(raw.get("status_recent_events", []) or [])[-_MAX_STATUS_EVENTS:],
                task_start_time=float(raw.get("task_start_time", 0.0) or 0.0),
                tools_run=int(raw.get("tools_run", 0) or 0),
                tools_failed=int(raw.get("tools_failed", 0) or 0),
                findings_count=int(raw.get("findings_count", 0) or 0),
                patches_count=int(raw.get("patches_count", 0) or 0),
                current_phase=str(raw.get("current_phase", "") or ""),
                last_tool_name=str(raw.get("last_tool_name", "") or ""),
                prompt_tokens=int(raw.get("prompt_tokens", 0) or 0),
                completion_tokens=int(raw.get("completion_tokens", 0) or 0),
                cached_tokens=int(raw.get("cached_tokens", 0) or 0),
            )

    def save_chat(self, chat_id: int, state: TelegramChatState) -> None:
        with self._lock:
            chats = self._data.setdefault("chats", {})
            chats[str(chat_id)] = asdict(state)
            self._save()


class TelegramApi:
    """Thin wrapper over the Telegram Bot HTTP API."""

    def __init__(self, token: str, *, poll_timeout_sec: int = 30):
        self._token = token
        self._poll_timeout_sec = poll_timeout_sec
        self._client = httpx.Client(timeout=httpx.Timeout(20.0, read=max(60.0, poll_timeout_sec + 10.0)))
        self._base_url = f"https://api.telegram.org/bot{token}"

    def close(self) -> None:
        self._client.close()

    def _request(self, method: str, *, json_body: dict[str, Any] | None = None, data: dict[str, Any] | None = None, files: dict[str, Any] | None = None, timeout: float | None = None) -> Any:
        response = self._client.post(
            f"{self._base_url}/{method}",
            json=json_body,
            data=data,
            files=files,
            timeout=timeout,
        )
        payload: dict[str, Any] | None
        try:
            payload = response.json()
        except ValueError:
            payload = None

        if payload is not None:
            if response.is_error or not payload.get("ok"):
                error_code = payload.get("error_code", response.status_code)
                description = payload.get("description") or response.reason_phrase or f"Telegram API error in {method}"
                raise RuntimeError(f"Telegram API {method} failed ({error_code}): {description}")
            return payload.get("result")

        response.raise_for_status()
        raise RuntimeError(f"Telegram API {method} returned a non-JSON response.")

    def get_me(self) -> dict[str, Any]:
        return self._request("getMe", json_body={})

    def get_updates(self, offset: int, timeout_sec: int) -> list[dict[str, Any]]:
        return self._request(
            "getUpdates",
            json_body={
                "offset": offset,
                "timeout": timeout_sec,
                "allowed_updates": ["message"],
            },
            timeout=timeout_sec + 15,
        )

    def send_message(self, chat_id: int, text: str, *, reply_markup: dict[str, Any] | None = None, disable_notification: bool = False) -> dict[str, Any] | None:
        last_result: dict[str, Any] | None = None
        for chunk in _chunk_text(text):
            body: dict[str, Any] = {
                "chat_id": chat_id,
                "text": chunk,
                "disable_web_page_preview": True,
            }
            if reply_markup:
                body["reply_markup"] = reply_markup
            if disable_notification:
                body["disable_notification"] = True
            last_result = self._request("sendMessage", json_body=body)
        return last_result

    def edit_message_text(self, chat_id: int, message_id: int, text: str) -> Any:
        return self._request(
            "editMessageText",
            json_body={
                "chat_id": chat_id,
                "message_id": message_id,
                "text": text,
                "disable_web_page_preview": True,
            },
        )

    def send_chat_action(self, chat_id: int, action: str) -> Any:
        return self._request(
            "sendChatAction",
            json_body={
                "chat_id": chat_id,
                "action": action,
            },
        )

    def send_document(self, chat_id: int, file_path: Path, *, caption: str = "") -> None:
        with file_path.open("rb") as handle:
            data = {"chat_id": str(chat_id)}
            if caption:
                data["caption"] = caption[:1024]
            self._request(
                "sendDocument",
                data=data,
                files={"document": (file_path.name, handle)},
                timeout=120,
            )

    def get_file(self, file_id: str) -> dict[str, Any]:
        return self._request("getFile", json_body={"file_id": file_id})

    def download_file(self, telegram_path: str, dest: Path) -> None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        response = self._client.get(
            f"https://api.telegram.org/file/bot{self._token}/{telegram_path}",
            timeout=120,
        )
        response.raise_for_status()
        dest.write_bytes(response.content)


def _chunk_text(text: str, limit: int = _MAX_TEXT_CHARS) -> list[str]:
    text = str(text or "").strip()
    if not text:
        return []
    if len(text) <= limit:
        return [text]

    chunks: list[str] = []
    remaining = text
    while remaining:
        if len(remaining) <= limit:
            chunks.append(remaining)
            break
        split_at = remaining.rfind("\n", 0, limit)
        if split_at < limit // 2:
            split_at = remaining.rfind(" ", 0, limit)
        if split_at < limit // 2:
            split_at = limit
        chunks.append(remaining[:split_at].rstrip())
        remaining = remaining[split_at:].lstrip()
    return chunks


def _shorten(text: str, *, max_chars: int = 160) -> str:
    normalized = " ".join(str(text or "").split())
    if len(normalized) <= max_chars:
        return normalized
    return normalized[: max_chars - 3].rstrip() + "..."


def _summarize_tool_content(content: str, *, max_chars: int = 1000) -> str:
    content = str(content or "").strip()
    if len(content) <= max_chars:
        return content
    head = content[: max_chars - 120].rstrip()
    return f"{head}\n\n... truncated ..."


def _format_tool_batch(messages: list[ToolMessage]) -> str:
    lines: list[str] = []
    for msg in messages:
        content = str(msg.content or "")
        lower = content[:160].lower()
        success = '"success": false' not in lower and '"error"' not in lower[:80]
        icon = "✅" if success else "❌"
        summary = _summarize_tool_content(content, max_chars=700)
        lines.append(f"{icon} {msg.name or 'tool'}\n{summary}")
    return "\n\n".join(lines)


def _phase_icon(headline: str) -> str:
    """Return an emoji icon based on the current phase headline."""
    h = headline.lower()
    if "upload" in h or "receiv" in h:
        return "📥"
    if "download" in h:
        return "⬇️"
    if "import" in h:
        return "📂"
    if "decompil" in h:
        return "🔬"
    if "running" in h or "tool" in h:
        return "⚙️"
    if "analys" in h or "scan" in h:
        return "🔍"
    if "patch" in h:
        return "🩹"
    if "sign" in h or "build" in h:
        return "📝"
    if "complet" in h or "done" in h or "finished" in h:
        return "✅"
    if "fail" in h or "error" in h:
        return "❌"
    if "wait" in h or "idle" in h:
        return "💤"
    if "approv" in h or "auto" in h:
        return "🤖"
    if "queued" in h or "start" in h:
        return "🚀"
    if "nudge" in h:
        return "💡"
    if "busy" in h:
        return "⏳"
    if "setting" in h or "updated" in h:
        return "⚙️"
    if "reset" in h:
        return "🔄"
    return "📡"


def _format_elapsed(seconds: float) -> str:
    """Format elapsed seconds into a human-readable string."""
    seconds = max(0, seconds)
    if seconds < 60:
        return f"{int(seconds)}s"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours = minutes // 60
    mins = minutes % 60
    return f"{hours}h {mins}m"


def _extract_tool_insight(tool_name: str, content: str) -> str:
    """Extract a brief human-readable insight from a tool result."""
    content = str(content or "").strip()
    if not content:
        return ""
    # Try to parse JSON for structured results
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            # Common patterns in tool results
            if "findings" in data and isinstance(data["findings"], list):
                return f"found {len(data['findings'])} items"
            if "classes" in data:
                count = data["classes"] if isinstance(data["classes"], int) else len(data["classes"])
                return f"{count} classes"
            if "matches" in data and isinstance(data["matches"], list):
                return f"{len(data['matches'])} matches"
            if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
                return f"{len(data['vulnerabilities'])} vulns"
            if "graph" in data and isinstance(data["graph"], dict):
                nodes = data["graph"].get("nodes", 0)
                edges = data["graph"].get("edges", 0)
                return f"{nodes} nodes, {edges} edges"
            if "patched" in data:
                return "patch applied" if data.get("success") else "patch failed"
            if data.get("success") is False:
                err = data.get("error", "")
                return f"failed: {_shorten(str(err), max_chars=60)}" if err else "failed"
            if data.get("success") is True:
                return "success"
    except (json.JSONDecodeError, TypeError, KeyError):
        pass
    return ""


def _categorize_tools(tool_names: list[str]) -> dict[str, list[str]]:
    """Group tool names into categories for display."""
    categories: dict[str, list[str]] = {}
    for name in tool_names:
        lower = name.lower()
        if any(k in lower for k in ("scan", "vuln", "finding", "detect")):
            cat = "🔍 Analysis"
        elif any(k in lower for k in ("patch", "smali", "bypass")):
            cat = "🩹 Patching"
        elif any(k in lower for k in ("graph", "index", "build")):
            cat = "📊 Indexing"
        elif any(k in lower for k in ("manifest", "component", "resource")):
            cat = "📄 Inspection"
        elif any(k in lower for k in ("sign", "align", "apk")):
            cat = "📦 Packaging"
        elif any(k in lower for k in ("read", "write", "file", "search", "list")):
            cat = "📁 File ops"
        elif any(k in lower for k in ("taint", "flow", "trace", "xref")):
            cat = "🔗 Tracing"
        else:
            cat = "⚙️ Tools"
        categories.setdefault(cat, []).append(name)
    return categories


def _reply_keyboard() -> dict[str, Any]:
    return {
        "keyboard": [
            [{"text": "/status"}, {"text": "/auto on"}, {"text": "/auto off"}],
            [{"text": "/human on"}, {"text": "/human off"}, {"text": "/context"}],
            [{"text": "/new"}, {"text": "/help"}],
        ],
        "resize_keyboard": True,
        "one_time_keyboard": False,
    }


class TelegramBotService:
    """Long-polling Telegram bridge that reuses the agent graph per project/session."""

    def __init__(self, config: AppConfig):
        self.config = config
        self.api = TelegramApi(config.telegram_bot_token, poll_timeout_sec=config.telegram_poll_timeout_sec)
        self.pm = ProjectManager(config.workspace_path)
        self.state_store = TelegramStateStore(config.workspace_path)
        self.allowed_chat_ids = set(config.telegram_allowed_chat_ids)
        self.stop_event = threading.Event()
        self.worker_lock = threading.Lock()
        self.active_chat_id: int | None = None
        self._outbound_lock = threading.Lock()
        self._status_lock = threading.Lock()
        self._recent_messages: dict[tuple[int, str], float] = {}
        self._process_lock: TelegramProcessLock | None = None

    def _load_chat_state(self, chat_id: int) -> TelegramChatState:
        state = self.state_store.get_chat(chat_id, True)
        return self._recover_stale_busy_state(chat_id, state)

    def _recover_stale_busy_state(self, chat_id: int, state: TelegramChatState) -> TelegramChatState:
        """Clear persisted busy state when no Telegram worker actually owns it anymore."""
        if not state.busy:
            return state

        # If this process is still actively serving this chat, keep the busy flag.
        if self.active_chat_id == chat_id and self.worker_lock.locked():
            return state

        active = load_active_session(self.config.workspace_path)
        shared_task_running = bool(
            active
            and active.started_by == "telegram"
            and active.status == "running"
            and (not state.current_project_id or active.project_id == state.current_project_id)
        )
        if shared_task_running:
            return state

        state.busy = False
        state.pending_interrupt = False
        state.task_start_time = 0.0
        state.current_phase = "recovered"
        state.last_tool_name = ""
        self._append_status_event(state, "Recovered stale Telegram task state")
        self.state_store.save_chat(chat_id, state)

        if active and active.started_by == "telegram":
            update_active_session(
                self.config.workspace_path,
                status="idle",
                phase="recovered stale task",
                last_tool="",
            )

        return state

    def _prune_recent_messages(self, now: float) -> None:
        expire_before = now - max(30.0, _OUTBOUND_DEDUPE_WINDOW_SEC * 6)
        stale_keys = [key for key, ts in self._recent_messages.items() if ts < expire_before]
        for key in stale_keys:
            self._recent_messages.pop(key, None)

    def _send_message(
        self,
        chat_id: int,
        text: str,
        *,
        reply_markup: dict[str, Any] | None = None,
        dedupe_key: str | None = None,
        dedupe_window_sec: float = _OUTBOUND_DEDUPE_WINDOW_SEC,
        force: bool = False,
        disable_notification: bool = False,
    ) -> dict[str, Any] | None:
        text = str(text or "").strip()
        if not text:
            return None

        fingerprint_material = dedupe_key or text
        if reply_markup:
            fingerprint_material += "\n" + json.dumps(reply_markup, sort_keys=True, ensure_ascii=False)
        fingerprint = hashlib.sha1(fingerprint_material.encode("utf-8")).hexdigest()
        now = time.monotonic()

        with self._outbound_lock:
            self._prune_recent_messages(now)
            if not force:
                last_sent = self._recent_messages.get((chat_id, fingerprint))
                if last_sent is not None and (now - last_sent) < dedupe_window_sec:
                    return None
            self._recent_messages[(chat_id, fingerprint)] = now

        return self.api.send_message(
            chat_id,
            text,
            reply_markup=reply_markup,
            disable_notification=disable_notification,
        )

    def _send_chat_action(self, chat_id: int, action: str) -> None:
        try:
            self.api.send_chat_action(chat_id, action)
        except Exception as exc:
            logger.debug("Failed to send chat action %s to %s: %s", action, chat_id, exc)

    def _append_status_event(self, state: TelegramChatState, event: str) -> None:
        event = _shorten(event, max_chars=160)
        if not event:
            return
        if state.status_recent_events and state.status_recent_events[-1] == event:
            return
        state.status_recent_events.append(event)
        state.status_recent_events = state.status_recent_events[-_MAX_STATUS_EVENTS:]

    def _build_status_text(self, state: TelegramChatState, headline: str, detail: str = "") -> str:
        lines: list[str] = []

        # Header with phase icon
        phase_icon = _phase_icon(headline)
        lines.append(f"{phase_icon} {headline}")

        # Project info
        if state.current_project_id:
            lines.append(f"📦 Project: {state.current_project_id[:12]}")

        # Elapsed time
        if state.task_start_time > 0 and state.busy:
            elapsed = time.time() - state.task_start_time
            lines.append(f"⏱ Elapsed: {_format_elapsed(elapsed)}")

        # Progress bar (visual)
        if state.tools_run > 0:
            lines.append("")
            lines.append(f"🔧 Tools: {state.tools_run} run" + (f" ({state.tools_failed} failed)" if state.tools_failed else ""))
            if state.findings_count > 0:
                lines.append(f"🔍 Findings: {state.findings_count}")
            if state.patches_count > 0:
                lines.append(f"🩹 Patches: {state.patches_count}")

        # Token usage
        total_tokens = state.prompt_tokens + state.completion_tokens
        if total_tokens > 0:
            lines.append(f"📊 Tokens: {total_tokens:,} (in:{state.prompt_tokens:,} out:{state.completion_tokens:,})"
                         + (f" cached:{state.cached_tokens:,}" if state.cached_tokens else ""))

        # Current tool
        if state.last_tool_name and state.busy:
            lines.append(f"\n⚙️ Current: {state.last_tool_name}")

        # Mode badges
        mode_parts: list[str] = []
        if state.auto_mode:
            mode_parts.append("🤖 Auto")
        if state.human_mode:
            mode_parts.append("🧠 Human")
        if state.busy:
            mode_parts.append("⏳ Working")
        elif state.pending_interrupt:
            mode_parts.append("❓ Awaiting reply")
        else:
            mode_parts.append("💤 Idle")
        lines.append("\n" + " │ ".join(mode_parts))

        # Detail text
        if detail:
            detail_lines = str(detail).strip().splitlines()
            if detail_lines:
                lines.append("")
                for raw_line in detail_lines[:4]:
                    raw_line = raw_line.strip()
                    if raw_line:
                        lines.append(_shorten(raw_line, max_chars=240))

        # Recent activity log
        if state.status_recent_events:
            lines.append("\n📋 Recent:")
            for event in state.status_recent_events[-6:]:
                lines.append(f"  • {event}")

        text = "\n".join(lines)
        if len(text) > _STATUS_TEXT_LIMIT:
            text = text[: _STATUS_TEXT_LIMIT - 3].rstrip() + "..."
        return text

    def _set_status(
        self,
        chat_id: int,
        state: TelegramChatState,
        headline: str,
        detail: str = "",
        *,
        record_event: str | None = None,
        extra_events: list[str] | None = None,
        force_new: bool = False,
    ) -> None:
        with self._status_lock:
            if extra_events:
                for event in extra_events:
                    self._append_status_event(state, event)
            elif record_event:
                self._append_status_event(state, record_event)

            status_text = self._build_status_text(state, headline, detail)
            if state.status_message_id and not force_new and status_text == state.status_text:
                return

            if state.status_message_id and not force_new:
                try:
                    self.api.edit_message_text(chat_id, state.status_message_id, status_text)
                except Exception as exc:
                    lower = str(exc).lower()
                    if "message is not modified" in lower:
                        state.status_text = status_text
                        self.state_store.save_chat(chat_id, state)
                        return
                    logger.debug("Status edit failed for chat %s: %s", chat_id, exc)
                    state.status_message_id = 0

            if not state.status_message_id or force_new:
                result = self._send_message(
                    chat_id,
                    status_text,
                    dedupe_key=f"status:{chat_id}:{hashlib.sha1(status_text.encode('utf-8')).hexdigest()}",
                    force=True,
                    disable_notification=True,
                )
                if result and result.get("message_id"):
                    state.status_message_id = int(result["message_id"])

            state.status_text = status_text
            self.state_store.save_chat(chat_id, state)

    def run_forever(self) -> None:
        try:
            self._process_lock = _acquire_process_lock(self.config.workspace_path)
        except RuntimeError as exc:
            logger.warning("Telegram bridge refused to start: %s", exc)
            return

        me: dict[str, Any] = {}
        final_status = "stopped"
        final_error = ""

        try:
            # Retry get_me() — transient DNS / network failures shouldn't kill the bridge
            for _attempt in range(5):
                try:
                    me = self.api.get_me()
                    break
                except Exception as _net_err:
                    if _attempt >= 4:
                        raise
                    wait = (_attempt + 1) * 5
                    logger.warning(
                        "get_me() failed (attempt %d/5): %s — retrying in %ds",
                        _attempt + 1, _net_err, wait,
                    )
                    time.sleep(wait)
            _write_process_status(
                self.config.workspace_path,
                {
                    "pid": os.getpid(),
                    "started_at": _now_iso(),
                    "status": "running",
                    "username": me.get("username", ""),
                    "workspace_root": str(self.config.workspace_path),
                },
            )
            logger.info("Telegram bridge started as @%s", me.get("username", "unknown"))

            offset = self.state_store.get_last_update_id()
            while not self.stop_event.is_set():
                try:
                    updates = self.api.get_updates(offset, self.config.telegram_poll_timeout_sec)
                    for update in updates:
                        offset = max(offset, int(update["update_id"]) + 1)
                        self.state_store.set_last_update_id(offset)
                        self._handle_update(update)
                except Exception as exc:
                    error_text = str(exc)
                    if "getupdates failed (409)" in error_text.lower():
                        final_status = "conflict"
                        final_error = error_text
                        logger.error("Another Telegram poller is active; stopping current bridge: %s", exc)
                        break
                    logger.exception("Telegram polling error: %s", exc)
                    time.sleep(3)
        finally:
            current_status = _read_process_status(self.config.workspace_path)
            if int(current_status.get("pid", 0) or 0) in {0, os.getpid()}:
                payload = {
                    "pid": os.getpid(),
                    "started_at": current_status.get("started_at", _now_iso()),
                    "status": final_status,
                    "username": me.get("username", current_status.get("username", "")),
                    "workspace_root": str(self.config.workspace_path),
                }
                if final_error:
                    payload["error"] = final_error
                _write_process_status(self.config.workspace_path, payload)

            self.api.close()
            if self._process_lock is not None:
                self._process_lock.release()

    def _handle_update(self, update: dict[str, Any]) -> None:
        message = update.get("message") or {}
        chat = message.get("chat") or {}
        chat_id = int(chat.get("id", 0) or 0)
        if not chat_id:
            return

        if chat_id not in self.allowed_chat_ids:
            try:
                self._send_message(chat_id, "Access denied for this chat.")
            except Exception:
                pass
            return

        if message.get("document"):
            self._handle_document(chat_id, message)
            return

        text = (message.get("text") or "").strip()
        if not text:
            self._send_message(chat_id, "Send an APK/XAPK file or a text command like /help.")
            return

        if text.startswith("/"):
            self._handle_command(chat_id, text)
        else:
            self._handle_text(chat_id, text)

    def _handle_command(self, chat_id: int, text: str) -> None:
        cmd, _, arg = text.partition(" ")
        arg = arg.strip().lower()
        state = self._load_chat_state(chat_id)

        if cmd == "/start":
            self._send_message(
                chat_id,
                "🔬 APK Agent — Android RE & Patching\n\n"
                "📥 Send an APK or XAPK file to start\n"
                "💬 Then describe your task\n\n"
                "Examples:\n"
                "• \"full security audit\"\n"
                "• \"bypass premium and return signed apk\"\n"
                "• \"remove ads and root detection\"\n\n"
                "Commands: /help /status /auto /context /new",
                reply_markup=_reply_keyboard(),
            )
            self._set_status(
                chat_id,
                state,
                "Waiting for APK upload",
                "Send an APK or XAPK file to create a project.",
                record_event="Bridge ready",
            )
            return

        if cmd == "/help":
            self._send_message(
                chat_id,
                "📖 APK Agent Commands\n\n"
                "📊 /status — live progress & stats\n"
                "🤖 /auto on|off — auto-approve mode\n"
                "🧠 /human on|off — step-by-step mode (you guide each action)\n"
                "📐 /context [N] — view/set context window\n"
                "🔄 /new — reset & upload new APK\n\n"
                "Just send an APK file, then describe your task!",
            )
            return

        if cmd == "/new":
            state.current_project_id = ""
            state.pending_interrupt = False
            state.awaiting_mode_choice = False
            state.busy = False
            state.last_artifact_path = ""
            state.last_artifact_mtime = 0.0
            state.status_recent_events = []
            self._set_status(
                chat_id,
                state,
                "Waiting for APK upload",
                "Current project cleared. Send a new APK or XAPK file.",
                record_event="Session reset",
            )
            return

        if cmd == "/status":
            # Fast path: build text and send directly without locking / editing the pinned status
            status_text = self._build_status_text(state, "Current status")

            # Show shared active session (may originate from CLI)
            active = load_active_session(self.config.workspace_path)
            if active:
                src = "CLI" if active.started_by == "cli" else "Telegram"
                status_text += f"\n\n🔗 Active session ({src}):"
                status_text += f"\n📦 Project: {active.project_id[:12]}"
                status_text += f"\n📊 Status: {active.status}"
                if active.phase:
                    status_text += f"\n🏷 Phase: {active.phase}"
                if active.last_tool:
                    status_text += f"\n⚙️ Last tool: {active.last_tool}"

            self._send_message(chat_id, status_text)
            return

        if cmd == "/auto":
            if arg in {"on", "off"}:
                state.auto_mode = arg == "on"
                self._set_status(
                    chat_id,
                    state,
                    "Setting updated",
                    f"Auto mode is now {'ON' if state.auto_mode else 'OFF'}.",
                    record_event=f"Auto mode -> {'ON' if state.auto_mode else 'OFF'}",
                )
            else:
                self._send_message(chat_id, f"Auto mode is {'ON' if state.auto_mode else 'OFF'}. Use /auto on or /auto off.")
            return

        if cmd == "/human":
            if arg in {"on", "off"}:
                state.human_mode = arg == "on"
                if state.human_mode:
                    msg = (
                        "🧠 Human Thinking mode ON\n\n"
                        "You guide each step. The agent executes one action, "
                        "shows you the result, and waits for your next instruction."
                    )
                else:
                    msg = "🧠 Human Thinking mode OFF — agent runs autonomously."
                self._set_status(
                    chat_id,
                    state,
                    "Setting updated",
                    msg,
                    record_event=f"Human mode -> {'ON' if state.human_mode else 'OFF'}",
                )
            else:
                self._send_message(
                    chat_id,
                    f"🧠 Human Thinking mode is {'ON' if state.human_mode else 'OFF'}.\n"
                    "Use /human on or /human off.",
                )
            return

        if cmd == "/context":
            if arg:
                try:
                    val = int(arg)
                    if val <= 0:
                        raise ValueError
                    self.config.context_window = val
                    threshold = int(val * 0.50)
                    self._send_message(
                        chat_id,
                        f"✅ Context window → {val:,} tokens\n"
                        f"Auto-compact at {threshold:,} tokens (50%).",
                    )
                except ValueError:
                    self._send_message(chat_id, "❌ Usage: /context <tokens>\nExample: /context 128000")
            else:
                if self.config.context_window > 0:
                    threshold = int(self.config.context_window * 0.50)
                    self._send_message(
                        chat_id,
                        f"📐 Context window: {self.config.context_window:,} tokens\n"
                        f"Auto-compact at: {threshold:,} tokens (50%)\n\n"
                        "Use /context <tokens> to change.",
                    )
                else:
                    from apk_agent.llm.provider import _FALLBACK_CONTEXT_WINDOW
                    threshold = int(_FALLBACK_CONTEXT_WINDOW * 0.50)
                    self._send_message(
                        chat_id,
                        f"⚠️ Context window not set — using fallback {_FALLBACK_CONTEXT_WINDOW:,} tokens\n"
                        f"Auto-compact at: {threshold:,} tokens (50%)\n\n"
                        "Set it: /context <tokens>\n"
                        "Example: /context 128000",
                    )
            return

        self._send_message(chat_id, "Unknown command. Use /help.")

    def _handle_document(self, chat_id: int, message: dict[str, Any]) -> None:
        state = self._load_chat_state(chat_id)
        if state.busy:
            self._send_message(chat_id, "A task is already running. Wait for it to finish before uploading another APK.")
            return

        doc = message["document"]
        file_name = doc.get("file_name") or f"upload-{doc.get('file_unique_id', 'apk')}.apk"
        suffix = Path(file_name).suffix.lower()
        if suffix not in {".apk", ".xapk"}:
            self._send_message(chat_id, "Only .apk and .xapk files are supported.")
            return

        upload_size = int(doc.get("file_size") or 0)
        if upload_size > _MAX_DOWNLOADABLE_TELEGRAM_FILE_BYTES:
            self._send_message(
                chat_id,
                "Telegram cloud download is limited to 20 MB per file for bots.\n"
                f"`{file_name}` is about {upload_size / (1024 * 1024):.1f} MB, so Telegram will reject getFile before APK Agent can import it.\n"
                "Send a smaller APK/XAPK. Larger Telegram uploads require running the bridge against a local Bot API server instead of the default Telegram cloud API.",
            )
            return

        # -----------------------------------------------------------
        # Check if there's already an active project (from CLI or earlier)
        # If so, import the APK into that project instead of creating new
        # -----------------------------------------------------------
        active = load_active_session(self.config.workspace_path)
        existing_project: Project | None = None
        if active and active.project_id:
            try:
                existing_project = self.pm.open_project(active.project_id)
            except Exception:
                existing_project = None

        chat_upload_dir = self.config.workspace_path / "telegram_uploads" / str(chat_id)
        download_path = chat_upload_dir / file_name

        state.status_recent_events = []
        self._set_status(
            chat_id,
            state,
            "Receiving APK upload",
            f"File: {file_name}\nSize: {upload_size / (1024 * 1024):.1f} MB",
            record_event=f"Upload received: {file_name}",
        )
        try:
            self._set_status(chat_id, state, "Preparing Telegram download", f"Resolving remote file path for {file_name}.", record_event="Resolved Telegram file metadata")
            telegram_file = self.api.get_file(doc["file_id"])
            self._send_chat_action(chat_id, "upload_document")
            self._set_status(chat_id, state, "Downloading APK from Telegram", f"Downloading {file_name} from Telegram cloud.", record_event=f"Downloading {file_name}")
            self.api.download_file(telegram_file["file_path"], download_path)

            if existing_project:
                project = self.pm.import_package(existing_project, download_path, self.config.max_apk_size_mb)
                self._set_status(chat_id, state, "Package added to existing project", f"Linked to active project {project.id[:12]}.", record_event=f"Package added to project {project.id[:12]}")
            else:
                self._set_status(chat_id, state, "Importing APK into workspace", f"Creating project from {file_name}.", record_event="Importing APK into workspace")
                project = self.pm.create_project(download_path, self.config.max_apk_size_mb)
        except Exception as exc:
            logger.exception("Failed to import Telegram APK")
            self._set_status(
                chat_id,
                state,
                "APK import failed",
                str(exc),
                record_event=f"Import failed: {_shorten(str(exc), max_chars=120)}",
            )
            self._send_message(chat_id, f"Failed to import APK: {exc}")
            return
        finally:
            try:
                if download_path.is_file():
                    download_path.unlink()
            except OSError:
                pass

        state.current_project_id = project.id
        state.pending_interrupt = False
        state.awaiting_mode_choice = True
        state.busy = False
        state.last_artifact_path = ""
        state.last_artifact_mtime = 0.0

        # Announce project to shared state so CLI can see it
        from apk_agent.session import ActiveSession
        save_active_session(
            self.config.workspace_path,
            ActiveSession(
                project_id=project.id,
                apk_name=project.apk_name,
                started_by="telegram",
                started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                status="idle",
                pid=os.getpid(),
            ),
        )

        linked_label = "linked to active project" if existing_project else "new project created"
        self._set_status(
            chat_id,
            state,
            "APK imported successfully",
            f"Project: {project.id}\nFile: {project.apk_name}\n({linked_label})\nSend your task.",
            record_event=f"Project ready: {project.id} ({linked_label})",
        )

        self._send_message(
            chat_id,
            f"✅ APK imported!\n\n"
            f"📦 {project.apk_name}\n"
            f"🆔 {project.id[:12]}\n"
            f"{'🔗 Linked to active project' if existing_project else '🆕 New project created'}\n\n"
            "Now send your task. Examples:\n"
            "• \"full security audit\"\n"
            "• \"bypass premium\"\n"
            "• \"remove ads and sign\"",
            reply_markup=_reply_keyboard(),
            dedupe_key=f"apk-ready:{project.id}",
        )

    def _handle_text(self, chat_id: int, text: str) -> None:
        state = self._load_chat_state(chat_id)
        lowered = text.strip().lower()

        if not state.current_project_id:
            # Auto-link to an active project started from CLI (or another Telegram session)
            active = load_active_session(self.config.workspace_path)
            if active and active.project_id:
                try:
                    project = self.pm.open_project(active.project_id)
                    state.current_project_id = project.id
                    self.state_store.save_chat(chat_id, state)
                    src = "CLI" if active.started_by == "cli" else "Telegram"
                    self._send_message(
                        chat_id,
                        f"🔗 Auto-linked to active project from {src}:\n"
                        f"📦 {project.apk_name}\n"
                        f"🆔 {project.id[:12]}",
                    )
                except Exception:
                    self._send_message(chat_id, "No active project yet. Send an APK or XAPK file first.")
                    return
            else:
                self._send_message(chat_id, "No active project yet. Send an APK or XAPK file first.")
                return

        if state.busy:
            self._send_message(chat_id, "A task is already running. Wait for the current run to finish.")
            return

        resume = state.pending_interrupt
        state.awaiting_mode_choice = False
        state.busy = True
        self.state_store.save_chat(chat_id, state)
        self._set_status(
            chat_id,
            state,
            "Queued user request",
            f"Request: {_shorten(text, max_chars=220)}",
            record_event=f"User request: {_shorten(text, max_chars=120)}",
        )

        thread = threading.Thread(
            target=self._run_turn_worker,
            args=(chat_id, text, resume),
            daemon=True,
        )
        thread.start()

    def _run_turn_worker(self, chat_id: int, text: str, resume: bool) -> None:
        if not self.worker_lock.acquire(blocking=False):
            state = self.state_store.get_chat(chat_id, True)
            state.busy = False
            self._set_status(
                chat_id,
                state,
                "Bridge busy",
                "Another Telegram task is already running globally. Try again in a moment.",
                record_event="Global worker busy",
            )
            return

        self.active_chat_id = chat_id
        try:
            self._run_turn(chat_id, text, resume=resume)
        except Exception as exc:
            logger.exception("Telegram turn failed")
            state = self.state_store.get_chat(chat_id, True)
            state.pending_interrupt = False
            state.busy = False
            state.current_phase = "error"
            update_active_session(self.config.workspace_path, status="idle", phase="error")
            elapsed = time.time() - state.task_start_time if state.task_start_time > 0 else 0
            self._set_status(
                chat_id,
                state,
                "Agent run failed",
                f"Error: {_shorten(str(exc), max_chars=200)}\n"
                f"After {_format_elapsed(elapsed)}, {state.tools_run} tools run",
                record_event=f"❌ Failed: {_shorten(str(exc), max_chars=120)}",
            )
            self._send_message(chat_id, f"❌ Agent run failed after {_format_elapsed(elapsed)}:\n{_shorten(str(exc), max_chars=300)}")
        finally:
            self.active_chat_id = None
            self.worker_lock.release()

    def _run_turn(self, chat_id: int, text: str, *, resume: bool) -> None:
        state = self.state_store.get_chat(chat_id, True)
        project = self.pm.open_project(state.current_project_id)
        config = AppConfig.load()
        config.validate()

        # Announce active session so CLI can see it
        from apk_agent.session import ActiveSession
        save_active_session(
            config.workspace_path,
            ActiveSession(
                project_id=project.id,
                apk_name=project.apk_name,
                started_by="telegram",
                started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                status="running",
                pid=os.getpid(),
            ),
        )

        session_meta = self._load_or_create_session_meta(project, config, auto_mode=state.auto_mode)

        # Set mode flags at graph/tool level
        import apk_agent.agent.tools_def as _td
        _td._auto_mode = state.auto_mode
        _td._human_mode = state.human_mode

        from apk_agent.agent.graph import build_graph, set_active_thread

        checkpointer = get_sqlite_checkpointer(project.workspace_path)
        graph, _ = build_graph(config, project, checkpointer=checkpointer)
        graph_config = build_langgraph_run_config(session_meta.thread_id)
        set_active_thread(session_meta.thread_id)

        stream_input: Any
        is_resume = resume
        if resume:
            stream_input = text
        else:
            session_meta.message_count += 1
            session_meta.last_user_input = text
            session_meta.touch()
            stream_input = self._build_input_state(graph, graph_config, text, project)

        state.status_recent_events = []
        state.pending_interrupt = False
        state.task_start_time = time.time()
        state.tools_run = 0
        state.tools_failed = 0
        state.findings_count = 0
        state.patches_count = 0
        state.prompt_tokens = 0
        state.completion_tokens = 0
        state.cached_tokens = 0
        state.last_tool_name = ""
        state.current_phase = "starting"
        self._send_chat_action(chat_id, "typing")
        self._set_status(
            chat_id,
            state,
            "Starting task",
            f"Project: {project.id}\nRequest: {_shorten(text, max_chars=240)}",
            record_event=f"🚀 Task started: {_shorten(text, max_chars=120)}",
        )

        while True:
            interrupt_info: dict[str, Any] | None = None

            if is_resume:
                events = graph.stream(Command(resume=stream_input), config=graph_config, stream_mode="updates")
            else:
                events = graph.stream(stream_input, config=graph_config, stream_mode="updates")

            for event in events:
                interrupt_info = self._process_stream_event(chat_id, state, event)
                if interrupt_info:
                    break

            if not interrupt_info:
                break

            is_human_step = interrupt_info.get("human_step", False)

            if state.auto_mode and not is_human_step:
                prompt_preview = _shorten(interrupt_info.get("prompt", ""), max_chars=220)
                self._set_status(
                    chat_id,
                    state,
                    "Auto-approving",
                    prompt_preview,
                    record_event="🤖 Auto-approved",
                )
                stream_input = interrupt_info["response"]
                is_resume = True
                continue

            # Pause and wait for user input (always for human_step, or non-auto mode)
            state.pending_interrupt = True
            state.busy = False
            headline = "🧠 What's next?" if is_human_step else "Waiting for your reply"
            event_tag = "🧠 Awaiting next step" if is_human_step else "❓ Awaiting user input"
            self.state_store.save_chat(chat_id, state)
            self._set_status(
                chat_id,
                state,
                headline,
                interrupt_info.get("prompt", ""),
                record_event=event_tag,
            )
            self._send_message(
                chat_id,
                interrupt_info.get("prompt", ""),
                dedupe_key=f"interrupt:{hashlib.sha1(str(interrupt_info.get('prompt', '')).encode('utf-8')).hexdigest()}",
            )
            session_meta.touch()
            save_session_meta(session_meta, project.workspace_path)
            return

        state.pending_interrupt = False
        state.busy = False
        state.last_tool_name = ""
        state.current_phase = "completed"
        update_active_session(self.config.workspace_path, status="idle", phase="completed")

        # Build completion summary
        elapsed = time.time() - state.task_start_time if state.task_start_time > 0 else 0
        summary_parts = [f"⏱ Time: {_format_elapsed(elapsed)}"]
        if state.tools_run:
            summary_parts.append(f"🔧 Tools: {state.tools_run}" + (f" ({state.tools_failed} failed)" if state.tools_failed else ""))
        if state.findings_count:
            summary_parts.append(f"🔍 Findings: {state.findings_count}")
        if state.patches_count:
            summary_parts.append(f"🩹 Patches: {state.patches_count}")
        total_tokens = state.prompt_tokens + state.completion_tokens
        if total_tokens > 0:
            summary_parts.append(f"📊 Tokens: {total_tokens:,} (in:{state.prompt_tokens:,} out:{state.completion_tokens:,})"
                                 + (f" cached:{state.cached_tokens:,}" if state.cached_tokens else ""))

        self._set_status(
            chat_id,
            state,
            "Task completed",
            "\n".join(summary_parts),
            record_event="✅ Task finished",
        )
        session_meta.touch()
        save_session_meta(session_meta, project.workspace_path)

        # Send completion summary as a separate message
        self._send_message(
            chat_id,
            f"✅ Task completed!\n\n" + "\n".join(summary_parts),
            dedupe_key=f"complete:{session_meta.thread_id}:{state.tools_run}",
        )

        # Send report if available
        self._send_report_if_ready(chat_id, project)

        # Send final signed APK
        self._send_final_artifact_if_ready(chat_id, project, state)

    def _build_input_state(self, graph, graph_config: dict[str, Any], user_input: str, project: Project) -> dict[str, Any]:
        input_state: dict[str, Any] = {
            "messages": [HumanMessage(content=user_input)],
            "task": user_input,
            "human_feedback": "",
            "project_id": project.id,
            "project_path": project.workspace_path,
            "apk_name": project.apk_name,
            "apktool_dir": str(project.apktool_dir),
            "jadx_dir": str(project.jadx_dir),
        }

        try:
            existing = graph.get_state(graph_config)
            is_first_turn = not existing or not existing.values or not existing.values.get("messages")
        except Exception:
            is_first_turn = True

        if is_first_turn:
            input_state.update(
                {
                    "findings": [],
                    "patch_results": [],
                    "patch_registry": [],
                    "patch_plans": [],
                    "tool_history": [],
                    "current_plan": "",
                    "plan_step_index": 0,
                    "graph_ready": False,
                    "target_packages": [],
                    "excluded_packages": [],
                    "scratchpad": {},
                    "task_plan": [],
                    "planning_started": False,
                    "analysis_complete_for_patching": False,
                    "patch_plan_ready": False,
                    "prebuild_validation_ready": False,
                    "runtime_validation_ready": False,
                }
            )
        return input_state

    def _load_or_create_session_meta(self, project: Project, config: AppConfig, *, auto_mode: bool) -> SessionMeta:
        meta = load_session_meta(project.workspace_path)
        if meta is not None:
            meta.auto_mode = auto_mode
            return meta

        meta = SessionMeta(
            thread_id=os.urandom(16).hex(),
            project_id=project.id,
            created_at=_now_iso(),
            last_active_at=_now_iso(),
            auto_mode=auto_mode,
        )
        save_session_meta(meta, project.workspace_path)
        return meta

    def _process_stream_event(self, chat_id: int, state: TelegramChatState, event: dict[str, Any]) -> dict[str, Any] | None:
        for node_name, node_output in event.items():
            if node_name == "agent":
                messages = node_output.get("messages", [])
                for msg in messages:
                    if isinstance(msg, AIMessage):
                        # ── Thinking / reasoning (mirrors CLI exactly) ──
                        from apk_agent.llm.provider import pop_last_reasoning
                        reasoning = pop_last_reasoning()
                        if not reasoning:
                            ak = getattr(msg, "additional_kwargs", {}) or {}
                            reasoning = (
                                ak.get("reasoning_text")
                                or ak.get("reasoning_content")
                                or ak.get("thinking")
                            )
                            if reasoning and isinstance(reasoning, str) and reasoning.strip():
                                reasoning = reasoning.strip()
                            else:
                                reasoning = None
                        if reasoning:
                            self._send_message(
                                chat_id,
                                f"💭 Thinking:\n\n{_summarize_tool_content(reasoning, max_chars=3200)}",
                                dedupe_key=f"think:{hashlib.sha1(reasoning.encode('utf-8')).hexdigest()}",
                                dedupe_window_sec=4.0,
                            )

                        # ── Token usage tracking (mirrors CLI) ──
                        usage = getattr(msg, "usage_metadata", None) or getattr(msg, "response_metadata", {}).get("token_usage", {})
                        if usage:
                            prompt_t = usage.get("input_tokens", 0) or usage.get("prompt_tokens", 0)
                            compl_t = usage.get("output_tokens", 0) or usage.get("completion_tokens", 0)
                            cached_t = 0
                            if isinstance(usage, dict):
                                ptd = usage.get("prompt_tokens_details") or {}
                                cached_t = ptd.get("cached_tokens", 0)
                            elif hasattr(usage, "get"):
                                ptd = usage.get("prompt_tokens_details") or {}
                                cached_t = ptd.get("cached_tokens", 0)
                            state.prompt_tokens += int(prompt_t or 0)
                            state.completion_tokens += int(compl_t or 0)
                            state.cached_tokens += int(cached_t or 0)

                        # ── Extract text content (handle str + list) ──
                        text_content = ""
                        if isinstance(msg.content, str):
                            text_content = msg.content.strip()
                        elif isinstance(msg.content, list):
                            parts: list[str] = []
                            for block in msg.content:
                                if isinstance(block, str):
                                    parts.append(block)
                                elif isinstance(block, dict):
                                    btype = block.get("type", "")
                                    if btype == "text":
                                        parts.append(block.get("text", ""))
                                    elif btype in ("thinking", "reasoning"):
                                        think_text = block.get("thinking") or block.get("text") or ""
                                        if think_text.strip() and not reasoning:
                                            self._send_message(
                                                chat_id,
                                                f"💭 Thinking:\n\n{_summarize_tool_content(think_text.strip(), max_chars=3200)}",
                                                dedupe_key=f"think:{hashlib.sha1(think_text.encode('utf-8')).hexdigest()}",
                                                dedupe_window_sec=4.0,
                                            )
                            text_content = "\n".join(p for p in parts if p.strip())

                        # ── Send AI text ──
                        if text_content:
                            self._send_message(
                                chat_id,
                                f"🤖 Agent:\n\n{text_content}",
                                dedupe_key=f"ai:{hashlib.sha1(text_content.encode('utf-8')).hexdigest()}",
                                dedupe_window_sec=12.0,
                            )

                        # ── Tool calls with args (mirrors CLI) ──
                        if msg.tool_calls:
                            tool_names = [tc.get("name", "tool") for tc in msg.tool_calls]
                            state.last_tool_name = ", ".join(tool_names[:3])
                            if len(tool_names) > 3:
                                state.last_tool_name += f" (+{len(tool_names) - 3})"

                            tool_lines: list[str] = []
                            if len(msg.tool_calls) > 1:
                                tool_lines.append(f"⚡ {len(msg.tool_calls)} tools in parallel")
                            for tc in msg.tool_calls:
                                name = tc.get("name", "tool")
                                args = tc.get("args", {})
                                arg_summary = ""
                                if args:
                                    arg_parts = []
                                    for k, v in list(args.items())[:3]:
                                        v_str = str(v)[:60]
                                        arg_parts.append(f"{k}={v_str}")
                                    arg_summary = ", ".join(arg_parts)
                                if arg_summary:
                                    tool_lines.append(f"🔧 {name}({arg_summary})")
                                else:
                                    tool_lines.append(f"🔧 {name}")

                            tool_msg_text = "\n".join(tool_lines)
                            self._send_message(
                                chat_id,
                                tool_msg_text,
                                dedupe_key=f"tc:{hashlib.sha1(tool_msg_text.encode('utf-8')).hexdigest()}",
                                dedupe_window_sec=6.0,
                                disable_notification=True,
                            )

                            # Status update
                            categories = _categorize_tools(tool_names)
                            if len(tool_names) == 1:
                                headline = f"Running: {tool_names[0]}"
                            else:
                                headline = f"Running {len(tool_names)} tools in parallel"

                            detail_lines: list[str] = []
                            for cat, names in categories.items():
                                detail_lines.append(f"{cat}: {', '.join(names)}")
                            detail = "\n".join(detail_lines)

                            self._send_chat_action(chat_id, "typing")
                            self._set_status(
                                chat_id,
                                state,
                                headline,
                                detail,
                                extra_events=[f"⚙️ {name}" for name in tool_names[:4]],
                            )

            elif node_name == "tools":
                tool_messages = [m for m in node_output.get("messages", []) if isinstance(m, ToolMessage)]
                if tool_messages:
                    event_lines: list[str] = []
                    for tool_msg in tool_messages:
                        content = str(tool_msg.content or "")
                        lower = content[:200].lower()
                        failed = '"success": false' in lower or '"error"' in lower[:120] or lower.startswith("error")
                        name = tool_msg.name or "tool"

                        state.tools_run += 1
                        if failed:
                            state.tools_failed += 1

                        icon = "✅" if not failed else "❌"
                        insight = _extract_tool_insight(name, content)
                        suffix = f" — {insight}" if insight else ""
                        event_lines.append(f"{icon} {name}{suffix}")

                        # ── Send FULL tool output (mirrors CLI) ──
                        truncated = _summarize_tool_content(content, max_chars=3200)
                        self._send_message(
                            chat_id,
                            f"{icon} {name}:\n\n{truncated}",
                            dedupe_key=f"tool:{name}:{hashlib.sha1(content[:500].encode('utf-8')).hexdigest()}",
                            dedupe_window_sec=4.0,
                            disable_notification=True,
                        )

                        # Track findings/patches from tool results
                        self._update_counters_from_tool(state, name, content)

                    # ── Task plan display (mirrors CLI) ──
                    plan_tools = {"update_task_plan", "mark_task_done", "edit_task_plan"}
                    if any(m.name in plan_tools for m in tool_messages if m.name):
                        try:
                            from apk_agent.agent.tools_def import _get_task_plan
                            plan = _get_task_plan()
                            if plan:
                                plan_lines: list[str] = ["📋 Task Plan:"]
                                for item in plan:
                                    status = item.get("status", "pending")
                                    label = item.get("label") or item.get("task", "")
                                    if status == "done":
                                        plan_lines.append(f"  ✅ {label}")
                                    elif status == "in_progress":
                                        plan_lines.append(f"  ⏳ {label}")
                                    else:
                                        plan_lines.append(f"  ⬜ {label}")
                                self._send_message(
                                    chat_id,
                                    "\n".join(plan_lines),
                                    dedupe_key=f"plan:{hashlib.sha1(str(plan).encode('utf-8')).hexdigest()}",
                                    dedupe_window_sec=10.0,
                                    disable_notification=True,
                                )
                        except Exception:
                            pass

                    self._set_status(
                        chat_id,
                        state,
                        f"Results ({state.tools_run} tools so far)",
                        "\n".join(event_lines[-6:]),
                        extra_events=event_lines,
                    )
                    self._send_chat_action(chat_id, "typing")

            elif node_name == "tools_post":
                # Post-processing step — keep typing indicator
                self._send_chat_action(chat_id, "typing")

            elif node_name == "nudge":
                # ── Send nudge as a message (mirrors CLI) ──
                self._send_message(
                    chat_id,
                    "⚡ Auto-nudging agent to execute tools...",
                    dedupe_key="nudge",
                    dedupe_window_sec=10.0,
                    disable_notification=True,
                )
                self._set_status(
                    chat_id,
                    state,
                    "Agent continuing analysis",
                    "The orchestration layer asked the agent to keep executing tools.",
                    record_event="💡 Agent nudged to continue",
                )
                self._send_chat_action(chat_id, "typing")

            elif node_name == "__interrupt__":
                interrupts = node_output
                if isinstance(interrupts, (list, tuple)):
                    for intr in interrupts:
                        value = intr.value if hasattr(intr, "value") else str(intr)
                        value_str = str(value)
                        is_human_step = "💬 What should I do next?" in value_str
                        if is_human_step:
                            # Human Thinking mode — always pause for user
                            response = ""
                        elif "❓" in value_str:
                            response = "Proceed with your best judgment."
                        else:
                            response = "yes"
                        return {"interrupt": True, "prompt": value_str, "response": response, "human_step": is_human_step}
        return None

    def _update_counters_from_tool(self, state: TelegramChatState, tool_name: str, content: str) -> None:
        """Update findings/patches counters from tool results."""
        try:
            data = json.loads(content)
            if not isinstance(data, dict):
                return
            # Count findings from scanner/analyzer tools
            if "findings" in data and isinstance(data["findings"], list):
                state.findings_count += len(data["findings"])
            if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
                state.findings_count += len(data["vulnerabilities"])
            # Count patches
            if tool_name in ("apply_smali_patch", "smart_entity_patch", "batch_patch") or "patch" in tool_name.lower():
                if data.get("success"):
                    state.patches_count += 1
        except (json.JSONDecodeError, TypeError):
            pass

    def _send_report_if_ready(self, chat_id: int, project: Project) -> None:
        """Send the security report as a document if it exists."""
        report_path = Path(project.workspace_path) / "outputs" / "report.md"
        if not report_path.is_file():
            return
        try:
            report_size = report_path.stat().st_size
            if report_size < 50:
                return  # Too small to be meaningful
            if report_size > _MAX_SENDABLE_DOCUMENT_BYTES:
                self._send_message(chat_id, f"📄 Report is too large for Telegram ({report_size / 1024 / 1024:.1f} MB).")
                return
            self._send_chat_action(chat_id, "upload_document")
            self.api.send_document(
                chat_id,
                report_path,
                caption=f"📄 Security report for {project.apk_name}",
            )
        except Exception as exc:
            logger.debug("Failed to send report: %s", exc)

    def _send_final_artifact_if_ready(self, chat_id: int, project: Project, state: TelegramChatState) -> None:
        final_artifact = get_final_artifact_path(project)
        artifact_label = "XAPK" if final_artifact.suffix.lower() == ".xapk" else "APK"
        if not final_artifact.is_file():
            self._set_status(
                chat_id,
                state,
                "Task completed",
                f"No final signed {artifact_label} was found in {final_artifact}.",
                record_event="No signed artifact produced",
            )
            return

        stat = final_artifact.stat()
        if final_artifact.resolve().as_posix() == state.last_artifact_path and stat.st_mtime <= state.last_artifact_mtime:
            self._set_status(
                chat_id,
                state,
                "Done",
                f"Final artifact already sent earlier: {final_artifact.name}",
                record_event=f"Artifact already sent: {final_artifact.name}",
            )
            return

        if stat.st_size > _MAX_SENDABLE_DOCUMENT_BYTES:
            self._send_message(
                chat_id,
                f"Final signed {artifact_label} is ready, but Telegram refused to send files larger than 49 MB.\n"
                f"Local path: {final_artifact}",
            )
            self._set_status(
                chat_id,
                state,
                "Final artifact ready locally",
                f"Telegram send limit exceeded. Local path: {final_artifact}",
                record_event=f"Signed artifact ready locally: {final_artifact.name}",
            )
        else:
            self._send_chat_action(chat_id, "upload_document")
            self._set_status(
                chat_id,
                state,
                f"Uploading final {artifact_label}",
                f"Sending {final_artifact.name} back to Telegram.",
                record_event=f"Uploading {final_artifact.name}",
            )
            self.api.send_document(
                chat_id,
                final_artifact,
                caption=f"Final patched {artifact_label} for project {project.id}",
            )
            self._set_status(
                chat_id,
                state,
                "Done",
                f"Final patched {artifact_label} sent successfully: {final_artifact.name}",
                record_event=f"Final artifact sent: {final_artifact.name}",
            )

        state.last_artifact_path = final_artifact.resolve().as_posix()
        state.last_artifact_mtime = stat.st_mtime
        self.state_store.save_chat(chat_id, state)


@click.command()
@click.option("--run", "run_mode", is_flag=True, help="Run the Telegram bot bridge.")
@click.option("--check", is_flag=True, help="Validate Telegram configuration and bot token, then exit.")
@click.option("--verbose", is_flag=True, help="Enable verbose logging.")
def main(run_mode: bool, check: bool, verbose: bool) -> None:
    """Run or validate the Telegram bridge process."""
    _setup_logging(verbose)
    config = AppConfig.load()
    config.validate()

    if not config.telegram_enabled:
        raise click.ClickException(
            "Telegram bridge is not configured. Set TELEGRAM_BOT_TOKEN and TELEGRAM_ALLOWED_CHAT_IDS in .env."
        )

    api = TelegramApi(config.telegram_bot_token, poll_timeout_sec=config.telegram_poll_timeout_sec)
    try:
        # Retry get_me() — transient DNS / network failures shouldn't kill the bridge
        me = None
        for _attempt in range(5):
            try:
                me = api.get_me()
                break
            except Exception as _net_err:
                if check or _attempt >= 4:
                    raise
                wait = (_attempt + 1) * 5
                logger.warning(
                    "get_me() failed (attempt %d/5): %s — retrying in %ds",
                    _attempt + 1, _net_err, wait,
                )
                time.sleep(wait)
        if check and not run_mode:
            click.echo(f"Telegram bot OK: @{me.get('username', 'unknown')} ({me.get('id')})")
            return
    finally:
        api.close()

    if not run_mode:
        raise click.ClickException("Nothing to do. Use --run or --check.")

    service = TelegramBotService(config)
    service.run_forever()


if __name__ == "__main__":
    main()