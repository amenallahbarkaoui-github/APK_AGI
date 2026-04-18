"""Telegram bot bridge for APK Agent.

Runs as a separate process so the Telegram workflow can reuse the same agent
engine and persistent sessions without colliding with the interactive CLI's
module-level graph/tool globals.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import click
import httpx
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langgraph.types import Command

from apk_agent.config import AppConfig
from apk_agent.session import (
    SessionMeta,
    get_sqlite_checkpointer,
    load_session_meta,
    save_session_meta,
)
from apk_agent.workspace import Project, ProjectManager

logger = logging.getLogger("apk_agent.telegram")

_PROCESS_STATUS_FILE = ".telegram-bot-process.json"
_STATE_FILE = ".telegram-bot-state.json"
_MAX_TEXT_CHARS = 3500
_MAX_DOWNLOADABLE_TELEGRAM_FILE_BYTES = 20 * 1_000_000
_MAX_SENDABLE_DOCUMENT_BYTES = 49 * 1024 * 1024


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
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _status_file(workspace_root: Path) -> Path:
    return workspace_root / _PROCESS_STATUS_FILE


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


def ensure_telegram_bot_running(config: AppConfig, *, verbose: bool = False) -> tuple[bool, str]:
    """Ensure the Telegram bot bridge background process is running."""
    if not config.telegram_enabled:
        return False, "Telegram bridge is not configured."

    status = _read_process_status(config.workspace_path)
    pid = int(status.get("pid", 0) or 0)
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
    thinking_enabled: bool = True
    auto_mode: bool = False
    pending_interrupt: bool = False
    awaiting_mode_choice: bool = False
    busy: bool = False
    last_artifact_path: str = ""
    last_artifact_mtime: float = 0.0


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

    def get_chat(self, chat_id: int, default_thinking: bool) -> TelegramChatState:
        with self._lock:
            raw = (self._data.get("chats") or {}).get(str(chat_id)) or {}
            if not raw:
                return TelegramChatState(thinking_enabled=default_thinking)
            return TelegramChatState(
                current_project_id=raw.get("current_project_id", ""),
                thinking_enabled=raw.get("thinking_enabled", default_thinking),
                auto_mode=raw.get("auto_mode", False),
                pending_interrupt=raw.get("pending_interrupt", False),
                awaiting_mode_choice=raw.get("awaiting_mode_choice", False),
                busy=raw.get("busy", False),
                last_artifact_path=raw.get("last_artifact_path", ""),
                last_artifact_mtime=float(raw.get("last_artifact_mtime", 0.0) or 0.0),
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

    def send_message(self, chat_id: int, text: str, *, reply_markup: dict[str, Any] | None = None) -> None:
        for chunk in _chunk_text(text):
            body: dict[str, Any] = {
                "chat_id": chat_id,
                "text": chunk,
                "disable_web_page_preview": True,
            }
            if reply_markup:
                body["reply_markup"] = reply_markup
            self._request("sendMessage", json_body=body)

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


def _reply_keyboard() -> dict[str, Any]:
    return {
        "keyboard": [
            [{"text": "thinking on"}, {"text": "thinking off"}],
            [{"text": "/auto on"}, {"text": "/auto off"}],
            [{"text": "/status"}, {"text": "/new"}],
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

    def run_forever(self) -> None:
        me = self.api.get_me()
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
                logger.exception("Telegram polling error: %s", exc)
                time.sleep(3)

    def _handle_update(self, update: dict[str, Any]) -> None:
        message = update.get("message") or {}
        chat = message.get("chat") or {}
        chat_id = int(chat.get("id", 0) or 0)
        if not chat_id:
            return

        if chat_id not in self.allowed_chat_ids:
            try:
                self.api.send_message(chat_id, "Access denied for this chat.")
            except Exception:
                pass
            return

        if message.get("document"):
            self._handle_document(chat_id, message)
            return

        text = (message.get("text") or "").strip()
        if not text:
            self.api.send_message(chat_id, "Send an APK/XAPK file or a text command like /help.")
            return

        if text.startswith("/"):
            self._handle_command(chat_id, text)
        else:
            self._handle_text(chat_id, text)

    def _handle_command(self, chat_id: int, text: str) -> None:
        cmd, _, arg = text.partition(" ")
        arg = arg.strip().lower()
        state = self.state_store.get_chat(chat_id, self.config.thinking_enabled)

        if cmd == "/start":
            self.api.send_message(
                chat_id,
                "APK Agent Telegram bridge is ready.\n\n"
                "1. Send an APK or XAPK file.\n"
                "2. Choose thinking mode with `thinking on` or `thinking off`.\n"
                "3. Send your task, for example: `bypass premium and return the signed apk`.\n\n"
                "Commands: /help /status /new /thinking /auto",
                reply_markup=_reply_keyboard(),
            )
            return

        if cmd == "/help":
            self.api.send_message(
                chat_id,
                "Commands:\n"
                "/status - show current project and modes\n"
                "/new - clear current project and wait for a new APK\n"
                "/thinking on|off - toggle deep thinking\n"
                "/auto on|off - toggle auto-approval mode\n\n"
                "You can also send plain text: `thinking on` / `thinking off`.",
            )
            return

        if cmd == "/new":
            state.current_project_id = ""
            state.pending_interrupt = False
            state.awaiting_mode_choice = False
            state.last_artifact_path = ""
            state.last_artifact_mtime = 0.0
            self.state_store.save_chat(chat_id, state)
            self.api.send_message(chat_id, "Current project cleared. Send a new APK or XAPK file.")
            return

        if cmd == "/status":
            busy = "yes" if state.busy else "no"
            thinking = "ON" if state.thinking_enabled else "OFF"
            auto_mode = "ON" if state.auto_mode else "OFF"
            project_line = state.current_project_id or "none"
            self.api.send_message(
                chat_id,
                f"Project: {project_line}\nThinking: {thinking}\nAuto: {auto_mode}\nBusy: {busy}\nPending interrupt: {'yes' if state.pending_interrupt else 'no'}",
            )
            return

        if cmd == "/thinking":
            if arg in {"on", "off"}:
                state.thinking_enabled = arg == "on"
                state.awaiting_mode_choice = False
                self.state_store.save_chat(chat_id, state)
                self.api.send_message(chat_id, f"Thinking mode is now {'ON' if state.thinking_enabled else 'OFF'}.")
            else:
                self.api.send_message(chat_id, f"Thinking mode is {'ON' if state.thinking_enabled else 'OFF'}. Use /thinking on or /thinking off.")
            return

        if cmd == "/auto":
            if arg in {"on", "off"}:
                state.auto_mode = arg == "on"
                self.state_store.save_chat(chat_id, state)
                self.api.send_message(chat_id, f"Auto mode is now {'ON' if state.auto_mode else 'OFF'}.")
            else:
                self.api.send_message(chat_id, f"Auto mode is {'ON' if state.auto_mode else 'OFF'}. Use /auto on or /auto off.")
            return

        self.api.send_message(chat_id, "Unknown command. Use /help.")

    def _handle_document(self, chat_id: int, message: dict[str, Any]) -> None:
        state = self.state_store.get_chat(chat_id, self.config.thinking_enabled)
        if state.busy:
            self.api.send_message(chat_id, "A task is already running. Wait for it to finish before uploading another APK.")
            return

        doc = message["document"]
        file_name = doc.get("file_name") or f"upload-{doc.get('file_unique_id', 'apk')}.apk"
        suffix = Path(file_name).suffix.lower()
        if suffix not in {".apk", ".xapk"}:
            self.api.send_message(chat_id, "Only .apk and .xapk files are supported.")
            return

        upload_size = int(doc.get("file_size") or 0)
        if upload_size > _MAX_DOWNLOADABLE_TELEGRAM_FILE_BYTES:
            self.api.send_message(
                chat_id,
                "Telegram cloud download is limited to 20 MB per file for bots.\n"
                f"`{file_name}` is about {upload_size / (1024 * 1024):.1f} MB, so Telegram will reject getFile before APK Agent can import it.\n"
                "Send a smaller APK/XAPK. Larger Telegram uploads require running the bridge against a local Bot API server instead of the default Telegram cloud API.",
            )
            return

        chat_upload_dir = self.config.workspace_path / "telegram_uploads" / str(chat_id)
        download_path = chat_upload_dir / file_name

        self.api.send_message(chat_id, f"Downloading `{file_name}` from Telegram...")
        try:
            telegram_file = self.api.get_file(doc["file_id"])
            self.api.download_file(telegram_file["file_path"], download_path)
            project = self.pm.create_project(download_path, self.config.max_apk_size_mb)
        except Exception as exc:
            logger.exception("Failed to import Telegram APK")
            self.api.send_message(chat_id, f"Failed to import APK: {exc}")
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
        self.state_store.save_chat(chat_id, state)

        self.api.send_message(
            chat_id,
            f"APK received successfully.\nProject: {project.id}\nFile: {project.apk_name}\n\n"
            f"Thinking is currently {'ON' if state.thinking_enabled else 'OFF'}.\n"
            "Reply with `thinking on` or `thinking off`, then send your task.",
            reply_markup=_reply_keyboard(),
        )

    def _handle_text(self, chat_id: int, text: str) -> None:
        state = self.state_store.get_chat(chat_id, self.config.thinking_enabled)
        lowered = text.strip().lower()

        if lowered in {"thinking on", "thinking off"}:
            state.thinking_enabled = lowered.endswith("on")
            state.awaiting_mode_choice = False
            self.state_store.save_chat(chat_id, state)
            self.api.send_message(chat_id, f"Thinking mode is now {'ON' if state.thinking_enabled else 'OFF'}. Now send your task.")
            return

        if not state.current_project_id:
            self.api.send_message(chat_id, "No active project yet. Send an APK or XAPK file first.")
            return

        if state.busy:
            self.api.send_message(chat_id, "A task is already running. Wait for the current run to finish.")
            return

        resume = state.pending_interrupt
        state.awaiting_mode_choice = False
        state.busy = True
        self.state_store.save_chat(chat_id, state)

        thread = threading.Thread(
            target=self._run_turn_worker,
            args=(chat_id, text, resume),
            daemon=True,
        )
        thread.start()

    def _run_turn_worker(self, chat_id: int, text: str, resume: bool) -> None:
        if not self.worker_lock.acquire(blocking=False):
            state = self.state_store.get_chat(chat_id, self.config.thinking_enabled)
            state.busy = False
            self.state_store.save_chat(chat_id, state)
            self.api.send_message(chat_id, "Another Telegram task is running right now. Try again in a moment.")
            return

        self.active_chat_id = chat_id
        try:
            self._run_turn(chat_id, text, resume=resume)
        except Exception as exc:
            logger.exception("Telegram turn failed")
            self.api.send_message(chat_id, f"Agent run failed: {exc}")
            state = self.state_store.get_chat(chat_id, self.config.thinking_enabled)
            state.pending_interrupt = False
            state.busy = False
            self.state_store.save_chat(chat_id, state)
        finally:
            self.active_chat_id = None
            self.worker_lock.release()

    def _run_turn(self, chat_id: int, text: str, *, resume: bool) -> None:
        state = self.state_store.get_chat(chat_id, self.config.thinking_enabled)
        project = self.pm.open_project(state.current_project_id)
        config = AppConfig.load()
        config.thinking_enabled = state.thinking_enabled
        config.validate()

        session_meta = self._load_or_create_session_meta(project, config, auto_mode=state.auto_mode)

        from apk_agent.agent.graph import build_graph, set_active_thread

        checkpointer = get_sqlite_checkpointer(project.workspace_path)
        graph, _ = build_graph(config, project, checkpointer=checkpointer)
        graph_config = {"configurable": {"thread_id": session_meta.thread_id}}
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

        state.pending_interrupt = False
        self.state_store.save_chat(chat_id, state)
        self.api.send_message(chat_id, f"Starting task on project {project.id}...")

        while True:
            interrupt_info: dict[str, Any] | None = None

            if is_resume:
                events = graph.stream(Command(resume=stream_input), config=graph_config, stream_mode="updates")
            else:
                events = graph.stream(stream_input, config=graph_config, stream_mode="updates")

            for event in events:
                interrupt_info = self._process_stream_event(chat_id, event)
                if interrupt_info:
                    break

            if not interrupt_info:
                break

            if state.auto_mode:
                stream_input = interrupt_info["response"]
                is_resume = True
                continue

            state.pending_interrupt = True
            state.busy = False
            self.state_store.save_chat(chat_id, state)
            session_meta.touch()
            save_session_meta(session_meta, project.workspace_path)
            return

        state.pending_interrupt = False
        state.busy = False
        self.state_store.save_chat(chat_id, state)
        session_meta.touch()
        save_session_meta(session_meta, project.workspace_path)
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
                }
            )
        return input_state

    def _load_or_create_session_meta(self, project: Project, config: AppConfig, *, auto_mode: bool) -> SessionMeta:
        meta = load_session_meta(project.workspace_path)
        if meta is not None:
            meta.thinking_mode = config.thinking_enabled
            meta.auto_mode = auto_mode
            return meta

        meta = SessionMeta(
            thread_id=os.urandom(16).hex(),
            project_id=project.id,
            created_at=_now_iso(),
            last_active_at=_now_iso(),
            thinking_mode=config.thinking_enabled,
            auto_mode=auto_mode,
        )
        save_session_meta(meta, project.workspace_path)
        return meta

    def _process_stream_event(self, chat_id: int, event: dict[str, Any]) -> dict[str, Any] | None:
        for node_name, node_output in event.items():
            if node_name == "agent":
                messages = node_output.get("messages", [])
                for msg in messages:
                    if isinstance(msg, AIMessage):
                        if msg.content and isinstance(msg.content, str) and msg.content.strip():
                            self.api.send_message(chat_id, msg.content)
                        if msg.tool_calls:
                            tool_names = [tc.get("name", "tool") for tc in msg.tool_calls]
                            if len(tool_names) == 1:
                                self.api.send_message(chat_id, f"Running tool: {tool_names[0]}")
                            else:
                                self.api.send_message(chat_id, "Running tools in parallel:\n" + "\n".join(f"- {name}" for name in tool_names))

            elif node_name == "tools":
                tool_messages = [m for m in node_output.get("messages", []) if isinstance(m, ToolMessage)]
                if tool_messages:
                    self.api.send_message(chat_id, _format_tool_batch(tool_messages))

            elif node_name == "nudge":
                self.api.send_message(chat_id, "Agent was nudged to keep executing tools.")

            elif node_name == "__interrupt__":
                interrupts = node_output
                if isinstance(interrupts, (list, tuple)):
                    for intr in interrupts:
                        value = intr.value if hasattr(intr, "value") else str(intr)
                        value_str = str(value)
                        if "❓" in value_str:
                            response = "Proceed with your best judgment."
                        else:
                            response = "yes"
                        self.api.send_message(chat_id, value_str)
                        return {"interrupt": True, "response": response}
        return None

    def _send_final_artifact_if_ready(self, chat_id: int, project: Project, state: TelegramChatState) -> None:
        signed_apk = Path(project.workspace_path) / "outputs" / "patched-signed.apk"
        if not signed_apk.is_file():
            return

        stat = signed_apk.stat()
        if signed_apk.resolve().as_posix() == state.last_artifact_path and stat.st_mtime <= state.last_artifact_mtime:
            return

        if stat.st_size > _MAX_SENDABLE_DOCUMENT_BYTES:
            self.api.send_message(
                chat_id,
                "Final signed APK is ready, but Telegram refused to send files larger than 49 MB.\n"
                f"Local path: {signed_apk}",
            )
        else:
            self.api.send_document(
                chat_id,
                signed_apk,
                caption=f"Final patched APK for project {project.id}",
            )

        state.last_artifact_path = signed_apk.resolve().as_posix()
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
        me = api.get_me()
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