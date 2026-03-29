"""Real-time progress tracking for APK Agent tasks.

Provides a thread-safe progress manager that tracks tool executions,
sub-agent tasks, and overall workflow progress displayed in the CLI.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    RETRYING = "retrying"


@dataclass
class TaskProgress:
    """Tracks a single task/tool execution."""
    id: str
    name: str
    description: str = ""
    status: TaskStatus = TaskStatus.PENDING
    started_at: float = 0.0
    completed_at: float = 0.0
    progress_pct: float = 0.0  # 0-100
    error: str = ""
    retries: int = 0
    max_retries: int = 3
    parent_id: Optional[str] = None  # for sub-tasks
    metadata: dict = field(default_factory=dict)

    @property
    def elapsed(self) -> float:
        if self.started_at == 0:
            return 0
        end = self.completed_at if self.completed_at else time.time()
        return end - self.started_at

    @property
    def is_terminal(self) -> bool:
        return self.status in (TaskStatus.SUCCESS, TaskStatus.FAILED, TaskStatus.SKIPPED)


class ProgressManager:
    """Thread-safe progress manager for the entire agent session."""

    def __init__(self):
        self._lock = threading.Lock()
        self._tasks: dict[str, TaskProgress] = {}
        self._task_order: list[str] = []
        self._listeners: list = []
        self._overall_description: str = ""
        self._overall_started: float = 0.0

    def set_overall_task(self, description: str) -> None:
        with self._lock:
            self._overall_description = description
            self._overall_started = time.time()

    def start_task(self, task_id: str, name: str, description: str = "",
                   parent_id: str | None = None) -> TaskProgress:
        with self._lock:
            task = TaskProgress(
                id=task_id,
                name=name,
                description=description,
                status=TaskStatus.RUNNING,
                started_at=time.time(),
                parent_id=parent_id,
            )
            self._tasks[task_id] = task
            if task_id not in self._task_order:
                self._task_order.append(task_id)
            self._notify("start", task)
            return task

    def update_task(self, task_id: str, progress_pct: float = 0,
                    status: TaskStatus | None = None,
                    detail: str = "", **metadata) -> None:
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return
            if progress_pct:
                task.progress_pct = min(100.0, progress_pct)
            if status:
                task.status = status
            if detail:
                metadata["detail"] = detail
            if metadata:
                task.metadata.update(metadata)
            self._notify("update", task)

    def complete_task(self, task_id: str, success: bool = True, error: str = "") -> None:
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return
            task.status = TaskStatus.SUCCESS if success else TaskStatus.FAILED
            task.completed_at = time.time()
            task.progress_pct = 100.0 if success else task.progress_pct
            task.error = error
            self._notify("complete", task)

    def retry_task(self, task_id: str) -> bool:
        """Mark a task for retry. Returns False if max retries exceeded."""
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return False
            if task.retries >= task.max_retries:
                return False
            task.retries += 1
            task.status = TaskStatus.RETRYING
            task.started_at = time.time()
            task.completed_at = 0.0
            task.error = ""
            self._notify("retry", task)
            return True

    def get_summary(self) -> dict:
        """Get a summary of all task progress."""
        with self._lock:
            tasks = [self._tasks[tid] for tid in self._task_order if tid in self._tasks]
            completed = sum(1 for t in tasks if t.status == TaskStatus.SUCCESS)
            failed = sum(1 for t in tasks if t.status == TaskStatus.FAILED)
            running = sum(1 for t in tasks if t.status == TaskStatus.RUNNING)
            pending = sum(1 for t in tasks if t.status == TaskStatus.PENDING)
            total = len(tasks)

            return {
                "overall": self._overall_description,
                "elapsed": time.time() - self._overall_started if self._overall_started else 0,
                "total": total,
                "completed": completed,
                "failed": failed,
                "running": running,
                "pending": pending,
                "progress_pct": (completed / total * 100) if total > 0 else 0,
                "tasks": [
                    {
                        "id": t.id,
                        "name": t.name,
                        "status": t.status.value,
                        "elapsed": round(t.elapsed, 1),
                        "progress_pct": round(t.progress_pct, 1),
                        "error": t.error,
                        "retries": t.retries,
                    }
                    for t in tasks
                ],
            }

    def get_active_tasks(self) -> list[TaskProgress]:
        with self._lock:
            return [
                self._tasks[tid]
                for tid in self._task_order
                if tid in self._tasks and self._tasks[tid].status == TaskStatus.RUNNING
            ]

    def add_listener(self, callback) -> None:
        self._listeners.append(callback)

    def _notify(self, event: str, task: TaskProgress) -> None:
        for listener in self._listeners:
            try:
                listener(event, task)
            except Exception:
                pass


# Global progress instance
progress_manager = ProgressManager()

# Thread-local storage for current running task ID
_thread_local = threading.local()


def set_current_task(task_id: str) -> None:
    """Set the current task ID for this thread (called by _safe_call)."""
    _thread_local.current_task_id = task_id


def get_current_task() -> str | None:
    """Get the current task ID for this thread."""
    return getattr(_thread_local, "current_task_id", None)


def report_progress(pct: float, detail: str = "") -> None:
    """Convenience: report progress on the current thread's task.

    Called from within tool functions (e.g. scan_smali_directory)
    to provide intermediate progress updates.
    """
    task_id = get_current_task()
    if task_id:
        progress_manager.update_task(task_id, progress_pct=pct, detail=detail)
