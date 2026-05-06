"""Per-session execution context for tool execution.

Keeps mutable tool/session state isolated per graph/session while preserving
the old module-level access style through lightweight proxy objects.
"""

from __future__ import annotations

from collections.abc import MutableMapping, MutableSequence
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ExecutionContext:
    """Mutable state bound to a single tool-execution session."""

    config: Any = None
    project: Any = None
    tool_cache: dict[str, str] = field(default_factory=dict)
    scratchpad: dict[str, Any] = field(default_factory=dict)
    task_plan: list[dict[str, Any]] = field(default_factory=list)
    execution_plan: dict[str, Any] = field(default_factory=dict)
    plan_journal: list[dict[str, Any]] = field(default_factory=list)
    patch_journal: list[dict[str, Any]] = field(default_factory=list)
    runtime_slots: dict[str, Any] = field(default_factory=dict)


_LEGACY_CONTEXT = ExecutionContext()
_ACTIVE_CONTEXT: ContextVar[ExecutionContext | None] = ContextVar(
    "apk_agent_execution_context",
    default=None,
)


def get_active_execution_context() -> ExecutionContext:
    """Return the current execution context.

    Falls back to a legacy singleton so older code paths keep working even if a
    caller has not explicitly initialised a session context yet.
    """
    context = _ACTIVE_CONTEXT.get()
    return context if context is not None else _LEGACY_CONTEXT


def set_active_execution_context(config: Any, project: Any) -> ExecutionContext:
    """Create and activate a fresh session context."""
    context = ExecutionContext(config=config, project=project)
    _ACTIVE_CONTEXT.set(context)
    return context


def get_runtime_slot(name: str, default: Any = None) -> Any:
    """Return a named runtime slot from the active context."""
    return get_active_execution_context().runtime_slots.get(name, default)


def set_runtime_slot(name: str, value: Any) -> Any:
    """Set a named runtime slot on the active context."""
    get_active_execution_context().runtime_slots[name] = value
    return value


def clear_runtime_slots(*names: str) -> None:
    """Clear specific runtime slots, or all of them if no names are supplied."""
    runtime_slots = get_active_execution_context().runtime_slots
    if not names:
        runtime_slots.clear()
        return
    for name in names:
        runtime_slots.pop(name, None)


class _ObjectProxy:
    def __init__(self, attr_name: str):
        object.__setattr__(self, "_attr_name", attr_name)

    def _target(self) -> Any:
        return getattr(get_active_execution_context(), object.__getattribute__(self, "_attr_name"))

    def __getattr__(self, name: str) -> Any:
        target = self._target()
        if target is None:
            raise AttributeError(name)
        return getattr(target, name)

    def __bool__(self) -> bool:
        return bool(self._target())

    def __repr__(self) -> str:
        return repr(self._target())

    def __str__(self) -> str:
        return str(self._target())


class _DictProxy(MutableMapping[str, Any]):
    def __init__(self, attr_name: str):
        self._attr_name = attr_name

    def _mapping(self) -> dict[str, Any]:
        return getattr(get_active_execution_context(), self._attr_name)

    def __getitem__(self, key: str) -> Any:
        return self._mapping()[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self._mapping()[key] = value

    def __delitem__(self, key: str) -> None:
        del self._mapping()[key]

    def __iter__(self):
        return iter(self._mapping())

    def __len__(self) -> int:
        return len(self._mapping())

    def __repr__(self) -> str:
        return repr(self._mapping())


class _ListProxy(MutableSequence[Any]):
    def __init__(self, attr_name: str):
        self._attr_name = attr_name

    def _items(self) -> list[Any]:
        return getattr(get_active_execution_context(), self._attr_name)

    def __getitem__(self, index):
        return self._items()[index]

    def __setitem__(self, index, value) -> None:
        self._items()[index] = value

    def __delitem__(self, index) -> None:
        del self._items()[index]

    def __len__(self) -> int:
        return len(self._items())

    def insert(self, index: int, value: Any) -> None:
        self._items().insert(index, value)

    def __repr__(self) -> str:
        return repr(self._items())


CONFIG_PROXY = _ObjectProxy("config")
PROJECT_PROXY = _ObjectProxy("project")
TOOL_CACHE_PROXY = _DictProxy("tool_cache")
SCRATCHPAD_PROXY = _DictProxy("scratchpad")
TASK_PLAN_PROXY = _ListProxy("task_plan")
EXECUTION_PLAN_PROXY = _DictProxy("execution_plan")
PLAN_JOURNAL_PROXY = _ListProxy("plan_journal")
PATCH_JOURNAL_PROXY = _ListProxy("patch_journal")