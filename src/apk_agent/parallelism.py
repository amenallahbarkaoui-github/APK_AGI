"""Shared worker-count heuristics for agent and tool parallelism."""

from __future__ import annotations

import os


def _cpu_count() -> int:
    return max(4, os.cpu_count() or 4)


def recommended_file_scan_workers() -> int:
    cpu_count = _cpu_count()
    return min(32, max(8, cpu_count * 2))


def recommended_tool_concurrency() -> int:
    cpu_count = _cpu_count()
    return min(12, max(4, cpu_count))


def build_langgraph_run_config(thread_id: str) -> dict[str, object]:
    return {
        "configurable": {"thread_id": thread_id},
        "max_concurrency": recommended_tool_concurrency(),
    }