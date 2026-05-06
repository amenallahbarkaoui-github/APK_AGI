"""Compatibility wrapper for project-wide native analysis.

The original module exposed a shallow inventory API. It now delegates to the
native RE core so existing callers keep the same entry point while receiving a
richer ELF/JNI/function/patch-target view.
"""

from __future__ import annotations

from pathlib import Path

from apk_agent.tools.native_re_core import analyze_native_project


def analyze_native_libs(apktool_dir: str | Path) -> dict:
    """Analyze project native libraries using the deeper native RE core."""
    return analyze_native_project(Path(apktool_dir))
