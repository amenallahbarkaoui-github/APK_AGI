"""JADX wrapper — decompile APK/DEX to Java source."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from .base import ToolResult, run_tool_command


def decompile(
    jadx_bin: str,
    apk_path: str | Path,
    output_dir: str | Path,
    log_file: Optional[Path] = None,
    threads: int = 4,
    show_bad_code: bool = True,
) -> ToolResult:
    """Decompile APK to Java source using JADX.

    Returns ToolResult with artifacts["output_dir"] and package info.
    """
    apk_path = Path(apk_path).resolve()
    output_dir = Path(output_dir).resolve()

    cmd = [
        jadx_bin,
        str(apk_path),
        "-d", str(output_dir),
        "--threads-count", str(threads),
        "--deobf",  # rename obfuscated names
    ]
    if show_bad_code:
        cmd.append("--show-bad-code")

    result = run_tool_command(cmd, log_file=log_file, timeout=600)
    if result.success or output_dir.exists():
        result.artifacts["output_dir"] = str(output_dir)
        # discover top-level packages
        sources_dir = output_dir / "sources"
        if sources_dir.is_dir():
            packages = sorted(
                d.name for d in sources_dir.iterdir() if d.is_dir()
            )
            result.artifacts["top_packages"] = packages[:20]
            result.artifacts["sources_dir"] = str(sources_dir)
        # check for resources
        res_dir = output_dir / "resources"
        result.artifacts["resources_dir_exists"] = res_dir.is_dir()

        # jadx exits with code 1 when some classes fail to decompile,
        # which is normal for obfuscated/large APKs.  Mark as success
        # when it actually produced usable output.
        if not result.success and sources_dir.is_dir():
            src_files = list(sources_dir.rglob("*.java"))
            if src_files:
                result.success = True
                result.artifacts["partial_errors"] = True
                result.artifacts["decompiled_files"] = len(src_files)
    return result
