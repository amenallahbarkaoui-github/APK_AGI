"""Zipalign wrapper — align APK ZIP entries to 4-byte boundaries."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from .base import ToolResult, run_tool_command


def zipalign(
    zipalign_bin: str,
    input_apk: str | Path,
    output_apk: str | Path,
    alignment: int = 4,
    log_file: Optional[Path] = None,
) -> ToolResult:
    """Zip-align an APK (required before signing with apksigner).

    Aligns uncompressed entries on 4-byte boundaries for runtime performance.
    Returns ToolResult with artifacts["aligned_apk"] on success.
    """
    input_apk = Path(input_apk).resolve()
    output_apk = Path(output_apk).resolve()
    output_apk.parent.mkdir(parents=True, exist_ok=True)

    # -f forces overwrite if output already exists
    cmd = [zipalign_bin, "-f", "-v", str(alignment), str(input_apk), str(output_apk)]
    result = run_tool_command(cmd, log_file=log_file, timeout=120)

    if result.success and output_apk.is_file():
        result.artifacts["aligned_apk"] = str(output_apk)
    return result


def verify_alignment(
    zipalign_bin: str,
    apk_path: str | Path,
    alignment: int = 4,
    log_file: Optional[Path] = None,
) -> ToolResult:
    """Verify that an APK is properly zip-aligned."""
    apk_path = Path(apk_path).resolve()
    cmd = [zipalign_bin, "-c", "-v", str(alignment), str(apk_path)]
    return run_tool_command(cmd, log_file=log_file, timeout=60)
