"""dex2jar wrapper — convert DEX/APK to JAR for JVM-level analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from .base import ToolResult, run_tool_command


def convert(
    d2j_bin: str,
    input_path: str | Path,
    output_jar: str | Path,
    force: bool = True,
    log_file: Optional[Path] = None,
) -> ToolResult:
    """Convert a .dex or .apk file to a .jar using dex2jar.

    Args:
        d2j_bin: Path to d2j-dex2jar binary (or .bat on Windows).
        input_path: Path to the .dex or .apk file.
        output_jar: Desired output .jar path.
        force: Overwrite output if it exists.
        log_file: Optional log file for full output.

    Returns:
        ToolResult with artifacts["jar_path"] on success.
    """
    input_path = Path(input_path).resolve()
    output_jar = Path(output_jar).resolve()
    output_jar.parent.mkdir(parents=True, exist_ok=True)

    cmd = [d2j_bin, str(input_path), "-o", str(output_jar)]
    if force:
        cmd.append("--force")

    result = run_tool_command(cmd, log_file=log_file, timeout=300)

    if result.success or output_jar.is_file():
        result.artifacts["jar_path"] = str(output_jar)
        if output_jar.is_file():
            size_bytes = output_jar.stat().st_size
            result.artifacts["jar_size_mb"] = round(size_bytes / (1024 * 1024), 2)
        else:
            result.artifacts["jar_size_mb"] = 0
    return result
