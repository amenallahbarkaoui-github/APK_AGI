"""Base tool utilities — ToolResult, subprocess runner, retry logic, and error recovery."""

from __future__ import annotations

import logging
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("apk_agent.tools")

# Max output lines sent to the LLM (kept short to avoid token bloat)
MAX_OUTPUT_LINES = 120


@dataclass
class ToolResult:
    """Structured result of a tool/command execution."""

    success: bool
    exit_code: int
    stdout: str  # truncated tail for LLM
    stderr: str  # truncated tail for LLM
    command: str
    duration_seconds: float = 0.0
    artifacts: dict = field(default_factory=dict)  # extra structured data
    retries: int = 0

    def to_llm_str(self) -> str:
        """Compact string representation for the LLM context window."""
        status = "✅ SUCCESS" if self.success else "❌ FAILED"
        parts = [
            f"[{status}] exit_code={self.exit_code}  duration={self.duration_seconds:.1f}s",
            f"command: {self.command}",
        ]
        if self.retries > 0:
            parts.append(f"retries: {self.retries}")
        if self.stdout.strip():
            parts.append(f"--- stdout (last {MAX_OUTPUT_LINES} lines) ---")
            parts.append(self.stdout.strip())
        if self.stderr.strip():
            parts.append(f"--- stderr (last {MAX_OUTPUT_LINES} lines) ---")
            parts.append(self.stderr.strip())
        if self.artifacts:
            parts.append(f"--- artifacts ---")
            for k, v in self.artifacts.items():
                parts.append(f"  {k}: {v}")
        if not self.success:
            parts.append("--- error recovery hints ---")
            parts.append(self._suggest_recovery())
        return "\n".join(parts)

    def _suggest_recovery(self) -> str:
        """Provide actionable recovery hints based on error type."""
        stderr_lower = self.stderr.lower()
        hints = []

        if "out of memory" in stderr_lower or "heap" in stderr_lower:
            hints.append("Try with fewer threads or on a smaller subset of files")
        if "permission denied" in stderr_lower:
            hints.append("Check file permissions or run with elevated privileges")
        if "not found" in stderr_lower or self.exit_code == -2:
            hints.append("Tool binary not found. Check tool path in config or install the tool")
        if "timeout" in stderr_lower or self.exit_code == -1:
            hints.append("Command timed out. Consider increasing timeout or processing fewer files")
        if "invalid" in stderr_lower or "malformed" in stderr_lower:
            hints.append("Input file may be corrupted or in unexpected format")
        if self.exit_code == 1 and "brut" in stderr_lower:
            hints.append("Apktool error — try with --force-all flag or update apktool")

        return "; ".join(hints) if hints else "Check stderr for details and try an alternative approach"


def _tail(text: str, max_lines: int = MAX_OUTPUT_LINES) -> str:
    """Keep only the last *max_lines* lines of text."""
    lines = text.splitlines()
    if len(lines) > max_lines:
        return f"... ({len(lines) - max_lines} lines truncated) ...\n" + "\n".join(
            lines[-max_lines:]
        )
    return text


def run_tool_command(
    cmd: list[str] | str,
    cwd: Optional[str | Path] = None,
    timeout: int = 600,
    log_file: Optional[Path] = None,
    shell: bool = False,
    max_retries: int = 0,
    retry_delay: float = 2.0,
) -> ToolResult:
    """Run a subprocess, capture output, return structured ToolResult.

    Full output is written to *log_file* (if given);
    truncated output is returned for LLM consumption.

    Args:
        max_retries: Number of retries on failure (0 = no retry).
        retry_delay: Seconds to wait between retries.
    """
    cmd_str = cmd if isinstance(cmd, str) else " ".join(cmd)
    logger.info("Running: %s  (cwd=%s)", cmd_str, cwd)

    last_result = None
    for attempt in range(max_retries + 1):
        if attempt > 0:
            logger.info("Retry %d/%d for: %s", attempt, max_retries, cmd_str)
            time.sleep(retry_delay)

        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(cwd) if cwd else None,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=shell,
            )
            elapsed = time.monotonic() - start

            # Full log
            if log_file:
                try:
                    log_file.parent.mkdir(parents=True, exist_ok=True)
                    with open(log_file, "a", encoding="utf-8") as f:
                        f.write(f"\n{'='*60}\n")
                        f.write(f"CMD: {cmd_str}\n")
                        f.write(f"EXIT: {proc.returncode}  TIME: {elapsed:.1f}s")
                        if attempt > 0:
                            f.write(f"  RETRY: {attempt}/{max_retries}")
                        f.write(f"\n--- STDOUT ---\n{proc.stdout}\n")
                        f.write(f"--- STDERR ---\n{proc.stderr}\n")
                except Exception:
                    pass  # Don't fail on log errors

            last_result = ToolResult(
                success=proc.returncode == 0,
                exit_code=proc.returncode,
                stdout=_tail(proc.stdout),
                stderr=_tail(proc.stderr),
                command=cmd_str,
                duration_seconds=round(elapsed, 2),
                retries=attempt,
            )

            if last_result.success:
                return last_result

        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - start
            last_result = ToolResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=f"Command timed out after {timeout}s",
                command=cmd_str,
                duration_seconds=round(elapsed, 2),
                retries=attempt,
            )

        except FileNotFoundError as e:
            last_result = ToolResult(
                success=False,
                exit_code=-2,
                stdout="",
                stderr=f"Command not found: {e}",
                command=cmd_str,
                duration_seconds=0.0,
                retries=attempt,
            )
            # No point retrying if the binary doesn't exist
            return last_result

        except Exception as e:
            elapsed = time.monotonic() - start
            last_result = ToolResult(
                success=False,
                exit_code=-99,
                stdout="",
                stderr=f"Unexpected error: {e}",
                command=cmd_str,
                duration_seconds=round(elapsed, 2),
                retries=attempt,
            )

    return last_result


def safe_tool_call(func, *args, **kwargs) -> str:
    """Wrap any tool function call with error handling.

    Returns a JSON error string on any exception instead of crashing.
    """
    import json
    import traceback

    try:
        return func(*args, **kwargs)
    except Exception as e:
        logger.error("Tool call failed: %s — %s", func.__name__ if hasattr(func, '__name__') else 'unknown', e)
        return json.dumps({
            "success": False,
            "error": str(e),
            "error_type": type(e).__name__,
            "recovery_hint": "The tool encountered an unexpected error. "
                           "Try a different approach or check the input parameters.",
            "traceback": traceback.format_exc()[-500:],
        })
