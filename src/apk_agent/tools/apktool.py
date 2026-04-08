"""Apktool wrapper — decompile and rebuild APKs."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from .base import ToolResult, run_tool_command


def decompile(
    apktool_bin: str,
    apk_path: str | Path,
    output_dir: str | Path,
    log_file: Optional[Path] = None,
    force: bool = True,
) -> ToolResult:
    """Decompile an APK using apktool d.

    Returns ToolResult with artifacts["output_dir"] on success.
    """
    apk_path = Path(apk_path).resolve()
    output_dir = Path(output_dir).resolve()

    cmd = [apktool_bin, "d", str(apk_path), "-o", str(output_dir)]
    if force:
        cmd.append("-f")

    result = run_tool_command(cmd, log_file=log_file, timeout=300)
    if result.success:
        result.artifacts["output_dir"] = str(output_dir)
        # list some key dirs found
        smali_dirs = sorted(output_dir.glob("smali*"))
        result.artifacts["smali_dirs"] = [str(d) for d in smali_dirs]
        manifest = output_dir / "AndroidManifest.xml"
        result.artifacts["manifest_exists"] = manifest.is_file()
    return result


def build(
    apktool_bin: str,
    project_dir: str | Path,
    output_apk: Optional[str | Path] = None,
    log_file: Optional[Path] = None,
    use_aapt2: bool = True,
    force_all: bool = False,
) -> ToolResult:
    """Rebuild an APK from decompiled apktool project using apktool b.

    Returns ToolResult with artifacts["output_apk"] on success.
    """
    project_dir = Path(project_dir).resolve()

    cmd = [apktool_bin, "b", str(project_dir)]
    if use_aapt2:
        cmd.append("--use-aapt2")
    if force_all:
        cmd.append("--force-all")
    if output_apk:
        output_apk = Path(output_apk).resolve()
        cmd.extend(["-o", str(output_apk)])
    else:
        output_apk = project_dir / "dist" / (project_dir.name + ".apk")

    result = run_tool_command(cmd, log_file=log_file, timeout=300)

    # If build failed due to private resource errors, retry with --force-all
    if not result.success and not force_all:
        stderr = result.stderr or ""
        if "is private" in stderr or "failed linking file resources" in stderr:
            result = run_tool_command(
                cmd + (["--force-all"] if "--force-all" not in cmd else []),
                log_file=log_file,
                timeout=300,
            )

    if result.success:
        # apktool puts output in dist/ by default
        if output_apk and output_apk.is_file():
            result.artifacts["output_apk"] = str(output_apk)
        else:
            # try default location
            default = project_dir / "dist"
            apks = list(default.glob("*.apk"))
            if apks:
                result.artifacts["output_apk"] = str(apks[0])
    return result
