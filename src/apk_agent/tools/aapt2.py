"""aapt2 wrapper — dump APK metadata (permissions, components, SDK info)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from .base import ToolResult, run_tool_command


def dump_badging(
    aapt2_bin: str,
    apk_path: str | Path,
    log_file: Optional[Path] = None,
) -> ToolResult:
    """Run `aapt2 dump badging <apk>` and parse the output.

    Returns ToolResult with structured artifacts:
        - package_name, version_code, version_name
        - min_sdk, target_sdk
        - app_label
        - permissions (list)
        - activities, services, receivers, providers (lists)
    """
    apk_path = Path(apk_path).resolve()
    cmd = [aapt2_bin, "dump", "badging", str(apk_path)]

    result = run_tool_command(cmd, log_file=log_file, timeout=60)

    if result.success and result.stdout:
        _parse_badging_output(result)
    return result


def dump_permissions(
    aapt2_bin: str,
    apk_path: str | Path,
    log_file: Optional[Path] = None,
) -> ToolResult:
    """Run `aapt2 dump permissions <apk>` for permission details."""
    apk_path = Path(apk_path).resolve()
    cmd = [aapt2_bin, "dump", "permissions", str(apk_path)]
    return run_tool_command(cmd, log_file=log_file, timeout=60)


def dump_resources(
    aapt2_bin: str,
    apk_path: str | Path,
    resource_type: str = "",
    log_file: Optional[Path] = None,
) -> ToolResult:
    """Run `aapt2 dump resources <apk>` to list all resources.

    Args:
        resource_type: Optional filter like 'string', 'drawable', etc.
    """
    apk_path = Path(apk_path).resolve()
    cmd = [aapt2_bin, "dump", "resources", str(apk_path)]
    result = run_tool_command(cmd, log_file=log_file, timeout=120)

    if resource_type and result.success:
        # Filter output lines to show only matching resource type
        filtered = []
        for line in result.stdout.splitlines():
            if resource_type.lower() in line.lower():
                filtered.append(line)
        if filtered:
            result.artifacts["filtered_resources"] = list(filtered[:100])
            result.artifacts["filter"] = resource_type
    return result


def _parse_badging_output(result: ToolResult) -> None:
    """Parse aapt2 dump badging output into structured artifacts."""
    text = result.stdout

    # Package info
    pkg_match = re.search(
        r"package: name='([^']+)'\s+versionCode='([^']+)'\s+versionName='([^']*)'",
        text,
    )
    if pkg_match:
        result.artifacts["package_name"] = pkg_match.group(1)
        result.artifacts["version_code"] = pkg_match.group(2)
        result.artifacts["version_name"] = pkg_match.group(3)

    # SDK versions
    sdk_min = re.search(r"sdkVersion:'(\d+)'", text)
    sdk_target = re.search(r"targetSdkVersion:'(\d+)'", text)
    if sdk_min:
        result.artifacts["min_sdk"] = int(sdk_min.group(1))
    if sdk_target:
        result.artifacts["target_sdk"] = int(sdk_target.group(1))

    # App label
    label = re.search(r"application-label(?:-[a-z]+)?:'([^']+)'", text)
    if label:
        result.artifacts["app_label"] = label.group(1)

    # Permissions used
    perms = re.findall(r"uses-permission:\s*name='([^']+)'", text)
    result.artifacts["permissions"] = sorted(set(perms))

    # Activities
    activities = re.findall(r"activity:\s*name='([^']+)'", text, re.IGNORECASE)
    result.artifacts["activities"] = list(activities[:50])

    # Services
    services = re.findall(r"service:\s*name='([^']+)'", text, re.IGNORECASE)
    result.artifacts["services"] = list(services[:50])

    # Receivers
    receivers = re.findall(r"receiver:\s*name='([^']+)'", text, re.IGNORECASE)
    result.artifacts["receivers"] = list(receivers[:50])

    # Providers
    providers = re.findall(r"provider:\s*name='([^']+)'", text, re.IGNORECASE)
    result.artifacts["providers"] = list(providers[:20])
