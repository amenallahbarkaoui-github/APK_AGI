"""Download and install external RE tools into the project's tools/bin/ directory.

Downloads:
  - apktool (JAR)
  - JADX (ZIP → extract)
  - dex-tools / dex2jar (ZIP → extract)

Usage:
    python scripts/setup_tools.py
"""

from __future__ import annotations

import io
import os
import stat
import sys
import urllib.request
import zipfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Tool download URLs (latest stable releases)
# ---------------------------------------------------------------------------

TOOLS = {
    "apktool": {
        "url": "https://github.com/iBotPeaches/Apktool/releases/download/v2.10.0/apktool_2.10.0.jar",
        "type": "jar",
        "jar_name": "apktool.jar",
    },
    "jadx": {
        "url": "https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip",
        "type": "zip",
        "subdir": "jadx",
    },
    "dex2jar": {
        "url": "https://github.com/pxb1988/dex2jar/releases/download/v2.4/dex-tools-v2.4.zip",
        "type": "zip",
        "subdir": "dex2jar",
    },
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _download(url: str, desc: str) -> bytes:
    """Download a URL with progress indication."""
    print(f"  ⬇️  Downloading {desc}...")
    print(f"      {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "APK-Agent-Setup/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = resp.read()
    size_mb = len(data) / (1024 * 1024)
    print(f"      Downloaded {size_mb:.1f} MB")
    return data


def _make_executable(path: Path) -> None:
    """Make a file executable (unix only, no-op on Windows)."""
    if os.name != "nt":
        path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def setup_tool(name: str, tool_info: dict, bin_dir: Path) -> Path | None:
    """Download and install a single tool. Returns path to binary/jar."""
    print(f"\n{'='*50}")
    print(f"📦 Setting up {name}...")

    if tool_info["type"] == "jar":
        jar_path = bin_dir / tool_info["jar_name"]
        if jar_path.is_file():
            print(f"  ✅ Already exists: {jar_path}")
            return jar_path
        data = _download(tool_info["url"], name)
        jar_path.write_bytes(data)
        print(f"  ✅ Saved to: {jar_path}")
        # Create wrapper batch/shell script
        _create_jar_wrapper(bin_dir, name, jar_path)
        return jar_path

    elif tool_info["type"] == "zip":
        subdir = bin_dir / tool_info["subdir"]
        if subdir.is_dir() and any(subdir.iterdir()):
            print(f"  ✅ Already exists: {subdir}")
            return subdir
        data = _download(tool_info["url"], name)
        subdir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            # Some zips have a root folder, extract contents
            top_dirs = {n.split("/")[0] for n in zf.namelist() if "/" in n}
            zf.extractall(subdir)
            # If there's a single root dir, move contents up
            if len(top_dirs) == 1:
                root_name = top_dirs.pop()
                nested = subdir / root_name
                if nested.is_dir():
                    for item in nested.iterdir():
                        dest = subdir / item.name
                        if not dest.exists():
                            item.rename(dest)
                    # Remove empty nested dir
                    try:
                        nested.rmdir()
                    except OSError:
                        pass
        # Make bin files executable
        bin_subdir = subdir / "bin"
        if bin_subdir.is_dir():
            for f in bin_subdir.iterdir():
                _make_executable(f)
        print(f"  ✅ Extracted to: {subdir}")
        return subdir

    return None


def _create_jar_wrapper(bin_dir: Path, name: str, jar_path: Path) -> None:
    """Create a .bat wrapper for a JAR tool on Windows."""
    bat = bin_dir / f"{name}.bat"
    bat.write_text(
        f'@echo off\njava -jar "{jar_path}" %*\n',
        encoding="utf-8",
    )
    print(f"  📝 Created wrapper: {bat}")

    # Also create a shell script for Unix
    sh = bin_dir / name
    sh.write_text(
        f'#!/bin/sh\njava -jar "{jar_path}" "$@"\n',
        encoding="utf-8",
    )
    _make_executable(sh)


def generate_env_paths(bin_dir: Path) -> dict[str, str]:
    """Find the actual binary paths after extraction."""
    paths = {}

    # apktool
    apktool_bat = bin_dir / "apktool.bat"
    if apktool_bat.is_file():
        paths["APKTOOL_PATH"] = str(apktool_bat)

    # jadx
    jadx_bin = bin_dir / "jadx" / "bin" / "jadx.bat"
    if jadx_bin.is_file():
        paths["JADX_PATH"] = str(jadx_bin)
    else:
        jadx_bin = bin_dir / "jadx" / "bin" / "jadx"
        if jadx_bin.is_file():
            paths["JADX_PATH"] = str(jadx_bin)

    # dex2jar
    d2j_bat = bin_dir / "dex2jar" / "d2j-dex2jar.bat"
    if d2j_bat.is_file():
        paths["DEX2JAR_PATH"] = str(d2j_bat)
    else:
        d2j_sh = bin_dir / "dex2jar" / "d2j-dex2jar.sh"
        if d2j_sh.is_file():
            paths["DEX2JAR_PATH"] = str(d2j_sh)

    return paths


def main() -> None:
    # Project root
    project_root = Path(__file__).resolve().parent.parent
    bin_dir = project_root / "tools" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    print("🔧 APK Agent — External Tools Setup")
    print(f"   Install directory: {bin_dir}")

    for name, info in TOOLS.items():
        try:
            setup_tool(name, info, bin_dir)
        except Exception as e:
            print(f"  ❌ Failed to install {name}: {e}")

    # Show detected paths
    paths = generate_env_paths(bin_dir)
    print(f"\n{'='*50}")
    print("📋 Add these to your .env file:\n")
    for key, val in paths.items():
        print(f"  {key}={val}")

    print(f"\n✅ Setup complete!")


if __name__ == "__main__":
    main()
