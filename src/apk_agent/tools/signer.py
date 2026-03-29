"""APK signing utilities — apksigner / uber-apk-signer / jarsigner."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional

from .base import ToolResult, run_tool_command


def _ensure_debug_keystore(keystore_path: Path) -> None:
    """Generate a debug keystore if it doesn't exist."""
    if keystore_path.is_file():
        return
    keystore_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "keytool",
        "-genkeypair",
        "-v",
        "-keystore", str(keystore_path),
        "-storepass", "android",
        "-alias", "androiddebugkey",
        "-keypass", "android",
        "-keyalg", "RSA",
        "-keysize", "2048",
        "-validity", "10000",
        "-dname", "CN=Debug,O=Android,C=US",
    ]
    subprocess.run(cmd, capture_output=True, timeout=30, check=False)


def sign_apk(
    signer_bin: str,
    unsigned_apk: str | Path,
    output_apk: str | Path,
    keystore_path: Optional[str | Path] = None,
    keystore_password: str = "android",
    key_alias: str = "androiddebugkey",
    key_password: str = "android",
    log_file: Optional[Path] = None,
) -> ToolResult:
    """Sign an APK using apksigner, uber-apk-signer, or jarsigner.

    Auto-generates a debug keystore if none is provided.
    """
    unsigned_apk = Path(unsigned_apk).resolve()
    output_apk = Path(output_apk).resolve()

    # Ensure keystore
    if not keystore_path:
        keystore_path = unsigned_apk.parent / "debug.keystore"
        _ensure_debug_keystore(keystore_path)
    keystore_path = Path(keystore_path)

    signer_name = Path(signer_bin).stem.lower()

    if "uber" in signer_name or signer_name.endswith(".jar"):
        # uber-apk-signer
        cmd = [
            "java", "-jar", str(signer_bin),
            "--apks", str(unsigned_apk),
            "--ks", str(keystore_path),
            "--ksPass", keystore_password,
            "--ksAlias", key_alias,
            "--ksKeyPass", key_password,
            "-o", str(output_apk.parent),
        ]
    elif "jarsigner" in signer_name:
        # jarsigner (legacy)
        import shutil
        shutil.copy2(str(unsigned_apk), str(output_apk))
        cmd = [
            signer_bin,
            "-verbose",
            "-sigalg", "SHA256withRSA",
            "-digestalg", "SHA-256",
            "-keystore", str(keystore_path),
            "-storepass", keystore_password,
            "-keypass", key_password,
            str(output_apk),
            key_alias,
        ]
    else:
        # apksigner (Android SDK)
        import shutil
        shutil.copy2(str(unsigned_apk), str(output_apk))
        cmd = [
            signer_bin, "sign",
            "--ks", str(keystore_path),
            "--ks-pass", f"pass:{keystore_password}",
            "--ks-key-alias", key_alias,
            "--key-pass", f"pass:{key_password}",
            str(output_apk),
        ]

    result = run_tool_command(cmd, log_file=log_file, timeout=120)
    if result.success or output_apk.is_file():
        result.artifacts["signed_apk"] = str(output_apk)
    return result


def zipalign_apk(
    zipalign_bin: str,
    input_apk: str | Path,
    output_apk: str | Path,
    log_file: Optional[Path] = None,
) -> ToolResult:
    """Zip-align an APK (optional pre-signing step)."""
    cmd = [zipalign_bin, "-v", "4", str(input_apk), str(output_apk)]
    return run_tool_command(cmd, log_file=log_file, timeout=60)
