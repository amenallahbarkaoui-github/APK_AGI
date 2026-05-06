"""APK signing utilities - apksigner / uber-apk-signer / jarsigner."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from .base import ToolResult, run_tool_command


_APKSIGNER_VERIFY_SCHEME_RE = re.compile(
    r"Verified using\s+(?P<scheme>v\d+(?:\.\d+)?)\s+scheme(?:\s*\([^)]*\))?:\s*(?P<verified>true|false)",
    re.IGNORECASE,
)

_MODERN_SIGNATURE_SCHEMES = ("v2", "v3", "v3.1", "v4")


def _extract_verified_signature_schemes(verify_output: str) -> tuple[list[str], dict[str, bool]]:
    schemes: list[str] = []
    scheme_details: dict[str, bool] = {}

    for match in _APKSIGNER_VERIFY_SCHEME_RE.finditer(verify_output or ""):
        scheme = match.group("scheme").lower()
        verified = match.group("verified").lower() == "true"
        scheme_details[scheme] = verified
        if verified:
            schemes.append(scheme)

    return schemes, scheme_details


def _build_verify_commands(
    *,
    signer_bin: str,
    signer_name: str,
    final_apk: Path,
    verify_bin: Optional[str | Path] = None,
) -> list[list[str]]:
    commands: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()

    def _add(cmd: list[str]) -> None:
        key = tuple(str(part) for part in cmd)
        if key in seen:
            return
        seen.add(key)
        commands.append(cmd)

    apksigner_verify_bin = str(verify_bin) if verify_bin else ""
    if not apksigner_verify_bin:
        if "uber" not in signer_name and not signer_name.endswith(".jar") and "jarsigner" not in signer_name:
            apksigner_verify_bin = signer_bin
        else:
            apksigner_verify_bin = "apksigner"

    if apksigner_verify_bin:
        _add([apksigner_verify_bin, "verify", "--verbose", "--print-certs", str(final_apk)])

    if "jarsigner" in signer_name:
        _add([signer_bin, "-verify", "-certs", "-verbose", str(final_apk)])
    elif "uber" in signer_name or signer_name.endswith(".jar"):
        _add(["jarsigner", "-verify", "-certs", "-verbose", str(final_apk)])

    return commands


def _is_apksigner_verify_command(cmd: list[str]) -> bool:
    if not cmd:
        return False
    binary_name = Path(str(cmd[0])).stem.lower()
    return "apksigner" in binary_name and len(cmd) > 1 and cmd[1] == "verify"


def _validate_keystore(
    keystore_path: Path,
    *,
    keystore_password: str = "android",
    key_alias: str = "androiddebugkey",
) -> tuple[bool, str]:
    if not keystore_path.is_file():
        return False, "Keystore file does not exist."
    try:
        if keystore_path.stat().st_size <= 0:
            return False, "Keystore file is empty."
    except OSError as exc:
        return False, str(exc)

    cmd = [
        "keytool",
        "-list",
        "-v",
        "-keystore", str(keystore_path),
        "-storepass", keystore_password,
        "-alias", key_alias,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    except OSError as exc:
        return False, str(exc)

    if result.returncode == 0:
        return True, ""

    details = (result.stderr or result.stdout or "keytool list failed").strip()
    return False, details[:500]


def _ensure_debug_keystore(keystore_path: Path) -> None:
    """Generate a usable debug keystore when the default one is missing or corrupt."""
    is_valid, validation_error = _validate_keystore(keystore_path)
    if is_valid:
        return

    if keystore_path.exists():
        corrupt_backup = keystore_path.with_suffix(f"{keystore_path.suffix}.corrupt")
        try:
            corrupt_backup.unlink(missing_ok=True)
        except OSError:
            pass
        try:
            keystore_path.replace(corrupt_backup)
        except OSError:
            try:
                keystore_path.unlink(missing_ok=True)
            except OSError:
                pass

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
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    except OSError as exc:
        raise RuntimeError(f"Failed to create debug keystore: {exc}") from exc

    if result.returncode != 0:
        details = (result.stderr or result.stdout or validation_error or "keytool genkeypair failed").strip()
        raise RuntimeError(f"Failed to create debug keystore: {details[:500]}")

    is_valid, validation_error = _validate_keystore(keystore_path)
    if not is_valid:
        raise RuntimeError(f"Generated debug keystore is still invalid: {validation_error}")


def sign_apk(
    signer_bin: str,
    unsigned_apk: str | Path,
    output_apk: str | Path,
    keystore_path: Optional[str | Path] = None,
    keystore_password: str = "android",
    key_alias: str = "androiddebugkey",
    key_password: str = "android",
    verify_bin: Optional[str | Path] = None,
    log_file: Optional[Path] = None,
) -> ToolResult:
    """Sign an APK using apksigner, uber-apk-signer, or jarsigner.

    Auto-generates a debug keystore if none is provided.
    """
    unsigned_apk = Path(unsigned_apk).resolve()
    output_apk = Path(output_apk).resolve()
    output_apk.parent.mkdir(parents=True, exist_ok=True)

    if not keystore_path:
        keystore_path = unsigned_apk.parent / "debug.keystore"
        try:
            _ensure_debug_keystore(keystore_path)
        except RuntimeError as exc:
            return ToolResult(
                success=False,
                exit_code=-12,
                stdout="",
                stderr=str(exc),
                command="sign_apk()",
            )
    keystore_path = Path(keystore_path)

    signer_name = Path(signer_bin).stem.lower()

    try:
        output_apk.unlink(missing_ok=True)
    except OSError:
        pass

    if "uber" in signer_name or signer_name.endswith(".jar"):
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
        cmd = [
            signer_bin, "sign",
            "--ks", str(keystore_path),
            "--ks-pass", f"pass:{keystore_password}",
            "--ks-key-alias", key_alias,
            "--key-pass", f"pass:{key_password}",
            "--v1-signing-enabled", "true",
            "--v2-signing-enabled", "true",
            "--v3-signing-enabled", "true",
            "--out", str(output_apk),
            str(unsigned_apk),
        ]

    result = run_tool_command(cmd, log_file=log_file, timeout=120)
    if not result.success:
        try:
            output_apk.unlink(missing_ok=True)
        except OSError:
            pass
        return result

    final_apk = output_apk
    if ("uber" in signer_name or signer_name.endswith(".jar")) and not final_apk.is_file():
        candidates = sorted(output_apk.parent.glob(f"{unsigned_apk.stem}*-debugSigned.apk"))
        if candidates:
            final_apk = candidates[-1]

    if not final_apk.is_file():
        result.success = False
        result.exit_code = -3
        result.stderr = "Signer reported success but no signed APK was created."
        return result

    verify_result: ToolResult | None = None
    verify_cmd_used: list[str] | None = None
    last_verify_failure: ToolResult | None = None
    for verify_cmd in _build_verify_commands(
        signer_bin=signer_bin,
        signer_name=signer_name,
        final_apk=final_apk,
        verify_bin=verify_bin,
    ):
        current_verify = run_tool_command(verify_cmd, log_file=log_file, timeout=120)
        if current_verify.success:
            verify_result = current_verify
            verify_cmd_used = verify_cmd
            break
        last_verify_failure = current_verify
        if current_verify.exit_code != -2:
            break

    if verify_result is None:
        verify_details = "No available verification command succeeded."
        exit_code = -4
        if last_verify_failure is not None:
            exit_code = last_verify_failure.exit_code
            verify_details = (last_verify_failure.stderr or last_verify_failure.stdout or verify_details).strip()
        result.success = False
        result.exit_code = exit_code
        result.artifacts["signature_verified"] = False
        result.stderr = (
            (result.stderr + "\n" if result.stderr else "")
            + f"Signature verification failed: {verify_details}"
        )
        try:
            final_apk.unlink(missing_ok=True)
        except OSError:
            pass
        return result

    if verify_cmd_used and _is_apksigner_verify_command(verify_cmd_used):
        verify_output = "\n".join(
            chunk for chunk in [verify_result.stdout, verify_result.stderr] if chunk
        )
        verified_schemes, scheme_details = _extract_verified_signature_schemes(verify_output)
        if scheme_details:
            result.artifacts["signature_scheme_details"] = scheme_details
            result.artifacts["signature_scheme_source"] = "apksigner verify"
            if not any(scheme_details.values()):
                result.success = False
                result.exit_code = -4
                result.artifacts["signature_verified"] = False
                result.stderr = (
                    (result.stderr + "\n" if result.stderr else "")
                    + "Signature verification failed: apksigner verify did not confirm any enabled signature scheme."
                )
                try:
                    final_apk.unlink(missing_ok=True)
                except OSError:
                    pass
                return result

            modern_schemes = [
                scheme for scheme in _MODERN_SIGNATURE_SCHEMES
                if scheme_details.get(scheme, False)
            ]
            if modern_schemes and not scheme_details.get("v1", False):
                result.artifacts["signature_compatibility_warning"] = (
                    "Modern signature schemes were verified without v1/JAR signing. "
                    "This is installable on modern Android but may not support very old devices."
                )
            elif scheme_details.get("v1", False) and not modern_schemes:
                result.artifacts["signature_compatibility_warning"] = (
                    "Only v1/JAR signing was verified. Installability may vary on newer-device policy combinations."
                )

        result.artifacts["signature_verified"] = True
        if verified_schemes:
            result.artifacts["signature_schemes"] = ",".join(verified_schemes)
    else:
        result.artifacts["signature_verified"] = True
        result.artifacts.setdefault("signature_scheme_source", "jarsigner verify")
        if "jarsigner" in signer_name:
            result.artifacts.setdefault("signature_schemes", "v1")
            result.artifacts.setdefault(
                "signature_compatibility_warning",
                "Verified with jarsigner only; modern v2/v3 scheme information is unavailable from this verifier.",
            )

    result.artifacts["signed_apk"] = str(final_apk)
    return result


def zipalign_apk(
    zipalign_bin: str,
    input_apk: str | Path,
    output_apk: str | Path,
    log_file: Optional[Path] = None,
) -> ToolResult:
    """Zip-align an APK (optional pre-signing step)."""
    cmd = [zipalign_bin, "-v", "4", str(input_apk), str(output_apk)]
    result = run_tool_command(cmd, log_file=log_file, timeout=60)
    if result.success and Path(output_apk).is_file():
        result.artifacts["aligned_apk"] = str(Path(output_apk).resolve())
    return result