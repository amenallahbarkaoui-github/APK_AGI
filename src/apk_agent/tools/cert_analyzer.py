"""APK certificate / signing info analyzer.

Extracts signing certificate information from META-INF/ without
requiring keytool or jarsigner — pure Python analysis.
"""

from __future__ import annotations

import hashlib
import os
import re
import zipfile
from pathlib import Path


def analyze_certificate(apk_path: str | Path) -> dict:
    """Analyze the APK's signing certificate.

    Args:
        apk_path: Path to the APK file.

    Returns:
        Certificate information including issuer, hashes, and security notes.
    """
    apk_path = Path(apk_path)
    if not apk_path.is_file():
        return {"success": False, "error": f"APK not found: {apk_path}"}

    result = {
        "success": True,
        "signing_files": [],
        "signature_scheme": "unknown",
        "cert_hashes": {},
        "findings": [],
    }

    try:
        with zipfile.ZipFile(apk_path) as zf:
            meta_files = [n for n in zf.namelist() if n.startswith("META-INF/")]

            for name in meta_files:
                result["signing_files"].append(name)

            # Detect signature scheme
            has_v1 = any(n.endswith((".SF", ".RSA", ".DSA", ".EC")) for n in meta_files)
            has_v2 = False  # V2/V3 are in APK Signing Block (outside ZIP)

            if has_v1:
                result["signature_scheme"] = "v1 (JAR signing)"

            # Extract certificate fingerprints
            cert_files = [n for n in meta_files if n.endswith((".RSA", ".DSA", ".EC"))]
            for cert_name in cert_files:
                cert_data = zf.read(cert_name)

                # Calculate hashes of the raw cert block
                result["cert_hashes"][cert_name] = {
                    "md5": hashlib.md5(cert_data).hexdigest(),
                    "sha1": hashlib.sha1(cert_data).hexdigest(),
                    "sha256": hashlib.sha256(cert_data).hexdigest(),
                    "size_bytes": len(cert_data),
                }

            # Analyze MANIFEST.MF
            if "META-INF/MANIFEST.MF" in meta_files:
                manifest_data = zf.read("META-INF/MANIFEST.MF").decode("utf-8", errors="replace")
                result["manifest_entries"] = manifest_data.count("Name:")
                
                # Check for digest algorithms
                if "SHA-256-Digest" in manifest_data:
                    result["digest_algorithm"] = "SHA-256"
                elif "SHA-1-Digest" in manifest_data:
                    result["digest_algorithm"] = "SHA-1"
                    result["findings"].append({
                        "severity": "MEDIUM",
                        "issue": "APK uses SHA-1 digest in MANIFEST.MF (deprecated)",
                        "remediation": "Re-sign with SHA-256 digest",
                    })
                elif "SHA1-Digest" in manifest_data:
                    result["digest_algorithm"] = "SHA-1"

            # Check for debug signing
            for cert_name in cert_files:
                cert_data = zf.read(cert_name)
                cert_text = cert_data.decode("latin-1", errors="replace")

                # Look for common debug certificate patterns
                debug_indicators = [
                    "Android Debug" in cert_text,
                    "CN=Android Debug" in cert_text,
                    "androiddebugkey" in cert_text.lower(),
                ]
                if any(debug_indicators):
                    result["is_debug_signed"] = True
                    result["findings"].append({
                        "severity": "HIGH",
                        "issue": "APK is signed with a debug certificate",
                        "remediation": "Sign with a release certificate for production",
                    })

            # Check APK alignment (basic check)
            for info in zf.infolist():
                if info.compress_type == 0:  # Stored (uncompressed)
                    # Check if the file data is 4-byte aligned
                    pass  # Complex check, skip for now

    except zipfile.BadZipFile:
        return {"success": False, "error": "File is not a valid ZIP/APK archive"}
    except Exception as e:
        return {"success": False, "error": f"Error analyzing certificate: {e}"}

    return result


def analyze_apk_from_meta_inf(apktool_dir: str | Path) -> dict:
    """Analyze certificate info from the decompiled META-INF directory.

    Args:
        apktool_dir: Path to the apktool decompiled directory.
    """
    apktool_dir = Path(apktool_dir)
    meta_dir = apktool_dir / "original" / "META-INF"

    if not meta_dir.is_dir():
        meta_dir = apktool_dir / "META-INF"

    if not meta_dir.is_dir():
        return {"success": True, "found": False, "note": "No META-INF directory found"}

    result = {
        "success": True,
        "found": True,
        "files": [],
    }

    for f in sorted(meta_dir.iterdir()):
        if f.is_file():
            result["files"].append({
                "name": f.name,
                "size_bytes": f.stat().st_size,
            })

    return result
