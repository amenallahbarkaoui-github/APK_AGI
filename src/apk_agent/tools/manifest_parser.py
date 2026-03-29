"""AndroidManifest.xml parser — extract structured data from apktool output.

Pure Python (xml.etree).  Works on the *decoded* XML produced by apktool,
NOT the raw binary XML inside the APK.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

# Android XML namespace
_NS = "{http://schemas.android.com/apk/res/android}"


def parse_manifest(manifest_path: str | Path) -> dict:
    """Parse a decoded AndroidManifest.xml and return structured data.

    Args:
        manifest_path: Path to the AndroidManifest.xml (apktool output).

    Returns:
        Dict with: success, package, version_code, version_name,
        min_sdk, target_sdk, debuggable, permissions, activities,
        services, receivers, providers, exported_components.
    """
    manifest_path = Path(manifest_path)
    if not manifest_path.is_file():
        return {"success": False, "error": f"Manifest not found: {manifest_path}"}

    try:
        tree = ET.parse(manifest_path)
    except ET.ParseError as e:
        return {"success": False, "error": f"XML parse error: {e}"}

    root = tree.getroot()

    result: dict = {"success": True}

    # --- Package info ---
    result["package"] = root.get("package", "")
    result["version_code"] = root.get(f"{_NS}versionCode", "")
    result["version_name"] = root.get(f"{_NS}versionName", "")

    # --- SDK versions ---
    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        result["min_sdk"] = uses_sdk.get(f"{_NS}minSdkVersion", "")
        result["target_sdk"] = uses_sdk.get(f"{_NS}targetSdkVersion", "")
    else:
        result["min_sdk"] = ""
        result["target_sdk"] = ""

    # --- Permissions ---
    permissions = []
    for perm in root.findall("uses-permission"):
        name = perm.get(f"{_NS}name", "")
        if name:
            permissions.append(name)
    result["permissions"] = sorted(set(permissions))

    # --- Custom permissions defined by the app ---
    custom_perms = []
    for perm in root.findall("permission"):
        name = perm.get(f"{_NS}name", "")
        protection = perm.get(f"{_NS}protectionLevel", "normal")
        if name:
            custom_perms.append({"name": name, "protection_level": protection})
    result["custom_permissions"] = custom_perms

    # --- Application element ---
    app = root.find("application")
    if app is None:
        result["debuggable"] = False
        result["activities"] = []
        result["services"] = []
        result["receivers"] = []
        result["providers"] = []
        result["exported_components"] = []
        return result

    result["debuggable"] = app.get(f"{_NS}debuggable", "false").lower() == "true"
    result["allow_backup"] = app.get(f"{_NS}allowBackup", "true").lower() == "true"
    result["use_cleartext"] = app.get(f"{_NS}usesCleartextTraffic", "false").lower() == "true"

    # --- Components ---
    exported_components: list[dict] = []

    def _parse_components(tag: str) -> list[dict]:
        components: list[dict] = []
        assert app is not None  # guarded above
        for elem in app.findall(tag):
            name = elem.get(f"{_NS}name", "")
            exported_raw = elem.get(f"{_NS}exported")
            permission = elem.get(f"{_NS}permission", "")

            # Intent filters
            intent_filters: list[dict] = []
            for if_elem in elem.findall("intent-filter"):
                actions = [
                    a.get(f"{_NS}name", "")
                    for a in if_elem.findall("action")
                ]
                categories = [
                    c.get(f"{_NS}name", "")
                    for c in if_elem.findall("category")
                ]
                data_elems = []
                for d in if_elem.findall("data"):
                    data_elems.append({
                        "scheme": d.get(f"{_NS}scheme", ""),
                        "host": d.get(f"{_NS}host", ""),
                        "path": d.get(f"{_NS}path", ""),
                    })
                intent_filters.append({
                    "actions": actions,
                    "categories": categories,
                    "data": data_elems if data_elems else None,
                })

            # Determine exported status
            has_intent_filter = len(intent_filters) > 0
            if exported_raw is not None:
                is_exported = str(exported_raw).lower() == "true"
            else:
                # Pre-Android 12: implicitly exported if has intent-filter
                is_exported = has_intent_filter

            comp = {
                "name": name,
                "exported": is_exported,
                "permission": permission,
                "intent_filters": intent_filters if intent_filters else None,
            }
            components.append(comp)

            # Track exported
            if is_exported:
                exported_components.append({
                    "type": tag,
                    "name": name,
                    "permission": permission,
                    "has_intent_filter": has_intent_filter,
                })

        return components

    result["activities"] = _parse_components("activity")
    result["services"] = _parse_components("service")
    result["receivers"] = _parse_components("receiver")
    result["providers"] = _parse_components("provider")
    result["exported_components"] = exported_components

    # --- Dangerous permissions highlight ---
    dangerous = {
        "android.permission.READ_SMS",
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.INSTALL_PACKAGES",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.SYSTEM_ALERT_WINDOW",
    }
    result["dangerous_permissions"] = sorted(
        set(permissions) & dangerous
    )

    return result
