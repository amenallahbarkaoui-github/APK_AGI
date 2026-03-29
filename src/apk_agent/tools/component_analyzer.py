"""Component dependency and permission risk analyzer.

Provides:
- Permission risk scoring (with risk levels per permission)
- Component attack surface analysis  
- Intent filter mapping
- Exported component enumeration with risk assessment
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path


# Permission risk database
PERMISSION_RISK: dict[str, dict] = {
    # Critical - can cause direct harm
    "android.permission.SEND_SMS": {"risk": "CRITICAL", "category": "SMS", "abuse": "Financial fraud via premium SMS"},
    "android.permission.READ_SMS": {"risk": "HIGH", "category": "SMS", "abuse": "OTP/2FA interception"},
    "android.permission.RECEIVE_SMS": {"risk": "HIGH", "category": "SMS", "abuse": "Silent SMS interception"},
    "android.permission.CALL_PHONE": {"risk": "HIGH", "category": "Phone", "abuse": "Premium call fraud"},
    "android.permission.READ_CALL_LOG": {"risk": "HIGH", "category": "Phone", "abuse": "Privacy violation"},
    "android.permission.READ_CONTACTS": {"risk": "HIGH", "category": "Contacts", "abuse": "Contact harvesting"},
    "android.permission.WRITE_CONTACTS": {"risk": "MEDIUM", "category": "Contacts", "abuse": "Contact manipulation"},
    "android.permission.CAMERA": {"risk": "HIGH", "category": "Sensors", "abuse": "Surveillance"},
    "android.permission.RECORD_AUDIO": {"risk": "HIGH", "category": "Sensors", "abuse": "Audio surveillance"},
    "android.permission.ACCESS_FINE_LOCATION": {"risk": "HIGH", "category": "Location", "abuse": "Precise tracking"},
    "android.permission.ACCESS_COARSE_LOCATION": {"risk": "MEDIUM", "category": "Location", "abuse": "Approximate tracking"},
    "android.permission.ACCESS_BACKGROUND_LOCATION": {"risk": "CRITICAL", "category": "Location", "abuse": "Continuous tracking"},
    "android.permission.READ_PHONE_STATE": {"risk": "MEDIUM", "category": "Phone", "abuse": "Device fingerprinting"},
    "android.permission.READ_EXTERNAL_STORAGE": {"risk": "MEDIUM", "category": "Storage", "abuse": "Data exfiltration"},
    "android.permission.WRITE_EXTERNAL_STORAGE": {"risk": "MEDIUM", "category": "Storage", "abuse": "Data tampering"},
    "android.permission.INTERNET": {"risk": "LOW", "category": "Network", "abuse": "Data exfiltration channel"},
    "android.permission.INSTALL_PACKAGES": {"risk": "CRITICAL", "category": "System", "abuse": "Malware installation"},
    "android.permission.REQUEST_INSTALL_PACKAGES": {"risk": "HIGH", "category": "System", "abuse": "App installation prompt"},
    "android.permission.SYSTEM_ALERT_WINDOW": {"risk": "HIGH", "category": "UI", "abuse": "Overlay attacks / tapjacking"},
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {"risk": "CRITICAL", "category": "Accessibility", "abuse": "Full screen control"},
    "android.permission.BIND_DEVICE_ADMIN": {"risk": "CRITICAL", "category": "System", "abuse": "Device lockout / wipe"},
    "android.permission.READ_PHONE_NUMBERS": {"risk": "MEDIUM", "category": "Phone", "abuse": "Identify user"},
    "android.permission.MANAGE_EXTERNAL_STORAGE": {"risk": "HIGH", "category": "Storage", "abuse": "Full filesystem access"},
    "android.permission.QUERY_ALL_PACKAGES": {"risk": "MEDIUM", "category": "Apps", "abuse": "App inventory fingerprinting"},
    "android.permission.FOREGROUND_SERVICE": {"risk": "LOW", "category": "Service", "abuse": "Persistent background execution"},
    "android.permission.RECEIVE_BOOT_COMPLETED": {"risk": "LOW", "category": "Boot", "abuse": "Auto-start persistence"},
    "android.permission.WAKE_LOCK": {"risk": "LOW", "category": "Power", "abuse": "Battery drain"},
    "android.permission.VIBRATE": {"risk": "NONE", "category": "Hardware", "abuse": "Minimal"},
    "android.permission.NFC": {"risk": "MEDIUM", "category": "NFC", "abuse": "NFC data interception"},
    "android.permission.BLUETOOTH": {"risk": "LOW", "category": "Bluetooth", "abuse": "BT device discovery"},
    "android.permission.BLUETOOTH_CONNECT": {"risk": "MEDIUM", "category": "Bluetooth", "abuse": "BT device connection"},
    "android.permission.USE_BIOMETRIC": {"risk": "LOW", "category": "Auth", "abuse": "Biometric prompt abuse"},
    "android.permission.POST_NOTIFICATIONS": {"risk": "LOW", "category": "UI", "abuse": "Notification spam"},
}


def score_permissions(permissions: list[str]) -> dict:
    """Score a list of permissions by risk level.

    Args:
        permissions: List of Android permission strings.

    Returns:
        Risk analysis with scored permissions and overall risk level.
    """
    scored = []
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0, "UNKNOWN": 0}

    for perm in permissions:
        # Look up the permission
        full_perm = perm if perm.startswith("android.") else f"android.permission.{perm}"
        info = PERMISSION_RISK.get(full_perm)

        if info:
            scored.append({
                "permission": perm,
                "risk": info["risk"],
                "category": info["category"],
                "abuse_potential": info["abuse"],
            })
            risk_counts[info["risk"]] += 1
        else:
            scored.append({
                "permission": perm,
                "risk": "UNKNOWN",
                "category": "Custom/Third-party",
                "abuse_potential": "Unknown — custom or third-party permission",
            })
            risk_counts["UNKNOWN"] += 1

    # Calculate overall risk
    if risk_counts["CRITICAL"] >= 2:
        overall = "CRITICAL"
    elif risk_counts["CRITICAL"] >= 1 or risk_counts["HIGH"] >= 3:
        overall = "HIGH"
    elif risk_counts["HIGH"] >= 1 or risk_counts["MEDIUM"] >= 3:
        overall = "MEDIUM"
    else:
        overall = "LOW"

    # Sort by risk
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}
    scored.sort(key=lambda x: risk_order.get(x["risk"], 99))

    return {
        "success": True,
        "total_permissions": len(permissions),
        "overall_risk": overall,
        "risk_counts": risk_counts,
        "permissions": scored,
    }


def analyze_attack_surface(manifest_path: str | Path) -> dict:
    """Analyze the AndroidManifest.xml for attack surface.

    Lists all exported components with their intent filters,
    permissions, and risk assessment.

    Args:
        manifest_path: Path to the decoded AndroidManifest.xml.
    """
    manifest_path = Path(manifest_path)
    if not manifest_path.is_file():
        return {"success": False, "error": f"Manifest not found: {manifest_path}"}

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError as e:
        return {"success": False, "error": f"XML parse error: {e}"}

    ns = {"android": "http://schemas.android.com/apk/res/android"}

    result = {
        "success": True,
        "exported_components": [],
        "deep_links": [],
        "custom_permissions": [],
        "findings": [],
    }

    component_types = [
        ("activity", "Activity"),
        ("activity-alias", "Activity Alias"),
        ("service", "Service"),
        ("receiver", "Broadcast Receiver"),
        ("provider", "Content Provider"),
    ]

    app = root.find("application")
    if app is None:
        return {"success": True, "note": "No <application> tag found"}

    for tag, type_name in component_types:
        for comp in app.findall(tag):
            name = comp.get(f"{{{ns['android']}}}name", "")
            exported = comp.get(f"{{{ns['android']}}}exported")
            permission = comp.get(f"{{{ns['android']}}}permission", "")

            # Collect intent filters
            intent_filters = []
            has_intent_filter = False
            for ifilter in comp.findall("intent-filter"):
                has_intent_filter = True
                actions = [a.get(f"{{{ns['android']}}}name", "") for a in ifilter.findall("action")]
                categories = [c.get(f"{{{ns['android']}}}name", "") for c in ifilter.findall("category")]
                data_elements = []
                for d in ifilter.findall("data"):
                    data_elements.append({
                        "scheme": d.get(f"{{{ns['android']}}}scheme", ""),
                        "host": d.get(f"{{{ns['android']}}}host", ""),
                        "pathPrefix": d.get(f"{{{ns['android']}}}pathPrefix", ""),
                        "path": d.get(f"{{{ns['android']}}}path", ""),
                    })
                    # Detect deep links
                    scheme = d.get(f"{{{ns['android']}}}scheme", "")
                    host = d.get(f"{{{ns['android']}}}host", "")
                    if scheme and host:
                        result["deep_links"].append(f"{scheme}://{host}")

                intent_filters.append({
                    "actions": actions,
                    "categories": categories,
                    "data": data_elements,
                })

            # Determine if exported
            is_exported = False
            if exported == "true":
                is_exported = True
            elif exported is None and has_intent_filter:
                # Default: exported if has intent-filter (pre-Android 12)
                is_exported = True

            if is_exported:
                risk = "LOW"
                if not permission:
                    if type_name == "Content Provider":
                        risk = "HIGH"
                    elif type_name in ("Service", "Broadcast Receiver"):
                        risk = "MEDIUM"
                    elif type_name == "Activity":
                        risk = "LOW"

                    if any("BROWSABLE" in c for ifilter in intent_filters
                           for c in ifilter.get("categories", [])):
                        risk = "MEDIUM"

                result["exported_components"].append({
                    "name": name,
                    "type": type_name,
                    "exported": True,
                    "permission": permission or "NONE (accessible by any app)",
                    "intent_filters": intent_filters,
                    "risk": risk,
                })

                if not permission:
                    result["findings"].append({
                        "severity": risk,
                        "issue": f"Exported {type_name} '{name}' has no permission protection",
                        "remediation": f"Add android:permission attribute to protect this {type_name.lower()}",
                    })

    # Custom permissions defined by the app
    for perm in root.findall("permission"):
        pname = perm.get(f"{{{ns['android']}}}name", "")
        plevel = perm.get(f"{{{ns['android']}}}protectionLevel", "normal")
        result["custom_permissions"].append({
            "name": pname,
            "protection_level": plevel,
        })
        if plevel in ("normal", "dangerous"):
            result["findings"].append({
                "severity": "INFO",
                "issue": f"Custom permission '{pname}' has protection level '{plevel}'",
                "note": "Other apps can request this permission",
            })

    return result
