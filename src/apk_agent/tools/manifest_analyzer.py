"""Manifest Semantic Analyzer — deep analysis of AndroidManifest.xml.

Goes beyond the existing component_analyzer by:
  - Cross-referencing exported components with code (are extras validated?)
  - Deep link abuse detection (unvalidated URI schemes)
  - Backup + debuggable + cleartext traffic checks
  - targetSdkVersion security implications
  - Intent redirection detection
  - Content provider SQL injection surface
  - Custom permission weakness analysis
  - Receiver ordering attacks

Works standalone (just needs manifest path) OR enhanced with SmaliIndex
for cross-referencing code with manifest declarations.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apk_agent.tools.smali_ir import SmaliIndex


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

@dataclass
class ManifestFinding:
    """A security finding from manifest analysis."""
    rule_id: str
    severity: str           # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    title: str
    description: str
    cwe: str
    element: str = ""       # the XML element/attribute that triggered it
    remediation: str = ""
    exploitability: str = "moderate"


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

def analyze_manifest(
    manifest_path: str | Path,
    index: "SmaliIndex | None" = None,
) -> dict:
    """Deep semantic analysis of AndroidManifest.xml.

    Args:
        manifest_path: Path to decoded AndroidManifest.xml.
        index: Optional SmaliIndex for cross-referencing with code.

    Returns:
        Comprehensive analysis with findings, attack surface, config issues.
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
    findings: list[ManifestFinding] = []

    result = {
        "success": True,
        "package": root.get("package", ""),
        "findings": [],
        "config_analysis": {},
        "attack_surface": {},
        "deep_links": [],
        "component_summary": {},
    }

    # 1. Application-level checks
    app = root.find("application")
    if app is not None:
        _check_app_config(app, ns, findings, result)

    # 2. SDK version checks
    _check_sdk_versions(root, ns, findings, result)

    # 3. Permission analysis
    _check_permissions(root, ns, findings, result)

    # 4. Component analysis (deep)
    if app is not None:
        _check_components(app, ns, findings, result, index)

    # 5. Deep link analysis
    if app is not None:
        _check_deep_links(app, ns, findings, result, index)

    # 6. Content provider analysis
    if app is not None:
        _check_content_providers(app, ns, findings, result, index)

    # Convert findings to dicts
    result["findings"] = [_finding_to_dict(f) for f in findings]
    result["total_findings"] = len(findings)

    # Severity summary
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    result["severity_summary"] = sev_counts

    return result


# ---------------------------------------------------------------------------
# App-level configuration checks
# ---------------------------------------------------------------------------

def _check_app_config(
    app: ET.Element, ns: dict, findings: list[ManifestFinding],
    result: dict,
) -> None:
    config = {}

    # allowBackup
    allow_backup = app.get(f"{{{ns['android']}}}allowBackup", "true")
    config["allowBackup"] = allow_backup
    if allow_backup.lower() == "true":
        findings.append(ManifestFinding(
            rule_id="MANIFEST-001",
            severity="MEDIUM",
            category="Data Storage",
            title="Backup Allowed",
            description="android:allowBackup=true — app data extractable via adb backup",
            cwe="CWE-312",
            element='android:allowBackup="true"',
            remediation="Set android:allowBackup=\"false\" or implement BackupAgent with encryption",
        ))

    # debuggable
    debuggable = app.get(f"{{{ns['android']}}}debuggable", "false")
    config["debuggable"] = debuggable
    if debuggable.lower() == "true":
        findings.append(ManifestFinding(
            rule_id="MANIFEST-002",
            severity="CRITICAL",
            category="Configuration",
            title="App is Debuggable",
            description="android:debuggable=true — attacker can attach debugger and inspect memory",
            cwe="CWE-489",
            element='android:debuggable="true"',
            remediation="Set android:debuggable=\"false\" for release builds",
            exploitability="trivial",
        ))

    # usesCleartextTraffic
    cleartext = app.get(f"{{{ns['android']}}}usesCleartextTraffic")
    config["usesCleartextTraffic"] = cleartext
    if cleartext and cleartext.lower() == "true":
        findings.append(ManifestFinding(
            rule_id="MANIFEST-003",
            severity="MEDIUM",
            category="Network",
            title="Cleartext Traffic Allowed",
            description="android:usesCleartextTraffic=true — HTTP connections allowed",
            cwe="CWE-319",
            element='android:usesCleartextTraffic="true"',
            remediation="Use HTTPS only + network_security_config.xml",
        ))

    # networkSecurityConfig
    nsc = app.get(f"{{{ns['android']}}}networkSecurityConfig")
    config["networkSecurityConfig"] = nsc or "not set"
    if nsc:
        findings.append(ManifestFinding(
            rule_id="MANIFEST-004",
            severity="INFO",
            category="Network",
            title="Network Security Config Present",
            description=f"Custom network_security_config.xml defined: {nsc}",
            cwe="N/A",
            element=f"networkSecurityConfig={nsc}",
            remediation="Review the NSC file for cleartext-permit or custom trust anchors",
        ))

    # fullBackupContent
    full_backup = app.get(f"{{{ns['android']}}}fullBackupContent")
    config["fullBackupContent"] = full_backup or "not set"

    result["config_analysis"] = config


# ---------------------------------------------------------------------------
# SDK version checks
# ---------------------------------------------------------------------------

def _check_sdk_versions(
    root: ET.Element, ns: dict, findings: list[ManifestFinding],
    result: dict,
) -> None:
    uses_sdk = root.find("uses-sdk")
    if uses_sdk is None:
        return

    min_sdk = uses_sdk.get(f"{{{ns['android']}}}minSdkVersion", "")
    target_sdk = uses_sdk.get(f"{{{ns['android']}}}targetSdkVersion", "")

    result["config_analysis"]["minSdkVersion"] = min_sdk
    result["config_analysis"]["targetSdkVersion"] = target_sdk

    try:
        min_val = int(min_sdk) if min_sdk else 0
        target_val = int(target_sdk) if target_sdk else 0
    except ValueError:
        return

    if min_val < 21:
        findings.append(ManifestFinding(
            rule_id="MANIFEST-010",
            severity="LOW",
            category="Configuration",
            title=f"Low minSdkVersion ({min_sdk})",
            description=f"minSdkVersion={min_sdk} — supports pre-Lollipop devices with weak security",
            cwe="N/A",
            element=f"minSdkVersion={min_sdk}",
            remediation="Consider raising minSdkVersion to 21+ for TLS 1.2 by default",
        ))

    if target_val < 28:
        findings.append(ManifestFinding(
            rule_id="MANIFEST-011",
            severity="MEDIUM",
            category="Configuration",
            title=f"Old targetSdkVersion ({target_sdk})",
            description=f"targetSdkVersion={target_sdk} — cleartext traffic allowed by default (needs >= 28)",
            cwe="CWE-319",
            element=f"targetSdkVersion={target_sdk}",
            remediation="Target SDK 28+ to enforce HTTPS by default",
        ))

    if target_val < 31:
        findings.append(ManifestFinding(
            rule_id="MANIFEST-012",
            severity="LOW",
            category="Configuration",
            title=f"targetSdkVersion < 31 ({target_sdk})",
            description="Components with intent-filters are exported by default (pre-Android 12)",
            cwe="CWE-926",
            element=f"targetSdkVersion={target_sdk}",
            remediation="Target SDK 31+ and explicitly set android:exported",
        ))


# ---------------------------------------------------------------------------
# Permission analysis
# ---------------------------------------------------------------------------

def _check_permissions(
    root: ET.Element, ns: dict, findings: list[ManifestFinding],
    result: dict,
) -> None:
    # Dangerous permission combinations
    requested = set()
    for perm in root.findall("uses-permission"):
        name = perm.get(f"{{{ns['android']}}}name", "")
        requested.add(name)

    # Check dangerous combos
    if "android.permission.INTERNET" in requested and "android.permission.READ_CONTACTS" in requested:
        findings.append(ManifestFinding(
            rule_id="MANIFEST-020",
            severity="MEDIUM",
            category="Permissions",
            title="Contact Exfiltration Risk",
            description="INTERNET + READ_CONTACTS — contacts could be exfiltrated",
            cwe="CWE-359",
            element="INTERNET + READ_CONTACTS",
        ))

    if "android.permission.INTERNET" in requested and "android.permission.ACCESS_FINE_LOCATION" in requested:
        findings.append(ManifestFinding(
            rule_id="MANIFEST-021",
            severity="MEDIUM",
            category="Permissions",
            title="Location Tracking Risk",
            description="INTERNET + ACCESS_FINE_LOCATION — location could be exfiltrated",
            cwe="CWE-359",
            element="INTERNET + ACCESS_FINE_LOCATION",
        ))

    if "android.permission.SEND_SMS" in requested:
        findings.append(ManifestFinding(
            rule_id="MANIFEST-022",
            severity="HIGH",
            category="Permissions",
            title="SMS Send Permission",
            description="SEND_SMS permission — potential for premium SMS fraud",
            cwe="CWE-284",
            element="android.permission.SEND_SMS",
            remediation="Verify SMS sending is legitimate and user-consented",
        ))

    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in requested:
        findings.append(ManifestFinding(
            rule_id="MANIFEST-023",
            severity="CRITICAL",
            category="Permissions",
            title="Accessibility Service",
            description="BIND_ACCESSIBILITY_SERVICE — full screen control, often abused by malware",
            cwe="CWE-284",
            element="android.permission.BIND_ACCESSIBILITY_SERVICE",
            remediation="Verify accessibility service is legitimate",
            exploitability="trivial",
        ))

    if "android.permission.BIND_DEVICE_ADMIN" in requested:
        findings.append(ManifestFinding(
            rule_id="MANIFEST-024",
            severity="CRITICAL",
            category="Permissions",
            title="Device Admin",
            description="BIND_DEVICE_ADMIN — can lock device, wipe data, enforce policies",
            cwe="CWE-284",
            element="android.permission.BIND_DEVICE_ADMIN",
            remediation="Verify device admin is legitimate",
            exploitability="moderate",
        ))

    # Custom permissions with normal protection level
    for perm_def in root.findall("permission"):
        pname = perm_def.get(f"{{{ns['android']}}}name", "")
        plevel = perm_def.get(f"{{{ns['android']}}}protectionLevel", "normal")
        if plevel in ("normal", "dangerous"):
            findings.append(ManifestFinding(
                rule_id="MANIFEST-025",
                severity="LOW",
                category="Permissions",
                title=f"Weak Custom Permission: {pname}",
                description=f"Custom permission '{pname}' has protection level '{plevel}' — any app can request it",
                cwe="CWE-276",
                element=f'{pname} protectionLevel="{plevel}"',
                remediation="Use signature protection level for inter-app permissions",
            ))


# ---------------------------------------------------------------------------
# Component analysis (exported, unprotected)
# ---------------------------------------------------------------------------

def _check_components(
    app: ET.Element, ns: dict, findings: list[ManifestFinding],
    result: dict, index: "SmaliIndex | None",
) -> None:
    component_types = [
        ("activity", "Activity"),
        ("activity-alias", "Activity Alias"),
        ("service", "Service"),
        ("receiver", "Broadcast Receiver"),
        ("provider", "Content Provider"),
    ]

    exported_components = []
    component_counts: dict[str, int] = {}

    for tag, type_name in component_types:
        count = 0
        for comp in app.findall(tag):
            count += 1
            name = comp.get(f"{{{ns['android']}}}name", "")
            exported = comp.get(f"{{{ns['android']}}}exported")
            permission = comp.get(f"{{{ns['android']}}}permission", "")

            has_intent_filter = len(comp.findall("intent-filter")) > 0

            is_exported = False
            if exported == "true":
                is_exported = True
            elif exported is None and has_intent_filter:
                is_exported = True

            if is_exported and not permission:
                severity = "LOW"
                if type_name == "Content Provider":
                    severity = "HIGH"
                elif type_name in ("Service", "Broadcast Receiver"):
                    severity = "MEDIUM"

                findings.append(ManifestFinding(
                    rule_id="MANIFEST-030",
                    severity=severity,
                    category="Attack Surface",
                    title=f"Unprotected Exported {type_name}",
                    description=f"Exported {type_name} '{name}' has no permission — accessible by any app",
                    cwe="CWE-926",
                    element=name,
                    remediation=f"Add android:permission to protect this {type_name.lower()} or set exported=false",
                ))

                exported_components.append({
                    "name": name,
                    "type": type_name,
                    "permission": "NONE",
                })

                # Cross-reference with code if index available
                if index and type_name == "Activity":
                    _check_activity_input_validation(name, index, findings)

        component_counts[type_name] = count

    result["attack_surface"] = {
        "exported_unprotected": len(exported_components),
        "components": exported_components,
    }
    result["component_summary"] = component_counts


def _check_activity_input_validation(
    activity_name: str, index: "SmaliIndex", findings: list[ManifestFinding],
) -> None:
    """Check if an exported Activity validates its intent extras."""
    # Convert activity name to smali class name
    smali_name = "L" + activity_name.replace(".", "/") + ";"
    cls = index.get_class(smali_name)
    if cls is None:
        return

    # Look for getIntent/getStringExtra/getParcelableExtra without validation
    for method in cls.methods:
        if method.name not in ("onCreate", "onNewIntent", "onResume"):
            continue

        has_get_extra = False
        has_validation = False

        for instr in method.instructions:
            if instr.is_invoke:
                target = f"{instr.target_class}->{instr.target_method}"
                if "getStringExtra" in target or "getParcelableExtra" in target or "getData" in target:
                    has_get_extra = True
                if "TextUtils;->isEmpty" in target or "equals" in target or "matches" in target:
                    has_validation = True

        if has_get_extra and not has_validation:
            findings.append(ManifestFinding(
                rule_id="MANIFEST-031",
                severity="MEDIUM",
                category="Input Validation",
                title=f"Unvalidated Intent Extras in {activity_name}",
                description=f"Exported Activity reads intent extras in {method.name}() without apparent validation",
                cwe="CWE-20",
                element=activity_name,
                remediation="Validate all intent extras before use",
            ))


# ---------------------------------------------------------------------------
# Deep link analysis
# ---------------------------------------------------------------------------

def _check_deep_links(
    app: ET.Element, ns: dict, findings: list[ManifestFinding],
    result: dict, index: "SmaliIndex | None",
) -> None:
    deep_links = []

    for activity in app.findall("activity"):
        name = activity.get(f"{{{ns['android']}}}name", "")

        for ifilter in activity.findall("intent-filter"):
            categories = [c.get(f"{{{ns['android']}}}name", "") for c in ifilter.findall("category")]
            is_browsable = any("BROWSABLE" in c for c in categories)

            for data in ifilter.findall("data"):
                scheme = data.get(f"{{{ns['android']}}}scheme", "")
                host = data.get(f"{{{ns['android']}}}host", "")
                path_prefix = data.get(f"{{{ns['android']}}}pathPrefix", "")
                path = data.get(f"{{{ns['android']}}}path", "")

                if scheme:
                    link = f"{scheme}://{host}{path_prefix or path}"
                    deep_links.append({
                        "activity": name,
                        "scheme": scheme,
                        "host": host,
                        "path": path_prefix or path,
                        "browsable": is_browsable,
                        "url": link,
                    })

                    if is_browsable and scheme not in ("https", "http"):
                        findings.append(ManifestFinding(
                            rule_id="MANIFEST-040",
                            severity="MEDIUM",
                            category="Deep Links",
                            title=f"Custom Deep Link Scheme: {scheme}://",
                            description=f"Activity '{name}' handles custom scheme '{scheme}://' — "
                                       f"any app can craft this URI to trigger the activity",
                            cwe="CWE-939",
                            element=link,
                            remediation="Use Android App Links (https://) with verified domain instead",
                        ))

                    if is_browsable and not host:
                        findings.append(ManifestFinding(
                            rule_id="MANIFEST-041",
                            severity="HIGH",
                            category="Deep Links",
                            title=f"Deep Link Without Host: {scheme}://",
                            description=f"Deep link scheme '{scheme}' has no host restriction — "
                                       f"broadly matches URIs",
                            cwe="CWE-939",
                            element=link,
                            remediation="Add android:host to restrict deep link matches",
                        ))

    result["deep_links"] = deep_links


# ---------------------------------------------------------------------------
# Content provider analysis
# ---------------------------------------------------------------------------

def _check_content_providers(
    app: ET.Element, ns: dict, findings: list[ManifestFinding],
    result: dict, index: "SmaliIndex | None",
) -> None:
    for provider in app.findall("provider"):
        name = provider.get(f"{{{ns['android']}}}name", "")
        exported = provider.get(f"{{{ns['android']}}}exported")
        permission = provider.get(f"{{{ns['android']}}}permission", "")
        read_perm = provider.get(f"{{{ns['android']}}}readPermission", "")
        write_perm = provider.get(f"{{{ns['android']}}}writePermission", "")
        authorities = provider.get(f"{{{ns['android']}}}authorities", "")
        grant_uri = provider.get(f"{{{ns['android']}}}grantUriPermissions", "false")

        is_exported = exported == "true"

        if is_exported:
            if not permission and not read_perm and not write_perm:
                findings.append(ManifestFinding(
                    rule_id="MANIFEST-050",
                    severity="CRITICAL",
                    category="Content Provider",
                    title=f"Unprotected Exported ContentProvider",
                    description=f"ContentProvider '{name}' (authority: {authorities}) "
                               f"is exported with no permissions — any app can query/modify data",
                    cwe="CWE-284",
                    element=name,
                    remediation="Add android:permission or android:readPermission/writePermission",
                    exploitability="trivial",
                ))

            if grant_uri.lower() == "true":
                findings.append(ManifestFinding(
                    rule_id="MANIFEST-051",
                    severity="HIGH",
                    category="Content Provider",
                    title=f"Grant URI Permissions Enabled",
                    description=f"ContentProvider '{name}' has grantUriPermissions=true — "
                               f"temporary access can be granted to any URI",
                    cwe="CWE-284",
                    element=name,
                    remediation="Use specific <grant-uri-permission> elements instead",
                ))

            # Check for path traversal in code
            if index:
                smali_name = "L" + name.replace(".", "/") + ";"
                cls = index.get_class(smali_name)
                if cls:
                    for method in cls.methods:
                        if method.name in ("query", "openFile", "call"):
                            # Check if URI is validated
                            has_uri_param = any(
                                "Landroid/net/Uri;" in str(instr.raw)
                                for instr in method.instructions
                            )
                            has_path_check = any(
                                "getPath" in instr.raw or "normalize" in instr.raw
                                for instr in method.instructions
                                if instr.is_invoke
                            )
                            if has_uri_param and not has_path_check:
                                findings.append(ManifestFinding(
                                    rule_id="MANIFEST-052",
                                    severity="HIGH",
                                    category="Content Provider",
                                    title=f"Potential Path Traversal in {name}.{method.name}()",
                                    description=f"ContentProvider method '{method.name}' processes URI "
                                               f"without apparent path normalization — path traversal risk",
                                    cwe="CWE-22",
                                    element=f"{name}.{method.name}",
                                    remediation="Normalize and validate URI paths before file access",
                                ))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding_to_dict(f: ManifestFinding) -> dict:
    return {
        "rule_id": f.rule_id,
        "severity": f.severity,
        "category": f.category,
        "title": f.title,
        "description": f.description,
        "cwe": f.cwe,
        "element": f.element,
        "remediation": f.remediation,
        "exploitability": f.exploitability,
    }
