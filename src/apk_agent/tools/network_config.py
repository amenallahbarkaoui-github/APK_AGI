"""Network Security Config analyzer — parse and analyze res/xml/network_security_config.xml.

Detects:
- Cleartext traffic permissions
- Custom trust anchors
- Certificate pinning configurations  
- Domain-specific security rules
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path


def analyze_network_config(apktool_dir: str | Path) -> dict:
    """Parse the network_security_config.xml if present.

    Args:
        apktool_dir: Path to the apktool decompiled directory.

    Returns:
        Structured analysis of network security configuration.
    """
    apktool_dir = Path(apktool_dir)

    # Search for the config file in multiple locations
    candidates = [
        apktool_dir / "res" / "xml" / "network_security_config.xml",
        apktool_dir / "res" / "raw" / "network_security_config.xml",
    ]

    config_path = None
    for c in candidates:
        if c.is_file():
            config_path = c
            break

    if not config_path:
        # Check AndroidManifest.xml for the reference
        manifest = apktool_dir / "AndroidManifest.xml"
        has_ref = False
        if manifest.is_file():
            text = manifest.read_text(encoding="utf-8", errors="replace")
            has_ref = "networkSecurityConfig" in text

        return {
            "success": True,
            "found": False,
            "manifest_references_config": has_ref,
            "note": "No network_security_config.xml found. "
                    "App uses default Android network security settings.",
        }

    try:
        tree = ET.parse(config_path)
        root = tree.getroot()
    except ET.ParseError as e:
        return {"success": False, "error": f"XML parse error: {e}"}

    result = {
        "success": True,
        "found": True,
        "path": str(config_path),
        "base_config": {},
        "domain_configs": [],
        "findings": [],
    }

    # Parse base-config
    base = root.find("base-config")
    if base is not None:
        cleartext = base.get("cleartextTrafficPermitted", "false")
        result["base_config"]["cleartext_permitted"] = cleartext == "true"
        if cleartext == "true":
            result["findings"].append({
                "severity": "MEDIUM",
                "issue": "Base config allows cleartext (HTTP) traffic globally",
                "remediation": "Set cleartextTrafficPermitted=\"false\" in base-config",
            })

        # Trust anchors
        trust_anchors = base.find("trust-anchors")
        if trust_anchors is not None:
            certs = []
            for cert in trust_anchors.findall("certificates"):
                certs.append({
                    "src": cert.get("src", ""),
                    "overridesPins": cert.get("overridePins", "false"),
                })
            result["base_config"]["trust_anchors"] = certs
            # Check for user certificates in trust
            for cert in certs:
                if cert["src"] == "user":
                    result["findings"].append({
                        "severity": "HIGH",
                        "issue": "Base config trusts user-installed certificates",
                        "remediation": "Remove user certificates from trust anchors in production",
                    })

    # Parse domain-config entries
    for domain_config in root.findall("domain-config"):
        dc = {
            "cleartext_permitted": domain_config.get("cleartextTrafficPermitted", "inherit"),
            "domains": [],
            "pins": [],
            "trust_anchors": [],
        }

        for domain in domain_config.findall("domain"):
            dc["domains"].append({
                "name": domain.text or "",
                "includeSubdomains": domain.get("includeSubdomains", "false") == "true",
            })

        # Pin set
        pin_set = domain_config.find("pin-set")
        if pin_set is not None:
            dc["pin_expiration"] = pin_set.get("expiration", "")
            for pin in pin_set.findall("pin"):
                dc["pins"].append({
                    "digest": pin.get("digest", ""),
                    "value": pin.text or "",
                })

        # Trust anchors for this domain
        ta = domain_config.find("trust-anchors")
        if ta is not None:
            for cert in ta.findall("certificates"):
                dc["trust_anchors"].append({
                    "src": cert.get("src", ""),
                    "overridesPins": cert.get("overridePins", "false"),
                })

        if dc["cleartext_permitted"] == "true":
            domains = ", ".join(d["name"] for d in dc["domains"])
            result["findings"].append({
                "severity": "MEDIUM",
                "issue": f"Cleartext traffic allowed for domains: {domains}",
                "remediation": "Use HTTPS for all domains",
            })

        if dc["pins"]:
            domains = ", ".join(d["name"] for d in dc["domains"])
            result["findings"].append({
                "severity": "INFO",
                "issue": f"Certificate pinning configured for: {domains}",
                "note": f"{len(dc['pins'])} pin(s) configured",
            })

        result["domain_configs"].append(dc)

    # Debug overrides
    debug_overrides = root.find("debug-overrides")
    if debug_overrides is not None:
        result["debug_overrides"] = True
        result["findings"].append({
            "severity": "INFO",
            "issue": "Debug overrides present in network security config",
            "note": "These only apply when android:debuggable=true",
        })

    return result
