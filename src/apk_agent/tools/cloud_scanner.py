"""Firebase & Cloud Config Scanner — detect misconfigured cloud services.

Scans for:
  - Firebase Realtime Database URLs (test .json read access)
  - Firebase Cloud Storage buckets
  - AWS access keys / secret keys
  - Google Cloud API keys
  - Google Maps API keys (often unrestricted)
  - Azure connection strings
  - Slack / Telegram / Discord webhooks/tokens
  - Generic API keys and secrets in strings

Works on the SmaliIndex (string_index) for fast lookup or can scan
raw files as fallback.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apk_agent.tools.smali_ir import SmaliIndex


# ---------------------------------------------------------------------------
# Cloud secret patterns
# ---------------------------------------------------------------------------

@dataclass
class CloudPattern:
    """A pattern for detecting cloud service credentials/config."""
    id: str
    name: str
    severity: str
    category: str
    description: str
    remediation: str
    regex: re.Pattern
    validator: str = ""   # optional secondary check


CLOUD_PATTERNS: list[CloudPattern] = [
    # Firebase
    CloudPattern(
        id="CLOUD-FB-001",
        name="Firebase Realtime Database URL",
        severity="HIGH",
        category="Firebase",
        description="Firebase RTDB URL found — check if .read/.write rules are open",
        remediation="Set proper Firebase security rules: .read: false, .write: false (or auth-required)",
        regex=re.compile(r"https://[\w-]+\.firebaseio\.com"),
    ),
    CloudPattern(
        id="CLOUD-FB-002",
        name="Firebase Storage Bucket",
        severity="MEDIUM",
        category="Firebase",
        description="Firebase Storage bucket found — check access rules",
        remediation="Set Storage rules to require authentication",
        regex=re.compile(r"[\w-]+\.appspot\.com"),
    ),
    CloudPattern(
        id="CLOUD-FB-003",
        name="Firebase API Key",
        severity="MEDIUM",
        category="Firebase",
        description="Firebase API key (expected in mobile apps, but check restrictions)",
        remediation="Restrict API key by app package name + SHA fingerprint in Google Cloud Console",
        regex=re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    ),
    CloudPattern(
        id="CLOUD-FB-004",
        name="Firebase Project ID",
        severity="LOW",
        category="Firebase",
        description="Firebase project ID — can be used to enumerate project",
        remediation="Not directly exploitable but reveals project name",
        regex=re.compile(r"\"project_id\"\s*:\s*\"([\w-]+)\""),
    ),

    # AWS
    CloudPattern(
        id="CLOUD-AWS-001",
        name="AWS Access Key ID",
        severity="CRITICAL",
        category="AWS",
        description="AWS access key found — if paired with secret key, full AWS access",
        remediation="Use AWS Cognito for mobile apps, rotate the exposed key immediately",
        regex=re.compile(r"AKIA[0-9A-Z]{16}"),
    ),
    CloudPattern(
        id="CLOUD-AWS-002",
        name="AWS Secret Access Key",
        severity="CRITICAL",
        category="AWS",
        description="AWS secret access key found in source code",
        remediation="Rotate key immediately, use Cognito Identity Pool for mobile",
        regex=re.compile(r"(?:aws_secret_access_key|secret_key|SecretKey)\s*[=:]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"),
    ),
    CloudPattern(
        id="CLOUD-AWS-003",
        name="AWS S3 Bucket URL",
        severity="MEDIUM",
        category="AWS",
        description="S3 bucket URL found — check bucket permissions",
        remediation="Ensure bucket is not publicly accessible",
        regex=re.compile(r"https?://[\w.-]+\.s3[\w.-]*\.amazonaws\.com|s3://[\w.-]+"),
    ),

    # Google Cloud
    CloudPattern(
        id="CLOUD-GCP-001",
        name="Google Cloud API Key",
        severity="MEDIUM",
        category="Google Cloud",
        description="Google Cloud API key found",
        remediation="Restrict by app package name, SHA fingerprint, and API scope",
        regex=re.compile(r"AIza[0-9A-Za-z\\-_]{35}"),
    ),
    CloudPattern(
        id="CLOUD-GCP-002",
        name="Google OAuth Client ID",
        severity="LOW",
        category="Google Cloud",
        description="Google OAuth client ID (expected in apps using Google Sign-In)",
        remediation="Ensure client ID is used only with proper redirect URI validation",
        regex=re.compile(r"\d{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com"),
    ),

    # Azure
    CloudPattern(
        id="CLOUD-AZURE-001",
        name="Azure Connection String",
        severity="CRITICAL",
        category="Azure",
        description="Azure Storage/Service Bus connection string found",
        remediation="Use managed identity or SAS tokens with minimal permissions",
        regex=re.compile(r"DefaultEndpointsProtocol=https?;AccountName=[\w]+;AccountKey=[A-Za-z0-9+/=]+"),
    ),

    # Messaging / Webhooks
    CloudPattern(
        id="CLOUD-SLACK-001",
        name="Slack Webhook URL",
        severity="HIGH",
        category="Messaging",
        description="Slack webhook URL — can send messages to the channel",
        remediation="Rotate webhook URL if exposed",
        regex=re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ),
    CloudPattern(
        id="CLOUD-TG-001",
        name="Telegram Bot Token",
        severity="HIGH",
        category="Messaging",
        description="Telegram bot token found — full bot control",
        remediation="Rotate bot token via @BotFather",
        regex=re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}"),
    ),
    CloudPattern(
        id="CLOUD-DISCORD-001",
        name="Discord Webhook/Token",
        severity="HIGH",
        category="Messaging",
        description="Discord webhook or bot token found",
        remediation="Rotate the token immediately",
        regex=re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[\w-]+"),
    ),

    # Generic secrets
    CloudPattern(
        id="CLOUD-SECRET-001",
        name="Generic API Key/Secret",
        severity="MEDIUM",
        category="Secrets",
        description="Potential API key or secret found in string constant",
        remediation="Verify if the key is sensitive and move to server-side",
        regex=re.compile(
            r"(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key)"
            r"\s*[=:]\s*['\"][A-Za-z0-9_\-./+=]{16,}['\"]",
            re.IGNORECASE,
        ),
    ),
    CloudPattern(
        id="CLOUD-SECRET-002",
        name="Private Key (PEM)",
        severity="CRITICAL",
        category="Secrets",
        description="PEM private key found in source code",
        remediation="Store private keys in Android Keystore, never in source",
        regex=re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    ),
    CloudPattern(
        id="CLOUD-JWT-001",
        name="JWT Token (Hardcoded)",
        severity="HIGH",
        category="Secrets",
        description="Hardcoded JWT token found — may contain claims/permissions",
        remediation="JWT tokens should be fetched from server, not hardcoded",
        regex=re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
    ),
]


# ---------------------------------------------------------------------------
# Scanner (operates on SmaliIndex)
# ---------------------------------------------------------------------------

def scan_cloud_config(
    index: "SmaliIndex",
    max_findings: int = 100,
) -> dict:
    """Scan all string constants in the SmaliIndex for cloud config issues.

    Much faster than file scanning — uses pre-indexed strings.
    """
    findings: list[dict] = []
    seen: set[str] = set()  # dedup by pattern_id + matched_value

    for string_val, locations in index.string_index.items():
        if len(findings) >= max_findings:
            break

        for pattern in CLOUD_PATTERNS:
            m = pattern.regex.search(string_val)
            if not m:
                continue

            matched = m.group(0)
            dedup_key = f"{pattern.id}|{matched[:60]}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            # Get first location
            file_path, line = locations[0] if locations else ("", 0)

            findings.append({
                "id": pattern.id,
                "name": pattern.name,
                "severity": pattern.severity,
                "category": pattern.category,
                "description": pattern.description,
                "remediation": pattern.remediation,
                "matched_value": _redact(matched),
                "file": file_path,
                "line": line,
                "total_locations": len(locations),
            })

    # Sort by severity
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    findings.sort(key=lambda f: -sev_order.get(f["severity"], 0))

    # Summary
    sev_counts: dict[str, int] = {}
    cat_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
        cat_counts[f["category"]] = cat_counts.get(f["category"], 0) + 1

    return {
        "success": True,
        "total_findings": len(findings),
        "severity_summary": sev_counts,
        "category_summary": cat_counts,
        "strings_searched": len(index.string_index),
        "findings": findings,
    }


def scan_cloud_config_files(
    directory: str,
    max_findings: int = 100,
) -> dict:
    """Fallback: Scan files directly for cloud config issues.

    Used when SmaliIndex is not available.
    """
    import os
    from pathlib import Path

    directory = Path(directory)
    if not directory.is_dir():
        return {"success": False, "error": f"Directory not found: {directory}"}

    findings: list[dict] = []
    seen: set[str] = set()
    files_scanned = 0

    scan_exts = {".java", ".smali", ".xml", ".json", ".properties", ".kt", ".yaml", ".yml"}

    for root, _, files in os.walk(directory):
        for fname in files:
            if not any(fname.endswith(ext) for ext in scan_exts):
                continue

            fpath = Path(root) / fname
            files_scanned += 1

            try:
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            rel = str(fpath.relative_to(directory))

            for pattern in CLOUD_PATTERNS:
                for m in pattern.regex.finditer(text):
                    matched = m.group(0)
                    dedup_key = f"{pattern.id}|{matched[:60]}"
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    line = text[:m.start()].count("\n") + 1

                    findings.append({
                        "id": pattern.id,
                        "name": pattern.name,
                        "severity": pattern.severity,
                        "category": pattern.category,
                        "description": pattern.description,
                        "remediation": pattern.remediation,
                        "matched_value": _redact(matched),
                        "file": rel,
                        "line": line,
                    })

                    if len(findings) >= max_findings:
                        break
                if len(findings) >= max_findings:
                    break
            if len(findings) >= max_findings:
                break
        if len(findings) >= max_findings:
            break

    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    findings.sort(key=lambda f: -sev_order.get(f["severity"], 0))

    return {
        "success": True,
        "total_findings": len(findings),
        "files_scanned": files_scanned,
        "findings": findings,
    }


def _redact(value: str) -> str:
    """Partially redact sensitive values for safe display."""
    if len(value) <= 8:
        return value
    # Show first 6 and last 4 chars
    return value[:6] + "***" + value[-4:]
