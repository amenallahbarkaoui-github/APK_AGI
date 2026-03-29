"""Vulnerability pattern scanner — detect 25+ security issues in decompiled APK code.

Pure Python.  Scans both Java source (JADX) and smali (apktool) for known
vulnerability patterns and security anti-patterns.  Each pattern has a
severity, category, CWE reference, and remediation hint.
"""

from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

# Shared thread pool for parallel file scanning
_VULN_POOL = ThreadPoolExecutor(max_workers=8)


@dataclass
class VulnPattern:
    """A single vulnerability detection pattern."""
    id: str
    name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    cwe: str  # CWE ID
    description: str
    remediation: str
    regex: re.Pattern
    file_types: list[str] = field(default_factory=lambda: [".java", ".smali"])


# ---------------------------------------------------------------------------
# Vulnerability pattern database
# ---------------------------------------------------------------------------

VULN_PATTERNS: list[VulnPattern] = [
    # === SSL/TLS ===
    VulnPattern(
        id="SSL-001",
        name="Empty TrustManager (SSL Bypass)",
        severity="CRITICAL",
        category="SSL/TLS",
        cwe="CWE-295",
        description="X509TrustManager with empty checkServerTrusted — accepts any certificate",
        remediation="Implement proper certificate validation or use network_security_config.xml",
        regex=re.compile(r"checkServerTrusted.*\{[\s\n]*\}", re.DOTALL),
    ),
    VulnPattern(
        id="SSL-002",
        name="Disabled HostnameVerifier",
        severity="CRITICAL",
        category="SSL/TLS",
        cwe="CWE-295",
        description="HostnameVerifier.verify() returns true for all hostnames",
        remediation="Use default HostnameVerifier or implement proper hostname verification",
        regex=re.compile(r"(ALLOW_ALL_HOSTNAME_VERIFIER|verify.*return\s+true)", re.IGNORECASE),
    ),
    VulnPattern(
        id="SSL-003",
        name="Certificate Pinning Detected",
        severity="INFO",
        category="SSL/TLS",
        cwe="N/A",
        description="App implements certificate pinning — may need bypass for testing",
        remediation="Consider if pinning needs to be disabled for analysis",
        regex=re.compile(r"CertificatePinner|\.pin\(|sha256/[A-Za-z0-9+/=]+"),
    ),
    VulnPattern(
        id="SSL-004",
        name="Cleartext HTTP Traffic",
        severity="MEDIUM",
        category="SSL/TLS",
        cwe="CWE-319",
        description="App uses unencrypted HTTP connections",
        remediation="Use HTTPS for all network communication",
        regex=re.compile(r'"http://[^"]+(?!localhost|127\.0\.0\.1|10\.0\.)', re.IGNORECASE),
    ),
    # === Root / Emulator Detection ===
    VulnPattern(
        id="ROOT-001",
        name="Root Detection",
        severity="INFO",
        category="Root Detection",
        cwe="N/A",
        description="App checks for rooted device — may block analysis tools",
        remediation="Patch root detection methods if needed for testing",
        regex=re.compile(r"isRooted|isDeviceRooted|RootBeer|rootCheck|superuser|com\.topjohnwu\.magisk", re.IGNORECASE),
    ),
    VulnPattern(
        id="ROOT-002",
        name="SU Binary Check",
        severity="INFO",
        category="Root Detection",
        cwe="N/A",
        description="App checks for su binary presence",
        remediation="Patch su binary check if needed for testing",
        regex=re.compile(r'"/system/xbin/su"|"/system/bin/su"|"/sbin/su"|"which su"'),
    ),
    VulnPattern(
        id="ROOT-003",
        name="Emulator Detection",
        severity="INFO",
        category="Root Detection",
        cwe="N/A",
        description="App detects emulator environment",
        remediation="Patch emulator detection if running in emulator",
        regex=re.compile(r"isEmulator|generic.*Build|sdk_phone|goldfish|ranchu|google_sdk", re.IGNORECASE),
    ),
    VulnPattern(
        id="ROOT-004",
        name="SafetyNet / Play Integrity",
        severity="INFO",
        category="Root Detection",
        cwe="N/A",
        description="App uses Google SafetyNet or Play Integrity API",
        remediation="May need to spoof attestation for testing",
        regex=re.compile(r"SafetyNet|PlayIntegrity|safetynet|integrity.*token", re.IGNORECASE),
    ),
    # === Crypto ===
    VulnPattern(
        id="CRYPTO-001",
        name="ECB Mode Encryption",
        severity="HIGH",
        category="Cryptography",
        cwe="CWE-327",
        description="AES/DES in ECB mode — identical plaintext blocks produce identical ciphertext",
        remediation="Use AES/GCM or AES/CBC with random IV",
        regex=re.compile(r'"AES/ECB|"DES/ECB', re.IGNORECASE),
    ),
    VulnPattern(
        id="CRYPTO-002",
        name="Hardcoded Encryption Key",
        severity="CRITICAL",
        category="Cryptography",
        cwe="CWE-321",
        description="SecretKeySpec initialized with a hardcoded byte array or string",
        remediation="Derive keys using PBKDF2 or Android Keystore",
        regex=re.compile(r"SecretKeySpec\(.*\.(getBytes|toByteArray)|new\s+SecretKeySpec\("),
    ),
    VulnPattern(
        id="CRYPTO-003",
        name="Weak Hash Algorithm (MD5/SHA1)",
        severity="MEDIUM",
        category="Cryptography",
        cwe="CWE-328",
        description="Using MD5 or SHA-1 for hashing — both are collision-vulnerable",
        remediation="Use SHA-256 or SHA-3",
        regex=re.compile(r'MessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"\s*\)', re.IGNORECASE),
    ),
    VulnPattern(
        id="CRYPTO-004",
        name="Static Initialization Vector",
        severity="HIGH",
        category="Cryptography",
        cwe="CWE-329",
        description="IvParameterSpec with hardcoded or static IV value",
        remediation="Generate a random IV for each encryption operation",
        regex=re.compile(r"new\s+IvParameterSpec\s*\("),
    ),
    VulnPattern(
        id="CRYPTO-005",
        name="Insecure Random Number Generator",
        severity="MEDIUM",
        category="Cryptography",
        cwe="CWE-330",
        description="Using java.util.Random instead of SecureRandom for security-sensitive operations",
        remediation="Use java.security.SecureRandom",
        regex=re.compile(r"new\s+Random\s*\(|java\.util\.Random"),
    ),
    # === Data Storage ===
    VulnPattern(
        id="STORAGE-001",
        name="World-Readable File",
        severity="HIGH",
        category="Data Storage",
        cwe="CWE-276",
        description="File created with MODE_WORLD_READABLE — accessible by any app",
        remediation="Use MODE_PRIVATE or ContentProvider for inter-app data sharing",
        regex=re.compile(r"MODE_WORLD_READABLE|0x0001.*openFileOutput"),
    ),
    VulnPattern(
        id="STORAGE-002",
        name="External Storage Usage",
        severity="MEDIUM",
        category="Data Storage",
        cwe="CWE-921",
        description="Data stored on external storage — accessible by other apps",
        remediation="Use internal storage or encrypted external storage",
        regex=re.compile(r"getExternalStorage|getExternalFilesDir|Environment\.getExternal"),
    ),
    VulnPattern(
        id="STORAGE-003",
        name="Unencrypted SQLite Database",
        severity="MEDIUM",
        category="Data Storage",
        cwe="CWE-312",
        description="SQLite database without encryption (SQLCipher)",
        remediation="Use SQLCipher or EncryptedSharedPreferences",
        regex=re.compile(r"openOrCreateDatabase|SQLiteOpenHelper|getWritableDatabase"),
    ),
    VulnPattern(
        id="STORAGE-004",
        name="Hardcoded Credentials",
        severity="CRITICAL",
        category="Data Storage",
        cwe="CWE-798",
        description="Hardcoded passwords, API keys, or tokens in source code",
        remediation="Use Android Keystore, encrypted SharedPreferences, or server-side key management",
        regex=re.compile(r'(?:password|passwd|pwd|api_key|apikey|secret|token)\s*[:=]\s*"[^"]{4,}"', re.IGNORECASE),
    ),
    # === WebView ===
    VulnPattern(
        id="WEBVIEW-001",
        name="JavaScript Enabled in WebView",
        severity="MEDIUM",
        category="WebView",
        cwe="CWE-749",
        description="WebView with JavaScript enabled — potential for XSS",
        remediation="Disable JS if not needed, use SafeBrowsing, validate loaded URLs",
        regex=re.compile(r"setJavaScriptEnabled\s*\(\s*true\s*\)"),
    ),
    VulnPattern(
        id="WEBVIEW-002",
        name="JavaScript Interface (addJavascriptInterface)",
        severity="HIGH",
        category="WebView",
        cwe="CWE-749",
        description="Exposing Java methods to JavaScript — RCE risk on API < 17",
        remediation="Require minSDK >= 17 and use @JavascriptInterface annotation",
        regex=re.compile(r"addJavascriptInterface"),
    ),
    VulnPattern(
        id="WEBVIEW-003",
        name="File Access in WebView",
        severity="HIGH",
        category="WebView",
        cwe="CWE-200",
        description="WebView can access local files — potential data exfiltration",
        remediation="Disable file access: setAllowFileAccess(false)",
        regex=re.compile(r"setAllowFileAccess\s*\(\s*true\s*\)|setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)"),
    ),
    # === Logging ===
    VulnPattern(
        id="LOG-001",
        name="Verbose Logging",
        severity="LOW",
        category="Logging",
        cwe="CWE-532",
        description="Debug/verbose logging that may leak sensitive data in logcat",
        remediation="Remove debug logs from release builds using ProGuard or build variants",
        regex=re.compile(r"Log\.(d|v|i)\s*\(|System\.out\.print|e\.printStackTrace\(\)"),
    ),
    # === IPC ===
    VulnPattern(
        id="IPC-001",
        name="Implicit Broadcast",
        severity="MEDIUM",
        category="IPC",
        cwe="CWE-927",
        description="Sending implicit broadcast — any app can receive it",
        remediation="Use LocalBroadcastManager or explicit intents",
        regex=re.compile(r"sendBroadcast\s*\(\s*new\s+Intent\s*\("),
    ),
    VulnPattern(
        id="IPC-002",
        name="Pending Intent with FLAG_MUTABLE",
        severity="HIGH",
        category="IPC",
        cwe="CWE-927",
        description="Mutable PendingIntent can be intercepted and modified by malicious apps",
        remediation="Use FLAG_IMMUTABLE for PendingIntents",
        regex=re.compile(r"PendingIntent\.(getActivity|getService|getBroadcast).*FLAG_MUTABLE"),
    ),
    # === SQL Injection ===
    VulnPattern(
        id="SQL-001",
        name="Raw SQL Query",
        severity="HIGH",
        category="SQL Injection",
        cwe="CWE-89",
        description="Using rawQuery or execSQL with string concatenation — SQL injection risk",
        remediation="Use parameterized queries with selection args",
        regex=re.compile(r'(rawQuery|execSQL)\s*\(\s*"[^"]*"\s*\+'),
    ),
    # === Dynamic Code Loading ===
    VulnPattern(
        id="DCL-001",
        name="Dynamic DEX Loading",
        severity="HIGH",
        category="Dynamic Code Loading",
        cwe="CWE-94",
        description="Loading DEX files at runtime — could load attacker-controlled code",
        remediation="Validate integrity of loaded code, load only from trusted sources",
        regex=re.compile(r"DexClassLoader|PathClassLoader|InMemoryDexClassLoader"),
    ),
]


@dataclass
class VulnFinding:
    """A vulnerability finding."""
    vuln_id: str
    name: str
    severity: str
    category: str
    cwe: str
    description: str
    remediation: str
    file: str
    line: int
    evidence: str


def scan_directory(
    directory: str | Path,
    file_types: list[str] | None = None,
    severity_filter: str | None = None,
    max_findings: int = 200,
) -> dict:
    """Scan a directory for vulnerability patterns using parallel I/O.

    Args:
        directory: Path to scan (jadx_src or apktool output).
        file_types: Extensions to scan (default: .java, .smali, .xml).
        severity_filter: Only return findings >= this severity.
        max_findings: Maximum number of findings to return.

    Returns:
        Dict with: success, findings, summary (by severity and category).
    """
    from apk_agent.progress import report_progress

    directory = Path(directory)
    if not directory.is_dir():
        return {"success": False, "error": f"Directory not found: {directory}"}

    if file_types is None:
        file_types = [".java", ".smali", ".xml", ".kt"]

    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    min_severity = severity_order.get(severity_filter or "", 0)

    # Collect all files
    file_list: list[Path] = []
    for root, _, files in os.walk(directory):
        for fname in files:
            if any(fname.endswith(ext) for ext in file_types):
                file_list.append(Path(root) / fname)

    total_files = len(file_list)
    if total_files == 0:
        return {"success": True, "files_scanned": 0, "total_findings": 0,
                "severity_summary": {}, "category_summary": {}, "findings": []}

    # Pre-group patterns by file extension for faster matching
    patterns_by_ext: dict[str, list[VulnPattern]] = {}
    for vp in VULN_PATTERNS:
        for ext in vp.file_types:
            patterns_by_ext.setdefault(ext, []).append(vp)

    def _scan_one(fpath: Path) -> list[dict]:
        """Scan a single file against all applicable patterns."""
        hits = []
        fname = fpath.name
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return hits

        # Get applicable patterns for this file type
        applicable: list[VulnPattern] = []
        for ext, pats in patterns_by_ext.items():
            if fname.endswith(ext):
                applicable.extend(pats)
        if not applicable:
            return hits

        # Deduplicate (a pattern may appear in multiple ext groups)
        seen_ids: set[str] = set()
        unique_pats = []
        for vp in applicable:
            if vp.id not in seen_ids:
                seen_ids.add(vp.id)
                unique_pats.append(vp)

        rel_path = str(fpath.relative_to(directory))
        for vp in unique_pats:
            for match in vp.regex.finditer(text):
                line_num = text[:match.start()].count("\n") + 1
                hits.append({
                    "id": vp.id,
                    "name": vp.name,
                    "severity": vp.severity,
                    "category": vp.category,
                    "cwe": vp.cwe,
                    "description": vp.description,
                    "remediation": vp.remediation,
                    "file": rel_path,
                    "line": line_num,
                    "evidence": match.group(0)[:200],
                })
        return hits

    findings: list[dict] = []
    severity_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    files_scanned = 0

    futures = {_VULN_POOL.submit(_scan_one, fp): fp for fp in file_list}
    for future in as_completed(futures):
        file_hits = future.result()
        files_scanned += 1

        for hit in file_hits:
            sev_val = severity_order.get(hit["severity"], 0)
            severity_counts[hit["severity"]] = severity_counts.get(hit["severity"], 0) + 1
            category_counts[hit["category"]] = category_counts.get(hit["category"], 0) + 1
            if sev_val >= min_severity and len(findings) < max_findings:
                findings.append(hit)

        if files_scanned % 50 == 0 or files_scanned == total_files:
            pct = files_scanned / total_files * 100
            report_progress(pct, f"{files_scanned}/{total_files} files | {len(findings)} findings")

    # Sort by severity (CRITICAL first)
    findings.sort(key=lambda f: -severity_order.get(f["severity"], 0))

    return {
        "success": True,
        "files_scanned": files_scanned,
        "total_findings": sum(severity_counts.values()),
        "severity_summary": dict(sorted(
            severity_counts.items(),
            key=lambda x: -severity_order.get(x[0], 0),
        )),
        "category_summary": dict(sorted(
            category_counts.items(),
            key=lambda x: -x[1],
        )),
        "findings": findings,
    }


def scan_for_pattern(
    directory: str | Path,
    pattern_ids: list[str],
    file_types: list[str] | None = None,
    max_findings: int = 100,
) -> dict:
    """Scan for specific vulnerability patterns by ID.

    Args:
        pattern_ids: List of pattern IDs (e.g., ["SSL-001", "CRYPTO-001"]).
    """
    directory = Path(directory)
    if not directory.is_dir():
        return {"success": False, "error": f"Directory not found: {directory}"}

    if file_types is None:
        file_types = [".java", ".smali", ".xml", ".kt"]

    selected = [vp for vp in VULN_PATTERNS if vp.id in pattern_ids]
    if not selected:
        available = [vp.id for vp in VULN_PATTERNS]
        return {"success": False, "error": f"No matching patterns. Available: {available}"}

    findings: list[dict] = []
    files_scanned = 0

    for root, _, files in os.walk(directory):
        for fname in files:
            if not any(fname.endswith(ext) for ext in file_types):
                continue

            fpath = Path(root) / fname
            files_scanned += 1
            try:
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            for vp in selected:
                for match in vp.regex.finditer(text):
                    line_num = text[:match.start()].count("\n") + 1
                    rel_path = str(fpath.relative_to(directory))
                    findings.append({
                        "id": vp.id,
                        "name": vp.name,
                        "severity": vp.severity,
                        "file": rel_path,
                        "line": line_num,
                        "evidence": match.group(0)[:200],
                    })
                    if len(findings) >= max_findings:
                        return {
                            "success": True,
                            "files_scanned": files_scanned,
                            "findings": findings,
                            "truncated": True,
                        }

    return {
        "success": True,
        "files_scanned": files_scanned,
        "findings": findings,
        "truncated": False,
    }


def list_patterns() -> list[dict]:
    """List all available vulnerability patterns."""
    return [
        {
            "id": vp.id,
            "name": vp.name,
            "severity": vp.severity,
            "category": vp.category,
            "cwe": vp.cwe,
        }
        for vp in VULN_PATTERNS
    ]
