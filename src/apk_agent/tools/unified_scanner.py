"""Unified Scanner Engine — single-pass, IR-based analysis over the SmaliIndex.

Replaces the fragmented detect_protections / scan_vulnerabilities /
crypto_scanner / code_graph approach with ONE consolidated engine that:

  1. Takes a SmaliIndex (already parsed) — no re-reading files
  2. Runs all detection categories in a single pass over the methods
  3. Deduplicates findings automatically
  4. Produces structured Finding objects with evidence chains
  5. Assigns severity, exploitability, CWE, and auto-patch hints

Categories scanned:
  - Protections: root, emulator, anti-debug, anti-tamper, packer
  - Crypto weaknesses: ECB, hardcoded key, weak hash, static IV
  - SSL/TLS: trust manager bypass, hostname bypass, pinning
  - Data storage: world-readable, external storage, cleartext DB  
  - WebView: JS enabled, JS bridge, file access
  - IPC: implicit broadcast, pending intent mutable
  - Logging: verbose logs leaking data
  - Dynamic loading: dex loader, reflection, Runtime.exec
  - Native: JNI, System.loadLibrary
  - Obfuscation: short names, string encryption, control flow flattening
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apk_agent.tools.smali_ir import SmaliIndex, SmaliMethod, SmaliInstruction


# ---------------------------------------------------------------------------
# Enums for structured classification
# ---------------------------------------------------------------------------

class ValidationState(str, Enum):
    """Lifecycle state of a finding's validation."""
    PENDING = "pending"                  # default — static-only, not yet verified
    VALIDATED = "validated"              # confirmed by runtime / dynamic check
    FAILED = "failed"                    # runtime check disproved the finding
    MANUAL_PENDING = "manual_pending"    # needs human review
    NOT_APPLICABLE = "not_applicable"    # cannot be validated dynamically


class ThreatLevel(str, Enum):
    """APK-wide threat classification."""
    BASIC = "basic"           # no protections, straightforward app
    OBFUSCATED = "obfuscated" # name-mangling, string encryption, some guards
    HARDENED = "hardened"     # anti-tamper, anti-debug, runtime checks, native guards


# ---------------------------------------------------------------------------
# Finding data model
# ---------------------------------------------------------------------------

@dataclass
class Evidence:
    """A single piece of evidence supporting a finding."""
    file: str           # relative path
    line: int
    code: str           # raw instruction or context
    register_state: dict[str, str] | None = None   # what was in the registers


@dataclass
class Finding:
    """A consolidated, deduplicated security finding."""
    id: str                                # e.g. "CRYPTO-001-Lcom/app/Foo;->encrypt"
    rule_id: str                           # e.g. "CRYPTO-001"
    severity: str                          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str                          # e.g. "Cryptography"
    title: str
    description: str
    cwe: str                               # CWE-xxx
    evidence: list[Evidence] = field(default_factory=list)
    method_signature: str = ""             # where it was found
    class_name: str = ""
    exploitability: str = "unknown"        # trivial, easy, moderate, hard
    confidence: str = "high"               # legacy string — kept for backwards compat
    confidence_score: float = 0.8          # numeric [0.0 – 1.0]
    risk_score: float = 0.0               # computed composite score
    evidence_strength: str = "single"     # single, corroborated, strong
    validation_state: str = ValidationState.PENDING.value
    threat_level: str = ThreatLevel.BASIC.value
    remediation: str = ""
    related_findings: list[str] = field(default_factory=list)
    auto_patchable: bool = False
    tags: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Detection rules — operates on SmaliMethod / SmaliInstruction
# ---------------------------------------------------------------------------

@dataclass
class DetectionRule:
    """A single detection rule that operates on methods/instructions."""
    rule_id: str
    title: str
    severity: str
    category: str
    cwe: str
    description: str
    remediation: str
    # Detection function: takes (method, instructions) → list of Evidence
    # We use string-based matching on instruction fields for performance
    api_patterns: list[str] = field(default_factory=list)       # match target_class->target_method
    string_patterns: list[re.Pattern] = field(default_factory=list)  # match string constants
    opcode_patterns: list[str] = field(default_factory=list)    # match opcodes
    instruction_patterns: list[re.Pattern] = field(default_factory=list)  # regex on raw instruction
    # Context requirements — e.g. "must be in a method implementing X"
    requires_interface: str = ""      # class must implement this interface
    requires_superclass: str = ""     # class must extend this
    # Exploitability
    exploitability: str = "moderate"
    auto_patchable: bool = False
    tags: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Rule database
# ---------------------------------------------------------------------------

RULES: list[DetectionRule] = [
    # === SSL/TLS ===
    DetectionRule(
        rule_id="SSL-001",
        title="Empty TrustManager (SSL Bypass)",
        severity="CRITICAL",
        category="SSL/TLS",
        cwe="CWE-295",
        description="X509TrustManager with empty checkServerTrusted — accepts any certificate",
        remediation="Implement proper certificate validation or use network_security_config.xml",
        api_patterns=["Ljavax/net/ssl/X509TrustManager;"],
        instruction_patterns=[re.compile(r"checkServerTrusted")],
        requires_interface="Ljavax/net/ssl/X509TrustManager;",
        exploitability="trivial",
        auto_patchable=True,
        tags=["ssl", "mitm"],
    ),
    DetectionRule(
        rule_id="SSL-002",
        title="Disabled HostnameVerifier",
        severity="CRITICAL",
        category="SSL/TLS",
        cwe="CWE-295",
        description="HostnameVerifier.verify() always returns true",
        remediation="Use default HostnameVerifier or implement proper hostname verification",
        api_patterns=["Ljavax/net/ssl/HostnameVerifier;"],
        instruction_patterns=[re.compile(r"ALLOW_ALL_HOSTNAME_VERIFIER")],
        requires_interface="Ljavax/net/ssl/HostnameVerifier;",
        exploitability="trivial",
        auto_patchable=True,
        tags=["ssl", "mitm"],
    ),
    DetectionRule(
        rule_id="SSL-003",
        title="Certificate Pinning",
        severity="INFO",
        category="SSL/TLS",
        cwe="N/A",
        description="Certificate pinning detected — may need bypass for testing",
        remediation="Use Frida or smali patch to bypass pinning for analysis",
        api_patterns=["CertificatePinner"],
        string_patterns=[re.compile(r"sha256/[A-Za-z0-9+/=]+")],
        exploitability="moderate",
        auto_patchable=True,
        tags=["ssl", "pinning"],
    ),
    DetectionRule(
        rule_id="SSL-004",
        title="Cleartext HTTP Traffic",
        severity="MEDIUM",
        category="SSL/TLS",
        cwe="CWE-319",
        description="App uses unencrypted HTTP connections",
        remediation="Use HTTPS for all network communication",
        string_patterns=[re.compile(r"^http://(?!localhost|127\.0\.0\.1|10\.0\.)")],
        tags=["ssl", "cleartext"],
    ),

    # === Root / Emulator Detection ===
    DetectionRule(
        rule_id="ROOT-001",
        title="Root Detection Library",
        severity="INFO",
        category="Root Detection",
        cwe="N/A",
        description="App uses root detection library (RootBeer, SafetyNet, etc.)",
        remediation="Patch root detection methods to return false",
        api_patterns=["RootBeer", "RootTools"],
        string_patterns=[
            re.compile(r"/system/app/Superuser\.apk"),
            re.compile(r"/system/xbin/su"),
            re.compile(r"/sbin/su"),
            re.compile(r"com\.topjohnwu\.magisk"),
            re.compile(r"com\.noshufou\.android\.su"),
            re.compile(r"eu\.chainfire\.supersu"),
            re.compile(r"test-keys"),
        ],
        exploitability="easy",
        auto_patchable=True,
        tags=["root", "bypass"],
    ),
    DetectionRule(
        rule_id="ROOT-002",
        title="Emulator Detection",
        severity="INFO",
        category="Root Detection",
        cwe="N/A",
        description="App detects emulator environment",
        remediation="Patch emulator checks or use a physical device",
        string_patterns=[
            re.compile(r"goldfish"),
            re.compile(r"sdk_gphone"),
            re.compile(r"Genymotion|BlueStacks|Nox"),
            re.compile(r"google_sdk|Emulator|android-x86"),
        ],
        exploitability="easy",
        auto_patchable=True,
        tags=["emulator", "bypass"],
    ),
    DetectionRule(
        rule_id="ROOT-003",
        title="SafetyNet / Play Integrity",
        severity="INFO",
        category="Root Detection",
        cwe="N/A",
        description="App uses Google SafetyNet or Play Integrity API",
        remediation="May need to spoof attestation for testing",
        api_patterns=["SafetyNet", "PlayIntegrity"],
        string_patterns=[re.compile(r"integrity.*token", re.IGNORECASE)],
        exploitability="hard",
        tags=["safetynet", "integrity"],
    ),

    # === Anti-Debug ===
    DetectionRule(
        rule_id="DEBUG-001",
        title="Debugger Detection",
        severity="HIGH",
        category="Anti-Debug",
        cwe="N/A",
        description="Anti-debugging mechanism detected",
        remediation="Patch debug detection or use Frida to bypass",
        api_patterns=[
            "Landroid/os/Debug;->isDebuggerConnected",
            "Landroid/os/Debug;->waitingForDebugger",
        ],
        string_patterns=[
            re.compile(r"TracerPid"),
            re.compile(r"/proc/self/status"),
            re.compile(r"ptrace"),
        ],
        exploitability="easy",
        auto_patchable=True,
        tags=["anti-debug", "bypass"],
    ),

    # === Anti-Tamper ===
    DetectionRule(
        rule_id="TAMPER-001",
        title="Signature Verification",
        severity="HIGH",
        category="Anti-Tamper",
        cwe="N/A",
        description="APK signature verification — will detect modified APK",
        remediation="Patch signature check to return original hash",
        api_patterns=[
            "Landroid/content/pm/PackageManager;->getPackageInfo",
            "Landroid/content/pm/PackageInfo;->signatures",
        ],
        instruction_patterns=[re.compile(r"checkSignature|verifySignature")],
        exploitability="moderate",
        auto_patchable=True,
        tags=["anti-tamper", "signature"],
    ),

    # === Cryptography ===
    DetectionRule(
        rule_id="CRYPTO-001",
        title="ECB Mode Encryption",
        severity="HIGH",
        category="Cryptography",
        cwe="CWE-327",
        description="AES/DES in ECB mode — identical blocks produce identical ciphertext",
        remediation="Use AES/GCM or AES/CBC with random IV",
        string_patterns=[re.compile(r"AES/ECB|DES/ECB", re.IGNORECASE)],
        tags=["crypto", "ecb"],
    ),
    DetectionRule(
        rule_id="CRYPTO-002",
        title="Hardcoded Encryption Key",
        severity="CRITICAL",
        category="Cryptography",
        cwe="CWE-321",
        description="SecretKeySpec initialized with hardcoded data",
        remediation="Derive keys using PBKDF2 or Android Keystore",
        api_patterns=["Ljavax/crypto/spec/SecretKeySpec;-><init>"],
        exploitability="easy",
        tags=["crypto", "hardcoded-key"],
    ),
    DetectionRule(
        rule_id="CRYPTO-003",
        title="Weak Hash (MD5/SHA1)",
        severity="MEDIUM",
        category="Cryptography",
        cwe="CWE-328",
        description="Using MD5 or SHA-1 — both collision-vulnerable",
        remediation="Use SHA-256 or SHA-3",
        string_patterns=[re.compile(r"^(MD5|SHA-?1)$", re.IGNORECASE)],
        tags=["crypto", "weak-hash"],
    ),
    DetectionRule(
        rule_id="CRYPTO-004",
        title="Static Initialization Vector",
        severity="HIGH",
        category="Cryptography",
        cwe="CWE-329",
        description="IvParameterSpec with hardcoded or static IV",
        remediation="Generate random IV for each encryption",
        api_patterns=["Ljavax/crypto/spec/IvParameterSpec;-><init>"],
        tags=["crypto", "static-iv"],
    ),
    DetectionRule(
        rule_id="CRYPTO-005",
        title="Insecure Random",
        severity="MEDIUM",
        category="Cryptography",
        cwe="CWE-330",
        description="java.util.Random instead of SecureRandom for security",
        remediation="Use java.security.SecureRandom",
        api_patterns=["Ljava/util/Random;-><init>"],
        tags=["crypto", "weak-random"],
    ),
    DetectionRule(
        rule_id="CRYPTO-006",
        title="Predictable SecureRandom Seed",
        severity="HIGH",
        category="Cryptography",
        cwe="CWE-330",
        description="SecureRandom.setSeed() with static value defeats randomness",
        remediation="Do not call setSeed() — let the system seed it",
        api_patterns=["Ljava/security/SecureRandom;->setSeed"],
        tags=["crypto", "seed"],
    ),

    # === Data Storage ===
    DetectionRule(
        rule_id="STORAGE-001",
        title="World-Readable File",
        severity="HIGH",
        category="Data Storage",
        cwe="CWE-276",
        description="MODE_WORLD_READABLE — accessible by any app",
        remediation="Use MODE_PRIVATE or ContentProvider",
        string_patterns=[re.compile(r"MODE_WORLD_READABLE")],
        tags=["storage"],
    ),
    DetectionRule(
        rule_id="STORAGE-002",
        title="External Storage Usage",
        severity="MEDIUM",
        category="Data Storage",
        cwe="CWE-921",
        description="Data on external storage — accessible by other apps",
        remediation="Use internal storage or encrypted external storage",
        api_patterns=[
            "Landroid/os/Environment;->getExternalStorageDirectory",
        ],
        instruction_patterns=[re.compile(r"getExternalFilesDir|getExternalStorage")],
        tags=["storage"],
    ),
    DetectionRule(
        rule_id="STORAGE-003",
        title="Unencrypted SQLite",
        severity="MEDIUM",
        category="Data Storage",
        cwe="CWE-312",
        description="SQLite without encryption (no SQLCipher)",
        remediation="Use SQLCipher or EncryptedSharedPreferences",
        api_patterns=[
            "Landroid/database/sqlite/SQLiteOpenHelper;",
            "Landroid/database/sqlite/SQLiteDatabase;->openOrCreateDatabase",
        ],
        tags=["storage", "database"],
    ),
    DetectionRule(
        rule_id="STORAGE-004",
        title="Hardcoded Credentials",
        severity="CRITICAL",
        category="Data Storage",
        cwe="CWE-798",
        description="Hardcoded passwords, API keys, or tokens in source",
        remediation="Use Android Keystore or server-side key management",
        string_patterns=[
            re.compile(r"(?:password|passwd|pwd|api_key|apikey|secret|token)\s*[:=]\s*.{4,}", re.IGNORECASE),
        ],
        exploitability="trivial",
        tags=["credentials", "hardcoded"],
    ),

    # === WebView ===
    DetectionRule(
        rule_id="WEBVIEW-001",
        title="JavaScript Enabled in WebView",
        severity="MEDIUM",
        category="WebView",
        cwe="CWE-749",
        description="WebView with JavaScript enabled — XSS risk",
        remediation="Disable JS if not needed, use SafeBrowsing",
        api_patterns=["Landroid/webkit/WebSettings;->setJavaScriptEnabled"],
        tags=["webview", "xss"],
    ),
    DetectionRule(
        rule_id="WEBVIEW-002",
        title="JavaScript Interface (RCE Risk)",
        severity="HIGH",
        category="WebView",
        cwe="CWE-749",
        description="addJavascriptInterface exposes Java to JS — RCE on API < 17",
        remediation="Require minSDK >= 17 + @JavascriptInterface",
        api_patterns=["Landroid/webkit/WebView;->addJavascriptInterface"],
        exploitability="easy",
        tags=["webview", "rce"],
    ),
    DetectionRule(
        rule_id="WEBVIEW-003",
        title="File Access in WebView",
        severity="HIGH",
        category="WebView",
        cwe="CWE-200",
        description="WebView can access local files — data exfiltration risk",
        remediation="setAllowFileAccess(false)",
        api_patterns=[
            "Landroid/webkit/WebSettings;->setAllowFileAccess",
            "Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs",
        ],
        tags=["webview", "file-access"],
    ),

    # === Logging ===
    DetectionRule(
        rule_id="LOG-001",
        title="Verbose Logging",
        severity="LOW",
        category="Logging",
        cwe="CWE-532",
        description="Debug logging may leak sensitive data in logcat",
        remediation="Remove debug logs from release builds",
        api_patterns=[
            "Landroid/util/Log;->d",
            "Landroid/util/Log;->v",
            "Landroid/util/Log;->i",
        ],
        instruction_patterns=[re.compile(r"System\.out\.print|e\.printStackTrace")],
        tags=["logging"],
    ),

    # === IPC ===
    DetectionRule(
        rule_id="IPC-001",
        title="Implicit Broadcast",
        severity="MEDIUM",
        category="IPC",
        cwe="CWE-927",
        description="Implicit broadcast — any app can receive",
        remediation="Use LocalBroadcastManager or explicit intents",
        api_patterns=["sendBroadcast"],
        tags=["ipc", "broadcast"],
    ),
    DetectionRule(
        rule_id="IPC-002",
        title="Mutable PendingIntent",
        severity="HIGH",
        category="IPC",
        cwe="CWE-927",
        description="FLAG_MUTABLE PendingIntent can be hijacked",
        remediation="Use FLAG_IMMUTABLE",
        instruction_patterns=[re.compile(r"FLAG_MUTABLE")],
        tags=["ipc", "pendingintent"],
    ),

    # === SQL Injection ===
    DetectionRule(
        rule_id="SQL-001",
        title="Raw SQL Query",
        severity="HIGH",
        category="SQL Injection",
        cwe="CWE-89",
        description="rawQuery/execSQL with string concatenation — SQL injection",
        remediation="Use parameterized queries",
        api_patterns=[
            "Landroid/database/sqlite/SQLiteDatabase;->rawQuery",
            "Landroid/database/sqlite/SQLiteDatabase;->execSQL",
        ],
        exploitability="moderate",
        tags=["sql", "injection"],
    ),

    # === Dynamic Code Loading ===
    DetectionRule(
        rule_id="DCL-001",
        title="Dynamic DEX Loading",
        severity="HIGH",
        category="Dynamic Code Loading",
        cwe="CWE-94",
        description="Runtime DEX loading — could load attacker-controlled code",
        remediation="Validate integrity of loaded code",
        api_patterns=[
            "Ldalvik/system/DexClassLoader;",
            "Ldalvik/system/InMemoryDexClassLoader;",
            "Ldalvik/system/PathClassLoader;",
        ],
        exploitability="moderate",
        tags=["dynamic-load", "dex"],
    ),
    DetectionRule(
        rule_id="DCL-002",
        title="Runtime Command Execution",
        severity="HIGH",
        category="Dynamic Code Loading",
        cwe="CWE-78",
        description="Runtime.exec() or ProcessBuilder — OS command execution",
        remediation="Avoid Runtime.exec; use Java APIs",
        api_patterns=[
            "Ljava/lang/Runtime;->exec",
            "Ljava/lang/ProcessBuilder;-><init>",
        ],
        exploitability="moderate",
        tags=["command-exec"],
    ),

    # === Reflection ===
    DetectionRule(
        rule_id="REFLECT-001",
        title="Reflection API Usage",
        severity="MEDIUM",
        category="Reflection",
        cwe="N/A",
        description="Reflection may bypass security or hide API calls",
        remediation="Trace reflected calls to understand hidden behavior",
        api_patterns=[
            "Ljava/lang/reflect/Method;->invoke",
            "Ljava/lang/reflect/Field;->set",
            "Ljava/lang/Class;->forName",
            "Ljava/lang/Class;->getDeclaredMethod",
        ],
        tags=["reflection", "obfuscation"],
    ),

    # === Native ===
    DetectionRule(
        rule_id="NATIVE-001",
        title="Native Library Loading",
        severity="MEDIUM",
        category="Native Code",
        cwe="N/A",
        description="System.loadLibrary — logic may be hidden in .so",
        remediation="Analyze native libraries with Ghidra/IDA",
        api_patterns=[
            "Ljava/lang/System;->loadLibrary",
            "Ljava/lang/System;->load",
        ],
        tags=["native", "jni"],
    ),

    # === Firebase / Cloud ===
    DetectionRule(
        rule_id="CLOUD-001",
        title="Firebase Database URL",
        severity="HIGH",
        category="Cloud Config",
        cwe="CWE-284",
        description="Firebase Realtime Database URL found — check .read/.write rules",
        remediation="Set proper Firebase security rules (no public read/write)",
        string_patterns=[re.compile(r"https://[a-z0-9-]+\.firebaseio\.com")],
        exploitability="easy",
        tags=["firebase", "cloud"],
    ),
    DetectionRule(
        rule_id="CLOUD-002",
        title="Firebase API Key Exposed",
        severity="MEDIUM",
        category="Cloud Config",
        cwe="CWE-312",
        description="Firebase API key in source — check for unrestricted APIs",
        remediation="Restrict API key in Google Cloud Console",
        string_patterns=[re.compile(r"AIza[0-9A-Za-z_-]{35}")],
        tags=["firebase", "api-key"],
    ),
    DetectionRule(
        rule_id="CLOUD-003",
        title="AWS Credentials",
        severity="CRITICAL",
        category="Cloud Config",
        cwe="CWE-798",
        description="AWS access key found in source code",
        remediation="Use AWS Cognito or STS for mobile apps",
        string_patterns=[re.compile(r"AKIA[0-9A-Z]{16}")],
        exploitability="trivial",
        tags=["aws", "credentials"],
    ),
    DetectionRule(
        rule_id="CLOUD-004",
        title="Google Cloud API Key",
        severity="MEDIUM",
        category="Cloud Config",
        cwe="CWE-312",
        description="Google Cloud API key found — check restrictions",
        remediation="Restrict by app package name and SHA fingerprint",
        string_patterns=[re.compile(r"AIza[0-9A-Za-z\\-_]{35}")],
        tags=["gcloud", "api-key"],
    ),

    # === Backup ===
    DetectionRule(
        rule_id="BACKUP-001",
        title="Backup Allowed",
        severity="MEDIUM",
        category="Data Storage",
        cwe="CWE-312",
        description="android:allowBackup=true — app data extractable via adb backup",
        remediation="Set allowBackup=false or use EncryptedSharedPreferences",
        string_patterns=[re.compile(r"allowBackup.*true|android:allowBackup")],
        tags=["backup"],
    ),

    # === Intent Redirection ===
    DetectionRule(
        rule_id="INTENT-001",
        title="Intent Redirection",
        severity="HIGH",
        category="IPC",
        cwe="CWE-940",
        description="getParcelableExtra used to start activity — intent redirection risk",
        remediation="Validate intent extras before use",
        api_patterns=[
            "Landroid/content/Intent;->getParcelableExtra",
        ],
        instruction_patterns=[re.compile(r"startActivity|startActivityForResult")],
        tags=["intent", "redirect"],
    ),
]


# ---------------------------------------------------------------------------
# Scoring & ranking utilities
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHT: dict[str, float] = {
    "CRITICAL": 1.0, "HIGH": 0.8, "MEDIUM": 0.5, "LOW": 0.25, "INFO": 0.1,
}

_EXPLOITABILITY_WEIGHT: dict[str, float] = {
    "trivial": 1.0, "easy": 0.8, "moderate": 0.5, "hard": 0.25, "unknown": 0.4,
}

_EXPLOITABILITY_BASE_CONFIDENCE: dict[str, float] = {
    "trivial": 0.95, "easy": 0.85, "moderate": 0.70, "hard": 0.55, "unknown": 0.60,
}


def _compute_confidence_score(rule: "DetectionRule", evidence_count: int) -> float:
    """Numeric confidence [0.0–1.0] from rule exploitability + evidence density."""
    base = _EXPLOITABILITY_BASE_CONFIDENCE.get(rule.exploitability, 0.60)
    # More evidence → higher confidence (diminishing returns)
    if evidence_count >= 3:
        boost = 0.10
    elif evidence_count >= 2:
        boost = 0.05
    else:
        boost = 0.0
    return min(1.0, base + boost)


def _evidence_strength(evidence_count: int) -> str:
    """Classify evidence strength."""
    if evidence_count >= 3:
        return "strong"
    elif evidence_count >= 2:
        return "corroborated"
    return "single"


def compute_risk_score(
    severity: str,
    exploitability: str,
    confidence_score: float,
    auto_patchable: bool,
) -> float:
    """Composite risk score: severity × exploitability × confidence × patchability.

    Range: 0.0 – 1.0. Higher = more important to fix.
    """
    sev = _SEVERITY_WEIGHT.get(severity, 0.3)
    exp = _EXPLOITABILITY_WEIGHT.get(exploitability, 0.4)
    patch_bonus = 1.0 if auto_patchable else 0.85  # patchable → slightly prioritized
    return round(sev * exp * confidence_score * patch_bonus, 4)


def rank_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by risk_score descending, then severity."""
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    return sorted(
        findings,
        key=lambda f: (-f.risk_score, -severity_order.get(f.severity, 0)),
    )


# ---------------------------------------------------------------------------
# Threat-model classification
# ---------------------------------------------------------------------------

def classify_threat_model(findings: list[Finding]) -> ThreatLevel:
    """Classify an APK's threat level from its findings.

    Heuristic:
      - hardened: anti-tamper / anti-debug / native guards + obfuscation
      - obfuscated: obfuscation indicators or >2 protection categories
      - basic: everything else
    """
    cats = {f.category for f in findings}
    tags_all = set()
    for f in findings:
        tags_all.update(f.tags)

    has_obfuscation = "Obfuscation" in cats
    has_anti_tamper = bool({"Anti-Tamper", "Anti-Debug"} & cats)
    has_native = "Native Code" in cats
    has_root_detect = "Root Detection" in cats
    protection_count = sum(1 for c in cats if c in {
        "Root Detection", "Anti-Tamper", "Anti-Debug",
        "Obfuscation", "SSL/TLS", "Native Code",
    })

    if has_anti_tamper and (has_obfuscation or has_native):
        return ThreatLevel.HARDENED
    if has_obfuscation or protection_count >= 3:
        return ThreatLevel.OBFUSCATED
    return ThreatLevel.BASIC


# ---------------------------------------------------------------------------
# Scanner engine
# ---------------------------------------------------------------------------

def scan(index: "SmaliIndex", rules: list[DetectionRule] | None = None,
         severity_filter: str | None = None,
         max_findings: int = 500) -> dict:
    """Run all detection rules against the SmaliIndex.

    Single pass over all methods — no file I/O.

    Args:
        index:  Pre-built SmaliIndex from smali_ir.build_index.
        rules:  Override rule set (default: RULES).
        severity_filter:  Minimum severity to include.
        max_findings: Cap on returned findings.

    Returns:
        Dict with findings, summary, stats.
    """
    if rules is None:
        rules = RULES

    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    min_sev = severity_order.get(severity_filter or "", 0)

    findings: list[Finding] = []
    seen_keys: set[str] = set()  # dedup key = rule_id + class + method

    for cls in index.classes.values():
        for method in cls.methods:
            for rule in rules:
                # Quick filter: check interface/superclass requirements
                if rule.requires_interface and rule.requires_interface not in cls.interfaces:
                    continue
                if rule.requires_superclass and rule.requires_superclass != cls.super_class:
                    continue

                evidences = _match_rule(rule, method, cls)
                if not evidences:
                    continue

                # Dedup
                dedup_key = f"{rule.rule_id}|{cls.name}|{method.name}"
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

                sev_val = severity_order.get(rule.severity, 0)
                if sev_val < min_sev:
                    continue

                conf_score = _compute_confidence_score(rule, len(evidences))
                risk = compute_risk_score(
                    rule.severity, rule.exploitability,
                    conf_score, rule.auto_patchable,
                )

                finding = Finding(
                    id=f"{rule.rule_id}-{cls.name}->{method.name}",
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    category=rule.category,
                    title=rule.title,
                    description=rule.description,
                    cwe=rule.cwe,
                    evidence=evidences,
                    method_signature=method.full_signature,
                    class_name=cls.name,
                    exploitability=rule.exploitability,
                    confidence_score=conf_score,
                    risk_score=risk,
                    evidence_strength=_evidence_strength(len(evidences)),
                    remediation=rule.remediation,
                    auto_patchable=rule.auto_patchable,
                    tags=list(rule.tags),
                )

                findings.append(finding)
                if len(findings) >= max_findings:
                    break
            if len(findings) >= max_findings:
                break
        if len(findings) >= max_findings:
            break

    # Rank by composite risk score (replaces simple severity sort)
    findings = rank_findings(findings)

    # Classify APK threat model
    threat = classify_threat_model(findings)
    # Stamp threat_level on each finding so downstream consumers see it
    for f in findings:
        f.threat_level = threat.value

    # Build summary
    sev_counts: dict[str, int] = defaultdict(int)
    cat_counts: dict[str, int] = defaultdict(int)
    for f in findings:
        sev_counts[f.severity] += 1
        cat_counts[f.category] += 1

    return {
        "success": True,
        "total_findings": len(findings),
        "threat_level": threat.value,
        "severity_summary": dict(sorted(sev_counts.items(),
                                        key=lambda x: -severity_order.get(x[0], 0))),
        "category_summary": dict(sorted(cat_counts.items(), key=lambda x: -x[1])),
        "findings": [_finding_to_dict(f) for f in findings],
        "classes_scanned": len(index.classes),
        "methods_scanned": len(index.methods),
    }


def _match_rule(rule: DetectionRule, method: "SmaliMethod",
                cls: "SmaliClass") -> list[Evidence]:
    """Check if a detection rule matches within a method. Returns evidence."""
    evidences: list[Evidence] = []

    # 1. API pattern matching (fastest — uses pre-indexed api_calls)
    for api_pat in rule.api_patterns:
        for api_call in method.api_calls:
            if api_pat in api_call:
                # Find the exact instruction
                for instr in method.instructions:
                    if instr.is_invoke and api_pat in instr.raw:
                        evidences.append(Evidence(
                            file=cls.file_path,
                            line=instr.line,
                            code=instr.raw[:200],
                        ))
                        break
                else:
                    # Fallback: report at method level
                    evidences.append(Evidence(
                        file=cls.file_path,
                        line=method.start_line,
                        code=f"API call to {api_call}",
                    ))

    # 2. String pattern matching (uses pre-indexed string_constants)
    for str_pat in rule.string_patterns:
        for s in method.string_constants:
            if str_pat.search(s):
                # Find the instruction
                for instr in method.instructions:
                    if instr.string_value and str_pat.search(instr.string_value):
                        evidences.append(Evidence(
                            file=cls.file_path,
                            line=instr.line,
                            code=instr.raw[:200],
                        ))
                        break
                else:
                    evidences.append(Evidence(
                        file=cls.file_path,
                        line=method.start_line,
                        code=f"String matches: {s[:80]}",
                    ))

    # 3. Instruction-level regex (more expensive — only if needed)
    for instr_pat in rule.instruction_patterns:
        for instr in method.instructions:
            if instr_pat.search(instr.raw):
                evidences.append(Evidence(
                    file=cls.file_path,
                    line=instr.line,
                    code=instr.raw[:200],
                ))
                break  # One match per pattern per method is enough

    # 4. Opcode matching
    for opc_pat in rule.opcode_patterns:
        for instr in method.instructions:
            if instr.opcode == opc_pat:
                evidences.append(Evidence(
                    file=cls.file_path,
                    line=instr.line,
                    code=instr.raw[:200],
                ))
                break

    return evidences


def _finding_to_dict(f: Finding) -> dict:
    """Convert Finding to JSON-serializable dict."""
    return {
        "id": f.id,
        "rule_id": f.rule_id,
        "severity": f.severity,
        "category": f.category,
        "title": f.title,
        "description": f.description,
        "cwe": f.cwe,
        "method": f.method_signature,
        "class": f.class_name,
        "exploitability": f.exploitability,
        "confidence": f.confidence,
        "confidence_score": f.confidence_score,
        "risk_score": f.risk_score,
        "evidence_strength": f.evidence_strength,
        "validation_state": f.validation_state,
        "threat_level": f.threat_level,
        "remediation": f.remediation,
        "auto_patchable": f.auto_patchable,
        "tags": f.tags,
        "evidence": [
            {"file": e.file, "line": e.line, "code": e.code}
            for e in f.evidence
        ],
        "related": f.related_findings,
    }
