"""High-performance APK patcher — automated bypass engine for common protections.

Provides categorized regex-based smali patching, Flutter binary patching,
manifest hardening removal, NSC injection, and ad network neutralization.

Uses ThreadPoolExecutor for parallel file scanning and atomic patching.
All operations return structured dicts for LLM consumption.
"""

from __future__ import annotations

import logging
import re
import shutil
import stat
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from os import cpu_count
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger("apk_agent.tools.patcher")

# ---------------------------------------------------------------------------
# Pattern categories
# ---------------------------------------------------------------------------


class PatchCategory(str, Enum):
    SSL_BYPASS = "ssl_bypass"
    VPN_BYPASS = "vpn_bypass"
    MOCK_LOCATION = "mock_location"
    LICENSE_BYPASS = "license_bypass"
    PAIRIP_BYPASS = "pairip_bypass"
    PURCHASE_BYPASS = "purchase_bypass"
    SCREENSHOT_BYPASS = "screenshot_bypass"
    USB_DEBUG_BYPASS = "usb_debug_bypass"
    DEVICE_SPOOF = "device_spoof"
    ADS_REMOVAL = "ads_removal"
    PACKAGE_SPOOF = "package_spoof"


@dataclass
class SmaliPattern:
    """A single regex-based smali transformation rule."""
    category: PatchCategory
    regex: str
    replacement: str | Callable
    tag: str

    def compiled(self) -> re.Pattern:
        return re.compile(self.regex, re.MULTILINE | re.DOTALL)


@dataclass
class PatchStats:
    """Aggregated result of a patching run."""
    files_scanned: int = 0
    files_matched: int = 0
    files_patched: int = 0
    patterns_applied: int = 0
    applied_details: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    categories_hit: set = field(default_factory=set)

    def to_dict(self) -> dict:
        # Group details by category for compact output (avoid listing every file)
        by_cat: dict[str, dict] = {}
        for d in self.applied_details:
            cat = d.get("category", "unknown")
            if cat not in by_cat:
                by_cat[cat] = {"patches": 0, "files": set(), "tags": set()}
            by_cat[cat]["patches"] += d.get("matches", 1)
            by_cat[cat]["files"].add(d.get("file", "?"))
            by_cat[cat]["tags"].add(d.get("tag", ""))
        cat_summary = {
            cat: {
                "patches": info["patches"],
                "files_count": len(info["files"]),
                "tags": sorted(info["tags"]),
            }
            for cat, info in by_cat.items()
        }
        return {
            "success": self.files_patched > 0 or not self.errors,
            "files_scanned": self.files_scanned,
            "files_matched": self.files_matched,
            "files_patched": self.files_patched,
            "patterns_applied": self.patterns_applied,
            "categories_hit": sorted(self.categories_hit),
            "per_category": cat_summary,
            "errors": self.errors[:10],
        }


# ---------------------------------------------------------------------------
# Pattern definitions — derived from analysis of professional patching tools,
# re-engineered with improvements (better group handling, fewer false positives)
# ---------------------------------------------------------------------------

# ---- SSL / TLS Pinning Bypass ----
SSL_PATTERNS: list[SmaliPattern] = [
    SmaliPattern(
        PatchCategory.SSL_BYPASS,
        r'(\.method [^(]*verify\([^\)]*(?:Ljavax/net/ssl/SSLSession;|Ljava/security/cert/X509Certificate;)[^\)]*\)Z\s+\.locals \d+)[\s\S]*?(\n\.end method)',
        r'\1\n    const/4 v0, 0x1\n    return v0\2',
        "SSL verify → always true",
    ),
    SmaliPattern(
        PatchCategory.SSL_BYPASS,
        r'(\.method [^(]*checkServerTrusted\([^\)]*Ljava/security/cert/X509Certificate;[^\)]*\)Ljava/util/List;\s+\.locals \d+)[\s\S]*?(\n\.end method)',
        r'\1\n    new-instance v0, Ljava/util/ArrayList;\n    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V\n    return-object v0\2',
        "checkServerTrusted(List) → empty list",
    ),
    SmaliPattern(
        PatchCategory.SSL_BYPASS,
        r'(\.method [^(]*check(?:Client|Server)Trusted\([^\)]*Ljava/security/cert/X509Certificate;[^\)]*\)V\s+\.locals \d+)[\s\S]*?(\n\.end method)',
        r'\1\n    return-void\2',
        "checkTrusted(void) → nop",
    ),
    SmaliPattern(
        PatchCategory.SSL_BYPASS,
        r'(\.method [^(]*check\(Ljava/lang/String;(?:Ljava/util/List;|\[Ljava/security/cert/Certificate;)\)V\s+\.locals \d+)[\s\S]*?(\n\.end method)',
        r'\1\n    return-void\2',
        "CertificatePinner.check → nop",
    ),
    SmaliPattern(
        PatchCategory.SSL_BYPASS,
        r'(\.method [^(]*check\$okhttp\(Ljava/lang/String;[^\)]*\)V\s+\.locals \d+)[\s\S]*?(\n\.end method)',
        r'\1\n    return-void\2',
        "check$okhttp → nop",
    ),
    SmaliPattern(
        PatchCategory.SSL_BYPASS,
        r'(\.method [^(]*getAcceptedIssuers\(\)\[Ljava/security/cert/X509Certificate;\s+\.locals \d+)[\s\S]*?(\n\.end method)',
        r'\1\n    const/4 v0, 0x0\n    new-array v0, v0, [Ljava/security/cert/X509Certificate;\n    return-object v0\2',
        "getAcceptedIssuers → empty array",
    ),
    SmaliPattern(
        PatchCategory.SSL_BYPASS,
        r'(\.method [^(]*\S+\(Ljava/lang/String;[^\)]*\)V\s+\.locals \d+)(?:(?!\.end method)[\s\S])*?(?:check-cast [pv]\d+, Ljava/security/cert/X509Certificate;|Ljavax/net/ssl/SSLPeerUnverifiedException;)(?:(?!\.end method)[\s\S])*?(\n\.end method)',
        r'\1\n    return-void\2',
        "OkHttp SSL handler → nop",
    ),
]

# ---- VPN / Proxy Detection Bypass ----
VPN_PATTERNS: list[SmaliPattern] = [
    SmaliPattern(
        PatchCategory.VPN_BYPASS,
        r'(const/4 [pv]\d+, 0x4[^>]*?invoke-\w+ \{[^\}]*\}, Landroid/net/NetworkCapabilities;->hasTransport\(I\)Z[^>]*?)move-result ([pv]\d+)',
        r'\1const/4 \2, 0x0',
        "NetworkCapabilities.hasTransport → false",
    ),
    SmaliPattern(
        PatchCategory.VPN_BYPASS,
        r'(Ljava/net/NetworkInterface;->(?:isUp|isVirtual|isLoopback)\(\)Z[^>]*?)move-result ([pv]\d+)',
        r'\1const/4 \2, 0x0',
        "NetworkInterface.isUp/isVirtual → false",
    ),
    SmaliPattern(
        PatchCategory.VPN_BYPASS,
        r'(const-string [pv]\d+, "(?:tun|tunl0|tun0|utun\d|pptp|ppp\d?|p2p0|ccmni0|ipsec)"[^>]*?invoke-\w+ \{[^\}]*\}, L[^\(]+;->\S+\(Ljava/lang/CharSequence;\)Z[^>]*?)move-result ([pv]\d+)',
        r'\1const/4 \2, 0x0',
        "VPN interface name check → false",
    ),
]

# ---- Mock Location Bypass ----
MOCK_PATTERNS: list[SmaliPattern] = [
    SmaliPattern(
        PatchCategory.MOCK_LOCATION,
        r'(invoke-virtual \{[^\}]*\}, Landroid/location/Location;->(?:isFromMockProvider|isMock)\(\)Z[^>]*?)move-result ([pv]\d+)',
        r'\1const/4 \2, 0x0',
        "Mock location → false",
    ),
    SmaliPattern(
        PatchCategory.MOCK_LOCATION,
        r'(invoke-virtual \{[^\}]*\}, Landroid/content/pm/PackageManager;->getInstallerPackageName\(Ljava/lang/String;\)Ljava/lang/String;[^>]*?)move-result-object ([pv]\d+)',
        r'\1const-string \2, "com.android.vending"',
        "Installer spoof → Play Store",
    ),
]

# ---- License / LVL Bypass ----
LICENSE_PATTERNS: list[SmaliPattern] = [
    SmaliPattern(
        PatchCategory.LICENSE_BYPASS,
        r'(invoke-interface \{[^\}]*\}, Lcom/google/android/vending/licensing/Policy;->allowAccess\(\)Z[^>]*?\s+)move-result ([pv]\d+)',
        r'\1const/4 \2, 0x1',
        "LVL allowAccess → true",
    ),
    SmaliPattern(
        PatchCategory.LICENSE_BYPASS,
        r'(\.method [^(]*connectToLicensingService\(\)V\s+\.locals \d+)[\s\S]*?(\s+return-void\n\.end method)',
        r'\1\2',
        "connectToLicensingService → empty",
    ),
    SmaliPattern(
        PatchCategory.LICENSE_BYPASS,
        r'(\.method [^(]*initializeLicenseCheck\(\)V\s+\.locals \d+)[\s\S]*?(\s+return-void\n\.end method)',
        r'\1\2',
        "initializeLicenseCheck → empty",
    ),
    SmaliPattern(
        PatchCategory.LICENSE_BYPASS,
        r'(\.method [^(]*processResponse\(ILandroid/os/Bundle;\)V\s+\.locals \d+)[\s\S]*?(\s+return-void\n\.end method)',
        r'\1\2',
        "processResponse → empty",
    ),
]

# ---- Pairip Integrity Bypass ----
PAIRIP_PATTERNS: list[SmaliPattern] = [
    SmaliPattern(
        PatchCategory.PAIRIP_BYPASS,
        r'invoke-static \{[^\}]*\}, Lcom/pairip/SignatureCheck;->verifyIntegrity\(Landroid/content/Context;\)V',
        r'#',
        "Pairip verifyIntegrity call → nop",
    ),
    SmaliPattern(
        PatchCategory.PAIRIP_BYPASS,
        r'(\.method [^(]*verifyIntegrity\(Landroid/content/Context;\)V\s+\.locals \d+)[\s\S]*?(\s+return-void\n\.end method)',
        r'\1\2',
        "verifyIntegrity body → empty",
    ),
    SmaliPattern(
        PatchCategory.PAIRIP_BYPASS,
        r'(\.method [^(]*verifySignatureMatches\(Ljava/lang/String;\)Z\s+\.locals \d+\s+)[\s\S]*?(\s+return ([pv]\d+)\n\.end method)',
        r'\1const/4 \3, 0x1\2',
        "verifySignatureMatches → true",
    ),
]

# ---- Purchase / Premium Bypass ----
PURCHASE_PATTERNS: list[SmaliPattern] = [
    SmaliPattern(
        PatchCategory.PURCHASE_BYPASS,
        r'(\.method [^(]*(?:getPrice|getMrp|getPro_mrp|getTotal(?:_)?Price|getOffer(?:_)?price|getSub_pack_price|getSub_actual_price|getActual_price|getDiscount(?:_)?price|getRegistration_price|getProduct_amount|getIs_locked)\(\)Ljava/lang/String;(?:(?!const-string [pv]\d+, "0")[\s\S])*?)(return-object ([pv]\d+)\n\.end method)',
        r'\1const-string \3, "0"\n\t\2',
        "Price getter → $0",
    ),
    SmaliPattern(
        PatchCategory.PURCHASE_BYPASS,
        r'(\.method [^(]*(?:is(?:_)?Paid|getIs(?:_)?Paid|is(?:_)?purchase(?:d)?|get(?:_)?Purchase(?:d)?|getIs(?:_)?purchase(?:d)?|getPurchaseStatus|getIs_pass|getIs_pro|getIs_pro_purchased|getIs_pro_content|isOwn|isLifetime|is(?:_)?Trial)\(.*\)(?:Ljava/lang/String;|Ljava/lang/Integer;)(?:(?!const-string [pv]\d+, "1")[\s\S])*?)(return-object ([pv]\d+)\n\.end method)',
        r'\1const-string \3, "1"\n\t\2',
        "isPurchased(String) → 1",
    ),
    SmaliPattern(
        PatchCategory.PURCHASE_BYPASS,
        r'(\.method [^(]*(?:is(?:_)?Paid|getInsIspaid|is(?:_)?purchase(?:d)?|getUser_purchase_status|getPurchaseId|is(?:_)?Trial)\(\)(?:I|Z)(?:(?!const [pv]\d+, 0x1)[\s\S])*?)(return ([pv]\d+)\n\.end method)',
        r'\1const \3, 0x1\n\t\2',
        "isPurchased(bool/int) → true",
    ),
]

# ---- Screenshot / FLAG_SECURE Bypass ----
SCREENSHOT_PATTERNS: list[SmaliPattern] = [
    SmaliPattern(
        PatchCategory.SCREENSHOT_BYPASS,
        r'(const/16 [pv]\d+, 0x)200(0\s+(?:\.line \d+\s+)*?invoke-virtual \{[^\}]*\}, Landroid/view/Window;->(?:add|set)Flags\(II\)V)',
        r'\1\2',
        "FLAG_SECURE addFlags → 0x0",
    ),
    SmaliPattern(
        PatchCategory.SCREENSHOT_BYPASS,
        r'(invoke-static \{[^\}]*\}, L[^\(]+;->isSecuredNow\(Landroid/view/Window;\)Z\s+(?:\.line \d+\s+)*?move-result [pv]\d+\s+(?:\.line \d+\s+)*?const/16 ([pv]\d+),) 0x2000',
        r'\1 0x0',
        "isSecuredNow flag → 0x0",
    ),
    SmaliPattern(
        PatchCategory.SCREENSHOT_BYPASS,
        r'(iget [pv]\d+, [pv]\d+, Landroid/view/WindowManager\$LayoutParams;->flags:I\s+(?:\.line \d+\s+)*?or-int/lit16 [pv]\d+, [pv]\d+,) 0x2000',
        r'\1 0x0',
        "LayoutParams FLAG_SECURE → 0x0",
    ),
    SmaliPattern(
        PatchCategory.SCREENSHOT_BYPASS,
        r'(invoke-virtual \{([pv]\d+), ([pv]\d+)\}, Landroid/view/SurfaceView;->setSecure\(Z\)V)',
        r'const/4 \3, 0x0\n\n\t\1',
        "SurfaceView.setSecure → false",
    ),
]

# ---- USB Debugging Detection Bypass ----
USB_DEBUG_PATTERNS: list[SmaliPattern] = [
    SmaliPattern(
        PatchCategory.USB_DEBUG_BYPASS,
        r'(const-string [pv]\d+, "development_settings_enabled"[^>]*invoke-static \{[^\}]*\}, L[^\(]+;->getInt\([^\)]*Ljava/lang/String;I\)I[^>]*)move-result ([pv]\d+)',
        r'\1const/4 \2, 0x0',
        "development_settings_enabled → 0",
    ),
    SmaliPattern(
        PatchCategory.USB_DEBUG_BYPASS,
        r'(const-string [pv]\d+, "adb_enabled"[^>]*invoke-static \{[^\}]*\}, L[^\(]+;->getInt\([^\(]*Ljava/lang/String;I\)I[^>]*)move-result ([pv]\d+)',
        r'\1const/4 \2, 0x0',
        "adb_enabled → 0",
    ),
]

# ---- Device ID Spoofing ----
DEVICE_SPOOF_PATTERNS: list[SmaliPattern] = [
    SmaliPattern(
        PatchCategory.DEVICE_SPOOF,
        r'(const-string [pv]\d+, "android_id"[^>]*?invoke-static \{[^\}]*\}, Landroid/provider/Settings\$Secure;->getString\(Landroid/content/ContentResolver;Ljava/lang/String;\)Ljava/lang/String;[^>]*?)move-result-object ([pv]\d+)',
        r'\1const-string \2, "0000000000000000"',
        "android_id → zeroed",
    ),
]

# ---- Package / Tamper Detection Bypass ----
PACKAGE_SPOOF_PATTERNS: list[SmaliPattern] = [
    SmaliPattern(
        PatchCategory.PACKAGE_SPOOF,
        r'invoke-static \{[^\}]*\}, (?:Ljava/lang/System;->exit|Landroid/os/Process;->killProcess)\(I\)V',
        'nop',
        "System.exit / killProcess → nop",
    ),
    SmaliPattern(
        PatchCategory.PACKAGE_SPOOF,
        r'(const-string [pv]\d+, )"de\.robv\.android\.xposed',
        r'\1"disabled.xposed',
        "Xposed detection string → disabled",
    ),
    SmaliPattern(
        PatchCategory.PACKAGE_SPOOF,
        r'const-string [pv]\d+, "/data/local/tmp/(?:frida|frida-server)"[^>]*?invoke-static \{[^\}]*\}, Ljava/io/File;->exists\(\)Z[^>]*?move-result ([pv]\d+)',
        r'const/4 \1, 0x0',
        "Frida detection → false",
    ),
]

# ---- Ad Network Neutralization ----
# Consolidated ad patterns — covers 40+ networks with optimized regexes
_AD_NETWORKS = (
    r'adcolony|admob|ads|adsdk|aerserv|appbrain|applovin|appodeal|appodealx|'
    r'appsflyer|bytedance/sdk/openadsdk|chartboost|flurry|fyber|hyprmx|inmobi|'
    r'ironsource|mbrg|mbridge|mintegral|moat|mobfox|mobilefuse|mopub|my/target|'
    r'ogury|Omid|onesignal|presage|smaato|smartadserver|snap/adkit|snap/appadskit|'
    r'startapp|taboola|tapjoy|tappx|vungle'
)

ADS_PATTERNS: list[SmaliPattern] = [
    SmaliPattern(
        PatchCategory.ADS_REMOVAL,
        rf'(invoke(?!.*(close|Destroy|Dismiss|Disabl|error|player|remov|expir|fail|hide|skip|stop)).*/'
        rf'({_AD_NETWORKS})/[^;]+;->(.*(load|show).*)\([^)]*\)V)',
        r'nop',
        "Ad load/show calls → nop",
    ),
    SmaliPattern(
        PatchCategory.ADS_REMOVAL,
        rf'(invoke(?!.*(close|Deactiv|Destroy|Dismiss|Disabl|error|player|remov|expir|fail|hide|skip|stop|Throw)).*/'
        rf'({_AD_NETWORKS})/[^;]+;->'
        rf'(request.*|(.*(activat|Banner|build|Event|exec|header|html|initAd|initi|JavaScript|Interstitial|load|log|MetaData|metri|Native|onAd|propert|report|response|Rewarded|show|trac|url|(fetch|refresh|render|video)Ad).*)|.*Request)\([^)]*\)V)',
        r'nop',
        "Ad init/request calls → nop",
    ),
    SmaliPattern(
        PatchCategory.ADS_REMOVAL,
        rf'(invoke(?!.*(close|Deactiv|Destroy|Dismiss|Disabl|error|player|remov|expir|fail|hide|skip|stop|Throw)).*/'
        rf'({_AD_NETWORKS})/[^;]+;->'
        rf'(request.*|(.*(activat|Banner|build|Event|exec|header|html|initAd|initi|JavaScript|Interstitial|load|log|MetaData|metri|Native|'
        rf'(?:can|get|is|has|was)Ad|propert|report|response|Rewarded|show|trac|url|'
        rf'(?:fetch|refresh|render|video)Ad).*)|.*Request)\([^)]*\)Z[^>]*?)move-result ([pv]\d+)',
        r'const/4 \g<last>, 0x0',
        "Ad status checks → false",
    ),
    SmaliPattern(
        PatchCategory.ADS_REMOVAL,
        r'(\.method\s(?:public|private|static)\s\b(?!\babstract|native\b)[^(]*?loadAd\([^)]*\)V)',
        r'\1\n\treturn-void',
        "loadAd methods → return-void",
    ),
    SmaliPattern(
        PatchCategory.ADS_REMOVAL,
        r'(\.method\s(?:public|private|static)\s\b(?!\babstract|native\b)[^(]*?loadAd\([^)]*\)Z)',
        r'\1\n\tconst/4 v0, 0x0\n\treturn v0',
        "loadAd(Z) methods → false",
    ),
    SmaliPattern(
        PatchCategory.ADS_REMOVAL,
        r'(invoke[^{]+ \{[^\}]*\}, L[^(]*loadAd\([^)]*\)[VZ])',
        r'#',
        "loadAd invocations → commented",
    ),
    SmaliPattern(
        PatchCategory.ADS_REMOVAL,
        r'"ca-app-pub-\d{16}/\d{10}"',
        r'"ca-app-pub-0000000000000000/0000000000"',
        "AdMob unit IDs → zeroed",
    ),
    SmaliPattern(
        PatchCategory.ADS_REMOVAL,
        r'"com\.google\.android\.play\.core\.appupdate\.protocol\.IAppUpdateService"',
        r'""',
        "App update service → disabled",
    ),
]

# ---- Master registry ----
ALL_PATTERNS: dict[PatchCategory, list[SmaliPattern]] = {
    PatchCategory.SSL_BYPASS: SSL_PATTERNS,
    PatchCategory.VPN_BYPASS: VPN_PATTERNS,
    PatchCategory.MOCK_LOCATION: MOCK_PATTERNS,
    PatchCategory.LICENSE_BYPASS: LICENSE_PATTERNS,
    PatchCategory.PAIRIP_BYPASS: PAIRIP_PATTERNS,
    PatchCategory.PURCHASE_BYPASS: PURCHASE_PATTERNS,
    PatchCategory.SCREENSHOT_BYPASS: SCREENSHOT_PATTERNS,
    PatchCategory.USB_DEBUG_BYPASS: USB_DEBUG_PATTERNS,
    PatchCategory.DEVICE_SPOOF: DEVICE_SPOOF_PATTERNS,
    PatchCategory.PACKAGE_SPOOF: PACKAGE_SPOOF_PATTERNS,
    PatchCategory.ADS_REMOVAL: ADS_PATTERNS,
}

# ---------------------------------------------------------------------------
# Parallel file scanner
# ---------------------------------------------------------------------------


def _collect_smali_files(dirs: list[Path], extensions: tuple[str, ...] = (".smali",)) -> list[Path]:
    """Recursively collect files matching extensions from multiple directories."""
    files: list[Path] = []
    # Skip directories that are guaranteed to never contain app code
    _SKIP_DIRS = frozenset({
        "android", "androidx", "kotlin", "kotlinx", "dalvik",
        "java", "javax", "org", "sun", "annotation",
    })
    for d in dirs:
        if not d.is_dir():
            continue
        for ext in extensions:
            for f in d.rglob(f"*{ext}"):
                # Skip framework/library top-level packages that never need patching
                try:
                    rel = f.relative_to(d)
                    top = rel.parts[0] if rel.parts else ""
                    if top in _SKIP_DIRS:
                        continue
                except ValueError:
                    pass
                files.append(f)
    return files


def _scan_file(path: Path, compiled_regexes: list[re.Pattern]) -> Optional[tuple[Path, str]]:
    """Check if a file matches any of the compiled regexes.
    Returns (path, content) tuple if match so we don't have to re-read in Phase 2."""
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        for rx in compiled_regexes:
            if rx.search(content):
                return (path, content)
    except Exception:
        pass
    return None


def _parallel_scan(
    files: list[Path],
    patterns: list[SmaliPattern],
    max_workers: int | None = None,
) -> list[tuple[Path, str]]:
    """Scan files in parallel for any matching pattern.
    Returns list of (path, content) tuples so we skip re-reading in Phase 2."""
    if not files:
        return []

    compiled = [p.compiled() for p in patterns]
    workers = max_workers or min(cpu_count() or 4, 8)
    matched: list[tuple[Path, str]] = []

    # Progress helper for scan phase
    try:
        from apk_agent.progress import report_progress as _rp
    except Exception:
        _rp = None

    total = len(files)
    done = 0
    report_every = max(1, total // 20)  # update ~20 times during scan

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_scan_file, f, compiled): f for f in files}
        for fut in as_completed(futures):
            result = fut.result()
            if result is not None:
                matched.append(result)
            done += 1
            if _rp and done % report_every == 0:
                pct = 5 + (done / total) * 35  # 5-40%
                try:
                    _rp(pct, f"Scanned {done}/{total} files ({len(matched)} hits)")
                except Exception:
                    pass

    return matched


# ---------------------------------------------------------------------------
# Core patching engine
# ---------------------------------------------------------------------------


def _apply_patterns_to_file(
    path: Path,
    patterns: list[SmaliPattern],
    backup_dir: Optional[Path] = None,
    preloaded_content: Optional[str] = None,
    compiled_cache: Optional[list[re.Pattern]] = None,
) -> list[dict]:
    """Apply all patterns to a single file. Returns list of applied patch details.

    Args:
        path: Path to the smali file.
        patterns: List of SmaliPattern rules.
        backup_dir: Optional backup directory.
        preloaded_content: Pre-read file content from scanning phase (avoids re-read).
        compiled_cache: Pre-compiled regex list (avoids re-compiling per file).
    """
    applied: list[dict] = []
    try:
        content = preloaded_content or path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        return [{"error": str(e), "file": str(path)}]

    original = content
    for i, pat in enumerate(patterns):
        try:
            rx = compiled_cache[i] if compiled_cache else pat.compiled()
            new_content = rx.sub(pat.replacement, content)
            if new_content != content:
                count = len(rx.findall(content))
                applied.append({
                    "category": pat.category.value,
                    "tag": pat.tag,
                    "file": path.name,
                    "path": str(path),
                    "matches": count,
                })
                content = new_content
        except Exception as e:
            applied.append({
                "category": pat.category.value,
                "tag": pat.tag,
                "file": path.name,
                "error": str(e),
            })

    if content != original:
        # Backup before write
        if backup_dir:
            rel = path.name
            bk = backup_dir / f"patcher_{rel}"
            bk.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copy2(str(path), str(bk))
            except Exception:
                pass
        # Clear read-only flag on Windows before writing
        if path.exists():
            path.chmod(path.stat().st_mode | stat.S_IWRITE)
        path.write_text(content, encoding="utf-8")

    return applied


def run_smali_patches(
    smali_dirs: list[Path],
    categories: list[PatchCategory] | None = None,
    backup_dir: Optional[Path] = None,
    max_workers: int | None = None,
    custom_device_id: str | None = None,
) -> PatchStats:
    """Run automated smali patching across all smali directories.

    Args:
        smali_dirs: List of smali directories to scan.
        categories: Which patch categories to apply. None = all.
        backup_dir: Where to backup files before patching.
        max_workers: Thread pool size.
        custom_device_id: If set, patches android_id to this value.

    Returns:
        PatchStats with full details.
    """
    stats = PatchStats()

    # Collect patterns for requested categories
    cats = categories or list(ALL_PATTERNS.keys())
    patterns: list[SmaliPattern] = []
    for cat in cats:
        if cat in ALL_PATTERNS:
            patterns.extend(ALL_PATTERNS[cat])

    # Override device ID if custom value given
    if custom_device_id and PatchCategory.DEVICE_SPOOF in cats:
        for p in patterns:
            if p.category == PatchCategory.DEVICE_SPOOF and "android_id" in p.tag:
                p.replacement = p.replacement.replace("0000000000000000", custom_device_id)

    if not patterns:
        stats.errors.append("No patterns match the requested categories")
        return stats

    # Collect files
    files = _collect_smali_files(smali_dirs)
    stats.files_scanned = len(files)

    if not files:
        stats.errors.append("No .smali files found in the given directories")
        return stats

    # Progress helper (safe import — works even outside agent context)
    try:
        from apk_agent.progress import report_progress as _rp
    except Exception:
        _rp = None

    def _report(pct: float, detail: str = "") -> None:
        if _rp:
            try:
                _rp(pct, detail)
            except Exception:
                pass

    _report(5, f"Scanning {len(files)} smali files…")

    # Phase 1: parallel scan to find matching files
    matched = _parallel_scan(files, patterns, max_workers=max_workers)
    stats.files_matched = len(matched)

    _report(40, f"Scan done — {len(matched)} files matched")

    if not matched:
        return stats

    # Pre-compile regexes once for the patch phase
    compiled = [p.compiled() for p in patterns]

    # Phase 2: apply patches (sequential for file safety)
    total_matched = len(matched)
    for idx, (file_path, content) in enumerate(matched):
        if idx % max(1, total_matched // 10) == 0:
            pct = 40 + (idx / total_matched) * 55  # 40-95%
            _report(pct, f"Patching {idx}/{total_matched} files…")
        results = _apply_patterns_to_file(
            file_path, patterns,
            backup_dir=backup_dir,
            preloaded_content=content,
            compiled_cache=compiled,
        )
        actual_patches = [r for r in results if "matches" in r]
        if actual_patches:
            stats.files_patched += 1
            stats.patterns_applied += sum(r.get("matches", 0) for r in actual_patches)
            stats.applied_details.extend(actual_patches)
            for r in actual_patches:
                stats.categories_hit.add(r["category"])
        errors = [r for r in results if "error" in r and "matches" not in r]
        for e in errors:
            stats.errors.append(f"{e.get('file', '?')}: {e.get('error', '?')}")

    _report(100, f"Done — {stats.patterns_applied} patches applied")
    return stats


# ---------------------------------------------------------------------------
# Flutter SSL binary patcher (pure Python — no r2pipe dependency)
# ---------------------------------------------------------------------------

# Hex signature bytes for ssl_verify_peer_cert across architectures
_FLUTTER_HEX_PATTERNS: dict[str, list[bytes]] = {
    "arm64": [
        bytes.fromhex("".join("F00F1CF8F05001A9F05002A9".split())),
        bytes.fromhex("".join("F04301D1FE6701A9F85F02A9F65703A9F44F04A9".split())),
    ],
    "arm": [
        bytes.fromhex("".join("2DE9F040D0F80080814698F81800D0F8".replace(" ", ""))),
    ],
    "x86_64": [
        bytes.fromhex("554157415641554154535049".replace(" ", "")),
    ],
}

# Return-zero patches per architecture
_FLUTTER_RET0: dict[str, bytes] = {
    "arm64": bytes.fromhex("E0031F2AC0035FD6"),  # mov w0, wzr; ret
    "arm": bytes.fromhex("0000A0E31EFF2FE1"),     # mov r0, #0; bx lr
    "x86_64": bytes.fromhex("31C0C3"),             # xor eax, eax; ret
}

_ARCH_MAP: dict[str, str] = {
    "arm64-v8a": "arm64",
    "armeabi-v7a": "arm",
    "armeabi": "arm",
    "x86_64": "x86_64",
    "x86": "x86_64",
}


def patch_flutter_ssl(apktool_dir: Path, backup_dir: Optional[Path] = None) -> dict:
    """Patch libflutter.so to disable SSL certificate verification.

    Uses pure Python hex pattern matching — no radare2 or r2pipe needed.
    Searches for ssl_verify_peer_cert function signature and patches it
    to return 0 (verification success).

    Returns dict with success status and details.
    """
    lib_dir = apktool_dir / "lib"
    if not lib_dir.is_dir():
        return {"success": False, "error": "No lib/ directory found — not a Flutter app or not decompiled"}

    # Find libflutter.so
    found_path: Optional[Path] = None
    found_arch: str = ""
    for arch_dir_name in ("arm64-v8a", "armeabi-v7a", "armeabi", "x86_64", "x86"):
        candidate = lib_dir / arch_dir_name / "libflutter.so"
        if candidate.is_file():
            found_path = candidate
            found_arch = _ARCH_MAP.get(arch_dir_name, "")
            break

    if not found_path:
        return {"success": False, "error": "libflutter.so not found in any architecture directory"}

    if found_arch not in _FLUTTER_HEX_PATTERNS:
        return {"success": False, "error": f"Unsupported architecture: {found_arch}"}

    # Read binary
    data = bytearray(found_path.read_bytes())
    original_data = bytes(data)

    # Search for the ssl_verify_peer_cert signature
    sig_patterns = _FLUTTER_HEX_PATTERNS[found_arch]
    ret0_patch = _FLUTTER_RET0[found_arch]

    offset = -1
    matched_sig = ""
    for sig in sig_patterns:
        idx = data.find(sig)
        if idx != -1:
            offset = idx
            matched_sig = sig.hex()
            break

    if offset == -1:
        return {
            "success": False,
            "error": "ssl_verify_peer_cert signature not found in libflutter.so",
            "architecture": found_arch,
            "lib_path": str(found_path),
            "hint": "The Flutter version may use a different signature pattern",
        }

    # Backup
    if backup_dir:
        bk = backup_dir / f"libflutter_{found_arch}.so.bak"
        bk.parent.mkdir(parents=True, exist_ok=True)
        bk.write_bytes(original_data)

    # Patch: overwrite function entry with ret0
    for i, b in enumerate(ret0_patch):
        data[offset + i] = b

    found_path.write_bytes(bytes(data))

    return {
        "success": True,
        "lib_path": str(found_path),
        "architecture": found_arch,
        "offset": f"0x{offset:x}",
        "signature": matched_sig[:32] + "...",
        "patch": "ssl_verify_peer_cert → return 0 (always succeed)",
    }


# ---------------------------------------------------------------------------
# Network Security Config injector
# ---------------------------------------------------------------------------

_NSC_TEMPLATE = """\
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">*</domain>
        <trust-anchors>
{cert_entries}
            <certificates src="system" overridePins="true" />
            <certificates src="user" overridePins="true" />
        </trust-anchors>
    </domain-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
{cert_entries}
            <certificates src="system" overridePins="true" />
            <certificates src="user" overridePins="true" />
        </trust-anchors>
    </base-config>
    <debug-overrides cleartextTrafficPermitted="true">
        <trust-anchors>
{cert_entries}
            <certificates src="system" overridePins="true" />
            <certificates src="user" overridePins="true" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>"""


def inject_nsc(apktool_dir: Path, cert_paths: list[str] | None = None) -> dict:
    """Inject a permissive network_security_config.xml and optional CA certs.

    Creates:
    - res/xml/network_security_config.xml  (trusts system+user certs, cleartext OK)
    - res/raw/custom_ca_N.pem              (copies provided cert files)

    Returns dict with success status and files created.
    """
    xml_dir = apktool_dir / "res" / "xml"
    xml_dir.mkdir(parents=True, exist_ok=True)
    raw_dir = apktool_dir / "res" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    files_created: list[str] = []
    cert_entries = ""

    if cert_paths:
        for idx, cert_path in enumerate(cert_paths, start=1):
            src = Path(cert_path)
            if not src.is_file():
                continue
            dest_name = f"custom_ca_{idx}.pem" if idx > 1 else "custom_ca.pem"
            dest = raw_dir / dest_name
            shutil.copy2(str(src), str(dest))
            files_created.append(str(dest))
            res_name = dest_name.rsplit(".", 1)[0]
            cert_entries += f'            <certificates src="@raw/{res_name}" overridePins="true" />\n'

    if not cert_entries:
        cert_entries = ""

    nsc_content = _NSC_TEMPLATE.replace("{cert_entries}", cert_entries.rstrip())
    nsc_path = xml_dir / "network_security_config.xml"
    if nsc_path.exists():
        nsc_path.chmod(nsc_path.stat().st_mode | stat.S_IWRITE)
    nsc_path.write_text(nsc_content, encoding="utf-8")
    files_created.append(str(nsc_path))

    return {
        "success": True,
        "files_created": files_created,
        "nsc_path": str(nsc_path),
        "features": [
            "cleartext traffic permitted (all domains)",
            "system certificates trusted with pin override",
            "user certificates trusted with pin override",
            "debug overrides enabled",
        ] + ([f"{len(cert_paths)} custom CA cert(s) installed"] if cert_paths else []),
    }


# ---------------------------------------------------------------------------
# Manifest security patcher
# ---------------------------------------------------------------------------


def patch_manifest(apktool_dir: Path) -> dict:
    """Patch AndroidManifest.xml for security bypass:
    - Remove split APK restrictions
    - Remove license check providers
    - Remove vending/stamp metadata
    - Inject usesCleartextTraffic=true
    - Inject networkSecurityConfig reference
    - Add storage permissions
    - Downgrade targetSdkVersion to 28
    - Add requestLegacyExternalStorage

    Returns dict with applied changes.
    """
    manifest_path = apktool_dir / "AndroidManifest.xml"
    if not manifest_path.is_file():
        return {"success": False, "error": "AndroidManifest.xml not found"}

    content = manifest_path.read_text(encoding="utf-8", errors="ignore")
    original = content
    changes: list[str] = []

    # 1. Remove split restrictions
    content, n = re.subn(
        r'\s+android:(?:splitTypes|requiredSplitTypes)="[^"]*?"', '', content
    )
    if n:
        changes.append(f"Removed split type attributes ({n})")

    content = re.sub(r'(isSplitRequired=)"true"', r'\1"false"', content)

    # 2. Remove vending/stamp/dynamic metadata
    content, n = re.subn(
        r'\s+<meta-data[^>]*"com\.android\.(?:vending\.|stamp\.|dynamic\.apk\.)[^"]*"[^>]*/>', '', content
    )
    if n:
        changes.append(f"Removed vending/stamp metadata ({n})")

    # 3. Remove license check providers
    content, n = re.subn(
        r'\s+<[^>]*"com\.(?:pairip\.licensecheck|android\.vending\.CHECK_LICENSE)[^"]*"[^>]*/>', '', content
    )
    if n:
        changes.append(f"Removed license check providers ({n})")

    # 4. Inject NSC + cleartext into <application> tag
    app_match = re.search(r'<application\s+[^>]*>', content)
    if app_match:
        app_tag = app_match.group(0)
        # Remove existing conflicting attrs
        cleaned = re.sub(
            r'\s+android:(?:usesCleartextTraffic|networkSecurityConfig)="[^"]*?"', '', app_tag
        )
        # Inject new attrs
        new_tag = cleaned.replace(
            '>',
            '\n        android:usesCleartextTraffic="true"'
            '\n        android:networkSecurityConfig="@xml/network_security_config">'
        )
        content = content.replace(app_tag, new_tag)
        changes.append("Injected usesCleartextTraffic=true")
        changes.append("Injected networkSecurityConfig reference")

        # Also inject requestLegacyExternalStorage
        cleaned2 = re.sub(
            r'\s+android:(?:request|preserve)LegacyExternalStorage="[^"]*?"', '', new_tag
        )
        final_tag = cleaned2.replace(
            '>',
            '\n        android:requestLegacyExternalStorage="true">'
        )
        content = content.replace(new_tag, final_tag)
        changes.append("Added requestLegacyExternalStorage=true")

    # 5. Downgrade targetSdkVersion
    content, n = re.subn(
        r'android:targetSdkVersion="\d+"', 'android:targetSdkVersion="28"', content
    )
    if n:
        changes.append("Downgraded targetSdkVersion to 28")

    # 6. Add storage permissions (remove existing first to avoid duplicates)
    content = re.sub(
        r'\s+<uses-permission[^>]*android:name="android\.permission\.(?:READ|WRITE|MANAGE)_EXTERNAL_STORAGE"[^>]*>',
        '', content
    )
    storage_perms = (
        '\n    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>'
        '\n    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>'
        '\n    <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>'
    )
    content = re.sub(r'(<manifest\s+[^>]*>)', r'\1' + storage_perms, content)
    changes.append("Added storage permissions (READ/WRITE/MANAGE)")

    if content != original:
        if manifest_path.exists():
            manifest_path.chmod(manifest_path.stat().st_mode | stat.S_IWRITE)
        manifest_path.write_text(content, encoding="utf-8")

    # 7. Also patch apktool.yml targetSdkVersion
    yml_path = apktool_dir / "apktool.yml"
    if yml_path.is_file():
        yml = yml_path.read_text(encoding="utf-8", errors="ignore")
        new_yml = re.sub(r'(targetSdkVersion:) \d+', r'\1 28', yml)
        if new_yml != yml:
            if yml_path.exists():
                yml_path.chmod(yml_path.stat().st_mode | stat.S_IWRITE)
            yml_path.write_text(new_yml, encoding="utf-8")
            changes.append("Updated apktool.yml targetSdkVersion to 28")

    return {
        "success": bool(changes),
        "manifest_path": str(manifest_path),
        "changes_applied": changes,
        "total_changes": len(changes),
    }


# ---------------------------------------------------------------------------
# List available bypass categories
# ---------------------------------------------------------------------------


def list_patch_categories() -> dict:
    """Return all available patch categories with pattern counts."""
    cats = {}
    for cat, pats in ALL_PATTERNS.items():
        cats[cat.value] = {
            "description": {
                PatchCategory.SSL_BYPASS: "SSL/TLS certificate pinning bypass (7 patterns)",
                PatchCategory.VPN_BYPASS: "VPN/proxy detection bypass",
                PatchCategory.MOCK_LOCATION: "Mock location detection bypass + installer spoof",
                PatchCategory.LICENSE_BYPASS: "Google Play LVL license check bypass",
                PatchCategory.PAIRIP_BYPASS: "Pairip integrity/signature verification bypass",
                PatchCategory.PURCHASE_BYPASS: "In-app purchase / premium status bypass",
                PatchCategory.SCREENSHOT_BYPASS: "FLAG_SECURE screenshot protection removal",
                PatchCategory.USB_DEBUG_BYPASS: "USB debugging / ADB detection bypass",
                PatchCategory.DEVICE_SPOOF: "Android device ID spoofing",
                PatchCategory.PACKAGE_SPOOF: "Package/tamper detection bypass (Xposed, Frida, System.exit)",
                PatchCategory.ADS_REMOVAL: "Ad network neutralization (40+ networks)",
            }.get(cat, cat.value),
            "pattern_count": len(pats),
            "patterns": [p.tag for p in pats],
        }
    return {"categories": cats, "total_patterns": sum(len(p) for p in ALL_PATTERNS.values())}
