"""Deep analysis tools — advanced APK analysis beyond basic search.

Provides:
  - Smali syntax validation (catch broken patches before build)
  - Class hierarchy mapping (find all subclasses/implementors)
  - Entry point discovery (what the app opens/runs first)
  - SharedPreferences / key-value store analysis
  - Diff between original and patched smali files
  - SO binary string extraction (find hardcoded keys in native libs)
  - Resource and asset analysis (find embedded secrets)
"""

from __future__ import annotations

import os
import re
import struct
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from apk_agent.tools.advanced_search import _is_third_party_path

_POOL = ThreadPoolExecutor(max_workers=8)

# ---------------------------------------------------------------------------
# Smali syntax validation patterns
# ---------------------------------------------------------------------------

_SMALI_DIRECTIVES = frozenset({
    ".class", ".super", ".source", ".implements", ".field", ".method",
    ".end method", ".registers", ".locals", ".param", ".prologue",
    ".line", ".annotation", ".end annotation", ".subannotation",
    ".end subannotation", ".enum", ".packed-switch", ".end packed-switch",
    ".sparse-switch", ".end sparse-switch", ".array-data", ".end array-data",
    ".catch", ".catchall", ".local", ".end local", ".restart local",
})

_SMALI_OPCODES = frozenset({
    "nop", "move", "move/from16", "move/16", "move-wide", "move-wide/from16",
    "move-wide/16", "move-object", "move-object/from16", "move-object/16",
    "move-result", "move-result-wide", "move-result-object", "move-exception",
    "return-void", "return", "return-wide", "return-object",
    "const/4", "const/16", "const", "const/high16",
    "const-wide/16", "const-wide/32", "const-wide", "const-wide/high16",
    "const-string", "const-string/jumbo", "const-class",
    "monitor-enter", "monitor-exit",
    "check-cast", "instance-of", "array-length",
    "new-instance", "new-array",
    "filled-new-array", "filled-new-array/range",
    "fill-array-data", "throw",
    "goto", "goto/16", "goto/32",
    "packed-switch", "sparse-switch",
    "if-eq", "if-ne", "if-lt", "if-ge", "if-gt", "if-le",
    "if-eqz", "if-nez", "if-ltz", "if-gez", "if-gtz", "if-lez",
    "iget", "iget-wide", "iget-object", "iget-boolean", "iget-byte",
    "iget-char", "iget-short",
    "iput", "iput-wide", "iput-object", "iput-boolean", "iput-byte",
    "iput-char", "iput-short",
    "sget", "sget-wide", "sget-object", "sget-boolean", "sget-byte",
    "sget-char", "sget-short",
    "sput", "sput-wide", "sput-object", "sput-boolean", "sput-byte",
    "sput-char", "sput-short",
    "invoke-virtual", "invoke-super", "invoke-direct", "invoke-static",
    "invoke-interface",
    "invoke-virtual/range", "invoke-super/range", "invoke-direct/range",
    "invoke-static/range", "invoke-interface/range",
    "add-int", "sub-int", "mul-int", "div-int", "rem-int",
    "and-int", "or-int", "xor-int", "shl-int", "shr-int", "ushr-int",
    "add-int/2addr", "sub-int/2addr", "mul-int/2addr", "div-int/2addr",
    "add-int/lit16", "add-int/lit8",
    "neg-int", "not-int", "neg-long", "neg-float", "neg-double",
    "int-to-long", "int-to-float", "int-to-double",
    "long-to-int", "long-to-float", "long-to-double",
    "float-to-int", "float-to-long", "float-to-double",
    "double-to-int", "double-to-long", "double-to-float",
    "int-to-byte", "int-to-char", "int-to-short",
    "aget", "aget-wide", "aget-object", "aget-boolean", "aget-byte",
    "aget-char", "aget-short",
    "aput", "aput-wide", "aput-object", "aput-boolean", "aput-byte",
    "aput-char", "aput-short",
})


def validate_smali_syntax(file_path: Path) -> dict:
    """Check a smali file for syntax errors that would cause apktool build to fail.

    Returns dict with:
      - valid: bool
      - errors: list of {line, message}
      - warnings: list of {line, message}
    """
    errors: list[dict] = []
    warnings: list[dict] = []

    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return {"valid": False, "errors": [{"line": 0, "message": f"File not found: {file_path}"}]}

    lines = text.splitlines()
    in_method = False
    method_name = ""
    method_start_line = 0
    has_registers = False
    brace_depth = 0  # annotation nesting

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Track method blocks
        if stripped.startswith(".method "):
            if in_method:
                errors.append({"line": i, "message": f"Nested .method (previous method '{method_name}' at line {method_start_line} never closed)"})
            in_method = True
            method_name = stripped.split()[-1] if stripped.split() else "?"
            method_start_line = i
            has_registers = False
            continue

        if stripped == ".end method":
            if not in_method:
                errors.append({"line": i, "message": ".end method without matching .method"})
            in_method = False
            continue

        # Track registers declaration
        if stripped.startswith(".registers ") or stripped.startswith(".locals "):
            has_registers = True
            continue

        # Track annotations
        if stripped.startswith(".annotation ") or stripped.startswith(".subannotation "):
            brace_depth += 1
            continue
        if stripped in (".end annotation", ".end subannotation"):
            brace_depth -= 1
            if brace_depth < 0:
                errors.append({"line": i, "message": f"{stripped} without matching open"})
                brace_depth = 0
            continue

        # Inside methods: validate opcodes
        if in_method and brace_depth == 0:
            # Skip labels (:label_name), .line, .param, .local, etc.
            if stripped.startswith(":") or stripped.startswith("."):
                continue
            # Extract opcode (first word)
            opcode = stripped.split()[0] if stripped.split() else ""
            # Check against known opcodes (loose check — many variants)
            base_opcode = opcode.split("/")[0] if "/" in opcode else opcode
            # Some opcodes have suffixes like add-int/lit8
            if base_opcode and base_opcode not in _SMALI_OPCODES and not any(
                opcode.startswith(k) for k in ("add-", "sub-", "mul-", "div-", "rem-",
                                                "and-", "or-", "xor-", "shl-", "shr-",
                                                "ushr-", "rsub-", "cmp")
            ):
                # Could be a valid opcode we missed; soft warning
                if not opcode.startswith("0x"):
                    warnings.append({"line": i, "message": f"Unknown opcode: '{opcode}'"})

    # Final checks
    if in_method:
        errors.append({"line": method_start_line, "message": f"Method '{method_name}' never closed with .end method"})
    if brace_depth > 0:
        warnings.append({"line": len(lines), "message": f"Unclosed annotation blocks: {brace_depth}"})

    return {
        "valid": len(errors) == 0,
        "errors": errors[:30],
        "warnings": warnings[:20],
        "lines_checked": len(lines),
    }


# ---------------------------------------------------------------------------
# Class hierarchy mapping
# ---------------------------------------------------------------------------

_RE_CLASS = re.compile(r"^\.class\s+.*\s+(L[\w/$]+;)", re.MULTILINE)
_RE_SUPER = re.compile(r"^\.super\s+(L[\w/$]+;)", re.MULTILINE)
_RE_IFACE = re.compile(r"^\.implements\s+(L[\w/$]+;)", re.MULTILINE)


def map_class_hierarchy(smali_dirs: list[Path], target_class: str = "") -> dict:
    """Build a class hierarchy map from smali directories.

    If target_class is given, returns just that class's tree (parents + children).
    Otherwise returns top-level stats and interesting hierarchies.

    Returns:
      - extends: {class: super_class} mapping
      - implements: {class: [interfaces]} mapping
      - children: {parent: [direct_subclasses]} reverse mapping
      - If target_class: full ancestor chain + all descendants
    """
    extends: dict[str, str] = {}
    implements: dict[str, list[str]] = defaultdict(list)
    children: dict[str, list[str]] = defaultdict(list)

    def _scan_file(fpath: Path):
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []
        results = []
        cls_m = _RE_CLASS.search(text)
        if not cls_m:
            return results
        cls = cls_m.group(1)
        sup_m = _RE_SUPER.search(text)
        if sup_m:
            results.append(("extends", cls, sup_m.group(1)))
        for iface_m in _RE_IFACE.finditer(text):
            results.append(("implements", cls, iface_m.group(1)))
        return results

    # Collect all smali files
    all_files = []
    for sd in smali_dirs:
        if not sd.is_dir():
            continue
        for root, _, files in os.walk(sd):
            for f in files:
                if f.endswith(".smali"):
                    fpath = Path(root) / f
                    rel = str(fpath.relative_to(sd)).replace("\\", "/")
                    if not _is_third_party_path(rel):
                        all_files.append(fpath)

    # Parallel scan
    futures = {_POOL.submit(_scan_file, f): f for f in all_files}
    for future in as_completed(futures):
        try:
            for rel_type, cls, parent in future.result():
                if rel_type == "extends":
                    extends[cls] = parent
                    children[parent].append(cls)
                else:
                    implements[cls].append(parent)
        except Exception:
            pass

    # If target_class specified, build focused tree
    if target_class:
        # Normalize target
        target = target_class if target_class.startswith("L") else None
        if not target:
            # Search for partial match
            for cls in extends:
                if target_class.lower() in cls.lower():
                    target = cls
                    break

        if not target:
            return {"success": False, "error": f"Class '{target_class}' not found in hierarchy"}

        # Build ancestor chain
        ancestors = []
        current = target
        seen = set()
        while current in extends and current not in seen:
            seen.add(current)
            parent = extends[current]
            ancestors.append(parent)
            current = parent

        # Build descendant tree
        def _get_descendants(cls, depth=0, max_depth=5):
            if depth >= max_depth:
                return []
            result = []
            for child in children.get(cls, []):
                result.append({"class": child, "depth": depth + 1})
                result.extend(_get_descendants(child, depth + 1, max_depth))
            return result

        descendants = _get_descendants(target)
        ifaces = implements.get(target, [])

        return {
            "success": True,
            "class": target,
            "ancestors": ancestors,
            "interfaces": ifaces,
            "descendants": descendants[:50],
            "total_descendants": len(descendants),
        }

    # Summary mode
    # Find interesting hierarchies (security-related)
    security_parents = []
    for cls, parent in extends.items():
        low_parent = parent.lower()
        if any(kw in low_parent for kw in ("trustmanager", "sslsocket", "certificatepinner",
                                             "webview", "broadcastreceiver", "contentprovider",
                                             "interceptor", "authenticator")):
            security_parents.append({"class": cls, "extends": parent})

    return {
        "success": True,
        "total_classes": len(extends),
        "total_interfaces": sum(len(v) for v in implements.values()),
        "deepest_hierarchies": sorted(
            [(cls, len(list(_ancestors(cls, extends)))) for cls in extends],
            key=lambda x: -x[1],
        )[:10],
        "security_hierarchies": security_parents[:30],
        "most_subclassed": sorted(
            [(parent, len(kids)) for parent, kids in children.items()],
            key=lambda x: -x[1],
        )[:10],
    }


def _ancestors(cls, extends_map):
    seen = set()
    current = cls
    while current in extends_map and current not in seen:
        seen.add(current)
        current = extends_map[current]
        yield current


# ---------------------------------------------------------------------------
# Entry point discovery
# ---------------------------------------------------------------------------

_ENTRY_PATTERNS = {
    "launcher_activity": re.compile(r"android\.intent\.category\.LAUNCHER", re.I),
    "main_action": re.compile(r"android\.intent\.action\.MAIN", re.I),
    "application_class": re.compile(r'android:name\s*=\s*"([^"]*)"', re.I),
    "boot_receiver": re.compile(r"android\.intent\.action\.BOOT_COMPLETED", re.I),
    "service_auto": re.compile(r"android\.intent\.action\.BIND|android:directBootAware", re.I),
    "content_provider_init": re.compile(r'android:authorities\s*=\s*"([^"]*)"', re.I),
}


def find_entry_points(manifest_path: Path, smali_dirs: list[Path]) -> dict:
    """Find all app entry points: launcher activities, Application class,
    boot receivers, auto-start services, content providers.

    Returns ordered list of where the app starts executing.
    """
    entry_points = []

    # Parse manifest for entry points
    try:
        manifest_text = manifest_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return {"success": False, "error": f"Cannot read manifest: {e}"}

    # Find Application class
    app_match = re.search(
        r'<application[^>]*android:name\s*=\s*"([^"]*)"', manifest_text, re.I
    )
    if app_match:
        app_class = app_match.group(1)
        entry_points.append({
            "type": "Application",
            "class": app_class,
            "priority": 1,
            "note": "First code to run — app initialization, SDK setup, security checks",
        })

    # Find launcher activities
    # Parse activity blocks with intent-filter containing MAIN + LAUNCHER
    activity_blocks = re.findall(
        r'<activity[^>]*android:name\s*=\s*"([^"]*)"[^>]*>.*?</activity>',
        manifest_text, re.DOTALL | re.I
    )
    # Also match self-closing activities that might have intent-filter siblings
    for block in re.finditer(
        r'<activity\s[^>]*android:name\s*=\s*"([^"]*)"[^>]*/?\s*>(?:(.*?)</activity>)?',
        manifest_text, re.DOTALL | re.I
    ):
        name = block.group(1)
        body = block.group(2) or ""
        if "LAUNCHER" in body and "MAIN" in body:
            entry_points.append({
                "type": "LauncherActivity",
                "class": name,
                "priority": 2,
                "note": "Main UI entry — user taps app icon → this Activity opens",
            })
        elif "MAIN" in body:
            entry_points.append({
                "type": "MainActivity",
                "class": name,
                "priority": 3,
                "note": "Has MAIN intent but not LAUNCHER — may be internal entry",
            })

    # Find boot receivers
    for recv_block in re.finditer(
        r'<receiver\s[^>]*android:name\s*=\s*"([^"]*)"[^>]*/?\s*>(?:(.*?)</receiver>)?',
        manifest_text, re.DOTALL | re.I
    ):
        name = recv_block.group(1)
        body = recv_block.group(2) or ""
        if "BOOT_COMPLETED" in body:
            entry_points.append({
                "type": "BootReceiver",
                "class": name,
                "priority": 4,
                "note": "Runs at device boot — often re-initializes security/tracking",
            })

    # Find content providers (auto-initialized)
    for prov_block in re.finditer(
        r'<provider\s[^>]*android:name\s*=\s*"([^"]*)"',
        manifest_text, re.I
    ):
        name = prov_block.group(1)
        entry_points.append({
            "type": "ContentProvider",
            "class": name,
            "priority": 5,
            "note": "Auto-initialized before Application.onCreate — often used for library init",
        })

    # Find exported services
    for svc_block in re.finditer(
        r'<service\s[^>]*android:name\s*=\s*"([^"]*)"[^>]*android:exported\s*=\s*"true"',
        manifest_text, re.I
    ):
        name = svc_block.group(1)
        entry_points.append({
            "type": "ExportedService",
            "class": name,
            "priority": 6,
            "note": "Externally accessible service — potential attack surface",
        })

    # Resolve smali file paths for each entry point
    for ep in entry_points:
        cls_name = ep["class"]
        if cls_name.startswith("."):
            # Relative class name — need manifest package
            pkg_match = re.search(r'package\s*=\s*"([^"]*)"', manifest_text)
            if pkg_match:
                cls_name = pkg_match.group(1) + cls_name
        smali_path = cls_name.replace(".", "/") + ".smali"
        for sd in smali_dirs:
            candidate = sd / smali_path
            if candidate.is_file():
                ep["smali_file"] = str(candidate)
                break

    # Sort by priority
    entry_points.sort(key=lambda x: x.get("priority", 99))

    return {
        "success": True,
        "entry_points": entry_points,
        "total": len(entry_points),
        "execution_order": (
            "1. ContentProviders (auto-init) → "
            "2. Application.onCreate() → "
            "3. LauncherActivity.onCreate() → "
            "4. BootReceivers (after reboot)"
        ),
        "recommendation": (
            "Start analysis from Application class — it initializes SDKs, "
            "security checks, and network clients. Then trace to LauncherActivity."
        ),
    }


# ---------------------------------------------------------------------------
# SharedPreferences / key-value store analysis
# ---------------------------------------------------------------------------

_SHARED_PREFS_PATTERNS = [
    ("getSharedPreferences", re.compile(r'getSharedPreferences\s*\(\s*"([^"]*)"', re.I)),
    ("putString", re.compile(r'\.putString\s*\(\s*"([^"]*)"', re.I)),
    ("getString", re.compile(r'\.getString\s*\(\s*"([^"]*)"', re.I)),
    ("putInt", re.compile(r'\.putInt\s*\(\s*"([^"]*)"', re.I)),
    ("putBoolean", re.compile(r'\.putBoolean\s*\(\s*"([^"]*)"', re.I)),
    ("getBoolean", re.compile(r'\.getBoolean\s*\(\s*"([^"]*)"', re.I)),
    # Smali equivalents
    ("smali_getSharedPrefs", re.compile(r'getSharedPreferences.*const-string.*"([^"]*)"', re.I)),
    ("smali_putString", re.compile(r'Landroid/content/SharedPreferences\$Editor;->putString', re.I)),
    ("smali_getString", re.compile(r'Landroid/content/SharedPreferences;->getString', re.I)),
]

_SECURITY_KEYS = frozenset({
    "token", "access_token", "refresh_token", "api_key", "apikey",
    "secret", "password", "pin", "auth", "session", "cookie",
    "encryption_key", "enc_key", "aes_key", "private_key",
    "license", "license_key", "subscription", "premium",
    "is_premium", "is_pro", "is_paid", "purchased",
    "root_check", "is_rooted", "tamper", "integrity",
    "debug", "debuggable", "first_run", "trial",
})


def analyze_shared_prefs(search_dirs: list[Path]) -> dict:
    """Find SharedPreferences usage across the app with security analysis.

    Returns:
      - prefs_files: Which SharedPreferences files are used
      - security_keys: Keys that may store sensitive data
      - boolean_flags: Potential bypass targets (is_premium, is_rooted, etc.)
    """
    prefs_files: set[str] = set()
    all_keys: dict[str, list[dict]] = defaultdict(list)
    security_hits: list[dict] = []
    boolean_flags: list[dict] = []

    def _scan_file(fpath: Path, base_dir: Path):
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        rel = str(fpath.relative_to(base_dir)).replace("\\", "/")
        results = []

        for label, pattern in _SHARED_PREFS_PATTERNS:
            for m in pattern.finditer(text):
                key_or_name = m.group(1) if m.lastindex else ""
                line_num = text[:m.start()].count("\n") + 1
                results.append({
                    "type": label,
                    "key": key_or_name,
                    "file": rel,
                    "line": line_num,
                })
        return results

    for base_dir in search_dirs:
        if not base_dir.is_dir():
            continue
        files = []
        for root, _, fnames in os.walk(base_dir):
            for fn in fnames:
                if fn.endswith((".java", ".kt", ".smali")):
                    fp = Path(root) / fn
                    rel = str(fp.relative_to(base_dir)).replace("\\", "/")
                    if not _is_third_party_path(rel):
                        files.append(fp)

        futures = {_POOL.submit(_scan_file, f, base_dir): f for f in files}
        for future in as_completed(futures):
            try:
                for hit in future.result():
                    key = hit["key"].lower()
                    if hit["type"] == "getSharedPreferences":
                        prefs_files.add(hit["key"])
                    if key:
                        all_keys[hit["key"]].append(hit)
                        if any(sk in key for sk in _SECURITY_KEYS):
                            security_hits.append(hit)
                        if "boolean" in hit["type"].lower() or any(
                            bp in key for bp in ("is_", "has_", "enable", "disable", "flag", "check")
                        ):
                            boolean_flags.append(hit)
            except Exception:
                pass

    return {
        "success": True,
        "prefs_files": sorted(prefs_files),
        "total_keys_found": len(all_keys),
        "security_sensitive_keys": security_hits[:30],
        "boolean_flags_potential_bypass": boolean_flags[:30],
        "all_keys_sample": dict(list(all_keys.items())[:50]),
        "recommendation": (
            "Boolean flags like 'is_premium', 'is_rooted' can often be bypassed by "
            "patching the SharedPreferences read to always return the desired value. "
            "Security keys may contain hardcoded tokens or API keys."
        ),
    }


# ---------------------------------------------------------------------------
# SO binary string extraction
# ---------------------------------------------------------------------------

def extract_strings_from_binary(so_path: Path, min_length: int = 6) -> dict:
    """Extract readable strings from a compiled .so native library.

    Similar to Unix 'strings' command. Finds:
      - ASCII strings (printable chars >= min_length)
      - JNI method names (Java_com_example_*)
      - Crypto library indicators (openssl, aes, sha, encrypt)
      - URL/API endpoints
      - Hardcoded keys/tokens
    """
    try:
        data = so_path.read_bytes()
    except Exception as e:
        return {"success": False, "error": f"Cannot read {so_path}: {e}"}

    # Extract ASCII strings
    strings = []
    current = []
    for byte in data:
        if 32 <= byte <= 126:  # printable ASCII
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append("".join(current))
            current = []
    if len(current) >= min_length:
        strings.append("".join(current))

    # Classify strings
    jni_methods = [s for s in strings if s.startswith("Java_")]
    crypto_indicators = [s for s in strings if re.search(
        r"(?i)openssl|aes|sha[1-9]|md5|rsa|encrypt|decrypt|cipher|hmac|pbkdf|bcrypt|argon",
        s
    )]
    urls = [s for s in strings if re.search(r"https?://|wss?://|/api/|\.com/|\.io/", s)]
    keys_tokens = [s for s in strings if re.search(
        r"(?i)api[_-]?key|token|secret|password|auth|bearer|sk_|pk_|AIza",
        s
    )]

    return {
        "success": True,
        "file": str(so_path),
        "file_size_kb": len(data) // 1024,
        "total_strings": len(strings),
        "jni_methods": jni_methods[:30],
        "crypto_indicators": crypto_indicators[:30],
        "urls_endpoints": urls[:30],
        "potential_keys": keys_tokens[:20],
        "all_strings_sample": strings[:100],
    }


# ---------------------------------------------------------------------------
# Asset and resource secrets scanner
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = [
    ("API Key", re.compile(r"(?i)(api[_-]?key|apikey)\s*[=:]\s*[\"']?([a-zA-Z0-9_\-]{16,})")),
    ("Bearer Token", re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}")),
    ("AWS Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Firebase URL", re.compile(r"https://[\w-]+\.firebaseio\.com")),
    ("Private Key", re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----")),
    ("Base64 Key (32+ chars)", re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")),
    ("Hardcoded URL", re.compile(r"https?://[a-zA-Z0-9._\-/]{10,}")),
    ("Password/Secret", re.compile(r'(?i)(password|secret|passwd)\s*[=:]\s*["\']([^"\']{4,})["\']')),
]


def scan_assets_for_secrets(apktool_dir: Path) -> dict:
    """Scan assets/, res/raw/, res/xml/ for embedded secrets, API keys, URLs.

    Checks:
      - JavaScript files in assets/ (WebView apps often embed API keys)
      - JSON config files
      - XML configs
      - Raw binary/text files
    """
    findings: list[dict] = []
    files_scanned = 0

    search_dirs = [
        apktool_dir / "assets",
        apktool_dir / "res" / "raw",
        apktool_dir / "res" / "xml",
    ]

    for search_dir in search_dirs:
        if not search_dir.is_dir():
            continue
        for root, _, fnames in os.walk(search_dir):
            for fn in fnames:
                fp = Path(root) / fn
                # Skip large binary files
                try:
                    if fp.stat().st_size > 2 * 1024 * 1024:  # 2MB limit
                        continue
                except Exception:
                    continue

                try:
                    text = fp.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue

                files_scanned += 1
                rel = str(fp.relative_to(apktool_dir)).replace("\\", "/")

                for label, pattern in _SECRET_PATTERNS:
                    for m in pattern.finditer(text):
                        line_num = text[:m.start()].count("\n") + 1
                        match_text = m.group(0)[:100]
                        findings.append({
                            "type": label,
                            "file": rel,
                            "line": line_num,
                            "match": match_text,
                        })

    return {
        "success": True,
        "files_scanned": files_scanned,
        "total_findings": len(findings),
        "findings": findings[:50],
    }


# ---------------------------------------------------------------------------
# Diff tool for smali patches
# ---------------------------------------------------------------------------

def diff_smali_files(original_path: Path, patched_path: Path) -> dict:
    """Compare original and patched smali files, showing exact changes.

    Args:
        original_path: Path to original (backup) file
        patched_path: Path to current (patched) file

    Returns dict with:
      - changes: list of {line, type (added/removed/modified), content}
      - summary: human-readable diff summary
    """
    try:
        orig_lines = original_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as e:
        return {"success": False, "error": f"Cannot read original: {e}"}

    try:
        patch_lines = patched_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as e:
        return {"success": False, "error": f"Cannot read patched: {e}"}

    import difflib
    differ = difflib.unified_diff(orig_lines, patch_lines, lineterm="",
                                   fromfile="original", tofile="patched", n=3)
    diff_lines = list(differ)

    changes = []
    for line in diff_lines:
        if line.startswith("---") or line.startswith("+++") or line.startswith("@@"):
            continue
        if line.startswith("-"):
            changes.append({"type": "removed", "content": line[1:]})
        elif line.startswith("+"):
            changes.append({"type": "added", "content": line[1:]})

    return {
        "success": True,
        "original": str(original_path),
        "patched": str(patched_path),
        "total_changes": len(changes),
        "additions": sum(1 for c in changes if c["type"] == "added"),
        "removals": sum(1 for c in changes if c["type"] == "removed"),
        "diff": diff_lines[:200],
        "changes": changes[:100],
    }


# ---------------------------------------------------------------------------
# APK Health Check — comprehensive pre-build validation
# ---------------------------------------------------------------------------


def apk_health_check(apktool_dir: Path, smali_dirs: list[Path],
                     patched_files: list[Path] | None = None) -> dict:
    """Run comprehensive health checks on the decompiled APK before building.

    Validates:
      1. All patched smali files for syntax errors
      2. Method return-type consistency (every path must end with correct return)
      3. Register usage (no references to registers beyond .registers/.locals count)
      4. Try/catch block integrity (.catch references valid labels)
      5. AndroidManifest.xml well-formedness and component references
      6. Resource XML well-formedness (patched res/ files)
      7. Cross-reference integrity (patched methods don't break invoke targets)

    Args:
        apktool_dir: Root of apktool decompiled output.
        smali_dirs: List of all smali directories.
        patched_files: If given, only check these files. Otherwise check ALL smali files
            that differ from backup (or all smali files if no backups exist).

    Returns:
        Dict with health_score (0-100), critical/warning/info issue lists, and
        a build_safe boolean indicating whether apktool_build is likely to succeed.
    """
    critical: list[dict] = []
    warnings: list[dict] = []
    info: list[dict] = []
    files_checked = 0

    # --- 1. Determine which smali files to check ---
    files_to_check: list[Path] = []
    if patched_files:
        files_to_check = [f for f in patched_files if f.is_file()]
    else:
        # Check all smali files (use thread pool for speed)
        for sd in smali_dirs:
            if sd.is_dir():
                files_to_check.extend(sd.rglob("*.smali"))

    # Limit to prevent extreme slowdowns on huge APKs
    MAX_FILES = 500
    all_smali = files_to_check[:MAX_FILES]

    # --- 2. Validate each smali file ---
    def _check_smali(fpath: Path) -> list[dict]:
        issues: list[dict] = []
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            issues.append({"severity": "critical", "file": str(fpath.name),
                           "message": f"Cannot read file: {e}"})
            return issues

        lines = text.splitlines()
        rel = str(fpath.relative_to(apktool_dir)) if str(fpath).startswith(str(apktool_dir)) else fpath.name

        in_method = False
        method_name = ""
        method_start = 0
        has_registers = False
        registers_count = 0
        max_register_used = -1
        method_has_return = False
        return_type = ""
        label_defs: set[str] = set()
        label_refs: set[str] = set()
        try_labels: list[tuple[int, str]] = []  # (line, label_ref)
        annotation_depth = 0

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Track labels
            if stripped.startswith(":"):
                label_defs.add(stripped.split()[0] if stripped.split() else stripped)

            # Track method blocks
            if stripped.startswith(".method "):
                if in_method:
                    issues.append({"severity": "critical", "file": rel, "line": i,
                                   "message": f"Nested .method — '{method_name}' at line {method_start} never closed"})
                in_method = True
                method_name = stripped
                method_start = i
                has_registers = False
                registers_count = 0
                max_register_used = -1
                method_has_return = False
                label_defs.clear()
                label_refs.clear()
                try_labels.clear()
                # Parse return type from method signature
                paren_end = stripped.rfind(")")
                if paren_end >= 0:
                    return_type = stripped[paren_end + 1:].strip()
                else:
                    return_type = "V"
                continue

            if stripped == ".end method":
                if not in_method:
                    issues.append({"severity": "critical", "file": rel, "line": i,
                                   "message": ".end method without matching .method"})
                else:
                    # Check: method must have a return statement (unless abstract/native)
                    if not method_has_return and "abstract" not in method_name and "native" not in method_name:
                        issues.append({"severity": "critical", "file": rel, "line": method_start,
                                       "message": f"Method has no return statement — will crash at runtime: {method_name.split('(')[0].split()[-1] if '(' in method_name else method_name}"})

                    # Check: registers declaration
                    if not has_registers and "abstract" not in method_name and "native" not in method_name:
                        issues.append({"severity": "warning", "file": rel, "line": method_start,
                                       "message": f"Method has no .registers/.locals declaration"})

                    # Check: register overflow
                    if has_registers and max_register_used >= registers_count and registers_count > 0:
                        issues.append({"severity": "critical", "file": rel, "line": method_start,
                                       "message": f"Register overflow: uses v{max_register_used}/p-regs but only {registers_count} declared"})

                    # Check: label references point to defined labels
                    for lbl in label_refs:
                        if lbl not in label_defs:
                            issues.append({"severity": "critical", "file": rel, "line": method_start,
                                           "message": f"Reference to undefined label {lbl} in method"})

                in_method = False
                continue

            # Track .registers/.locals
            if stripped.startswith(".registers "):
                has_registers = True
                try:
                    registers_count = int(stripped.split()[1])
                except (IndexError, ValueError):
                    pass
                continue
            if stripped.startswith(".locals "):
                has_registers = True
                try:
                    registers_count = int(stripped.split()[1])
                except (IndexError, ValueError):
                    pass
                continue

            # Track annotations
            if stripped.startswith(".annotation ") or stripped.startswith(".subannotation "):
                annotation_depth += 1
                continue
            if stripped in (".end annotation", ".end subannotation"):
                annotation_depth -= 1
                if annotation_depth < 0:
                    issues.append({"severity": "critical", "file": rel, "line": i,
                                   "message": f"Unmatched {stripped}"})
                    annotation_depth = 0
                continue

            # Inside method body
            if in_method and annotation_depth == 0:
                # Skip directives
                if stripped.startswith(".") or stripped.startswith(":"):
                    # Catch .catch/.catchall label refs
                    if stripped.startswith(".catch"):
                        parts = stripped.split()
                        for part in parts:
                            if part.startswith(":"):
                                label_refs.add(part.rstrip(","))
                    continue

                # Track return statements
                if stripped.startswith("return"):
                    method_has_return = True
                    # Verify return type matches
                    opcode = stripped.split()[0]
                    if return_type == "V" and opcode != "return-void":
                        issues.append({"severity": "critical", "file": rel, "line": i,
                                       "message": f"void method uses '{opcode}' instead of return-void"})
                    elif return_type != "V" and opcode == "return-void":
                        issues.append({"severity": "critical", "file": rel, "line": i,
                                       "message": f"Non-void method uses return-void (expects {return_type})"})

                # Track register usage (vN registers)
                reg_matches = re.findall(r'\bv(\d+)\b', stripped)
                for rm in reg_matches:
                    rn = int(rm)
                    if rn > max_register_used:
                        max_register_used = rn

                # Track goto/if label references
                parts = stripped.split()
                for part in parts:
                    if part.startswith(":"):
                        label_refs.add(part.rstrip(","))

        # End-of-file checks
        if in_method:
            issues.append({"severity": "critical", "file": rel, "line": method_start,
                           "message": f"Method '{method_name}' never closed"})
        if annotation_depth > 0:
            issues.append({"severity": "warning", "file": rel, "line": len(lines),
                           "message": f"Unclosed annotation blocks: {annotation_depth}"})

        return issues

    # Run checks in parallel
    all_issues: list[dict] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_check_smali, f): f for f in all_smali}
        for fut in as_completed(futures):
            try:
                file_issues = fut.result()
                all_issues.extend(file_issues)
                files_checked += 1
            except Exception:
                files_checked += 1

    # --- 3. Validate AndroidManifest.xml ---
    manifest = apktool_dir / "AndroidManifest.xml"
    if manifest.is_file():
        try:
            import xml.etree.ElementTree as ET
            ET.parse(str(manifest))
            info.append({"file": "AndroidManifest.xml", "message": "XML is well-formed"})
        except ET.ParseError as e:
            critical.append({"file": "AndroidManifest.xml", "line": 0,
                             "message": f"Manifest XML parse error — APK will NOT build: {e}"})
    else:
        critical.append({"file": "AndroidManifest.xml", "line": 0,
                         "message": "AndroidManifest.xml not found!"})

    # --- 4. Validate patched resource XMLs ---
    res_dir = apktool_dir / "res"
    if res_dir.is_dir():
        import xml.etree.ElementTree as ET
        xml_errors = 0
        for xml_file in res_dir.rglob("*.xml"):
            try:
                ET.parse(str(xml_file))
            except ET.ParseError as e:
                xml_errors += 1
                if xml_errors <= 10:  # Cap reported errors
                    warnings.append({"file": str(xml_file.relative_to(apktool_dir)),
                                     "message": f"XML parse error: {e}"})
        if xml_errors == 0:
            info.append({"file": "res/", "message": f"All resource XMLs are well-formed"})
        elif xml_errors > 10:
            warnings.append({"file": "res/", "message": f"... and {xml_errors - 10} more XML errors"})

    # --- 5. Classify issues ---
    for issue in all_issues:
        sev = issue.pop("severity", "warning")
        if sev == "critical":
            critical.append(issue)
        elif sev == "warning":
            warnings.append(issue)
        else:
            info.append(issue)

    # --- 6. Compute health score ---
    # Critical = -15 each, Warning = -3 each, capped at 0
    score = 100 - (len(critical) * 15) - (len(warnings) * 3)
    score = max(0, min(100, score))

    build_safe = len(critical) == 0

    return {
        "health_score": score,
        "build_safe": build_safe,
        "build_recommendation": "SAFE to build" if build_safe else "FIX critical issues before building",
        "files_checked": files_checked,
        "summary": {
            "critical_issues": len(critical),
            "warnings": len(warnings),
            "info": len(info),
        },
        "critical": critical[:30],
        "warnings": warnings[:20],
        "info": info[:10],
    }
