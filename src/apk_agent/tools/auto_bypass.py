"""Auto-Bypass Engine — generates smali patches and Frida scripts for detected protections.

For each detected protection/finding, produces:
  1. Bypass difficulty score (1-10)
  2. Ready-to-apply smali patch (compatible with PatchEngine)
  3. Ready-to-run Frida hook script
  4. Call chain from detection → enforcement

Works on SmaliIndex IR + unified_scanner Findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apk_agent.tools.smali_ir import SmaliIndex, SmaliMethod, SmaliClass
    from apk_agent.tools.unified_scanner import Finding


# ---------------------------------------------------------------------------
# Bypass result model
# ---------------------------------------------------------------------------

@dataclass
class BypassPlan:
    """Complete bypass plan for a detected protection."""
    protection_type: str        # "root_detection", "ssl_pinning", etc.
    target_method: str          # full smali signature
    target_class: str
    target_file: str            # relative path to smali file
    bypass_difficulty: int      # 1-10
    # Smali patch
    smali_patch: dict           # PatchEngine-compatible plan
    # Frida hook
    frida_script: str
    # Context
    description: str
    call_chain: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Bypass generators by protection type
# ---------------------------------------------------------------------------

def generate_bypasses(
    index: "SmaliIndex",
    findings: list[dict],
    max_bypasses: int = 50,
) -> dict:
    """Generate bypass plans for all auto-patchable findings.

    Args:
        index: SmaliIndex for looking up method bodies.
        findings: List of finding dicts from unified_scanner.scan().
        max_bypasses: Maximum bypasses to generate.

    Returns:
        Dict with: bypasses (list of BypassPlan dicts), summary.
    """
    bypasses: list[dict] = []

    for finding in findings:
        if not finding.get("auto_patchable"):
            continue
        if len(bypasses) >= max_bypasses:
            break

        rule_id = finding.get("rule_id", "")
        method_sig = finding.get("method", "")
        class_name = finding.get("class", "")

        method = index.get_method(method_sig) if method_sig else None
        cls = index.get_class(class_name) if class_name else None

        bp = _generate_bypass(rule_id, finding, method, cls, index)
        if bp:
            bypasses.append(_bypass_to_dict(bp))

    # Summary
    types: dict[str, int] = {}
    for bp in bypasses:
        t = bp.get("protection_type", "unknown")
        types[t] = types.get(t, 0) + 1

    return {
        "success": True,
        "total_bypasses": len(bypasses),
        "by_type": types,
        "bypasses": bypasses,
    }


def _generate_bypass(
    rule_id: str,
    finding: dict,
    method: "SmaliMethod | None",
    cls: "SmaliClass | None",
    index: "SmaliIndex",
) -> BypassPlan | None:
    """Generate a bypass plan based on the rule type."""
    generators = {
        "ROOT-001": _bypass_root_detection,
        "ROOT-002": _bypass_emulator_detection,
        "ROOT-003": _bypass_safetynet,
        "DEBUG-001": _bypass_debug_detection,
        "TAMPER-001": _bypass_signature_check,
        "SSL-001": _bypass_trust_manager,
        "SSL-002": _bypass_hostname_verifier,
        "SSL-003": _bypass_cert_pinning,
    }

    gen_fn = generators.get(rule_id)
    if gen_fn and method and cls:
        return gen_fn(finding, method, cls, index)
    return None


# ---------------------------------------------------------------------------
# Root detection bypass
# ---------------------------------------------------------------------------

def _bypass_root_detection(
    finding: dict, method: "SmaliMethod", cls: "SmaliClass",
    index: "SmaliIndex",
) -> BypassPlan:
    """Bypass root detection by patching method to return false."""
    # Find methods that return boolean and contain root detection strings
    target_methods = _find_boolean_methods_with_pattern(
        cls, ["isRooted", "checkRoot", "isDeviceRooted", "/system/xbin/su",
               "/sbin/su", "Superuser", "magisk", "supersu"],
    )

    if not target_methods:
        target_methods = [method]

    patches = []
    frida_hooks = []

    for tm in target_methods[:5]:
        # Smali patch: replace method body with `return 0` (false)
        patch = _make_return_false_patch(tm, cls)
        patches.append(patch)

        # Frida hook
        frida = _make_frida_return_false(tm, cls)
        frida_hooks.append(frida)

    return BypassPlan(
        protection_type="root_detection",
        target_method=method.full_signature,
        target_class=cls.name,
        target_file=cls.file_path,
        bypass_difficulty=2,
        smali_patch=_combine_patches("Root detection bypass", patches),
        frida_script="\n\n".join(frida_hooks),
        description=f"Root detection in {cls.name} — patch {len(target_methods)} methods to return false",
        call_chain=[m.full_signature for m in target_methods],
    )


# ---------------------------------------------------------------------------
# Emulator detection bypass
# ---------------------------------------------------------------------------

def _bypass_emulator_detection(
    finding: dict, method: "SmaliMethod", cls: "SmaliClass",
    index: "SmaliIndex",
) -> BypassPlan:
    target_methods = _find_boolean_methods_with_pattern(
        cls, ["isEmulator", "checkEmulator", "goldfish", "sdk_gphone",
               "Genymotion", "BlueStacks"],
    )
    if not target_methods:
        target_methods = [method]

    patches = []
    frida_hooks = []
    for tm in target_methods[:5]:
        patches.append(_make_return_false_patch(tm, cls))
        frida_hooks.append(_make_frida_return_false(tm, cls))

    return BypassPlan(
        protection_type="emulator_detection",
        target_method=method.full_signature,
        target_class=cls.name,
        target_file=cls.file_path,
        bypass_difficulty=2,
        smali_patch=_combine_patches("Emulator detection bypass", patches),
        frida_script="\n\n".join(frida_hooks),
        description=f"Emulator detection in {cls.name}",
    )


# ---------------------------------------------------------------------------
# Debug detection bypass
# ---------------------------------------------------------------------------

def _bypass_debug_detection(
    finding: dict, method: "SmaliMethod", cls: "SmaliClass",
    index: "SmaliIndex",
) -> BypassPlan:
    patches = [_make_return_false_patch(method, cls)]
    frida_hooks = [_make_frida_return_false(method, cls)]

    # Also hook Debug.isDebuggerConnected
    frida_hooks.append(
        'Java.perform(function() {\n'
        '    var Debug = Java.use("android.os.Debug");\n'
        '    Debug.isDebuggerConnected.implementation = function() {\n'
        '        console.log("[*] Debug.isDebuggerConnected() -> false");\n'
        '        return false;\n'
        '    };\n'
        '});'
    )

    return BypassPlan(
        protection_type="anti_debug",
        target_method=method.full_signature,
        target_class=cls.name,
        target_file=cls.file_path,
        bypass_difficulty=3,
        smali_patch=_combine_patches("Anti-debug bypass", patches),
        frida_script="\n\n".join(frida_hooks),
        description=f"Anti-debug detection in {cls.name}",
    )


# ---------------------------------------------------------------------------
# Signature / tamper check bypass
# ---------------------------------------------------------------------------

def _bypass_signature_check(
    finding: dict, method: "SmaliMethod", cls: "SmaliClass",
    index: "SmaliIndex",
) -> BypassPlan:
    patches = [_make_return_true_patch(method, cls)]
    frida_hooks = [_make_frida_return_true(method, cls)]

    return BypassPlan(
        protection_type="anti_tamper",
        target_method=method.full_signature,
        target_class=cls.name,
        target_file=cls.file_path,
        bypass_difficulty=5,
        smali_patch=_combine_patches("Signature verification bypass", patches),
        frida_script="\n\n".join(frida_hooks),
        description=f"Signature verification in {cls.name}",
    )


# ---------------------------------------------------------------------------
# SSL/TLS bypasses
# ---------------------------------------------------------------------------

def _bypass_trust_manager(
    finding: dict, method: "SmaliMethod", cls: "SmaliClass",
    index: "SmaliIndex",
) -> BypassPlan:
    # For TrustManager: make checkServerTrusted a no-op
    check_methods = [m for m in cls.methods if "checkServerTrusted" in m.name]
    if not check_methods:
        check_methods = [method]

    patches = []
    for m in check_methods:
        patches.append(_make_return_void_patch(m, cls))

    frida_script = (
        'Java.perform(function() {\n'
        '    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");\n'
        '    var SSLContext = Java.use("javax.net.ssl.SSLContext");\n'
        '    var TrustManager = Java.registerClass({\n'
        '        name: "com.bypass.TrustManager",\n'
        '        implements: [X509TrustManager],\n'
        '        methods: {\n'
        '            checkClientTrusted: function(chain, authType) {},\n'
        '            checkServerTrusted: function(chain, authType) {},\n'
        '            getAcceptedIssuers: function() { return []; }\n'
        '        }\n'
        '    });\n'
        '    var TrustManagers = [TrustManager.$new()];\n'
        '    var sslContext = SSLContext.getInstance("TLS");\n'
        '    sslContext.init(null, TrustManagers, null);\n'
        '    console.log("[*] SSL TrustManager bypassed");\n'
        '});'
    )

    return BypassPlan(
        protection_type="ssl_trust_manager",
        target_method=method.full_signature,
        target_class=cls.name,
        target_file=cls.file_path,
        bypass_difficulty=3,
        smali_patch=_combine_patches("SSL TrustManager bypass", patches),
        frida_script=frida_script,
        description=f"SSL TrustManager bypass in {cls.name}",
    )


def _bypass_hostname_verifier(
    finding: dict, method: "SmaliMethod", cls: "SmaliClass",
    index: "SmaliIndex",
) -> BypassPlan:
    verify_methods = [m for m in cls.methods if "verify" in m.name]
    if not verify_methods:
        verify_methods = [method]

    patches = [_make_return_true_patch(m, cls) for m in verify_methods]

    frida_script = (
        'Java.perform(function() {\n'
        '    var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");\n'
        '    var HV = Java.registerClass({\n'
        '        name: "com.bypass.HostnameVerifier",\n'
        '        implements: [HostnameVerifier],\n'
        '        methods: {\n'
        '            verify: function(hostname, session) {\n'
        '                console.log("[*] HostnameVerifier.verify(" + hostname + ") -> true");\n'
        '                return true;\n'
        '            }\n'
        '        }\n'
        '    });\n'
        '    console.log("[*] HostnameVerifier bypassed");\n'
        '});'
    )

    return BypassPlan(
        protection_type="ssl_hostname_verifier",
        target_method=method.full_signature,
        target_class=cls.name,
        target_file=cls.file_path,
        bypass_difficulty=2,
        smali_patch=_combine_patches("HostnameVerifier bypass", patches),
        frida_script=frida_script,
        description=f"HostnameVerifier bypass in {cls.name}",
    )


def _bypass_cert_pinning(
    finding: dict, method: "SmaliMethod", cls: "SmaliClass",
    index: "SmaliIndex",
) -> BypassPlan:
    # OkHttp CertificatePinner bypass
    check_methods = [m for m in cls.methods if m.name == "check"]
    if not check_methods:
        check_methods = [method]

    patches = [_make_return_void_patch(m, cls) for m in check_methods]

    frida_script = (
        'Java.perform(function() {\n'
        '    // OkHttp3 CertificatePinner bypass\n'
        '    try {\n'
        '        var CertificatePinner = Java.use("okhttp3.CertificatePinner");\n'
        '        CertificatePinner.check.overload("java.lang.String", "java.util.List")\n'
        '            .implementation = function(hostname, peerCertificates) {\n'
        '                console.log("[*] CertificatePinner.check(" + hostname + ") bypassed");\n'
        '            };\n'
        '    } catch(e) {\n'
        '        console.log("[!] OkHttp3 CertificatePinner not found: " + e);\n'
        '    }\n'
        '\n'
        '    // TrustManagerImpl bypass (Android 7+)\n'
        '    try {\n'
        '        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");\n'
        '        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain,\n'
        '                host, clientAuth, ocspData, tlsSctData) {\n'
        '            console.log("[*] TrustManagerImpl.verifyChain() bypassed for: " + host);\n'
        '            return untrustedChain;\n'
        '        };\n'
        '    } catch(e) {\n'
        '        console.log("[!] TrustManagerImpl not found: " + e);\n'
        '    }\n'
        '});'
    )

    return BypassPlan(
        protection_type="ssl_pinning",
        target_method=method.full_signature,
        target_class=cls.name,
        target_file=cls.file_path,
        bypass_difficulty=4,
        smali_patch=_combine_patches("Certificate pinning bypass", patches),
        frida_script=frida_script,
        description=f"Certificate pinning bypass in {cls.name}",
    )


# ---------------------------------------------------------------------------
# SafetyNet bypass
# ---------------------------------------------------------------------------

def _bypass_safetynet(
    finding: dict, method: "SmaliMethod", cls: "SmaliClass",
    index: "SmaliIndex",
) -> BypassPlan:
    frida_script = (
        'Java.perform(function() {\n'
        '    // SafetyNet bypass — hook the attestation callback\n'
        '    try {\n'
        '        var SafetyNetApi = Java.use("com.google.android.gms.safetynet.SafetyNetApi");\n'
        '        console.log("[*] SafetyNet API found — use Magisk DenyList for proper bypass");\n'
        '    } catch(e) {\n'
        '        console.log("[!] SafetyNet not found: " + e);\n'
        '    }\n'
        '\n'
        '    // Play Integrity bypass\n'
        '    try {\n'
        '        var IntegrityManager = Java.use("com.google.android.play.core.integrity.IntegrityManager");\n'
        '        console.log("[*] Play Integrity API found — server-side check may still fail");\n'
        '    } catch(e) {\n'
        '        console.log("[!] Play Integrity not found: " + e);\n'
        '    }\n'
        '});'
    )

    return BypassPlan(
        protection_type="safetynet",
        target_method=method.full_signature,
        target_class=cls.name,
        target_file=cls.file_path,
        bypass_difficulty=8,
        smali_patch=_combine_patches("SafetyNet bypass (limited)", []),
        frida_script=frida_script,
        description="SafetyNet/Play Integrity — Frida hook provided but server-side validation may still fail",
    )


# ---------------------------------------------------------------------------
# Patch generation helpers
# ---------------------------------------------------------------------------

def _find_boolean_methods_with_pattern(
    cls: "SmaliClass", patterns: list[str],
) -> list["SmaliMethod"]:
    """Find methods in a class that return boolean and match any pattern."""
    results = []
    for method in cls.methods:
        if method.return_type != "Z":
            continue
        # Check if method name or string constants match any pattern
        for pat in patterns:
            if pat.lower() in method.name.lower():
                results.append(method)
                break
            for s in method.string_constants:
                if pat.lower() in s.lower():
                    results.append(method)
                    break
            else:
                continue
            break
    return results


def _make_return_false_patch(method: "SmaliMethod", cls: "SmaliClass") -> dict:
    """Generate smali patch that replaces method body with `return 0`."""
    return {
        "file": cls.abs_path or cls.file_path,
        "operation": "replace_method_body",
        "method_signature": method.signature,
        "original_start_line": method.start_line,
        "original_end_line": method.end_line,
        "new_body": (
            f".method {' '.join(sorted(method.access_flags))} {method.signature}\n"
            f"    .registers 1\n"
            f"\n"
            f"    const/4 v0, 0x0\n"
            f"    return v0\n"
            f".end method"
        ),
    }


def _make_return_true_patch(method: "SmaliMethod", cls: "SmaliClass") -> dict:
    """Generate smali patch that replaces method body with `return 1`."""
    return {
        "file": cls.abs_path or cls.file_path,
        "operation": "replace_method_body",
        "method_signature": method.signature,
        "original_start_line": method.start_line,
        "original_end_line": method.end_line,
        "new_body": (
            f".method {' '.join(sorted(method.access_flags))} {method.signature}\n"
            f"    .registers 1\n"
            f"\n"
            f"    const/4 v0, 0x1\n"
            f"    return v0\n"
            f".end method"
        ),
    }


def _make_return_void_patch(method: "SmaliMethod", cls: "SmaliClass") -> dict:
    """Generate smali patch that replaces method body with `return-void`."""
    return {
        "file": cls.abs_path or cls.file_path,
        "operation": "replace_method_body",
        "method_signature": method.signature,
        "original_start_line": method.start_line,
        "original_end_line": method.end_line,
        "new_body": (
            f".method {' '.join(sorted(method.access_flags))} {method.signature}\n"
            f"    .registers 0\n"
            f"\n"
            f"    return-void\n"
            f".end method"
        ),
    }


def _combine_patches(description: str, patches: list[dict]) -> dict:
    """Combine multiple patches into a PatchEngine-compatible plan."""
    return {
        "description": description,
        "patch_count": len(patches),
        "patches": patches,
    }


def _make_frida_return_false(method: "SmaliMethod", cls: "SmaliClass") -> str:
    """Generate Frida hook that makes a method return false."""
    java_class = cls.name.strip("L;").replace("/", ".")
    return (
        f'Java.perform(function() {{\n'
        f'    var cls = Java.use("{java_class}");\n'
        f'    cls.{method.name}.implementation = function() {{\n'
        f'        console.log("[*] {java_class}.{method.name}() -> false");\n'
        f'        return false;\n'
        f'    }};\n'
        f'}});'
    )


def _make_frida_return_true(method: "SmaliMethod", cls: "SmaliClass") -> str:
    """Generate Frida hook that makes a method return true."""
    java_class = cls.name.strip("L;").replace("/", ".")
    return (
        f'Java.perform(function() {{\n'
        f'    var cls = Java.use("{java_class}");\n'
        f'    cls.{method.name}.implementation = function() {{\n'
        f'        console.log("[*] {java_class}.{method.name}() -> true");\n'
        f'        return true;\n'
        f'    }};\n'
        f'}});'
    )


def _bypass_to_dict(bp: BypassPlan) -> dict:
    return {
        "protection_type": bp.protection_type,
        "target_method": bp.target_method,
        "target_class": bp.target_class,
        "target_file": bp.target_file,
        "bypass_difficulty": bp.bypass_difficulty,
        "description": bp.description,
        "smali_patch": bp.smali_patch,
        "frida_script": bp.frida_script,
        "call_chain": bp.call_chain,
    }
