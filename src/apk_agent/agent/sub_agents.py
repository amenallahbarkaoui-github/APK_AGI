"""Sub-agent definitions for the Orchestrator mode.

Each sub-agent is a specialized LangGraph agent with a focused tool set
and dedicated system prompt for its domain.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SubAgentDef:
    """Definition of a sub-agent with its role, tools, and prompt."""
    name: str
    role: str
    description: str
    tool_names: list[str]
    system_prompt_extra: str = ""
    max_iterations: int = 15


# ---------------------------------------------------------------------------
# Sub-agent catalog
# ---------------------------------------------------------------------------

RECON_AGENT = SubAgentDef(
    name="recon",
    role="Reconnaissance Agent",
    description="Performs quick APK reconnaissance: metadata, permissions, strings, manifest analysis",
    tool_names=[
        "aapt2_dump",
        "extract_strings",
        "parse_manifest",
        "apktool_decompile",
        "jadx_decompile",
        "list_files",
        "directory_overview",
        "read_file",
    ],
    system_prompt_extra="""You are a specialized reconnaissance agent. Your job is to quickly gather 
all available metadata about the APK:
1. Run aapt2_dump to get package info, SDK versions, permissions, components
2. Run extract_strings to find URLs, API keys, secrets
3. After decompilation, parse_manifest for exported components and dangerous permissions
4. Use directory_overview to understand the app structure
5. Report all findings in a structured format.

Be thorough but fast. Focus on gathering data, not deep analysis.""",
    max_iterations=5,
)

VULN_SCAN_AGENT = SubAgentDef(
    name="vuln_scanner",
    role="Vulnerability Scanner Agent",
    description="Scans for security vulnerabilities: SSL, crypto, storage, WebView, IPC issues",
    tool_names=[
        "scan_vulnerabilities",
        "list_vuln_patterns",
        "search_in_code",
        "context_search",
        "multi_search",
        "read_file",
        "analyze_smali_class",
        "find_method_xrefs",
        "scan_smali_classes",
        "list_files",
    ],
    system_prompt_extra="""You are a specialized vulnerability scanner agent. Your job is to find 
ALL security issues in the decompiled APK:
1. Run scan_vulnerabilities on both jadx and smali directories
2. Use list_vuln_patterns to know what you can detect
3. For each HIGH/CRITICAL finding, use context_search to get surrounding code
4. Use find_method_xrefs to trace security-critical call chains
5. Cross-reference findings between Java source and smali
6. Report findings with severity, evidence, and file locations.

Be thorough. Check EVERY category. Don't stop after finding a few issues.""",
    max_iterations=8,
)

CRYPTO_AGENT = SubAgentDef(
    name="crypto_analyst",
    role="Cryptography Analyst Agent",
    description="Deep analysis of cryptographic implementations: key management, algorithms, SSL/TLS",
    tool_names=[
        "search_in_code",
        "context_search",
        "multi_search",
        "read_file",
        "analyze_smali_class",
        "find_string_decryption_patterns",
        "find_method_xrefs",
        "scan_smali_classes",
        "xref_search",
    ],
    system_prompt_extra="""You are a cryptography analysis expert. Deeply analyze all crypto usage:
1. Search for all Cipher, KeyGenerator, KeyStore, SecretKeySpec, MessageDigest usage
2. Trace key derivation chains — where do keys come from?
3. Check for ECB mode, static IVs, weak hashes (MD5/SHA1)
4. Look for SSL pinning implementations and trust manager customizations
5. Find string encryption/decryption patterns
6. Analyze obfuscated crypto code
7. Report each finding with the full code context and risk assessment.""",
    max_iterations=7,
)

PATCHER_AGENT = SubAgentDef(
    name="patcher",
    role="Smali Patcher Agent",
    description="Creates and applies precise smali patches for SSL bypass, root detection removal, etc.",
    tool_names=[
        "read_file",
        "write_file",
        "search_in_code",
        "context_search",
        "analyze_smali_class",
        "find_method_xrefs",
        "preview_smali_patch",
        "apply_smali_patch",
        "apktool_build",
        "zipalign_apk_tool",
        "sign_apk",
        "list_files",
    ],
    system_prompt_extra="""You are a smali patching expert. Your job is to create precise patches:
1. Study the Java source to understand the logic
2. Find the corresponding smali file  
3. Create a targeted patch plan
4. ALWAYS use preview_smali_patch first to verify
5. Apply the patch only after preview looks correct
6. After all patches, rebuild and sign the APK
7. Report what was patched and why.

Be extremely precise with smali patterns. Smali is whitespace-sensitive.""",
    max_iterations=10,
)

REPORT_AGENT = SubAgentDef(
    name="reporter",
    role="Report Generator Agent",
    description="Consolidates all findings into a comprehensive security report",
    tool_names=[
        "generate_report",
        "read_file",
        "list_files",
    ],
    system_prompt_extra="""You are a security report expert. Compile all findings into a report:
1. Gather findings from the consolidated results
2. Organize by severity and category
3. Generate a comprehensive Markdown report
4. Include evidence, remediation advice, and risk scores.""",
    max_iterations=3,
)


SUB_AGENT_CATALOG: dict[str, SubAgentDef] = {
    "recon": RECON_AGENT,
    "vuln_scanner": VULN_SCAN_AGENT,
    "crypto_analyst": CRYPTO_AGENT,
    "patcher": PATCHER_AGENT,
    "reporter": REPORT_AGENT,
}
