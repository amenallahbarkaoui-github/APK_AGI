<p align="center">
  <img src="https://img.shields.io/badge/APK_AGI-v2.0.0-blueviolet?style=for-the-badge&logo=android" alt="Version"/>
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/LangGraph-Agentic_AI-00C853?style=for-the-badge" alt="LangGraph"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License"/>
</p>

<h1 align="center">🧠 APK AGI</h1>

<h3 align="center">
  AI-Powered Autonomous Android Reverse-Engineering Agent
</h3>

<p align="center">
  <em>
    A fully autonomous agentic system that decompiles, analyzes, patches, rebuilds & signs Android APKs — driven entirely by natural language.
  </em>
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#%EF%B8%8F-architecture">Architecture</a> •
  <a href="#-tool-arsenal">Tools</a> •
  <a href="#-getting-started">Getting Started</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-credits--attribution">Credits</a>
</p>

---

## 🎯 What is APK AGI?

**APK AGI** is a state-of-the-art autonomous agent that performs professional-grade Android APK security analysis and modification through natural language conversation. Powered by a **LangGraph ReAct state machine** and armed with **41+ specialized tools**, it can:

- 🔍 **Decompile** APKs into Smali bytecode, Java source, and JAR archives
- 🛡️ **Detect** 25+ vulnerability patterns (SSL bypass, root detection, weak crypto, WebView RCE, etc.)
- 🧬 **Reverse-engineer** encrypted payloads, obfuscated strings, and native bridges
- 🔧 **Patch** Smali bytecode to bypass protections (SSL pinning, anti-tamper, anti-debug)
- 📦 **Rebuild & sign** fully functional, installable APKs
- 📝 **Generate** detailed forensic Markdown reports

All through a single chat prompt: *"Bypass SSL pinning and disable root detection in this APK."*

---

## ✨ Features

### Core Capabilities

| Category | Capabilities |
|:---------|:-------------|
| **Decompilation** | Smali (apktool), Java source (JADX), JAR archive (dex2jar) |
| **Vulnerability Scanning** | 25+ patterns — SSL bypass, root/emulator detection, weak crypto, hardcoded secrets, WebView RCE, SQL injection, logging leaks, dynamic code loading, IPC issues |
| **Protection Detection** | Root detection, emulator checks, anti-debug, anti-tamper, obfuscation, SSL pinning, certificate validation |
| **Crypto Analysis** | ECB mode usage, hardcoded keys, weak hashing (MD5/SHA1), string decryption, XOR/Base64 deobfuscation |
| **Network Analysis** | SSL pinning configs, OkHttp/Retrofit interceptor chains, cleartext traffic, trust anchors, network security config |
| **Native Code** | JNI declarations, `System.loadLibrary`, `.so` library inventory, React Native & Flutter bridges |
| **Dynamic Loading** | `DexClassLoader`, `Class.forName`, reflection, hidden DEX/JAR in assets |
| **Attack Surface** | Exported components, deep links, custom permissions, intent filters, risk scoring |
| **Smali Patching** | 6 operation types (replace, insert, delete) with auto-backup, unified diffs, and preview mode |
| **Build Pipeline** | Rebuild → zipalign → sign — outputs a ready-to-install APK |
| **Forensic Evidence** | Persistent evidence notebook that survives context compaction |
| **Reporting** | Markdown report with executive summary, findings table, patch diffs, and tool execution log |

### What Makes It Unique

- **🤖 Fully Autonomous** — Reasons, plans, executes, and adapts without hand-holding
- **🔄 ReAct Loop** — Think → Act → Observe → Re-plan cycle with dynamic strategy adjustment
- **🧠 Context Compaction** — Automatically summarizes old messages at 90K tokens to maintain coherence in long sessions
- **🔒 Human-in-the-Loop** — Interrupts for user approval on high-risk smali patches before applying
- **💾 Durable State** — Findings, patches, and evidence survive context compaction via LangGraph state
- **⚡ Tool Caching** — Idempotent tools are cached within session to skip redundant re-runs
- **📋 Evidence System** — Forensic notebook with categorized, severity-tagged, searchable entries
- **🔐 Smart Patch Ordering** — Anti-tamper patches applied first (prevents rebuilt APK crashes)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         APK AGI — Agent Core                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   ┌──────────┐    ┌─────────────────┐    ┌──────────────────────┐  │
│   │  User     │───▶│  CLI / Rich UI  │───▶│  LangGraph Engine    │  │
│   │  (Chat)   │◀───│  (Interactive)  │◀───│  (State Machine)     │  │
│   └──────────┘    └─────────────────┘    └──────────┬───────────┘  │
│                                                      │              │
│                          ┌───────────────────────────┼──────┐      │
│                          ▼                           ▼      │      │
│                   ┌─────────────┐            ┌────────────┐ │      │
│                   │  agent_node │◀──────────▶│  tools     │ │      │
│                   │  (LLM Call) │            │  (ToolNode)│ │      │
│                   └──────┬──────┘            └─────┬──────┘ │      │
│                          │                         │        │      │
│                          ▼                         ▼        │      │
│                   ┌─────────────┐            ┌────────────┐ │      │
│                   │  should_    │            │  tools_    ◀──┘      │
│                   │  continue   │            │  postproc  │        │
│                   └──┬───┬──┬──┘            └────────────┘        │
│                      │   │  │                                      │
│            ┌─────────┘   │  └──────────┐                           │
│            ▼             ▼             ▼                            │
│     ┌──────────┐  ┌──────────┐  ┌──────────┐                      │
│     │  tools   │  │  human_  │  │   END    │                      │
│     │  (loop)  │  │  review  │  │          │                      │
│     └──────────┘  └──────────┘  └──────────┘                      │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                        Tool Arsenal (41+)                           │
├──────────┬──────────┬──────────┬──────────┬──────────┬─────────────┤
│Decompile │ Analysis │ Scanning │ Patching │ Build    │ Evidence    │
│ apktool  │ smali    │ vuln_    │ apply_   │ apktool  │ save_       │
│ jadx     │ deep     │  scanner │  patch   │  _build  │  evidence   │
│ dex2jar  │ manifest │ detect_  │ preview_ │ zipalign │ load_       │
│ aapt2    │ strings  │  protect │  patch   │ sign_apk │  evidence   │
│          │ network  │ targeted │          │          │ search_     │
│          │ native   │  analysis│          │          │  evidence   │
│          │ cert     │ xref     │          │          │ summary     │
│          │ component│          │          │          │             │
└──────────┴──────────┴──────────┴──────────┴──────────┴─────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                  External Android Tools                             │
│   apktool 2.9.3 • JADX 1.5.0 • dex2jar • apksigner • zipalign    │
└─────────────────────────────────────────────────────────────────────┘
```

### Agent Loop Flow

```
                    ┌──────────────────────┐
                    │     User Message     │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │    🧠 Agent Node     │ ◄─── LLM reasons about task
                    │  (Think + Plan)      │      Reviews findings so far
                    └──────────┬───────────┘      Decides next action
                               │
                     ┌─────────┼──────────┐
                     │         │          │
                     ▼         ▼          ▼
               ┌──────┐  ┌────────┐  ┌──────┐
               │Tools │  │ Human  │  │ END  │
               │Call  │  │ Review │  │      │
               └──┬───┘  └───┬────┘  └──────┘
                  │          │
                  ▼          ▼
            ┌──────────┐  User approves
            │ Execute  │  or rejects
            │ Tool(s)  │  the patch
            └──┬───────┘
               │
               ▼
         ┌───────────────┐
         │ Post-Process   │ ◄── Extract findings
         │ (save to state)│     Save evidence
         └───────┬───────┘     Cache results
                 │
                 ▼
           Back to Agent
           (Observe + Re-plan)
```

---

## 🔧 Tool Arsenal

### Complete Tool Inventory (41 Tools)

<details>
<summary><b>🔨 Decompilation (3)</b></summary>

| Tool | Description |
|:-----|:------------|
| `apktool_decompile` | Decompile APK → Smali bytecode + resources + AndroidManifest |
| `jadx_decompile` | Decompile APK → readable Java source code |
| `dex2jar_convert` | Convert DEX → JAR archive for JVM-level analysis |

</details>

<details>
<summary><b>🔎 Quick Reconnaissance (3)</b></summary>

| Tool | Description |
|:-----|:------------|
| `aapt2_dump` | Extract package name, version, SDK info, permissions, components |
| `extract_strings` | Classify strings: URLs, API keys, AWS keys, Firebase, tokens, Base64 |
| `analyze_certificate` | Certificate fingerprints (MD5/SHA1/SHA256), debug detection, signature scheme |

</details>

<details>
<summary><b>📋 Manifest & Components (4)</b></summary>

| Tool | Description |
|:-----|:------------|
| `parse_manifest` | Parse permissions (dangerous set flagged), exported components, security flags |
| `analyze_attack_surface` | Exported component risk scores, deep links, custom permissions, intent filters |
| `analyze_network_config` | Cleartext traffic, trust anchors, certificate pinning, domain rules |
| `score_permissions` | Risk-scored permissions: CRITICAL / HIGH / MEDIUM / LOW with abuse potential |

</details>

<details>
<summary><b>🧬 Smali Deep Analysis (4)</b></summary>

| Tool | Description |
|:-----|:------------|
| `scan_smali_classes` | Class counts, crypto API usage, method summaries |
| `analyze_smali_class` | Parse class info, methods, fields, string constants, security APIs |
| `find_string_decryption_patterns` | Detect XOR loops, Base64 decoding, byte-array-to-String obfuscation |
| `find_method_xrefs` | All call sites — reverse cross-reference graph |

</details>

<details>
<summary><b>🕵️ Professional Reversing (4)</b></summary>

| Tool | Description |
|:-----|:------------|
| `analyze_method_deep` | Full disassembly — registers, API calls, strings, branches, try/catch |
| `detect_protections` | ALL protections: root, emulator, anti-debug, anti-tamper, DCL, native, obfuscation, SSL |
| `trace_call_chain` | Reverse call graph — who calls method → who calls them (configurable depth) |
| `reconstruct_strings` | Decode obfuscated byte arrays, char arrays, and string building patterns |

</details>

<details>
<summary><b>🛡️ Vulnerability Scanning (2)</b></summary>

| Tool | Description |
|:-----|:------------|
| `scan_vulnerabilities` | 25+ patterns: SSL bypass, root detection, weak crypto, hardcoded secrets, WebView RCE, SQL injection, logging, DCL, IPC |
| `list_vuln_patterns` | Metadata on all patterns — ID, name, severity, CWE mapping, category |

</details>

<details>
<summary><b>🔍 Advanced Search (4)</b></summary>

| Tool | Description |
|:-----|:------------|
| `context_search` | Grep with surrounding context lines |
| `multi_search` | Multi-pattern AND/OR search across codebase |
| `xref_search` | Cross-reference callers/callees of any class or method |
| `directory_overview` | File counts, sizes, types for analysis planning |

</details>

<details>
<summary><b>🎯 Targeted Analysis (3)</b></summary>

| Tool | Description |
|:-----|:------------|
| `search_interceptors` | Find OkHttp/Retrofit interceptors, chain.proceed, crypto+network co-location |
| `search_native_code` | JNI declarations, System.loadLibrary, React Native/Flutter bridges, `.so` inventory |
| `search_dynamic_loaders` | DexClassLoader, Class.forName, reflection, runtime DEX/JAR loading, hidden DEX in assets |

</details>

<details>
<summary><b>📁 File Operations (4)</b></summary>

| Tool | Description |
|:-----|:------------|
| `read_file` | Read files with 5 fallback path resolutions |
| `write_file` | Write/modify files in project |
| `search_in_code` | Regex search across `.java`/`.smali`/`.kt` only (no XML/JSON noise) |
| `list_files` | Directory structure browsing with configurable depth |

</details>

<details>
<summary><b>🔬 Evidence & Forensics (4)</b></summary>

| Tool | Description |
|:-----|:------------|
| `save_evidence` | Append to forensic notebook — 12 categories, severity-tagged |
| `load_evidence` | Retrieve evidence by category or severity filter |
| `search_evidence` | Keyword search within evidence entries |
| `get_evidence_summary` | Counts by category/severity, critical findings list |

</details>

<details>
<summary><b>🔧 Patching (2)</b></summary>

| Tool | Description |
|:-----|:------------|
| `apply_smali_patch` | Apply patch plan with auto-backup + unified diff generation |
| `preview_smali_patch` | Preview changes without modifying (validation step) |

</details>

<details>
<summary><b>📦 Build & Sign (3)</b></summary>

| Tool | Description |
|:-----|:------------|
| `apktool_build` | Rebuild APK from patched Smali |
| `zipalign_apk_tool` | 4-byte alignment optimization (pre-signing) |
| `sign_apk` | Sign APK with configured keystore |

</details>

<details>
<summary><b>📝 Reporting (1)</b></summary>

| Tool | Description |
|:-----|:------------|
| `generate_report` | Markdown report: executive summary, findings, patches, tool log, limitations |

</details>

---

## 🚀 Getting Started

### Prerequisites

- **Python** 3.11+
- **Java** JDK/JRE 11+ (for apktool, JADX, dex2jar)
- An **LLM API key** (OpenAI-compatible — AIML API, OpenRouter, OpenAI, or any compatible provider)

### Installation

```bash
# Clone the repository
git clone https://github.com/amenallahbarkaoui-github/APK_AGI.git
cd APK_AGI

# Install the package
pip install -e .

# Set up external tools (apktool, JADX, dex2jar)
python scripts/setup_tools.py
```

### Configuration

Create a `.env` file in the project root:

```env
# Required
API_KEY=your-api-key-here

# LLM Provider (OpenAI-compatible endpoint)
API_BASE_URL=https://api.aimlapi.com/v1
MODEL_NAME=anthropic/claude-sonnet-4-6-20250514

# External tools (auto-detected if in PATH or tools/bin/)
# APKTOOL_PATH=tools/bin/apktool.bat
# JADX_PATH=tools/bin/jadx/bin/jadx.bat
# APKSIGNER_PATH=tools/bin/build-tools/apksigner.bat

# Keystore for signing (optional — uses debug keystore if not set)
# KEYSTORE_PATH=path/to/keystore.jks
# KEYSTORE_PASSWORD=your-password
# KEY_ALIAS=your-alias
```

### Docker

```bash
docker build -t apk-agi .
docker run -it --env-file .env -v ./workspace:/app/workspace apk-agi
```

---

## 💡 Usage

### Interactive Mode

```bash
# Analyze a new APK
apk-agent path/to/app.apk

# Open an existing project
apk-agent --project <project-id>

# Launch project picker
apk-agent
```

### Chat Commands

| Command | Description |
|:--------|:------------|
| `/status` | Show current project status |
| `/logs` | View execution logs |
| `/report` | Generate analysis report |
| `/list` | List all projects |
| `/new` | Create new project |
| `/help` | Show help |
| `/quit` | Exit |

### Example Session

```
$ apk-agent myapp.apk

╔══════════════════════════════════════════════════════════╗
║                  🧠 APK AGI v2.0.0                      ║
║         AI-Powered APK Reverse Engineering Agent         ║
╚══════════════════════════════════════════════════════════╝

✅ Project created: a1b2c3d4

You: Find and bypass all security protections in this APK

🤖 I'll perform a comprehensive security analysis and bypass all protections.

  Phase 1 — Reconnaissance
  🔧 apktool_decompile()        ✅ Smali extracted
  🔧 jadx_decompile()           ✅ Java source ready
  🔧 aapt2_dump()               ✅ Package info retrieved
  🔧 parse_manifest()           ✅ 12 dangerous permissions found

  Phase 2 — Deep Analysis
  🔧 detect_protections()       ✅ Found: SSL pinning, root detection,
                                   anti-tamper, emulator detection
  🔧 scan_vulnerabilities()     ✅ 8 vulnerabilities identified
  🔧 search_interceptors()      ✅ OkHttp interceptor chain found
  🔧 trace_call_chain()         ✅ Call graph mapped

  Phase 3 — Patching
  🔒 Human Review Required:
     📝 Patch 1: Disable signature verification (anti-tamper)
     📝 Patch 2: Bypass SSL certificate pinning
     📝 Patch 3: Disable root detection
     📝 Patch 4: Remove emulator checks

  Do you approve these patches? (yes/no/modify): yes

  🔧 apply_smali_patch() ×4     ✅ All patches applied

  Phase 4 — Build
  🔧 apktool_build()            ✅ APK rebuilt
  🔧 zipalign_apk_tool()        ✅ Aligned
  🔧 sign_apk()                 ✅ Signed

  Phase 5 — Report
  🔧 generate_report()          ✅ Report saved

✅ Done! Patched APK: workspace/a1b2c3d4/outputs/patched-signed.apk
```

---

## 🧰 Tech Stack

| Technology | Role |
|:-----------|:-----|
| [**LangGraph**](https://github.com/langchain-ai/langgraph) | Agentic state machine — nodes, edges, conditional routing, interrupts |
| [**LangChain**](https://github.com/langchain-ai/langchain) | LLM abstraction layer — ChatOpenAI interface, tool binding |
| [**OpenAI SDK**](https://github.com/openai/openai-python) | API transport for OpenAI-compatible providers |
| [**Click**](https://github.com/pallets/click) | CLI framework — commands, options, argument parsing |
| [**Rich**](https://github.com/Textualize/rich) | Terminal UI — panels, Markdown rendering, progress bars, syntax highlighting |
| [**tiktoken**](https://github.com/openai/tiktoken) | Token counting for context window management |
| [**python-dotenv**](https://github.com/theskumar/python-dotenv) | Environment configuration from `.env` files |
| [**PyYAML**](https://github.com/yaml/pyyaml) | YAML parsing for apktool configurations |

---

## 📊 Project Statistics

| Metric | Value |
|:-------|:------|
| Integrated Tools | **41+** |
| Vulnerability Patterns | **25+** |
| Tool Layer Modules | **14** |
| Graph Nodes | **4** (agent, tools, postprocess, human_review) |
| Conditional Routes | **3** |
| Evidence Categories | **12** |
| Patch Operations | **6** types |
| Supported LLM Providers | **Unlimited** (any OpenAI-compatible API) |

---

## 🗂️ Project Structure

```
APK_AGI/
├── src/apk_agent/
│   ├── cli.py                 # Interactive CLI entry point
│   ├── config.py              # Configuration management
│   ├── patch_engine.py        # Smali patch engine (6 operations)
│   ├── reporting.py           # Markdown report generator
│   ├── ui.py                  # Rich console UI
│   ├── workspace.py           # Project & workspace management
│   ├── progress.py            # Real-time progress tracking
│   ├── agent/
│   │   ├── graph.py           # LangGraph state machine
│   │   ├── state.py           # Agent state definition
│   │   ├── prompts.py         # System prompt & methodology
│   │   └── tools_def.py       # Tool definitions & registration
│   ├── llm/
│   │   └── provider.py        # LLM provider (OpenAI-compatible)
│   └── tools/
│       ├── apktool.py         # APK decompile/rebuild
│       ├── jadx.py            # JADX Java decompiler
│       ├── dex2jar.py         # DEX→JAR converter
│       ├── aapt2.py           # APK metadata dumper
│       ├── signer.py          # APK signing
│       ├── zipalign.py        # APK alignment
│       ├── file_ops.py        # File read/write/search
│       ├── manifest_parser.py # AndroidManifest analysis
│       ├── strings_tool.py    # String classification
│       ├── smali_analyzer.py  # Smali pattern detection
│       ├── vuln_scanner.py    # 25+ vulnerability patterns
│       ├── advanced_search.py # Multi-pattern & xref search
│       ├── deep_analyzer.py   # Method disassembly & protection detection
│       ├── targeted_analysis.py # Interceptor/native/dynamic loader search
│       ├── native_analyzer.py # Native .so analysis
│       ├── cert_analyzer.py   # Certificate forensics
│       ├── component_analyzer.py # Component & permission analysis
│       ├── network_config.py  # Network security config analysis
│       └── evidence.py        # Forensic evidence notebook
├── tools/bin/                 # External tool binaries
├── scripts/setup_tools.py     # Tool installer script
├── Dockerfile                 # Docker container build
├── pyproject.toml             # Project metadata & dependencies
└── .env                       # Configuration (not tracked)
```

---

## 🔐 Security & Methodology

### Analysis Phases

1. **Reconnaissance** — Decompile, dump metadata, parse manifest, extract strings
2. **Deep Analysis** — Scan vulnerabilities, detect protections, trace call chains, analyze methods
3. **Patching** — Preview patches, human approval, apply with backups, verify changes
4. **Build** — Rebuild APK, zipalign, sign with keystore
5. **Report** — Generate forensic Markdown report with all findings and diffs

### Smart Patch Ordering

The agent enforces a critical patch order to ensure rebuilt APKs don't crash:

1. **Anti-tamper / Signature verification** ← *Must be first*
2. SSL certificate pinning
3. Root detection
4. Anti-debug checks
5. Emulator detection

### Vulnerability Pattern Coverage

| Category | Example Patterns |
|:---------|:-----------------|
| **SSL/TLS** | Certificate pinning bypass, TrustManager override, hostname verifier bypass |
| **Crypto** | ECB mode usage, hardcoded encryption keys, weak hashing (MD5/SHA1) |
| **Root Detection** | SuperUser check, Magisk detection, su binary lookup |
| **Anti-Debug** | `android.os.Debug.isDebuggerConnected`, ptrace checks |
| **Secrets** | Hardcoded API keys, AWS credentials, Firebase URLs, bearer tokens |
| **WebView** | JavaScript interface injection, `setAllowFileAccess`, `addJavascriptInterface` |
| **IPC** | Exported components, implicit intents, unprotected content providers |
| **Logging** | `Log.d`/`Log.v` with sensitive data, verbose error messages |
| **Dynamic Code** | `DexClassLoader`, `Class.forName`, runtime JAR loading |

---

## ⚖️ Credits & Attribution

APK AGI builds upon the excellent work of the open-source community. The following third-party tools and libraries are integral to the project:

### Android Reverse-Engineering Tools

| Tool | Author / Organization | License | Description |
|:-----|:----------------------|:--------|:------------|
| [**apktool**](https://github.com/iBotPeaches/Apktool) | iBotPeaches (Connor Tumbleson) | Apache 2.0 | APK decompilation & rebuilding — Smali disassembly, resource decoding |
| [**JADX**](https://github.com/skylot/jadx) | skylot | Apache 2.0 | DEX to Java decompiler — produces readable Java source |
| [**dex2jar**](https://github.com/pxb1988/dex2jar) | pxb1988 | Apache 2.0 | DEX to JAR conversion tools |
| [**Android SDK Build Tools**](https://developer.android.com/studio/command-line) | Google | Apache 2.0 | `apksigner`, `zipalign`, `aapt2` — signing, alignment, metadata |

### AI & Agent Framework

| Library | Author / Organization | License | Description |
|:--------|:----------------------|:--------|:------------|
| [**LangGraph**](https://github.com/langchain-ai/langgraph) | LangChain AI | MIT | Graph-based agent orchestration — state machines, tool nodes, interrupts |
| [**LangChain**](https://github.com/langchain-ai/langchain) | LangChain AI | MIT | LLM abstraction layer — chat models, tool binding, message management |
| [**OpenAI Python SDK**](https://github.com/openai/openai-python) | OpenAI | Apache 2.0 | API client for OpenAI-compatible LLM providers |
| [**tiktoken**](https://github.com/openai/tiktoken) | OpenAI | MIT | BPE tokenizer for accurate token counting |

### CLI & Interface

| Library | Author / Organization | License | Description |
|:--------|:----------------------|:--------|:------------|
| [**Rich**](https://github.com/Textualize/rich) | Will McGugan (Textualize) | MIT | Beautiful terminal formatting — panels, tables, Markdown, syntax highlighting |
| [**Click**](https://github.com/pallets/click) | Pallets Projects (Armin Ronacher) | BSD-3 | Composable CLI framework — commands, options, argument parsing |
| [**python-dotenv**](https://github.com/theskumar/python-dotenv) | Saurabh Kumar | BSD-3 | Configuration management from `.env` files |
| [**PyYAML**](https://github.com/yaml/pyyaml) | Kirill Simonov / YAML Community | MIT | YAML parsing for apktool configuration files |

---

## ⚠️ Disclaimer

> **This tool is provided strictly for authorized security testing, white-team engagements, and educational research. Any illegal or unauthorized use is strictly prohibited.**

APK AGI is designed to assist **security professionals, penetration testers, and researchers** in performing authorized assessments of Android applications. It must **only** be used on applications you own or have explicit written permission to test.

**By using this tool, you agree that:**
- You will **not** use it for any illegal, unauthorized, or malicious activity
- You bear **full responsibility** for how you use this software
- The author(s) accept **no liability** for any misuse, damage, or legal consequences arising from unauthorized use
- You will comply with all applicable local, national, and international laws

**Intended use cases:**
- White-team / red-team authorized security assessments
- Bug bounty programs with explicit scope authorization
- Academic and educational security research
- Testing your own applications during development

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Built with ❤️ by <a href="https://github.com/amenallahbarkaoui-github">Amenallah Barkaoui</a>
</p>
