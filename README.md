
# Aegis Agent v9.0 "Nexus" — Full-Spectrum Cyber Operations Platform

**Aegis Agent** is an AI-powered autonomous penetration testing platform that transforms from traditional vulnerability scanning into an intelligent zero-day research system. Built with a multi-LLM architecture and advanced exploitation capabilities, it discovers vulnerabilities through generative fuzzing, state-aware navigation, and deep protocol analysis.

**v9.0 NEW: "NEXUS"** — State-of-the-Art Web UI + MCP Client Integration for dynamic tool hot-plugging.


> ⚠️ **AUTHORIZED USE ONLY**: This tool is designed for professional penetration testers and security researchers. Always obtain explicit written permission before testing any system. Unauthorized testing is illegal.

---

## 🚀 What's New in v9.0 "Nexus"

### Modern Web Interface
- **React + TypeScript Frontend** with dark "Cyberpunk" theme
- **Real-time Chat Interface** for dialoguing with the agent
- **Mode Selector** for instant switching between Penetration Testing, CTF Mode, Red Teaming, and Audit modes
- **Mission Dashboard** with real-time tool status, progress bars, and swarm monitor
- **File Upload Support** for analyzing binaries, documents, PCAPs, and screenshots

### MCP Client Integration
- **Dynamic Tool Hot-Plugging** via Model Context Protocol
- **Connect to Any MCP Server** without restarting the agent
- **SSE and stdio Transport Support** for flexible connectivity
- **Unified Tool Registry** across all connected servers

### Performance Optimizations
- **Memory Compression** to prevent context saturation during long scans
- **Parallel Hypothesis Testing** in KTV Loop (3x faster)
- **Consolidated Server Architecture** (FastAPI + WebSocket)

---

## 🌐 OMEGA PROTOCOL: Neuro-Symbolic Swarm Intelligence

The **Omega Protocol** is an advanced cognitive architecture that enhances the agent's reasoning capabilities:

### Core Components

| Component | Description | Key Features |
|-----------|-------------|--------------|
| **Knowledge Graph** | Graph-native attack surface mapping | Nodes (Assets, Tech, Creds), Edges (Attack Paths), Traversal-based testing |
| **Adversarial Swarm** | Internal debate before risky actions | RED (Attacker), BLUE (Defender), JUDGE (Strategist) |
| **Epistemic Priority** | Confidence-based mode shifting | Blocks exploitation until confidence ≥ 60%, focuses on information gain |
| **Virtual Sandbox** | Safe execution with verification | Pre-compute predictions, halt on >20% deviation, dependency lock |
| **Report Generator** | Multi-format export | JSON, HTML, PDF reports with attack graphs |

### Graph-Native KTV Loop

All reasoning maps to the Knowledge Graph:

```
[GRAPH STATE] Nodes: 5 (Web, API, ?DB), Edges: 2
[ATTACK PATH] Node(Web) --[SQLi, Conf: 0.9]--> Node(DB) --[Access, Conf: 0.7]--> Node(AdminHash)
```

- **KNOW (Nodes)**: Every confirmed fact is a Node
- **THINK (Edges)**: Every hypothesis is a probabilistic Edge
- **TEST (Traversal)**: Validate paths through the graph

### Adversarial Swarm Protocol

Before executing high-risk tools (risk score > 5), the agent conducts an internal debate:

```
[DEBATE] 
  RED: Use aggressive SQLMap with all payloads
  BLUE: WAF detected (Cloudflare), aggressive scans will trigger blocks
  JUDGE: Execute stealth variant with URL encoding and 2-second delays
```

### Epistemic Priority Rule

When architecture confidence is low, exploitation is disabled:

```
[EPISTEMIC STATE] Mode: SEARCH
[CONFIDENCE] Overall: 45% (threshold: 60%)
[EXPLOITATION] LOCKED - Complete reconnaissance first

[RECOMMENDED ACTIONS]
1. technology_fingerprint - Identify technology stack
2. javascript_analysis - Extract endpoints from JS
3. api_discovery - Find API endpoints
```

### Virtual Sandbox Safety

Every command is pre-computed and verified:

1. **Pre-Compute**: Predict expected HTTP response before execution
2. **Atomic Verify**: If response deviates >20%, HALT and re-evaluate
3. **Dependency Lock**: No tool installation mid-mission; use fallbacks

### Report Generation

Generate professional reports in multiple formats:

```python
from utils.report_generator import get_report_generator, ReportFormat

generator = get_report_generator()
paths = generator.generate_report(report_data, formats=[
    ReportFormat.JSON,  # Machine-readable
    ReportFormat.HTML,  # Interactive web report
    ReportFormat.PDF    # Professional document (requires weasyprint)
])
```

### Using the Omega Protocol

```python
from agents.omega_protocol import get_omega_protocol

# Initialize with AI core and scanner
protocol = get_omega_protocol(ai_core, scanner)

# Execute a complete mission
results = await protocol.execute_omega_mission(
    target="https://target.com",
    rules="Standard penetration testing",
    max_iterations=10
)

# Or execute individual actions through the pipeline
result = await protocol.execute_action({
    "tool": "sql_injection_test",
    "args": {"url": "https://target.com/search?q=test"}
})

# Get current state for UI display
state = protocol.get_omega_state()
# {
#   "graph": {"nodes": 12, "edges": 8, "attack_paths": 3},
#   "epistemic": {"confidence": 0.72, "mode": "exploitation"},
#   "swarm": {"debates": 5}
# }
```

---

##  Full-Spectrum Cyber Operations

### NEW: Five Specialized Capability Domains

Aegis v8.0 expands beyond web security into five new domains, making it a complete CTF and Red Team operator:

| Domain | Module | Tools Wrapped | Key Functions |
|--------|--------|---------------|---------------|
| **🔐 Cryptography** | `crypto_engine` | Ciphey, hashid, John | `solve_crypto()`, `crack_hash()` |
| **🔧 Reverse Engineering** | `reverse_engine` | strings, objdump, radare2, gdb | `analyze_binary()`, `disassemble_function()` |
| **🔬 Forensics** | `forensics_lab` | exiftool, binwalk, steghide, volatility | `analyze_file_artifacts()`, `extract_steghide()` |
| **💀 Binary Exploitation** | `pwn_exploiter` | checksec, pwntools | `check_binary_protections()`, `find_rop_gadgets()` |
| **📡 Network Analysis** | `network_sentry` | tshark, tcpdump | `analyze_pcap()`, `follow_tcp_stream()` |

### NEW: Self-Healing Infrastructure

Aegis v9.0 is **Autonomous and Self-Healing**. If a required tool is missing, the agent:

1. **Detects** the missing dependency
2. **Proposes** installation (or auto-installs if self-healing mode is enabled)
3. **Adapts** its strategy with fallback mechanisms

```bash
# Enable self-healing mode
export AEGIS_SELF_HEALING=true

# The agent will automatically install missing tools like:
# - radare2 (apt-get install radare2)
# - ciphey (pip install ciphey)
# - pwntools (pip install pwntools)
```

### NEW: Domain-Context Aware LLM Selection

The multi-LLM orchestrator now **automatically detects and adapts** based on the operation domain:

| Domain Context | LLM Priority | Use Case | Auto-Detected Keywords |
|----------------|--------------|----------|------------------------|
| **Binary / Pwn** | Coder LLM (Qwen) | Exploit scripts, ROP chains | `binary`, `pwn`, `elf`, `rop`, `buffer overflow` |
| **Crypto** | Reasoning LLM (DeepSeek) | Mathematical analysis, cipher breaking | `crypto`, `cipher`, `hash`, `encryption`, `rsa` |
| **Forensics** | Reasoning LLM (DeepSeek) | Evidence analysis, metadata extraction | `forensic`, `steganography`, `metadata`, `exif` |
| **Network** | Reasoning LLM (DeepSeek) | Protocol analysis, PCAP parsing | `network`, `pcap`, `packet`, `tcp`, `dns` |
| **Web** | Balanced routing | Web vulnerabilities | `http`, `https`, `www`, `api`, `xss`, `sqli` |

#### Automatic Domain Detection

When you start a mission, Aegis automatically analyzes the target and rules to set the optimal domain context:

```python
# Auto-detection happens at mission start
# Example: Target = "challenge.pwn.me", Rules = "binary exploitation challenge"
# → Domain context auto-set to "Binary"
# → Coder LLM (Qwen) prioritized for exploit development

# Example: Target = "crypto_challenge.zip", Rules = "decrypt the message"
# → Domain context auto-set to "Crypto"
# → Reasoning LLM (DeepSeek) prioritized for mathematical analysis
```

#### Manual Override

You can also manually set domain context for specialized scenarios:

```python
# Manual domain context setting
ai_core.orchestrator.set_domain_context("Binary")     # For pwn challenges
ai_core.blackboard.set_domain_context("Crypto")       # For crypto challenges
ai_core.orchestrator.set_domain_context("Forensics")  # For forensics challenges
```

### CTF Strategy Guide

The AI automatically applies the right tools:

| If you find... | Aegis uses... |
|----------------|---------------|
| Hash or ciphertext | `solve_crypto()` or `crack_hash()` |
| Binary file | `analyze_binary()` → `check_binary_protections()` |
| Image/PDF/Document | `analyze_file_artifacts()` |
| PCAP file | `analyze_pcap()` |
| Pwn challenge | `check_binary_protections()` → `find_rop_gadgets()` |

---

## 🎯 What Makes Aegis Unique

### Zero-Day Capabilities (Genesis Fuzzer)

Unlike traditional scanners that match CVE signatures, **Aegis discovers unknown vulnerabilities** through intelligent mutation:

- **Evolutionary Genetic Fuzzing** — Byte-level mutations with feedback loops identify edge cases that static payloads miss
- **Differential Analysis** — Levenshtein distance, timing analysis, and structure comparison detect blind vulnerabilities
- **Context-Aware Mutations** — Technology fingerprinting (Flask, Django, Express, PHP) enables framework-specific payloads
- **7 Mutation Strategies** — Integer overflow, format strings, boundary violations, Unicode injection, null bytes, command injection, and template injection

```python
from tools.genesis_fuzzer import get_genesis_fuzzer

fuzzer = get_genesis_fuzzer()
fuzzer.compile_grammar({
    "username": {"type": "string", "max_len": 20},
    "amount": {"type": "integer", "min": 0, "max": 999999}
})

result = await fuzzer.fuzz_endpoint(
    url="https://api.target.com/transfer",
    method="POST",
    base_payload={"username": "admin", "amount": 100}
)
# Discovers: integer overflow, negative amounts, format string injection
```

### Visual-Cognitive Engine (Set-of-Mark)

Aegis employs **Set-of-Mark (SoM)** visual grounding technology to interact with modern SPAs that defeat DOM-based tools:

- **Visual Element Tagging** — Numbered badges overlay every clickable element in screenshots
- **Precise UI Navigation** — Click elements by SoM ID for exact interaction
- **SPA Detection** — Automatic re-capture after client-side navigation
- **DOM Obfuscation Bypass** — Works when React/Vue/Angular obscure the traditional DOM

```python
# Capture screenshot with SoM tags
result = await scanner.execute_action({
    "tool": "capture_screenshot_som",
    "args": {"url": "https://app.target.com", "full_page": True}
})
# Returns: screenshot with numbered badges + element_mapping {ID: selector}

# Click specific element by ID
await scanner.execute_action({
    "tool": "click_element_by_id",
    "args": {"url": "https://app.target.com", "element_id": 15}
})
```

### Self-Healing Infrastructure

Aegis automatically installs missing dependencies when tools fail:

- **Playwright Auto-Install** — If Chrome binary missing, runs `playwright install chromium` and retries
- **Selenium Path Detection** — Searches `/usr/bin/google-chrome`, `/usr/bin/chromium`, etc.
- **Tool Discovery** — Scans PATH for security tools (Nuclei, Nmap, SQLMap, Subfinder)
- **Graceful Degradation** — Continues with available tools if some are missing

```python
# Browser initialization with self-healing
async def _initialize_browser(self):
    try:
        self.browser = await self.playwright.chromium.launch()
    except Exception as e:
        if 'chrome' in str(e).lower():
            # Auto-install and retry
            subprocess.run(["playwright", "install", "chromium"])
            self.browser = await self.playwright.chromium.launch()
```

### Multi-LLM Brain (Sharded API Architecture)

Four specialized AI models collaborate through **role-specific API key sharding**:

| Role | Default Model | Specialization |
|------|---------------|----------------|
| **Strategic** | Hermes 3 Llama 70B | Mission planning, triage, scope analysis |
| **Reasoning** | Dolphin 3.0 R1 Mistral 24B | Vulnerability analysis, exploit reasoning |
| **Coding** | Qwen 2.5 72B | Payload generation, code analysis |
| **Visual** | Qwen 2.5 VL 32B | Screenshot analysis, UI reconnaissance |

**Key Benefits:**
- **Parallel Execution** — Different API keys per role bypass per-account rate limits
- **Cost Isolation** — Track spending per capability independently
- **Model Flexibility** — Change any model via `.env` without code changes

```bash
# .env configuration
OPENROUTER_API_KEY=your_main_api_key_here           # Fallback for all roles
STRATEGIC_API_KEY=your_strategic_key_here       # Separate account for planning
REASONING_API_KEY=your_reasoning_key_here       # Separate account for analysis
CODE_API_KEY=your_code_key_here                 # Separate account for payloads
VISUAL_API_KEY=your_visual_key_here             # Separate account for screenshots
```

---


## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    AEGIS AGENT v7.5                         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Strategic  │  │  Reasoning  │  │  Code + Visual LLM  │  │
│  │    LLM      │  │     LLM     │  │    (Multi-Modal)    │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
│         └────────────────┼────────────────────┘             │
│                          ▼                                   │
│              ┌───────────────────────┐                       │
│              │  Multi-LLM Orchestrator │                      │
│              │  (API Key Sharding)    │                       │
│              └───────────┬───────────┘                       │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Cortex Memory (Knowledge Graph)          │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌────────────┐  │   │
│  │  │  Facts  │ │  Goals  │ │ Vectors │ │ Attack Path│  │   │
│  │  └─────────┘ └─────────┘ └─────────┘ └────────────┘  │   │
│  └──────────────────────────────────────────────────────┘   │
│                          ▼                                   │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                     Tool Layer                        │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐  │   │
│  │  │ Genesis  │ │  Nuclei  │ │  SQLMap  │ │ Chronos │  │   │
│  │  │ Fuzzer   │ │   Scan   │ │  Inject  │ │  Race   │  │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └─────────┘  │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐  │   │
│  │  │   CDP    │ │  Visual  │ │ App      │ │  Logic  │  │   │
│  │  │  Hooks   │ │  Recon   │ │ Spider   │ │ Tester  │  │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └─────────┘  │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+ (for frontend)
- OpenRouter API key ([get one here](https://openrouter.ai/))

### Installation

#### Option 1: New Web UI (Recommended for v9.0)

```bash
# Clone repository
git clone https://github.com/Yahya-hacker/Aegis_agent.git
cd Aegis_agent

# Install Python dependencies
pip install -r requirements.txt

# Configure API keys
cp .env.example .env
nano .env  # Add your OpenRouter API key(s)

# Install frontend dependencies (optional)
cd frontend
npm install
npm run build
cd ..

# Start the v9.0 Nexus server
python server.py

# Access the UI at http://localhost:8000
```

#### Option 2: CLI Mode (Legacy)

```bash
# For command-line interface (no web UI)
python main.py
```

#### Option 3: Automated Setup

```bash
# Run automated setup script
python setup.py

# The setup script will:
# - Check Python and Go versions
# - Install all Python dependencies
# - Install Playwright browsers
# - Install Go-based security tools (if Go is installed)
# - Configure environment variables (.env)
# - Create necessary directories
# - Verify installation

# After setup completes:
python server.py  # Web UI
# OR
python main.py    # CLI mode
```

### Environment Variables

```bash
# Required
OPENROUTER_API_KEY=your_openrouter_api_key_here

# Server Configuration
HOST=0.0.0.0
PORT=8000

# Optional: Model overrides
STRATEGIC_MODEL=deepseek/deepseek-r1
CODE_MODEL=qwen/qwen-2.5-72b-instruct
```

---

## 🔧 Configuration

### Environment Variables (v8.0 Full-Spectrum Architecture)

All components are fully configurable via `.env` file - **NO hardcoded values**:

```bash
# =============================================================================
# API KEYS
# =============================================================================
# Master API key - used as fallback for all roles if specific keys not set
OPENROUTER_API_KEY=your_openrouter_api_key_here

# Optional: Role-specific API keys for granular cost control and rate limits
# If not set, falls back to OPENROUTER_API_KEY
STRATEGIC_API_KEY=         # Strategic planning LLM
REASONING_API_KEY=         # Vulnerability analysis LLM
CODE_API_KEY=              # Payload generation LLM
VISUAL_API_KEY=            # Screenshot analysis LLM

# =============================================================================
# MODEL CONFIGURATION (v8.0 Defaults)
# =============================================================================
# All models can be swapped without code changes via this file

# Strategic Model - for mission planning, triage, decision-making
# Default: DeepSeek R1 for deep reasoning
STRATEGIC_MODEL=deepseek/deepseek-r1

# Reasoning Model - for vulnerability analysis, exploit planning
# Default: DeepSeek R1 for deep reasoning
REASONING_MODEL=deepseek/deepseek-r1

# Code Model - for code analysis, payload generation, binary exploitation
# Default: Qwen 2.5 72B for technical implementation
CODE_MODEL=qwen/qwen-2.5-72b-instruct

# Visual Model - for screenshot analysis, UI reconnaissance
# Default: Qwen 2.5 VL 72B for multimodal analysis
VISUAL_MODEL=qwen/qwen2.5-vl-72b-instruct

# =============================================================================
# GENERATION PARAMETERS
# =============================================================================
# Default temperature for all LLM calls (0.0 to 1.0)
DEFAULT_TEMPERATURE=0.7

# Default maximum tokens for LLM responses
DEFAULT_MAX_TOKENS=4096

# =============================================================================
# DOMAIN CONTEXT (Auto-Detected)
# =============================================================================
# The agent automatically detects the domain context from target and rules:
# - "Binary" or "Pwn" → Prioritizes Coder LLM (Qwen) for exploit scripts
# - "Crypto" or "Forensics" → Prioritizes Reasoning LLM (DeepSeek) for analysis
# - "Network" → Prioritizes Reasoning LLM for protocol analysis
# - "Web" → Balanced routing based on task type
#
# You can also manually set domain context in code:
# ai_core.orchestrator.set_domain_context("Binary")
# ai_core.blackboard.set_domain_context("Binary")
```

### System Prompts (Advanced Configuration)

Override default system prompts for specialized use cases:

```bash
# Optional: Custom system prompts (multi-line supported via .env)
TRIAGE_SYSTEM_PROMPT=Your custom triage prompt
CODE_ANALYSIS_SYSTEM_PROMPT=Your custom code analysis prompt
PAYLOAD_GEN_SYSTEM_PROMPT=Your custom payload generation prompt
VERIFICATION_SYSTEM_PROMPT=Your custom verification prompt
TRIAGE_FINDING_SYSTEM_PROMPT=Your custom triage finding prompt
FACT_EXTRACTION_SYSTEM_PROMPT=Your custom fact extraction prompt
```

---

## 🛡️ Safety & Authorization

### Mandatory Authorization
Use Aegis **only** against systems you:
- Explicitly own, OR
- Have written authorization to test (signed agreement, bug bounty program)

### Human-in-the-Loop
- **Reconnaissance** — Auto-approved (passive)
- **Exploitation** — Requires explicit human approval
- **High-Risk Actions** — Always confirmed before execution

### Rate Limiting
- Default: 2 second minimum delay between tool calls
- Maximum 3 concurrent tool executions
- Configurable per-tool rate limits

---

## 📚 Documentation

- [V7_5_FEATURES.md](V7_5_FEATURES.md) — Complete feature documentation
- [MULTI_LLM_GUIDE.md](MULTI_LLM_GUIDE.md) — Multi-LLM architecture details
- [ARCHITECTURE.md](ARCHITECTURE.md) — Technical architecture overview
- [QUICK_START_V7_5.md](QUICK_START_V7_5.md) — Getting started guide

---

## 🧪 Testing

```bash
# Test v7.5 features
python test_v7_5_features.py

# Test multi-LLM integration
python test_multi_llm.py

# Integration tests
python test_integration_all_features.py

# Run demonstration
python demo_v7_5_integration.py
```

---

## 📝 License

This project is provided for educational and authorized security testing purposes only. See LICENSE for details.

---

**Built for security researchers who demand more than signature matching.**
