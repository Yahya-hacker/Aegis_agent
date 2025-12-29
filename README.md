# Aegis Agent v9.0 — Full-Spectrum Cyber Operations Platform

**Aegis Agent** is an AI-powered autonomous penetration testing platform that transforms from traditional vulnerability scanning into an intelligent zero-day research system. Built with a multi-LLM architecture and advanced exploitation capabilities, it discovers vulnerabilities through generative fuzzing, state-aware navigation, and deep protocol analysis.

**v9.0 NEW:** Modern React Web Interface with Cyberpunk theme, OMEGA Protocol (Adversarial Swarm Intelligence), Mode Selector (Fast/Pro/Deep-Think), and enhanced Report Generator.

> ⚠️ **AUTHORIZED USE ONLY**: This tool is designed for professional penetration testers and security researchers. Always obtain explicit written permission before testing any system. Unauthorized testing is illegal.

---

## 🚀 Aegis v9.0: Modern React Web Interface & OMEGA Protocol

### NEW v9.0 Features

#### 🎨 Modern React Web Interface
Complete frontend overhaul with React + TypeScript:

- **Cyberpunk Dark Theme**: Immersive dark UI with neon accents and animations
- **Real-time Chat**: WebSocket-powered bidirectional communication
- **Mode Selector**: One-click switching between Fast, Pro, and Deep-Think modes
- **Mission Dashboard**: Live progress bars, tool status, and swarm monitor
- **File Upload**: Drag-and-drop support for binaries, documents, PCAPs, screenshots
- **MCP Integration**: Connect to any MCP server without restarting

#### 🧠 OMEGA Protocol: Neuro-Symbolic Swarm Intelligence
Advanced cognitive architecture for enhanced reasoning:

| Component | Description | Key Features |
|-----------|-------------|--------------|
| **Knowledge Graph** | Graph-native attack surface mapping | Nodes (Assets, Tech, Creds), Edges (Attack Paths), Traversal-based testing |
| **Adversarial Swarm** | Internal debate before risky actions | RED (Attacker), BLUE (Defender), JUDGE (Strategist) |
| **Epistemic Priority** | Confidence-based mode shifting | Blocks exploitation until confidence ≥ 60% |
| **Virtual Sandbox** | Safe execution with verification | Pre-compute predictions, halt on >20% deviation |
| **Report Generator** | Multi-format export | JSON, HTML, PDF reports with attack graphs |

#### ⚡ Operation Modes
Three distinct modes optimized for different scenarios:

| Mode | Models | Use Case |
|------|--------|----------|
| **Fast** | Llama 8B, Qwen Coder 7B, DeepSeek VL, Mistral Nemo 12B | Rapid recon, basic targets |
| **Pro** | Hermes 3 70B, Dolphin 3.0 24B, Qwen 72B, Qwen VL 32B | Full power, most use cases |
| **Deep-Think** | DeepSeek R1, Qwen 72B, Qwen VL 32B | Maximum reasoning, complex analysis |

---

## 🚀 Aegis v8.5: Self-Modifying Agent

### NEW v8.5 Features

#### 🔧 Self-Modification Engine
Aegis can now **modify its own code** and **create custom tools on-the-fly**:

- **Dynamic Tool Creation**: AI-powered tool generation based on requirements
- **Tool Adaptation**: Automatically modifies tools that fail or underperform
- **Performance Monitoring**: Tracks success rates and execution times
- **Code Validation**: Syntax checking and security scanning before execution

```python
# Create a custom tool during runtime
await agent.create_custom_tool(
    tool_name="custom_scanner",
    description="Scan for specific vulnerabilities",
    requirements="Should check for XSS, CSRF, and SQLi",
    expected_inputs=["url", "depth"],
    expected_outputs=["vulnerabilities", "severity"]
)
```

#### ⚡ Parallel Execution Engine
Execute multiple operations concurrently for **10x performance boost**:

- **Concurrent Task Execution**: Run up to 20 parallel operations
- **Smart Prioritization**: Critical tasks get priority
- **Dependency Management**: Automatic task ordering
- **Resource Limiting**: Prevents system overload

```python
# Execute multiple scans in parallel
results = await agent.execute_parallel_tasks([
    {"name": "Port Scan", "coroutine": scan_ports()},
    {"name": "Directory Enum", "coroutine": enum_dirs()},
    {"name": "Subdomain Discovery", "coroutine": find_subdomains()}
])
```

#### 🎯 Enhanced CTF Mode
Specialized mode for **Capture The Flag competitions**:

- **Multi-Domain Support**: Web, Crypto, Binary, Reverse, Forensics, Network, PWN
- **Concurrent Challenge Solving**: Solve multiple challenges simultaneously
- **Auto-Detection**: Automatically classify challenges by domain
- **Strategy Generation**: AI creates custom solving strategies
- **Flag Pattern Recognition**: Identifies flags automatically

```bash
# Activate CTF mode
> activate ctf mode
> solve all challenges
```

#### 🛡️ Enhanced Error Recovery
**Self-healing capabilities** that recover from failures:

- **Auto-Retry with Backoff**: Intelligent retry strategies
- **Self-Healing**: Automatically fixes common errors (missing modules, timeouts)
- **Graceful Degradation**: Continues operation even with partial failures
- **Error Pattern Learning**: Adapts strategies based on error history

#### 💎 Modern React Web Interface
**Next-generation UI** with Cyberpunk dark theme:

- **React + TypeScript Frontend**: Modern component-based architecture
- **Real-time Chat Interface**: WebSocket-powered communication
- **Mode Selector**: Instant switching between Fast, Pro, and Deep-Think modes
- **Mission Dashboard**: Live status, progress bars, and swarm monitor
- **File Upload Support**: Analyze binaries, documents, PCAPs, screenshots
- **MCP Integration**: Dynamic tool hot-plugging without restart

```bash
# Start the modern web UI
./start_web_ui.sh

# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
# API Docs: http://localhost:8000/docs
```

See [WEB_INTERFACE.md](WEB_INTERFACE.md) for detailed documentation.

#### 🧠 OMEGA Protocol: Neuro-Symbolic Swarm Intelligence
Advanced cognitive architecture for enhanced reasoning:

- **Knowledge Graph**: Graph-native attack surface mapping with traversal-based testing
- **Adversarial Swarm**: RED/BLUE/JUDGE internal debate before risky actions
- **Epistemic Priority**: Blocks exploitation until confidence ≥ 60%
- **Virtual Sandbox**: Pre-compute predictions, halt on >20% deviation
- **Report Generator**: Multi-format export (JSON, HTML, PDF)

---

## 🚀 Aegis v8.0: Full-Spectrum Cyber Operations

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

Aegis v8.0 is **Autonomous and Self-Healing**. If a required tool is missing, the agent:

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

The multi-LLM orchestrator now adapts based on the operation domain:

- **Binary Context** → Prioritizes **Coder LLM** (Qwen) for writing exploit scripts
- **Crypto Context** → Prioritizes **Reasoning LLM** (DeepSeek) for mathematical analysis
- **Network Context** → Prioritizes **Reasoning LLM** for protocol analysis

```python
# Set domain context for optimized LLM selection
ai_core.blackboard.set_domain_context("Binary")  # For pwn challenges
ai_core.blackboard.set_domain_context("Crypto")  # For crypto challenges
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
OPENROUTER_API_KEY=sk-main-key           # Fallback for all roles
STRATEGIC_API_KEY=sk-strategic-key       # Separate account for planning
REASONING_API_KEY=sk-reasoning-key       # Separate account for analysis
CODE_API_KEY=sk-code-key                 # Separate account for payloads
VISUAL_API_KEY=sk-visual-key             # Separate account for screenshots
```

---


## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                    AEGIS AGENT v8.5                                 │
├─────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐  │
│  │  Strategic  │  │  Reasoning  │  │    Code     │  │   Visual  │  │
│  │     LLM     │  │     LLM     │  │     LLM     │  │    LLM    │  │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────┬─────┘  │
│         └────────────────┴────────────────┴────────────────┘        │
│                          ▼                                           │
│              ┌────────────────────────────┐                          │
│              │  Multi-LLM Orchestrator   │                          │
│              │   (API Key Sharding)      │                          │
│              └────────────┬───────────────┘                          │
│                           ▼                                          │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │           Enhanced AI Core with Self-Modification          │     │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐   │     │
│  │  │   Cortex     │ │   Parallel   │ │ Self-Mod Engine │   │     │
│  │  │   Memory     │ │   Execution  │ │  (Tool Creator) │   │     │
│  │  └──────────────┘ └──────────────┘ └──────────────────┘   │     │
│  └────────────────────────────────────────────────────────────┘     │
│                           ▼                                          │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │                  Advanced Tool Layer                       │     │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐  │     │
│  │  │ Genesis  │ │  Nuclei  │ │  SQLMap  │ │   CTF Mode   │  │     │
│  │  │ Fuzzer   │ │   Scan   │ │  Inject  │ │ (Multi-Domain│  │     │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────────┘  │     │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐  │     │
│  │  │ Visual   │ │ App      │ │  Custom  │ │    Error     │  │     │
│  │  │ Recon    │ │ Spider   │ │  Tools   │ │   Recovery   │  │     │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────────┘  │     │
│  └────────────────────────────────────────────────────────────┘     │
│                           ▼                                          │
│  ┌────────────────────────────────────────────────────────────┐     │
│  │              Professional Gemini-Style UI                  │     │
│  │  • Real-time Metrics  • Interactive Controls               │     │
│  │  • Visual Feedback    • Mode Selection                     │     │
│  └────────────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- OpenRouter API key ([get one here](https://openrouter.ai/))
- Node.js (for Mirror JS Sandbox)

### Installation

```bash
# Clone repository
git clone https://github.com/Yahya-hacker/Aegis_agent.git
cd Aegis_agent

# Install Python dependencies
pip install -r requirements.txt

# Install Playwright browsers (auto-installed if missing)
playwright install chromium

# Configure API keys
cp .env.example .env
nano .env  # Add your OpenRouter API key(s)

# Run Aegis
python main.py
```

### Optional Security Tools

```bash
# Install Go-based tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest

# Install SQLMap
apt install sqlmap  # or pip install sqlmap
```

---

## 📖 Usage Examples

### Basic Penetration Testing

```bash
# Start Aegis
python main.py

# Scan a target
> scan example.com

# Activate UI mode
> ui
# Then run: streamlit run app.py
```

### CTF Mode

```bash
# Activate CTF mode
> activate ctf mode
CTF Name: PicoCTF 2024

# The agent will prompt for challenge information
# Or auto-detect from a directory

# Solve all challenges in parallel
> solve all challenges

# View scoreboard
> scoreboard
```

### Creating Custom Tools

```python
# Create a tool for specific vulnerability testing
> create tool custom_xss_scanner that does comprehensive XSS detection

Tool name: custom_xss_scanner
Description: Comprehensive XSS scanner with DOM analysis
Requirements: Should test for reflected, stored, and DOM-based XSS
Expected inputs: url, depth, payloads
Expected outputs: vulnerabilities, locations, severity

# The agent will generate and validate the tool automatically
```

### Parallel Operations

```python
# From Python API
import asyncio
from agents.enhanced_ai_core import EnhancedAegisAI

async def main():
    agent = EnhancedAegisAI()
    await agent.initialize()
    
    # Execute multiple tasks concurrently
    results = await agent.execute_parallel_tasks([
        {
            "name": "Subdomain Discovery",
            "coroutine": discover_subdomains("example.com"),
            "priority": "high"
        },
        {
            "name": "Port Scanning",
            "coroutine": scan_ports("example.com"),
            "priority": "normal"
        },
        {
            "name": "Directory Enumeration",
            "coroutine": enum_directories("example.com"),
            "priority": "normal"
        }
    ])
    
    print(f"Completed {results['metrics']['completed']} tasks")

asyncio.run(main())
```

### Advanced Commands

```bash
# Check agent status and metrics
> status

# List all available tools
> list available tools

# Get help
> help

# Inject custom instruction during mission
> inject: Focus on API endpoints only

# Stop current mission
> stop
```

---

## 🎯 CTF Challenge Examples

### Web Challenge
```bash
> activate ctf mode
> register challenge "SQL Injection Login" domain=web points=200
> solve challenge
```

### Cryptography Challenge
```bash
> register challenge "RSA Weak Keys" domain=crypto points=300
# Agent will automatically use ciphey, hashcat, and custom crypto tools
```

### Binary Exploitation
```bash
> register challenge "Buffer Overflow" domain=pwn points=500
# Agent will use checksec, pwntools, and generate ROP chains
```

---

## 🔧 Configuration

### Environment Variables

```bash
# API Keys (required)
OPENROUTER_API_KEY=your_main_key       # Master key (fallback)
STRATEGIC_API_KEY=optional_separate    # Strategic planning
REASONING_API_KEY=optional_separate    # Vulnerability analysis
CODE_API_KEY=optional_separate         # Payload generation
VISUAL_API_KEY=optional_separate       # Screenshot analysis

# Model Selection (all configurable)
STRATEGIC_MODEL=nousresearch/hermes-3-llama-3.1-70b
REASONING_MODEL=cognitivecomputations/dolphin3.0-r1-mistral-24b
CODE_MODEL=qwen/qwen-2.5-72b-instruct
VISUAL_MODEL=qwen/qwen2.5-vl-32b-instruct:free

# Generation Parameters
DEFAULT_TEMPERATURE=0.7
DEFAULT_MAX_TOKENS=4096
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
