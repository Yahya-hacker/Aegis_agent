# Aegis Agent v9.0 — Unified Single-LLM Cyber Operations Platform

**Aegis Agent** is an AI-powered autonomous penetration testing platform that transforms from traditional vulnerability scanning into an intelligent zero-day research system. Built with a **unified single-LLM architecture** and advanced exploitation capabilities, it discovers vulnerabilities through generative fuzzing, state-aware navigation, and deep protocol analysis.

**v9.0 NEW:** Unified Single-LLM Architecture using DeepSeek R1 for consistent reasoning across all tasks.

> ⚠️ **AUTHORIZED USE ONLY**: This tool is designed for professional penetration testers and security researchers. Always obtain explicit written permission before testing any system. Unauthorized testing is illegal.

---

## 🚀 Aegis v9.0: Unified Single-LLM Architecture

### NEW: Single LLM for ALL Tasks

Aegis v9.0 introduces a **unified single-LLM architecture** that simplifies operations while maintaining powerful capabilities:

| Component | Model | Purpose |
|-----------|-------|---------|
| **Main LLM** | DeepSeek R1 | ALL tasks: planning, vulnerability analysis, code analysis, payload generation, reasoning |
| **Visual LLM** | Qwen 2.5 VL | Screenshot/image analysis only |

**Benefits of Unified Architecture:**
- 🧠 **Consistent Reasoning** — Single context across all task types
- 🔧 **Simplified Configuration** — One model to configure and manage
- 💪 **Better Context Retention** — No context loss between different LLM calls
- ⚡ **Reduced API Complexity** — Single persistent connection

### Configuration

```bash
# .env configuration for v9.0
OPENROUTER_API_KEY=your_api_key        # Master key

# Unified LLM (handles everything)
MAIN_MODEL=deepseek/deepseek-r1        # Or any preferred model

# Visual LLM (images only)
VISUAL_MODEL=qwen/qwen2.5-vl-32b-instruct:free

# Generation Parameters (optimized for DeepSeek R1)
DEFAULT_TEMPERATURE=0.7
DEFAULT_MAX_TOKENS=8192                # Higher for complex reasoning
```

### Full-Spectrum CTF & Red Team Operations

All v8.0 capabilities remain, now powered by the unified LLM:

| Domain | Module | Tools Wrapped | Key Functions |
|--------|--------|---------------|---------------|
| **🔐 Cryptography** | `crypto_engine` | Ciphey, hashid, John | `solve_crypto()`, `crack_hash()` |
| **🔧 Reverse Engineering** | `reverse_engine` | strings, objdump, radare2, gdb | `analyze_binary()`, `disassemble_function()` |
| **🔬 Forensics** | `forensics_lab` | exiftool, binwalk, steghide, volatility | `analyze_file_artifacts()`, `extract_steghide()` |
| **💀 Binary Exploitation** | `pwn_exploiter` | checksec, pwntools | `check_binary_protections()`, `find_rop_gadgets()` |
| **📡 Network Analysis** | `network_sentry` | tshark, tcpdump | `analyze_pcap()`, `follow_tcp_stream()` |

### Self-Healing Infrastructure

Aegis v9.0 remains **Autonomous and Self-Healing**:

1. **Detects** missing dependencies
2. **Proposes** installation (or auto-installs if self-healing mode is enabled)
3. **Adapts** its strategy with fallback mechanisms

```bash
# Enable self-healing mode
export AEGIS_SELF_HEALING=true
```

---

## 🎯 What Makes Aegis Unique

### Zero-Day Capabilities (Genesis Fuzzer)

Unlike traditional scanners that match CVE signatures, **Aegis discovers unknown vulnerabilities** through intelligent mutation:

- **Evolutionary Genetic Fuzzing** — Byte-level mutations with feedback loops
- **Differential Analysis** — Levenshtein distance, timing analysis, structure comparison
- **Context-Aware Mutations** — Technology fingerprinting enables framework-specific payloads
- **7 Mutation Strategies** — Integer overflow, format strings, boundary violations, etc.

### Visual-Cognitive Engine (Set-of-Mark)

Aegis employs **Set-of-Mark (SoM)** visual grounding technology:

- **Visual Element Tagging** — Numbered badges overlay every clickable element
- **Precise UI Navigation** — Click elements by SoM ID
- **SPA Detection** — Automatic re-capture after client-side navigation
- **DOM Obfuscation Bypass** — Works when React/Vue/Angular obscure the DOM

### Self-Healing Infrastructure

Automatic dependency management:

- **Playwright Auto-Install** — Runs `playwright install chromium` if needed
- **Tool Discovery** — Scans PATH for security tools
- **Graceful Degradation** — Continues with available tools

---

## 🏗️ Architecture Overview (v9.0)

```
┌─────────────────────────────────────────────────────────────┐
│                    AEGIS AGENT v9.0                         │
├─────────────────────────────────────────────────────────────┤
│  ┌────────────────────────┐  ┌─────────────────────────┐    │
│  │      Main LLM          │  │    Visual LLM           │    │
│  │    (DeepSeek R1)       │  │  (Qwen 2.5 VL)          │    │
│  │  ALL Tasks:            │  │  Images/Screenshots     │    │
│  │  - Planning            │  │  Only                   │    │
│  │  - Analysis            │  │                         │    │
│  │  - Code Gen            │  │                         │    │
│  │  - Exploitation        │  │                         │    │
│  └───────────┬────────────┘  └───────────┬─────────────┘    │
│              └──────────────┬────────────┘                   │
│                             ▼                                │
│              ┌───────────────────────┐                       │
│              │  Unified Orchestrator  │                       │
│              │  (Persistent Session)  │                       │
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
nano .env  # Add your OpenRouter API key

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

## 🔧 Configuration

### Environment Variables

```bash
# API Keys (required)
OPENROUTER_API_KEY=your_main_key       # Master key

# Model Selection (v9.0 unified)
MAIN_MODEL=deepseek/deepseek-r1        # Single LLM for all tasks
VISUAL_MODEL=qwen/qwen2.5-vl-32b-instruct:free  # Images only

# Generation Parameters
DEFAULT_TEMPERATURE=0.7
DEFAULT_MAX_TOKENS=8192                # Higher for DeepSeek R1 reasoning
```

---

## 🛡️ Safety & Authorization

### Mandatory Authorization
Use Aegis **only** against systems you:
- Explicitly own, OR
- Have written authorization to test

### Human-in-the-Loop
- **Reconnaissance** — Auto-approved (passive)
- **Exploitation** — Requires explicit human approval
- **High-Risk Actions** — Always confirmed before execution

---

## 📚 Documentation

- [V7_5_FEATURES.md](V7_5_FEATURES.md) — Feature documentation
- [ARCHITECTURE.md](ARCHITECTURE.md) — Technical architecture overview
- [QUICK_START_V7_5.md](QUICK_START_V7_5.md) — Getting started guide

---

## 🧪 Testing

```bash
# Run demonstration
python demo_v7_5_integration.py
```

---

## 📝 License

This project is provided for educational and authorized security testing purposes only. See LICENSE for details.

---

**Built for security researchers who demand more than signature matching.**
