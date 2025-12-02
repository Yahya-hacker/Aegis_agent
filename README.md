# Aegis Agent v8.0 — Full-Spectrum Cyber Operations Platform

**Aegis Agent** is an AI-powered autonomous penetration testing platform that transforms from traditional vulnerability scanning into an intelligent zero-day research system. Built with a multi-LLM architecture and advanced exploitation capabilities, it discovers vulnerabilities through generative fuzzing, state-aware navigation, and deep protocol analysis.

**v8.0 NEW:** Full-Spectrum CTF & Red Team Operations with autonomous self-healing capabilities.

> ⚠️ **AUTHORIZED USE ONLY**: This tool is designed for professional penetration testers and security researchers. Always obtain explicit written permission before testing any system. Unauthorized testing is illegal.

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
