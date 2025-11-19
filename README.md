# Aegis Agent v7.5 — "Architect" Zero-Day Research Platform

**Aegis Agent** is an AI-powered autonomous penetration testing assistant that transforms from a traditional tool orchestrator into an intelligent zero-day researcher. Built with a multi-LLM architecture and advanced exploitation capabilities, it helps security researchers, penetration testers, and bug bounty hunters discover vulnerabilities through generative fuzzing, state-aware navigation, and deep protocol analysis.

> ⚠️ **Important**: This tool is for authorized security testing only. Always obtain explicit written permission before testing any system. Unauthorized testing is illegal and unethical.

## 🎯 What Makes v7.5 "Architect" Unique

Aegis v7.5 goes beyond traditional security scanners by **generating** vulnerabilities instead of just matching signatures:

- 🧬 **Genesis Protocol Fuzzer** - Grammar-based mutation engine finds zero-days through intelligent protocol breaking
- 🧠 **Cortex Graph Memory** - State-aware navigation with algorithmic backtracking prevents context loss
- 🔍 **Deep Dive CDP Interceptor** - JavaScript sink detection discovers invisible DOM-based XSS
- ⏱️ **Chronos Concurrency Engine** - Race condition detection using synchronization barriers
- 🪞 **Mirror JS Sandbox** - Execute target's JavaScript to bypass client-side validation
- 📡 **Echo OOB Correlator** - Detect blind vulnerabilities through out-of-band callbacks

## 🏗️ Multi-LLM Architecture

Aegis uses three specialized AI models via OpenRouter API, each optimized for specific security tasks:

- **Hermes 3 Llama 70B** - Strategic planning, mission triage, and scope analysis
- **Dolphin 3.0 R1 Mistral 24B** - Vulnerability analysis and exploitation planning  
- **Qwen 2.5 72B** - Code analysis and payload generation

The orchestrator automatically selects the optimal model for each task. See [MULTI_LLM_GUIDE.md](MULTI_LLM_GUIDE.md) for details.

## 🚀 Core Capabilities

### Zero-Day Discovery
- **Grammar-based fuzzing** generates thousands of protocol mutations to find logic flaws
- **7 mutation strategies**: bit flips, integer overflow, format strings, boundary violations, unicode/encoding edge cases, null byte injection, command injection
- **Anomaly detection** automatically identifies unusual responses indicating vulnerabilities

### Advanced Exploitation
- **DOM-based XSS detection** via Chrome DevTools Protocol hooking
- **Race condition testing** with synchronized concurrent requests
- **Client-side bypass** by executing target's own JavaScript
- **Blind vulnerability detection** using out-of-band callbacks (DNS, HTTP, SMTP)

### Intelligent Navigation
- **Knowledge graph memory** tracks every state, URL, and action
- **Algorithmic backtracking** recovers from dead ends with untested/successful/nearest strategies
- **Session persistence** survives crashes and enables long-term missions

### Traditional Security Testing
- Automated reconnaissance (subdomain enumeration, port scanning, endpoint discovery)
- Vulnerability scanning with session management for authenticated areas
- Dynamic tool discovery and semi-autonomous operation
- Visual grounding (Set-of-Mark) for web UI interaction

## 📋 Setup & Installation

### Prerequisites
- Python 3.8 or higher
- OpenRouter API key (get one at https://openrouter.ai/)
- Node.js (for Mirror JS Sandbox)

### Quick Start

1. **Clone the repository**
```bash
git clone https://github.com/Yahya-hacker/Aegis_agent.git
cd Aegis_agent
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Configure OpenRouter API**
```bash
cp .env.example .env
nano .env  # Add your OpenRouter API key
```

Add your API key to `.env`:
```
OPENROUTER_API_KEY=your_actual_api_key_here
```

4. **Run Aegis Agent**
```bash
python main.py
```

### Optional Security Tools

For full functionality, install these tools:

```bash
# Subdomain enumeration
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Port scanning
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Vulnerability scanning
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# URL discovery
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest

# HTTP probing
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

## 🔧 Configuration

Edit `.env` to customize model selection and parameters:

```bash
# Model selection (optional overrides)
STRATEGIC_MODEL=nousresearch/hermes-3-llama-3.1-70b
VULNERABILITY_MODEL=cognitivecomputations/dolphin3.0-r1-mistral-24b
CODER_MODEL=qwen/qwen-2.5-72b-instruct

# Generation parameters
DEFAULT_TEMPERATURE=0.7
DEFAULT_MAX_TOKENS=2048
```

## 📖 Key Features in Detail

### Genesis Protocol Fuzzer

Discovers zero-days by breaking protocol grammar instead of matching CVE signatures:

```python
from tools.genesis_fuzzer import get_genesis_fuzzer

fuzzer = get_genesis_fuzzer()
fuzzer.compile_grammar({
    "username": {"type": "string", "max_len": 20},
    "age": {"type": "integer", "min": 0, "max": 120}
})

result = await fuzzer.fuzz_endpoint(
    url="https://api.example.com/register",
    method="POST",
    grammar=grammar,
    base_payload={"username": "admin", "age": 25}
)
```

### Cortex Graph Memory

Eliminates "state amnesia" with knowledge graph navigation:

```python
from agents.enhanced_ai_core import CortexMemory

cortex = CortexMemory(mission_id="pentest_2024")
cortex.record_action(
    action="Navigate to login",
    result={"success_score": 1.0},
    new_url="https://example.com/login"
)

# When stuck, backtrack intelligently
backtrack_node = cortex.find_backtrack_path(heuristic="successful")
```

### Deep Dive CDP Interceptor

Finds DOM XSS invisible to traditional scanners:

```python
from tools.cdp_hooks import get_cdp_hooks

cdp = get_cdp_hooks()
await cdp.initialize(headless=True)

result = await cdp.test_dom_xss(
    url="https://example.com/search?q=test",
    test_payloads=["<img src=x onerror=alert('XSS')>"]
)
```

### Chronos Concurrency Engine

Detects race conditions and TOCTOU bugs:

```python
from tools.race_engine import get_chronos_engine

engine = get_chronos_engine()
result = await engine.execute_race(
    url="https://example.com/api/redeem-coupon",
    method="POST",
    data={"coupon_code": "SAVE50"},
    threads=50
)
```

## 📚 Documentation

- [V7_5_FEATURES.md](V7_5_FEATURES.md) - Comprehensive guide to all v7.5 capabilities
- [MULTI_LLM_GUIDE.md](MULTI_LLM_GUIDE.md) - Multi-LLM architecture details
- [ARCHITECTURE.md](ARCHITECTURE.md) - Technical architecture overview
- [QUICK_START_V7_5.md](QUICK_START_V7_5.md) - Quick start guide for v7.5

## 🧪 Testing

Run the test suite to verify functionality:

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

## 🛡️ Safety & Ethics

### Authorization Required
Use Aegis Agent **only** against systems you:
- Explicitly own, OR
- Have written authorization to test (signed contract, bug bounty program enrollment)

Unauthorized testing is illegal and unethical.

### Operator-in-the-Loop
- The agent prepares and suggests commands and PoCs
- Any intrusive, destructive, or high-risk action requires explicit approval
- The agent will not act as a free-running exploit bot

### Scope Enforcement
- Configure allowed/blocked targets before any active scanning
- Review all actions that target production systems
- The agent understands BBP rules when configured but cannot infer authorization

### Safe Defaults
- Conservative request rates and concurrency limits
- Validation required before disclosure
- Automated results may include false positives — always validate manually

## 📝 Recommended Workflow

1. **Configure scope** - Add allowed targets and out-of-scope lists
2. **Start with passive recon** - Collect OSINT without touching target infrastructure
3. **Review suggested checks** - Inspect and approve any active scans
4. **Run validated scans** - Execute approved tests with conservative rate limits
5. **Triage and validate** - Mark findings as confirmed/false-positive
6. **Draft report** - Use generated templates for responsible disclosure

## ⚠️ Limitations

- Not a substitute for experienced human pentesters
- Assists and speeds up routine work but cannot fully reason about complex business-logic flaws
- Dependent on configured tools and data sources
- Proper configuration essential to avoid out-of-scope testing

## 🤝 Contributing

Contributions are welcome! Please ensure all contributions:
- Follow ethical security research principles
- Include appropriate safety checks
- Are tested with the existing test suite
- Document new features clearly

## 📄 License

This project is provided for educational and authorized security testing purposes only. See LICENSE file for details.

---

**Built with ❤️ for the security research community**
