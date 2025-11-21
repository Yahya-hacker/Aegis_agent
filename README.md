# Aegis Agent v7.5 — "Architect" Zero-Day Research Platform

**Aegis Agent** is an AI-powered autonomous penetration testing assistant that transforms from a traditional tool orchestrator into an intelligent zero-day researcher. Built with a multi-LLM architecture and advanced exploitation capabilities, it helps security researchers, penetration testers, and bug bounty hunters discover vulnerabilities through generative fuzzing, state-aware navigation, and deep protocol analysis.

> ⚠️ **Important**: This tool is for authorized security testing only. Always obtain explicit written permission before testing any system. Unauthorized testing is illegal and unethical.

## 🎯 What Makes v7.5 "Architect" Unique

Aegis v7.5 goes beyond traditional security scanners by **generating** vulnerabilities instead of just matching signatures:

- 🧬 **Zero-Day Discovery Engine (Genesis)** - Grammar-based protocol fuzzer discovers integer overflows, logic errors, race conditions, and format string injections through intelligent mutation
- 🧠 **Cortex Graph Memory (Blackboard Architecture)** - Separates verified facts from strategic goals to maintain infinite context during long campaigns
- 🔍 **Deep Dive CDP Interceptor** - JavaScript sink detection discovers invisible DOM-based XSS
- ⏱️ **Chronos Concurrency Engine** - Race condition detection using synchronization barriers
- 👁️ **Visual-Cognitive Architecture (Set-of-Mark)** - Hacks complex SPAs (React/Vue) by "seeing" and tagging interactive elements, bypassing DOM obfuscation
- 🪞 **Mirror JS Sandbox** - Execute target's JavaScript to bypass client-side validation
- 📡 **Echo OOB Correlator** - Detect blind vulnerabilities through out-of-band callbacks
- 💰 **Cost & Performance Optimization** - Multi-account key sharding for parallel execution and rate-limit evasion

## 🏗️ Multi-LLM Architecture

Aegis uses **four specialized AI models** via OpenRouter API, each optimized for specific security tasks:

- **Hermes 3 Llama 70B** (Strategic Model) - High-level decision making, mission planning, triage, scope analysis, and risk assessment
- **Dolphin 3.0 R1 Mistral 24B** (Reasoning Model) - Vulnerability analysis, reasoning about exploits, and security assessment
- **Qwen 2.5 72B** (Code Model) - Code analysis, payload generation, script writing, and technical implementation
- **Qwen 2.5 VL 32B** (Visual Model) - Screenshot analysis, UI reconnaissance, and visual vulnerability detection through multimodal analysis

**🎯 Key Innovation: Multi-Account API Key Sharding**

All models support **separate API keys per role**, enabling:
- **Parallel execution** across different OpenRouter accounts to bypass global rate limits
- **Cost tracking** by isolating spending for each capability (strategy, reasoning, coding, vision)
- **Budget control** with independent usage limits per model type
- **Rate limit evasion** by distributing requests across multiple accounts

**Environment-Based Configuration**

All models are **100% configurable via the `.env` file** - no need to edit Python code! Simply change the model identifiers in your `.env` file to use any model available on OpenRouter. This makes it easy to:
- Test different models for optimal performance
- Use specialized models for specific tasks
- Adapt to new models as they become available
- Control costs by using different model tiers

The orchestrator automatically selects the optimal model for each task. See [MULTI_LLM_GUIDE.md](MULTI_LLM_GUIDE.md) for details.

## 🚀 Core Capabilities

### Zero-Day Discovery Engine (Genesis)

The Genesis engine is a **grammar-based protocol fuzzer** that goes beyond traditional signature matching. Instead of searching for known vulnerabilities, it generates mutations based on API documentation analysis to discover previously unknown security flaws:

- **Intelligent Mutation Strategies**: Discovers integer overflows, logic errors, race conditions, and format string injections
- **Protocol Grammar Analysis**: Parses API specifications to understand expected input formats
- **Automated Anomaly Detection**: Identifies unusual responses that indicate potential vulnerabilities
- **7 Advanced Mutation Techniques**: Bit flips, integer overflow triggers, format strings, boundary violations, unicode/encoding edge cases, null byte injection, and command injection patterns

Unlike traditional fuzzers, Genesis understands the semantic meaning of protocol fields and generates context-aware mutations that are more likely to trigger security vulnerabilities.

### Visual-Cognitive Architecture (Set-of-Mark)

Aegis employs **Set-of-Mark (SoM)** technology that enables it to interact with complex single-page applications (React, Vue, Angular) by processing visual information:

- **Visual Element Tagging**: Automatically identifies and tags interactive elements in screenshots
- **DOM Obfuscation Bypass**: Works even when JavaScript frameworks obscure the traditional DOM structure
- **SPA Navigation**: Successfully navigates modern web applications that heavily rely on client-side routing
- **Interactive Element Detection**: Recognizes buttons, forms, links, and other UI components through computer vision
- **Visual Vulnerability Detection**: Identifies security issues by analyzing UI behavior and visual feedback

This visual-cognitive approach allows Aegis to test applications that are difficult or impossible to analyze using traditional DOM-based tools.

### Blackboard Memory System

The **Blackboard Architecture** separates knowledge into distinct categories to maintain context during long-running security campaigns:

- **Verified Facts Storage**: Maintains a persistent database of confirmed vulnerabilities and system behaviors
- **Strategic Goals Tracking**: Keeps mission objectives separate from tactical findings
- **Infinite Context Maintenance**: Survives crashes, restarts, and long-duration missions without losing critical information
- **Knowledge Graph Navigation**: Links related findings and tracks exploration paths through tested targets
- **Session Persistence**: Enables multi-day campaigns with automatic state recovery

This architecture solves the "context amnesia" problem common in AI-driven testing, ensuring that insights from earlier phases inform later exploitation attempts.

### Cost & Performance Optimization

Aegis v7.5 implements **multi-account API key sharding** to overcome rate limits and enable cost tracking:

- **Parallel Execution**: Different model types use separate API keys, allowing simultaneous execution
- **Rate Limit Evasion**: Distribute load across multiple OpenRouter accounts to bypass per-account limits
- **Granular Cost Tracking**: Monitor spending per capability (strategy, reasoning, coding, vision)
- **Budget Control**: Set different usage limits for each model role
- **Account Isolation**: Protect critical operations by isolating them to dedicated API keys

This sophisticated approach enables longer missions and higher throughput while maintaining cost visibility.

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

Aegis Agent v7.5 now supports **full environment-based configuration** - you can easily change any LLM model, temperature, or max_tokens without touching the Python code!

### Quick Configuration

Edit `.env` to customize all models and parameters:

```bash
# OpenRouter API Key (Required)
OPENROUTER_API_KEY=your_actual_api_key_here

# LLM Model Selection (All four models are configurable!)
STRATEGIC_MODEL=nousresearch/hermes-3-llama-3.1-70b
REASONING_MODEL=cognitivecomputations/dolphin3.0-r1-mistral-24b
CODE_MODEL=qwen/qwen-2.5-72b-instruct
VISUAL_MODEL=qwen/qwen2.5-vl-32b-instruct:free

# Generation Parameters (Control LLM behavior)
DEFAULT_TEMPERATURE=0.7        # 0.0=deterministic, 1.0=creative
DEFAULT_MAX_TOKENS=4096        # Maximum response length
```

### Changing Models

To use different models from OpenRouter:

1. Browse available models at https://openrouter.ai/models
2. Copy the model identifier (e.g., `anthropic/claude-3-opus`)
3. Update the corresponding variable in `.env`
4. Restart Aegis Agent - that's it!

**Example - Using Claude 3 Opus for strategic planning:**
```bash
STRATEGIC_MODEL=anthropic/claude-3-opus
```

**Example - Using GPT-4 for code analysis:**
```bash
CODE_MODEL=openai/gpt-4-turbo
```

### Model Roles

Each model has a specialized role in the Aegis architecture:

- **STRATEGIC_MODEL**: High-level decision making, mission planning, triage, scope analysis, and risk assessment
- **REASONING_MODEL**: Vulnerability analysis, reasoning about exploits, and security assessment  
- **CODE_MODEL**: Code analysis, payload generation, script writing, and technical implementation
- **VISUAL_MODEL**: Screenshot analysis, UI reconnaissance, and visual vulnerability detection

### Temperature & Token Configuration

Fine-tune LLM behavior with these parameters:

- **DEFAULT_TEMPERATURE** (0.0 - 1.0):
  - Lower (0.3-0.5): More focused, deterministic, consistent
  - Higher (0.7-0.9): More creative, varied, exploratory
  
- **DEFAULT_MAX_TOKENS** (recommended: 2048-4096):
  - Controls maximum response length
  - Higher values = more detailed responses (but higher cost)
  - 4096 recommended for complex reasoning tasks

### Advanced: Per-Task Temperature Override

While the defaults work well, individual methods can override temperature for specific needs:
- Verification tasks: Lower temperature (0.6) for consistency
- Exploit generation: Default temperature (0.7) for creativity
- Creative brainstorming: Higher temperature (0.8-0.9) for variety

These overrides happen automatically in the code and don't require configuration.

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
