Aegis Agent — Multi-LLM Pentesting & Ethical Hacking AI Agent (v6.0)

Aegis Agent is an AI-powered autonomous assistant implemented in Python, built specifically to help security researchers, penetration testers, and bug bounty hunters with reconnaissance, vulnerability discovery, exploitation support (POC generation and safe validation), and reporting. It is a tool to accelerate and organize security testing workflows — it does not replace human judgment or authorization.

**NEW in v6.0**: Multi-LLM Architecture using Together AI
- 🧠 **Llama 70B** for strategic planning and triage
- 🎯 **Mixtral 8x7B** for vulnerability analysis and exploitation
- 💻 **Qwen-coder** for code analysis and payload generation

Each LLM is automatically selected based on the task type, providing specialized expertise where it's needed most. See [MULTI_LLM_GUIDE.md](MULTI_LLM_GUIDE.md) for detailed information.

**ENHANCED**: Transparent Reasoning & Reliability Features
- 💭 **Reasoning Display** - See all agent thoughts and decision-making processes in real-time
- 🔋 **Keep-Alive Mechanism** - Prevents terminal from sleeping during long operations
- 🎯 **Enhanced Decision Framework** - Improved sophistication for better detection chances
- 📊 **Comprehensive Logging** - Export reasoning history for analysis and debugging

See [REASONING_FEATURES.md](REASONING_FEATURES.md) for detailed information about these features.

Important statement: this doesn't mean to do what you want — always get explicit authorization before testing any target.

Core capabilities
- Reconnaissance
  - Passive and active asset discovery when configured with approved tools and data sources (subdomain enumeration, port/service discovery, directory and endpoint discovery).
  - OSINT aggregation and context for targets within scope.
- Vulnerability discovery and exploitation support
  - Automates common checks and suggests reproducible proof-of-concept steps (HTTP requests, exploit templates, minimal scripts).
  - Orchestrates external scanners and tools you configure (nmap, ffuf, nikto, ZAP/Burp etc.) and consolidates results for triage.
  - Helps validate and reproduce findings with operator approval before any intrusive actions.
- Rules-of-engagement and scope awareness
  - Designed to respect bug bounty program (BBP) rules and out-of-scope assets when configured with scope lists and policy definitions.
  - Will flag or block actions that target out-of-scope hosts if the configuration is provided.
- Workflow & reporting
  - Plan multi-step engagements (recon → enumeration → validation → report) and maintain short-term context across steps.
  - Produce human-readable reports and exportable artifacts (Markdown, JSON) with reproduction steps, impact, and mitigation suggestions.
- Extensibility
  - Plugin/action architecture for adding custom checks, adapters to new tools, and reporting templates.

Safety, ethics, and legal constraints (must-read)
- Authorization required: Use Aegis Agent only against systems you explicitly own or have written authorization to test (targets enrolled in a bug bounty program with explicit scope, or with a signed engagement). Unauthorized testing is illegal and unethical.
- Operator-in-the-loop: The agent can prepare and suggest commands and PoCs, but any intrusive, destructive, or high-risk action must be explicitly approved by the operator. The agent will not act as a free-running exploit bot.
- Scope enforcement: Configure allowed/blocked targets and program rules before any active scanning. The agent is designed to understand BBP rules when provided but cannot infer authorization by itself.
- Rate limits & safe defaults: Configure request rates, concurrency, and time windows. Review defaults before large runs.
- Data handling: Protect logs, API keys, and stored findings. Do not exfiltrate sensitive data or perform destructive tests unless explicitly permitted.
- Validation: Automated results can include false positives — always validate manually before disclosure.

Usage guidance (recommended safe workflow)
1. Configure scope: Add allowed targets, out-of-scope lists, and program rules in the configuration.
2. Start with passive recon: Let the agent collect OSINT and passive indicators without touching target infrastructure.
3. Review suggested active checks: Inspect and explicitly approve any active scans or intrusive tests.
4. Run validated scans: Execute approved scans with conservative rate limits.
5. Triage and validate: Mark findings as confirmed/false-positive and refine PoCs.
6. Draft report: Use the agent’s generated report templates to prepare responsible disclosure to the program.

Limitations
- Not a substitute for an experienced human pentester — the agent assists and speeds up routine work but cannot fully reason about complex business-logic flaws or nuanced exploit chains.
- Dependent on configured tools and data sources; it cannot invent zero-day exploits on its own.
- Proper configuration is essential to avoid accidental out-of-scope testing.

## Setup & Installation

### Prerequisites
- Python 3.8 or higher
- Together AI API key (get one at https://api.together.xyz/)

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

3. **Configure Together AI API**
```bash
# Copy the example environment file
cp .env.example .env

# Edit .env and add your Together AI API key
nano .env  # or use your preferred editor
```

Add your API key:
```
TOGETHER_API_KEY=your_actual_api_key_here
```

4. **Run Aegis Agent**
```bash
python main.py
```

### Multi-LLM Architecture

Aegis v6.0 uses three specialized LLMs:

- **Llama 70B** (`meta-llama/Llama-3-70b-chat-hf`)
  - Strategic planning, mission triage, scope analysis
  
- **Mixtral 8x7B** (`mistralai/Mixtral-8x7B-Instruct-v0.1`)
  - Vulnerability analysis, exploitation planning, security assessment
  
- **Qwen-coder** (`Qwen/Qwen2.5-Coder-32B-Instruct`)
  - Code analysis, payload generation, technical implementation

The orchestrator automatically selects the best LLM for each task. For detailed information, see [MULTI_LLM_GUIDE.md](MULTI_LLM_GUIDE.md).

### Optional: Install Security Tools

For full functionality, install these security tools:
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

### Configuration

Edit `.env` to customize model selection and parameters:
```bash
# Override default models (optional)
STRATEGIC_MODEL=meta-llama/Llama-3-70b-chat-hf
VULNERABILITY_MODEL=mistralai/Mixtral-8x7B-Instruct-v0.1
CODER_MODEL=Qwen/Qwen2.5-Coder-32B-Instruct

# Adjust generation parameters
DEFAULT_TEMPERATURE=0.7
DEFAULT_MAX_TOKENS=2048
```

## Documentation

- [Multi-LLM Architecture Guide](MULTI_LLM_GUIDE.md) - Detailed guide on the three-LLM system
- [Requirements](requirements.txt) - Python dependencies

