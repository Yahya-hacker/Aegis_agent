Aegis Agent — Multi-LLM Pentesting & Ethical Hacking AI Agent (v7.0 - Battle-Ready)

Aegis Agent is an AI-powered autonomous assistant implemented in Python, built specifically to help security researchers, penetration testers, and bug bounty hunters with reconnaissance, vulnerability discovery, exploitation support (POC generation and safe validation), and reporting. It is a tool to accelerate and organize security testing workflows — it does not replace human judgment or authorization.

**🚀 NEW in v7.0 - Battle-Ready Platform**: Major Architectural Improvements
- 🔐 **Authenticated Session Management** - Scan authenticated areas of applications
- 💾 **Mission Database** - Persistent storage prevents duplicate work and enables strategic memory
- 🛠️ **Dynamic Arsenal** - Automatic discovery of available Kali tools, no more hardcoded tool lists
- ⚡ **Semi-Autonomous Mode** - Reconnaissance auto-approved, exploitation requires approval
- 👁️ **Visual Grounding (Set-of-Mark)** - AI can "see" and interact with web UIs by identifying clickable elements
- 🧠 **Blackboard Memory** - Persistent mission knowledge base tracks facts, goals, and discarded attack vectors

See [V5_FEATURES.md](V5_FEATURES.md) for comprehensive documentation on these game-changing features.

**NEW in v6.0**: Multi-LLM Architecture using OpenRouter API
- 🧠 **Hermes 3 Llama 70B** for strategic planning and triage
- 🎯 **Dolphin 3.0 R1 Mistral 24B** for vulnerability analysis and exploitation
- 💻 **Qwen 2.5 72B** for code analysis and payload generation

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
  - **NEW**: Automatic tool discovery and semi-autonomous reconnaissance mode.
- Vulnerability discovery and exploitation support
  - Automates common checks and suggests reproducible proof-of-concept steps (HTTP requests, exploit templates, minimal scripts).
  - Orchestrates external scanners and tools you configure (nmap, ffuf, nikto, ZAP/Burp etc.) and consolidates results for triage.
  - Helps validate and reproduce findings with operator approval before any intrusive actions.
  - **NEW**: Can scan authenticated areas using session management.
- Rules-of-engagement and scope awareness
  - Designed to respect bug bounty program (BBP) rules and out-of-scope assets when configured with scope lists and policy definitions.
  - Will flag or block actions that target out-of-scope hosts if the configuration is provided.
- Workflow & reporting
  - Plan multi-step engagements (recon → enumeration → validation → report) and maintain short-term context across steps.
  - Produce human-readable reports and exportable artifacts (Markdown, JSON) with reproduction steps, impact, and mitigation suggestions.
  - **NEW**: Mission database tracks all findings and scanned targets to prevent duplicate work.
- Extensibility
  - Plugin/action architecture for adding custom checks, adapters to new tools, and reporting templates.
  - **NEW**: JSON-based tool manifest makes adding new tools trivial.

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
- OpenRouter API key (get one at https://openrouter.ai/)

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
# Copy the example environment file
cp .env.example .env

# Edit .env and add your OpenRouter API key
nano .env  # or use your preferred editor
```

Add your API key:
```
OPENROUTER_API_KEY=your_actual_api_key_here
```

4. **Run Aegis Agent**
```bash
python main.py
```

### Multi-LLM Architecture

Aegis v6.0 uses three specialized LLMs via OpenRouter:

- **Hermes 3 Llama 70B** (`nousresearch/hermes-3-llama-3.1-70b`)
  - Strategic planning, mission triage, scope analysis
  
- **Dolphin 3.0 R1 Mistral 24B** (`cognitivecomputations/dolphin3.0-r1-mistral-24b`)
  - Vulnerability analysis, exploitation planning, security assessment
  
- **Qwen 2.5 72B** (`qwen/qwen-2.5-72b-instruct`)
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
STRATEGIC_MODEL=nousresearch/hermes-3-llama-3.1-70b
VULNERABILITY_MODEL=cognitivecomputations/dolphin3.0-r1-mistral-24b
CODER_MODEL=qwen/qwen-2.5-72b-instruct

# Adjust generation parameters
DEFAULT_TEMPERATURE=0.7
DEFAULT_MAX_TOKENS=2048
```

## Advanced Features

### Visual Grounding with Set-of-Mark (SoM)

Aegis Agent can now "see" and interact with web interfaces using Set-of-Mark visual grounding:

**How it works:**
1. The agent captures a screenshot with numbered red badges overlaid on all clickable elements (links, buttons, inputs)
2. Each element is assigned a unique ID and the system stores a mapping of {ID: selector}
3. The AI analyzes the screenshot and identifies which element to interact with
4. The agent clicks the specific element using its ID, and the system automatically uses the stored selector

**Available tools:**
- `capture_screenshot_som(url)` - Capture screenshot with numbered badges on clickable elements
- `click_element_by_id(url, element_id)` - Click a specific element using its SoM ID
- `visual_screenshot(url)` - Regular screenshot without SoM badges

**Use cases:**
- Navigate complex multi-step workflows
- Test authentication flows and form submissions
- Identify and interact with hidden or dynamically generated UI elements
- Validate UI-based security controls

### Blackboard Memory System

The Blackboard Memory system provides persistent mission knowledge across the entire session:

**Components:**
- **Verified Facts**: Ground truths discovered and confirmed (e.g., "Port 443 is open", "WordPress 5.8 detected")
- **Pending Goals**: Objectives to achieve, prioritized (e.g., "Test admin panel for weak credentials")
- **Discarded Vectors**: Attack paths already tried and failed (e.g., "SQL injection in search - WAF blocked")

**How it works:**
1. After every tool execution, the AI automatically extracts facts, goals, and discarded vectors
2. The blackboard is updated with new knowledge
3. The blackboard summary is included in the AI's context for every decision
4. All data persists to disk and survives across sessions

**Benefits:**
- Prevents duplicate work and wasted effort
- Maintains strategic memory of what has been tried
- Enables the AI to learn and adapt during long missions
- Provides clear mission status at any point

**File location:** Blackboard data is stored in `data/blackboard_<mission_id>.json`

## Documentation

- [Multi-LLM Architecture Guide](MULTI_LLM_GUIDE.md) - Detailed guide on the three-LLM system
- [Requirements](requirements.txt) - Python dependencies

