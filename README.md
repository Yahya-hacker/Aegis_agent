
# Aegis Agent v10.0 "Omega" — OODA Loop Enhanced Autonomous Pentesting

**Aegis Agent** is an AI-powered autonomous penetration testing platform featuring **AegisOmega** — a hybrid agent that merges fast LLM reasoning with neuro-symbolic swarm intelligence.

> ⚠️ **AUTHORIZED USE ONLY**: Always obtain explicit written permission before testing any system.

---

## 🚀 What's New in v10.0 "Omega"

### AegisOmega Hybrid Agent
- **OODA Loop Architecture**: Observe → Orient → Decide → Act
- **Epistemic Priority**: Blocks exploitation until 60%+ confidence
- **Adversarial Swarm**: RED/BLUE/JUDGE debate before risky tools
- **Knowledge Graph**: Dynamic attack path mapping
- **Virtual Sandbox**: Pre-compute + verify responses (honeypot detection)
- **Hive Mind**: Multi-session collaboration and knowledge sharing

### Clean Architecture
```
aegis/
├── agent.py            # AegisOmega (OODA Loop)
├── llm.py              # Multi-model LLM interface
├── state.py            # State management
├── knowledge_graph.py  # Attack surface mapping
├── epistemic_priority.py # Confidence gating
├── adversarial_swarm.py  # RED/BLUE debates
├── virtual_sandbox.py    # Pre-compute verification
├── hive_mind.py          # Multi-session collaboration
├── omega_protocol.py     # Unified orchestration
└── tools/
    └── manager.py
```

---

## 🧠 OODA Loop Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AegisOmega Agent                        │
├─────────────────────────────────────────────────────────────┤
│  1. OBSERVE                                                │
│     ├─ Receive tool result                                 │
│     ├─ Query HiveMind for shared knowledge                 │
│     └─ Update KnowledgeGraph                               │
├─────────────────────────────────────────────────────────────┤
│  2. ORIENT                                                 │
│     ├─ Calculate overall confidence                        │
│     ├─ Determine mode: SEARCH / BALANCED / EXPLOIT         │
│     └─ Identify knowledge gaps                             │
├─────────────────────────────────────────────────────────────┤
│  3. DECIDE                                                 │
│     ├─ LLM generates action proposal                       │
│     ├─ If risk > threshold: RED/BLUE/JUDGE debate          │
│     └─ Pre-compute expected response (VirtualSandbox)      │
├─────────────────────────────────────────────────────────────┤
│  4. ACT                                                    │
│     ├─ Run tool via ToolManager                            │
│     ├─ Verify response against prediction                  │
│     ├─ Detect honeypots / anomalies                        │
│     └─ Share discoveries with HiveMind                     │
└─────────────────────────────────────────────────────────────┘
```

---

## 🌐 Omega Protocol Components

| Component | Description |
|-----------|-------------|
| **Knowledge Graph** | Graph-native attack surface mapping with nodes (Assets, Tech, Creds) and edges (Attack Paths) |
| **Adversarial Swarm** | Internal debate: RED (attack), BLUE (defend), JUDGE (synthesize) |
| **Epistemic Priority** | Confidence-based mode shifting; blocks exploits until confidence ≥ 60% |
| **Virtual Sandbox** | Pre-compute predictions, verify responses, detect honeypots |
| **Hive Mind** | Share discoveries (WAF bypasses, vulns) across agent sessions |

### Epistemic Mode Shifting

```
Mode: SEARCH (Confidence: 45%)
├─ Allowed: recon tools only
├─ Blocked: SQLMap, XSS tests, exploitation
└─ Focus: Gather intel to increase confidence

Mode: EXPLOIT (Confidence: 72%)
├─ Allowed: all tools
├─ Swarm: debates risky actions
└─ Focus: Validate vulnerabilities
```

### Adversarial Swarm Protocol

```
[DEBATE] Tool: sql_injection_test
  🔴 RED: Use aggressive SQLMap with all payloads
  🔵 BLUE: Cloudflare WAF detected, will block aggressive scans
  ⚖️ JUDGE: Execute stealth variant with URL encoding + 2s delays
  ✅ APPROVED with modifications
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- OpenRouter API key ([get one here](https://openrouter.ai/))

### Installation

```bash
# Clone and install
git clone https://github.com/Yahya-hacker/Aegis_agent.git
cd Aegis_agent
pip install -r requirements.txt

# Configure
cp .env.example .env
nano .env  # Add OPENROUTER_API_KEY

# Run
python server.py
# → Backend: http://localhost:8000
# → API: http://localhost:8000/api/status
```

### Start a Mission

```bash
curl -X POST http://localhost:8000/api/mission/start \
  -H "Content-Type: application/json" \
  -d '{"target": "testphp.vulnweb.com"}'
```

---

## ⚙️ Configuration

```bash
# Required
OPENROUTER_API_KEY=your_key

# Models
STRATEGIC_MODEL=deepseek/deepseek-r1
REASONING_MODEL=deepseek/deepseek-r1
CODE_MODEL=qwen/qwen-2.5-72b-instruct

# Server
HOST=0.0.0.0
PORT=8000
```

---

## 🔧 Python API

```python
from aegis import get_agent, get_knowledge_graph, get_epistemic_manager

# Get agent
agent = get_agent()

# Start mission
mission_id = await agent.start_mission(
    target="example.com",
    rules="Standard pentest"
)

# Check status
status = agent.get_status()
# {
#   "running": True,
#   "confidence": 0.65,
#   "mode": "balanced",
#   "graph_nodes": 12,
#   "attack_paths": 3
# }

# Get knowledge graph
graph = get_knowledge_graph()
paths = graph.find_attack_paths()

# Check epistemic state
epistemic = get_epistemic_manager()
gaps = epistemic.get_knowledge_gaps()
```

---

## 🛡️ Safety

- **Mode Gating**: Exploitation blocked until 60%+ confidence
- **Swarm Debates**: High-risk tools require RED/BLUE/JUDGE approval
- **Honeypot Detection**: Virtual sandbox flags anomalous responses
- **Rate Limiting**: Default 2s delay between tool calls

---

## 📁 Project Structure

```
Aegis_agent/
├── aegis/              # Core package
│   ├── agent.py        # AegisOmega (main agent)
│   ├── llm.py          # LLM interface
│   ├── state.py        # State management
│   ├── knowledge_graph.py
│   ├── epistemic_priority.py
│   ├── adversarial_swarm.py
│   ├── virtual_sandbox.py
│   ├── hive_mind.py
│   └── omega_protocol.py
├── tools/              # Tool implementations
├── server.py           # FastAPI backend
└── web/                # React frontend
```

---

## 📝 License

For educational and authorized security testing only.

---

**Built for security researchers who demand intelligent, adaptive, and collaborative agents.**
