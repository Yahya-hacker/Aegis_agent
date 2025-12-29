# 🛡️ Aegis AI - Modern Web Interface

A React + TypeScript frontend with a dark "Cyberpunk" theme for the Aegis AI autonomous penetration testing agent.

## Features

### 🎨 Modern Web Interface
- **React + TypeScript Frontend** with dark "Cyberpunk" theme
- **Real-time Chat Interface** for dialoguing with the agent
- **Mode Selector** for instant switching between operation modes
- **Mission Dashboard** with real-time tool status, progress bars, and swarm monitor
- **File Upload Support** for analyzing binaries, documents, PCAPs, and screenshots

### ⚡ Operation Modes

| Mode | Description | Models Used |
|------|-------------|-------------|
| **Fast** | Lightweight, rapid reconnaissance | Llama 3.1 8B, Qwen Coder 7B, DeepSeek VL 7B, Mistral Nemo 12B |
| **Pro** | Full power, recommended for most use cases | Hermes 3 70B, Dolphin 3.0 24B, Qwen 2.5 72B, Qwen VL 32B |
| **Deep-Think** | Maximum reasoning for complex analysis | DeepSeek R1, Qwen 2.5 72B, Qwen VL 32B |

### 🔌 MCP Client Integration
- Dynamic Tool Hot-Plugging via Model Context Protocol
- Connect to Any MCP Server without restarting the agent
- SSE and stdio Transport Support for flexible connectivity
- Unified Tool Registry across all connected servers

### 🧠 OMEGA Protocol: Neuro-Symbolic Swarm Intelligence

The OMEGA Protocol is an advanced cognitive architecture that enhances the agent's reasoning capabilities:

#### Core Components

| Component | Description | Key Features |
|-----------|-------------|--------------|
| **Knowledge Graph** | Graph-native attack surface mapping | Nodes (Assets, Tech, Creds), Edges (Attack Paths), Traversal-based testing |
| **Adversarial Swarm** | Internal debate before risky actions | RED (Attacker), BLUE (Defender), JUDGE (Strategist) |
| **Epistemic Priority** | Confidence-based mode shifting | Blocks exploitation until confidence ≥ 60%, focuses on information gain |
| **Virtual Sandbox** | Safe execution with verification | Pre-compute predictions, halt on >20% deviation, dependency lock |
| **Report Generator** | Multi-format export | JSON, HTML, PDF reports with attack graphs |

### ⚡ Performance Optimizations
- **Memory Compression** to prevent context saturation during long scans
- **Parallel Hypothesis Testing** in KTV Loop (3x faster)
- **Consolidated Server Architecture** (FastAPI + WebSocket)

## Quick Start

### Prerequisites
- Python 3.10+
- Node.js 18+
- npm or yarn

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Yahya-hacker/Aegis_agent.git
   cd Aegis_agent
   ```

2. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env and add your OpenRouter API key
   ```

3. **Start the application**
   ```bash
   ./start_web_ui.sh
   ```

   Or start backend and frontend separately:
   ```bash
   # Terminal 1 - Backend
   ./start_web_ui.sh backend

   # Terminal 2 - Frontend
   ./start_web_ui.sh frontend
   ```

4. **Open the application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Docs: http://localhost:8000/docs

## Architecture

```
Aegis_agent/
├── frontend/              # React frontend
│   ├── src/
│   │   ├── components/    # React components
│   │   │   ├── ChatView.jsx       # Chat interface
│   │   │   ├── Dashboard.jsx      # Mission dashboard
│   │   │   ├── ModeSelector.jsx   # Mode switching
│   │   │   ├── MemoryView.jsx     # Cortex memory
│   │   │   └── ui/                # shadcn/ui components
│   │   ├── data/          # Mock data and configurations
│   │   └── lib/           # Utilities
│   └── package.json
├── backend/               # FastAPI backend
│   ├── server.py          # Main API server
│   └── requirements.txt
├── agents/                # AI agents
├── tools/                 # Security tools
├── utils/                 # Utilities
│   ├── omega_protocol.py      # OMEGA Protocol implementation
│   ├── report_generator.py    # Report generation
│   └── memory_compression.py  # Memory optimization
└── start_web_ui.sh        # Startup script
```

## API Endpoints

### Chat
- `GET /api/chat/history` - Get chat history
- `POST /api/chat/message` - Send a message
- `DELETE /api/chat/history` - Clear chat history

### Modes
- `GET /api/modes` - Get available modes
- `GET /api/modes/{mode_id}` - Get mode details
- `POST /api/modes/select/{mode_id}` - Select a mode

### File Upload
- `POST /api/upload` - Upload a file
- `GET /api/uploads` - List uploaded files

### MCP Servers
- `GET /api/mcp/servers` - List MCP servers
- `POST /api/mcp/servers` - Register a server
- `DELETE /api/mcp/servers/{name}` - Unregister a server
- `POST /api/mcp/connect/{name}` - Connect to a server

### Tools
- `GET /api/tools` - List all tools
- `POST /api/tools` - Register a tool
- `GET /api/tools/categories` - Get tool categories

### Mission
- `GET /api/mission/state` - Get mission state
- `POST /api/mission/start` - Start a mission
- `POST /api/mission/stop` - Stop the mission

### WebSocket
- `WS /ws/{client_id}` - Real-time bidirectional communication

## Report Generation

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

## OMEGA Protocol Usage

### Knowledge Graph
```python
from utils.omega_protocol import get_omega_protocol, NodeType, EdgeType

omega = get_omega_protocol()
omega.activate()

# Add nodes
omega.knowledge_graph.add_node("example.com", NodeType.ASSET)
omega.knowledge_graph.add_node("nginx 1.21", NodeType.TECHNOLOGY)

# Add relationships
omega.knowledge_graph.add_edge(
    "example.com", NodeType.ASSET,
    "nginx 1.21", NodeType.TECHNOLOGY,
    EdgeType.RUNS
)

# Find attack paths
paths = omega.knowledge_graph.find_attack_paths()
```

### Adversarial Swarm
```python
# Actions with risk score > 5 trigger swarm debate
debate_result = await omega.adversarial_swarm.conduct_debate(
    action={"tool": "sqlmap", "args": {"target": "http://example.com"}},
    context="Testing SQL injection vulnerabilities",
    orchestrator=ai_orchestrator
)

# Result includes RED, BLUE, JUDGE perspectives and verdict
if debate_result["verdict"] == "PROCEED":
    # Execute the action
    pass
```

## License

MIT License - See LICENSE file for details.
