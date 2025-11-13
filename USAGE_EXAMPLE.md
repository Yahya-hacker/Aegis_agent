# Usage Example: Enhanced Aegis Agent

This document demonstrates how the new reasoning display and keep-alive features work in practice.

## Starting the Agent

When you run `python main.py`, you'll now see:

```
🚀 Démarrage de l'Agent Autonome Aegis AI avec Multi-LLM...
📋 LLMs configurés:
   • Llama 70B: Planification stratégique et triage
   • Mixtral 8x7B: Analyse de vulnérabilités et exploitation
   • Qwen-coder: Analyse de code et génération de payloads
🔋 Keep-alive mechanism activated (prevents terminal sleep)

🛡️  AEGIS AI - AGENT AUTONOME DE PENTEST (v6.0 - Multi-LLM)
=============================================================
🤖 Cerveaux Multi-LLM via Together AI:
   • Llama 70B:     Planification stratégique et triage
   • Mixtral 8x7B:  Analyse vulnérabilités et exploitation
   • Qwen-coder:    Analyse code et génération de payloads
🛠️  Mode:   Autonome (Human-in-the-Loop)
🔥 Cap.:   Analyse règles, Raisonnement multi-agent, Auto-apprentissage

🧑‍💻 VOUS:
```

## Example Session: Scanning a Target

### User Input
```
scan example.com
```

### Agent Reasoning Display

The agent now shows its complete thought process:

```
────────────────────────────────────────────────────────────────────────────────
🧠 STRATEGIC [2025-11-13 18:30:15]
────────────────────────────────────────────────────────────────────────────────
Analyzing conversation to determine mission readiness

Metadata:
  • conversation_length: 1
  • function: triage_mission
────────────────────────────────────────────────────────────────────────────────
```

### LLM Interaction

Every LLM call is shown in detail:

```
════════════════════════════════════════════════════════════════════════════════
🤖 LLM INTERACTION: Strategic Planner & Triage Agent [2025-11-13 18:30:17]
════════════════════════════════════════════════════════════════════════════════

📤 PROMPT:
┌──────────────────────────────────────────────────────────────────────────────┐
│ Conversation history:                                                         │
│ user: scan example.com                                                        │
│                                                                               │
│ Analyze this conversation and determine if we have all information           │
│ (target and rules) to start the mission. Respond with the appropriate JSON.  │
└──────────────────────────────────────────────────────────────────────────────┘

📥 RESPONSE:
┌──────────────────────────────────────────────────────────────────────────────┐
│ ```json                                                                       │
│ {                                                                             │
│   "response_type": "question",                                                │
│   "text": "I need more information. Please provide the bug bounty program    │
│   rules and scope for example.com"                                           │
│ }                                                                             │
│ ```                                                                           │
└──────────────────────────────────────────────────────────────────────────────┘

📊 METADATA:
  • model: meta-llama/Llama-3-70b-chat-hf
  • usage: {'prompt_tokens': 156, 'completion_tokens': 45, 'total_tokens': 201}
  • temperature: 0.7
  • max_tokens: 1024
════════════════════════════════════════════════════════════════════════════════
```

### Decision Display

```
────────────────────────────────────────────────────────────────────────────────
✅ DECISION [2025-11-13 18:30:18]
────────────────────────────────────────────────────────────────────────────────
Triage decision: question

Metadata:
  • response_type: question
  • text: I need more information. Please provide the bug bounty program rules...
────────────────────────────────────────────────────────────────────────────────
```

### Autonomous Loop Reasoning

When the mission starts, each step shows detailed reasoning:

```
======================================================================
🧠 ÉTAPE D'AGENT 1/20

────────────────────────────────────────────────────────────────────────────────
📋 PLANNING [2025-11-13 18:32:10]
────────────────────────────────────────────────────────────────────────────────
Starting autonomous step 1 of 20

Metadata:
  • step: 1
  • total_steps: 20
  • memory_size: 1
  • findings_count: 0
────────────────────────────────────────────────────────────────────────────────

🧠 Aegis AI réfléchit...

────────────────────────────────────────────────────────────────────────────────
🔍 ANALYSIS [2025-11-13 18:32:11]
────────────────────────────────────────────────────────────────────────────────
Agent is analyzing current state and determining next action
────────────────────────────────────────────────────────────────────────────────
```

### LLM Selection Reasoning

```
────────────────────────────────────────────────────────────────────────────────
✅ DECISION [2025-11-13 18:32:12]
────────────────────────────────────────────────────────────────────────────────
Selected Vulnerability Analyst & Exploitation Expert for task type 'next_action'

Metadata:
  • task_type: next_action
  • selected_llm: vulnerability
  • model: mistralai/Mixtral-8x7B-Instruct-v0.1
  • specialization: ['vulnerability_analysis', 'exploit_planning', ...]
────────────────────────────────────────────────────────────────────────────────
```

### Action Proposal with Reasoning

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                               🎯 ACTION PROPOSAL                               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Tool:                        subdomain_enumeration                          ║
║ Arguments:                                                                        ║
║   • domain: example.com                                                      ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Reasoning:                                                                      ║
║ Based on the mission rules and current state, subdomain enumeration is the  ║
║ logical first step. This will:                                               ║
║ 1. Discover the full attack surface within scope                            ║
║ 2. Identify potential targets for deeper analysis                           ║
║ 3. Follow the standard reconnaissance methodology                           ║
║ 4. Provide a foundation for subsequent vulnerability testing                ║
║                                                                              ║
║ This action maximizes detection chances by ensuring comprehensive coverage  ║
║ of the target domain while respecting the defined scope boundaries.         ║
╚══════════════════════════════════════════════════════════════════════════════╝

🤖 PROPOSITION IA : {'tool': 'subdomain_enumeration', 'args': {'domain': 'example.com'}, ...}
❓ Approuvez-vous cette action ? (o/n/q) :
```

### Execution and Observation

When user approves:

```
────────────────────────────────────────────────────────────────────────────────
🚀 EXECUTION [2025-11-13 18:33:45]
────────────────────────────────────────────────────────────────────────────────
Executing approved action: subdomain_enumeration

Metadata:
  • tool: subdomain_enumeration
  • args: {'domain': 'example.com'}
────────────────────────────────────────────────────────────────────────────────

🚀 Exécution : subdomain_enumeration...
📝 Résultat : success

────────────────────────────────────────────────────────────────────────────────
👁️ OBSERVATION [2025-11-13 18:34:02]
────────────────────────────────────────────────────────────────────────────────
Action subdomain_enumeration réussie. 15 résultats trouvés.
Voici les 10 premiers: ["api.example.com", "dev.example.com", ...]

Metadata:
  • action: subdomain_enumeration
  • status: success
  • results_count: 15
────────────────────────────────────────────────────────────────────────────────
```

### Error Handling

If an action fails:

```
────────────────────────────────────────────────────────────────────────────────
❌ ERROR [2025-11-13 18:35:20]
────────────────────────────────────────────────────────────────────────────────
Action port_scanning failed: Connection timeout

Metadata:
  • action: port_scanning
  • error: Connection timeout
────────────────────────────────────────────────────────────────────────────────
```

### Warning Display

```
────────────────────────────────────────────────────────────────────────────────
⚠️ WARNING [2025-11-13 18:36:10]
────────────────────────────────────────────────────────────────────────────────
Could not parse as JSON, treating as conversational response

Metadata:
  • raw_response: The target appears to be...
────────────────────────────────────────────────────────────────────────────────
```

## Keep-Alive in Action

While the agent runs, the keep-alive mechanism works silently in the background:

```
🔋 Keep-alive mechanism activated (prevents terminal sleep)
[Agent runs for hours without interruption]
...
🔋 Keep-alive mechanism stopped
```

You can check the keep-alive status:

```python
from utils.keep_alive import get_keep_alive_status

status = get_keep_alive_status()
print(status)
# {'running': True, 'elapsed_seconds': 3600, 'heartbeat_count': 60, 'interval': 60}
```

## Exit

When the agent exits:

```
🛡️  Session Aegis AI terminée par l'utilisateur.
🔋 Keep-alive mechanism stopped
```

## Reasoning Log Export

After the session, you can export the complete reasoning log:

```python
from utils.reasoning_display import get_reasoning_display

display = get_reasoning_display()
display.export_reasoning_log('mission_reasoning.json')
```

This creates a JSON file with every thought, decision, and LLM interaction:

```json
[
  {
    "timestamp": "2025-11-13 18:30:15",
    "type": "strategic",
    "thought": "Analyzing conversation to determine mission readiness",
    "metadata": {
      "conversation_length": 1,
      "function": "triage_mission"
    }
  },
  {
    "timestamp": "2025-11-13 18:30:17",
    "type": "llm_interaction",
    "llm_name": "Strategic Planner & Triage Agent",
    "prompt": "...",
    "response": "...",
    "metadata": {...}
  },
  ...
]
```

## Benefits in Practice

### 1. Transparency
Users can see exactly what the agent is thinking at every step, building trust and understanding.

### 2. Learning
The detailed reasoning serves as an educational tool, teaching penetration testing methodology.

### 3. Debugging
When something goes wrong, the complete reasoning history makes it easy to identify the issue.

### 4. Reliability
The keep-alive mechanism ensures long reconnaissance operations complete without terminal timeout.

### 5. Accountability
Every decision is logged with reasoning, creating a clear audit trail.

## Summary

The enhanced agent provides:
- **Complete transparency** through detailed reasoning display
- **Reliability** through automatic keep-alive
- **Better results** through improved decision-making framework
- **Educational value** through visible pentesting methodology
- **Debugging capability** through comprehensive logging

All while maintaining the same user-friendly interface!
