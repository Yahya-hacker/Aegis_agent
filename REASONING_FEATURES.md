# Enhanced Reasoning and Keep-Alive Features

This document describes the new features added to Aegis Agent to improve robustness, transparency, and reliability.

## Overview

Aegis Agent has been enhanced with two major features:

1. **Transparent Reasoning Display** - Shows all internal thoughts and decision-making processes
2. **Keep-Alive Mechanism** - Prevents terminal from sleeping during long operations

## Features

### 1. Transparent Reasoning Display

The agent now displays its complete reasoning process, making it easy to understand:
- What the agent is thinking
- Why it makes specific decisions
- What information it's processing
- How it analyzes results

#### Types of Reasoning Displayed

The reasoning display categorizes thoughts into different types:

- **Strategic** 🧠 - High-level planning and mission strategy
- **Tactical** ⚡ - Specific action decisions and immediate steps
- **Analysis** 🔍 - Data analysis and pattern recognition
- **Decision** ✅ - Final decisions and action selection
- **Observation** 👁️ - Results and findings from actions
- **Planning** 📋 - Mission planning and task organization
- **Execution** 🚀 - Action execution status
- **LLM Interaction** 🤖 - Complete LLM prompts and responses
- **Error** ❌ - Error conditions and failures
- **Warning** ⚠️ - Warnings and important notices

#### Example Output

```
────────────────────────────────────────────────────────────────────────────────
🧠 STRATEGIC [2025-11-13 18:20:32]
────────────────────────────────────────────────────────────────────────────────
Analyzing target scope and determining initial reconnaissance strategy

Metadata:
  • target: example.com
  • scope: ["*.example.com"]
  • out_of_scope: ["admin.example.com"]
────────────────────────────────────────────────────────────────────────────────
```

#### LLM Interaction Display

Every interaction with the three specialized LLMs is displayed in detail:

```
════════════════════════════════════════════════════════════════════════════════
🤖 LLM INTERACTION: Mixtral 8x7B (Vulnerability Analyst) [2025-11-13 18:20:35]
════════════════════════════════════════════════════════════════════════════════

📤 PROMPT:
┌──────────────────────────────────────────────────────────────────────────────┐
│ What should be the next step after discovering these subdomains?             │
└──────────────────────────────────────────────────────────────────────────────┘

📥 RESPONSE:
┌──────────────────────────────────────────────────────────────────────────────┐
│ Based on the discovered subdomains, I recommend:                             │
│ 1. Perform technology detection on each subdomain                            │
│ 2. Focus on dev.example.com as it may have weaker security                   │
│ 3. Check for common vulnerabilities in the identified services               │
└──────────────────────────────────────────────────────────────────────────────┘

📊 METADATA:
  • model: mistralai/Mixtral-8x7B-Instruct-v0.1
  • temperature: 0.7
  • tokens_used: 150
════════════════════════════════════════════════════════════════════════════════
```

#### Action Proposals

Every action the agent proposes is displayed with full reasoning:

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                               🎯 ACTION PROPOSAL                               ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Tool:                            tech_detection                             ║
║ Arguments:                                                                        ║
║   • target: dev.example.com                                                  ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Reasoning:                                                                      ║
║ Development subdomains often have different technology stacks and may expose ║
║ more information. This will help identify potential attack vectors and       ║
║ vulnerable components.                                                       ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### 2. Keep-Alive Mechanism

The keep-alive mechanism prevents the terminal from sleeping or timing out during long operations.

#### Features

- **Automatic Activation** - Starts automatically when the agent launches
- **Silent Operation** - Runs in the background without cluttering output
- **Configurable Interval** - Default 60 seconds between heartbeats
- **Multiple Methods** - Uses multiple techniques to keep the session active:
  - Stdout activity
  - Process title updates (Linux/Unix)
  - Marker file updates

#### Status Information

The keep-alive mechanism tracks:
- Running status
- Elapsed time
- Number of heartbeats sent
- Heartbeat interval

#### Usage

The keep-alive mechanism is automatically enabled in `main.py`:

```python
from utils.keep_alive import start_keep_alive, stop_keep_alive

# Start keep-alive (runs automatically)
keep_alive = start_keep_alive(interval=60)

try:
    # Your agent operations here
    await conversation.start()
finally:
    # Cleanup on exit
    stop_keep_alive()
```

You can also use it manually:

```python
from utils.keep_alive import KeepAlive

# Method 1: Direct control
keep_alive = KeepAlive(interval=60)
keep_alive.start()
# ... do work ...
keep_alive.stop()

# Method 2: Context manager
with KeepAlive(interval=60) as keep_alive:
    # ... do work ...
    status = keep_alive.get_status()
    print(status)
```

## Enhanced Agent Sophistication

### Improved Decision Making

The agent now uses an enhanced reasoning framework for deciding actions:

1. **Analysis Phase** - Thoroughly analyzes what has been done and what remains
2. **Strategic Thinking** - Considers multiple approaches and evaluates options
3. **Comprehensive Coverage** - Ensures thorough testing of all attack surfaces
4. **Decision Making** - Chooses the optimal action with clear reasoning

### Better Detection Chances

The enhancements improve vulnerability detection through:

- **Detailed reasoning** - Every decision is explained and justified
- **Multi-perspective analysis** - Three specialized LLMs provide different viewpoints
- **Comprehensive exploration** - Better coverage of attack surfaces
- **Pattern learning** - Incorporates learned patterns from previous missions
- **Methodical approach** - Follows logical progression for better results

## Programmatic Access

### Reasoning Display API

```python
from utils.reasoning_display import get_reasoning_display

# Get the global reasoning display
display = get_reasoning_display(verbose=True)

# Show different types of thoughts
display.show_thought("Analyzing target", thought_type="strategic", metadata={...})
display.show_llm_interaction(llm_name, prompt, response, metadata={...})
display.show_action_proposal(action, reasoning)
display.show_step_summary(step_number, total_steps, status, summary)

# Export reasoning log
display.export_reasoning_log("/path/to/log.json")

# Get reasoning history
history = display.get_reasoning_history()
```

### Keep-Alive API

```python
from utils.keep_alive import start_keep_alive, stop_keep_alive, get_keep_alive_status

# Start global keep-alive
keep_alive = start_keep_alive(interval=60)

# Check status
status = get_keep_alive_status()
print(f"Running: {status['running']}, Heartbeats: {status['heartbeat_count']}")

# Stop keep-alive
stop_keep_alive()
```

## Testing

Test the new features:

```bash
# Test reasoning display and keep-alive
python test_reasoning_display.py
```

This will demonstrate:
- All types of reasoning display
- LLM interaction formatting
- Action proposal display
- Keep-alive mechanism
- Reasoning log export

## Benefits

### For Users

- **Transparency** - See exactly what the agent is thinking
- **Trust** - Understand why decisions are made
- **Learning** - Educational view into pentesting methodology
- **Debugging** - Easier to identify issues or incorrect reasoning
- **Reliability** - No more interrupted operations due to terminal timeout

### For Developers

- **Debugging** - Detailed logs of agent reasoning
- **Monitoring** - Track agent decision-making process
- **Analysis** - Export and analyze reasoning patterns
- **Integration** - Easy to integrate reasoning display into new features

## Configuration

### Disable Reasoning Display

To disable verbose output:

```python
from utils.reasoning_display import get_reasoning_display

display = get_reasoning_display(verbose=False)
```

### Adjust Keep-Alive Interval

```python
from utils.keep_alive import start_keep_alive

# More frequent heartbeats (every 30 seconds)
keep_alive = start_keep_alive(interval=30)

# Less frequent heartbeats (every 2 minutes)
keep_alive = start_keep_alive(interval=120)
```

## Logging

All reasoning is logged to:
- Console (if verbose=True)
- `aegis_agent.log` file
- Optional JSON export for analysis

The keep-alive mechanism logs:
- Start/stop events
- Heartbeat activity (debug level)
- Status changes

## Future Enhancements

Potential future improvements:
- Web UI for reasoning display
- Real-time reasoning stream over websockets
- Advanced reasoning analytics
- Reasoning pattern detection
- Adaptive keep-alive based on operation type
