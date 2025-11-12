# Aegis AI v6.0 - Multi-LLM Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         USER INTERFACE                          │
│                    (conversational_agent.py)                    │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ↓
┌─────────────────────────────────────────────────────────────────┐
│                    ENHANCED AI CORE                             │
│                  (enhanced_ai_core.py)                          │
│                                                                 │
│  • Mission Triage                                               │
│  • Agent Decision Making                                        │
│  • Code Analysis                                                │
│  • Payload Generation                                           │
│  • Collaborative Assessment                                     │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ↓
┌─────────────────────────────────────────────────────────────────┐
│                  MULTI-LLM ORCHESTRATOR                         │
│              (multi_llm_orchestrator.py)                        │
│                                                                 │
│  ┌─────────────────────────────────────────────────────┐       │
│  │           INTELLIGENT TASK ROUTER                   │       │
│  │  Automatically selects best LLM for each task       │       │
│  └─────────────────────────────────────────────────────┘       │
│                          │                                      │
│          ┌───────────────┼───────────────┐                     │
│          ↓               ↓               ↓                     │
│    ┌─────────┐     ┌─────────┐    ┌──────────┐               │
│    │ Llama   │     │ Mixtral │    │  Qwen    │               │
│    │  70B    │     │ 8x7B    │    │  Coder   │               │
│    └─────────┘     └─────────┘    └──────────┘               │
│         │               │               │                      │
│         └───────────────┴───────────────┘                      │
│                         │                                      │
└─────────────────────────┼──────────────────────────────────────┘
                          │
                          ↓
              ┌───────────────────────┐
              │   TOGETHER AI API     │
              │   api.together.xyz    │
              └───────────────────────┘
```

## Component Breakdown

### 1. User Interface Layer

**File**: `conversational_agent.py`

**Responsibilities**:
- Accept user input (natural language)
- Display agent actions for approval
- Coordinate autonomous loop
- Integrate field testing results

**Flow**:
```
User Input → Extract Target → Get BBP Rules → Start Autonomous Loop
```

### 2. Enhanced AI Core

**File**: `enhanced_ai_core.py`

**Key Methods**:

| Method | LLM Used | Purpose |
|--------|----------|---------|
| `triage_mission()` | Llama 70B | Gather mission requirements |
| `get_next_action()` | Mixtral 8x7B | Decide what to do next |
| `analyze_code()` | Qwen-coder | Find code vulnerabilities |
| `generate_payload()` | Qwen-coder | Create exploit payloads |
| `collaborative_vulnerability_assessment()` | All 3 | Comprehensive analysis |

**Design Pattern**: Facade Pattern
- Provides simple interface to complex multi-LLM system
- Hides orchestration complexity from callers

### 3. Multi-LLM Orchestrator

**File**: `multi_llm_orchestrator.py`

**Core Components**:

#### A. LLM Configuration
```python
{
    'strategic': {
        'model': 'meta-llama/Llama-3-70b-chat-hf',
        'specialization': ['planning', 'triage', 'decisions']
    },
    'vulnerability': {
        'model': 'mistralai/Mixtral-8x7B-Instruct-v0.1',
        'specialization': ['vulnerabilities', 'exploitation']
    },
    'coder': {
        'model': 'Qwen/Qwen2.5-Coder-32B-Instruct',
        'specialization': ['code', 'payloads', 'implementation']
    }
}
```

#### B. Task Router
Intelligent routing based on task type:

```
Task Type              → Selected LLM
─────────────────────────────────────
mission_planning       → Llama 70B
triage                 → Llama 70B
vulnerability_analysis → Mixtral 8x7B
next_action            → Mixtral 8x7B
code_analysis          → Qwen-coder
payload_generation     → Qwen-coder
```

#### C. API Interface
- Handles Together AI API calls
- Manages authentication
- Processes responses
- Error handling & retries

### 4. Supporting Components

#### Scanner (`scanner.py`)
Executes security tools based on AI decisions:
- Subdomain enumeration
- Port scanning
- Vulnerability scanning
- URL discovery
- Form testing

#### Learning Engine (`learning_engine.py`)
Continuous improvement:
- Saves successful techniques
- Identifies false positives
- Loads learned patterns for AI context
- Improves over time

#### Field Tester (`field_tester.py`)
Human validation:
- Manual verification of findings
- Learn from user feedback
- Build knowledge base

## Data Flow: Complete Mission

```
1. USER INPUT
   │
   ↓
2. TRIAGE (Llama 70B)
   ├─ Parse requirements
   ├─ Extract target
   └─ Understand BBP rules
   │
   ↓
3. AUTONOMOUS LOOP
   │
   ├─ THINK (Mixtral 8x7B)
   │  └─ Decide next action based on memory
   │
   ├─ PROPOSE
   │  └─ Present action to user
   │
   ├─ APPROVE (Human)
   │  └─ User approves/rejects
   │
   ├─ ACT (Scanner)
   │  └─ Execute security tool
   │
   └─ OBSERVE
      └─ Add results to memory
      └─ Loop back to THINK
   │
   ↓
4. FINDINGS ANALYSIS
   │
   ├─ CODE REVIEW (Qwen-coder)
   │  └─ Analyze vulnerable code
   │
   ├─ PAYLOAD GEN (Qwen-coder)
   │  └─ Create exploits
   │
   └─ COLLABORATIVE (All 3)
      ├─ Strategic assessment (Llama 70B)
      ├─ Vulnerability prioritization (Mixtral 8x7B)
      └─ Technical recommendations (Qwen-coder)
   │
   ↓
5. HUMAN VALIDATION (Field Tester)
   └─ Confirm findings
   └─ Feed back to learning engine
```

## API Communication

### Request Flow
```
Python Code
    │
    ↓
aiohttp Client
    │
    ↓
HTTPS Request
    │
    ↓
Together AI API
    │
    ↓
Model Inference
    │
    ↓
Response (JSON)
    │
    ↓
Python Processing
    │
    ↓
Return to Caller
```

### Request Structure
```json
{
  "model": "meta-llama/Llama-3-70b-chat-hf",
  "messages": [
    {"role": "system", "content": "You are..."},
    {"role": "user", "content": "Question..."}
  ],
  "temperature": 0.7,
  "max_tokens": 2048
}
```

### Response Structure
```json
{
  "choices": [{
    "message": {
      "content": "AI response..."
    }
  }],
  "usage": {
    "prompt_tokens": 100,
    "completion_tokens": 150,
    "total_tokens": 250
  }
}
```

## Security Considerations

### 1. Human-in-the-Loop
- All intrusive actions require approval
- User can reject any action
- Mission can be stopped at any time

### 2. Scope Enforcement
- BBP rules parsed by strategic LLM
- Out-of-scope targets flagged
- Conservative rate limits

### 3. Data Privacy
- API key stored in environment variable
- No sensitive data logged
- Findings kept local

### 4. Error Handling
```
API Error → Log → Fallback → Notify User
Timeout → Retry → Fail Gracefully
Rate Limit → Wait → Resume
```

## Performance Optimization

### 1. Parallel Execution
Collaborative mode calls all 3 LLMs in parallel:
```python
results = await asyncio.gather(
    llama_task,
    mixtral_task,
    qwen_task
)
```

### 2. Caching
- Learning engine caches patterns
- Conversation history maintained
- Findings stored locally

### 3. Token Management
- Efficient prompts
- Truncate long contexts
- Stream responses when possible

## Extension Points

### Adding a New LLM
1. Add to `multi_llm_orchestrator.py`:
```python
self.llms['new_specialist'] = LLMConfig(
    model_name="provider/model-name",
    role="New Specialist",
    specialization=["task1", "task2"]
)
```

2. Update task mapping:
```python
task_mapping = {
    'new_task_type': 'new_specialist',
    ...
}
```

### Adding a New Tool
1. Implement in `scanner.py`:
```python
elif tool == "new_tool":
    return await self.tools.new_tool(args)
```

2. Add to prompt in `enhanced_ai_core.py`:
```
- new_tool: Description (args: param1, param2)
```

## Monitoring & Debugging

### Logging
All components log to:
- Console (INFO level)
- `aegis_agent.log` (DEBUG level)

### Key Log Messages
```
🤖 Initializing Multi-LLM Orchestrator...
🎯 Task 'vulnerability_analysis' → LLM: Mixtral 8x7B
🔄 Calling Vulnerability Analyst...
✅ Response received from Qwen-coder
```

### Testing
```bash
# Test orchestrator
python test_multi_llm.py

# Run examples
python examples/multi_llm_usage.py
```

## Deployment

### Local Development
```bash
export TOGETHER_API_KEY='key'
python main.py
```

### Docker (Future)
```dockerfile
FROM python:3.10
COPY . /app
RUN pip install -r requirements.txt
ENV TOGETHER_API_KEY=${TOGETHER_API_KEY}
CMD ["python", "main.py"]
```

### Cloud (Future)
- Deploy on AWS/GCP/Azure
- Use secrets manager for API key
- Scale horizontally with multiple instances

## Future Enhancements

1. **Model Fine-tuning**: Train on pentesting-specific data
2. **Result Caching**: Reduce API calls for similar queries
3. **Multi-provider**: Support OpenAI, Anthropic, etc.
4. **Confidence Scoring**: Track model certainty
5. **A/B Testing**: Compare model performance
6. **Cost Tracking**: Monitor API spending
7. **Streaming**: Real-time response display

---

**Version**: 6.0  
**Last Updated**: 2024-11  
**Maintainers**: Aegis AI Team
