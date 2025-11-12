# Multi-LLM Examples

This directory contains example scripts demonstrating the multi-LLM capabilities of Aegis Agent v6.0.

## Prerequisites

Before running examples, ensure you have:

1. **Together AI API Key** set in environment:
   ```bash
   export TOGETHER_API_KEY='your_api_key_here'
   ```

2. **Dependencies installed**:
   ```bash
   pip install -r ../requirements.txt
   ```

## Examples

### 1. Basic Usage Examples (`multi_llm_usage.py`)

Demonstrates all five core capabilities:

```bash
python examples/multi_llm_usage.py
```

**What it shows:**
- Mission triage with Llama 70B
- Vulnerability analysis with Mixtral 8x7B
- Code analysis with Qwen-coder
- Payload generation with Qwen-coder
- Collaborative analysis using all three LLMs

### 2. Test Orchestrator (`../test_multi_llm.py`)

Tests the multi-LLM orchestrator functionality:

```bash
python test_multi_llm.py
```

**What it tests:**
- API key validation
- Orchestrator initialization
- LLM selection logic
- Individual LLM calls
- Collaborative analysis

## Expected Output

Each example will:
1. Initialize the specified LLM(s)
2. Show which LLM is being used for the task
3. Display the response from the LLM
4. Show token usage statistics

## API Costs

Running all examples will make approximately:
- 5-10 API calls total
- ~2,000-5,000 tokens per call
- Total cost: ~$0.01-0.05 USD

## Troubleshooting

### API Key Not Set
```
❌ TOGETHER_API_KEY environment variable not set
```
**Solution**: Set the environment variable:
```bash
export TOGETHER_API_KEY='your_actual_key'
```

### Import Errors
```
ModuleNotFoundError: No module named 'agents'
```
**Solution**: Run from project root:
```bash
cd /path/to/Aegis_agent
python examples/multi_llm_usage.py
```

### Rate Limiting
```
Error: Rate limit exceeded
```
**Solution**: Wait a moment and try again, or upgrade your Together AI plan.

## Writing Your Own Examples

Here's a template for creating custom examples:

```python
#!/usr/bin/env python3
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.enhanced_ai_core import EnhancedAegisAI

async def my_custom_example():
    # Initialize AI
    ai = EnhancedAegisAI()
    await ai.initialize()
    
    # Use specific LLM through orchestrator
    result = await ai.orchestrator.execute_task(
        task_type='your_task_type',  # Determines which LLM to use
        system_prompt='Your instructions',
        user_message='Your query',
        temperature=0.7
    )
    
    print(result['content'])

if __name__ == "__main__":
    asyncio.run(my_custom_example())
```

## More Information

- [Multi-LLM Architecture Guide](../MULTI_LLM_GUIDE.md)
- [Main README](../README.md)
- [Together AI Documentation](https://docs.together.ai/)
