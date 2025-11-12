# Multi-LLM Architecture Guide

## Overview

Aegis Agent v6.0 now uses **three specialized LLMs** from Together AI, each optimized for specific pentesting tasks:

### 🧠 The Three Specialists

1. **Llama 70B** (`meta-llama/Llama-3-70b-chat-hf`)
   - **Role**: Strategic Planner & Triage Agent
   - **Best for**:
     - Mission planning and overall strategy
     - Analyzing bug bounty program rules
     - Triaging conversations to gather requirements
     - High-level decision making
     - Risk assessment and prioritization
     - Understanding scope and constraints

2. **Mixtral 8x7B** (`mistralai/Mixtral-8x7B-Instruct-v0.1`)
   - **Role**: Vulnerability Analyst & Exploitation Expert
   - **Best for**:
     - Identifying and analyzing vulnerabilities
     - Planning exploitation strategies
     - Security assessment and weakness identification
     - Determining attack vectors
     - Autonomous agent decision-making
     - Vulnerability triage and severity rating

3. **Qwen-coder** (`Qwen/Qwen2.5-Coder-32B-Instruct`)
   - **Role**: Code Analyst & Payload Engineer
   - **Best for**:
     - Deep code analysis for vulnerabilities
     - Generating exploit payloads
     - Writing proof-of-concept code
     - Technical implementation details
     - Tool orchestration and scripting
     - Understanding and manipulating code

## Setup

### 1. Get Together AI API Key

1. Go to [Together AI](https://api.together.xyz/)
2. Sign up or log in
3. Navigate to Settings → API Keys
4. Create a new API key
5. Copy your API key

### 2. Configure Environment

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env and add your API key
echo "TOGETHER_API_KEY=your_actual_api_key_here" > .env
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## How It Works

### Intelligent Task Routing

The `MultiLLMOrchestrator` automatically selects the best LLM for each task:

```python
# Example task routing:
task_type = "mission_planning"  # → Routes to Llama 70B
task_type = "vulnerability_analysis"  # → Routes to Mixtral 8x7B  
task_type = "payload_generation"  # → Routes to Qwen-coder
```

### Workflow Example

1. **User starts conversation**: "I want to test example.com"
   - **Llama 70B** (Strategic): Triages the request, asks for BBP rules

2. **User provides BBP rules**: "In scope: *.example.com, No DDoS"
   - **Llama 70B** (Strategic): Confirms understanding, plans initial approach

3. **Agent starts reconnaissance**: Finds subdomains, open ports, technologies
   - **Mixtral 8x7B** (Vulnerability): Decides next security testing steps

4. **Finds potential SQL injection**: Form with suspicious parameters
   - **Qwen-coder** (Code): Generates payloads to test the vulnerability

5. **All findings collected**: Multiple vulnerabilities identified
   - **All Three LLMs** (Collaborative): Provide comprehensive assessment
     - Llama 70B: Overall risk and strategic recommendations
     - Mixtral 8x7B: Exploitation paths and vulnerability priorities
     - Qwen-coder: Technical details and PoC code

### Collaborative Analysis

For complex scenarios, all three LLMs can work together:

```python
# Example: Comprehensive vulnerability assessment
results = await ai_core.collaborative_vulnerability_assessment(
    target="example.com",
    findings=discovered_vulnerabilities
)

# Returns:
# - strategic_assessment (from Llama 70B)
# - vulnerability_analysis (from Mixtral 8x7B)
# - technical_recommendations (from Qwen-coder)
```

## Usage Examples

### Basic Scan

```bash
python main.py
# When prompted:
🧑‍💻 VOUS: scan example.com
# Llama 70B will ask for BBP rules
# Then the agent runs autonomously with all three LLMs
```

### Code Analysis

```python
from agents.enhanced_ai_core import EnhancedAegisAI

ai = EnhancedAegisAI()
await ai.initialize()

# Analyze code for vulnerabilities (uses Qwen-coder)
result = await ai.analyze_code(
    code="""
    def login(username, password):
        query = f"SELECT * FROM users WHERE username='{username}'"
        # SQL injection vulnerability!
    """,
    context="Python login function"
)
```

### Generate Exploit Payload

```python
# Generate payloads (uses Qwen-coder)
result = await ai.generate_payload(
    vulnerability_type="SQL Injection",
    target_info={
        "url": "https://example.com/login",
        "parameter": "username",
        "database": "MySQL"
    },
    constraints=["Must bypass WAF", "Time-based blind"]
)
```

## Architecture Benefits

### 1. **Specialized Expertise**
Each LLM is used where it performs best, leading to higher quality results:
- Strategic decisions from a model trained for reasoning
- Security expertise from a model fine-tuned for vulnerabilities
- Code generation from a model specialized in programming

### 2. **Cost Optimization**
- Smaller, specialized models for specific tasks
- Larger model only when complex reasoning is needed
- Parallel execution when multiple perspectives are required

### 3. **Enhanced Accuracy**
- Each LLM focuses on its domain of expertise
- Reduced hallucinations by using the right tool for the job
- Better overall pentesting coverage

### 4. **Collaborative Intelligence**
- Multiple perspectives on complex security issues
- Cross-validation of findings across different models
- Comprehensive analysis from strategic, security, and technical angles

## Configuration Options

### Custom Model Selection

You can override the default models in `.env`:

```bash
# Use different models
STRATEGIC_MODEL=meta-llama/Llama-3.1-70B-Instruct-Turbo
VULNERABILITY_MODEL=mistralai/Mixtral-8x22B-Instruct-v0.1
CODER_MODEL=Qwen/Qwen2.5-Coder-32B-Instruct

# Adjust parameters
DEFAULT_TEMPERATURE=0.7
DEFAULT_MAX_TOKENS=2048
```

### Task Type Mapping

To customize which LLM handles which task, edit `multi_llm_orchestrator.py`:

```python
def select_llm(self, task_type: str) -> str:
    task_mapping = {
        'your_custom_task': 'vulnerability',  # Use Mixtral
        # ... add your mappings
    }
```

## API Usage & Costs

Together AI offers:
- **Pay-as-you-go**: Only pay for what you use
- **Competitive pricing**: Generally cheaper than OpenAI
- **Free credits**: New users get free credits to start

Approximate costs per 1M tokens (as of Nov 2024):
- Llama 70B: ~$0.90 input / ~$0.90 output
- Mixtral 8x7B: ~$0.60 input / ~$0.60 output
- Qwen-coder: ~$0.60 input / ~$0.60 output

Check current pricing at: https://www.together.ai/pricing

## Troubleshooting

### API Key Issues

```bash
# Verify API key is set
python -c "import os; print('API Key:', 'SET' if os.getenv('TOGETHER_API_KEY') else 'NOT SET')"

# Test API connection
python -c "
import asyncio
from agents.multi_llm_orchestrator import MultiLLMOrchestrator

async def test():
    orch = MultiLLMOrchestrator()
    await orch.initialize()
    print('✅ Connection successful!')

asyncio.run(test())
"
```

### Model Not Available

If a model is unavailable, check Together AI's model catalog:
```bash
curl https://api.together.xyz/v1/models \
  -H "Authorization: Bearer $TOGETHER_API_KEY"
```

### Rate Limiting

If you hit rate limits:
1. Add delays between requests
2. Upgrade to a higher tier plan
3. Use smaller models for less critical tasks

## Best Practices

1. **Start with clear scope**: Provide detailed BBP rules to Llama 70B
2. **Let models specialize**: Don't override the automatic LLM selection
3. **Use collaborative mode**: For final assessments, get all three perspectives
4. **Monitor costs**: Check API usage regularly
5. **Validate AI decisions**: Always verify vulnerabilities manually (Human-in-the-Loop)

## Future Enhancements

Potential improvements:
- [ ] Add more specialized models (e.g., image analysis, network protocol analysis)
- [ ] Implement model voting for critical decisions
- [ ] Add caching layer to reduce API calls
- [ ] Fine-tune models on pentesting-specific data
- [ ] Add confidence scoring and uncertainty estimation
- [ ] Implement automatic model selection based on performance metrics

## Support

For issues with:
- **Aegis Agent**: Open an issue on GitHub
- **Together AI API**: Contact support@together.xyz
- **Model behavior**: Report in GitHub issues with examples

## License

Same as main project - see LICENSE file.
