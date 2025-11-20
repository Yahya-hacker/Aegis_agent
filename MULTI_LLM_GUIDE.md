# Multi-LLM Architecture Guide

## Overview

Aegis Agent v7.5 now uses **four specialized LLMs** from OpenRouter, each optimized for specific pentesting tasks. All models are **fully configurable via environment variables** - no code changes needed!

### 🧠 The Four Specialists

1. **Strategic Model** (Default: `nousresearch/hermes-3-llama-3.1-70b`)
   - **Role**: Strategic Planner & Triage Agent
   - **Best for**:
     - Mission planning and overall strategy
     - Analyzing bug bounty program rules
     - Triaging conversations to gather requirements
     - High-level decision making
     - Risk assessment and prioritization
     - Understanding scope and constraints
   - **Environment Variable**: `STRATEGIC_MODEL`

2. **Reasoning Model** (Default: `cognitivecomputations/dolphin3.0-r1-mistral-24b`)
   - **Role**: Vulnerability Analyst & Exploitation Expert
   - **Best for**:
     - Identifying and analyzing vulnerabilities
     - Planning exploitation strategies
     - Security assessment and weakness identification
     - Determining attack vectors
     - Autonomous agent decision-making
     - Vulnerability triage and severity rating
   - **Environment Variable**: `REASONING_MODEL`

3. **Code Model** (Default: `qwen/qwen-2.5-72b-instruct`)
   - **Role**: Code Analyst & Payload Engineer
   - **Best for**:
     - Deep code analysis for vulnerabilities
     - Generating exploit payloads
     - Writing proof-of-concept code
     - Technical implementation details
     - Tool orchestration and scripting
     - Understanding and manipulating code
   - **Environment Variable**: `CODE_MODEL`

4. **Visual Model** (Default: `qwen/qwen2.5-vl-32b-instruct:free`)
   - **Role**: Visual Analyst & UI Reconnaissance (Multimodal)
   - **Best for**:
     - Analyzing screenshots and UI layouts
     - Identifying clickable elements visually
     - Visual grounding with Set-of-Mark (SoM)
     - Detecting visual vulnerabilities
     - Understanding web interface structure
     - Multimodal security analysis
   - **Environment Variable**: `VISUAL_MODEL`

## Setup

### 1. Get OpenRouter API Key

1. Go to [OpenRouter](https://openrouter.ai/)
2. Sign up or log in
3. Navigate to Keys section
4. Create a new API key
5. Copy your API key

### 2. Configure Environment

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env and add your API key
nano .env  # or use your preferred editor
```

Add your configuration to `.env`:

```bash
# Required: OpenRouter API Key
OPENROUTER_API_KEY=your_actual_api_key_here

# Optional: Customize models (defaults shown)
STRATEGIC_MODEL=nousresearch/hermes-3-llama-3.1-70b
REASONING_MODEL=cognitivecomputations/dolphin3.0-r1-mistral-24b
CODE_MODEL=qwen/qwen-2.5-72b-instruct
VISUAL_MODEL=qwen/qwen2.5-vl-32b-instruct:free

# Optional: Customize generation parameters
DEFAULT_TEMPERATURE=0.7
DEFAULT_MAX_TOKENS=4096
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## 🔄 Changing Models

**One of the biggest advantages of v7.5 is the ability to easily swap models without editing code!**

### Why Change Models?

- **Performance**: Test different models to find the best fit for your use case
- **Cost**: Use cheaper models for less critical tasks
- **Capabilities**: Leverage newer or specialized models as they become available
- **Experimentation**: Try different model combinations for optimal results

### How to Change Models

1. **Browse OpenRouter Models**: Visit [https://openrouter.ai/models](https://openrouter.ai/models)
2. **Find Your Model**: Look for models that fit your needs (coding, reasoning, vision, etc.)
3. **Copy Model ID**: Copy the model identifier (e.g., `anthropic/claude-3-opus`)
4. **Update .env**: Paste the model ID into your `.env` file
5. **Restart Aegis**: Restart the application - changes take effect immediately!

### Example: Using Different Models

```bash
# .env configuration examples:

# Option 1: Use Claude 3 Opus for everything (high quality, higher cost)
STRATEGIC_MODEL=anthropic/claude-3-opus
REASONING_MODEL=anthropic/claude-3-opus
CODE_MODEL=anthropic/claude-3-opus

# Option 2: Mix and match for cost optimization
STRATEGIC_MODEL=anthropic/claude-3-opus        # Best strategic planning
REASONING_MODEL=anthropic/claude-3-sonnet      # Good reasoning, lower cost
CODE_MODEL=qwen/qwen-2.5-72b-instruct         # Excellent coding, very affordable

# Option 3: Use GPT-4 Turbo for code tasks
CODE_MODEL=openai/gpt-4-turbo

# Option 4: Use Gemini for visual analysis
VISUAL_MODEL=google/gemini-pro-vision
```

### Model Recommendations by Task

**Strategic Planning** (STRATEGIC_MODEL):
- Best: `anthropic/claude-3-opus`, `openai/gpt-4-turbo`
- Good: `nousresearch/hermes-3-llama-3.1-70b` (default)
- Budget: `anthropic/claude-3-haiku`

**Vulnerability Analysis** (REASONING_MODEL):
- Best: `anthropic/claude-3-opus`, `cognitivecomputations/dolphin3.0-r1-mistral-24b` (default)
- Good: `meta-llama/llama-3.1-70b-instruct`
- Budget: `meta-llama/llama-3.1-8b-instruct`

**Code Analysis & Payloads** (CODE_MODEL):
- Best: `qwen/qwen-2.5-72b-instruct` (default), `anthropic/claude-3-opus`
- Good: `deepseek/deepseek-coder-33b-instruct`
- Budget: `qwen/qwen-2.5-7b-instruct`

**Visual Analysis** (VISUAL_MODEL):
- Best: `qwen/qwen2.5-vl-32b-instruct:free` (default), `google/gemini-pro-vision`
- Good: `anthropic/claude-3-opus` (multimodal)
- Note: Ensure chosen model supports vision/multimodal input

### Temperature & Token Configuration

Fine-tune LLM behavior globally or let the system use optimal per-task settings:

```bash
# In .env:

# Default temperature (0.0 = deterministic, 1.0 = creative)
DEFAULT_TEMPERATURE=0.7

# Default max tokens (response length)
DEFAULT_MAX_TOKENS=4096
```

**Temperature Guidelines**:
- `0.3-0.5`: Focused, consistent, deterministic (good for verification)
- `0.6-0.7`: Balanced (recommended default)
- `0.8-0.9`: Creative, exploratory (good for brainstorming)

**Max Tokens Guidelines**:
- `1024-2048`: Shorter responses, faster, cheaper
- `4096`: Recommended for complex reasoning
- `8192+`: Very detailed responses (if model supports it)

### Testing Your Configuration

After changing models, test that everything works:

```bash
# Start Aegis
python main.py

# The startup will show your configuration:
🚀 Démarrage de l'Agent Autonome Aegis AI avec Multi-LLM...
🔧 LLM Configuration loaded from environment:
   Strategic Model: anthropic/claude-3-opus
   Reasoning Model: anthropic/claude-3-sonnet
   Code Model: qwen/qwen-2.5-72b-instruct
   Visual Model: qwen/qwen2.5-vl-32b-instruct:free
   Default Temperature: 0.7
   Default Max Tokens: 4096
```

## How It Works

### Intelligent Task Routing

The `MultiLLMOrchestrator` automatically selects the best LLM for each task:

```python
# Example task routing:
task_type = "mission_planning"        # → Routes to Strategic Model (Hermes 3 Llama 70B)
task_type = "vulnerability_analysis"  # → Routes to Reasoning Model (Dolphin 3.0)
task_type = "payload_generation"      # → Routes to Code Model (Qwen 2.5 72B)
task_type = "visual_analysis"         # → Routes to Visual Model (Qwen 2.5 VL 32B)
```

### Workflow Example

1. **User starts conversation**: "I want to test example.com"
   - **Strategic Model** (Hermes 3): Triages the request, asks for BBP rules

2. **User provides BBP rules**: "In scope: *.example.com, No DDoS"
   - **Strategic Model** (Hermes 3): Confirms understanding, plans initial approach

3. **Agent starts reconnaissance**: Finds subdomains, open ports, technologies
   - **Reasoning Model** (Dolphin 3.0): Decides next security testing steps

4. **Visual reconnaissance**: Captures screenshot of web interface
   - **Visual Model** (Qwen 2.5 VL): Analyzes UI layout, identifies interactive elements

5. **Finds potential SQL injection**: Form with suspicious parameters
   - **Code Model** (Qwen 2.5): Generates payloads to test the vulnerability

6. **All findings collected**: Multiple vulnerabilities identified
   - **All Four LLMs** (Collaborative): Provide comprehensive assessment
     - Strategic Model: Overall risk and strategic recommendations
     - Reasoning Model: Exploitation paths and vulnerability priorities
     - Code Model: Technical details and PoC code
     - Visual Model: UI-based attack surfaces and visual vulnerabilities

### Collaborative Analysis

For complex scenarios, all LLMs can work together:

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
