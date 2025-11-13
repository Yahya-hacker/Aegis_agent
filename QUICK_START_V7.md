# Aegis Agent v7.0 - Quick Start Guide

## 🚀 What's New in v7.0?

This version introduces "Battle-Ready" features with the "Mixture of Agents" architecture:

1. **OpenRouter API**: Access to uncensored, specialized models
2. **Smart Memory**: Automatic pruning prevents slowdowns
3. **OOB Detection**: Find blind vulnerabilities (RCE, SSRF, XXE)
4. **Robust Parsing**: Never crashes on malformed output
5. **Stealth Mode**: Evade WAF detection with rotation & jitter

---

## ⚡ Quick Setup

### 1. Get OpenRouter API Key
```bash
# Visit: https://openrouter.ai/keys
# Create an account and generate an API key
```

### 2. Configure Environment
```bash
# Copy the example file
cp .env.example .env

# Edit .env and add your key
nano .env
```

```env
# Required
OPENROUTER_API_KEY=sk-or-v1-your-key-here

# Optional: Add proxies for stealth mode
PROXY_LIST=http://proxy1:8080,http://proxy2:8080
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run Aegis
```bash
python main.py
```

---

## 🎯 New Features Guide

### Stealth Mode (Auto-Enabled)

All HTTP requests now automatically include:
- ✅ Random User-Agent rotation (20 realistic UAs)
- ✅ Browser-like HTTP headers
- ✅ 1-3 second jitter between requests
- ✅ Proxy rotation (if configured)

**No code changes needed - it just works!**

### OOB Detection for Blind Vulnerabilities

Detect vulnerabilities that don't show direct responses:

```python
# Generate a unique OOB payload
result = await tool_manager.generate_oob_payload("http")
payload_id = result["data"]["payload_id"]
oob_url = result["data"]["url"]

# Inject the OOB URL in your test
# Example: test parameter with payload
# After injection, check for callbacks:

interactions = await tool_manager.check_oob_interactions(payload_id)
if interactions["data"]["interactions_found"] > 0:
    print("🎯 Blind vulnerability confirmed!")
```

**Note**: For production use, integrate with interactsh library

### Smart Memory Management

The agent now automatically manages conversation history:
- Keeps last 5 detailed interactions
- Summarizes older conversations
- Prevents token limit issues
- **Completely automatic - no action needed!**

### Robust Parsing

All tool outputs are now guaranteed to parse:
- Handles invalid JSON gracefully
- Extracts structured data using regex
- Never crashes the agent
- Always returns useful information

---

## 🔧 Model Configuration

The agent uses three specialized models via OpenRouter:

| Role | Model | Purpose |
|------|-------|---------|
| **Orchestrator** | `nousresearch/hermes-3-llama-3.1-70b` | Strategic planning, triage |
| **Code Specialist** | `qwen/qwen-2.5-72b-instruct` | Code analysis, payloads |
| **Reasoning** | `cognitivecomputations/dolphin3.0-r1-mistral-24b` | Vulnerability analysis |

These are **hardcoded constants** and cannot be changed accidentally.

---

## 📊 Usage Examples

### Basic Scan
```bash
python main.py
> Target: example.com
> Rules: Stay in scope, no DoS
```

The agent will automatically:
1. Use stealth features (random UA, jitter)
2. Parse all outputs robustly
3. Manage memory efficiently
4. Select the right specialized model for each task

### Advanced: Using Proxies
```bash
# Add to .env
PROXY_LIST=http://proxy1.com:8080,http://proxy2.com:8080,socks5://proxy3.com:1080

# Run normally - proxies will rotate automatically
python main.py
```

### Advanced: OOB Testing
```python
from tools.python_tools import PythonToolManager
import asyncio

async def test_blind_ssrf():
    manager = PythonToolManager()
    
    # Generate OOB payload
    payload = await manager.generate_oob_payload("http")
    oob_url = payload["data"]["payloads"]["http"]
    
    print(f"Inject this URL: {oob_url}")
    # ... perform injection ...
    
    # Wait for callback
    await asyncio.sleep(10)
    
    # Check interactions
    result = await manager.check_oob_interactions(payload["data"]["payload_id"])
    print(result)

asyncio.run(test_blind_ssrf())
```

---

## 🛡️ Security Notes

### API Key Security
- ✅ Never commit `.env` file to git
- ✅ API key is loaded from environment only
- ✅ No hardcoded credentials in code

### Responsible Use
- Only test systems you have permission to test
- Follow bug bounty program rules strictly
- Use stealth features responsibly
- OOB detection should be used ethically

---

## 🔍 Troubleshooting

### "OPENROUTER_API_KEY not set"
```bash
# Make sure .env file exists and contains:
OPENROUTER_API_KEY=your-actual-key-here
```

### "Parser crashed"
This should never happen now! But if it does:
- Check `REFACTORING_SUMMARY.md` for details
- Report the issue with the raw output
- Parsers have multiple fallback layers

### "Memory growing too large"
This should never happen now - automatic pruning enabled!
- Memory is pruned every action decision
- Keeps last 5 interactions automatically
- No manual intervention needed

### "Requests blocked by WAF"
Enable stealth mode:
```bash
# Add proxies to .env
PROXY_LIST=http://proxy1:8080,http://proxy2:8080

# Requests will automatically:
# - Rotate User-Agents
# - Rotate proxies
# - Add random jitter
```

---

## 📚 Documentation

- `REFACTORING_SUMMARY.md` - Complete technical documentation
- `README.md` - General project information
- `ARCHITECTURE.md` - System architecture details
- `MULTI_LLM_GUIDE.md` - Multi-LLM usage guide

---

## 🎓 Learning Resources

### Understanding the Models

**Orchestrator (Hermes 3)**: Best for strategic thinking
- Mission planning
- Scope analysis
- High-level decisions

**Code Specialist (Qwen 2.5)**: Best for technical tasks
- Payload generation
- Code analysis
- Exploit development

**Reasoning (Dolphin 3.0)**: Best for analysis
- Vulnerability assessment
- Attack vector identification
- Security reasoning

### Advanced Features

**Memory Pruning Algorithm**:
```
If history > 5 items:
  Keep: Last 5 items (recent context)
  Summarize: Everything older
  Result: 1 summary + 5 recent = 6 total
```

**Stealth Headers**:
```
User-Agent: [Random from 20 realistic UAs]
Accept: text/html,application/xhtml+xml,...
Accept-Language: en-US,en;q=0.9
DNT: 1
[...12 total realistic browser headers]
```

**OOB Detection Flow**:
```
1. generate_oob_payload() → unique URL
2. Inject URL in test
3. check_oob_interactions() → verify callback
4. Callback found? → Vulnerability confirmed!
```

---

## ⚠️ Migration from v6.0

### Required Changes
```bash
# Update .env file
- TOGETHER_API_KEY=xxx
+ OPENROUTER_API_KEY=xxx
```

### Optional Changes
```bash
# Add proxy support (new feature)
+ PROXY_LIST=http://proxy1:8080,http://proxy2:8080
```

### No Code Changes
All existing code works with v7.0! Changes are backward compatible.

---

## 🎯 Performance Tips

1. **Use Proxies Wisely**: More proxies = better distribution, but manage quality
2. **Jitter is Good**: 1-3s delays prevent detection and rate limiting
3. **Memory Pruning**: Happens automatically, no tuning needed
4. **Model Selection**: Automatic based on task type, trust the orchestrator

---

## 🆘 Support

- **Issues**: Create GitHub issue with details
- **Security**: Email security concerns privately
- **Questions**: Check documentation first, then ask

---

## ✅ Pre-Flight Checklist

Before starting a mission:

- [ ] `.env` file configured with `OPENROUTER_API_KEY`
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] Target and rules clearly defined
- [ ] Permission to test confirmed
- [ ] (Optional) Proxies configured for stealth
- [ ] Documentation reviewed

---

## 🚀 Ready to Go!

You're all set! The new v7.0 features will make your testing:
- **Smarter**: Better model selection
- **Faster**: Optimized memory usage
- **Stealthier**: WAF evasion built-in
- **More Reliable**: Robust parsing never crashes
- **More Capable**: OOB detection for blind vulns

Happy hunting! 🎯

---

**Version**: 7.0  
**Last Updated**: 2025-11-13  
**Status**: Production Ready
