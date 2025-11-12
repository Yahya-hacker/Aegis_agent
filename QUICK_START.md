# Aegis AI v6.0 - Quick Start Guide

## 🚀 Get Started in 3 Minutes

### Step 1: Install Dependencies
```bash
pip install aiohttp python-dotenv python-nmap beautifulsoup4 selenium colorama pillow
```

### Step 2: Set Your API Key
```bash
# Get your free API key from https://api.together.xyz/
export TOGETHER_API_KEY='paste_your_key_here'
```

### Step 3: Run Aegis AI
```bash
python main.py
```

## 💬 First Mission

```
🧑‍💻 VOUS: scan example.com

🤖 Aegis AI will ask for:
   1. Bug bounty program rules
   2. Scope (what's in/out)
   
📜 You paste the BBP rules

✅ Agent starts autonomous testing with human approval for each action
```

## 🧠 The Three AI Brains

| LLM | What It Does | When It's Used |
|-----|--------------|----------------|
| **Llama 70B** | Strategic planning, mission triage | Planning, decision-making, scope analysis |
| **Mixtral 8x7B** | Vulnerability analysis & exploitation | Finding vulnerabilities, choosing next action |
| **Qwen-coder** | Code & payload engineering | Analyzing code, generating exploits |

## 📝 Example Commands

### Basic Scan
```
scan example.com
```

### With Context
```
I need to test example.com. It's a bug bounty program.
```

### Get Help
```
help
```

### Exit
```
quit
```

## 🔧 Common Issues

### "API key not set"
```bash
export TOGETHER_API_KEY='your_actual_key'
```

### "Module not found"
```bash
cd /path/to/Aegis_agent
pip install -r requirements.txt
python main.py
```

### "Rate limit exceeded"
Wait 60 seconds, or upgrade your Together AI plan.

## 🎓 Learn More

- **Full Guide**: See [MULTI_LLM_GUIDE.md](MULTI_LLM_GUIDE.md)
- **Examples**: Check [examples/](examples/)
- **Test System**: Run `python test_multi_llm.py`

## ⚖️ Legal & Ethics

⚠️ **IMPORTANT**: Only test systems you own or have written authorization to test.
- Get explicit permission before any testing
- Respect bug bounty program rules
- Use human approval for all intrusive actions
- Report vulnerabilities responsibly

## 🆘 Getting Help

1. Check [MULTI_LLM_GUIDE.md](MULTI_LLM_GUIDE.md) for detailed docs
2. Review [examples/](examples/) for usage patterns
3. Open an issue on GitHub
4. Ensure `TOGETHER_API_KEY` is set correctly

## 💰 API Costs

Typical mission costs:
- **Reconnaissance**: ~$0.01-0.05
- **Full scan**: ~$0.10-0.50
- **Deep analysis**: ~$0.50-2.00

Free tier includes credits to get started!

## ✨ Key Features

✅ Three specialized AI models
✅ Intelligent task routing
✅ Human-in-the-loop safety
✅ Auto-learning from results
✅ Collaborative analysis mode
✅ Respects BBP rules
✅ Generates PoC code

---

Ready to start? Run: `python main.py`
