# API Key Sharding Guide

## Overview

The **API Key Sharding** system allows you to assign different OpenRouter API keys to different model roles in Aegis AI. This enables:

- 📊 **Cost Tracking**: Monitor and track costs per model type
- 🛡️ **Quota Management**: Prevent a single model from consuming your entire API quota
- 🎯 **Granular Control**: Set different rate limits and budgets for each role
- 💰 **Budget Isolation**: Isolate budgets across different teams or use cases

## How It Works

The system supports **four distinct roles**, each with optional dedicated API keys:

| Role | Environment Variable | Model Type | Use Case |
|------|---------------------|------------|----------|
| **Strategic** | `STRATEGIC_API_KEY` | Orchestrator/Manager | Mission planning, triage, decision making |
| **Vulnerability** | `REASONING_API_KEY` | DeepSeek/Thinking | Vulnerability analysis, exploit reasoning |
| **Coder** | `CODE_API_KEY` | Qwen/Coder | Code analysis, payload generation |
| **Visual** | `VISUAL_API_KEY` | Vision Models | Screenshot analysis, UI reconnaissance |

## Configuration Options

### Option 1: Master Key Only (Default - Backward Compatible)

**Perfect for**: Getting started, simple setups, single budget tracking

```bash
# .env
OPENROUTER_API_KEY=sk-or-v1-abc123...
```

**Result**: All four roles use the same master key. ✅ **Zero configuration required!**

---

### Option 2: Full API Key Sharding

**Perfect for**: Maximum cost control, multi-team environments, strict budgets

```bash
# .env
OPENROUTER_API_KEY=sk-or-v1-master-key...    # Fallback (optional)

# Role-specific keys
STRATEGIC_API_KEY=sk-or-v1-strategic-key...
REASONING_API_KEY=sk-or-v1-reasoning-key...
CODE_API_KEY=sk-or-v1-code-key...
VISUAL_API_KEY=sk-or-v1-visual-key...
```

**Result**: Each role uses its dedicated key. Perfect isolation! 🎯

---

### Option 3: Partial Sharding (Hybrid Approach)

**Perfect for**: Selectively controlling high-cost models, flexible budgeting

```bash
# .env
OPENROUTER_API_KEY=sk-or-v1-master-key...    # Fallback

# Only set keys for models you want to isolate
REASONING_API_KEY=sk-or-v1-reasoning-key...  # Isolate expensive reasoning model
CODE_API_KEY=sk-or-v1-code-key...           # Isolate code generation
# Strategic and Visual will fallback to master key
```

**Result**: Specified roles use their keys, others fallback to master. Best of both worlds! 🌟

---

## Setup Instructions

### Step 1: Get Your API Keys

1. Go to [OpenRouter Keys](https://openrouter.ai/keys)
2. Create one or more API keys:
   - **Option A**: Create a single master key (easiest)
   - **Option B**: Create separate keys for each role you want to control
   - **Option C**: Create keys for only the models you want to isolate

### Step 2: Configure Environment Variables

Edit your `.env` file (copy from `.env.example` if needed):

```bash
cp .env.example .env
nano .env  # or your favorite editor
```

Add your keys based on your chosen configuration option (see above).

### Step 3: Verify Configuration

Run Aegis AI normally. At startup, you'll see detailed logging:

```
🤖 Initializing Multi-LLM Orchestrator with API Key Sharding...
🔑 API Key Configuration Status:
   Master Key (OPENROUTER_API_KEY): ✅ Configured
   
   Role-Specific Key Assignment:
   ✅ Strategic: Using specific key (STRATEGIC_API_KEY)
   ⚠️  Vulnerability: Fallback to master key (OPENROUTER_API_KEY)
   ✅ Coder: Using specific key (CODE_API_KEY)
   ⚠️  Visual: Fallback to master key (OPENROUTER_API_KEY)
   
✅ Multi-LLM Orchestrator ready with API Key Sharding enabled.
```

## Use Cases & Examples

### Use Case 1: Development vs Production

**Scenario**: Use a free-tier key for development, production key for live testing

```bash
# Development
OPENROUTER_API_KEY=sk-or-v1-free-tier-key...
# All models use free tier

# Production
OPENROUTER_API_KEY=sk-or-v1-prod-master...
REASONING_API_KEY=sk-or-v1-prod-premium...  # Premium key for reasoning
```

---

### Use Case 2: Team Budget Allocation

**Scenario**: Different teams control different model budgets

```bash
STRATEGIC_API_KEY=sk-or-v1-team-alpha...    # Team Alpha's budget
REASONING_API_KEY=sk-or-v1-team-beta...     # Team Beta's budget
CODE_API_KEY=sk-or-v1-team-alpha...         # Team Alpha's budget
VISUAL_API_KEY=sk-or-v1-shared...           # Shared team budget
```

---

### Use Case 3: Cost Optimization

**Scenario**: Isolate expensive models to monitor and control costs

```bash
OPENROUTER_API_KEY=sk-or-v1-standard...          # Standard key for most models
REASONING_API_KEY=sk-or-v1-premium-limited...   # Limited budget for expensive reasoning
```

---

## Security Best Practices

### ✅ DO:

- Store API keys in `.env` file (never commit to git)
- Use different keys for development and production
- Regularly rotate your API keys
- Monitor usage in OpenRouter dashboard
- Set spending limits in OpenRouter for each key

### ❌ DON'T:

- Commit `.env` file to version control
- Share API keys in chat/email
- Use the same key across multiple projects without monitoring
- Hardcode keys in Python files

---

## Troubleshooting

### Error: "Missing API keys for roles: strategic, vulnerability, coder, visual"

**Cause**: No master key AND no role-specific keys are set.

**Solution**: Set at least `OPENROUTER_API_KEY` in your `.env` file:

```bash
OPENROUTER_API_KEY=sk-or-v1-your-key-here...
```

---

### Error: "API key for role 'X' is empty or invalid at runtime"

**Cause**: A key was set but is empty or only whitespace.

**Solution**: Ensure your keys are valid:

```bash
# ❌ WRONG
STRATEGIC_API_KEY=

# ✅ CORRECT
STRATEGIC_API_KEY=sk-or-v1-abc123...
```

---

### Question: Can I mix and match keys?

**Yes!** The system is designed for maximum flexibility. You can:

- Use master key for all roles (default)
- Use specific keys for all roles (full sharding)
- Use specific keys for some, master key for others (partial sharding)

The system automatically falls back to the master key when a role-specific key isn't provided.

---

## Advanced Configuration

### Monitoring Usage

Each role's API key is used independently, allowing you to:

1. Log into [OpenRouter Dashboard](https://openrouter.ai/activity)
2. View usage per API key
3. Track costs per model role
4. Set alerts and limits per key

### Dynamic Key Rotation

For advanced users, you can update API keys without restarting:

```python
# After initialization, you can manually update keys if needed
orchestrator.api_keys['strategic'] = 'new-key-here'
```

However, we recommend restarting Aegis AI for clean initialization.

---

## Migration Guide

### Migrating from Single Key Setup

**Before**:
```bash
OPENROUTER_API_KEY=sk-or-v1-my-key...
```

**After** (with sharding):
```bash
# Keep your master key as fallback
OPENROUTER_API_KEY=sk-or-v1-my-key...

# Add role-specific keys gradually
REASONING_API_KEY=sk-or-v1-reasoning-key...  # Start with one
# Other roles automatically fallback to master
```

✅ **Zero downtime**: The system is 100% backward compatible!

---

## FAQ

**Q: Do I need to set all four role-specific keys?**  
A: No! You can set none (use master only), some (partial sharding), or all (full sharding).

**Q: What happens if I only set role-specific keys but no master key?**  
A: The system validates that EVERY role has a key. If you want to use only role-specific keys, you must set all four.

**Q: Can I use the same key for multiple roles?**  
A: Yes! You can set the same key value for multiple role variables if desired.

**Q: Will this slow down the agent?**  
A: No performance impact. Key lookup is instant from the registry dictionary.

**Q: Can I track which key was used for each request?**  
A: Yes, check the logs. Each LLM call logs which role and model were used, allowing you to correlate with your OpenRouter dashboard.

**Q: How can I monitor token usage during long missions?**  
A: The orchestrator includes sophisticated tracking. Call `orchestrator.get_usage_statistics()` to see cumulative stats by role, including total calls, tokens, and recurring error patterns.

**Q: What happens if I exceed token limits during complex exploit chains?**  
A: The system automatically warns when a single call uses >75% of max_tokens and tracks context history to detect exhaustion patterns over time.

---

## Long Mission Monitoring

Aegis v7.5 includes **sophisticated tracking** for long-running missions and complex exploit chains to prevent common AI issues:

### Automatic Context Monitoring

The orchestrator tracks:
- **Token usage per call** and cumulative totals by role
- **Context history** over time to detect patterns
- **Automatic warnings** when approaching limits (>75% max_tokens)
- **Error pattern detection** to identify systemic issues

### Getting Usage Statistics

During or after a mission, get comprehensive stats:

```python
stats = orchestrator.get_usage_statistics()

# Returns:
# {
#     'total_calls': 150,
#     'total_tokens': 245000,
#     'by_role': {
#         'strategic': {'calls': 50, 'tokens': 75000},
#         'vulnerability': {'calls': 40, 'tokens': 80000},
#         'coder': {'calls': 45, 'tokens': 70000},
#         'visual': {'calls': 15, 'tokens': 20000}
#     },
#     'recurring_errors': {...}
# }
```

### Mission Checkpointing

For very long missions, reset tracking between phases:

```python
orchestrator.reset_usage_tracking()
```

This clears call/token counters while preserving error patterns for systemic issue detection.

### Common Issues Detected

1. **Context Window Exhaustion**: Warns when individual calls use >75% of max_tokens
2. **Recurring Errors**: Detects patterns after 3+ occurrences of the same error
3. **Unbalanced Load**: Statistics show if one role is being overused
4. **Token Accumulation**: Tracks cumulative usage to prevent quota exhaustion

---

## Support

For issues or questions:
1. Check the error messages (they're designed to be helpful!)
2. Review this guide
3. Open an issue on [GitHub](https://github.com/Yahya-hacker/Aegis_agent/issues)

---

**Happy Testing! 🚀**
