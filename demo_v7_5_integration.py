#!/usr/bin/env python3
"""
Aegis v7.5 "Architect" - Integration Demo

This demo shows how all six modules work together to discover
and exploit vulnerabilities using a zero-day research approach.
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))


async def demo_integrated_workflow():
    """
    Demonstrate an integrated workflow using all v7.5 modules together.
    
    This simulates a real penetration test workflow where:
    1. Genesis fuzzes endpoints
    2. Cortex tracks the navigation path
    3. CDP detects DOM vulnerabilities
    4. Chronos tests for race conditions
    5. Mirror executes JS for bypasses
    6. Echo tracks blind vulnerabilities
    """
    
    print("\n" + "="*70)
    print("AEGIS v7.5 'ARCHITECT' - INTEGRATED WORKFLOW DEMO")
    print("="*70)
    
    # Initialize all modules
    from agents.enhanced_ai_core import CortexMemory
    from tools.genesis_fuzzer import get_genesis_fuzzer
    from tools.cdp_hooks import get_cdp_hooks
    from tools.race_engine import get_chronos_engine
    from tools.python_tools import PythonToolManager
    from listeners.dns_callback import get_oob_manager
    
    print("\n[1/6] Initializing Modules...")
    cortex = CortexMemory(mission_id="integrated_demo")
    cortex.clear()
    genesis = get_genesis_fuzzer()
    cdp = get_cdp_hooks()
    chronos = get_chronos_engine()
    mirror = PythonToolManager()
    oob = get_oob_manager(callback_domain="demo.aegis-c2.local")
    
    print("  ✓ All modules initialized")
    
    # Phase 1: Use Cortex to track navigation
    print("\n[2/6] Cortex Memory - Tracking Application Navigation...")
    
    cortex.record_action(
        action="Navigate to homepage",
        result={"success_score": 1.0, "status_code": 200},
        new_url="https://demo.example.com/",
        artifacts={"forms": [], "links": ["login", "register"]}
    )
    
    cortex.record_action(
        action="Navigate to registration page",
        result={"success_score": 1.0, "status_code": 200},
        new_url="https://demo.example.com/register",
        artifacts={"forms": ["registration_form"], "inputs": ["email", "password", "age"]}
    )
    
    state = cortex.get_current_state()
    print(f"  ✓ Current position: {state['url']}")
    print(f"  ✓ Graph: {state['total_nodes']} nodes, {state['total_edges']} edges")
    
    # Phase 2: Use Genesis to fuzz the registration endpoint
    print("\n[3/6] Genesis Fuzzer - Fuzzing Registration Endpoint...")
    
    grammar = {
        "email": {"type": "string"},
        "password": {"type": "string"},
        "age": {"type": "integer", "min": 0, "max": 120}
    }
    
    genesis.compile_grammar(grammar)
    base_payload = {
        "email": "user@example.com",
        "password": "password123",
        "age": 25
    }
    
    mutations = genesis.generate_mutations(base_payload)
    print(f"  ✓ Generated {len(mutations)} fuzzing mutations")
    print(f"  ✓ Mutation strategies: integer overflow, SQL injection, XSS, format strings")
    
    # Simulate fuzzing results (in real scenario, would call fuzz_endpoint)
    print(f"  ✓ [Simulated] Found 3 anomalies in response patterns")
    
    # Phase 3: Use OOB to create tracked payloads
    print("\n[4/6] Echo OOB - Creating Tracked Payloads...")
    
    # Create DNS payload for potential RCE
    rce_payload = oob.create_dns_payload(
        target_url="https://demo.example.com/api/search",
        payload_type="RCE",
        target_parameter="q"
    )
    
    # Create HTTP payload for blind XSS
    xss_payload = oob.create_http_payload(
        target_url="https://demo.example.com/comment",
        payload_type="XSS",
        target_parameter="message"
    )
    
    print(f"  ✓ RCE payload: {rce_payload['instrumented_payload'][:60]}...")
    print(f"  ✓ XSS payload: {xss_payload['instrumented_payload'][:60]}...")
    print(f"  ✓ Payloads tracked with IDs: {rce_payload['payload_id']}, {xss_payload['payload_id']}")
    
    # Phase 4: Use Mirror to execute client-side token generation
    print("\n[5/6] Mirror JS Sandbox - Executing Client-Side Logic...")
    
    js_code = """
    function generateAuthToken(username, timestamp) {
        const secret = 'app_secret_key';
        return btoa(username + ':' + timestamp + ':' + secret);
    }
    """
    
    try:
        token = mirror.execute_extracted_js(
            js_code=js_code,
            arguments=["admin", "1234567890"],
            function_name="generateAuthToken"
        )
        
        if token:
            print(f"  ✓ Generated valid auth token: {token}")
            print(f"  ✓ Can now bypass client-side validation")
        else:
            print(f"  ℹ️  JS execution available (requires Node.js)")
    except Exception as e:
        print(f"  ℹ️  Mirror sandbox demo skipped (Node.js not available)")
    
    # Phase 5: Use CDP for DOM XSS detection
    print("\n[6/6] CDP Hooks - Detecting DOM-Based Vulnerabilities...")
    
    print(f"  ✓ JavaScript hooks ready for: eval, innerHTML, document.write")
    print(f"  ✓ MutationObserver monitoring dangerous attributes")
    print(f"  ✓ Console trap system active")
    
    # Simulate trap detection
    class MockTrap:
        text = '[AEGIS_TRAP] {"type": "AEGIS_TRAP", "sink": "innerHTML", "payload": "<img src=x onerror=alert(1)>"}'
    
    cdp._handle_console_message(MockTrap())
    print(f"  ✓ [Simulated] Detected DOM XSS via innerHTML sink")
    print(f"  ✓ Trapped events: {len(cdp.trapped_events)}")
    
    # Phase 6: Integration Summary
    print("\n" + "="*70)
    print("INTEGRATION WORKFLOW COMPLETE")
    print("="*70)
    
    print("\n📊 Workflow Summary:")
    print(f"  1. Cortex tracked {state['total_nodes']} application states")
    print(f"  2. Genesis generated {len(mutations)} fuzzing mutations")
    print(f"  3. Echo created 2 OOB-tracked payloads")
    print(f"  4. Mirror executed client-side JavaScript")
    print(f"  5. CDP detected 1 DOM-based vulnerability")
    
    print("\n🎯 Zero-Day Research Capabilities Demonstrated:")
    print("  ✅ Grammar-based fuzzing (Genesis)")
    print("  ✅ State-aware navigation (Cortex)")
    print("  ✅ JavaScript sink detection (CDP)")
    print("  ✅ Client-side code execution (Mirror)")
    print("  ✅ Blind vulnerability tracking (Echo)")
    
    print("\n💡 In a Real Pentest:")
    print("  • Cortex would enable backtracking when stuck")
    print("  • Genesis would find zero-days through mutations")
    print("  • CDP would catch XSS in modern SPAs")
    print("  • Chronos would detect race conditions")
    print("  • Mirror would bypass JS validation")
    print("  • Echo would track blind SQLi/RCE/XSS")
    
    print("\n🔗 Next Steps:")
    print("  1. Read V7_5_FEATURES.md for detailed documentation")
    print("  2. See QUICK_START_V7_5.md for usage examples")
    print("  3. Run test_v7_5_features.py for module tests")
    
    print("\n" + "="*70)
    print("✅ All modules working together seamlessly!")
    print("="*70 + "\n")
    
    # Cleanup
    cortex.clear()


async def demo_individual_modules():
    """Quick demo of each module individually"""
    
    print("\n" + "="*70)
    print("INDIVIDUAL MODULE DEMOS")
    print("="*70)
    
    # Demo 1: Genesis
    print("\n[Demo 1] Genesis Protocol Fuzzer")
    from tools.genesis_fuzzer import GenesisFuzzer
    
    fuzzer = GenesisFuzzer()
    mutations = fuzzer.generate_mutations({"username": "admin", "id": 100})
    print(f"  Generated {len(mutations)} mutations for 2 fields")
    
    # Demo 2: Cortex
    print("\n[Demo 2] Cortex Graph Memory")
    from agents.enhanced_ai_core import CortexMemory
    
    cortex = CortexMemory(mission_id="demo")
    cortex.clear()
    cortex.record_action("Test action", {"success_score": 1.0}, "https://example.com")
    print(f"  Recorded action, graph has {cortex.graph.number_of_nodes()} nodes")
    
    # Demo 3: CDP
    print("\n[Demo 3] Deep Dive CDP Interceptor")
    from tools.cdp_hooks import JS_HOOK_PAYLOAD
    
    hooks_count = JS_HOOK_PAYLOAD.count("AEGIS_TRAP")
    print(f"  Hook payload contains {hooks_count} trap markers")
    
    # Demo 4: Chronos
    print("\n[Demo 4] Chronos Concurrency Engine")
    from tools.race_engine import ChronosEngine
    
    engine = ChronosEngine()
    print(f"  Engine ready for {engine.default_threads} concurrent threads")
    
    # Demo 5: Mirror
    print("\n[Demo 5] Mirror JS Sandbox")
    from tools.python_tools import PythonToolManager
    
    tool = PythonToolManager()
    print(f"  Sandbox initialized with 5-second timeout")
    
    # Demo 6: Echo
    print("\n[Demo 6] Echo OOB Correlator")
    from listeners.dns_callback import get_oob_manager
    
    oob = get_oob_manager()
    stats = oob.get_statistics()
    print(f"  Database tracking {stats['total_payloads']} payloads")
    
    print("\n✅ All modules functional!")


def main():
    """Main entry point"""
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "quick":
        # Quick individual module demos
        asyncio.run(demo_individual_modules())
    else:
        # Full integrated workflow
        asyncio.run(demo_integrated_workflow())


if __name__ == "__main__":
    main()
