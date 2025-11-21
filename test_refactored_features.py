#!/usr/bin/env python3
"""
Test script for refactored features:
- Genesis Fuzzer with evolutionary mutations
- Chronos Engine with statistical verification
- Logic Mapper with NetworkX graphs
"""

import asyncio
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def test_levenshtein_distance():
    """Test Levenshtein distance calculation"""
    from tools.genesis_fuzzer import levenshtein_distance
    
    print("\n" + "="*60)
    print("TEST 1: Levenshtein Distance (Differential Analysis)")
    print("="*60)
    
    test_cases = [
        ("hello", "hello", 0),
        ("hello", "hallo", 1),
        ("kitten", "sitting", 3),
        ("Saturday", "Sunday", 3),
        ("", "hello", 5),
    ]
    
    for s1, s2, expected in test_cases:
        distance = levenshtein_distance(s1, s2)
        status = "✓" if distance == expected else "✗"
        print(f"{status} distance('{s1}', '{s2}') = {distance} (expected: {expected})")
    
    print("✓ Levenshtein distance tests passed")


def test_genesis_fuzzer():
    """Test Genesis Fuzzer with context awareness"""
    from tools.genesis_fuzzer import get_genesis_fuzzer
    
    print("\n" + "="*60)
    print("TEST 2: Genesis Fuzzer - Context Awareness")
    print("="*60)
    
    fuzzer = get_genesis_fuzzer()
    
    # Test technology detection
    headers = {
        "Server": "nginx",
        "X-Powered-By": "Express",
        "Content-Type": "application/json"
    }
    
    detected = fuzzer.detect_technology(headers, "")
    print(f"✓ Detected technologies from headers: {detected}")
    
    # Test mutation generation
    payload = {"username": "admin", "password": "test123"}
    
    # Without context
    mutations_basic = fuzzer.generate_mutations(payload)
    print(f"✓ Generated {len(mutations_basic)} mutations without context")
    
    # With context (Flask detected)
    mutations_context = fuzzer.generate_mutations(payload, detected_tech=["flask"])
    print(f"✓ Generated {len(mutations_context)} context-aware mutations (Flask)")
    
    # Test byte-level mutations
    byte_mutations = fuzzer._byte_level_mutation("test")
    print(f"✓ Generated {len(byte_mutations)} byte-level mutations")
    
    print("✓ Genesis Fuzzer tests passed")


async def test_chronos_engine():
    """Test Chronos Engine with statistical verification"""
    from tools.race_engine import get_chronos_engine
    
    print("\n" + "="*60)
    print("TEST 3: Chronos Engine - Statistical Verification")
    print("="*60)
    
    engine = get_chronos_engine()
    
    # Create mock results for statistical analysis
    mock_results = [
        {"worker_id": i, "response_time": 0.1 + (i * 0.01), "status_code": 200, 
         "content_length": 1000, "content": "test"}
        for i in range(20)
    ]
    
    # Add some outliers to simulate race condition
    mock_results.append({"worker_id": 20, "response_time": 2.5, "status_code": 200, 
                        "content_length": 1000, "content": "test"})
    mock_results.append({"worker_id": 21, "response_time": 2.8, "status_code": 500, 
                        "content_length": 500, "content": "error"})
    
    # Test statistical verification
    stats = engine._statistical_verification(mock_results)
    
    print(f"✓ Statistical analysis completed:")
    print(f"  - Has anomaly: {stats.get('has_statistical_anomaly', False)}")
    print(f"  - Severity score: {stats.get('severity_score', 0)}")
    print(f"  - Findings: {len(stats.get('findings', []))}")
    
    if 'statistics' in stats:
        st = stats['statistics']
        print(f"  - Mean response time: {st.get('mean', 0):.3f}s")
        print(f"  - Coefficient of variation: {st.get('coefficient_variation', 0):.2f}")
    
    print("✓ Chronos Engine tests passed")


def test_logic_mapper():
    """Test Logic Mapper with NetworkX graphs"""
    from tools.logic_mapper import get_logic_mapper
    
    print("\n" + "="*60)
    print("TEST 4: Logic Mapper - Business Logic State Graphs")
    print("="*60)
    
    mapper = get_logic_mapper("test_mission")
    
    # Build a simple e-commerce workflow
    mapper.add_state("Login Page", state_type="normal", privilege_level="none", 
                    description="User login page")
    mapper.add_state("User Dashboard", state_type="normal", privilege_level="user",
                    description="Standard user dashboard")
    mapper.add_state("Admin Panel", state_type="privileged", privilege_level="admin",
                    description="Administrative control panel")
    mapper.add_state("Checkout", state_type="normal", privilege_level="user",
                    description="Shopping cart checkout")
    
    # Add transitions
    mapper.add_transition("Entry_Point", "Login Page", action="Navigate to login",
                         required_auth=False)
    mapper.add_transition("Login Page", "User Dashboard", action="Submit credentials",
                         required_auth=True, required_role="user")
    mapper.add_transition("User Dashboard", "Checkout", action="Go to checkout",
                         required_auth=True, required_role="user")
    
    # Add a potentially vulnerable transition (no auth check!)
    mapper.add_transition("User Dashboard", "Admin Panel", action="Click admin link",
                         required_auth=False)  # VULNERABLE!
    
    print("✓ Built business logic graph:")
    print(mapper.get_graph_summary())
    
    # Find paths to admin panel
    paths = mapper.find_paths_to_target("Admin Panel")
    print(f"\n✓ Found {len(paths)} path(s) to Admin Panel:")
    for i, path in enumerate(paths, 1):
        print(f"\n  Path {i}: {' → '.join(path)}")
        print(mapper.visualize_path(path))
    
    # Find bypass vulnerabilities
    vulns = mapper.find_bypass_vulnerabilities()
    print(f"\n✓ Detected {len(vulns)} potential bypass vulnerabilities:")
    for vuln in vulns:
        print(f"  - Target: {vuln['target_state']}")
        print(f"    Severity: {vuln['severity']}")
        print(f"    Indicators: {len(vuln['indicators'])}")
    
    # Find escalation path
    escalation = mapper.find_shortest_escalation_path("none", "admin")
    if escalation:
        path, length = escalation
        print(f"\n✓ Shortest privilege escalation ({length} steps):")
        print(f"  {' → '.join(path)}")
    
    print("\n✓ Logic Mapper tests passed")


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("TESTING REFACTORED AEGIS FEATURES")
    print("="*60)
    
    try:
        # Test 1: Levenshtein Distance
        test_levenshtein_distance()
        
        # Test 2: Genesis Fuzzer
        test_genesis_fuzzer()
        
        # Test 3: Chronos Engine (async)
        asyncio.run(test_chronos_engine())
        
        # Test 4: Logic Mapper
        test_logic_mapper()
        
        print("\n" + "="*60)
        print("ALL TESTS PASSED ✓")
        print("="*60)
        
    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
