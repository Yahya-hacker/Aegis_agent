#!/usr/bin/env python3
"""
Aegis v8.0 Full-Spectrum Architecture Integration Tests

Tests all key components of the v8.0 architecture:
1. 4-Role LLM orchestration
2. Domain context auto-detection and routing
3. All 5 specialized capability engines
4. Self-healing infrastructure
5. Blackboard memory system
6. Genesis fuzzer integration
7. Visual SoM capability
"""

import asyncio
import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Test results tracking
test_results = []

# Shared mock classes to avoid duplication
class MockOrchestrator:
    """Mock orchestrator for testing"""
    async def call_llm(self, *args, **kwargs):
        return {'content': '{}'}
    
    def set_domain_context(self, context):
        self._context = context
    
    def get_domain_context(self):
        return getattr(self, '_context', None)

class MockBlackboard:
    """Mock blackboard for testing"""
    def set_domain_context(self, context):
        self._context = context

class MockAICore:
    """Mock AI core for testing"""
    orchestrator = MockOrchestrator()
    blackboard = MockBlackboard()

def test_result(name: str, passed: bool, details: str = ""):
    """Record a test result"""
    status = "✅ PASS" if passed else "❌ FAIL"
    test_results.append({
        "name": name,
        "passed": passed,
        "details": details
    })
    print(f"{status}: {name}")
    if details:
        print(f"    {details}")

async def test_orchestrator_initialization():
    """Test 1: Multi-LLM Orchestrator Initialization"""
    try:
        from agents.multi_llm_orchestrator import MultiLLMOrchestrator
        
        orchestrator = MultiLLMOrchestrator()
        
        # Check 4-role architecture
        expected_roles = ['strategic', 'vulnerability', 'coder', 'visual']
        actual_roles = list(orchestrator.llms.keys())
        
        roles_match = set(expected_roles) == set(actual_roles)
        test_result(
            "4-Role Architecture (Strategic, Vulnerability, Coder, Visual)",
            roles_match,
            f"Found roles: {actual_roles}"
        )
        
        # Check model configuration
        strategic_model = orchestrator.llms['strategic'].model_name
        # Verify model is set (either default or from env)
        model_is_valid = strategic_model and len(strategic_model) > 0
        test_result(
            "Strategic Model Configuration",
            model_is_valid,
            f"Model: {strategic_model}"
        )
        
        # Check domain context capability
        has_set_context = hasattr(orchestrator, 'set_domain_context')
        has_get_context = hasattr(orchestrator, 'get_domain_context')
        test_result(
            "Domain Context Methods",
            has_set_context and has_get_context,
            f"set_domain_context: {has_set_context}, get_domain_context: {has_get_context}"
        )
        
        return True
    except Exception as e:
        test_result("Multi-LLM Orchestrator Initialization", False, str(e))
        return False

async def test_capability_engines():
    """Test 2: All 5 Specialized Capability Engines"""
    try:
        from tools.capabilities import (
            get_crypto_engine,
            get_reverse_engine,
            get_forensics_lab,
            get_pwn_exploiter,
            get_network_sentry
        )
        
        engines = {
            "CryptoEngine": get_crypto_engine(),
            "ReverseEngine": get_reverse_engine(),
            "ForensicsLab": get_forensics_lab(),
            "PwnExploiter": get_pwn_exploiter(),
            "NetworkSentry": get_network_sentry()
        }
        
        for name, engine in engines.items():
            test_result(
                f"Capability Engine: {name}",
                engine is not None,
                f"Type: {type(engine).__name__}"
            )
        
        return True
    except Exception as e:
        test_result("Capability Engines Initialization", False, str(e))
        return False

async def test_scanner_integration():
    """Test 3: Scanner Integration with All Engines"""
    try:
        from agents.scanner import AegisScanner
        
        scanner = AegisScanner(MockAICore())
        
        # Check all engines are initialized
        engines_check = {
            "crypto_engine": scanner.crypto_engine,
            "reverse_engine": scanner.reverse_engine,
            "forensics_lab": scanner.forensics_lab,
            "pwn_exploiter": scanner.pwn_exploiter,
            "network_sentry": scanner.network_sentry,
            "genesis_fuzzer": scanner.genesis_fuzzer,
            "visual_recon": scanner.visual_recon
        }
        
        all_initialized = all(engine is not None for engine in engines_check.values())
        test_result(
            "Scanner: All Engines Initialized",
            all_initialized,
            f"Engines: {', '.join(engines_check.keys())}"
        )
        
        # Check self-healing method exists
        has_fallback = hasattr(scanner, '_execute_with_fallback')
        test_result(
            "Scanner: Self-Healing Infrastructure",
            has_fallback,
            "Method: _execute_with_fallback"
        )
        
        return all_initialized
    except Exception as e:
        test_result("Scanner Integration", False, str(e))
        return False

async def test_blackboard_memory():
    """Test 4: Blackboard Memory System"""
    try:
        from agents.enhanced_ai_core import MissionBlackboard
        
        blackboard = MissionBlackboard(mission_id="test_v8")
        
        # Test domain context
        blackboard.set_domain_context("Binary")
        context = blackboard.get_domain_context()
        test_result(
            "Blackboard: Domain Context",
            context == "Binary",
            f"Set: Binary, Got: {context}"
        )
        
        # Test fact storage
        blackboard.add_fact("Port 443 is open")
        test_result(
            "Blackboard: Fact Storage",
            len(blackboard.verified_facts) > 0,
            f"Facts: {len(blackboard.verified_facts)}"
        )
        
        # Test knowledge graph
        blackboard.add_relationship("admin.example.com", "HAS_VULN", "SQLi")
        test_result(
            "Blackboard: Knowledge Graph",
            blackboard.knowledge_graph.number_of_edges() > 0,
            f"Edges: {blackboard.knowledge_graph.number_of_edges()}"
        )
        
        # Cleanup
        blackboard.clear()
        
        return True
    except Exception as e:
        test_result("Blackboard Memory System", False, str(e))
        return False

async def test_domain_context_detection():
    """Test 5: Domain Context Auto-Detection"""
    try:
        from agents.conversational_agent import AegisConversation
        
        conversation = AegisConversation(MockAICore())
        
        # Test Binary detection
        context = conversation._detect_domain_context(
            target="challenge.pwn.me",
            rules="binary exploitation challenge with buffer overflow"
        )
        test_result(
            "Domain Detection: Binary/Pwn",
            context == "Binary",
            f"Detected: {context}"
        )
        
        # Test Crypto detection
        context = conversation._detect_domain_context(
            target="crypto_challenge.zip",
            rules="decrypt the RSA encrypted message"
        )
        test_result(
            "Domain Detection: Crypto",
            context == "Crypto",
            f"Detected: {context}"
        )
        
        # Test Web detection
        context = conversation._detect_domain_context(
            target="https://example.com",
            rules="test for XSS and SQLi vulnerabilities"
        )
        test_result(
            "Domain Detection: Web",
            context == "Web",
            f"Detected: {context}"
        )
        
        return True
    except Exception as e:
        test_result("Domain Context Auto-Detection", False, str(e))
        return False

async def test_genesis_fuzzer():
    """Test 6: Genesis Fuzzer Integration"""
    try:
        from tools.genesis_fuzzer import get_genesis_fuzzer
        
        fuzzer = get_genesis_fuzzer()
        
        test_result(
            "Genesis Fuzzer: Initialization",
            fuzzer is not None,
            f"Type: {type(fuzzer).__name__}"
        )
        
        # Check mutation strategies exist
        has_mutations = hasattr(fuzzer, '_byte_level_mutation')
        has_fuzzing = hasattr(fuzzer, 'fuzz_endpoint')
        test_result(
            "Genesis Fuzzer: Mutation & Fuzzing Capability",
            has_mutations and has_fuzzing,
            f"_byte_level_mutation: {has_mutations}, fuzz_endpoint: {has_fuzzing}"
        )
        
        return True
    except Exception as e:
        test_result("Genesis Fuzzer Integration", False, str(e))
        return False

async def test_visual_som():
    """Test 7: Visual SoM (Set-of-Mark) Capability"""
    try:
        from tools.visual_recon import get_visual_recon_tool
        
        visual_tool = get_visual_recon_tool()
        
        test_result(
            "Visual SoM: Initialization",
            visual_tool is not None,
            f"Type: {type(visual_tool).__name__}"
        )
        
        # Check SoM methods exist
        has_som = hasattr(visual_tool, 'capture_with_som')
        has_click = hasattr(visual_tool, 'click_element')
        test_result(
            "Visual SoM: Methods",
            has_som and has_click,
            f"capture_with_som: {has_som}, click_element: {has_click}"
        )
        
        return True
    except Exception as e:
        test_result("Visual SoM Capability", False, str(e))
        return False

async def main():
    """Run all integration tests"""
    print("=" * 70)
    print("AEGIS v8.0 FULL-SPECTRUM ARCHITECTURE INTEGRATION TESTS")
    print("=" * 70)
    print()
    
    # Run all tests
    await test_orchestrator_initialization()
    print()
    
    await test_capability_engines()
    print()
    
    await test_scanner_integration()
    print()
    
    await test_blackboard_memory()
    print()
    
    await test_domain_context_detection()
    print()
    
    await test_genesis_fuzzer()
    print()
    
    await test_visual_som()
    print()
    
    # Summary
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    total = len(test_results)
    passed = sum(1 for r in test_results if r['passed'])
    failed = total - passed
    
    print(f"Total Tests: {total}")
    print(f"Passed: {passed} ✅")
    print(f"Failed: {failed} ❌")
    print(f"Success Rate: {(passed/total*100):.1f}%")
    print()
    
    if failed > 0:
        print("Failed Tests:")
        for result in test_results:
            if not result['passed']:
                print(f"  ❌ {result['name']}")
                if result['details']:
                    print(f"     {result['details']}")
    else:
        print("🎉 ALL TESTS PASSED! Aegis v8.0 Full-Spectrum Architecture is fully operational.")
    
    print()
    
    # Exit code
    sys.exit(0 if failed == 0 else 1)

if __name__ == "__main__":
    asyncio.run(main())
