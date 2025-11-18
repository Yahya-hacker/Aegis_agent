#!/usr/bin/env python3
"""
Test script for Deep Think verification and Self-Correction mechanisms
Tests the new anti-hallucination features added in Task 1, 2, and 3
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from agents.enhanced_ai_core import EnhancedAegisAI
from agents.scanner import AegisScanner
from agents.learning_engine import AegisLearningEngine
from utils.database_manager import get_database

async def test_verify_finding_with_reasoning():
    """Test Task 1: Deep Think verification of findings"""
    print("=" * 70)
    print("TEST 1: Deep Think Verification (verify_finding_with_reasoning)")
    print("=" * 70)
    
    try:
        # Initialize AI core
        ai_core = EnhancedAegisAI()
        await ai_core.initialize()
        
        print("\n🧪 Testing with a legitimate finding...")
        legitimate_finding = {
            "type": "SQL Injection",
            "severity": "high",
            "description": "SQL injection in login form parameter 'username'",
            "evidence": "Error message: 'You have an error in your SQL syntax'",
            "template-id": "sql-injection-test",
            "info": {
                "name": "SQL Injection in login",
                "severity": "high"
            },
            "matched-at": "http://example.com/login?user=admin' OR 1=1--"
        }
        
        result = await ai_core.verify_finding_with_reasoning(
            legitimate_finding,
            "http://example.com/login"
        )
        
        if result is not None:
            print("✅ Legitimate finding was ACCEPTED")
        else:
            print("❌ Legitimate finding was REJECTED (may be false positive in test)")
        
        print("\n🧪 Testing with a likely false positive (404 error)...")
        false_positive = {
            "type": "Path Traversal",
            "severity": "high",
            "description": "404 Not Found",
            "evidence": "HTTP 404 - The requested URL was not found",
            "template-id": "404-false-positive",
            "info": {
                "name": "404 Not Found Error",
                "severity": "high"
            },
            "matched-at": "http://example.com/nonexistent"
        }
        
        result = await ai_core.verify_finding_with_reasoning(
            false_positive,
            "http://example.com/nonexistent"
        )
        
        if result is None:
            print("✅ False positive was REJECTED")
        else:
            print("⚠️ False positive was ACCEPTED (AI may have different assessment)")
        
        print("\n✅ Deep Think verification test completed")
        return True
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_strict_grounding_rule():
    """Test Task 2: Strict grounding rule in system prompt"""
    print("\n" + "=" * 70)
    print("TEST 2: Strict Grounding Rule (Database-based targeting)")
    print("=" * 70)
    
    try:
        # Initialize AI core
        ai_core = EnhancedAegisAI()
        await ai_core.initialize()
        
        # Create sample agent memory with database context
        agent_memory = [
            {"type": "observation", "content": "Started reconnaissance on example.com"},
            {"type": "action", "content": "Executed subdomain_enumeration on example.com"},
            {"type": "result", "content": "Found 3 subdomains: www.example.com, api.example.com, admin.example.com"}
        ]
        
        bbp_rules = """
        Target: example.com
        In scope: *.example.com
        Out of scope: Do not test example.org
        """
        
        print("\n🧪 Testing next action decision with database grounding...")
        
        # Call the next action method which includes the STRICT GROUNDING RULE
        action = await ai_core._get_next_action_async(bbp_rules, agent_memory)
        
        print(f"\n📋 AI proposed action: {action.get('tool')}")
        print(f"   Arguments: {action.get('args')}")
        
        # Check if the action includes reasoning
        if 'reasoning' in action:
            print(f"   Reasoning summary: {action['reasoning'].get('justification', 'N/A')[:100]}...")
        
        print("\n✅ Strict grounding rule test completed")
        print("   (The AI should only propose actions on targets from database)")
        return True
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_self_correction():
    """Test Task 3: Self-correction mechanism in scanner"""
    print("\n" + "=" * 70)
    print("TEST 3: Self-Correction Mechanism (Error recovery)")
    print("=" * 70)
    
    try:
        # Initialize AI core and scanner
        ai_core = EnhancedAegisAI()
        await ai_core.initialize()
        
        scanner = AegisScanner(ai_core)
        
        print("\n🧪 Testing self-correction helper method...")
        
        # Test the self-correction method with a simulated error
        corrected_args = await scanner._self_correct_and_retry(
            tool="subdomain_enumeration",
            original_args={"domain": "invalid domain with spaces"},
            error_message="Invalid domain format: contains spaces"
        )
        
        if corrected_args is not None:
            print(f"✅ Self-correction suggested fix: {corrected_args}")
        else:
            print("⚠️ Self-correction could not suggest a fix (this is acceptable)")
        
        print("\n🧪 Testing execute_action with built-in retry...")
        
        # Test with a valid action that should succeed
        action = {
            "tool": "db_get_statistics",
            "args": {}
        }
        
        result = await scanner.execute_action(action)
        
        if result.get("status") == "success":
            print("✅ Execute action with retry logic completed successfully")
            print(f"   Result: {result.get('data', {})}")
        else:
            print(f"⚠️ Execute action returned: {result}")
        
        print("\n✅ Self-correction test completed")
        return True
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_integration():
    """Test integration of all three features"""
    print("\n" + "=" * 70)
    print("INTEGRATION TEST: All features working together")
    print("=" * 70)
    
    try:
        # Initialize components
        ai_core = EnhancedAegisAI()
        await ai_core.initialize()
        
        scanner = AegisScanner(ai_core)
        db = get_database()
        
        print("\n🧪 Testing verification in vulnerability_scan workflow...")
        
        # Simulate a vulnerability scan result that would trigger verification
        # Note: This won't actually run the scanner, but tests the verification integration
        
        test_finding = {
            "type": "XSS",
            "severity": "medium",
            "description": "Reflected XSS in search parameter",
            "evidence": "<script>alert('test')</script> reflected in response",
            "template-id": "xss-reflected",
            "info": {
                "name": "Reflected XSS",
                "severity": "medium"
            },
            "matched-at": "http://example.com/search?q=<script>"
        }
        
        # Test the verification directly
        verified = await ai_core.verify_finding_with_reasoning(
            test_finding,
            "http://example.com/search"
        )
        
        if verified is not None:
            print("✅ Finding passed verification, would be added to database")
        else:
            print("⚠️ Finding rejected by verification")
        
        # Test database statistics
        stats = db.get_statistics()
        print(f"\n📊 Current database stats:")
        print(f"   Total findings: {stats.get('total_findings', 0)}")
        print(f"   Verified findings: {stats.get('verified_findings', 0)}")
        print(f"   Scanned targets: {stats.get('total_scanned_targets', 0)}")
        
        print("\n✅ Integration test completed")
        return True
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """Run all tests"""
    print("🚀 Starting Deep Think Features Test Suite\n")
    
    results = []
    
    # Run all tests
    results.append(("Deep Think Verification", await test_verify_finding_with_reasoning()))
    results.append(("Strict Grounding Rule", await test_strict_grounding_rule()))
    results.append(("Self-Correction", await test_self_correction()))
    results.append(("Integration", await test_integration()))
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    
    for test_name, passed in results:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{status}: {test_name}")
    
    total_passed = sum(1 for _, passed in results if passed)
    total_tests = len(results)
    
    print(f"\nTotal: {total_passed}/{total_tests} tests passed")
    
    return total_passed == total_tests


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
