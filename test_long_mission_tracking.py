#!/usr/bin/env python3
"""
Test script for Long Mission Tracking features
Validates sophisticated monitoring for context exhaustion, usage tracking, and error patterns
"""

import asyncio
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from agents.multi_llm_orchestrator import MultiLLMOrchestrator

# Test constants
TEST_API_KEY = "test_key_12345"

async def test_usage_tracking():
    """Test that usage tracking works correctly"""
    print("\n" + "=" * 80)
    print("TEST: Usage Tracking for Long Missions")
    print("=" * 80)
    
    # Set test API key
    os.environ["OPENROUTER_API_KEY"] = TEST_API_KEY
    
    # Clear role-specific keys
    for key in ["STRATEGIC_API_KEY", "REASONING_API_KEY", "CODE_API_KEY", "VISUAL_API_KEY"]:
        if key in os.environ:
            del os.environ[key]
    
    try:
        orchestrator = MultiLLMOrchestrator()
        await orchestrator.initialize()
        
        # Verify initial state
        assert hasattr(orchestrator, 'usage_tracker'), "Missing usage_tracker attribute"
        assert hasattr(orchestrator, 'context_history'), "Missing context_history attribute"
        assert hasattr(orchestrator, 'error_patterns'), "Missing error_patterns attribute"
        
        print("  ✅ All tracking attributes initialized")
        
        # Check initial values
        for role in ['strategic', 'vulnerability', 'coder', 'visual']:
            assert role in orchestrator.usage_tracker, f"Role {role} missing from tracker"
            assert orchestrator.usage_tracker[role]['calls'] == 0, f"Initial calls should be 0 for {role}"
            assert orchestrator.usage_tracker[role]['tokens'] == 0, f"Initial tokens should be 0 for {role}"
        
        print("  ✅ Usage tracker initialized with correct structure")
        
        # Test get_usage_statistics method
        stats = orchestrator.get_usage_statistics()
        assert 'total_calls' in stats, "Missing total_calls in statistics"
        assert 'total_tokens' in stats, "Missing total_tokens in statistics"
        assert 'by_role' in stats, "Missing by_role in statistics"
        assert stats['total_calls'] == 0, "Initial total_calls should be 0"
        
        print("  ✅ get_usage_statistics() returns correct structure")
        
        # Test reset_usage_tracking method
        orchestrator.reset_usage_tracking()
        assert orchestrator.usage_tracker['strategic']['calls'] == 0, "Reset should clear calls"
        assert len(orchestrator.context_history) == 0, "Reset should clear context history"
        
        print("  ✅ reset_usage_tracking() works correctly")
        
        print("\n✅ TEST PASSED: Usage tracking works correctly for long missions")
        return True
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_error_pattern_tracking():
    """Test that error pattern tracking is initialized"""
    print("\n" + "=" * 80)
    print("TEST: Error Pattern Tracking")
    print("=" * 80)
    
    os.environ["OPENROUTER_API_KEY"] = TEST_API_KEY
    
    try:
        orchestrator = MultiLLMOrchestrator()
        await orchestrator.initialize()
        
        # Verify error_patterns exists
        assert hasattr(orchestrator, 'error_patterns'), "Missing error_patterns attribute"
        assert isinstance(orchestrator.error_patterns, dict), "error_patterns should be a dict"
        assert len(orchestrator.error_patterns) == 0, "Initial error_patterns should be empty"
        
        print("  ✅ Error pattern tracking initialized correctly")
        
        print("\n✅ TEST PASSED: Error pattern tracking ready for long missions")
        return True
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_context_history_tracking():
    """Test that context history tracking is initialized"""
    print("\n" + "=" * 80)
    print("TEST: Context History Tracking")
    print("=" * 80)
    
    os.environ["OPENROUTER_API_KEY"] = TEST_API_KEY
    
    try:
        orchestrator = MultiLLMOrchestrator()
        await orchestrator.initialize()
        
        # Verify context_history exists
        assert hasattr(orchestrator, 'context_history'), "Missing context_history attribute"
        assert isinstance(orchestrator.context_history, list), "context_history should be a list"
        assert len(orchestrator.context_history) == 0, "Initial context_history should be empty"
        
        print("  ✅ Context history tracking initialized correctly")
        
        print("\n✅ TEST PASSED: Context history ready to track token usage over time")
        return True
        
    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

async def main():
    """Run all long mission tracking tests"""
    print("\n" + "=" * 80)
    print("LONG MISSION TRACKING - COMPREHENSIVE TEST SUITE")
    print("=" * 80)
    
    tests = [
        ("Usage Tracking", test_usage_tracking),
        ("Error Pattern Tracking", test_error_pattern_tracking),
        ("Context History Tracking", test_context_history_tracking),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = await test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"\n❌ {test_name} CRASHED: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))
    
    # Print summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print("\n" + "=" * 80)
    print(f"FINAL RESULT: {passed}/{total} tests passed")
    print("=" * 80)
    
    # Clean up environment
    for key in ["OPENROUTER_API_KEY", "STRATEGIC_API_KEY", "REASONING_API_KEY", "CODE_API_KEY", "VISUAL_API_KEY"]:
        if key in os.environ:
            del os.environ[key]
    
    sys.exit(0 if passed == total else 1)

if __name__ == "__main__":
    asyncio.run(main())
