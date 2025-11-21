#!/usr/bin/env python3
"""
Test script for API Key Sharding functionality
Validates that the API key registry works correctly with fallback logic
"""

import asyncio
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from agents.multi_llm_orchestrator import MultiLLMOrchestrator

async def test_master_key_only():
    """Test backward compatibility: only OPENROUTER_API_KEY set"""
    print("\n" + "=" * 80)
    print("TEST 1: Master Key Only (Backward Compatibility)")
    print("=" * 80)
    
    # Set only master key
    os.environ["OPENROUTER_API_KEY"] = "test_master_key_12345"
    
    # Clear all role-specific keys
    for key in ["STRATEGIC_API_KEY", "REASONING_API_KEY", "CODE_API_KEY", "VISUAL_API_KEY"]:
        if key in os.environ:
            del os.environ[key]
    
    try:
        orchestrator = MultiLLMOrchestrator()
        await orchestrator.initialize()
        
        # Verify all roles fall back to master key
        expected_key = "test_master_key_12345"
        for role, key in orchestrator.api_keys.items():
            assert key == expected_key, f"Role '{role}' should use master key, got: {key}"
            print(f"  ✅ {role}: Correctly using master key")
        
        print("\n✅ TEST 1 PASSED: All roles correctly fallback to master key")
        return True
        
    except Exception as e:
        print(f"\n❌ TEST 1 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_role_specific_keys():
    """Test with role-specific keys set"""
    print("\n" + "=" * 80)
    print("TEST 2: Role-Specific Keys")
    print("=" * 80)
    
    # Set master key and role-specific keys
    os.environ["OPENROUTER_API_KEY"] = "master_key"
    os.environ["STRATEGIC_API_KEY"] = "strategic_key_123"
    os.environ["REASONING_API_KEY"] = "reasoning_key_456"
    os.environ["CODE_API_KEY"] = "code_key_789"
    os.environ["VISUAL_API_KEY"] = "visual_key_000"
    
    try:
        orchestrator = MultiLLMOrchestrator()
        await orchestrator.initialize()
        
        # Verify each role uses its specific key
        expected_keys = {
            'strategic': 'strategic_key_123',
            'vulnerability': 'reasoning_key_456',
            'coder': 'code_key_789',
            'visual': 'visual_key_000'
        }
        
        for role, expected_key in expected_keys.items():
            actual_key = orchestrator.api_keys[role]
            assert actual_key == expected_key, f"Role '{role}' should use '{expected_key}', got: {actual_key}"
            print(f"  ✅ {role}: Correctly using role-specific key")
        
        print("\n✅ TEST 2 PASSED: All roles correctly use their specific keys")
        return True
        
    except Exception as e:
        print(f"\n❌ TEST 2 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_partial_keys_with_fallback():
    """Test with some role-specific keys and some falling back to master"""
    print("\n" + "=" * 80)
    print("TEST 3: Partial Keys with Fallback")
    print("=" * 80)
    
    # Set master key and only some role-specific keys
    os.environ["OPENROUTER_API_KEY"] = "master_key_xyz"
    os.environ["STRATEGIC_API_KEY"] = "strategic_only_123"
    os.environ["CODE_API_KEY"] = "code_only_456"
    
    # Clear other role-specific keys
    for key in ["REASONING_API_KEY", "VISUAL_API_KEY"]:
        if key in os.environ:
            del os.environ[key]
    
    try:
        orchestrator = MultiLLMOrchestrator()
        await orchestrator.initialize()
        
        # Verify mixed usage
        expected_keys = {
            'strategic': 'strategic_only_123',  # specific key
            'vulnerability': 'master_key_xyz',   # fallback
            'coder': 'code_only_456',           # specific key
            'visual': 'master_key_xyz'          # fallback
        }
        
        for role, expected_key in expected_keys.items():
            actual_key = orchestrator.api_keys[role]
            assert actual_key == expected_key, f"Role '{role}' should use '{expected_key}', got: {actual_key}"
            key_type = "specific" if expected_key != "master_key_xyz" else "fallback"
            print(f"  ✅ {role}: Correctly using {key_type} key")
        
        print("\n✅ TEST 3 PASSED: Partial keys with fallback working correctly")
        return True
        
    except Exception as e:
        print(f"\n❌ TEST 3 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_missing_all_keys():
    """Test validation: no master key and no role-specific keys"""
    print("\n" + "=" * 80)
    print("TEST 4: Missing All Keys (Validation Test)")
    print("=" * 80)
    
    # Clear all keys
    for key in ["OPENROUTER_API_KEY", "STRATEGIC_API_KEY", "REASONING_API_KEY", "CODE_API_KEY", "VISUAL_API_KEY"]:
        if key in os.environ:
            del os.environ[key]
    
    try:
        orchestrator = MultiLLMOrchestrator()
        await orchestrator.initialize()
        
        # Should never reach here
        print("\n❌ TEST 4 FAILED: Should have raised ValueError for missing keys")
        return False
        
    except ValueError as e:
        # This is expected
        error_msg = str(e)
        assert "CRITICAL: Missing API keys for roles" in error_msg, f"Unexpected error message: {error_msg}"
        assert "strategic" in error_msg, "Error should mention 'strategic' role"
        assert "vulnerability" in error_msg, "Error should mention 'vulnerability' role"
        assert "coder" in error_msg, "Error should mention 'coder' role"
        assert "visual" in error_msg, "Error should mention 'visual' role"
        print(f"  ✅ Correctly raised ValueError: {error_msg[:100]}...")
        print("\n✅ TEST 4 PASSED: Missing keys correctly detected and reported")
        return True
        
    except Exception as e:
        print(f"\n❌ TEST 4 FAILED with unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_empty_string_keys():
    """Test validation: empty string keys should be treated as missing"""
    print("\n" + "=" * 80)
    print("TEST 5: Empty String Keys (Validation Test)")
    print("=" * 80)
    
    # Set empty string keys
    os.environ["OPENROUTER_API_KEY"] = ""
    os.environ["STRATEGIC_API_KEY"] = "   "  # whitespace only
    
    # Clear other keys
    for key in ["REASONING_API_KEY", "CODE_API_KEY", "VISUAL_API_KEY"]:
        if key in os.environ:
            del os.environ[key]
    
    try:
        orchestrator = MultiLLMOrchestrator()
        await orchestrator.initialize()
        
        # Should never reach here
        print("\n❌ TEST 5 FAILED: Should have raised ValueError for empty/whitespace keys")
        return False
        
    except ValueError as e:
        # This is expected
        error_msg = str(e)
        assert "CRITICAL: Missing API keys" in error_msg, f"Unexpected error message: {error_msg}"
        print(f"  ✅ Correctly raised ValueError for empty keys: {error_msg[:100]}...")
        print("\n✅ TEST 5 PASSED: Empty keys correctly detected as invalid")
        return True
        
    except Exception as e:
        print(f"\n❌ TEST 5 FAILED with unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_key_registry_structure():
    """Test that the key registry has the correct structure"""
    print("\n" + "=" * 80)
    print("TEST 6: Key Registry Structure")
    print("=" * 80)
    
    # Set master key and clear all role-specific keys
    os.environ["OPENROUTER_API_KEY"] = "test_key"
    for key in ["STRATEGIC_API_KEY", "REASONING_API_KEY", "CODE_API_KEY", "VISUAL_API_KEY"]:
        if key in os.environ:
            del os.environ[key]
    
    try:
        orchestrator = MultiLLMOrchestrator()
        await orchestrator.initialize()
        
        # Check that all expected roles are in the registry
        expected_roles = {'strategic', 'vulnerability', 'coder', 'visual'}
        actual_roles = set(orchestrator.api_keys.keys())
        
        assert actual_roles == expected_roles, f"Expected roles {expected_roles}, got {actual_roles}"
        print(f"  ✅ All expected roles present in registry: {expected_roles}")
        
        # Check that legacy self.api_key is maintained
        assert hasattr(orchestrator, 'api_key'), "Legacy self.api_key attribute missing"
        assert orchestrator.api_key == "test_key", "Legacy self.api_key should equal master key"
        print(f"  ✅ Legacy self.api_key maintained for backward compatibility")
        
        print("\n✅ TEST 6 PASSED: Key registry structure is correct")
        return True
        
    except Exception as e:
        print(f"\n❌ TEST 6 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_whitespace_handling():
    """Test that whitespace in keys is properly stripped"""
    print("\n" + "=" * 80)
    print("TEST 7: Whitespace Handling")
    print("=" * 80)
    
    # Set keys with whitespace
    os.environ["OPENROUTER_API_KEY"] = "  master_key_with_spaces  "
    os.environ["STRATEGIC_API_KEY"] = "\tstrategic_key_with_tabs\t"
    
    try:
        orchestrator = MultiLLMOrchestrator()
        await orchestrator.initialize()
        
        # Verify whitespace is stripped
        assert orchestrator.api_keys['strategic'] == "strategic_key_with_tabs", "Whitespace not stripped from strategic key"
        assert orchestrator.api_keys['vulnerability'] == "master_key_with_spaces", "Whitespace not stripped from master key"
        
        print(f"  ✅ Whitespace correctly stripped from all keys")
        print("\n✅ TEST 7 PASSED: Whitespace handling works correctly")
        return True
        
    except Exception as e:
        print(f"\n❌ TEST 7 FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

async def main():
    """Run all tests"""
    print("\n" + "=" * 80)
    print("API KEY SHARDING - COMPREHENSIVE TEST SUITE")
    print("=" * 80)
    
    tests = [
        ("Master Key Only", test_master_key_only),
        ("Role-Specific Keys", test_role_specific_keys),
        ("Partial Keys with Fallback", test_partial_keys_with_fallback),
        ("Missing All Keys", test_missing_all_keys),
        ("Empty String Keys", test_empty_string_keys),
        ("Key Registry Structure", test_key_registry_structure),
        ("Whitespace Handling", test_whitespace_handling),
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
