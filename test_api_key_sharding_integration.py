#!/usr/bin/env python3
"""
Integration test for API Key Sharding with backward compatibility
This test simulates the old behavior where only OPENROUTER_API_KEY is used
"""

import asyncio
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from agents.multi_llm_orchestrator import MultiLLMOrchestrator

async def test_backward_compatibility_integration():
    """Test that the system works exactly as before with only master key"""
    print("\n" + "=" * 80)
    print("BACKWARD COMPATIBILITY INTEGRATION TEST")
    print("Testing that old .env files (only OPENROUTER_API_KEY) still work")
    print("=" * 80)
    
    # Simulate old-style .env with only master key
    os.environ["OPENROUTER_API_KEY"] = "sk-test-backward-compatibility-key"
    
    # Ensure no role-specific keys are set (simulating old config)
    for key in ["STRATEGIC_API_KEY", "REASONING_API_KEY", "CODE_API_KEY", "VISUAL_API_KEY"]:
        if key in os.environ:
            del os.environ[key]
    
    try:
        print("\n1️⃣ Creating orchestrator...")
        orchestrator = MultiLLMOrchestrator()
        
        print("\n2️⃣ Initializing orchestrator...")
        await orchestrator.initialize()
        
        print("\n3️⃣ Verifying all roles use master key...")
        master_key = os.environ["OPENROUTER_API_KEY"]
        
        test_passed = True
        for role in ['strategic', 'vulnerability', 'coder', 'visual']:
            actual_key = orchestrator.api_keys[role]
            if actual_key != master_key:
                print(f"   ❌ FAIL: {role} key doesn't match master key")
                test_passed = False
            else:
                print(f"   ✅ {role}: Using master key")
        
        print("\n4️⃣ Verifying LLM configuration...")
        expected_llms = ['strategic', 'vulnerability', 'coder', 'visual']
        for llm_type in expected_llms:
            if llm_type not in orchestrator.llms:
                print(f"   ❌ FAIL: Missing LLM type '{llm_type}'")
                test_passed = False
            else:
                config = orchestrator.llms[llm_type]
                print(f"   ✅ {llm_type}: {config.role} ({config.model_name})")
        
        print("\n5️⃣ Verifying LLM selection logic...")
        test_selections = [
            ('mission_planning', 'strategic'),
            ('vulnerability_analysis', 'vulnerability'),
            ('code_analysis', 'coder'),
            ('triage', 'strategic'),
        ]
        
        for task, expected_llm in test_selections:
            selected = orchestrator.select_llm(task)
            if selected != expected_llm:
                print(f"   ❌ FAIL: Task '{task}' selected '{selected}', expected '{expected_llm}'")
                test_passed = False
            else:
                print(f"   ✅ {task} → {expected_llm}")
        
        print("\n6️⃣ Verifying legacy self.api_key attribute...")
        if orchestrator.api_key != master_key:
            print(f"   ❌ FAIL: Legacy self.api_key doesn't match master key")
            test_passed = False
        else:
            print(f"   ✅ Legacy self.api_key maintained correctly")
        
        if test_passed:
            print("\n" + "=" * 80)
            print("✅ BACKWARD COMPATIBILITY TEST PASSED")
            print("Old .env files with only OPENROUTER_API_KEY work perfectly!")
            print("=" * 80)
            return True
        else:
            print("\n" + "=" * 80)
            print("❌ BACKWARD COMPATIBILITY TEST FAILED")
            print("=" * 80)
            return False
            
    except Exception as e:
        print(f"\n❌ TEST FAILED WITH ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Clean up
        for key in ["OPENROUTER_API_KEY", "STRATEGIC_API_KEY", "REASONING_API_KEY", "CODE_API_KEY", "VISUAL_API_KEY"]:
            if key in os.environ:
                del os.environ[key]

async def test_new_api_key_sharding_integration():
    """Test that the new API key sharding feature works correctly"""
    print("\n" + "=" * 80)
    print("NEW API KEY SHARDING INTEGRATION TEST")
    print("Testing new feature with role-specific keys")
    print("=" * 80)
    
    # Simulate new-style .env with sharding
    os.environ["OPENROUTER_API_KEY"] = "sk-master-key"
    os.environ["STRATEGIC_API_KEY"] = "sk-strategic-specific"
    os.environ["CODE_API_KEY"] = "sk-code-specific"
    # Leave REASONING_API_KEY and VISUAL_API_KEY unset to test partial sharding
    
    try:
        print("\n1️⃣ Creating orchestrator with partial key sharding...")
        orchestrator = MultiLLMOrchestrator()
        
        print("\n2️⃣ Initializing orchestrator...")
        await orchestrator.initialize()
        
        print("\n3️⃣ Verifying key assignments...")
        expected_keys = {
            'strategic': 'sk-strategic-specific',  # specific key
            'vulnerability': 'sk-master-key',      # fallback to master
            'coder': 'sk-code-specific',           # specific key
            'visual': 'sk-master-key'              # fallback to master
        }
        
        test_passed = True
        for role, expected_key in expected_keys.items():
            actual_key = orchestrator.api_keys[role]
            key_type = "specific" if "specific" in expected_key else "master"
            if actual_key != expected_key:
                print(f"   ❌ FAIL: {role} key doesn't match expected")
                test_passed = False
            else:
                print(f"   ✅ {role}: Using {key_type} key")
        
        print("\n4️⃣ Verifying orchestrator is ready...")
        if not orchestrator.is_initialized:
            print(f"   ❌ FAIL: Orchestrator not initialized")
            test_passed = False
        else:
            print(f"   ✅ Orchestrator initialized successfully")
        
        if test_passed:
            print("\n" + "=" * 80)
            print("✅ API KEY SHARDING INTEGRATION TEST PASSED")
            print("Role-specific keys work correctly with fallback!")
            print("=" * 80)
            return True
        else:
            print("\n" + "=" * 80)
            print("❌ API KEY SHARDING INTEGRATION TEST FAILED")
            print("=" * 80)
            return False
            
    except Exception as e:
        print(f"\n❌ TEST FAILED WITH ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Clean up
        for key in ["OPENROUTER_API_KEY", "STRATEGIC_API_KEY", "REASONING_API_KEY", "CODE_API_KEY", "VISUAL_API_KEY"]:
            if key in os.environ:
                del os.environ[key]

async def main():
    """Run all integration tests"""
    print("\n" + "=" * 80)
    print("API KEY SHARDING - INTEGRATION TEST SUITE")
    print("=" * 80)
    
    test1 = await test_backward_compatibility_integration()
    test2 = await test_new_api_key_sharding_integration()
    
    print("\n" + "=" * 80)
    print("INTEGRATION TEST SUMMARY")
    print("=" * 80)
    print(f"{'✅ PASS' if test1 else '❌ FAIL'}: Backward Compatibility Integration")
    print(f"{'✅ PASS' if test2 else '❌ FAIL'}: API Key Sharding Integration")
    print("=" * 80)
    
    if test1 and test2:
        print("\n🎉 ALL INTEGRATION TESTS PASSED!")
        sys.exit(0)
    else:
        print("\n❌ SOME INTEGRATION TESTS FAILED")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
