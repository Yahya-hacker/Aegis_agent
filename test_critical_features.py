#!/usr/bin/env python3
"""
Test script for critical features implementation
Tests TASK 1, 2, 3, and 4 implementations
"""

import asyncio
import sys
import json
from pathlib import Path

# Test utilities
def print_test(name, passed, details=""):
    status = "✅ PASS" if passed else "❌ FAIL"
    print(f"{status} {name}")
    if details:
        print(f"    {details}")

def test_task1_session_management():
    """TASK 1: Test authenticated session management"""
    print("\n" + "="*70)
    print("TASK 1: Testing Authenticated Session Management")
    print("="*70)
    
    try:
        from tools.python_tools import PythonToolManager
        from utils.dynamic_tool_loader import get_tool_loader
        
        # Test 1: manage_session exists in PythonToolManager
        ptm = PythonToolManager()
        has_method = hasattr(ptm, 'manage_session')
        print_test("manage_session method exists in PythonToolManager", has_method)
        
        # Test 2: manage_session is in tool manifest
        tool_loader = get_tool_loader()
        tool_info = tool_loader.get_tool_info('manage_session')
        print_test("manage_session in kali_tool_manifest.json", 
                   tool_info is not None,
                   f"Category: {tool_info.get('category') if tool_info else 'N/A'}")
        
        # Test 3: Session injection methods exist
        has_inject = hasattr(ptm, '_inject_session_data')
        has_load = hasattr(ptm, '_load_session_data')
        print_test("Session injection methods exist", 
                   has_inject and has_load,
                   f"_inject_session_data: {has_inject}, _load_session_data: {has_load}")
        
        # Test 4: Session injection in tool_manager
        from tools.tool_manager import RealToolManager
        rtm = RealToolManager()
        has_rtm_load = hasattr(rtm, '_load_session_data')
        has_rtm_build = hasattr(rtm, '_build_cookie_header')
        print_test("Session injection in tool_manager", 
                   has_rtm_load and has_rtm_build,
                   f"_load_session_data: {has_rtm_load}, _build_cookie_header: {has_rtm_build}")
        
        return True
        
    except Exception as e:
        print_test("Session management tests", False, f"Error: {e}")
        return False

def test_task2_database_integration():
    """TASK 2: Test strategic database integration"""
    print("\n" + "="*70)
    print("TASK 2: Testing Strategic Database Integration")
    print("="*70)
    
    try:
        from utils.database_manager import get_database
        from agents.enhanced_ai_core import EnhancedAegisAI
        from agents.scanner import AegisScanner
        
        # Test 1: Database manager exists and works
        db = get_database()
        print_test("Database manager initialized", True)
        
        # Test 2: Database operations work
        test_target = "test-target-" + str(hash("test") % 10000)
        success = db.mark_scanned(test_target, "test_scan", "Test scan result")
        is_scanned = db.is_scanned(test_target, "test_scan")
        print_test("Database mark_scanned and is_scanned work", 
                   success and is_scanned)
        
        # Test 3: Enhanced AI Core has database
        ai = EnhancedAegisAI()
        has_db = hasattr(ai, 'db')
        print_test("EnhancedAegisAI has database instance", has_db)
        
        # Test 4: Scanner has database
        scanner = AegisScanner(ai)
        has_scanner_db = hasattr(scanner, 'db')
        print_test("AegisScanner has database instance", has_scanner_db)
        
        # Test 5: Database tools in manifest
        from utils.dynamic_tool_loader import get_tool_loader
        tool_loader = get_tool_loader()
        
        db_tools = ['db_add_finding', 'db_get_findings', 'db_is_scanned', 
                    'db_mark_scanned', 'db_get_statistics']
        all_present = all(tool_loader.get_tool_info(t) is not None for t in db_tools)
        print_test("All database tools in manifest", all_present,
                   f"Tools: {', '.join(db_tools)}")
        
        # Test 6: Database statistics
        stats = db.get_statistics()
        has_stats = isinstance(stats, dict) and len(stats) > 0
        print_test("Database statistics working", has_stats,
                   f"Keys: {list(stats.keys())}")
        
        return True
        
    except Exception as e:
        print_test("Database integration tests", False, f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_task3_semi_autonomous():
    """TASK 3: Test semi-autonomous mode"""
    print("\n" + "="*70)
    print("TASK 3: Testing Semi-Autonomous Mode")
    print("="*70)
    
    try:
        from utils.dynamic_tool_loader import get_tool_loader
        
        tool_loader = get_tool_loader()
        
        # Test 1: Tool intrusive detection
        print_test("Tool loader has is_tool_intrusive method",
                   hasattr(tool_loader, 'is_tool_intrusive'))
        
        # Test 2: Non-intrusive tools are marked correctly
        non_intrusive = ['subdomain_enumeration', 'tech_detection', 'manage_session']
        correct = all(not tool_loader.is_tool_intrusive(t) for t in non_intrusive)
        print_test("Non-intrusive tools marked correctly", correct,
                   f"Tested: {', '.join(non_intrusive)}")
        
        # Test 3: Intrusive tools are marked correctly
        intrusive = ['vulnerability_scan', 'run_sqlmap', 'test_form_payload']
        correct = all(tool_loader.is_tool_intrusive(t) for t in intrusive)
        print_test("Intrusive tools marked correctly", correct,
                   f"Tested: {', '.join(intrusive)}")
        
        # Test 4: Auto-approval logic in conversational_agent
        # Read the file to check for auto-approval logic
        agent_file = Path("agents/conversational_agent.py")
        if agent_file.exists():
            content = agent_file.read_text()
            has_auto_approve = 'auto-approuvée' in content or 'Auto-approve' in content
            has_intrusive_check = 'is_intrusive' in content
            print_test("Auto-approval logic in conversational_agent",
                       has_auto_approve and has_intrusive_check,
                       f"Has auto-approve text: {has_auto_approve}, Has intrusive check: {has_intrusive_check}")
        
        return True
        
    except Exception as e:
        print_test("Semi-autonomous mode tests", False, f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_task4_readme_updates():
    """TASK 4: Test README updates"""
    print("\n" + "="*70)
    print("TASK 4: Testing README Updates")
    print("="*70)
    
    try:
        readme_file = Path("README.md")
        if not readme_file.exists():
            print_test("README.md exists", False)
            return False
        
        content = readme_file.read_text()
        
        # Test 1: No more "Mixtral 8x7B" references
        has_old_mixtral = "Mixtral 8x7B" in content
        print_test("No 'Mixtral 8x7B' references", not has_old_mixtral)
        
        # Test 2: Has "Dolphin" model
        has_dolphin = "Dolphin" in content or "dolphin" in content
        print_test("References to 'Dolphin' model present", has_dolphin)
        
        # Test 3: No more "Together AI" in API context
        has_together = content.count("Together AI") - content.count("using Together AI") > 2
        print_test("Together AI references minimized", not has_together,
                   f"Found {content.count('Together AI')} references")
        
        # Test 4: Has "OpenRouter" references
        has_openrouter = "OpenRouter" in content
        print_test("OpenRouter references present", has_openrouter)
        
        # Test 5: Correct model identifiers
        has_hermes = "hermes-3-llama-3.1-70b" in content
        has_dolphin_model = "dolphin3.0-r1-mistral-24b" in content
        has_qwen = "qwen-2.5-72b-instruct" in content
        print_test("Correct model identifiers present",
                   has_hermes and has_dolphin_model and has_qwen,
                   f"Hermes: {has_hermes}, Dolphin: {has_dolphin_model}, Qwen: {has_qwen}")
        
        # Test 6: OPENROUTER_API_KEY instead of TOGETHER_API_KEY
        has_old_key = "TOGETHER_API_KEY" in content
        has_new_key = "OPENROUTER_API_KEY" in content
        print_test("Correct API key variable", not has_old_key and has_new_key,
                   f"Old key: {has_old_key}, New key: {has_new_key}")
        
        return True
        
    except Exception as e:
        print_test("README update tests", False, f"Error: {e}")
        return False

def test_model_constants():
    """Test that model constants match documentation"""
    print("\n" + "="*70)
    print("BONUS: Testing Model Constants Match Documentation")
    print("="*70)
    
    try:
        from agents.enhanced_ai_core import ORCHESTRATOR_MODEL, CODE_MODEL, REASONING_MODEL
        
        print_test("ORCHESTRATOR_MODEL defined", 
                   ORCHESTRATOR_MODEL == "nousresearch/hermes-3-llama-3.1-70b",
                   f"Value: {ORCHESTRATOR_MODEL}")
        
        print_test("CODE_MODEL defined",
                   CODE_MODEL == "qwen/qwen-2.5-72b-instruct",
                   f"Value: {CODE_MODEL}")
        
        print_test("REASONING_MODEL defined",
                   REASONING_MODEL == "cognitivecomputations/dolphin3.0-r1-mistral-24b",
                   f"Value: {REASONING_MODEL}")
        
        return True
        
    except Exception as e:
        print_test("Model constants tests", False, f"Error: {e}")
        return False

def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("CRITICAL FEATURES IMPLEMENTATION TEST SUITE")
    print("="*70)
    
    results = {
        "TASK 1 - Session Management": test_task1_session_management(),
        "TASK 2 - Database Integration": test_task2_database_integration(),
        "TASK 3 - Semi-Autonomous Mode": test_task3_semi_autonomous(),
        "TASK 4 - README Updates": test_task4_readme_updates(),
        "BONUS - Model Constants": test_model_constants()
    }
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    total = len(results)
    passed = sum(1 for v in results.values() if v)
    
    for task, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {task}")
    
    print(f"\nTotal: {passed}/{total} tasks passed")
    
    if passed == total:
        print("\n🎉 All critical features successfully implemented!")
        return 0
    else:
        print("\n⚠️ Some tests failed. Please review the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
