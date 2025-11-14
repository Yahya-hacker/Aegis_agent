#!/usr/bin/env python3
"""
Test suite for V5 Battle-Ready Platform features
Tests TASK 1-4 implementations
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

def test_database():
    """Test database manager functionality"""
    print("\n" + "="*70)
    print("Testing TASK 2: Mission Database")
    print("="*70)
    
    from utils.database_manager import get_database
    
    db = get_database()
    
    # Test adding findings
    print("✓ Testing add_finding...")
    id1 = db.add_finding('XSS', 'https://test.com/search', 'high', 'Test XSS')
    assert id1 > 0, "Failed to add finding"
    
    # Test getting findings
    print("✓ Testing get_findings...")
    findings = db.get_findings()
    assert len(findings) > 0, "Failed to retrieve findings"
    
    # Test scanning tracking
    print("✓ Testing mark_scanned...")
    result = db.mark_scanned('test.com', 'subdomain_enum', 'Test result')
    assert result == True, "Failed to mark as scanned"
    
    print("✓ Testing is_scanned...")
    is_scanned = db.is_scanned('test.com', 'subdomain_enum')
    assert is_scanned == True, "Failed to check if scanned"
    
    # Test statistics
    print("✓ Testing get_statistics...")
    stats = db.get_statistics()
    assert isinstance(stats, dict), "Failed to get statistics"
    assert stats['total_findings'] > 0, "Statistics incorrect"
    
    print("\n✅ TASK 2 (Database) - ALL TESTS PASSED")
    return True

def test_dynamic_tools():
    """Test dynamic tool loader"""
    print("\n" + "="*70)
    print("Testing TASK 3: Dynamic Arsenal")
    print("="*70)
    
    from utils.dynamic_tool_loader import get_tool_loader
    
    loader = get_tool_loader()
    
    # Test manifest loading
    print("✓ Testing manifest loading...")
    assert len(loader.all_tools) > 0, "No tools loaded from manifest"
    
    # Test tool discovery
    print("✓ Testing tool discovery...")
    available, unavailable = loader.discover_available_tools()
    assert len(available) > 0, "No tools discovered as available"
    
    # Test dynamic prompt generation
    print("✓ Testing dynamic prompt generation...")
    prompt = loader.build_dynamic_tool_prompt()
    assert len(prompt) > 0, "Failed to build dynamic prompt"
    assert "AVAILABLE TOOLS:" in prompt, "Prompt missing header"
    
    # Test tool info retrieval
    print("✓ Testing get_tool_info...")
    tool_info = loader.get_tool_info('fetch_url')
    assert tool_info is not None, "Failed to get tool info"
    assert tool_info['tool_name'] == 'fetch_url', "Wrong tool info"
    
    # Test intrusive flag
    print("✓ Testing intrusive flag...")
    is_intrusive = loader.is_tool_intrusive('test_form_payload')
    assert is_intrusive == True, "Intrusive flag incorrect for test_form_payload"
    
    is_intrusive = loader.is_tool_intrusive('fetch_url')
    assert is_intrusive == False, "Intrusive flag incorrect for fetch_url"
    
    # Test statistics
    print("✓ Testing get_statistics...")
    stats = loader.get_statistics()
    assert isinstance(stats, dict), "Failed to get statistics"
    assert 'total_tools' in stats, "Statistics missing total_tools"
    
    print("\n✅ TASK 3 (Dynamic Arsenal) - ALL TESTS PASSED")
    return True

async def test_session_management():
    """Test session management"""
    print("\n" + "="*70)
    print("Testing TASK 1: Session Management")
    print("="*70)
    
    from tools.python_tools import PythonToolManager
    
    pm = PythonToolManager()
    
    # Test logout (should work even without session)
    print("✓ Testing logout without session...")
    result = await pm.manage_session('logout')
    assert result['status'] == 'success', "Logout failed"
    
    # Test invalid action
    print("✓ Testing invalid action...")
    result = await pm.manage_session('invalid_action')
    assert result['status'] == 'error', "Should return error for invalid action"
    
    # Test login with missing credentials
    print("✓ Testing login with missing credentials...")
    result = await pm.manage_session('login', {})
    assert result['status'] == 'error', "Should return error for missing credentials"
    
    # Test session data injection helper
    print("✓ Testing _inject_session_data helper...")
    headers = {'User-Agent': 'Test'}
    updated_headers, cookies = pm._inject_session_data(headers)
    assert isinstance(updated_headers, dict), "Headers should be dict"
    assert isinstance(cookies, dict), "Cookies should be dict"
    
    print("\n✅ TASK 1 (Session Management) - ALL TESTS PASSED")
    return True

def test_semi_autonomous():
    """Test semi-autonomous mode logic"""
    print("\n" + "="*70)
    print("Testing TASK 4: Semi-Autonomous Mode")
    print("="*70)
    
    from utils.dynamic_tool_loader import get_tool_loader
    
    loader = get_tool_loader()
    
    # Test that intrusive tools are correctly flagged
    print("✓ Testing intrusive tool detection...")
    intrusive_tools = ['test_form_payload', 'run_sqlmap', 'vulnerability_scan']
    for tool_name in intrusive_tools:
        is_intrusive = loader.is_tool_intrusive(tool_name)
        assert is_intrusive == True, f"{tool_name} should be intrusive"
    
    # Test that non-intrusive tools are correctly flagged
    print("✓ Testing non-intrusive tool detection...")
    non_intrusive_tools = ['subdomain_enumeration', 'fetch_url', 'db_get_findings']
    for tool_name in non_intrusive_tools:
        is_intrusive = loader.is_tool_intrusive(tool_name)
        assert is_intrusive == False, f"{tool_name} should NOT be intrusive"
    
    # Test getting intrusive and non-intrusive tool lists
    print("✓ Testing tool list filtering...")
    intrusive_list = loader.get_intrusive_tools()
    non_intrusive_list = loader.get_non_intrusive_tools()
    
    assert len(intrusive_list) > 0, "Should have intrusive tools"
    assert len(non_intrusive_list) > 0, "Should have non-intrusive tools"
    
    print(f"  Found {len(intrusive_list)} intrusive tools")
    print(f"  Found {len(non_intrusive_list)} non-intrusive tools")
    
    print("\n✅ TASK 4 (Semi-Autonomous Mode) - ALL TESTS PASSED")
    return True

def test_integration():
    """Test integration between components"""
    print("\n" + "="*70)
    print("Testing Integration")
    print("="*70)
    
    from utils.database_manager import get_database
    from utils.dynamic_tool_loader import get_tool_loader
    
    db = get_database()
    loader = get_tool_loader()
    
    # Test that database tools are in manifest
    print("✓ Testing database tools in manifest...")
    db_tools = ['db_add_finding', 'db_get_findings', 'db_is_scanned', 'db_mark_scanned', 'db_get_statistics']
    for tool_name in db_tools:
        tool_info = loader.get_tool_info(tool_name)
        assert tool_info is not None, f"Database tool {tool_name} not in manifest"
        assert tool_info['category'] == 'database', f"{tool_name} should be in database category"
    
    # Test that session management tool is in manifest
    print("✓ Testing session management tool in manifest...")
    tool_info = loader.get_tool_info('manage_session')
    assert tool_info is not None, "Session management tool not in manifest"
    assert tool_info['category'] == 'session_management', "manage_session should be in session_management category"
    
    print("\n✅ Integration Tests - ALL TESTS PASSED")
    return True

def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("V5 BATTLE-READY PLATFORM TEST SUITE")
    print("="*70)
    
    try:
        # Run synchronous tests
        test_database()
        test_dynamic_tools()
        test_semi_autonomous()
        test_integration()
        
        # Run asynchronous tests
        asyncio.run(test_session_management())
        
        print("\n" + "="*70)
        print("✅ ALL TESTS PASSED!")
        print("="*70)
        print("\nV5 Battle-Ready Platform is functioning correctly!")
        print("All 4 tasks (Session Management, Database, Dynamic Arsenal, Semi-Autonomous) are working.")
        
        return 0
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
