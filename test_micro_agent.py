#!/usr/bin/env python3
"""
Test suite for Micro-Agent Script Manager
"""

import sys
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))


def test_script_generation():
    """Test script generation"""
    print("\n" + "="*70)
    print("Testing Micro-Agent Script Generation")
    print("="*70)
    
    from utils.micro_agent_script_manager import get_script_manager
    
    manager = get_script_manager()
    
    # Test basic script generation
    print("✓ Testing basic script generation...")
    script_code = """
import sys

def main():
    print("Hello from micro-agent!")
    print("Arguments:", sys.argv[1:])
    return 0

if __name__ == "__main__":
    sys.exit(main())
"""
    
    script_path = manager.generate_script(
        script_name="test_hello",
        script_code=script_code,
        description="Simple test script"
    )
    
    assert script_path.exists(), "Script file not created"
    assert script_path.suffix == ".py", "Wrong file extension"
    
    print(f"  Generated: {script_path.name}")
    
    # Test script with dangerous operations (should fail in safe mode)
    print("✓ Testing safety validation...")
    dangerous_code = """
import os
os.system("echo 'dangerous'")
"""
    
    try:
        manager.generate_script(
            script_name="test_dangerous",
            script_code=dangerous_code,
            description="Dangerous script",
            safe_mode=True
        )
        assert False, "Should have rejected dangerous script"
    except ValueError as e:
        print(f"  Correctly rejected dangerous script: {str(e)[:50]}...")
    
    print("\n✅ Script Generation - TESTS PASSED")
    return True


def test_script_execution():
    """Test script execution"""
    print("\n" + "="*70)
    print("Testing Micro-Agent Script Execution")
    print("="*70)
    
    from utils.micro_agent_script_manager import get_script_manager
    
    manager = get_script_manager()
    
    # Create a simple test script
    print("✓ Creating test script...")
    script_code = """
import sys
import json

def generate_token(user_id, secret):
    # Simple token generation (for testing)
    import hashlib
    token = hashlib.sha256(f"{user_id}:{secret}".encode()).hexdigest()
    return token

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: script.py <user_id> <secret>", file=sys.stderr)
        sys.exit(1)
    
    user_id = sys.argv[1]
    secret = sys.argv[2]
    
    token = generate_token(user_id, secret)
    
    # Output as JSON
    result = {
        "user_id": user_id,
        "token": token,
        "timestamp": "2024-01-01T00:00:00Z"
    }
    print(json.dumps(result))
"""
    
    script_path = manager.generate_script(
        script_name="test_token_generator",
        script_code=script_code,
        description="Test token generator",
        safe_mode=False  # hashlib import might be flagged
    )
    
    # Execute the script
    print("✓ Executing script with arguments...")
    result = manager.execute_script(
        script_path,
        args=["user123", "secret456"],
        timeout=10
    )
    
    assert result['success'], f"Script execution failed: {result.get('stderr', '')}"
    assert result['return_code'] == 0, "Non-zero return code"
    assert len(result['stdout']) > 0, "No output captured"
    
    print(f"  Execution time: {result['execution_time']:.3f}s")
    print(f"  Output: {result['stdout'][:100]}...")
    
    # Test script timeout
    print("✓ Testing execution timeout...")
    timeout_code = """
import time
time.sleep(10)
print("Should not reach here")
"""
    
    timeout_script = manager.generate_script(
        script_name="test_timeout",
        script_code=timeout_code,
        description="Timeout test"
    )
    
    timeout_result = manager.execute_script(
        timeout_script,
        timeout=2
    )
    
    assert not timeout_result['success'], "Timeout should have failed"
    assert 'Timeout' in timeout_result.get('error', ''), "Should indicate timeout"
    
    print("  Correctly handled timeout")
    
    print("\n✅ Script Execution - TESTS PASSED")
    return True


def test_script_management():
    """Test script management features"""
    print("\n" + "="*70)
    print("Testing Script Management")
    print("="*70)
    
    from utils.micro_agent_script_manager import get_script_manager
    
    manager = get_script_manager()
    
    # List scripts
    print("✓ Testing script listing...")
    scripts = manager.list_scripts()
    print(f"  Found {len(scripts)} script(s)")
    
    for script in scripts[:3]:  # Show first 3
        print(f"    - {script['name']} ({script['size']} bytes)")
    
    # Get execution history
    print("✓ Testing execution history...")
    history = manager.get_execution_history(limit=5)
    print(f"  Found {len(history)} execution(s)")
    
    for entry in history[:2]:  # Show first 2
        print(f"    - {Path(entry['script']).name}: "
              f"{'✓' if entry['success'] else '✗'} "
              f"({entry['execution_time']:.2f}s)")
    
    # Test cleanup (don't actually delete, just test the logic)
    print("✓ Testing cleanup logic...")
    # We won't actually delete files created in this test session
    # Just verify the method exists and can be called
    deleted = manager.cleanup_old_scripts(max_age_hours=1000)  # Very old
    print(f"  Would cleanup {deleted} old script(s)")
    
    print("\n✅ Script Management - TESTS PASSED")
    return True


def test_realistic_use_case():
    """Test a realistic use case - custom auth token generation"""
    print("\n" + "="*70)
    print("Testing Realistic Use Case: Custom Auth Token")
    print("="*70)
    
    from utils.micro_agent_script_manager import get_script_manager
    import json
    
    manager = get_script_manager()
    
    # Scenario: Target uses custom HMAC-based auth tokens
    # Agent needs to generate valid tokens for each request
    print("✓ Generating custom auth token script...")
    
    auth_script = """
import sys
import json
import hashlib
import hmac
import time

def generate_custom_token(api_key, api_secret, timestamp=None):
    '''
    Generate custom HMAC-SHA256 token
    Format: HMAC(api_key + timestamp, api_secret)
    '''
    if timestamp is None:
        timestamp = str(int(time.time()))
    
    message = f"{api_key}:{timestamp}"
    signature = hmac.new(
        api_secret.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return {
        "api_key": api_key,
        "timestamp": timestamp,
        "signature": signature,
        "auth_header": f"CustomAuth {api_key}:{timestamp}:{signature}"
    }

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(json.dumps({"error": "Usage: script.py <api_key> <api_secret>"}))
        sys.exit(1)
    
    api_key = sys.argv[1]
    api_secret = sys.argv[2]
    
    result = generate_custom_token(api_key, api_secret)
    print(json.dumps(result, indent=2))
"""
    
    script_path = manager.generate_script(
        script_name="custom_auth_token",
        script_code=auth_script,
        description="Generate custom HMAC-SHA256 auth tokens for target API",
        safe_mode=False  # hmac/hashlib are needed
    )
    
    print("✓ Executing token generator...")
    result = manager.execute_script(
        script_path,
        args=["test_key_123", "super_secret_456"]
    )
    
    assert result['success'], "Token generation failed"
    
    # Parse JSON output
    token_data = json.loads(result['stdout'])
    
    print("  Generated token data:")
    print(f"    API Key: {token_data['api_key']}")
    print(f"    Timestamp: {token_data['timestamp']}")
    print(f"    Signature: {token_data['signature'][:32]}...")
    print(f"    Auth Header: {token_data['auth_header'][:50]}...")
    
    assert 'signature' in token_data, "Missing signature"
    assert 'auth_header' in token_data, "Missing auth header"
    
    print("\n✅ Realistic Use Case - TEST PASSED")
    print("   This demonstrates how the agent can generate custom auth tokens")
    print("   when encountering non-standard authentication schemes.")
    
    return True


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("MICRO-AGENT SCRIPT MANAGER TEST SUITE")
    print("="*70)
    
    try:
        # Run all tests
        test_script_generation()
        test_script_execution()
        test_script_management()
        test_realistic_use_case()
        
        print("\n" + "="*70)
        print("✅ ALL TESTS PASSED!")
        print("="*70)
        print("\nImplementation Summary:")
        print("✅ B. Dynamic Micro-Agent Scripting:")
        print("   - MicroAgentScriptManager class for script lifecycle")
        print("   - generate_script() with safety validation")
        print("   - execute_script() with timeout and output capture")
        print("   - Script persistence in temp_scripts/ directory")
        print("   - Execution logging and history tracking")
        print("   - Cleanup for old scripts")
        print("\n📝 Use Cases:")
        print("   - Custom authentication token generation (HMAC, JWT, etc.)")
        print("   - Complex payload encoding/decoding")
        print("   - API-specific request signing")
        print("   - Custom cryptographic operations")
        print("\nNext steps:")
        print("- Integrate with EnhancedAegisAI for automatic script generation")
        print("- Add more sophisticated sandboxing if needed")
        print("- Consider adding script templates for common patterns")
        
        return True
        
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
