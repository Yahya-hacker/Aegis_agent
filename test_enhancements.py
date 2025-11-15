#!/usr/bin/env python3
"""
Comprehensive validation tests for Aegis Agent enhancements
Tests all major improvements made to the system
"""

import sys
import asyncio
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))


def test_imports():
    """Test that all modules import correctly"""
    print("🧪 Testing imports...")
    try:
        from agents.enhanced_ai_core import EnhancedAegisAI
        from agents.conversational_agent import AegisConversation
        from agents.learning_engine import AegisLearningEngine
        from agents.multi_llm_orchestrator import MultiLLMOrchestrator
        from agents.scanner import AegisScanner
        from utils.vulnerability_analyzer import get_vulnerability_analyzer
        from utils.database_manager import get_database
        from utils.dynamic_tool_loader import get_tool_loader
        from utils.helpers import AegisHelpers
        print("   ✅ All imports successful")
        return True
    except Exception as e:
        print(f"   ❌ Import failed: {e}")
        return False


def test_vulnerability_analyzer():
    """Test vulnerability analyzer functionality"""
    print("\n🧪 Testing vulnerability analyzer...")
    try:
        from utils.vulnerability_analyzer import get_vulnerability_analyzer
        
        analyzer = get_vulnerability_analyzer()
        
        # Test finding analysis
        finding = {
            'type': 'sql_injection',
            'url': 'https://test.com/search',
            'description': 'SQL injection in search parameter',
            'evidence': "' OR '1'='1"
        }
        
        analyzed = analyzer.analyze_finding(finding)
        
        assert 'analysis' in analyzed
        assert 'risk_score' in analyzed['analysis']
        assert 'severity' in analyzed['analysis']
        assert 'priority' in analyzed['analysis']
        assert analyzed['analysis']['severity'] == 'critical'
        assert analyzed['analysis']['risk_score'] > 0
        
        print(f"   ✅ Risk Score: {analyzed['analysis']['risk_score']}/10")
        print(f"   ✅ Priority: {analyzed['analysis']['priority']}")
        print(f"   ✅ CVSS: {analyzed['analysis']['cvss_vector']}")
        
        # Test prioritization
        findings = [
            {'type': 'sql_injection', 'url': 'https://test.com/1', 'description': 'SQLi'},
            {'type': 'xss', 'url': 'https://test.com/2', 'description': 'XSS'},
            {'type': 'csrf', 'url': 'https://test.com/3', 'description': 'CSRF'}
        ]
        
        prioritized = analyzer.prioritize_findings(findings)
        assert len(prioritized) == 3
        # SQL injection should be highest priority
        assert prioritized[0]['type'] == 'sql_injection'
        
        print("   ✅ Prioritization working")
        
        # Test statistics
        stats = analyzer.get_statistics(findings)
        assert stats['total'] == 3
        assert 'by_severity' in stats
        
        print(f"   ✅ Statistics: {stats['total']} findings")
        
        return True
    except Exception as e:
        print(f"   ❌ Vulnerability analyzer test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_learning_engine():
    """Test learning engine functionality"""
    print("\n🧪 Testing learning engine...")
    try:
        from agents.learning_engine import AegisLearningEngine
        
        engine = AegisLearningEngine()
        
        # Test recording success
        engine.record_successful_action('test_tool', 'test.com', 'Success')
        print("   ✅ Recorded successful action")
        
        # Test recording failure
        engine.record_failed_attempt('test_tool', 'test.com', 'Test error')
        print("   ✅ Recorded failed attempt")
        
        # Test avoidance check
        should_avoid, reason = engine.should_avoid_action('test_tool', 'test.com')
        assert isinstance(should_avoid, bool)
        print(f"   ✅ Avoidance check: {should_avoid}")
        
        # Test pattern loading
        patterns = engine.load_learned_patterns()
        assert isinstance(patterns, str)
        print("   ✅ Patterns loaded")
        
        return True
    except Exception as e:
        print(f"   ❌ Learning engine test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_database_manager():
    """Test database manager with context manager"""
    print("\n🧪 Testing database manager...")
    try:
        from utils.database_manager import MissionDatabase
        import tempfile
        import os
        
        # Use temporary database
        temp_db = tempfile.mktemp(suffix='.db')
        
        # Test context manager
        with MissionDatabase(temp_db) as db:
            # Test adding finding
            finding_id = db.add_finding(
                'test_vuln',
                'https://test.com',
                'high',
                'Test description',
                'Test evidence'
            )
            assert finding_id > 0
            print(f"   ✅ Added finding ID: {finding_id}")
            
            # Test retrieving findings
            findings = db.get_findings(severity='high')
            assert len(findings) > 0
            print(f"   ✅ Retrieved {len(findings)} findings")
            
            # Test marking scanned
            success = db.mark_scanned('test.com', 'test_scan', 'Result')
            assert success
            print("   ✅ Marked target as scanned")
            
            # Test statistics
            stats = db.get_statistics()
            assert 'total_findings' in stats
            print(f"   ✅ Statistics: {stats}")
        
        # Cleanup
        if os.path.exists(temp_db):
            os.remove(temp_db)
        
        print("   ✅ Context manager cleanup successful")
        return True
    except Exception as e:
        print(f"   ❌ Database manager test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_input_validation():
    """Test input validation in scanner"""
    print("\n🧪 Testing input validation...")
    try:
        from agents.scanner import AegisScanner
        
        class MockAICore:
            pass
        
        scanner = AegisScanner(MockAICore())
        
        # Test domain validation
        assert scanner._validate_domain('example.com')
        assert scanner._validate_domain('sub.example.com')
        assert not scanner._validate_domain('invalid domain')
        assert not scanner._validate_domain('')
        print("   ✅ Domain validation working")
        
        # Test URL validation
        assert scanner._validate_url('https://example.com')
        assert scanner._validate_url('http://example.com/path')
        assert not scanner._validate_url('not-a-url')
        assert not scanner._validate_url('')
        print("   ✅ URL validation working")
        
        # Test target validation
        assert scanner._validate_target('example.com')
        assert scanner._validate_target('192.168.1.1')
        assert scanner._validate_target('https://example.com')
        assert not scanner._validate_target('999.999.999.999')
        print("   ✅ Target validation working")
        
        return True
    except Exception as e:
        print(f"   ❌ Input validation test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_helpers():
    """Test helper utilities"""
    print("\n🧪 Testing helper utilities...")
    try:
        from utils.helpers import AegisHelpers
        
        # Test URL sanitization
        url = AegisHelpers.sanitize_target_url('example.com')
        assert url.startswith('https://')
        print(f"   ✅ URL sanitization: {url}")
        
        # Test domain extraction
        domain = AegisHelpers.extract_domain('https://example.com/path')
        assert domain == 'example.com'
        print(f"   ✅ Domain extraction: {domain}")
        
        # Test same domain check
        assert AegisHelpers.is_same_domain('https://example.com/a', 'https://example.com/b')
        assert not AegisHelpers.is_same_domain('https://example.com', 'https://other.com')
        print("   ✅ Same domain check working")
        
        # Test stealth headers
        headers = AegisHelpers.get_stealth_headers()
        assert 'User-Agent' in headers
        assert 'Accept' in headers
        print("   ✅ Stealth headers generated")
        
        # Test random user agent
        ua = AegisHelpers.get_random_user_agent()
        assert len(ua) > 0
        print(f"   ✅ Random UA: {ua[:50]}...")
        
        return True
    except Exception as e:
        print(f"   ❌ Helper utilities test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_memory_management():
    """Test memory management in enhanced AI core"""
    print("\n🧪 Testing memory management...")
    try:
        from agents.enhanced_ai_core import EnhancedAegisAI
        
        ai_core = EnhancedAegisAI()
        
        # Create large history
        history = [{'role': 'user', 'content': f'Message {i}'} for i in range(20)]
        
        # Test pruning
        pruned = ai_core._prune_memory(history)
        
        # Should have summary + recent messages
        assert len(pruned) <= ai_core.max_history_size + 1
        print(f"   ✅ Pruned {len(history)} messages to {len(pruned)}")
        
        # First entry should be summary
        assert pruned[0]['role'] == 'system'
        assert 'Context' in pruned[0]['content'] or 'Previous' in pruned[0]['content']
        print("   ✅ Summary entry created")
        
        return True
    except Exception as e:
        print(f"   ❌ Memory management test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_rate_limiting():
    """Test rate limiting in tool manager"""
    print("\n🧪 Testing rate limiting...")
    try:
        from tools.tool_manager import RealToolManager
        import time
        
        manager = RealToolManager()
        
        # Record initial time
        start = time.time()
        
        # Simulate two consecutive requests (would be rate limited)
        # We'll just test the timing mechanism
        tool_name = 'test_tool'
        manager.last_request_time[tool_name] = start
        
        current = start + 0.5  # 0.5 seconds later
        time_since_last = current - manager.last_request_time[tool_name]
        
        if time_since_last < manager.min_delay_between_requests:
            wait_time = manager.min_delay_between_requests - time_since_last
            assert wait_time > 0
            print(f"   ✅ Rate limiting would enforce {wait_time:.1f}s delay")
        
        # Test concurrent limit
        assert manager.max_concurrent_requests == 3
        print(f"   ✅ Max concurrent requests: {manager.max_concurrent_requests}")
        
        return True
    except Exception as e:
        print(f"   ❌ Rate limiting test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_all_tests():
    """Run all validation tests"""
    print("=" * 70)
    print("🚀 AEGIS AGENT COMPREHENSIVE VALIDATION TESTS")
    print("=" * 70)
    
    tests = [
        ("Imports", test_imports),
        ("Vulnerability Analyzer", test_vulnerability_analyzer),
        ("Learning Engine", test_learning_engine),
        ("Database Manager", test_database_manager),
        ("Input Validation", test_input_validation),
        ("Helper Utilities", test_helpers),
        ("Memory Management", test_memory_management),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"❌ Test {name} crashed: {e}")
            results.append((name, False))
    
    # Run async tests
    print("\n🧪 Testing rate limiting (async)...")
    try:
        result = asyncio.run(test_rate_limiting())
        results.append(("Rate Limiting", result))
    except Exception as e:
        print(f"❌ Rate limiting test crashed: {e}")
        results.append(("Rate Limiting", False))
    
    # Print summary
    print("\n" + "=" * 70)
    print("📊 TEST SUMMARY")
    print("=" * 70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {name}")
    
    print(f"\n🎯 Overall: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("\n🎉 All tests passed! System is ready.")
        return 0
    else:
        print(f"\n⚠️  {total - passed} tests failed. Please review.")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
