#!/usr/bin/env python3
"""
Test suite for HTTP Replay Memory (Vector Database RAG)
"""

import sys
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))


def test_http_interaction():
    """Test HTTPInteraction class"""
    print("\n" + "="*70)
    print("Testing HTTPInteraction Class")
    print("="*70)
    
    from utils.http_replay_memory import HTTPInteraction
    
    # Create interaction
    print("✓ Creating HTTP interaction...")
    request = {
        'method': 'POST',
        'url': 'https://example.com/api/login',
        'headers': {'Content-Type': 'application/json', 'User-Agent': 'Test'},
        'body': '{"username": "admin", "password": "test123"}'
    }
    
    response = {
        'status_code': 200,
        'headers': {'Set-Cookie': 'session=abc123; HttpOnly'},
        'body': '{"success": true, "token": "jwt_token_here"}'
    }
    
    metadata = {'tag': 'login', 'attempt': 1}
    
    interaction = HTTPInteraction(request, response, metadata)
    
    assert interaction.id is not None, "Missing interaction ID"
    assert interaction.request == request, "Request not stored correctly"
    assert interaction.response == response, "Response not stored correctly"
    
    # Test text conversion
    print("✓ Testing text conversion...")
    text = interaction.to_text()
    assert 'POST' in text, "Method not in text"
    assert 'example.com' in text, "URL not in text"
    assert 'session=abc123' in text, "Cookie not in text"
    print(f"  Generated text length: {len(text)} chars")
    
    # Test serialization
    print("✓ Testing serialization...")
    data = interaction.to_dict()
    interaction2 = HTTPInteraction.from_dict(data)
    assert interaction2.id == interaction.id, "ID mismatch after deserialization"
    assert interaction2.request == interaction.request, "Request mismatch"
    
    print("\n✅ HTTPInteraction - TESTS PASSED")
    return True


def test_replay_memory_basic():
    """Test basic replay memory operations"""
    print("\n" + "="*70)
    print("Testing HTTP Replay Memory - Basic Operations")
    print("="*70)
    
    from utils.http_replay_memory import get_replay_memory
    
    memory = get_replay_memory()
    memory.clear()  # Start fresh
    
    # Add some interactions
    print("✓ Adding HTTP interactions...")
    
    # Interaction 1: Login
    id1 = memory.add_interaction(
        request={
            'method': 'POST',
            'url': 'https://example.com/api/login',
            'headers': {'Content-Type': 'application/json'},
            'body': '{"username": "admin", "csrf_token": "abc123"}'
        },
        response={
            'status_code': 200,
            'headers': {'Set-Cookie': 'session=xyz789'},
            'body': '{"success": true}'
        },
        metadata={'tag': 'authentication'}
    )
    
    # Interaction 2: CSRF token fetch
    id2 = memory.add_interaction(
        request={
            'method': 'GET',
            'url': 'https://example.com/csrf-token',
            'headers': {}
        },
        response={
            'status_code': 200,
            'headers': {},
            'body': '{"csrf_token": "def456", "format": "hex"}'
        },
        metadata={'tag': 'csrf'}
    )
    
    # Interaction 3: API call with auth
    id3 = memory.add_interaction(
        request={
            'method': 'GET',
            'url': 'https://example.com/api/users',
            'headers': {'Authorization': 'Bearer token123'},
        },
        response={
            'status_code': 200,
            'headers': {},
            'body': '[{"id": 1, "name": "User1"}]'
        }
    )
    
    assert len(memory.interactions) == 3, "Wrong number of interactions"
    print(f"  Added {len(memory.interactions)} interactions")
    
    # Get statistics
    print("✓ Testing statistics...")
    stats = memory.get_statistics()
    print(f"  Total: {stats['total_interactions']}")
    print(f"  Methods: {stats['methods']}")
    print(f"  Status codes: {stats['status_codes']}")
    
    assert stats['total_interactions'] == 3, "Wrong interaction count"
    assert 'POST' in stats['methods'], "Missing POST method"
    assert 'GET' in stats['methods'], "Missing GET method"
    
    print("\n✅ Basic Operations - TESTS PASSED")
    return True


def test_similarity_search():
    """Test similarity search functionality"""
    print("\n" + "="*70)
    print("Testing Similarity Search")
    print("="*70)
    
    from utils.http_replay_memory import get_replay_memory
    
    memory = get_replay_memory()
    
    # Search for CSRF-related interactions
    print("✓ Searching for 'CSRF token'...")
    results = memory.search_similar("CSRF token format hex", top_k=3, min_similarity=0.05)
    
    print(f"  Found {len(results)} similar interaction(s)")
    for interaction, similarity in results:
        print(f"    - {interaction.request.get('method')} {interaction.request.get('url', '')[:40]} "
              f"(similarity: {similarity:.3f})")
    
    assert len(results) > 0, "Should find at least one CSRF-related interaction"
    
    # Search for authentication
    print("✓ Searching for 'authentication login'...")
    results = memory.search_similar("authentication login username password", top_k=3, min_similarity=0.05)
    
    print(f"  Found {len(results)} similar interaction(s)")
    for interaction, similarity in results:
        print(f"    - {interaction.request.get('method')} {interaction.request.get('url', '')[:40]} "
              f"(similarity: {similarity:.3f})")
    
    assert len(results) > 0, "Should find at least one login-related interaction"
    
    # Search for non-existent pattern
    print("✓ Searching for unrelated content...")
    results = memory.search_similar("database injection SQL", top_k=3, min_similarity=0.3)
    print(f"  Found {len(results)} similar interaction(s) (expected: 0 or low similarity)")
    
    print("\n✅ Similarity Search - TESTS PASSED")
    return True


def test_pattern_search():
    """Test pattern-based search"""
    print("\n" + "="*70)
    print("Testing Pattern-Based Search")
    print("="*70)
    
    from utils.http_replay_memory import get_replay_memory
    
    memory = get_replay_memory()
    
    # Search by URL pattern
    print("✓ Searching by URL pattern...")
    results = memory.search_by_pattern({
        'url_contains': 'api',
        'method': 'POST'
    }, top_k=5)
    
    print(f"  Found {len(results)} POST request(s) to API endpoints")
    for interaction, score in results:
        print(f"    - {interaction.request.get('url', '')[:50]} (score: {score:.2f})")
    
    # Search by status code
    print("✓ Searching by status code...")
    results = memory.search_by_pattern({
        'status_code': 200
    }, top_k=5)
    
    print(f"  Found {len(results)} interaction(s) with status 200")
    assert len(results) > 0, "Should find 200 responses"
    
    # Search by headers
    print("✓ Searching by response headers...")
    results = memory.search_by_pattern({
        'header_contains': {'Set-Cookie': 'session'}
    }, top_k=5)
    
    print(f"  Found {len(results)} interaction(s) with session cookie")
    
    print("\n✅ Pattern Search - TESTS PASSED")
    return True


def test_realistic_use_case():
    """Test a realistic use case"""
    print("\n" + "="*70)
    print("Testing Realistic Use Case: CSRF Token Analysis")
    print("="*70)
    
    from utils.http_replay_memory import get_replay_memory
    
    memory = get_replay_memory()
    
    # Scenario: Agent encounters a CSRF token and wants to know if we've seen this format before
    print("✓ Scenario: Analyzing CSRF token format...")
    
    # Add more CSRF-related interactions
    memory.add_interaction(
        request={
            'method': 'POST',
            'url': 'https://app.example.com/submit',
            'headers': {'X-CSRF-Token': '1234567890abcdef'},
            'body': 'data=value'
        },
        response={
            'status_code': 200,
            'headers': {},
            'body': 'Success'
        },
        metadata={'note': 'CSRF token in header, hex format, 16 chars'}
    )
    
    memory.add_interaction(
        request={
            'method': 'POST',
            'url': 'https://app.example.com/delete',
            'headers': {},
            'body': 'csrf_token=abcd1234&id=5'
        },
        response={
            'status_code': 403,
            'headers': {},
            'body': 'Invalid CSRF token'
        },
        metadata={'note': 'CSRF token in POST body, failed'}
    )
    
    # Query: Have we seen this CSRF token format before?
    query = "CSRF token header X-CSRF-Token hexadecimal format"
    
    print(f"\n  Query: '{query}'")
    results = memory.search_similar(query, top_k=3, min_similarity=0.1)
    
    print(f"\n  Analysis Results ({len(results)} similar interactions found):")
    for i, (interaction, similarity) in enumerate(results, 1):
        print(f"\n  [{i}] Similarity: {similarity:.3f}")
        print(f"      Request: {interaction.request.get('method')} {interaction.request.get('url')}")
        print(f"      Headers: {list(interaction.request.get('headers', {}).keys())}")
        
        if 'note' in interaction.metadata:
            print(f"      Note: {interaction.metadata['note']}")
    
    print("\n  Conclusion: Agent can learn that:")
    print("  - CSRF tokens appear in both headers and POST bodies")
    print("  - Header format: X-CSRF-Token with hex values")
    print("  - Should try both locations when testing")
    
    assert len(results) > 0, "Should find CSRF-related interactions"
    
    print("\n✅ Realistic Use Case - TEST PASSED")
    return True


def test_persistence():
    """Test persistence and reload"""
    print("\n" + "="*70)
    print("Testing Persistence and Reload")
    print("="*70)
    
    from utils.http_replay_memory import HTTPReplayMemory
    
    # Create first instance
    print("✓ Creating first memory instance...")
    memory1 = HTTPReplayMemory()
    initial_count = len(memory1.interactions)
    print(f"  Loaded {initial_count} existing interaction(s)")
    
    # Add new interaction
    memory1.add_interaction(
        request={'method': 'GET', 'url': 'https://test.com/persist'},
        response={'status_code': 200, 'body': 'test'}
    )
    
    new_count = len(memory1.interactions)
    assert new_count == initial_count + 1, "Interaction not added"
    
    # Create second instance (should load from disk)
    print("✓ Creating second memory instance (reload from disk)...")
    memory2 = HTTPReplayMemory()
    
    assert len(memory2.interactions) == new_count, "Persistence failed"
    print(f"  Successfully reloaded {len(memory2.interactions)} interaction(s)")
    
    print("\n✅ Persistence - TESTS PASSED")
    return True


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("HTTP REPLAY MEMORY (VECTOR DATABASE RAG) TEST SUITE")
    print("="*70)
    
    try:
        # Run all tests
        test_http_interaction()
        test_replay_memory_basic()
        test_similarity_search()
        test_pattern_search()
        test_realistic_use_case()
        test_persistence()
        
        print("\n" + "="*70)
        print("✅ ALL TESTS PASSED!")
        print("="*70)
        print("\nImplementation Summary:")
        print("✅ C. Replay Memory (Vector Database RAG):")
        print("   - HTTPInteraction class for request/response storage")
        print("   - HTTPReplayMemory with TF-IDF vectorization")
        print("   - Similarity search using cosine similarity")
        print("   - Pattern-based search for specific attributes")
        print("   - Persistence using pickle serialization")
        print("   - Automatic vector rebuild and caching")
        print("\n📝 Use Cases:")
        print("   - 'Have we seen this CSRF token format before?'")
        print("   - 'What authentication methods has this API used?'")
        print("   - 'Find similar error responses'")
        print("   - 'Locate past successful payloads'")
        print("\n💡 Benefits:")
        print("   - Bypasses short-term context window limits")
        print("   - Learns from past interactions (avoid repeating mistakes)")
        print("   - Semantic search over 1000+ interactions")
        print("   - No external dependencies (uses scikit-learn TF-IDF)")
        print("\nNext steps:")
        print("- Integrate with scanner to auto-store HTTP requests")
        print("- Add CLI commands for querying replay memory")
        print("- Consider adding filters by timestamp/target")
        
        return True
        
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
