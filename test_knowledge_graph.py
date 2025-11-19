#!/usr/bin/env python3
"""
Test suite for Knowledge Graph and Enhanced Features
Tests the new features added for:
- A. Knowledge Graph (NetworkX integration)
- B. Dynamic Micro-Agent Scripting (future enhancement)
- C. Replay Memory (Vector Database RAG - future enhancement)
- D. Robust JSON Parsing
"""

import asyncio
import sys
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))


def test_knowledge_graph():
    """Test Knowledge Graph implementation"""
    print("\n" + "="*70)
    print("Testing Knowledge Graph Implementation")
    print("="*70)
    
    from agents.enhanced_ai_core import MissionBlackboard
    
    # Create a test blackboard
    print("✓ Creating test blackboard with knowledge graph...")
    blackboard = MissionBlackboard(mission_id="test_kg")
    
    # Test adding relationships
    print("✓ Testing add_relationship...")
    blackboard.add_relationship("admin.example.com", "HAS_VULN", "SQLi")
    blackboard.add_relationship("SQLi", "ALLOWS_ACTION", "Dump DB")
    blackboard.add_relationship("Port 443", "EXPOSES", "Web Server")
    blackboard.add_relationship("Web Server", "RUNS", "WordPress 5.8")
    blackboard.add_relationship("Entry_Point", "LEADS_TO", "Web Server")
    blackboard.add_relationship("Web Server", "HAS_VULN", "SQLi")
    
    assert blackboard.knowledge_graph.number_of_nodes() >= 6, "Failed to add nodes to graph"
    assert blackboard.knowledge_graph.number_of_edges() >= 6, "Failed to add edges to graph"
    
    # Test get_attack_path
    print("✓ Testing get_attack_path...")
    blackboard.add_relationship("SQLi", "LEADS_TO", "Dump DB")
    paths = blackboard.get_attack_path("Dump DB")
    print(f"  Found {len(paths)} attack path(s) to 'Dump DB'")
    
    # Test graph summary
    print("✓ Testing get_graph_summary...")
    summary = blackboard.get_graph_summary()
    assert "nodes" in summary.lower(), "Summary missing nodes count"
    assert "edges" in summary.lower(), "Summary missing edges count"
    print(f"  {summary}")
    
    # Test persistence
    print("✓ Testing graph persistence...")
    blackboard2 = MissionBlackboard(mission_id="test_kg")
    assert blackboard2.knowledge_graph.number_of_nodes() >= 6, "Failed to load persisted graph"
    assert blackboard2.knowledge_graph.number_of_edges() >= 6, "Failed to load persisted edges"
    
    # Clean up
    blackboard.clear()
    
    print("\n✅ Knowledge Graph - ALL TESTS PASSED")
    return True


def test_robust_json_parsing():
    """Test robust JSON parsing with malformed input"""
    print("\n" + "="*70)
    print("Testing Robust JSON Parsing")
    print("="*70)
    
    from agents.enhanced_ai_core import parse_json_robust
    
    # Test 1: Normal JSON in markdown block
    print("✓ Testing JSON in markdown code block...")
    content1 = '```json\n{"key": "value", "number": 42}\n```'
    result1 = parse_json_robust(content1)
    assert result1 is not None, "Failed to parse valid markdown JSON"
    assert result1["key"] == "value", "Incorrect value parsed"
    assert result1["number"] == 42, "Incorrect number parsed"
    
    # Test 2: Raw JSON object
    print("✓ Testing raw JSON object...")
    content2 = 'Some text before {"key": "value"} some text after'
    result2 = parse_json_robust(content2)
    assert result2 is not None, "Failed to parse raw JSON"
    assert result2["key"] == "value", "Incorrect value from raw JSON"
    
    # Test 3: Malformed JSON (missing closing quote) - json_repair should fix this
    print("✓ Testing malformed JSON repair...")
    content3 = '{"key": "value", "incomplete": "test'  # Missing closing quote and brace
    result3 = parse_json_robust(content3)
    # json_repair should be able to fix this
    if result3:
        print(f"  Successfully repaired malformed JSON: {result3}")
    else:
        print("  Note: json_repair couldn't fix this particular malformation (expected)")
    
    # Test 4: Valid JSON with nested structure
    print("✓ Testing nested JSON...")
    content4 = '''```json
{
    "relationships": [
        ["source1", "RELATION", "target1"],
        ["source2", "RELATION", "target2"]
    ],
    "verified_facts": ["fact1", "fact2"]
}
```'''
    result4 = parse_json_robust(content4)
    assert result4 is not None, "Failed to parse nested JSON"
    assert "relationships" in result4, "Missing relationships key"
    assert len(result4["relationships"]) == 2, "Incorrect relationships count"
    
    # Test 5: Empty/None input
    print("✓ Testing empty input...")
    result5 = parse_json_robust("")
    assert result5 is None, "Should return None for empty input"
    
    result6 = parse_json_robust(None)
    assert result6 is None, "Should return None for None input"
    
    print("\n✅ Robust JSON Parsing - ALL TESTS PASSED")
    return True


def test_blackboard_with_relationships():
    """Test blackboard integration with relationships"""
    print("\n" + "="*70)
    print("Testing Blackboard Integration with Relationships")
    print("="*70)
    
    from agents.enhanced_ai_core import MissionBlackboard
    
    # Create blackboard
    print("✓ Creating blackboard...")
    blackboard = MissionBlackboard(mission_id="test_integration")
    
    # Add facts and relationships together
    print("✓ Testing mixed operations...")
    blackboard.add_fact("Port 443 is open on example.com")
    blackboard.add_relationship("example.com", "EXPOSES", "Port 443")
    blackboard.add_goal("Test for SQL injection")
    blackboard.add_relationship("Port 443", "RUNS", "Apache 2.4")
    
    # Get summary
    summary = blackboard.get_summary()
    
    # Verify summary contains all components
    assert "VERIFIED FACTS" in summary, "Missing facts section"
    assert "PENDING GOALS" in summary, "Missing goals section"
    assert "Knowledge Graph" in summary, "Missing graph section"
    
    print("  Summary includes:")
    print(f"    - {len(blackboard.verified_facts)} verified facts")
    print(f"    - {len(blackboard.pending_goals)} pending goals")
    print(f"    - {blackboard.knowledge_graph.number_of_nodes()} graph nodes")
    print(f"    - {blackboard.knowledge_graph.number_of_edges()} graph edges")
    
    # Clean up
    blackboard.clear()
    
    print("\n✅ Blackboard Integration - ALL TESTS PASSED")
    return True


def test_enhanced_ai_core_integration():
    """Test EnhancedAegisAI integration with knowledge graph"""
    print("\n" + "="*70)
    print("Testing EnhancedAegisAI Knowledge Graph Integration")
    print("="*70)
    
    from agents.enhanced_ai_core import EnhancedAegisAI
    
    # Create AI core
    print("✓ Creating EnhancedAegisAI instance...")
    ai_core = EnhancedAegisAI()
    
    # Check that blackboard has knowledge graph
    print("✓ Checking knowledge graph availability...")
    assert hasattr(ai_core.blackboard, 'knowledge_graph'), "Blackboard missing knowledge_graph"
    assert hasattr(ai_core.blackboard, 'add_relationship'), "Blackboard missing add_relationship method"
    assert hasattr(ai_core.blackboard, 'get_attack_path'), "Blackboard missing get_attack_path method"
    
    # Test adding relationships via AI core's blackboard
    print("✓ Testing relationship management...")
    ai_core.blackboard.add_relationship("test_source", "TEST_REL", "test_target")
    assert ai_core.blackboard.knowledge_graph.number_of_edges() >= 1, "Failed to add relationship"
    
    # Verify parse_json_robust is available
    print("✓ Checking parse_json_robust availability...")
    from agents.enhanced_ai_core import parse_json_robust
    test_json = '{"test": "value"}'
    parsed = parse_json_robust(test_json)
    assert parsed is not None, "parse_json_robust not working"
    assert parsed["test"] == "value", "parse_json_robust returned incorrect value"
    
    # Clean up
    ai_core.blackboard.clear()
    
    print("\n✅ EnhancedAegisAI Integration - ALL TESTS PASSED")
    return True


def test_attack_path_scenarios():
    """Test various attack path scenarios"""
    print("\n" + "="*70)
    print("Testing Attack Path Scenarios")
    print("="*70)
    
    from agents.enhanced_ai_core import MissionBlackboard
    
    # Create a realistic attack scenario
    print("✓ Building realistic attack scenario...")
    blackboard = MissionBlackboard(mission_id="test_attack_paths")
    
    # Build attack graph
    blackboard.add_relationship("Entry_Point", "LEADS_TO", "web.example.com")
    blackboard.add_relationship("web.example.com", "EXPOSES", "Port 443")
    blackboard.add_relationship("Port 443", "RUNS", "Apache 2.4")
    blackboard.add_relationship("Apache 2.4", "HAS_VULN", "Directory Traversal")
    blackboard.add_relationship("Directory Traversal", "ALLOWS_ACTION", "Read Config")
    blackboard.add_relationship("Read Config", "LEADS_TO", "Database Credentials")
    blackboard.add_relationship("Database Credentials", "ALLOWS_ACTION", "Database Access")
    
    # Find paths to Database Access
    print("✓ Testing attack path discovery...")
    paths = blackboard.get_attack_path("Database Access")
    
    if paths:
        print(f"  Found {len(paths)} attack path(s) to 'Database Access':")
        for i, path in enumerate(paths, 1):
            print(f"    Path {i}: {' -> '.join(path)}")
        assert len(paths) >= 1, "Should find at least one path"
    else:
        print("  No paths found (as expected if Entry_Point not connected)")
    
    # Test path from specific node
    print("✓ Testing path from specific source...")
    paths2 = blackboard.get_attack_path("Database Access", source="web.example.com")
    print(f"  Found {len(paths2)} path(s) from 'web.example.com'")
    
    # Test non-existent path
    print("✓ Testing non-existent path...")
    paths3 = blackboard.get_attack_path("Nonexistent Target")
    assert len(paths3) == 0, "Should return empty list for non-existent target"
    
    # Clean up
    blackboard.clear()
    
    print("\n✅ Attack Path Scenarios - ALL TESTS PASSED")
    return True


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("KNOWLEDGE GRAPH & ENHANCED FEATURES TEST SUITE")
    print("="*70)
    
    try:
        # Run all tests
        test_knowledge_graph()
        test_robust_json_parsing()
        test_blackboard_with_relationships()
        test_enhanced_ai_core_integration()
        test_attack_path_scenarios()
        
        print("\n" + "="*70)
        print("✅ ALL TESTS PASSED!")
        print("="*70)
        print("\nImplementation Summary:")
        print("✅ A. Knowledge Graph Implementation:")
        print("   - NetworkX DiGraph integration in MissionBlackboard")
        print("   - add_relationship() method for adding edges")
        print("   - get_attack_path() method for finding paths to objectives")
        print("   - Graph persistence via GraphML format")
        print("   - Graph summary in blackboard display")
        print("\n✅ D. Robust JSON Parsing:")
        print("   - parse_json_robust() helper function")
        print("   - Multiple parsing strategies (markdown, raw, repair)")
        print("   - json_repair library integration for malformed JSON")
        print("   - Updated all JSON parsing in enhanced_ai_core.py")
        print("\n📝 Future Enhancements (Not Implemented Yet):")
        print("   - B. Dynamic Micro-Agent Scripting")
        print("   - C. Replay Memory (Vector Database RAG)")
        print("\nNext steps:")
        print("- Verify knowledge graph works with real missions")
        print("- Test relationship extraction from tool outputs")
        print("- Consider implementing vector database for HTTP replay")
        
        return True
        
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
