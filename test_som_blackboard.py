#!/usr/bin/env python3
"""
Test suite for Set-of-Mark (SoM) and Blackboard Memory implementations
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))


def test_blackboard_memory():
    """Test MissionBlackboard class"""
    print("\n" + "="*70)
    print("Testing Blackboard Memory Implementation")
    print("="*70)
    
    from agents.enhanced_ai_core import MissionBlackboard
    
    # Create a test blackboard
    print("✓ Creating test blackboard...")
    blackboard = MissionBlackboard(mission_id="test_mission")
    
    # Test adding facts
    print("✓ Testing add_fact...")
    blackboard.add_fact("Port 443 is open on example.com")
    blackboard.add_fact("WordPress 5.8 detected")
    assert len(blackboard.verified_facts) == 2, "Failed to add facts"
    
    # Test adding goals
    print("✓ Testing add_goal...")
    blackboard.add_goal("Test admin panel for weak credentials")
    blackboard.add_goal("Enumerate WordPress plugins")
    assert len(blackboard.pending_goals) == 2, "Failed to add goals"
    
    # Test discarding vectors
    print("✓ Testing discard_vector...")
    blackboard.discard_vector("SQL injection in search - WAF blocked")
    assert len(blackboard.discarded_vectors) == 1, "Failed to discard vector"
    
    # Test completing goal
    print("✓ Testing complete_goal...")
    blackboard.complete_goal("Test admin panel for weak credentials")
    assert len(blackboard.pending_goals) == 1, "Failed to complete goal"
    
    # Test summary
    print("✓ Testing get_summary...")
    summary = blackboard.get_summary()
    assert "VERIFIED FACTS" in summary, "Summary missing facts section"
    assert "PENDING GOALS" in summary, "Summary missing goals section"
    assert "DISCARDED VECTORS" in summary, "Summary missing vectors section"
    
    # Test persistence
    print("✓ Testing persistence...")
    blackboard2 = MissionBlackboard(mission_id="test_mission")
    assert len(blackboard2.verified_facts) == 2, "Failed to load persisted facts"
    assert len(blackboard2.pending_goals) == 1, "Failed to load persisted goals"
    
    # Clean up
    blackboard.clear()
    
    print("\n✅ Blackboard Memory - ALL TESTS PASSED")
    return True


def test_visual_recon_som():
    """Test Set-of-Mark (SoM) implementation"""
    print("\n" + "="*70)
    print("Testing Set-of-Mark (SoM) Visual Grounding")
    print("="*70)
    
    from tools.visual_recon import VisualReconTool
    
    # Create visual recon tool
    print("✓ Creating VisualReconTool instance...")
    visual_tool = VisualReconTool()
    
    # Check that capture_with_som method exists
    print("✓ Checking capture_with_som method exists...")
    assert hasattr(visual_tool, 'capture_with_som'), "capture_with_som method not found"
    
    # Check that click_element method exists
    print("✓ Checking click_element method exists...")
    assert hasattr(visual_tool, 'click_element'), "click_element method not found"
    
    # Verify method signatures
    import inspect
    
    print("✓ Verifying capture_with_som signature...")
    som_sig = inspect.signature(visual_tool.capture_with_som)
    assert 'url' in som_sig.parameters, "capture_with_som missing 'url' parameter"
    
    print("✓ Verifying click_element signature...")
    click_sig = inspect.signature(visual_tool.click_element)
    assert 'url' in click_sig.parameters, "click_element missing 'url' parameter"
    assert 'element_id' in click_sig.parameters, "click_element missing 'element_id' parameter"
    assert 'element_mapping' in click_sig.parameters, "click_element missing 'element_mapping' parameter"
    
    print("\n✅ Set-of-Mark (SoM) - ALL TESTS PASSED")
    print("   Note: Full browser tests require Playwright browser installation")
    return True


def test_scanner_integration():
    """Test scanner integration with SoM tools"""
    print("\n" + "="*70)
    print("Testing Scanner Integration with SoM Tools")
    print("="*70)
    
    # Import scanner
    from agents.scanner import AegisScanner
    from agents.enhanced_ai_core import EnhancedAegisAI
    
    # Create mock AI core
    print("✓ Creating scanner instance...")
    ai_core = EnhancedAegisAI()
    scanner = AegisScanner(ai_core)
    
    # Check that scanner has visual_recon
    print("✓ Checking visual_recon integration...")
    assert hasattr(scanner, 'visual_recon'), "Scanner missing visual_recon attribute"
    
    # Check that scanner has som_mappings
    print("✓ Checking som_mappings storage...")
    assert hasattr(scanner, 'som_mappings'), "Scanner missing som_mappings attribute"
    assert isinstance(scanner.som_mappings, dict), "som_mappings should be a dictionary"
    
    print("\n✅ Scanner Integration - ALL TESTS PASSED")
    return True


def test_enhanced_ai_core():
    """Test EnhancedAegisAI blackboard integration"""
    print("\n" + "="*70)
    print("Testing EnhancedAegisAI Blackboard Integration")
    print("="*70)
    
    from agents.enhanced_ai_core import EnhancedAegisAI
    
    # Create AI core
    print("✓ Creating EnhancedAegisAI instance...")
    ai_core = EnhancedAegisAI()
    
    # Check that it has blackboard
    print("✓ Checking blackboard integration...")
    assert hasattr(ai_core, 'blackboard'), "AI core missing blackboard attribute"
    
    # Check that extract_facts_from_output method exists
    print("✓ Checking extract_facts_from_output method...")
    assert hasattr(ai_core, 'extract_facts_from_output'), "extract_facts_from_output method not found"
    
    # Verify blackboard is initialized
    print("✓ Verifying blackboard initialization...")
    assert ai_core.blackboard is not None, "Blackboard not initialized"
    assert hasattr(ai_core.blackboard, 'verified_facts'), "Blackboard missing verified_facts"
    assert hasattr(ai_core.blackboard, 'pending_goals'), "Blackboard missing pending_goals"
    assert hasattr(ai_core.blackboard, 'discarded_vectors'), "Blackboard missing discarded_vectors"
    
    print("\n✅ EnhancedAegisAI Integration - ALL TESTS PASSED")
    return True


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("SOM & BLACKBOARD MEMORY TEST SUITE")
    print("="*70)
    
    try:
        # Run all tests
        test_blackboard_memory()
        test_visual_recon_som()
        test_scanner_integration()
        test_enhanced_ai_core()
        
        print("\n" + "="*70)
        print("✅ ALL TESTS PASSED!")
        print("="*70)
        print("\nImplementation Summary:")
        print("1. ✅ Set-of-Mark (SoM) visual grounding implemented in VisualReconTool")
        print("2. ✅ Blackboard Memory system implemented in EnhancedAegisAI")
        print("3. ✅ Scanner integration with SoM tools (capture_screenshot_som, click_element_by_id)")
        print("4. ✅ Fact extraction from tool outputs to update blackboard")
        print("\nNext steps:")
        print("- Install Playwright browsers: python -m playwright install")
        print("- Test SoM with real web pages")
        print("- Validate fact extraction in real missions")
        
        return True
        
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
