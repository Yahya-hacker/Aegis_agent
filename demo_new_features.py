#!/usr/bin/env python3
"""
Demo script for Visual Grounding (SoM) and Blackboard Memory features
This demonstrates the new capabilities without requiring a full mission setup.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


async def demo_blackboard():
    """Demonstrate Blackboard Memory System"""
    print("\n" + "="*70)
    print("DEMO: Blackboard Memory System")
    print("="*70)
    
    from agents.enhanced_ai_core import MissionBlackboard
    
    # Create a demo blackboard
    print("\n1. Creating a mission blackboard...")
    blackboard = MissionBlackboard(mission_id="demo_mission")
    
    # Simulate discovering facts during a mission
    print("\n2. Adding verified facts as they're discovered...")
    blackboard.add_fact("Port 443 is open on example.com")
    blackboard.add_fact("WordPress 5.8 detected on example.com")
    blackboard.add_fact("Admin panel found at /wp-admin")
    blackboard.add_fact("No rate limiting on login form")
    
    # Simulate setting goals
    print("\n3. Adding pending goals for the mission...")
    blackboard.add_goal("Test admin panel for weak credentials")
    blackboard.add_goal("Enumerate WordPress plugins")
    blackboard.add_goal("Check for SQL injection in search")
    
    # Simulate trying and discarding failed attack vectors
    print("\n4. Discarding failed attack vectors...")
    blackboard.discard_vector("SQL injection in search - WAF blocked")
    blackboard.discard_vector("Directory traversal - input sanitized")
    
    # Show current mission state
    print("\n5. Current mission blackboard state:")
    print(blackboard.get_summary())
    
    # Complete a goal
    print("\n6. Completing a goal...")
    blackboard.complete_goal("Test admin panel for weak credentials")
    
    # Show updated state
    print("\n7. Updated blackboard after completing goal:")
    print(blackboard.get_summary())
    
    # Demonstrate persistence
    print("\n8. Testing persistence...")
    print("   Creating a new blackboard instance with same mission_id...")
    blackboard2 = MissionBlackboard(mission_id="demo_mission")
    print("   Data automatically loaded from disk!")
    print(f"   Facts: {len(blackboard2.verified_facts)}")
    print(f"   Goals: {len(blackboard2.pending_goals)}")
    print(f"   Discarded: {len(blackboard2.discarded_vectors)}")
    
    # Clean up
    print("\n9. Cleaning up demo data...")
    blackboard.clear()
    print("   ✓ Blackboard cleared")
    
    print("\n" + "="*70)
    print("✅ Blackboard Memory Demo Complete!")
    print("="*70)


async def demo_visual_grounding():
    """Demonstrate Visual Grounding (Set-of-Mark) concepts"""
    print("\n" + "="*70)
    print("DEMO: Visual Grounding with Set-of-Mark (SoM)")
    print("="*70)
    
    from tools.visual_recon import VisualReconTool
    
    print("\n1. Visual Grounding enables the AI to:")
    print("   • 'See' web interfaces by analyzing screenshots")
    print("   • Identify clickable elements (links, buttons, inputs)")
    print("   • Interact with elements by their visual position")
    
    print("\n2. Set-of-Mark (SoM) Process:")
    print("   Step 1: Capture screenshot with numbered badges")
    print("   Step 2: AI analyzes screenshot and identifies target element")
    print("   Step 3: Click element using its SoM ID")
    
    print("\n3. Example SoM Workflow:")
    print("   ```python")
    print("   # Capture screenshot with SoM tagging")
    print("   result = await scanner.execute_action({")
    print("       'tool': 'capture_screenshot_som',")
    print("       'args': {'url': 'https://example.com'}")
    print("   })")
    print("")
    print("   # Screenshot shows: [1] Login  [2] Home  [3] Search  [4] About")
    print("   # Element mapping: {1: '#login-btn', 2: '.home-link', ...}")
    print("")
    print("   # Click the login button (element #1)")
    print("   result = await scanner.execute_action({")
    print("       'tool': 'click_element_by_id',")
    print("       'args': {'url': 'https://example.com', 'element_id': 1}")
    print("   })")
    print("   ```")
    
    print("\n4. Benefits:")
    print("   ✓ Navigate complex JavaScript-heavy applications")
    print("   ✓ Test authentication and multi-step workflows")
    print("   ✓ Identify all interactive elements automatically")
    print("   ✓ Precise element targeting without manual selector creation")
    
    print("\n5. Available Tools:")
    print("   • capture_screenshot_som - Tag all clickable elements")
    print("   • click_element_by_id - Click specific element by ID")
    print("   • visual_screenshot - Regular screenshot for documentation")
    
    print("\n" + "="*70)
    print("✅ Visual Grounding Demo Complete!")
    print("="*70)
    print("\nNote: Full browser testing requires Playwright installation:")
    print("      python -m playwright install chromium")


async def demo_integration():
    """Demonstrate how both features work together"""
    print("\n" + "="*70)
    print("DEMO: Integration of SoM + Blackboard Memory")
    print("="*70)
    
    print("\n1. Complete Workflow Example:")
    print("   " + "-"*65)
    
    print("\n   A. Initial Reconnaissance")
    print("      → Run subdomain_enumeration")
    print("      → Blackboard updated with:")
    print("        Facts: ['Found 10 subdomains', 'api.example.com exists']")
    print("        Goals: ['Test api.example.com', 'Scan other subdomains']")
    
    print("\n   B. Visual Reconnaissance")
    print("      → Run capture_screenshot_som on api.example.com")
    print("      → Screenshot shows: [1] Login  [2] API Docs  [3] Register")
    print("      → Blackboard updated with:")
    print("        Facts: ['Login form found', 'API documentation available']")
    print("        Goals: ['Test login for vulnerabilities']")
    
    print("\n   C. Interactive Testing")
    print("      → Run click_element_by_id to click Login (element #1)")
    print("      → Navigates to login page")
    print("      → Blackboard updated with:")
    print("        Facts: ['Login page requires username/password']")
    print("        Goals: ['Test for default credentials', 'Check for SQL injection']")
    
    print("\n   D. Exploitation Attempts")
    print("      → Test SQL injection in login")
    print("      → If WAF blocks: Add to discarded_vectors")
    print("      → Blackboard updated with:")
    print("        Discarded: ['SQL injection in login - WAF protection']")
    
    print("\n   E. Strategic Decision Making")
    print("      → AI reads blackboard summary")
    print("      → Knows what's been tried and what failed")
    print("      → Makes informed decision about next action")
    print("      → Avoids duplicate work and dead ends")
    
    print("\n" + "="*70)
    print("✅ Integration Demo Complete!")
    print("="*70)
    
    print("\n2. Key Advantages:")
    print("   ✓ Visual understanding enables UI testing")
    print("   ✓ Blackboard prevents duplicate scans")
    print("   ✓ Facts accumulate for better context")
    print("   ✓ Failed attempts are remembered")
    print("   ✓ Goals guide mission progression")
    
    print("\n3. Real-World Impact:")
    print("   • Faster missions (no duplicate work)")
    print("   • Better coverage (systematic goal tracking)")
    print("   • Smarter decisions (context from blackboard)")
    print("   • Complete workflows (visual interaction)")


async def main():
    """Run all demos"""
    print("\n")
    print("╔" + "="*68 + "╗")
    print("║" + " "*15 + "AEGIS AGENT - NEW FEATURES DEMO" + " "*22 + "║")
    print("║" + " "*15 + "Visual Grounding & Blackboard Memory" + " "*17 + "║")
    print("╚" + "="*68 + "╝")
    
    try:
        # Run demos
        await demo_blackboard()
        await demo_visual_grounding()
        await demo_integration()
        
        print("\n\n" + "="*70)
        print("All demos completed successfully!")
        print("="*70)
        print("\nFor more information, see:")
        print("  • VISUAL_GROUNDING_GUIDE.md - Comprehensive feature guide")
        print("  • README.md - Updated with new features")
        print("  • test_som_blackboard.py - Test suite for validation")
        print("\nTo use these features in a mission:")
        print("  1. Start Aegis: python main.py")
        print("  2. Provide target and rules")
        print("  3. Use capture_screenshot_som to analyze UIs")
        print("  4. Use click_element_by_id to interact")
        print("  5. Blackboard automatically tracks mission progress")
        print("\n")
        
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
