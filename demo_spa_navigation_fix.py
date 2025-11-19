#!/usr/bin/env python3
"""
Demonstration of the SPA Navigation Fix

This script demonstrates how the click_element_by_id action now automatically
re-captures the screenshot with SoM when clicking in a Single Page Application
where the URL doesn't change but the content does.
"""

import asyncio
from unittest.mock import MagicMock, AsyncMock


async def demonstrate_spa_navigation_fix():
    """Demonstrate the SPA navigation fix with a realistic example"""
    print("="*70)
    print("SPA NAVIGATION FIX DEMONSTRATION")
    print("="*70)
    print()
    
    # Import the scanner
    from agents.scanner import AegisScanner
    
    # Create mock AI core
    mock_ai_core = MagicMock()
    mock_ai_core.orchestrator = MagicMock()
    
    # Create scanner
    scanner = AegisScanner(mock_ai_core)
    scanner.visual_recon = MagicMock()
    
    # Scenario: Testing a React SPA application
    app_url = "http://example-spa.com/app"
    
    print("📍 Scenario: Testing a React-based Single Page Application")
    print(f"   URL: {app_url}")
    print()
    
    # Step 1: Initial capture
    print("Step 1: Initial SoM capture of the application")
    print("-" * 50)
    
    initial_mapping = {
        1: {"tag": "button", "text": "Products", "css_selector": "button#products-tab"},
        2: {"tag": "button", "text": "About", "css_selector": "button#about-tab"},
        3: {"tag": "button", "text": "Contact", "css_selector": "button#contact-tab"},
    }
    
    scanner.som_mappings[app_url] = initial_mapping
    print(f"✅ Captured {len(initial_mapping)} clickable elements")
    for elem_id, elem_info in initial_mapping.items():
        print(f"   [{elem_id}] {elem_info['tag']}: {elem_info['text']}")
    print()
    
    # Step 2: Click on "Products" tab (SPA navigation - URL stays the same)
    print("Step 2: Click on 'Products' tab")
    print("-" * 50)
    
    # Mock the click result - URL unchanged (SPA)
    click_result = {
        "status": "success",
        "element_id": 1,
        "old_url": app_url,
        "new_url": app_url,  # URL stays the same!
        "url_changed": False,
        "page_title": "Example SPA - Products"
    }
    scanner.visual_recon.click_element = AsyncMock(return_value=click_result)
    
    # Mock the re-capture - new content appears after navigation
    fresh_mapping = {
        1: {"tag": "button", "text": "Products", "css_selector": "button#products-tab"},
        2: {"tag": "button", "text": "About", "css_selector": "button#about-tab"},
        3: {"tag": "button", "text": "Contact", "css_selector": "button#contact-tab"},
        4: {"tag": "a", "text": "Product 1", "css_selector": "a.product-link"},
        5: {"tag": "a", "text": "Product 2", "css_selector": "a.product-link"},
        6: {"tag": "a", "text": "Product 3", "css_selector": "a.product-link"},
        7: {"tag": "button", "text": "Add to Cart", "css_selector": "button.add-cart"},
    }
    
    recapture_result = {
        "status": "success",
        "url": app_url,
        "element_mapping": fresh_mapping,
        "screenshot_path": "/path/to/fresh_screenshot.png"
    }
    scanner.visual_recon.capture_with_som = AsyncMock(return_value=recapture_result)
    
    # Execute the click action
    action = {
        "tool": "click_element_by_id",
        "args": {
            "url": app_url,
            "element_id": 1
        }
    }
    
    result = await scanner.execute_action(action)
    
    print(f"🖱️  Clicked element #{result.get('element_id')}")
    print(f"   URL changed: {result.get('url_changed')}")
    print()
    
    # Step 3: Automatic re-capture
    print("Step 3: Automatic SoM re-capture triggered")
    print("-" * 50)
    print("🔄 SPA navigation detected (URL unchanged)")
    print(f"✅ Re-captured screenshot with fresh element mapping")
    
    if "spa_recapture" in result:
        spa_info = result["spa_recapture"]
        if spa_info["status"] == "success":
            print(f"   New elements indexed: {spa_info['new_element_count']}")
            print(f"   Screenshot saved: {spa_info['screenshot_path']}")
    print()
    
    # Step 4: Show the updated mapping
    print("Step 4: Updated SoM mapping")
    print("-" * 50)
    print(f"✅ SoM mapping updated with {len(scanner.som_mappings[app_url])} elements")
    print("   New clickable elements detected:")
    
    # Show only new elements (that weren't in initial mapping)
    for elem_id in sorted(scanner.som_mappings[app_url].keys()):
        if elem_id not in initial_mapping:
            elem_info = scanner.som_mappings[app_url][elem_id]
            print(f"   [{elem_id}] {elem_info['tag']}: {elem_info['text']}")
    print()
    
    # Summary
    print("="*70)
    print("SUMMARY")
    print("="*70)
    print()
    print("✅ Before fix: SoM mapping would become stale after SPA navigation")
    print("✅ After fix:  SoM mapping automatically refreshed for SPA navigation")
    print()
    print("Benefits:")
    print("  • AI can continue interacting with newly appeared elements")
    print("  • No manual re-capture needed")
    print("  • Seamless testing of Single Page Applications")
    print("  • Element IDs always refer to current page state")
    print()
    
    # Contrast with regular navigation
    print("="*70)
    print("CONTRAST: Regular Navigation (URL changes)")
    print("="*70)
    print()
    
    old_url = "http://example.com/page1"
    new_url = "http://example.com/page2"
    
    scanner.som_mappings[old_url] = {1: {"tag": "a", "text": "Link to Page 2"}}
    
    # Mock regular navigation
    regular_click_result = {
        "status": "success",
        "element_id": 1,
        "old_url": old_url,
        "new_url": new_url,  # URL changes!
        "url_changed": True,
        "page_title": "Page 2"
    }
    scanner.visual_recon.click_element = AsyncMock(return_value=regular_click_result)
    scanner.visual_recon.capture_with_som = AsyncMock()  # Should not be called
    
    action = {
        "tool": "click_element_by_id",
        "args": {
            "url": old_url,
            "element_id": 1
        }
    }
    
    result = await scanner.execute_action(action)
    
    print(f"🖱️  Clicked element #{result.get('element_id')}")
    print(f"   Old URL: {old_url}")
    print(f"   New URL: {new_url}")
    print(f"   URL changed: {result.get('url_changed')}")
    print()
    print("✅ No automatic re-capture triggered (URL changed)")
    print("   This is correct - AI will capture new page separately if needed")
    print()
    
    # Verify re-capture was NOT called
    assert not scanner.visual_recon.capture_with_som.called, "Re-capture should not be called for regular navigation"
    
    print("="*70)
    print()


if __name__ == "__main__":
    asyncio.run(demonstrate_spa_navigation_fix())
