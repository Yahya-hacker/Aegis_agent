#!/usr/bin/env python3
"""
Test suite for SPA navigation fix in click_element_by_id
Tests that after clicking an element in an SPA (where URL doesn't change),
the system automatically re-captures the screenshot with SoM to update mappings.
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))


def test_spa_navigation_logic():
    """Test SPA navigation detection and re-capture logic"""
    print("\n" + "="*70)
    print("Testing SPA Navigation Detection Logic")
    print("="*70)
    
    # Test URL change detection
    print("✓ Testing URL change detection...")
    
    # Case 1: URL changed (traditional navigation) - no re-capture needed
    result_url_changed = {
        "status": "success",
        "old_url": "http://example.com/page1",
        "new_url": "http://example.com/page2",
        "url_changed": True
    }
    should_recapture = result_url_changed.get("status") == "success" and not result_url_changed.get("url_changed", True)
    assert should_recapture == False, "Should not re-capture when URL changed"
    print("  ✓ URL changed: No re-capture needed")
    
    # Case 2: URL unchanged (SPA navigation) - re-capture needed
    result_url_unchanged = {
        "status": "success",
        "old_url": "http://example.com/app",
        "new_url": "http://example.com/app",
        "url_changed": False
    }
    should_recapture = result_url_unchanged.get("status") == "success" and not result_url_unchanged.get("url_changed", True)
    assert should_recapture == True, "Should re-capture when URL unchanged (SPA)"
    print("  ✓ URL unchanged: Re-capture needed")
    
    # Case 3: Click failed - no re-capture
    result_failed = {
        "status": "error",
        "error": "Element not found",
        "url_changed": False
    }
    should_recapture = result_failed.get("status") == "success" and not result_failed.get("url_changed", True)
    assert should_recapture == False, "Should not re-capture when click failed"
    print("  ✓ Click failed: No re-capture")
    
    print("\n✅ SPA Navigation Logic - ALL TESTS PASSED")
    return True


async def test_scanner_spa_recapture():
    """Test scanner's SPA re-capture functionality with mocks"""
    print("\n" + "="*70)
    print("Testing Scanner SPA Re-capture with Mocks")
    print("="*70)
    
    from agents.scanner import AegisScanner
    
    # Create mock AI core
    mock_ai_core = MagicMock()
    mock_ai_core.orchestrator = MagicMock()
    
    print("✓ Creating scanner instance...")
    scanner = AegisScanner(mock_ai_core)
    
    # Mock the visual_recon tool
    scanner.visual_recon = MagicMock()
    
    # Test URL and element data
    test_url = "http://example.com/app"
    element_id = 1
    
    # Setup initial SoM mapping
    initial_mapping = {
        1: {
            "xpath": "/html/body/button[1]",
            "css_selector": "button.old-button",
            "tag": "button",
            "text": "Click Me"
        }
    }
    scanner.som_mappings[test_url] = initial_mapping
    
    # Mock click_element to return SPA navigation (URL unchanged)
    click_result = {
        "status": "success",
        "element_id": element_id,
        "old_url": test_url,
        "new_url": test_url,
        "url_changed": False
    }
    scanner.visual_recon.click_element = AsyncMock(return_value=click_result)
    
    # Mock capture_with_som to return fresh mapping
    fresh_mapping = {
        1: {
            "xpath": "/html/body/button[1]",
            "css_selector": "button.new-button",
            "tag": "button",
            "text": "New Content"
        },
        2: {
            "xpath": "/html/body/div[1]",
            "css_selector": "div.new-element",
            "tag": "div",
            "text": "Dynamically Added"
        }
    }
    recapture_result = {
        "status": "success",
        "url": test_url,
        "element_mapping": fresh_mapping,
        "screenshot_path": "/path/to/screenshot.png"
    }
    scanner.visual_recon.capture_with_som = AsyncMock(return_value=recapture_result)
    
    print("✓ Testing click_element_by_id with SPA navigation...")
    
    # Execute the action
    action = {
        "tool": "click_element_by_id",
        "args": {
            "url": test_url,
            "element_id": element_id
        }
    }
    
    result = await scanner.execute_action(action)
    
    # Verify the click was executed
    print("✓ Verifying click was executed...")
    assert result.get("status") == "success", f"Click should succeed, got: {result}"
    scanner.visual_recon.click_element.assert_called_once_with(test_url, element_id, initial_mapping)
    
    # Verify SPA re-capture was triggered
    print("✓ Verifying SPA re-capture was triggered...")
    scanner.visual_recon.capture_with_som.assert_called_once_with(test_url, full_page=False)
    
    # Verify SoM mapping was updated
    print("✓ Verifying SoM mapping was updated...")
    assert test_url in scanner.som_mappings, "URL should still be in mappings"
    assert scanner.som_mappings[test_url] == fresh_mapping, "Mapping should be updated with fresh data"
    assert len(scanner.som_mappings[test_url]) == 2, "Fresh mapping should have 2 elements"
    
    # Verify result includes spa_recapture info
    print("✓ Verifying result includes spa_recapture info...")
    assert "spa_recapture" in result, "Result should include spa_recapture info"
    assert result["spa_recapture"]["status"] == "success", "spa_recapture should be successful"
    assert result["spa_recapture"]["new_element_count"] == 2, "Should report 2 new elements"
    
    print("\n✅ Scanner SPA Re-capture - ALL TESTS PASSED")
    return True


async def test_scanner_non_spa_navigation():
    """Test that regular navigation (URL changed) doesn't trigger re-capture"""
    print("\n" + "="*70)
    print("Testing Regular Navigation (No Re-capture)")
    print("="*70)
    
    from agents.scanner import AegisScanner
    
    # Create mock AI core
    mock_ai_core = MagicMock()
    mock_ai_core.orchestrator = MagicMock()
    
    print("✓ Creating scanner instance...")
    scanner = AegisScanner(mock_ai_core)
    
    # Mock the visual_recon tool
    scanner.visual_recon = MagicMock()
    
    # Test URLs
    old_url = "http://example.com/page1"
    new_url = "http://example.com/page2"
    element_id = 1
    
    # Setup initial SoM mapping
    initial_mapping = {
        1: {
            "xpath": "/html/body/a[1]",
            "css_selector": "a.link",
            "tag": "a",
            "text": "Go to Page 2"
        }
    }
    scanner.som_mappings[old_url] = initial_mapping
    
    # Mock click_element to return regular navigation (URL changed)
    click_result = {
        "status": "success",
        "element_id": element_id,
        "old_url": old_url,
        "new_url": new_url,
        "url_changed": True
    }
    scanner.visual_recon.click_element = AsyncMock(return_value=click_result)
    scanner.visual_recon.capture_with_som = AsyncMock()
    
    print("✓ Testing click_element_by_id with URL change...")
    
    # Execute the action
    action = {
        "tool": "click_element_by_id",
        "args": {
            "url": old_url,
            "element_id": element_id
        }
    }
    
    result = await scanner.execute_action(action)
    
    # Verify the click was executed
    print("✓ Verifying click was executed...")
    assert result.get("status") == "success", "Click should succeed"
    scanner.visual_recon.click_element.assert_called_once()
    
    # Verify SPA re-capture was NOT triggered
    print("✓ Verifying SPA re-capture was NOT triggered...")
    scanner.visual_recon.capture_with_som.assert_not_called()
    
    # Verify result does NOT include spa_recapture info
    print("✓ Verifying result does not include spa_recapture...")
    assert "spa_recapture" not in result, "Result should not include spa_recapture for regular navigation"
    
    print("\n✅ Regular Navigation Test - ALL TESTS PASSED")
    return True


async def test_scanner_spa_recapture_failure():
    """Test that scanner handles re-capture failure gracefully"""
    print("\n" + "="*70)
    print("Testing SPA Re-capture Failure Handling")
    print("="*70)
    
    from agents.scanner import AegisScanner
    
    # Create mock AI core
    mock_ai_core = MagicMock()
    mock_ai_core.orchestrator = MagicMock()
    
    print("✓ Creating scanner instance...")
    scanner = AegisScanner(mock_ai_core)
    
    # Mock the visual_recon tool
    scanner.visual_recon = MagicMock()
    
    # Test URL and element data
    test_url = "http://example.com/app"
    element_id = 1
    
    # Setup initial SoM mapping
    initial_mapping = {
        1: {"xpath": "/html/body/button[1]", "css_selector": "button", "tag": "button", "text": "Click"}
    }
    scanner.som_mappings[test_url] = initial_mapping
    
    # Mock click_element to return SPA navigation
    click_result = {
        "status": "success",
        "element_id": element_id,
        "old_url": test_url,
        "new_url": test_url,
        "url_changed": False
    }
    scanner.visual_recon.click_element = AsyncMock(return_value=click_result)
    
    # Mock capture_with_som to fail
    recapture_result = {
        "status": "error",
        "error": "Browser crashed"
    }
    scanner.visual_recon.capture_with_som = AsyncMock(return_value=recapture_result)
    
    print("✓ Testing click_element_by_id with re-capture failure...")
    
    # Execute the action
    action = {
        "tool": "click_element_by_id",
        "args": {
            "url": test_url,
            "element_id": element_id
        }
    }
    
    result = await scanner.execute_action(action)
    
    # Verify the click itself was still successful
    print("✓ Verifying click was successful despite re-capture failure...")
    assert result.get("status") == "success", "Click should still be successful"
    
    # Verify spa_recapture error is reported
    print("✓ Verifying spa_recapture error is reported...")
    assert "spa_recapture" in result, "Result should include spa_recapture info"
    assert result["spa_recapture"]["status"] == "error", "spa_recapture should report error"
    assert "error" in result["spa_recapture"], "spa_recapture should include error message"
    
    print("\n✅ Re-capture Failure Handling - ALL TESTS PASSED")
    return True


async def run_async_tests():
    """Run all async tests"""
    await test_scanner_spa_recapture()
    await test_scanner_non_spa_navigation()
    await test_scanner_spa_recapture_failure()


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("SPA NAVIGATION FIX TEST SUITE")
    print("="*70)
    
    try:
        # Run sync tests
        test_spa_navigation_logic()
        
        # Run async tests
        asyncio.run(run_async_tests())
        
        print("\n" + "="*70)
        print("✅ ALL TESTS PASSED!")
        print("="*70)
        print("\nImplementation Summary:")
        print("1. ✅ SPA navigation detection (URL unchanged after click)")
        print("2. ✅ Automatic re-capture of screenshot with SoM")
        print("3. ✅ SoM mapping update with fresh element data")
        print("4. ✅ Graceful handling of re-capture failures")
        print("5. ✅ Regular navigation unchanged (no re-capture)")
        
        return True
        
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
