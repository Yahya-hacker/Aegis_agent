"""
Visual Reconnaissance Tool for Aegis AI
Provides authenticated visual data gathering using Playwright
"""

import asyncio
import base64
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from playwright.async_api import async_playwright, Browser, BrowserContext, Page

logger = logging.getLogger(__name__)


class VisualReconTool:
    """
    Visual reconnaissance tool using Playwright for authenticated web scraping,
    screenshot capture, and DOM analysis.
    
    This tool reuses session management from tool_manager.py to maintain
    authenticated state during visual reconnaissance.
    """
    
    def __init__(self):
        """Initialize the visual recon tool"""
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.playwright = None
        self.viewport_width = 1920
        self.viewport_height = 1080
        self.timeout = 30000  # 30 seconds
        logger.info("VisualReconTool initialized")
    
    def _load_session_data(self) -> Optional[Dict]:
        """
        Load session data from file if it exists
        Copied from tools/tool_manager.py for authenticated requests
        
        Returns:
            Session data dictionary or None if not found
        """
        session_file = Path("data/session.json")
        if session_file.exists():
            try:
                with open(session_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load session data: {e}")
        
        return None
    
    def _build_cookie_header(self, session_data: Dict) -> str:
        """
        Build cookie header from session data
        Copied from tools/tool_manager.py for authenticated requests
        
        Args:
            session_data: Session data dictionary with cookies
            
        Returns:
            Cookie header string
        """
        if not session_data or 'cookies' not in session_data:
            return ""
        
        cookie_pairs = []
        for cookie in session_data['cookies']:
            cookie_pairs.append(f"{cookie['name']}={cookie['value']}")
        
        return "; ".join(cookie_pairs)
    
    async def _initialize_browser(self) -> None:
        """Initialize Playwright browser with session cookies"""
        if self.browser is not None:
            return  # Already initialized
        
        try:
            logger.info("🌐 Initializing Playwright browser...")
            self.playwright = await async_playwright().start()
            
            # Launch browser in headless mode
            self.browser = await self.playwright.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-setuid-sandbox']
            )
            
            # Create browser context
            self.context = await self.browser.new_context(
                viewport={'width': self.viewport_width, 'height': self.viewport_height},
                user_agent='Aegis-AI/7.0 Visual Recon Tool'
            )
            
            # Load and inject session cookies
            session_data = self._load_session_data()
            if session_data and 'cookies' in session_data:
                # Convert cookies to Playwright format
                playwright_cookies = []
                for cookie in session_data['cookies']:
                    playwright_cookies.append({
                        'name': cookie['name'],
                        'value': cookie['value'],
                        'domain': cookie.get('domain', ''),
                        'path': cookie.get('path', '/'),
                        'secure': cookie.get('secure', False),
                        'httpOnly': cookie.get('httpOnly', False),
                        'sameSite': cookie.get('sameSite', 'Lax')
                    })
                
                await self.context.add_cookies(playwright_cookies)
                logger.info(f"🔐 Loaded {len(playwright_cookies)} session cookies")
            
            logger.info("✅ Browser initialized with session")
            
        except Exception as e:
            logger.error(f"Failed to initialize browser: {e}", exc_info=True)
            raise
    
    async def _cleanup_browser(self) -> None:
        """Cleanup browser resources"""
        try:
            if self.context:
                await self.context.close()
                self.context = None
            
            if self.browser:
                await self.browser.close()
                self.browser = None
            
            if self.playwright:
                await self.playwright.stop()
                self.playwright = None
            
            logger.info("Browser cleaned up")
            
        except Exception as e:
            logger.error(f"Error cleaning up browser: {e}", exc_info=True)
    
    async def capture_screenshot(
        self,
        url: str,
        output_path: Optional[str] = None,
        full_page: bool = False,
        wait_for_selector: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Capture a screenshot of a web page with authenticated session
        
        Args:
            url: Target URL to screenshot
            output_path: Optional path to save screenshot (default: data/screenshots/)
            full_page: Whether to capture full page or just viewport
            wait_for_selector: Optional CSS selector to wait for before screenshot
            
        Returns:
            Dictionary with screenshot data and metadata
        """
        logger.info(f"📸 Capturing screenshot: {url}")
        
        try:
            await self._initialize_browser()
            
            # Create new page
            page = await self.context.new_page()
            
            # Set timeout
            page.set_default_timeout(self.timeout)
            
            # Navigate to URL
            await page.goto(url, wait_until='networkidle')
            
            # Wait for specific selector if provided
            if wait_for_selector:
                await page.wait_for_selector(wait_for_selector)
                logger.info(f"✓ Waited for selector: {wait_for_selector}")
            
            # Determine output path
            if not output_path:
                screenshot_dir = Path("data/screenshots")
                screenshot_dir.mkdir(exist_ok=True, parents=True)
                import time
                safe_url = url.replace('://', '_').replace('/', '_')[:50]
                output_path = str(screenshot_dir / f"screenshot_{safe_url}_{int(time.time())}.png")
            
            # Capture screenshot
            screenshot_bytes = await page.screenshot(
                path=output_path,
                full_page=full_page
            )
            
            # Get page title and dimensions
            title = await page.title()
            viewport = page.viewport_size
            
            await page.close()
            
            logger.info(f"✅ Screenshot saved: {output_path}")
            
            return {
                "status": "success",
                "url": url,
                "screenshot_path": output_path,
                "screenshot_size": len(screenshot_bytes),
                "page_title": title,
                "viewport": viewport,
                "full_page": full_page,
                "screenshot_base64": base64.b64encode(screenshot_bytes).decode('utf-8')
            }
            
        except Exception as e:
            logger.error(f"Error capturing screenshot: {e}", exc_info=True)
            return {
                "status": "error",
                "url": url,
                "error": str(e)
            }
    
    async def get_dom_snapshot(
        self,
        url: str,
        selectors: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Get a DOM snapshot with specific elements or full HTML
        
        Args:
            url: Target URL
            selectors: Optional list of CSS selectors to extract
            
        Returns:
            Dictionary with DOM data and extracted elements
        """
        logger.info(f"🔍 Getting DOM snapshot: {url}")
        
        try:
            await self._initialize_browser()
            
            # Create new page
            page = await self.context.new_page()
            page.set_default_timeout(self.timeout)
            
            # Navigate to URL
            await page.goto(url, wait_until='networkidle')
            
            # Get page metadata
            title = await page.title()
            url_final = page.url
            
            # Get HTML content
            html_content = await page.content()
            
            # Extract specific elements if selectors provided
            extracted_elements = {}
            if selectors:
                for selector in selectors:
                    try:
                        elements = await page.query_selector_all(selector)
                        extracted_elements[selector] = []
                        
                        for element in elements:
                            inner_text = await element.inner_text()
                            inner_html = await element.inner_html()
                            extracted_elements[selector].append({
                                'text': inner_text,
                                'html': inner_html
                            })
                        
                        logger.info(f"✓ Extracted {len(elements)} elements for '{selector}'")
                    except Exception as e:
                        logger.warning(f"Failed to extract selector '{selector}': {e}")
                        extracted_elements[selector] = {"error": str(e)}
            
            # Get all links
            links = await page.evaluate('''() => {
                return Array.from(document.querySelectorAll('a[href]')).map(a => ({
                    href: a.href,
                    text: a.innerText.trim()
                }));
            }''')
            
            # Get all forms
            forms = await page.evaluate('''() => {
                return Array.from(document.querySelectorAll('form')).map(form => ({
                    action: form.action,
                    method: form.method,
                    inputs: Array.from(form.querySelectorAll('input, select, textarea')).map(input => ({
                        name: input.name,
                        type: input.type || input.tagName.toLowerCase(),
                        id: input.id
                    }))
                }));
            }''')
            
            await page.close()
            
            logger.info(f"✅ DOM snapshot complete: {len(links)} links, {len(forms)} forms")
            
            return {
                "status": "success",
                "url": url,
                "final_url": url_final,
                "title": title,
                "html_length": len(html_content),
                "html_content": html_content[:10000],  # First 10KB to avoid huge responses
                "links_count": len(links),
                "links": links[:50],  # First 50 links
                "forms_count": len(forms),
                "forms": forms,
                "extracted_elements": extracted_elements
            }
            
        except Exception as e:
            logger.error(f"Error getting DOM snapshot: {e}", exc_info=True)
            return {
                "status": "error",
                "url": url,
                "error": str(e)
            }
    
    async def close(self) -> None:
        """Close the browser and cleanup resources"""
        await self._cleanup_browser()
    
    async def __aenter__(self):
        """Context manager entry"""
        await self._initialize_browser()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        await self._cleanup_browser()


# Singleton instance
_visual_recon_instance = None


def get_visual_recon_tool() -> VisualReconTool:
    """Get singleton visual recon tool instance"""
    global _visual_recon_instance
    if _visual_recon_instance is None:
        _visual_recon_instance = VisualReconTool()
    return _visual_recon_instance
