"""
Visual Reconnaissance Tool for Aegis AI.

Provides authenticated visual data gathering using Playwright with
Set-of-Mark (SoM) visual grounding for precise UI element interaction.

Features:
    - Authenticated screenshot capture with session cookies
    - SoM visual grounding with numbered element badges
    - DOM snapshot extraction with selector-based element extraction
    - Click element by SoM ID for precise UI navigation
    - Auto-installation of Chromium if not found
"""

import asyncio
import base64
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List
from playwright.async_api import async_playwright, Browser, BrowserContext, Page

logger = logging.getLogger(__name__)

# Version constant for user agent and compatibility tracking
AEGIS_VERSION = "7.5"


class VisualReconTool:
    """
    Visual reconnaissance tool using Playwright for authenticated web scraping,
    screenshot capture, and DOM analysis.
    
    This tool reuses session management from tool_manager.py to maintain
    authenticated state during visual reconnaissance. Includes auto-installation
    of Chromium browser if not found.
    
    Attributes:
        browser: Playwright Browser instance.
        context: Playwright BrowserContext with session cookies.
        playwright: Playwright instance for browser management.
        viewport_width: Default viewport width in pixels.
        viewport_height: Default viewport height in pixels.
        timeout: Default operation timeout in milliseconds.
    """
    
    def __init__(self):
        """Initialize the visual recon tool with default settings."""
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.playwright = None
        self.viewport_width = 1920
        self.viewport_height = 1080
        self.timeout = 30000  # 30 seconds
        logger.info("🔧 VisualReconTool initialized")
    
    def _load_session_data(self) -> Optional[Dict]:
        """
        Load session data from file if it exists.
        
        Copied from tools/tool_manager.py for authenticated requests.
        
        Returns:
            Optional[Dict]: Session data dictionary containing cookies and headers,
                or None if session file not found or invalid.
        """
        session_file = Path("data/session.json")
        if session_file.exists():
            try:
                with open(session_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"⚠️ Failed to load session data: {e}")
        
        return None
    
    def _build_cookie_header(self, session_data: Dict) -> str:
        """
        Build cookie header from session data.
        
        Copied from tools/tool_manager.py for authenticated requests.
        
        Args:
            session_data: Session data dictionary with cookies.
            
        Returns:
            str: Cookie header string in format "name1=value1; name2=value2".
        """
        if not session_data or 'cookies' not in session_data:
            return ""
        
        cookie_pairs = []
        for cookie in session_data['cookies']:
            cookie_pairs.append(f"{cookie['name']}={cookie['value']}")
        
        return "; ".join(cookie_pairs)
    
    def _install_chromium(self) -> bool:
        """
        Auto-install Chromium browser using Playwright's install command.
        
        Called automatically when Playwright fails to launch due to missing
        Chrome binary. This implements the self-healing infrastructure pattern.
        
        Returns:
            bool: True if installation succeeded, False otherwise.
        """
        logger.info("🔧 Chrome binary not found. Auto-installing Chromium...")
        try:
            # Use sys.executable to find the Python interpreter, then invoke playwright module
            # This is safer than relying on PATH for the playwright command
            import sys
            result = subprocess.run(
                [sys.executable, "-m", "playwright", "install", "chromium"],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            if result.returncode == 0:
                logger.info("✅ Chromium installed successfully via Playwright")
                return True
            else:
                logger.error(f"❌ Chromium installation failed: {result.stderr}")
                return False
        except subprocess.TimeoutExpired:
            logger.error("❌ Chromium installation timed out after 5 minutes")
            return False
        except FileNotFoundError:
            logger.error("❌ Python or playwright module not found")
            return False
        except Exception as e:
            logger.error(f"❌ Error installing Chromium: {e}")
            return False
    
    async def _initialize_browser(self) -> None:
        """
        Initialize Playwright browser with session cookies.
        
        Implements self-healing: if Playwright fails to launch due to missing
        Chrome binary, automatically runs 'playwright install chromium' and retries.
        
        Stealth Mode: Uses specific browser arguments to hide automation fingerprints
        and bypass WAF/bot detection systems.
        
        Raises:
            RuntimeError: If browser initialization fails after auto-install attempt.
        """
        if self.browser is not None:
            return  # Already initialized
        
        try:
            logger.info("🌐 Initializing Playwright browser with stealth mode...")
            self.playwright = await async_playwright().start()
            
            # Stealth browser launch arguments to hide bot signature
            stealth_args = [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-blink-features=AutomationControlled',  # HIDES BOT STATUS
                '--disable-infobars',
                '--window-size=1920,1080',
                '--disable-dev-shm-usage',
                '--disable-gpu',
            ]
            
            # First attempt to launch browser
            try:
                self.browser = await self.playwright.chromium.launch(
                    headless=True,
                    args=stealth_args
                )
            except Exception as launch_error:
                error_msg = str(launch_error).lower()
                # Check if error is related to missing Chrome binary
                if 'chrome' in error_msg or 'chromium' in error_msg or 'executable' in error_msg:
                    logger.warning(f"⚠️ Browser launch failed: {launch_error}")
                    
                    # Auto-install Chromium
                    if self._install_chromium():
                        # Retry browser launch after installation
                        logger.info("🔄 Retrying browser launch after Chromium installation...")
                        self.browser = await self.playwright.chromium.launch(
                            headless=True,
                            args=stealth_args
                        )
                    else:
                        raise RuntimeError(
                            "Failed to auto-install Chromium. "
                            "Please run: pip install playwright && playwright install chromium"
                        )
                else:
                    raise  # Re-raise if not a Chrome binary issue
            
            # Create browser context with stealth parameters
            # Use realistic user agent matching real Chrome to avoid detection
            headers = {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
            }
            
            self.context = await self.browser.new_context(
                viewport={'width': self.viewport_width, 'height': self.viewport_height},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
                java_script_enabled=True,
                locale='en-US',
                extra_http_headers=headers
            )
            
            # CRITICAL: Remove the webdriver property to hide bot status
            await self.context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
            
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
            logger.error(f"❌ Failed to initialize browser: {e}", exc_info=True)
            raise
    
    async def _cleanup_browser(self) -> None:
        """
        Cleanup browser resources.
        
        Closes context, browser, and playwright instances in order.
        Safe to call multiple times.
        """
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
            
            logger.info("🔧 Browser cleaned up")
            
        except Exception as e:
            logger.error(f"❌ Error cleaning up browser: {e}", exc_info=True)
    
    async def capture_screenshot(
        self,
        url: str,
        output_path: Optional[str] = None,
        full_page: bool = False,
        wait_for_selector: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Capture a screenshot of a web page with authenticated session.
        
        Args:
            url: Target URL to screenshot.
            output_path: Optional path to save screenshot (default: data/screenshots/).
            full_page: Whether to capture full page or just viewport.
            wait_for_selector: Optional CSS selector to wait for before screenshot.
            
        Returns:
            Dict[str, Any]: Dictionary containing:
                - status: "success" or "error"
                - url: The URL that was captured
                - screenshot_path: Path where screenshot was saved
                - screenshot_size: Size of screenshot in bytes
                - page_title: Title of the page
                - viewport: Viewport dimensions
                - full_page: Whether full page was captured
                - screenshot_base64: Base64 encoded screenshot data
                - error: Error message if status is "error"
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
    
    async def capture_with_som(
        self,
        url: str,
        output_path: Optional[str] = None,
        full_page: bool = False
    ) -> Dict[str, Any]:
        """
        Capture screenshot with Set-of-Mark (SoM) visual grounding.
        Overlays numbered red badges on all clickable elements.
        
        Args:
            url: Target URL to screenshot
            output_path: Optional path to save screenshot
            full_page: Whether to capture full page or just viewport
            
        Returns:
            Dictionary with screenshot data and element mapping {ID: selector}
        """
        logger.info(f"📸 Capturing SoM screenshot: {url}")
        
        try:
            await self._initialize_browser()
            
            # Create new page
            page = await self.context.new_page()
            page.set_default_timeout(self.timeout)
            
            # Navigate to URL
            await page.goto(url, wait_until='networkidle')
            
            # Inject JavaScript to add SoM badges and collect element data
            som_script = """
            () => {
                // Find all clickable elements
                const clickableSelectors = 'a, button, input[type="submit"], input[type="button"], [onclick], [role="button"]';
                const elements = Array.from(document.querySelectorAll(clickableSelectors));
                
                // Filter visible elements only
                const visibleElements = elements.filter(el => {
                    const style = window.getComputedStyle(el);
                    return style.display !== 'none' && 
                           style.visibility !== 'hidden' && 
                           style.opacity !== '0' &&
                           el.offsetWidth > 0 && 
                           el.offsetHeight > 0;
                });
                
                // Create mapping and add badges
                const mapping = {};
                
                visibleElements.forEach((el, index) => {
                    const id = index + 1;
                    
                    // Generate XPath for the element
                    const getXPath = (element) => {
                        if (element.id) {
                            return `//*[@id="${element.id}"]`;
                        }
                        if (element === document.body) {
                            return '/html/body';
                        }
                        let ix = 0;
                        const siblings = element.parentNode?.childNodes || [];
                        for (let i = 0; i < siblings.length; i++) {
                            const sibling = siblings[i];
                            if (sibling === element) {
                                const parentPath = element.parentNode ? getXPath(element.parentNode) : '';
                                return `${parentPath}/${element.tagName.toLowerCase()}[${ix + 1}]`;
                            }
                            if (sibling.nodeType === 1 && sibling.tagName === element.tagName) {
                                ix++;
                            }
                        }
                        return '';
                    };
                    
                    // Generate CSS selector as fallback
                    const getCssSelector = (element) => {
                        if (element.id) {
                            return `#${element.id}`;
                        }
                        let path = [];
                        let current = element;
                        while (current && current !== document.body) {
                            let selector = current.tagName.toLowerCase();
                            if (current.className) {
                                const classes = current.className.trim().split(/\\s+/).join('.');
                                if (classes) selector += '.' + classes;
                            }
                            path.unshift(selector);
                            current = current.parentElement;
                        }
                        return path.join(' > ');
                    };
                    
                    const xpath = getXPath(el);
                    const cssSelector = getCssSelector(el);
                    const text = el.innerText?.trim().substring(0, 50) || el.value || '';
                    
                    // Store mapping
                    mapping[id] = {
                        xpath: xpath,
                        css_selector: cssSelector,
                        tag: el.tagName.toLowerCase(),
                        text: text,
                        type: el.type || '',
                        id_attr: el.id || '',
                        classes: el.className || ''
                    };
                    
                    // Create and position badge
                    const badge = document.createElement('div');
                    badge.innerText = id.toString();
                    badge.style.cssText = `
                        position: absolute;
                        background-color: #ff0000;
                        color: white;
                        font-weight: bold;
                        font-size: 12px;
                        padding: 2px 6px;
                        border-radius: 10px;
                        z-index: 10000;
                        pointer-events: none;
                        font-family: Arial, sans-serif;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.3);
                    `;
                    
                    // Position badge at top-left of element
                    const rect = el.getBoundingClientRect();
                    badge.style.left = (rect.left + window.scrollX) + 'px';
                    badge.style.top = (rect.top + window.scrollY) + 'px';
                    
                    // Add data attribute to track
                    badge.setAttribute('data-som-id', id);
                    
                    document.body.appendChild(badge);
                });
                
                return mapping;
            }
            """
            
            # Execute script and get element mapping
            element_mapping = await page.evaluate(som_script)
            
            logger.info(f"✅ SoM: Tagged {len(element_mapping)} clickable elements")
            
            # Wait a moment for badges to render
            await asyncio.sleep(0.5)
            
            # Determine output path
            if not output_path:
                screenshot_dir = Path("data/screenshots")
                screenshot_dir.mkdir(exist_ok=True, parents=True)
                import time
                safe_url = url.replace('://', '_').replace('/', '_')[:50]
                output_path = str(screenshot_dir / f"som_{safe_url}_{int(time.time())}.png")
            
            # Capture screenshot with badges
            screenshot_bytes = await page.screenshot(
                path=output_path,
                full_page=full_page
            )
            
            # Get page metadata
            title = await page.title()
            viewport = page.viewport_size
            
            await page.close()
            
            logger.info(f"✅ SoM screenshot saved: {output_path}")
            
            return {
                "status": "success",
                "url": url,
                "screenshot_path": output_path,
                "screenshot_size": len(screenshot_bytes),
                "page_title": title,
                "viewport": viewport,
                "full_page": full_page,
                "screenshot_base64": base64.b64encode(screenshot_bytes).decode('utf-8'),
                "element_mapping": element_mapping,
                "num_elements": len(element_mapping)
            }
            
        except Exception as e:
            logger.error(f"Error capturing SoM screenshot: {e}", exc_info=True)
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
    
    async def click_element(
        self,
        url: str,
        element_id: int,
        element_mapping: Dict[int, Dict[str, str]]
    ) -> Dict[str, Any]:
        """
        Click an element using SoM element ID and mapping
        
        Args:
            url: Target URL
            element_id: SoM element ID from the mapping
            element_mapping: Element mapping from capture_with_som
            
        Returns:
            Dictionary with click result and new page state
        """
        logger.info(f"🖱️ Clicking element #{element_id} on {url}")
        
        try:
            if element_id not in element_mapping:
                return {
                    "status": "error",
                    "error": f"Element ID {element_id} not found in mapping"
                }
            
            await self._initialize_browser()
            
            # Create new page
            page = await self.context.new_page()
            page.set_default_timeout(self.timeout)
            
            # Navigate to URL
            await page.goto(url, wait_until='networkidle')
            
            # Get element info from mapping
            element_info = element_mapping[element_id]
            css_selector = element_info.get('css_selector')
            xpath = element_info.get('xpath')
            
            logger.info(f"  Element: {element_info.get('tag')} - '{element_info.get('text', '')[:30]}'")
            
            # Try CSS selector first, fallback to XPath
            clicked = False
            click_method = None
            
            # Try CSS selector
            if css_selector:
                try:
                    await page.click(css_selector, timeout=5000)
                    clicked = True
                    click_method = "css_selector"
                    logger.info(f"  ✓ Clicked using CSS selector")
                except Exception as e:
                    logger.warning(f"  CSS selector click failed: {e}")
            
            # Fallback to XPath if CSS failed
            if not clicked and xpath:
                try:
                    element = await page.query_selector(f'xpath={xpath}')
                    if element:
                        await element.click()
                        clicked = True
                        click_method = "xpath"
                        logger.info(f"  ✓ Clicked using XPath")
                    else:
                        logger.warning(f"  XPath element not found")
                except Exception as e:
                    logger.warning(f"  XPath click failed: {e}")
            
            if not clicked:
                await page.close()
                return {
                    "status": "error",
                    "error": f"Failed to click element {element_id}",
                    "element_info": element_info
                }
            
            # Wait for navigation or network idle after click
            try:
                await page.wait_for_load_state('networkidle', timeout=5000)
            except:
                pass  # Timeout is okay, element might not trigger navigation
            
            # Get new page state
            new_url = page.url
            title = await page.title()
            
            await page.close()
            
            logger.info(f"✅ Click successful, new URL: {new_url}")
            
            return {
                "status": "success",
                "element_id": element_id,
                "element_info": element_info,
                "click_method": click_method,
                "old_url": url,
                "new_url": new_url,
                "page_title": title,
                "url_changed": new_url != url
            }
            
        except Exception as e:
            logger.error(f"Error clicking element: {e}", exc_info=True)
            return {
                "status": "error",
                "element_id": element_id,
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
