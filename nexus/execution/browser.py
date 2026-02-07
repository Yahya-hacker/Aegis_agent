"""
Nexus v2.0 - Browser Automation
===============================

Playwright-based browser automation for:
- DOM XSS testing
- SPA crawling
- Screenshot capture
- JavaScript analysis
"""

import asyncio
import logging
import json
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path

from nexus.config import get_config

logger = logging.getLogger(__name__)

# Try to import Playwright
try:
    from playwright.async_api import async_playwright, Browser, Page, BrowserContext
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.warning("⚠️ Playwright not installed. Run: pip install playwright && playwright install")


@dataclass
class PageResult:
    """Result of page interaction."""
    url: str
    title: str
    status_code: int
    content: str
    headers: Dict[str, str]
    cookies: List[Dict[str, Any]]
    console_logs: List[str]
    network_requests: List[Dict[str, Any]]
    dom_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    screenshot_path: Optional[str] = None


class BrowserAutomation:
    """
    Playwright-based browser automation.
    
    Features:
    - Headless browser control
    - DOM XSS detection
    - JavaScript extraction
    - Request interception
    - Screenshot capture
    """
    
    def __init__(self):
        self.config = get_config()
        self._playwright = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        
        self.headless = self.config.execution.browser_headless
        self.timeout = self.config.execution.browser_timeout
        
        # Storage paths
        self.screenshots_dir = Path(self.config.data.chromadb_path).parent / "screenshots"
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
    
    async def start(self) -> bool:
        """Start the browser."""
        if not PLAYWRIGHT_AVAILABLE:
            logger.error("❌ Playwright not available")
            return False
        
        try:
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=self.headless,
                args=[
                    '--disable-blink-features=AutomationControlled',
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                ]
            )
            self._context = await self._browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )
            
            logger.info("🌐 Browser started")
            return True
        except Exception as e:
            logger.error(f"❌ Failed to start browser: {e}")
            return False
    
    async def stop(self):
        """Stop the browser."""
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        logger.info("🌐 Browser stopped")
    
    async def navigate(self, url: str, wait_for: str = "networkidle") -> PageResult:
        """
        Navigate to URL and capture page data.
        
        Args:
            url: Target URL
            wait_for: Wait condition (networkidle, load, domcontentloaded)
        
        Returns:
            PageResult with all captured data
        """
        if not self._browser:
            await self.start()
        
        page = await self._context.new_page()
        
        console_logs = []
        network_requests = []
        
        # Capture console logs
        page.on('console', lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"))
        
        # Capture network requests
        page.on('request', lambda req: network_requests.append({
            'url': req.url,
            'method': req.method,
            'headers': dict(req.headers),
        }))
        
        try:
            response = await page.goto(url, wait_until=wait_for, timeout=self.timeout)
            
            result = PageResult(
                url=page.url,
                title=await page.title(),
                status_code=response.status if response else 0,
                content=await page.content(),
                headers=dict(response.headers) if response else {},
                cookies=await self._context.cookies(),
                console_logs=console_logs,
                network_requests=network_requests,
            )
            
            # Take screenshot
            screenshot_path = self.screenshots_dir / f"{hash(url) % 100000}.png"
            await page.screenshot(path=str(screenshot_path), full_page=True)
            result.screenshot_path = str(screenshot_path)
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Navigation error: {e}")
            return PageResult(
                url=url,
                title="Error",
                status_code=0,
                content=str(e),
                headers={},
                cookies=[],
                console_logs=console_logs,
                network_requests=network_requests,
            )
        finally:
            await page.close()
    
    async def test_dom_xss(self, url: str, payloads: List[str] = None) -> List[Dict[str, Any]]:
        """
        Test for DOM XSS vulnerabilities.
        
        Args:
            url: Target URL with parameter placeholder {PAYLOAD}
            payloads: XSS payloads to test
        
        Returns:
            List of successful XSS findings
        """
        if not self._browser:
            await self.start()
        
        payloads = payloads or [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            '<svg onload=alert(1)>',
            'javascript:alert(1)',
        ]
        
        findings = []
        
        for payload in payloads:
            test_url = url.replace("{PAYLOAD}", payload)
            
            page = await self._context.new_page()
            
            dialog_triggered = False
            
            async def handle_dialog(dialog):
                nonlocal dialog_triggered
                dialog_triggered = True
                await dialog.dismiss()
            
            page.on('dialog', handle_dialog)
            
            try:
                await page.goto(test_url, wait_until='networkidle', timeout=10000)
                await asyncio.sleep(0.5)  # Wait for JS execution
                
                if dialog_triggered:
                    findings.append({
                        'url': test_url,
                        'payload': payload,
                        'type': 'DOM XSS (alert triggered)',
                        'severity': 'high',
                    })
                    logger.info(f"🎯 DOM XSS found: {payload}")
                
                # Check for reflection in DOM
                content = await page.content()
                if payload in content:
                    findings.append({
                        'url': test_url,
                        'payload': payload,
                        'type': 'Reflected payload in DOM',
                        'severity': 'medium',
                    })
                    
            except Exception as e:
                logger.debug(f"XSS test error: {e}")
            finally:
                await page.close()
        
        return findings
    
    async def extract_javascript(self, url: str) -> Dict[str, Any]:
        """
        Extract and analyze JavaScript from page.
        
        Args:
            url: Target URL
        
        Returns:
            Extracted JS data (endpoints, secrets, etc.)
        """
        if not self._browser:
            await self.start()
        
        page = await self._context.new_page()
        
        js_files = []
        inline_js = []
        extracted_data = {
            'endpoints': [],
            'api_keys': [],
            'secrets': [],
            'comments': [],
        }
        
        # Capture JS requests
        async def capture_js(request):
            if request.resource_type == 'script':
                try:
                    response = await request.response()
                    if response:
                        body = await response.body()
                        js_files.append({
                            'url': request.url,
                            'content': body.decode('utf-8', errors='ignore')[:50000]
                        })
                except:
                    pass
        
        page.on('request', capture_js)
        
        try:
            await page.goto(url, wait_until='networkidle', timeout=self.timeout)
            
            # Extract inline scripts
            scripts = await page.query_selector_all('script')
            for script in scripts:
                content = await script.inner_text()
                if content.strip():
                    inline_js.append(content)
            
            # Analyze all JS
            all_js = '\n'.join(inline_js) + '\n'.join([f['content'] for f in js_files])
            
            # Extract endpoints
            import re
            
            # API endpoints
            endpoints = re.findall(r'["\']/(api|v1|v2|graphql)[^"\']*["\']', all_js)
            extracted_data['endpoints'] = list(set([e if isinstance(e, str) else e[0] for e in endpoints]))
            
            # API keys
            api_keys = re.findall(r'["\']([A-Za-z0-9_-]{20,})["\']', all_js)
            extracted_data['api_keys'] = api_keys[:10]  # Limit
            
            # URLs
            urls = re.findall(r'https?://[^\s"\'<>]+', all_js)
            extracted_data['urls'] = list(set(urls))[:50]
            
            return {
                'js_files_count': len(js_files),
                'inline_scripts_count': len(inline_js),
                'extracted': extracted_data,
            }
            
        except Exception as e:
            logger.error(f"❌ JS extraction error: {e}")
            return {'error': str(e)}
        finally:
            await page.close()
    
    async def crawl_spa(self, url: str, max_pages: int = 20) -> List[str]:
        """
        Crawl a Single Page Application.
        
        Args:
            url: Starting URL
            max_pages: Maximum pages to visit
        
        Returns:
            List of discovered URLs
        """
        if not self._browser:
            await self.start()
        
        discovered = set()
        to_visit = [url]
        visited = set()
        
        while to_visit and len(discovered) < max_pages:
            current_url = to_visit.pop(0)
            if current_url in visited:
                continue
            
            visited.add(current_url)
            page = await self._context.new_page()
            
            try:
                await page.goto(current_url, wait_until='networkidle', timeout=self.timeout)
                await asyncio.sleep(1)  # Wait for SPA routing
                
                # Get all links
                links = await page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('a[href]'))
                        .map(a => a.href)
                        .filter(href => href.startsWith(window.location.origin));
                }""")
                
                for link in links:
                    if link not in discovered:
                        discovered.add(link)
                        to_visit.append(link)
                
                # Get router links (Vue/React)
                router_links = await page.evaluate("""() => {
                    const links = [];
                    // Vue Router
                    document.querySelectorAll('[to], router-link').forEach(el => {
                        const to = el.getAttribute('to');
                        if (to) links.push(new URL(to, window.location.origin).href);
                    });
                    return links;
                }""")
                
                for link in router_links:
                    if link not in discovered:
                        discovered.add(link)
                        
            except Exception as e:
                logger.debug(f"Crawl error for {current_url}: {e}")
            finally:
                await page.close()
        
        return list(discovered)
    
    async def fill_form(self, url: str, fields: Dict[str, str]) -> PageResult:
        """
        Fill and submit a form.
        
        Args:
            url: Page URL
            fields: Field name -> value mapping
        
        Returns:
            PageResult after submission
        """
        if not self._browser:
            await self.start()
        
        page = await self._context.new_page()
        
        try:
            await page.goto(url, wait_until='networkidle', timeout=self.timeout)
            
            # Fill fields
            for field_name, value in fields.items():
                # Try different selectors
                for selector in [
                    f'input[name="{field_name}"]',
                    f'input[id="{field_name}"]',
                    f'textarea[name="{field_name}"]',
                    f'[data-testid="{field_name}"]',
                ]:
                    try:
                        await page.fill(selector, value)
                        break
                    except:
                        continue
            
            # Submit form
            submit_selectors = [
                'button[type="submit"]',
                'input[type="submit"]',
                'button:has-text("Submit")',
                'button:has-text("Login")',
            ]
            
            for selector in submit_selectors:
                try:
                    await page.click(selector)
                    break
                except:
                    continue
            
            await page.wait_for_load_state('networkidle')
            
            return PageResult(
                url=page.url,
                title=await page.title(),
                status_code=200,
                content=await page.content(),
                headers={},
                cookies=await self._context.cookies(),
                console_logs=[],
                network_requests=[],
            )
            
        except Exception as e:
            logger.error(f"❌ Form fill error: {e}")
            return PageResult(
                url=url,
                title="Error",
                status_code=0,
                content=str(e),
                headers={},
                cookies=[],
                console_logs=[],
                network_requests=[],
            )
        finally:
            await page.close()


# Singleton
_browser: Optional[BrowserAutomation] = None


async def get_browser() -> BrowserAutomation:
    """Get the global browser instance."""
    global _browser
    if _browser is None:
        _browser = BrowserAutomation()
    return _browser
