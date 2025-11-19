# tools/cdp_hooks.py
# --- VERSION 7.5 - Deep Dive CDP Interceptor ---
"""
The "Deep Dive" CDP Interceptor - JavaScript Sink Detection

Uses Chrome DevTools Protocol (CDP) to hook JavaScript sinks and detect DOM XSS.
The agent injects a "Spy" script that reports whenever dangerous functions are
called with user input, enabling detection of invisible attack surfaces.
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from playwright.async_api import async_playwright, Page, Browser

logger = logging.getLogger(__name__)


# JavaScript hook payload that intercepts dangerous sinks
JS_HOOK_PAYLOAD = """
(function() {
    // Store original functions
    const aegisTraps = {
        originalEval: window.eval,
        originalSetTimeout: window.setTimeout,
        originalSetInterval: window.setInterval,
        originalFunction: window.Function,
        consoleLog: console.log.bind(console)
    };
    
    // Counter for tracking calls
    let trapCounter = 0;
    
    // Helper to log trap events
    function logTrap(type, args) {
        const trapId = ++trapCounter;
        const message = {
            type: 'AEGIS_TRAP',
            trapId: trapId,
            sink: type,
            payload: String(args[0]).substring(0, 200),
            timestamp: Date.now(),
            stack: new Error().stack
        };
        aegisTraps.consoleLog('[AEGIS_TRAP]', JSON.stringify(message));
        return message;
    }
    
    // Overwrite 'eval' to spy on arguments
    window.eval = function(code) {
        logTrap('eval', [code]);
        return aegisTraps.originalEval(code);
    };
    
    // Trap setTimeout
    window.setTimeout = function(code, delay) {
        if (typeof code === 'string') {
            logTrap('setTimeout', [code]);
        }
        return aegisTraps.originalSetTimeout.apply(this, arguments);
    };
    
    // Trap setInterval
    window.setInterval = function(code, delay) {
        if (typeof code === 'string') {
            logTrap('setInterval', [code]);
        }
        return aegisTraps.originalSetInterval.apply(this, arguments);
    };
    
    // Trap Function constructor
    window.Function = function() {
        const args = Array.prototype.slice.call(arguments);
        logTrap('Function', args);
        return aegisTraps.originalFunction.apply(this, arguments);
    };
    
    // Trap innerHTML modifications
    const elementProto = Element.prototype;
    const originalInnerHTMLDescriptor = Object.getOwnPropertyDescriptor(elementProto, 'innerHTML');
    
    Object.defineProperty(elementProto, 'innerHTML', {
        get: originalInnerHTMLDescriptor.get,
        set: function(html) {
            logTrap('innerHTML', [html]);
            return originalInnerHTMLDescriptor.set.call(this, html);
        }
    });
    
    // Trap outerHTML modifications
    const originalOuterHTMLDescriptor = Object.getOwnPropertyDescriptor(elementProto, 'outerHTML');
    
    Object.defineProperty(elementProto, 'outerHTML', {
        get: originalOuterHTMLDescriptor.get,
        set: function(html) {
            logTrap('outerHTML', [html]);
            return originalOuterHTMLDescriptor.set.call(this, html);
        }
    });
    
    // Trap document.write
    const originalDocumentWrite = document.write;
    document.write = function(html) {
        logTrap('document.write', [html]);
        return originalDocumentWrite.apply(this, arguments);
    };
    
    // Trap document.writeln
    const originalDocumentWriteln = document.writeln;
    document.writeln = function(html) {
        logTrap('document.writeln', [html]);
        return originalDocumentWriteln.apply(this, arguments);
    };
    
    // Trap location changes
    let locationChangeTrapped = false;
    try {
        const originalLocationDescriptor = Object.getOwnPropertyDescriptor(window, 'location');
        Object.defineProperty(window, 'location', {
            get: function() {
                return originalLocationDescriptor.get.call(this);
            },
            set: function(value) {
                logTrap('location', [value]);
                return originalLocationDescriptor.set.call(this, value);
            }
        });
        locationChangeTrapped = true;
    } catch (e) {
        // Some browsers don't allow redefining location
        aegisTraps.consoleLog('[AEGIS_TRAP] Could not trap location changes:', e.message);
    }
    
    // Trap postMessage
    const originalPostMessage = window.postMessage;
    window.postMessage = function(message, targetOrigin, transfer) {
        logTrap('postMessage', [message]);
        return originalPostMessage.apply(this, arguments);
    };
    
    // Monitor attribute changes that could lead to XSS
    const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(mutation) {
            if (mutation.type === 'attributes') {
                const attrName = mutation.attributeName;
                const element = mutation.target;
                const attrValue = element.getAttribute(attrName);
                
                // Check for dangerous attributes
                if (attrName && attrName.startsWith('on') && attrValue) {
                    logTrap('attribute:' + attrName, [attrValue]);
                }
                
                // Check for href/src with javascript:
                if ((attrName === 'href' || attrName === 'src') && 
                    attrValue && attrValue.toLowerCase().startsWith('javascript:')) {
                    logTrap('attribute:' + attrName, [attrValue]);
                }
            }
        });
    });
    
    // Start observing the document
    observer.observe(document.documentElement, {
        attributes: true,
        subtree: true,
        attributeFilter: ['href', 'src', 'onclick', 'onload', 'onerror', 'onmouseover']
    });
    
    aegisTraps.consoleLog('[AEGIS_TRAP] Hooks installed successfully. Monitoring dangerous sinks...');
})();
"""


class CDPHooks:
    """
    Chrome DevTools Protocol Hooks for detecting DOM-based vulnerabilities.
    
    This class provides functionality to:
    1. Inject JavaScript hooks into pages before they load
    2. Monitor console output for trap triggers
    3. Correlate trap triggers with payloads to confirm vulnerabilities
    """
    
    def __init__(self):
        """Initialize CDP hooks manager"""
        self.trapped_events: List[Dict[str, Any]] = []
        self.browser: Optional[Browser] = None
        self.playwright = None
        
    async def initialize(self, headless: bool = True) -> None:
        """
        Initialize Playwright browser with CDP support.
        
        Args:
            headless: Whether to run browser in headless mode
        """
        if self.playwright is None:
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(
                headless=headless,
                args=['--disable-blink-features=AutomationControlled']
            )
            logger.info("[CDP] Browser initialized with hooks support")
    
    async def close(self) -> None:
        """Close the browser and cleanup"""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
        logger.info("[CDP] Browser closed")
    
    async def inject_hooks(self, page: Page) -> None:
        """
        Injects the Spy script before the page loads.
        
        Args:
            page: Playwright page object
        """
        # Set up console message listener
        page.on("console", self._handle_console_message)
        
        # Inject hooks before page navigation
        await page.add_init_script(JS_HOOK_PAYLOAD)
        
        logger.info("[CDP] JavaScript hooks injected into page")
    
    def _handle_console_message(self, msg) -> None:
        """
        Handle console messages from the page.
        Filters for AEGIS_TRAP markers.
        
        Args:
            msg: Console message object
        """
        text = msg.text
        
        if '[AEGIS_TRAP]' in text:
            # Extract the trap data
            try:
                # Remove the [AEGIS_TRAP] prefix
                json_start = text.find('{')
                if json_start != -1:
                    import json
                    trap_data = json.loads(text[json_start:])
                    self.trapped_events.append(trap_data)
                    
                    logger.warning(
                        f"[!] DOM SINK TRIGGERED: {trap_data['sink']} "
                        f"with payload: {trap_data['payload'][:50]}..."
                    )
                else:
                    # Just a log message
                    logger.info(f"[CDP] {text}")
            except Exception as e:
                logger.debug(f"[CDP] Console message: {text}")
    
    async def monitor_page(
        self, 
        url: str, 
        payloads: List[str] = None,
        interaction_script: str = None,
        timeout: int = 30000
    ) -> Dict[str, Any]:
        """
        Monitor a page for DOM-based vulnerabilities.
        
        Args:
            url: URL to monitor
            payloads: List of XSS payloads to test
            interaction_script: Optional JavaScript to execute for interaction
            timeout: Page load timeout in milliseconds
        
        Returns:
            Dictionary with monitoring results
        """
        if not self.browser:
            await self.initialize()
        
        self.trapped_events = []  # Reset events
        
        context = await self.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )
        
        page = await context.new_page()
        
        try:
            # Inject hooks before navigation
            await self.inject_hooks(page)
            
            # Navigate to the page
            logger.info(f"[CDP] Navigating to {url}")
            await page.goto(url, timeout=timeout, wait_until='networkidle')
            
            # Wait a moment for any dynamic content
            await page.wait_for_timeout(2000)
            
            # If payloads provided, inject them into inputs
            if payloads:
                await self._inject_payloads(page, payloads)
            
            # Execute custom interaction script if provided
            if interaction_script:
                await page.evaluate(interaction_script)
                await page.wait_for_timeout(1000)
            
            # Wait a bit more for any delayed events
            await page.wait_for_timeout(2000)
            
            # Capture final state
            screenshot = await page.screenshot(full_page=True)
            
            results = {
                "url": url,
                "trapped_events": self.trapped_events,
                "total_traps": len(self.trapped_events),
                "vulnerable": len(self.trapped_events) > 0,
                "screenshot_size": len(screenshot),
                "summary": self._generate_summary()
            }
            
            return results
            
        except Exception as e:
            logger.error(f"[CDP] Error monitoring page: {e}")
            return {
                "url": url,
                "error": str(e),
                "trapped_events": self.trapped_events,
                "total_traps": len(self.trapped_events)
            }
        finally:
            await context.close()
    
    async def _inject_payloads(self, page: Page, payloads: List[str]) -> None:
        """
        Inject XSS payloads into all input fields on the page.
        
        Args:
            page: Playwright page object
            payloads: List of payloads to inject
        """
        try:
            # Find all input fields
            inputs = await page.query_selector_all('input[type="text"], input[type="search"], textarea')
            
            logger.info(f"[CDP] Found {len(inputs)} input fields, injecting {len(payloads)} payloads")
            
            for input_elem in inputs:
                for payload in payloads[:3]:  # Limit to 3 payloads per field
                    try:
                        await input_elem.fill(payload)
                        await input_elem.press('Enter')
                        await page.wait_for_timeout(500)
                    except Exception as e:
                        logger.debug(f"[CDP] Could not inject payload into input: {e}")
            
            # Also try URL parameters
            for payload in payloads[:3]:
                try:
                    current_url = page.url
                    if '?' in current_url:
                        test_url = f"{current_url}&xss={payload}"
                    else:
                        test_url = f"{current_url}?xss={payload}"
                    
                    await page.goto(test_url, wait_until='networkidle', timeout=5000)
                    await page.wait_for_timeout(1000)
                except Exception as e:
                    logger.debug(f"[CDP] Could not test URL parameter: {e}")
                    
        except Exception as e:
            logger.warning(f"[CDP] Error injecting payloads: {e}")
    
    def _generate_summary(self) -> str:
        """Generate a human-readable summary of trap events"""
        if not self.trapped_events:
            return "No dangerous sinks were triggered."
        
        sink_counts = {}
        for event in self.trapped_events:
            sink = event.get('sink', 'unknown')
            sink_counts[sink] = sink_counts.get(sink, 0) + 1
        
        summary = f"Detected {len(self.trapped_events)} dangerous sink calls:\n"
        for sink, count in sorted(sink_counts.items(), key=lambda x: x[1], reverse=True):
            summary += f"  - {sink}: {count} calls\n"
        
        return summary
    
    def get_trapped_events(self) -> List[Dict[str, Any]]:
        """
        Get all trapped events.
        
        Returns:
            List of trap event dictionaries
        """
        return self.trapped_events
    
    def check_payload_execution(self, payload: str) -> bool:
        """
        Check if a specific payload triggered any traps.
        
        Args:
            payload: Payload to check for
        
        Returns:
            True if payload was found in trap events
        """
        for event in self.trapped_events:
            if payload in event.get('payload', ''):
                return True
        return False
    
    async def test_dom_xss(
        self,
        url: str,
        test_payloads: List[str] = None
    ) -> Dict[str, Any]:
        """
        Automated DOM XSS testing.
        
        Args:
            url: Target URL
            test_payloads: Custom payloads (uses defaults if not provided)
        
        Returns:
            Dictionary with test results
        """
        if test_payloads is None:
            test_payloads = [
                "<img src=x onerror=alert('AEGIS_XSS')>",
                "<script>alert('AEGIS_XSS')</script>",
                "javascript:alert('AEGIS_XSS')",
                "';alert('AEGIS_XSS');//",
                "\"><script>alert('AEGIS_XSS')</script>",
            ]
        
        logger.info(f"[CDP] Starting DOM XSS test for {url}")
        
        results = await self.monitor_page(url, payloads=test_payloads)
        
        # Analyze if any of our test payloads triggered traps
        confirmed_vulns = []
        for payload in test_payloads:
            if self.check_payload_execution(payload):
                confirmed_vulns.append({
                    "payload": payload,
                    "confirmed": True,
                    "severity": "HIGH"
                })
        
        results["confirmed_vulnerabilities"] = confirmed_vulns
        results["vulnerability_count"] = len(confirmed_vulns)
        
        return results


# Singleton instance
_cdp_hooks_instance = None

def get_cdp_hooks() -> CDPHooks:
    """Get or create the singleton CDP hooks instance"""
    global _cdp_hooks_instance
    if _cdp_hooks_instance is None:
        _cdp_hooks_instance = CDPHooks()
    return _cdp_hooks_instance


async def inject_hooks(page: Page) -> None:
    """
    Convenience function to inject hooks into a Playwright page.
    
    Args:
        page: Playwright page object
    
    Example:
        from playwright.async_api import async_playwright
        
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()
            await inject_hooks(page)
            await page.goto("https://example.com")
    """
    hooks = get_cdp_hooks()
    await hooks.inject_hooks(page)
