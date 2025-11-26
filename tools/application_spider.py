"""
Application Spider Tool for Aegis AI.

Cognitive web application crawler with 3 levels of depth for discovering
API endpoints, routes, forms, and application logic.

Levels:
    1. Fast (HTML parsing) - Parse HTML for links and forms
    2. Static JS (JavaScript analysis) - Download and analyze JS files for API routes
    3. Deep Visual (AI-powered) - Use visual reconnaissance and AI analysis

Features:
    - Authenticated crawling with session cookies
    - JavaScript API endpoint extraction
    - AI-powered minified JS de-obfuscation
    - Visual element discovery with multimodal LLM
"""

import asyncio
import httpx
import json
import re
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


class ApplicationSpiderTool:
    """
    Multi-level application spider for discovering API endpoints, routes, and logic.
    
    This tool provides three levels of crawling depth:
        - Fast: HTML parsing for links and forms (fastest, good for initial recon)
        - Static JS: JavaScript analysis for API routes (medium, finds hidden endpoints)
        - Deep Visual: AI-powered screenshot analysis (slowest, best coverage)
    
    Attributes:
        orchestrator: MultiLLMOrchestrator instance for AI-powered analysis.
        timeout: Default request timeout in seconds.
        max_redirects: Maximum number of redirects to follow.
        discovered_map: Dictionary storing discovered URLs, forms, APIs, JS files.
    """
    
    def __init__(self, orchestrator=None):
        """
        Initialize the application spider.
        
        Args:
            orchestrator: Optional MultiLLMOrchestrator instance for AI-powered analysis.
        """
        self.orchestrator = orchestrator
        self.timeout = 30.0
        self.max_redirects = 5
        self.discovered_map: Dict[str, Any] = {
            "urls": set(),
            "forms": [],
            "api_endpoints": set(),
            "js_files": set(),
            "interesting_patterns": []
        }
        logger.info("🕷️ ApplicationSpiderTool initialized")
    
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
    
    def _build_headers(self, additional_headers: Optional[Dict] = None) -> Dict[str, str]:
        """
        Build HTTP headers including session cookies
        
        Args:
            additional_headers: Optional additional headers to include
            
        Returns:
            Dictionary of headers
        """
        headers = {
            "User-Agent": "Aegis-AI/7.0 Application Spider",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        
        # Load and inject session cookies
        session_data = self._load_session_data()
        if session_data:
            cookie_header = self._build_cookie_header(session_data)
            if cookie_header:
                headers["Cookie"] = cookie_header
                logger.info("🔐 Session cookies loaded for authenticated spider")
        
        # Add any additional headers
        if additional_headers:
            headers.update(additional_headers)
        
        return headers
    
    async def crawl_and_map_application(
        self,
        base_url: str,
        mode: str = "fast"
    ) -> Dict[str, Any]:
        """
        Crawl and map an application using the specified mode
        
        Args:
            base_url: Base URL of the application to crawl
            mode: Crawling mode - "fast", "static_js", or "deep_visual"
            
        Returns:
            Dictionary with discovered application map
        """
        logger.info(f"🕷️ Starting application spider in '{mode}' mode for {base_url}")
        
        # Reset discovered map
        self.discovered_map = {
            "urls": set(),
            "forms": [],
            "api_endpoints": set(),
            "js_files": set(),
            "interesting_patterns": []
        }
        
        try:
            if mode == "fast":
                await self._crawl_fast(base_url)
            elif mode == "static_js":
                await self._crawl_static_js(base_url)
            elif mode == "deep_visual":
                await self._crawl_deep_visual(base_url)
            else:
                raise ValueError(f"Unknown mode: {mode}. Use 'fast', 'static_js', or 'deep_visual'")
            
            # Save discovered map to file
            self._save_discovered_map()
            
            # Convert sets to lists for JSON serialization
            result = {
                "base_url": base_url,
                "mode": mode,
                "urls": list(self.discovered_map["urls"]),
                "forms": self.discovered_map["forms"],
                "api_endpoints": list(self.discovered_map["api_endpoints"]),
                "js_files": list(self.discovered_map["js_files"]),
                "interesting_patterns": self.discovered_map["interesting_patterns"],
                "total_urls": len(self.discovered_map["urls"]),
                "total_forms": len(self.discovered_map["forms"]),
                "total_api_endpoints": len(self.discovered_map["api_endpoints"]),
                "total_js_files": len(self.discovered_map["js_files"])
            }
            
            logger.info(f"✅ Spider complete: {result['total_urls']} URLs, "
                       f"{result['total_forms']} forms, "
                       f"{result['total_api_endpoints']} API endpoints")
            
            return result
            
        except Exception as e:
            logger.error(f"Error in spider: {e}", exc_info=True)
            return {
                "error": str(e),
                "base_url": base_url,
                "mode": mode
            }
    
    async def _crawl_fast(self, base_url: str) -> None:
        """
        Level 1: Fast HTML parsing for links and forms
        
        Args:
            base_url: Base URL to crawl
        """
        logger.info("📄 Level 1: Fast HTML parsing")
        
        visited = set()
        to_visit = {base_url}
        max_pages = 50  # Limit for fast mode
        
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            max_redirects=self.max_redirects
        ) as client:
            
            while to_visit and len(visited) < max_pages:
                url = to_visit.pop()
                
                if url in visited:
                    continue
                
                visited.add(url)
                logger.info(f"  Crawling: {url}")
                
                try:
                    headers = self._build_headers()
                    response = await client.get(url, headers=headers)
                    
                    if response.status_code != 200:
                        continue
                    
                    # Parse HTML
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Extract links
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        absolute_url = urljoin(url, href)
                        
                        # Only follow links on same domain
                        if self._is_same_domain(base_url, absolute_url):
                            self.discovered_map["urls"].add(absolute_url)
                            to_visit.add(absolute_url)
                    
                    # Extract forms
                    for form in soup.find_all('form'):
                        form_data = {
                            "action": urljoin(url, form.get('action', '')),
                            "method": form.get('method', 'GET').upper(),
                            "inputs": []
                        }
                        
                        for input_field in form.find_all(['input', 'textarea', 'select']):
                            form_data["inputs"].append({
                                "name": input_field.get('name', ''),
                                "type": input_field.get('type', 'text'),
                                "required": input_field.has_attr('required')
                            })
                        
                        self.discovered_map["forms"].append(form_data)
                    
                    # Extract script tags with src
                    for script in soup.find_all('script', src=True):
                        js_url = urljoin(url, script['src'])
                        self.discovered_map["js_files"].add(js_url)
                    
                except Exception as e:
                    logger.debug(f"Error crawling {url}: {e}")
                    continue
    
    async def _crawl_static_js(self, base_url: str) -> None:
        """
        Level 2: Download and analyze JavaScript files for API routes
        
        Args:
            base_url: Base URL to crawl
        """
        logger.info("📦 Level 2: Static JavaScript analysis")
        
        # First, do a fast crawl to find JS files
        await self._crawl_fast(base_url)
        
        logger.info(f"  Found {len(self.discovered_map['js_files'])} JavaScript files")
        
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True
        ) as client:
            
            for js_url in list(self.discovered_map["js_files"]):
                try:
                    logger.info(f"  Analyzing: {js_url}")
                    headers = self._build_headers()
                    response = await client.get(js_url, headers=headers)
                    
                    if response.status_code != 200:
                        continue
                    
                    js_code = response.text
                    
                    # Extract API endpoints using regex patterns
                    api_patterns = [
                        r'["\']/(api/[^"\']+)["\']',  # /api/...
                        r'["\']/(v\d+/[^"\']+)["\']',  # /v1/...
                        r'fetch\(["\']([^"\']+)["\']',  # fetch('...')
                        r'axios\.[a-z]+\(["\']([^"\']+)["\']',  # axios.get/post('...')
                        r'\.get\(["\']([^"\']+)["\']',  # .get('...')
                        r'\.post\(["\']([^"\']+)["\']',  # .post('...')
                        r'url:\s*["\']([^"\']+)["\']',  # url: '...'
                    ]
                    
                    for pattern in api_patterns:
                        matches = re.findall(pattern, js_code)
                        for match in matches:
                            # Construct full URL
                            if match.startswith('http'):
                                endpoint = match
                            else:
                                endpoint = urljoin(base_url, match)
                            
                            self.discovered_map["api_endpoints"].add(endpoint)
                    
                    # Use AI to de-minify and extract APIs if code appears minified
                    if self._is_minified(js_code) and self.orchestrator:
                        await self._ai_analyze_js(js_code, js_url)
                    
                except Exception as e:
                    logger.debug(f"Error analyzing JS {js_url}: {e}")
                    continue
        
        logger.info(f"  Discovered {len(self.discovered_map['api_endpoints'])} API endpoints")
    
    async def _crawl_deep_visual(self, base_url: str) -> None:
        """
        Level 3: Use visual reconnaissance and AI to find interactive elements
        
        Args:
            base_url: Base URL to crawl
        """
        logger.info("👁️ Level 3: Deep visual analysis with AI")
        
        # First, do static JS crawl
        await self._crawl_static_js(base_url)
        
        # Now use visual recon for screenshot analysis
        try:
            from tools.visual_recon import VisualReconTool
            
            visual_tool = VisualReconTool()
            
            # Capture screenshot of main page
            logger.info(f"  Capturing screenshot of {base_url}")
            screenshot_path = await visual_tool.capture_screenshot(
                url=base_url,
                full_page=True
            )
            
            if screenshot_path and self.orchestrator:
                # Use AI to analyze the screenshot
                logger.info("  Analyzing screenshot with AI...")
                analysis_prompt = """Analyze this web application screenshot and identify:
1. All interactive elements (buttons, links, forms, inputs)
2. Navigation menus and their structure
3. Hidden or dynamically loaded content areas
4. API endpoints or AJAX calls that might be triggered
5. Interesting security-relevant features (login forms, file uploads, admin panels)

Provide a structured analysis in JSON format."""
                
                result = await self.orchestrator.execute_multimodal_task(
                    text_prompt=analysis_prompt,
                    image_path=screenshot_path
                )
                
                if 'content' in result:
                    # Store AI analysis
                    self.discovered_map["interesting_patterns"].append({
                        "type": "visual_ai_analysis",
                        "url": base_url,
                        "analysis": result['content']
                    })
            
            # Clean up visual tool
            await visual_tool.cleanup()
            
        except Exception as e:
            logger.error(f"Error in visual analysis: {e}", exc_info=True)
    
    def _is_same_domain(self, base_url: str, url: str) -> bool:
        """Check if URL is on the same domain as base_url"""
        base_domain = urlparse(base_url).netloc
        url_domain = urlparse(url).netloc
        return base_domain == url_domain
    
    def _is_minified(self, js_code: str) -> bool:
        """Detect if JavaScript code is minified"""
        # Simple heuristics for minification detection
        lines = js_code.split('\n')
        if len(lines) < 10:
            return False
        
        # Check average line length (minified code has very long lines)
        avg_line_length = sum(len(line) for line in lines) / len(lines)
        
        # Check for lack of whitespace
        whitespace_ratio = js_code.count(' ') / max(len(js_code), 1)
        
        return avg_line_length > 500 or whitespace_ratio < 0.05
    
    async def _ai_analyze_js(self, js_code: str, js_url: str) -> None:
        """
        Use AI (CODER_MODEL) to analyze minified JavaScript
        
        Args:
            js_code: JavaScript code to analyze
            js_url: URL of the JavaScript file
        """
        if not self.orchestrator:
            return
        
        logger.info(f"  Using AI to analyze minified JavaScript: {js_url}")
        
        try:
            # Truncate very large files
            max_code_length = 10000
            if len(js_code) > max_code_length:
                js_code = js_code[:max_code_length] + "\n... (truncated)"
            
            prompt = f"""Analyze this JavaScript code (possibly minified) and extract:
1. All API endpoint URLs (REST, GraphQL, etc.)
2. WebSocket connections
3. Authentication/authorization endpoints
4. Interesting function names or patterns

JavaScript code:
```javascript
{js_code}
```

Provide a structured list of findings in JSON format."""
            
            response = await self.orchestrator.execute_task(
                task_type='code_analysis',
                system_prompt="You are an expert JavaScript analyst specializing in API discovery.",
                user_message=prompt,
                temperature=0.6,
                max_tokens=1024
            )
            
            content = response.get('content', '')
            
            # Try to extract URLs from the AI response
            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
            urls = re.findall(url_pattern, content)
            for url in urls:
                self.discovered_map["api_endpoints"].add(url)
            
            # Store the full analysis
            self.discovered_map["interesting_patterns"].append({
                "type": "ai_js_analysis",
                "file": js_url,
                "analysis": content
            })
            
        except Exception as e:
            logger.error(f"Error in AI JS analysis: {e}", exc_info=True)
    
    def _save_discovered_map(self) -> None:
        """Save the discovered application map to data/discovered_logic_map.json"""
        try:
            output_file = Path("data/discovered_logic_map.json")
            output_file.parent.mkdir(exist_ok=True, parents=True)
            
            # Convert sets to lists for JSON serialization
            serializable_map = {
                "urls": list(self.discovered_map["urls"]),
                "forms": self.discovered_map["forms"],
                "api_endpoints": list(self.discovered_map["api_endpoints"]),
                "js_files": list(self.discovered_map["js_files"]),
                "interesting_patterns": self.discovered_map["interesting_patterns"]
            }
            
            with open(output_file, 'w') as f:
                json.dump(serializable_map, f, indent=2)
            
            logger.info(f"💾 Discovered map saved to {output_file}")
            
        except Exception as e:
            logger.error(f"Error saving discovered map: {e}", exc_info=True)


# Singleton instance
_spider_instance = None


def get_application_spider(orchestrator=None) -> ApplicationSpiderTool:
    """Get singleton application spider instance"""
    global _spider_instance
    if _spider_instance is None:
        _spider_instance = ApplicationSpiderTool(orchestrator)
    return _spider_instance
