"""
Nexus v2.0 - Web Crawler
========================

Tools: katana, gospider, hakrawler
"""

import asyncio
import logging
import re
from typing import Dict, Any, List, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin

from nexus.execution.e2b_sandbox import execute_in_sandbox

logger = logging.getLogger(__name__)


@dataclass
class CrawlResult:
    """Result of web crawling."""
    base_url: str
    urls: List[str]
    forms: List[Dict[str, Any]]
    js_files: List[str]
    api_endpoints: List[str]
    parameters: Dict[str, List[str]]  # endpoint -> parameters
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_url": self.base_url,
            "urls": self.urls,
            "forms": self.forms,
            "js_files": self.js_files,
            "api_endpoints": self.api_endpoints,
            "parameters": self.parameters,
            "total_urls": len(self.urls),
        }


async def run_katana(
    url: str,
    depth: int = 3,
    timeout: int = 300
) -> List[str]:
    """
    Run katana web crawler.
    
    Args:
        url: Starting URL
        depth: Crawl depth
        timeout: Timeout in seconds
    
    Returns:
        List of discovered URLs
    """
    result = await execute_in_sandbox({
        "tool": "katana",
        "args": {
            "u": url,
            "d": str(depth),
            "silent": True,
            "jc": True,  # JavaScript crawl
        }
    })
    
    if result.get("status") == "success":
        output = result.get("stdout", "")
        return [line.strip() for line in output.split("\n") if line.strip()]
    return []


async def run_gospider(url: str, depth: int = 2) -> List[str]:
    """Run gospider for web crawling."""
    result = await execute_in_sandbox({
        "tool": "gospider",
        "args": {
            "s": url,
            "d": str(depth),
            "c": "10",  # Concurrency
            "q": True,  # Quiet mode
        }
    })
    
    urls = []
    if result.get("status") == "success":
        output = result.get("stdout", "")
        # Parse gospider output format: [source] - url
        for line in output.split("\n"):
            match = re.search(r'\[.*?\]\s*-\s*(.+)', line)
            if match:
                urls.append(match.group(1).strip())
    return urls


async def crawl_website(
    url: str,
    depth: int = 3,
    extract_forms: bool = True,
    extract_js: bool = True
) -> CrawlResult:
    """
    Comprehensive website crawling.
    
    Args:
        url: Starting URL
        depth: Crawl depth
        extract_forms: Extract form data
        extract_js: Extract JavaScript files
    
    Returns:
        CrawlResult with all discovered data
    """
    logger.info(f"🕷️ Crawling {url}")
    
    all_urls: Set[str] = set()
    forms: List[Dict[str, Any]] = []
    js_files: Set[str] = set()
    api_endpoints: Set[str] = set()
    parameters: Dict[str, List[str]] = {}
    
    # Run multiple crawlers
    tasks = [
        run_katana(url, depth),
        run_gospider(url, depth),
    ]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for result in results:
        if isinstance(result, list):
            all_urls.update(result)
    
    # Parse URLs for additional info
    base_domain = urlparse(url).netloc
    
    for discovered_url in all_urls:
        parsed = urlparse(discovered_url)
        
        # Filter to same domain
        if base_domain not in parsed.netloc:
            continue
        
        # Extract JavaScript files
        if parsed.path.endswith(".js"):
            js_files.add(discovered_url)
        
        # Extract API endpoints
        if any(p in parsed.path for p in ["/api/", "/v1/", "/v2/", "/graphql"]):
            api_endpoints.add(discovered_url)
        
        # Extract parameters
        if parsed.query:
            params = re.findall(r'([^&=]+)=', parsed.query)
            endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if endpoint not in parameters:
                parameters[endpoint] = []
            parameters[endpoint].extend(p for p in params if p not in parameters[endpoint])
    
    # Sort results
    sorted_urls = sorted(all_urls)
    sorted_js = sorted(js_files)
    sorted_api = sorted(api_endpoints)
    
    logger.info(f"✅ Found {len(sorted_urls)} URLs, {len(sorted_api)} API endpoints")
    
    return CrawlResult(
        base_url=url,
        urls=sorted_urls,
        forms=forms,
        js_files=sorted_js,
        api_endpoints=sorted_api,
        parameters=parameters,
    )


async def extract_endpoints_from_js(js_url: str) -> List[str]:
    """Extract API endpoints from JavaScript file."""
    import aiohttp
    
    endpoints = []
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(js_url, timeout=30) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Find API paths
                    patterns = [
                        r'["\']/(api|v1|v2|graphql)[^"\']*["\']',
                        r'fetch\(["\']([^"\']+)["\']',
                        r'axios\.[a-z]+\(["\']([^"\']+)["\']',
                        r'url:\s*["\']([^"\']+)["\']',
                    ]
                    
                    for pattern in patterns:
                        matches = re.findall(pattern, content)
                        endpoints.extend(matches)
    except Exception as e:
        logger.debug(f"JS extraction error: {e}")
    
    return list(set(endpoints))


async def deep_crawl(
    url: str,
    max_urls: int = 1000,
    follow_js: bool = True
) -> CrawlResult:
    """
    Deep crawl with JavaScript analysis.
    
    Args:
        url: Starting URL
        max_urls: Maximum URLs to discover
        follow_js: Analyze JavaScript files
    
    Returns:
        CrawlResult with comprehensive data
    """
    # Initial crawl
    result = await crawl_website(url, depth=4)
    
    # Analyze JavaScript files if enabled
    if follow_js and result.js_files:
        js_endpoints = []
        for js_url in result.js_files[:20]:  # Limit JS files
            endpoints = await extract_endpoints_from_js(js_url)
            js_endpoints.extend(endpoints)
        
        # Add JS-discovered endpoints
        base = urlparse(url)
        for endpoint in js_endpoints:
            if endpoint.startswith("/"):
                full_url = f"{base.scheme}://{base.netloc}{endpoint}"
                result.api_endpoints.append(full_url)
    
    return result
