"""
Nexus v2.0 - Wayback Machine Mining
===================================

Tools: gau, waybackurls, waymore
"""

import asyncio
import aiohttp
import logging
import re
from typing import Dict, Any, List, Set
from dataclasses import dataclass
from urllib.parse import urlparse

from nexus.execution.e2b_sandbox import execute_in_sandbox

logger = logging.getLogger(__name__)


@dataclass
class WaybackResult:
    """Result of wayback mining."""
    domain: str
    urls: List[str]
    parameters: List[str]
    interesting_files: List[str]
    js_files: List[str]
    api_endpoints: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "total_urls": len(self.urls),
            "parameters": self.parameters,
            "interesting_files": self.interesting_files,
            "js_files": self.js_files,
            "api_endpoints": self.api_endpoints,
        }


async def run_gau(domain: str, timeout: int = 300) -> List[str]:
    """
    Run gau (Get All URLs) for historical URL discovery.
    
    Args:
        domain: Target domain
        timeout: Timeout in seconds
    
    Returns:
        List of historical URLs
    """
    result = await execute_in_sandbox({
        "tool": "gau",
        "args": {
            "domain": domain,
            "subs": True,  # Include subdomains
        }
    })
    
    urls = []
    if result.get("status") == "success":
        output = result.get("stdout", "")
        urls = [line.strip() for line in output.split("\n") if line.strip()]
    return urls


async def run_waybackurls(domain: str) -> List[str]:
    """Run waybackurls for historical URL discovery."""
    result = await execute_in_sandbox({
        "tool": "waybackurls",
        "args": {"domain": domain}
    })
    
    urls = []
    if result.get("status") == "success":
        output = result.get("stdout", "")
        urls = [line.strip() for line in output.split("\n") if line.strip()]
    return urls


async def query_wayback_api(domain: str) -> List[str]:
    """Direct query to Wayback Machine CDX API."""
    urls = []
    
    try:
        async with aiohttp.ClientSession() as session:
            api_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&fl=original"
            
            async with session.get(api_url, timeout=60) as response:
                if response.status == 200:
                    data = await response.json()
                    # Skip header row
                    urls = [row[0] for row in data[1:] if row]
    except Exception as e:
        logger.debug(f"Wayback API error: {e}")
    
    return urls


async def mine_wayback(domain: str) -> WaybackResult:
    """
    Comprehensive wayback machine mining.
    
    Args:
        domain: Target domain
    
    Returns:
        WaybackResult with analyzed historical data
    """
    logger.info(f"⏳ Mining Wayback Machine for {domain}")
    
    all_urls: Set[str] = set()
    
    # Run multiple sources
    tasks = [
        run_gau(domain),
        run_waybackurls(domain),
        query_wayback_api(domain),
    ]
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for result in results:
        if isinstance(result, list):
            all_urls.update(result)
    
    # Analyze URLs
    parameters: Set[str] = set()
    interesting_files: List[str] = []
    js_files: List[str] = []
    api_endpoints: List[str] = []
    
    # Interesting file extensions
    interesting_extensions = [
        ".sql", ".bak", ".backup", ".old", ".conf", ".config",
        ".env", ".ini", ".log", ".db", ".sqlite", ".zip",
        ".tar", ".gz", ".xml", ".json", ".csv", ".xlsx",
        ".pdf", ".doc", ".docx", ".txt", ".key", ".pem", ".crt",
    ]
    
    for url in all_urls:
        parsed = urlparse(url)
        
        # Extract parameters
        if parsed.query:
            params = re.findall(r'([^&=]+)=', parsed.query)
            parameters.update(params)
        
        # Find interesting files
        path_lower = parsed.path.lower()
        for ext in interesting_extensions:
            if path_lower.endswith(ext):
                interesting_files.append(url)
                break
        
        # Find JavaScript files
        if path_lower.endswith(".js"):
            js_files.append(url)
        
        # Find API endpoints
        if any(p in parsed.path for p in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"]):
            api_endpoints.append(url)
    
    logger.info(f"✅ Found {len(all_urls)} historical URLs")
    
    return WaybackResult(
        domain=domain,
        urls=sorted(all_urls),
        parameters=sorted(parameters),
        interesting_files=interesting_files[:100],
        js_files=js_files[:100],
        api_endpoints=api_endpoints[:100],
    )


async def find_sensitive_files(domain: str) -> List[Dict[str, Any]]:
    """
    Find potentially sensitive files from wayback.
    
    Args:
        domain: Target domain
    
    Returns:
        List of sensitive file findings
    """
    result = await mine_wayback(domain)
    
    findings = []
    
    # Check if interesting files are still accessible
    import aiohttp
    
    async with aiohttp.ClientSession() as session:
        for url in result.interesting_files[:20]:
            try:
                async with session.head(url, timeout=10, allow_redirects=True) as response:
                    if response.status == 200:
                        findings.append({
                            "url": url,
                            "type": "sensitive_file",
                            "status": "accessible",
                            "severity": "medium",
                        })
            except:
                continue
    
    return findings


async def diff_endpoints(domain: str) -> Dict[str, Any]:
    """
    Find endpoints that existed in past but may be forgotten.
    
    Args:
        domain: Target domain
    
    Returns:
        Diff of historical vs current endpoints
    """
    # Get historical endpoints
    wayback = await mine_wayback(domain)
    historical = set(wayback.api_endpoints)
    
    # Get current endpoints (simplified - in production, crawl current site)
    # This would compare against current crawl results
    
    return {
        "historical_endpoints": len(historical),
        "potentially_forgotten": list(historical)[:50],
    }
