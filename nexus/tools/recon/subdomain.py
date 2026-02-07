"""
Nexus v2.0 - Subdomain Enumeration
==================================

Tools: subfinder, amass, assetfinder, crt.sh
"""

import asyncio
import logging
import re
from typing import Dict, Any, List, Set
from dataclasses import dataclass

from nexus.execution.e2b_sandbox import execute_in_sandbox

logger = logging.getLogger(__name__)


@dataclass
class SubdomainResult:
    """Result of subdomain enumeration."""
    domain: str
    subdomains: List[str]
    sources: Dict[str, List[str]]  # source -> subdomains from that source
    total_found: int
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "subdomains": self.subdomains,
            "sources": self.sources,
            "total_found": self.total_found,
        }


async def run_subfinder(domain: str, timeout: int = 300) -> List[str]:
    """Run subfinder for subdomain discovery."""
    result = await execute_in_sandbox({
        "tool": "subfinder",
        "args": {
            "d": domain,
            "silent": True,
            "all": True,
        }
    })
    
    if result.get("status") == "success":
        output = result.get("stdout", "")
        return [line.strip() for line in output.split("\n") if line.strip()]
    return []


async def run_crtsh(domain: str) -> List[str]:
    """Query crt.sh certificate transparency logs."""
    import aiohttp
    
    subdomains = set()
    
    try:
        async with aiohttp.ClientSession() as session:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            async with session.get(url, timeout=30) as response:
                if response.status == 200:
                    data = await response.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for sub in name.split("\n"):
                            sub = sub.strip().lower()
                            if sub.endswith(domain) and "*" not in sub:
                                subdomains.add(sub)
    except Exception as e:
        logger.debug(f"crt.sh error: {e}")
    
    return list(subdomains)


async def run_assetfinder(domain: str) -> List[str]:
    """Run assetfinder for subdomain discovery."""
    result = await execute_in_sandbox({
        "tool": "assetfinder",
        "args": {"domain": domain}
    })
    
    if result.get("status") == "success":
        output = result.get("stdout", "")
        return [line.strip() for line in output.split("\n") 
                if line.strip() and domain in line]
    return []


async def enumerate_subdomains(
    domain: str,
    use_passive: bool = True,
    use_active: bool = False,
    sources: List[str] = None
) -> SubdomainResult:
    """
    Comprehensive subdomain enumeration.
    
    Args:
        domain: Target domain
        use_passive: Use passive sources (crt.sh, etc.)
        use_active: Use active brute-forcing
        sources: Specific sources to use
    
    Returns:
        SubdomainResult with all found subdomains
    """
    logger.info(f"🔍 Enumerating subdomains for {domain}")
    
    all_subdomains: Set[str] = set()
    source_results: Dict[str, List[str]] = {}
    
    # Run enumeration sources in parallel
    tasks = []
    source_names = []
    
    if sources is None or "subfinder" in sources:
        tasks.append(run_subfinder(domain))
        source_names.append("subfinder")
    
    if use_passive and (sources is None or "crtsh" in sources):
        tasks.append(run_crtsh(domain))
        source_names.append("crtsh")
    
    if sources is None or "assetfinder" in sources:
        tasks.append(run_assetfinder(domain))
        source_names.append("assetfinder")
    
    # Execute all tasks
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for i, result in enumerate(results):
        source = source_names[i]
        if isinstance(result, Exception):
            logger.debug(f"{source} error: {result}")
            source_results[source] = []
        else:
            source_results[source] = result
            all_subdomains.update(result)
    
    # Clean and sort results
    clean_subdomains = sorted([
        s for s in all_subdomains 
        if s.endswith(f".{domain}") or s == domain
    ])
    
    logger.info(f"✅ Found {len(clean_subdomains)} subdomains for {domain}")
    
    return SubdomainResult(
        domain=domain,
        subdomains=clean_subdomains,
        sources=source_results,
        total_found=len(clean_subdomains),
    )


async def check_subdomain_takeover(subdomain: str) -> Dict[str, Any]:
    """Check if subdomain is vulnerable to takeover."""
    import aiohttp
    
    # Known takeover fingerprints
    fingerprints = {
        "github": "There isn't a GitHub Pages site here",
        "heroku": "No such app",
        "aws_s3": "NoSuchBucket",
        "azure": "404 Web Site not found",
        "shopify": "Sorry, this shop is currently unavailable",
        "tumblr": "There's nothing here",
        "wordpress": "Do you want to register",
        "ghost": "The thing you were looking for is no longer here",
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            for proto in ["https", "http"]:
                try:
                    async with session.get(
                        f"{proto}://{subdomain}",
                        timeout=10,
                        allow_redirects=True
                    ) as response:
                        body = await response.text()
                        
                        for service, fingerprint in fingerprints.items():
                            if fingerprint.lower() in body.lower():
                                return {
                                    "subdomain": subdomain,
                                    "vulnerable": True,
                                    "service": service,
                                    "severity": "high",
                                }
                except:
                    continue
    except Exception as e:
        logger.debug(f"Takeover check error for {subdomain}: {e}")
    
    return {"subdomain": subdomain, "vulnerable": False}
