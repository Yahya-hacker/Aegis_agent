"""
Nexus v2.0 - Parameter Discovery
================================

Tools: arjun, paramspider, x8
"""

import asyncio
import logging
import re
from typing import Dict, Any, List, Set
from dataclasses import dataclass, field

from nexus.execution.e2b_sandbox import execute_in_sandbox

logger = logging.getLogger(__name__)


@dataclass
class Parameter:
    """A discovered parameter."""
    name: str
    location: str  # query, body, header, cookie
    reflected: bool = False
    value_type: str = ""  # string, int, bool, etc.
    sample_value: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location,
            "reflected": self.reflected,
            "value_type": self.value_type,
            "sample_value": self.sample_value,
        }


@dataclass
class ParamResult:
    """Result of parameter discovery."""
    url: str
    parameters: List[Parameter]
    hidden_params: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "parameters": [p.to_dict() for p in self.parameters],
            "hidden_params": self.hidden_params,
            "total_found": len(self.parameters),
        }


async def run_arjun(url: str, timeout: int = 300) -> List[str]:
    """
    Run arjun for parameter discovery.
    
    Args:
        url: Target URL
        timeout: Timeout in seconds
    
    Returns:
        List of discovered parameter names
    """
    result = await execute_in_sandbox({
        "tool": "arjun",
        "args": {
            "u": url,
            "oT": "-",  # Output to stdout
            "q": True,  # Quiet mode
        }
    })
    
    params = []
    if result.get("status") == "success":
        output = result.get("stdout", "")
        # Parse arjun output
        for line in output.split("\n"):
            if line.strip() and not line.startswith("["):
                params.append(line.strip())
    return params


async def run_paramspider(domain: str) -> List[str]:
    """
    Run paramspider to find URLs with parameters.
    
    Args:
        domain: Target domain
    
    Returns:
        List of URLs with parameters
    """
    result = await execute_in_sandbox({
        "tool": "paramspider",
        "args": {
            "d": domain,
            "s": True,  # Silent mode
        }
    })
    
    urls = []
    if result.get("status") == "success":
        output = result.get("stdout", "")
        for line in output.split("\n"):
            if "?" in line:
                urls.append(line.strip())
    return urls


async def discover_parameters(
    url: str,
    use_bruteforce: bool = True,
    wordlist: str = None
) -> ParamResult:
    """
    Discover parameters for a URL.
    
    Args:
        url: Target URL
        use_bruteforce: Use parameter brute-forcing
        wordlist: Custom wordlist
    
    Returns:
        ParamResult with discovered parameters
    """
    logger.info(f"🔍 Discovering parameters for {url}")
    
    discovered_params: List[Parameter] = []
    hidden_params: List[str] = []
    
    # Extract existing parameters from URL
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(url)
    existing_params = parse_qs(parsed.query)
    
    for name, values in existing_params.items():
        discovered_params.append(Parameter(
            name=name,
            location="query",
            sample_value=values[0] if values else "",
        ))
    
    # Run arjun for hidden parameter discovery
    if use_bruteforce:
        arjun_params = await run_arjun(url)
        for param in arjun_params:
            if param not in [p.name for p in discovered_params]:
                discovered_params.append(Parameter(
                    name=param,
                    location="query",
                ))
                hidden_params.append(param)
    
    logger.info(f"✅ Found {len(discovered_params)} parameters ({len(hidden_params)} hidden)")
    
    return ParamResult(
        url=url,
        parameters=discovered_params,
        hidden_params=hidden_params,
    )


async def find_reflected_params(url: str, params: List[str]) -> List[str]:
    """
    Find which parameters are reflected in responses.
    
    Args:
        url: Target URL
        params: Parameters to test
    
    Returns:
        List of reflected parameter names
    """
    import aiohttp
    
    reflected = []
    test_value = "nexus7357test"
    
    try:
        async with aiohttp.ClientSession() as session:
            for param in params:
                test_url = f"{url}{'&' if '?' in url else '?'}{param}={test_value}"
                
                try:
                    async with session.get(test_url, timeout=10) as response:
                        if response.status == 200:
                            body = await response.text()
                            if test_value in body:
                                reflected.append(param)
                                logger.debug(f"🎯 Reflected: {param}")
                except:
                    continue
    except Exception as e:
        logger.debug(f"Reflection test error: {e}")
    
    return reflected


# Common hidden parameter wordlist
COMMON_PARAMS = [
    "id", "page", "search", "query", "q", "s",
    "user", "username", "email", "password",
    "redirect", "url", "next", "return", "callback",
    "file", "path", "filename", "upload",
    "admin", "debug", "test", "token",
    "api_key", "apikey", "key", "secret",
    "action", "cmd", "command", "exec",
    "order", "sort", "limit", "offset",
    "lang", "language", "locale",
    "format", "type", "output", "view",
    "filter", "category", "tag", "status",
    "date", "from", "to", "start", "end",
    "size", "width", "height", "color",
    "name", "title", "description", "content",
    "comment", "message", "subject", "body",
]


async def quick_param_fuzz(url: str) -> List[str]:
    """Quick parameter fuzzing with common names."""
    import aiohttp
    
    found = []
    base_url = url.split("?")[0]
    
    try:
        async with aiohttp.ClientSession() as session:
            # Get baseline response
            async with session.get(base_url, timeout=10) as response:
                baseline_length = len(await response.text())
            
            # Test each parameter
            for param in COMMON_PARAMS:
                test_url = f"{base_url}?{param}=test123"
                
                try:
                    async with session.get(test_url, timeout=10) as response:
                        body = await response.text()
                        
                        # Check for significant change
                        if abs(len(body) - baseline_length) > 50:
                            found.append(param)
                        # Check for reflection
                        elif "test123" in body:
                            found.append(param)
                except:
                    continue
    except Exception as e:
        logger.debug(f"Quick fuzz error: {e}")
    
    return found
