"""
Nexus v2.0 - Katana Wrapper
===========================

Wrapper for Katana (Web Crawler) running in Docker.
"""

from typing import List, Dict, Any, Optional
import json
import logging
from dataclasses import dataclass

from nexus.execution.container import get_container

logger = logging.getLogger(__name__)

@dataclass
class CrawlResult:
    command: str
    urls: List[str]
    forms: List[Dict[str, Any]]
    
    def to_dict(self):
        return {
            "command": self.command,
            "urls": self.urls,
            "forms": self.forms
        }

async def run_katana(
    url: str,
    depth: int = 3,
    javascript: bool = True,
    headless: bool = True
) -> CrawlResult:
    """
    Run Katana crawler against a URL.
    
    Args:
        url: Target URL
        depth: Crawl depth
        javascript: Enable JavaScript crawling
        headless: Use headless mode (requires chrome installed in container)
        
    Returns:
        Crawl result
    """
    container = get_container()
    
    if not await container.check_tool_installed("katana"):
        await container.install_tool("katana")
        
    # Note: Headless crawling needs a browser installed. 
    # The default katana install might not have it.
    # For now, we'll assume standard crawling or that user provides a capable image.
    
    output_file = f"katana_{url.replace('http', '').replace('://', '').replace('/', '_')}.jsonl"
    
    cmd = (
        f"katana -u {url} "
        f"-d {depth} "
        f"-jsonl -o {output_file} "
        "-jc" # JS crawling
    )
    
    if headless:
        cmd += " -headless"
        
    logger.info(f"🕷️ Running Katana: {cmd}")
    await container.execute_command(cmd, timeout=600)
    
    urls = []
    forms = []
    
    content = await container.read_file(output_file)
    if content:
        for line in content.splitlines():
            try:
                data = json.loads(line)
                endpoint = data.get("request", {}).get("endpoint")
                if endpoint:
                    urls.append(endpoint)
                    
                # Extract basic form info if available in response
                # Katana output might vary, capturing raw endpoints for now
            except:
                pass
                
    return CrawlResult(
        command=cmd,
        urls=list(set(urls)),
        forms=forms
    )
