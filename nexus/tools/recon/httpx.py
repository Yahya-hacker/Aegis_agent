"""
Nexus v2.0 - HTTPX Wrapper
==========================

Wrapper for HTTPX (Project Discovery) running in Docker.
"""

from typing import List, Dict, Any
import json
import logging
from dataclasses import dataclass

from nexus.execution.container import get_container

logger = logging.getLogger(__name__)

async def run_httpx(domains: List[str]) -> List[Dict[str, Any]]:
    """Run httpx against a list of domains."""
    container = get_container()
    
    if not await container.check_tool_installed("httpx"):
        await container.install_tool("httpx")
        
    # Write targets to file
    input_file = "httpx_targets.txt"
    container.write_file(input_file, "\n".join(domains))
    
    output_file = "httpx_results.json"
    
    cmd = f"httpx -l {input_file} -json -o {output_file} -status-code -tech-detect -title"
    
    logger.info(f"🕸️ Running HTTPX: {cmd}")
    await container.execute_command(cmd)
    
    results = []
    content = await container.read_file(output_file)
    if content:
        for line in content.splitlines():
            try:
                results.append(json.loads(line))
            except:
                pass
                
    return results
