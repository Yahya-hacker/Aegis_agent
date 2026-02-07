"""
Nexus v2.0 - Subfinder Wrapper
==============================

Wrapper for Subfinder running in Docker.
"""

from typing import List, Dict, Any
import json
import logging
from dataclasses import dataclass

from nexus.execution.container import get_container

logger = logging.getLogger(__name__)

async def run_subfinder(domain: str) -> List[str]:
    """Run subfinder to enumerate subdomains."""
    container = get_container()
    
    if not await container.check_tool_installed("subfinder"):
        await container.install_tool("subfinder")
        
    output_file = f"subfinder_{domain}.json"
    
    cmd = f"subfinder -d {domain} -silent -oJ -o {output_file}"
    
    logger.info(f"🌎 Running Subfinder: {cmd}")
    await container.execute_command(cmd)
    
    subdomains = []
    content = await container.read_file(output_file)
    if content:
        for line in content.splitlines():
            try:
                data = json.loads(line)
                subdomains.append(data.get("host"))
            except:
                pass
                
    return subdomains
