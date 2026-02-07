"""
Nexus v2.0 - FFUF Wrapper
=========================

Wrapper for FFUF (Fuzz Faster U Fool) running in Docker.
"""

from typing import List, Dict, Any, Optional
import json
import logging
from dataclasses import dataclass
from pathlib import Path

from nexus.execution.container import get_container
from nexus.config import get_config

logger = logging.getLogger(__name__)

@dataclass
class FfufResult:
    command: str
    findings: List[Dict[str, Any]]
    
    def to_dict(self):
        return {
            "command": self.command,
            "findings": self.findings
        }

async def run_ffuf(
    url: str,
    wordlist: str = "common.txt", # relative to wordlist dir or container path
    mode: str = "directory", # directory, param, vhost
    extensions: str = None,
    recursive: bool = False
) -> FfufResult:
    """
    Run FFUF against a target.
    
    Args:
        url: Target URL containing FUZZ keyword (or auto-appended)
        wordlist: Name of wordlist
        mode: Scan mode
        extensions: Extensions to append (e.g. .php,.html)
        recursive: Recursive scanning
        
    Returns:
        Fuzzing results
    """
    container = get_container()
    config = get_config()
    
    if not await container.check_tool_installed("ffuf"):
        await container.install_tool("ffuf")
    
    # Locate wordlist
    # In a real scenario, we'd mount a wordlist volume.
    # For now, we might need to wget one if missing, or use default Kali paths.
    wordlist_path = f"/usr/share/wordlists/{wordlist}"
    
    # If not found, download a small common one for testing
    check_wl = await container.execute_command(f"ls {wordlist_path}")
    if check_wl["exit_code"] != 0:
        logger.info("⬇️ Downloading default wordlist...")
        # Using SecLists common.txt as fallback
        fallback_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
        await container.execute_command(f"wget {fallback_url} -O /nexus_data/common.txt")
        wordlist_path = "/nexus_data/common.txt"
    
    # Construct URL with FUZZ keyword if needed
    target_url = url
    if "FUZZ" not in target_url:
        if mode == "directory":
            if not target_url.endswith("/"):
                target_url += "/"
            target_url += "FUZZ"
        elif mode == "param":
            target_url += "?FUZZ=test"
    
    output_file = f"ffuf_{mode}_{url.replace('http', '').replace('://', '').replace('/', '_')}.json"
    
    cmd = (
        f"ffuf -u '{target_url}' "
        f"-w {wordlist_path} "
        f"-o {output_file} -of json "
        "-mc 200,204,301,302,307,401,403 " # Match codes (exclude 404)
        "-ac" # Auto-calibrate filtering
    )
    
    if extensions:
        cmd += f" -e {extensions}"
        
    if recursive:
        cmd += " -recursion"
        
    logger.info(f"💣 Running FFUF: {cmd}")
    await container.execute_command(cmd, timeout=900)
    
    findings = []
    content = await container.read_file(output_file)
    if content:
        try:
            data = json.loads(content)
            results = data.get("results", [])
            for res in results:
                findings.append({
                    "url": res.get("url"),
                    "status": res.get("status"),
                    "length": res.get("length"),
                    "words": res.get("words"),
                    "redirect": res.get("redirectlocation"),
                    "input": res.get("input", {}).get("FUZZ")
                })
        except Exception as e:
            logger.error(f"FFUF JSON Parse Error: {e}")
            
    return FfufResult(
        command=cmd,
        findings=findings
    )
