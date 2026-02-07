# aegis/tools/manager.py
"""
Unified Tool Manager for Aegis AI.

Consolidates tool execution into a single, clean interface.
Delegates to specialized tool modules for actual execution.
"""

import asyncio
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class ToolManager:
    """
    Central tool orchestration.
    
    Maps tool names to their implementations and handles:
    - Rate limiting
    - Timeout management
    - Error handling and retries
    """
    
    def __init__(self):
        self._recon_tools = None
        self._injection_tools = None
        self._real_tools = None
        
    def _get_real_tools(self):
        """Lazy load the real tool manager from tools/"""
        if not self._real_tools:
            from tools.tool_manager import RealToolManager
            self._real_tools = RealToolManager()
        return self._real_tools
    
    def _get_python_tools(self):
        """Lazy load Python tools."""
        if not hasattr(self, '_python_tools'):
            from tools.python_tools import PythonToolManager
            self._python_tools = PythonToolManager()
        return self._python_tools
    
    async def execute(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a tool by name.
        
        Args:
            tool_name: Name of the tool to execute
            args: Tool arguments
            
        Returns:
            Result dictionary with status and data/error
        """
        logger.info(f"⚙️ Executing: {tool_name} {args}")
        
        try:
            # Map tool names to implementations
            if tool_name == "nmap_scan":
                return await self._get_real_tools().nmap_scan(
                    args.get("target"),
                    args.get("ports")
                )
            
            elif tool_name == "subdomain_enumeration":
                return await self._get_real_tools().subdomain_enumeration(
                    args.get("domain")
                )
            
            elif tool_name == "vulnerability_scan":
                return await self._get_real_tools().vulnerability_scan(
                    args.get("target")
                )
            
            elif tool_name == "port_scanning":
                return await self._get_real_tools().port_scanning(
                    args.get("target")
                )
            
            elif tool_name == "url_discovery":
                return await self._get_real_tools().url_discovery(
                    args.get("domain")
                )
            
            elif tool_name == "run_sqlmap":
                return await self._get_real_tools().run_sqlmap(
                    args.get("url") or args.get("target"),
                    args.get("high_impact", False)
                )
            
            elif tool_name == "xss_test":
                from tools.xss_scanner import test_xss
                return await test_xss(
                    args.get("url"),
                    args.get("params"),
                    args.get("scan_form", True)
                )
            
            elif tool_name == "http_request":
                return await self._get_python_tools().fetch_url(
                    args.get("url")
                )
            
            elif tool_name == "directory_bruteforce":
                # Use feroxbuster or similar if available
                return {"status": "not_implemented", "message": "Directory bruteforce pending"}
            
            elif tool_name == "finish_mission":
                return {"status": "success", "message": "Mission completed by agent request"}
            
            else:
                return {"status": "error", "error": f"Unknown tool: {tool_name}"}
                
        except Exception as e:
            logger.error(f"Tool execution failed: {e}", exc_info=True)
            return {"status": "error", "error": str(e)}


# Singleton
_manager = None

def get_tool_manager() -> ToolManager:
    global _manager
    if _manager is None:
        _manager = ToolManager()
    return _manager
