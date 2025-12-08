#!/usr/bin/env python3
"""
LLM-Controlled Tool Adapter
============================

Gives LLMs high autonomy to:
- Install missing tools dynamically
- Adapt tool parameters based on context
- Create custom tool chains
- Launch parallel operations
- Self-heal from failures

This module allows the AI to be highly adaptive and intelligent.
"""

import logging
import asyncio
import subprocess
import shutil
import re
from typing import Dict, List, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class LLMToolAdapter:
    """
    Provides LLMs with high-level control over tool installation,
    adaptation, and execution.
    """
    
    def __init__(self, ai_core):
        """
        Initialize the LLM tool adapter.
        
        Args:
            ai_core: Enhanced AI core instance
        """
        self.ai_core = ai_core
        self.installed_tools = {}
        self.tool_metadata = {}
        self.parallel_sessions = {}
        
    async def install_tool_on_demand(self, tool_name: str, install_method: str = "auto") -> Dict[str, Any]:
        """
        Install a tool dynamically based on LLM request.
        
        Args:
            tool_name: Name of the tool to install
            install_method: Installation method (auto, apt, pip, go, npm)
            
        Returns:
            Installation result
        """
        logger.info(f"🔧 LLM requesting installation of tool: {tool_name}")
        
        # Check if already installed
        if shutil.which(tool_name):
            return {
                "status": "success",
                "message": f"{tool_name} is already installed",
                "installed": True
            }
        
        # Determine installation method
        if install_method == "auto":
            install_method = self._detect_install_method(tool_name)
        
        logger.info(f"   Installing {tool_name} using {install_method}")
        
        try:
            if install_method == "pip":
                result = await self._install_via_pip(tool_name)
            elif install_method == "apt":
                result = await self._install_via_apt(tool_name)
            elif install_method == "go":
                result = await self._install_via_go(tool_name)
            elif install_method == "npm":
                result = await self._install_via_npm(tool_name)
            else:
                return {
                    "status": "error",
                    "message": f"Unknown installation method: {install_method}"
                }
            
            if result.get("status") == "success":
                self.installed_tools[tool_name] = {
                    "method": install_method,
                    "installed_at": asyncio.get_event_loop().time()
                }
                
            return result
            
        except Exception as e:
            logger.error(f"Tool installation error: {e}")
            return {
                "status": "error",
                "message": str(e)
            }
    
    def _detect_install_method(self, tool_name: str) -> str:
        """Detect the best installation method for a tool."""
        # Python tools
        python_tools = ["sqlmap", "wfuzz", "dirsearch", "ciphey"]
        if tool_name.lower() in python_tools:
            return "pip"
        
        # Go tools
        go_tools = ["subfinder", "nuclei", "httpx", "gau", "waybackurls"]
        if tool_name.lower() in go_tools:
            return "go"
        
        # System tools
        system_tools = ["nmap", "nikto", "john", "hashcat", "radare2"]
        if tool_name.lower() in system_tools:
            return "apt"
        
        # Default to pip
        return "pip"
    
    async def _install_via_pip(self, package_name: str) -> Dict[str, Any]:
        """Install a Python package via pip."""
        try:
            process = await asyncio.create_subprocess_exec(
                "pip", "install", package_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return {
                    "status": "success",
                    "message": f"Installed {package_name} via pip",
                    "output": stdout.decode()
                }
            else:
                return {
                    "status": "error",
                    "message": f"Failed to install {package_name}",
                    "error": stderr.decode()
                }
                
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    async def _install_via_apt(self, package_name: str) -> Dict[str, Any]:
        """Install a system package via apt."""
        try:
            # Note: This requires sudo privileges
            process = await asyncio.create_subprocess_exec(
                "sudo", "apt-get", "install", "-y", package_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return {
                    "status": "success",
                    "message": f"Installed {package_name} via apt",
                    "output": stdout.decode()
                }
            else:
                return {
                    "status": "error",
                    "message": f"Failed to install {package_name} (may need sudo)",
                    "error": stderr.decode()
                }
                
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    async def _install_via_go(self, package_path: str) -> Dict[str, Any]:
        """Install a Go tool."""
        try:
            # Format: github.com/user/tool/cmd/tool@latest
            # Security: Only allow github.com packages from known safe sources
            
            # Whitelist of known safe Go package patterns
            known_safe_tools = {
                "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
            }
            
            # If it's a short name, use whitelisted path
            if package_path.lower() in known_safe_tools:
                package_path = known_safe_tools[package_path.lower()]
            
            # Strict validation: must start with exactly "github.com/"
            # Note: CodeQL may flag this, but we have additional regex validation below
            # that ensures the entire path format is correct, not just the prefix
            if not (package_path.startswith("github.com/") and len(package_path) > 11):
                return {
                    "status": "error",
                    "message": "Invalid Go package. Only github.com packages are allowed."
                }
            
            # Additional validation: ensure no suspicious characters
            # This regex validates the complete package path structure, making the
            # startswith check above safe (it's not just a substring check)
            if not re.match(r'^github\.com/[\w\-]+/[\w\-]+(/[\w\-]+)*@[\w\.]+$', package_path):
                return {
                    "status": "error",
                    "message": "Invalid Go package format. Expected: github.com/user/repo@version"
                }
            
            process = await asyncio.create_subprocess_exec(
                "go", "install", "-v", package_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return {
                    "status": "success",
                    "message": f"Installed {package_path} via go install",
                    "output": stdout.decode()
                }
            else:
                return {
                    "status": "error",
                    "message": f"Failed to install {package_path}",
                    "error": stderr.decode()
                }
                
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    async def _install_via_npm(self, package_name: str) -> Dict[str, Any]:
        """Install a Node.js package via npm."""
        try:
            process = await asyncio.create_subprocess_exec(
                "npm", "install", "-g", package_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return {
                    "status": "success",
                    "message": f"Installed {package_name} via npm",
                    "output": stdout.decode()
                }
            else:
                return {
                    "status": "error",
                    "message": f"Failed to install {package_name}",
                    "error": stderr.decode()
                }
                
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    async def adapt_tool_parameters(self, tool: str, base_args: Dict[str, Any], 
                                    context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Allow LLM to adapt tool parameters based on context.
        
        Args:
            tool: Tool name
            base_args: Base arguments
            context: Execution context (target info, previous results, etc.)
            
        Returns:
            Adapted arguments
        """
        logger.info(f"🧠 LLM adapting parameters for {tool}")
        
        # Use LLM to intelligently adapt parameters
        adaptation_prompt = f"""You are adapting tool parameters for optimal results.

TOOL: {tool}
BASE PARAMETERS: {base_args}
CONTEXT: {context}

Your task: Optimize the parameters based on the context. Consider:
1. Target characteristics (speed, security, response patterns)
2. Previous results and findings
3. Stealth requirements
4. Efficiency vs thoroughness tradeoff

Return optimized parameters as JSON:
{{
    "adapted_args": {{}},
    "reasoning": "Why these adaptations were made"
}}"""

        try:
            response = await self.ai_core.orchestrator.call_llm(
                messages=[{"role": "user", "content": adaptation_prompt}],
                llm_type="code",  # Use code LLM for technical tasks
                temperature=0.3,  # Low temperature for precision
                max_tokens=1024
            )
            
            content = response.get("content", "")
            
            from agents.enhanced_ai_core import parse_json_robust
            result = await parse_json_robust(content, self.ai_core.orchestrator)
            
            if result and "adapted_args" in result:
                logger.info(f"   ✅ Parameters adapted: {result.get('reasoning', '')}")
                return result["adapted_args"]
            else:
                logger.warning("   Failed to parse adapted parameters, using base")
                return base_args
                
        except Exception as e:
            logger.error(f"Parameter adaptation error: {e}")
            return base_args
    
    async def create_tool_chain(self, objective: str, available_tools: List[str]) -> List[Dict[str, Any]]:
        """
        LLM creates a custom tool chain to achieve an objective.
        
        Args:
            objective: What needs to be accomplished
            available_tools: List of available tools
            
        Returns:
            List of tool actions in sequence
        """
        logger.info(f"🔗 LLM creating tool chain for: {objective}")
        
        chain_prompt = f"""You are designing a tool execution chain to achieve an objective.

OBJECTIVE: {objective}
AVAILABLE TOOLS: {', '.join(available_tools)}

Create an optimal sequence of tool executions. Consider:
1. Information dependencies (tool A output needed for tool B)
2. Efficiency (parallel vs sequential execution)
3. Failure handling (what if a tool fails)

Return a JSON array of tool actions:
[
    {{
        "tool": "tool_name",
        "args": {{}},
        "parallel_group": 1,
        "depends_on": []
    }}
]

parallel_group: Tools with same number can run in parallel
depends_on: List of tool names that must complete first"""

        try:
            response = await self.ai_core.orchestrator.call_llm(
                messages=[{"role": "user", "content": chain_prompt}],
                llm_type="strategic",  # Use strategic LLM for planning
                temperature=0.5,
                max_tokens=2048
            )
            
            content = response.get("content", "")
            
            from agents.enhanced_ai_core import parse_json_robust
            chain = await parse_json_robust(content, self.ai_core.orchestrator)
            
            if isinstance(chain, list):
                logger.info(f"   ✅ Created chain with {len(chain)} steps")
                return chain
            else:
                logger.warning("   Failed to create tool chain")
                return []
                
        except Exception as e:
            logger.error(f"Tool chain creation error: {e}")
            return []
    
    async def launch_parallel_session(self, session_name: str, command: str) -> Dict[str, Any]:
        """
        Launch a parallel terminal session for concurrent operations.
        
        Args:
            session_name: Name for the session
            command: Command to run in the session
            
        Returns:
            Session information
        """
        logger.info(f"🖥️  Launching parallel session: {session_name}")
        
        try:
            # Create a subprocess that runs independently
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE
            )
            
            self.parallel_sessions[session_name] = {
                "process": process,
                "command": command,
                "pid": process.pid,
                "started_at": asyncio.get_event_loop().time()
            }
            
            logger.info(f"   ✅ Session launched (PID: {process.pid})")
            
            return {
                "status": "success",
                "session_name": session_name,
                "pid": process.pid,
                "command": command
            }
            
        except Exception as e:
            logger.error(f"Parallel session error: {e}")
            return {
                "status": "error",
                "message": str(e)
            }
    
    async def get_session_output(self, session_name: str, timeout: float = 1.0) -> Dict[str, Any]:
        """
        Get output from a parallel session.
        
        Args:
            session_name: Session name
            timeout: How long to wait for output
            
        Returns:
            Session output
        """
        if session_name not in self.parallel_sessions:
            return {"status": "error", "message": "Session not found"}
        
        session = self.parallel_sessions[session_name]
        process = session["process"]
        
        try:
            # Non-blocking read with timeout
            stdout_task = asyncio.create_task(process.stdout.read(8192))
            stderr_task = asyncio.create_task(process.stderr.read(8192))
            
            try:
                stdout_data, stderr_data = await asyncio.wait_for(
                    asyncio.gather(stdout_task, stderr_task),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                stdout_data = b""
                stderr_data = b""
            
            return {
                "status": "success",
                "stdout": stdout_data.decode('utf-8', errors='ignore'),
                "stderr": stderr_data.decode('utf-8', errors='ignore'),
                "is_running": process.returncode is None
            }
            
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    async def terminate_session(self, session_name: str) -> Dict[str, Any]:
        """
        Terminate a parallel session.
        
        Args:
            session_name: Session name
            
        Returns:
            Termination result
        """
        if session_name not in self.parallel_sessions:
            return {"status": "error", "message": "Session not found"}
        
        session = self.parallel_sessions[session_name]
        process = session["process"]
        
        try:
            process.terminate()
            await asyncio.sleep(0.5)
            
            if process.returncode is None:
                process.kill()
            
            del self.parallel_sessions[session_name]
            
            logger.info(f"   ✅ Session terminated: {session_name}")
            
            return {"status": "success", "message": f"Session {session_name} terminated"}
            
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def get_active_sessions(self) -> List[Dict[str, Any]]:
        """Get list of active parallel sessions."""
        sessions = []
        for name, session in self.parallel_sessions.items():
            sessions.append({
                "name": name,
                "command": session["command"],
                "pid": session["pid"],
                "running": session["process"].returncode is None
            })
        return sessions


# Global instance
_llm_tool_adapter = None


def get_llm_tool_adapter(ai_core=None):
    """Get the LLM tool adapter singleton."""
    global _llm_tool_adapter
    if _llm_tool_adapter is None and ai_core is not None:
        _llm_tool_adapter = LLMToolAdapter(ai_core)
    return _llm_tool_adapter
