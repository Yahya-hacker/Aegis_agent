"""
Nexus - E2B Sandbox Integration
================================

Secure cloud-based execution using E2B SDK.
Replaces local Docker sandbox with isolated environments.
"""

import os
import logging
import asyncio
from typing import Optional, Any, Literal
from contextlib import asynccontextmanager

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# E2B imports (lazy to handle missing package gracefully)
try:
    from e2b_code_interpreter import AsyncCodeInterpreter
    from e2b import AsyncSandbox
    E2B_AVAILABLE = True
except ImportError:
    E2B_AVAILABLE = False
    logger.warning("⚠️ E2B SDK not installed. Run: pip install e2b e2b-code-interpreter")


SandboxType = Literal["code_interpreter", "custom", "bash"]


# E2B configuration
E2B_API_KEY = os.getenv("E2B_API_KEY")
E2B_TEMPLATE = os.getenv("E2B_TEMPLATE", "base")
E2B_TIMEOUT = int(os.getenv("E2B_SANDBOX_TIMEOUT", "300"))


class E2BSandbox:
    """
    E2B Sandbox manager for secure tool execution.
    
    Supports:
    - Code Interpreter: Python/JS execution with notebook interface
    - Custom Sandbox: Full Linux environment with pentest tools
    - Bash Sandbox: Simple command execution
    """
    
    def __init__(self):
        self._code_interpreter: Optional[Any] = None
        self._custom_sandbox: Optional[Any] = None
        
    async def _get_code_interpreter(self):
        """Get or create Code Interpreter sandbox."""
        if not E2B_AVAILABLE:
            raise RuntimeError("E2B SDK not available")
        
        if self._code_interpreter is None:
            self._code_interpreter = await AsyncCodeInterpreter.create(
                api_key=E2B_API_KEY,
                timeout=E2B_TIMEOUT
            )
            logger.info("🔐 E2B Code Interpreter sandbox created")
        
        return self._code_interpreter
    
    async def _get_custom_sandbox(self):
        """Get or create custom pentest sandbox."""
        if not E2B_AVAILABLE:
            raise RuntimeError("E2B SDK not available")
        
        if self._custom_sandbox is None:
            self._custom_sandbox = await AsyncSandbox.create(
                template=E2B_TEMPLATE,
                api_key=E2B_API_KEY,
                timeout=E2B_TIMEOUT
            )
            logger.info(f"🔐 E2B Custom sandbox created (template: {E2B_TEMPLATE})")
        
        return self._custom_sandbox
    
    async def execute_code(self, code: str, language: str = "python") -> dict[str, Any]:
        """
        Execute code in Code Interpreter sandbox.
        
        Args:
            code: Code to execute
            language: Programming language (python, javascript)
        
        Returns:
            Execution result with stdout, stderr, and artifacts
        """
        sandbox = await self._get_code_interpreter()
        
        logger.info(f"🔧 Executing {language} code in E2B...")
        
        try:
            execution = await sandbox.notebook.exec_cell(code)
            
            return {
                "status": "success",
                "stdout": execution.logs.stdout,
                "stderr": execution.logs.stderr,
                "results": [r.text for r in execution.results if r.text],
                "error": execution.error.message if execution.error else None,
            }
        except Exception as e:
            logger.error(f"❌ E2B execution error: {e}")
            return {
                "status": "error",
                "error": str(e),
            }
    
    async def execute_command(
        self,
        command: str,
        args: list[str] = None,
        cwd: str = "/home/user"
    ) -> dict[str, Any]:
        """
        Execute shell command in custom sandbox.
        
        Args:
            command: Command to execute
            args: Command arguments
            cwd: Working directory
        
        Returns:
            Command output with stdout, stderr, and exit code
        """
        sandbox = await self._get_custom_sandbox()
        
        cmd_str = f"{command} {' '.join(args or [])}"
        logger.info(f"🔧 Executing command in E2B: {cmd_str[:50]}...")
        
        try:
            result = await sandbox.process.start_and_wait(
                cmd=command,
                args=args or [],
                cwd=cwd,
                timeout=E2B_TIMEOUT
            )
            
            return {
                "status": "success" if result.exit_code == 0 else "error",
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.exit_code,
            }
        except Exception as e:
            logger.error(f"❌ E2B command error: {e}")
            return {
                "status": "error",
                "error": str(e),
            }
    
    async def execute_tool(
        self,
        tool: str,
        args: dict[str, Any],
        sandbox_type: SandboxType = "custom"
    ) -> dict[str, Any]:
        """
        Execute a security tool in the appropriate sandbox.
        
        Args:
            tool: Tool name (nmap, sqlmap, nuclei, etc.)
            args: Tool arguments
            sandbox_type: Type of sandbox to use
        
        Returns:
            Tool execution result
        """
        # Build command from tool and args
        cmd_args = []
        for key, value in args.items():
            if isinstance(value, bool):
                if value:
                    cmd_args.append(f"--{key}")
            else:
                cmd_args.append(f"--{key}={value}")
        
        if sandbox_type == "code_interpreter":
            # Execute as shell command in notebook
            code = f"!{tool} {' '.join(cmd_args)}"
            return await self.execute_code(code)
        else:
            # Execute in custom sandbox
            return await self.execute_command(tool, cmd_args)
    
    async def write_file(self, path: str, content: str) -> bool:
        """
        Write file to sandbox (for self-modification).
        
        Args:
            path: File path in sandbox
            content: File content
        
        Returns:
            Success status
        """
        sandbox = await self._get_custom_sandbox()
        
        try:
            await sandbox.filesystem.write(path, content)
            logger.info(f"📝 Wrote file to E2B: {path}")
            return True
        except Exception as e:
            logger.error(f"❌ E2B write error: {e}")
            return False
    
    async def read_file(self, path: str) -> Optional[str]:
        """
        Read file from sandbox.
        
        Args:
            path: File path in sandbox
        
        Returns:
            File content or None
        """
        sandbox = await self._get_custom_sandbox()
        
        try:
            content = await sandbox.filesystem.read(path)
            return content
        except Exception as e:
            logger.error(f"❌ E2B read error: {e}")
            return None
    
    async def close(self):
        """Close all sandboxes."""
        if self._code_interpreter:
            await self._code_interpreter.close()
            self._code_interpreter = None
        
        if self._custom_sandbox:
            await self._custom_sandbox.close()
            self._custom_sandbox = None
        
        logger.info("🔐 E2B sandboxes closed")


# Singleton instance
_sandbox: Optional[E2BSandbox] = None


def get_e2b_sandbox() -> E2BSandbox:
    """Get the E2B sandbox singleton."""
    global _sandbox
    if _sandbox is None:
        _sandbox = E2BSandbox()
    return _sandbox


# Convenience function
async def execute_in_sandbox(
    action: dict[str, Any],
    sandbox_type: SandboxType = "custom"
) -> dict[str, Any]:
    """
    Execute an action in E2B sandbox.
    
    This is the main entry point for tool execution.
    
    Args:
        action: Action dict with 'tool' and 'args'
        sandbox_type: Type of sandbox to use
    
    Returns:
        Execution result
    """
    sandbox = get_e2b_sandbox()
    tool = action.get("tool", "")
    args = action.get("args", {})
    
    return await sandbox.execute_tool(tool, args, sandbox_type)
