"""
Nexus v2.0 - Docker Container Manager
=====================================

Manages the local Kali Linux Docker container for tool execution.
"""

import asyncio
import logging
import os
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union
import json

from nexus.config import get_config

logger = logging.getLogger(__name__)


class ContainerManager:
    """
    Manages a local Docker container for executing security tools.
    
    Features:
    - Auto-starts Kali Linux container
    - Executes commands via docker exec
    - Handles file transfers (inputs/outputs)
    - Manages tool installation
    """
    
    def __init__(self):
        self.config = get_config()
        self.container_name = self.config.execution.docker_container_name
        self.image = self.config.execution.docker_image
        self.volume_path = Path(self.config.execution.docker_volume_path)
        
        # Ensure volume path exists
        self.volume_path.mkdir(parents=True, exist_ok=True)
        
        # internal mount point in container
        self.mount_point = "/nexus_data"
    
    async def _run_subprocess(self, cmd: str) -> Tuple[int, str, str]:
        """Run a local subprocess command."""
        process = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        return process.returncode, stdout.decode().strip(), stderr.decode().strip()
    
    async def ensure_container_running(self) -> bool:
        """Ensure the Docker container is running."""
        # Check if running
        code, stdout, _ = await self._run_subprocess(
            f"docker inspect -f '{{{{.State.Running}}}}' {self.container_name}"
        )
        
        if code == 0 and stdout == "true":
            return True
            
        # Check if exists but stopped
        code, _, _ = await self._run_subprocess(
            f"docker inspect {self.container_name}"
        )
        
        if code == 0:
            logger.info(f"🐳 Starting existing container: {self.container_name}")
            await self._run_subprocess(f"docker start {self.container_name}")
            return True
            
        # Create and run
        logger.info(f"🐳 Creating new container: {self.container_name}")
        
        # Ensure image exists
        logger.info(f"⬇️ Pulling image: {self.image}")
        await self._run_subprocess(f"docker pull {self.image}")
        
        run_cmd = (
            f"docker run -d "
            f"--name {self.container_name} "
            f"-v {self.volume_path}:{self.mount_point} "
            f"--entrypoint tail "  # Keep alive
            f"{self.image} "
            f"-f /dev/null"
        )
        
        code, stdout, stderr = await self._run_subprocess(run_cmd)
        
        if code != 0:
            logger.error(f"❌ Failed to start container: {stderr}")
            return False
            
        logger.info(f"✅ Container started: {stdout[:12]}")
        
        # Initial setup
        await self.install_basics()
        
        return True

    async def install_basics(self):
        """Install basic utilities."""
        logger.info("🛠️ Installing basic utilities in Kali container...")
        cmds = [
            "apt-get update",
            "apt-get install -y curl wget git jq unzip"
        ]
        for cmd in cmds:
            await self.execute_command(cmd)

    async def execute_command(
        self, 
        command: str, 
        workdir: str = "/nexus_data",
        timeout: int = 300
    ) -> Dict[str, Any]:
        """
        Execute a command inside the container.
        
        Args:
            command: Command string
            workdir: Working directory inside container
            timeout: Execution timeout in seconds
            
        Returns:
            Dict with exit_code, stdout, stderr
        """
        if not await self.ensure_container_running():
            return {"exit_code": -1, "stdout": "", "stderr": "Container not running"}
            
        # Escape command for safety
        safe_cmd = command.replace("'", "'\\''")
        
        docker_cmd = (
            f"docker exec -w {workdir} {self.container_name} "
            f"bash -c '{safe_cmd}'"
        )
        
        logger.debug(f"🐳 Exec: {command}")
        
        try:
            process = await asyncio.create_subprocess_shell(
                docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                
                result = {
                    "exit_code": process.returncode,
                    "stdout": stdout.decode("utf-8", errors="replace").strip(),
                    "stderr": stderr.decode("utf-8", errors="replace").strip()
                }
                
                if process.returncode != 0:
                    logger.warning(f"⚠️ Command failed ({process.returncode}): {command}")
                    logger.debug(f"Stderr: {result['stderr']}")
                
                return result
                
            except asyncio.TimeoutError:
                process.kill()
                logger.error(f"⏰ Command timed out: {command}")
                return {"exit_code": -1, "stdout": "", "stderr": "Timeout"}
                
        except Exception as e:
            logger.error(f"❌ Docker execution error: {e}")
            return {"exit_code": -1, "stdout": "", "stderr": str(e)}

    async def check_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool is installed."""
        res = await self.execute_command(f"which {tool_name}")
        return res["exit_code"] == 0 and len(res["stdout"]) > 0

    async def install_tool(self, tool_name: str, package_name: str = None) -> bool:
        """Install a tool via apt."""
        pkg = package_name or tool_name
        
        if await self.check_tool_installed(tool_name):
            return True
            
        logger.info(f"🛠️ Installing {pkg}...")
        res = await self.execute_command(f"apt-get install -y {pkg}")
        
        return res["exit_code"] == 0

    async def read_file(self, file_path: str) -> Optional[str]:
        """
        Read a file from the shared volume.
        
        Args:
            file_path: Relative path inside the mount point (e.g., "scan_results.json")
        """
        local_path = self.volume_path / file_path
        if local_path.exists():
            return local_path.read_text(errors="replace")
        return None

    def write_file(self, file_path: str, content: str) -> Path:
        """
        Write content to a file in the shared volume.
        
        Args:
            file_path: Relative path
            content: String content
            
        Returns:
            Absolute local path
        """
        local_path = self.volume_path / file_path
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_text(content)
        return local_path


# Singleton
_container: Optional[ContainerManager] = None

def get_container() -> ContainerManager:
    """Get global container manager."""
    global _container
    if _container is None:
        _container = ContainerManager()
    return _container
