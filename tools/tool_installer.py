"""
Tool Installer for Aegis AI.

Secure tool installation with human-in-the-loop confirmation.
Allows AI to request tool installations from GitHub repositories,
but requires explicit human approval before executing.

Features:
    - Human-in-the-loop confirmation for security
    - GitHub repository validation
    - Installation logging and history
    - Timeout protection for long installations
"""

import asyncio
import json
import logging
import subprocess
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class ToolInstaller:
    """
    Secure tool installer with human-in-the-loop confirmation.
    
    Allows AI to request tool installations from GitHub repositories,
    but requires explicit human approval before executing. This ensures
    security while enabling the agent to expand its capabilities.
    
    Attributes:
        install_log_file: Path to JSON file storing installation history.
    """
    
    def __init__(self):
        """Initialize the tool installer with default log path."""
        self.install_log_file = Path("data/tool_install_log.json")
        logger.info("🔧 ToolInstaller initialized")
    
    async def request_install_from_github(
        self,
        repo_url: str,
        description: str,
        package_name: Optional[str] = None
    ) -> str:
        """
        Request installation of a tool from GitHub (PUBLIC METHOD)
        
        This method DOES NOT install anything. It returns a special JSON
        response that triggers the human-in-the-loop confirmation flow.
        
        Args:
            repo_url: GitHub repository URL (e.g., 'https://github.com/user/repo')
            description: What this tool does and why it's needed
            package_name: Optional package name if different from repo name
            
        Returns:
            JSON string with confirmation_required flag
        """
        logger.info(f"🔧 Tool installation requested: {repo_url}")
        logger.info(f"   Description: {description}")
        
        # Extract repo name from URL
        if not package_name:
            package_name = repo_url.rstrip('/').split('/')[-1]
        
        # Validate the repo URL format
        if not repo_url.startswith('https://github.com/'):
            return json.dumps({
                "confirmation_required": False,
                "status": "error",
                "error": "Only GitHub repositories are supported (must start with https://github.com/)"
            })
        
        # Build the confirmation request
        confirmation_request = {
            "confirmation_required": True,
            "action": "install_tool",
            "repo_url": repo_url,
            "package_name": package_name,
            "description": description,
            "install_command": f"pip install git+{repo_url}",
            "message": f"""
🔧 TOOL INSTALLATION REQUEST
============================
Package: {package_name}
Repository: {repo_url}
Description: {description}

Command to execute:
  pip install git+{repo_url}

This action requires your approval to proceed.
"""
        }
        
        logger.info("📋 Installation request prepared, awaiting human confirmation")
        
        return json.dumps(confirmation_request, indent=2)
    
    async def _execute_install(
        self,
        repo_url: str,
        package_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute the actual installation (PRIVATE METHOD)
        
        This method should only be called after human confirmation.
        It installs the tool using pip in a secure subprocess.
        
        Args:
            repo_url: GitHub repository URL
            package_name: Optional package name
            
        Returns:
            Dictionary with installation result
        """
        logger.info(f"⚙️ Executing installation of {repo_url}...")
        
        try:
            # Build the pip install command
            install_url = f"git+{repo_url}"
            cmd = ['pip', 'install', install_url]
            
            logger.info(f"   Running: {' '.join(cmd)}")
            
            # Execute with asyncio subprocess
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Wait for completion with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=300  # 5 minute timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise RuntimeError("Installation timed out after 5 minutes")
            
            # Check result
            if process.returncode == 0:
                logger.info(f"✅ Installation successful: {package_name or repo_url}")
                
                # Log the successful installation
                await self._log_installation(repo_url, package_name, True, None)
                
                return {
                    "status": "success",
                    "package": package_name or repo_url,
                    "stdout": stdout.decode('utf-8'),
                    "message": f"Successfully installed {package_name or repo_url}"
                }
            else:
                error_msg = stderr.decode('utf-8')
                logger.error(f"❌ Installation failed: {error_msg}")
                
                # Log the failed installation
                await self._log_installation(repo_url, package_name, False, error_msg)
                
                return {
                    "status": "error",
                    "package": package_name or repo_url,
                    "error": error_msg,
                    "message": f"Failed to install {package_name or repo_url}"
                }
                
        except Exception as e:
            logger.error(f"❌ Installation error: {e}", exc_info=True)
            
            # Log the error
            await self._log_installation(repo_url, package_name, False, str(e))
            
            return {
                "status": "error",
                "package": package_name or repo_url,
                "error": str(e),
                "message": f"Installation error: {str(e)}"
            }
    
    async def _log_installation(
        self,
        repo_url: str,
        package_name: Optional[str],
        success: bool,
        error_message: Optional[str]
    ) -> None:
        """
        Log installation attempt to file
        
        Args:
            repo_url: GitHub repository URL
            package_name: Package name
            success: Whether installation succeeded
            error_message: Error message if failed
        """
        try:
            # Load existing log
            log_data = []
            if self.install_log_file.exists():
                with open(self.install_log_file, 'r') as f:
                    log_data = json.load(f)
            
            # Add new entry
            import time
            log_entry = {
                "timestamp": time.time(),
                "repo_url": repo_url,
                "package_name": package_name,
                "success": success,
                "error_message": error_message
            }
            log_data.append(log_entry)
            
            # Save log
            self.install_log_file.parent.mkdir(exist_ok=True, parents=True)
            with open(self.install_log_file, 'w') as f:
                json.dump(log_data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to log installation: {e}")
    
    def get_installation_history(self) -> list:
        """
        Get history of tool installations
        
        Returns:
            List of installation log entries
        """
        try:
            if self.install_log_file.exists():
                with open(self.install_log_file, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            logger.error(f"Failed to read installation history: {e}")
            return []


# Singleton instance
_installer_instance = None


def get_tool_installer() -> ToolInstaller:
    """Get singleton tool installer instance"""
    global _installer_instance
    if _installer_instance is None:
        _installer_instance = ToolInstaller()
    return _installer_instance
