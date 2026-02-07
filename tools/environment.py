"""
Aegis Agent - Environment Audit Module
=======================================

Pre-flight environment validation for Kali Linux / Docker execution.
Runs on server startup to ensure all required tools are available.
"""

import asyncio
import logging
import os
import shutil
import subprocess
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class AuditResult:
    """Result of environment audit."""
    is_kali: bool = False
    is_debian: bool = False
    is_docker: bool = False
    os_name: str = ""
    kernel: str = ""
    tools_found: Dict[str, str] = field(default_factory=dict)
    tools_missing: List[str] = field(default_factory=list)
    tools_installed: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    @property
    def is_valid(self) -> bool:
        return self.is_kali or self.is_debian or self.is_docker


# Core penetration testing tools to check for
CORE_TOOLS = [
    # Reconnaissance
    "nmap", "subfinder", "httpx", "nuclei", "katana", "gau", "waybackurls",
    "amass", "naabu", "masscan", "ffuf", "gobuster", "feroxbuster",
    # Exploitation
    "sqlmap", "commix", "hydra", "john", "hashcat",
    # Web
    "nikto", "wpscan", "whatweb", "curl", "wget",
    # Network
    "netcat", "socat", "tcpdump", "wireshark", "tshark",
    # Utilities
    "jq", "git", "python3", "pip3", "go",
]

# Package name mapping (tool_name -> apt package name)
PACKAGE_MAP = {
    "subfinder": "subfinder",
    "httpx": "httpx-toolkit",
    "nuclei": "nuclei", 
    "katana": "katana",
    "naabu": "naabu",
    "ffuf": "ffuf",
    "feroxbuster": "feroxbuster",
    "netcat": "netcat-openbsd",
    "python3": "python3",
    "pip3": "python3-pip",
}


class EnvironmentAudit:
    """
    Pre-flight environment validator.
    
    Checks OS type, discovers installed tools, and can auto-install missing ones.
    """
    
    def __init__(self, auto_install: bool = False):
        """
        Initialize the environment audit.
        
        Args:
            auto_install: If True, automatically install missing tools via apt.
        """
        self.auto_install = auto_install
        self.result = AuditResult()
    
    async def run_full_audit(self) -> AuditResult:
        """Run complete environment audit."""
        logger.info("🔍 Starting environment audit...")
        
        # Step 1: Detect OS
        await self._detect_os()
        
        # Step 2: Discover tools
        await self._discover_tools()
        
        # Step 3: Auto-install if enabled
        if self.auto_install and self.result.tools_missing:
            await self._auto_install_missing()
        
        # Log summary
        self._log_summary()
        
        return self.result
    
    async def _detect_os(self):
        """Detect operating system and environment."""
        self.result.kernel = platform.release()
        
        # Check for Docker
        if os.path.exists("/.dockerenv"):
            self.result.is_docker = True
            logger.info("🐳 Running inside Docker container")
        
        # Check /etc/os-release
        os_release = Path("/etc/os-release")
        if os_release.exists():
            content = os_release.read_text().lower()
            
            if "kali" in content:
                self.result.is_kali = True
                self.result.os_name = "Kali Linux"
                logger.info("✅ Kali Linux detected")
            elif "debian" in content or "ubuntu" in content:
                self.result.is_debian = True
                self.result.os_name = "Debian/Ubuntu"
                logger.info("✅ Debian-based OS detected")
            else:
                # Try to extract ID
                for line in content.split("\n"):
                    if line.startswith("id="):
                        self.result.os_name = line.split("=")[1].strip('"')
                        break
        else:
            self.result.os_name = platform.system()
            logger.warning(f"⚠️ Non-Linux OS: {self.result.os_name}")
    
    async def _discover_tools(self):
        """Scan system for installed security tools."""
        logger.info("🔧 Discovering installed tools...")
        
        for tool in CORE_TOOLS:
            path = shutil.which(tool)
            if path:
                self.result.tools_found[tool] = path
            else:
                self.result.tools_missing.append(tool)
        
        found = len(self.result.tools_found)
        missing = len(self.result.tools_missing)
        logger.info(f"   Found: {found} tools, Missing: {missing} tools")
    
    async def _auto_install_missing(self):
        """Install missing tools via apt."""
        if not (self.result.is_kali or self.result.is_debian):
            logger.warning("⚠️ Auto-install only supported on Debian-based systems")
            return
        
        # Update package list first
        logger.info("📦 Updating package list...")
        try:
            proc = await asyncio.create_subprocess_exec(
                "apt-get", "update",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.wait()
        except Exception as e:
            self.result.errors.append(f"apt-get update failed: {e}")
            return
        
        # Install each missing tool
        for tool in self.result.tools_missing[:]:  # Copy list to allow modification
            package = PACKAGE_MAP.get(tool, tool)
            success = await self._install_package(package)
            if success:
                # Re-check if tool is now available
                path = shutil.which(tool)
                if path:
                    self.result.tools_found[tool] = path
                    self.result.tools_missing.remove(tool)
                    self.result.tools_installed.append(tool)
    
    async def _install_package(self, package: str) -> bool:
        """Install a single package via apt."""
        logger.info(f"📦 Installing {package}...")
        
        try:
            proc = await asyncio.create_subprocess_exec(
                "apt-get", "install", "-y", package,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode == 0:
                logger.info(f"   ✅ {package} installed")
                return True
            else:
                error = stderr.decode("utf-8", errors="replace")
                logger.warning(f"   ❌ Failed to install {package}: {error[:100]}")
                self.result.errors.append(f"Failed to install {package}")
                return False
                
        except Exception as e:
            logger.error(f"   ❌ Exception installing {package}: {e}")
            self.result.errors.append(str(e))
            return False
    
    def _log_summary(self):
        """Log audit summary."""
        logger.info("=" * 50)
        logger.info("📋 ENVIRONMENT AUDIT SUMMARY")
        logger.info("=" * 50)
        logger.info(f"   OS: {self.result.os_name}")
        logger.info(f"   Kernel: {self.result.kernel}")
        logger.info(f"   Docker: {self.result.is_docker}")
        logger.info(f"   Valid Environment: {self.result.is_valid}")
        logger.info(f"   Tools Found: {len(self.result.tools_found)}")
        logger.info(f"   Tools Missing: {len(self.result.tools_missing)}")
        if self.result.tools_installed:
            logger.info(f"   Tools Installed: {self.result.tools_installed}")
        logger.info("=" * 50)
    
    def ensure_tool_in_path(self, tool_name: str, install_path: str) -> bool:
        """
        Ensure a tool is accessible via PATH.
        
        If the tool exists at install_path but is not in PATH,
        create a symlink in /usr/local/bin.
        
        Args:
            tool_name: Name of the tool
            install_path: Full path to the tool binary
            
        Returns:
            True if tool is now accessible
        """
        if shutil.which(tool_name):
            return True
        
        if not os.path.exists(install_path):
            return False
        
        # Create symlink in /usr/local/bin
        link_path = f"/usr/local/bin/{tool_name}"
        try:
            os.symlink(install_path, link_path)
            logger.info(f"🔗 Created symlink: {link_path} -> {install_path}")
            return True
        except PermissionError:
            logger.warning(f"⚠️ Cannot create symlink (permission denied): {link_path}")
            return False
        except Exception as e:
            logger.error(f"❌ Failed to create symlink: {e}")
            return False
    
    def get_tool_path(self, tool_name: str) -> Optional[str]:
        """Get the path to a tool, or None if not found."""
        return self.result.tools_found.get(tool_name) or shutil.which(tool_name)


# Singleton instance
_audit: Optional[EnvironmentAudit] = None


def get_environment() -> EnvironmentAudit:
    """Get the global environment audit instance."""
    global _audit
    if _audit is None:
        _audit = EnvironmentAudit()
    return _audit


async def run_preflight_check(auto_install: bool = False) -> AuditResult:
    """
    Run pre-flight environment check.
    
    This should be called during server startup.
    
    Args:
        auto_install: If True, attempt to install missing tools
        
    Returns:
        AuditResult with environment status
    """
    global _audit
    _audit = EnvironmentAudit(auto_install=auto_install)
    return await _audit.run_full_audit()
