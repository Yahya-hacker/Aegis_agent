"""
Tool Installer for Aegis AI v8.0.

Secure tool installation with human-in-the-loop confirmation and 
self-healing capabilities for JIT (Just-in-Time) tool installation.

Features:
    - Human-in-the-loop confirmation for security
    - GitHub repository validation against trusted list
    - Commit hash verification for reproducibility
    - System package installation (apt-get)
    - Python package installation (pip)
    - Self-healing decorator for automatic tool installation
    - Installation logging and history
    - Timeout protection for long installations

Security:
    - Only whitelisted organizations/repos can be installed without explicit approval
    - Commit hash pinning ensures reproducible installations
    - All installations are logged for audit trails
"""

import asyncio
import functools
import json
import logging
import os
import re
import shutil
import subprocess
from typing import Dict, Any, Optional, Callable, List, Set
from pathlib import Path

logger = logging.getLogger(__name__)

# Global flag for self-healing mode
# When enabled, missing tools are installed automatically without user confirmation
SELF_HEALING_MODE = os.environ.get("AEGIS_SELF_HEALING", "false").lower() == "true"

# ============================================================================
# TRUSTED REPOSITORY CONFIGURATION
# ============================================================================

# Trusted GitHub organizations whose repositories can be installed with reduced friction
# Repositories from these orgs still require human confirmation but are marked as "trusted"
TRUSTED_GITHUB_ORGS: Set[str] = {
    # Security tool organizations
    "projectdiscovery",  # nuclei, httpx, subfinder, etc.
    "OWASP",             # OWASP tools
    "rapid7",            # Metasploit, etc.
    "sqlmapproject",     # sqlmap
    "vanhauser-thc",     # THC-Hydra
    "SecureAuthCorp",    # Impacket
    "portswigger",       # Burp extensions
    "nmap",              # nmap
    "wireshark",         # Wireshark
    "radareorg",         # Radare2
    "pwndbg",            # pwndbg
    "hugsy",             # gef (GDB Enhanced Features)
    "longld",            # peda
    
    # Well-known Python security packages
    "volatilityfoundation",  # Volatility
    "ReFirmLabs",        # binwalk
    "Gallopsled",        # pwntools
    
    # Aegis ecosystem (self-trust)
    "Yahya-hacker",
}

# Specific trusted repositories (for repos not in trusted orgs)
# Format: "owner/repo" -> Optional[commit_hash] (None means any version)
TRUSTED_REPOS: Dict[str, Optional[str]] = {
    # Add specific trusted repos here
    # Example: "user/repo": "abc123def456" or "user/repo": None
}

# Require commit hash for non-trusted repos (security enforcement)
REQUIRE_COMMIT_HASH_FOR_UNTRUSTED = os.environ.get(
    "AEGIS_REQUIRE_COMMIT_HASH", "true"
).lower() == "true"

# Regex pattern for validating commit hashes
COMMIT_HASH_PATTERN = re.compile(r'^[a-fA-F0-9]{7,40}$')

# Dependency mapping: tool command -> package name for apt-get
TOOL_TO_PACKAGE_MAP = {
    # Cryptography tools
    "ciphey": "ciphey",  # pip package
    "hashid": "hashid",  # pip package
    "john": "john",
    "hash-identifier": "hash-identifier",
    
    # Reverse engineering tools
    "r2": "radare2",
    "radare2": "radare2",
    "gdb": "gdb",
    "strings": "binutils",
    "objdump": "binutils",
    "readelf": "binutils",
    
    # Forensics tools
    "exiftool": "libimage-exiftool-perl",
    "binwalk": "binwalk",
    "steghide": "steghide",
    "volatility": "volatility",
    "foremost": "foremost",
    "zsteg": "zsteg",  # Ruby gem
    
    # Network tools
    "tshark": "tshark",
    "tcpdump": "tcpdump",
    "capinfos": "wireshark-common",
    
    # Binary exploitation
    "checksec": "checksec",
    
    # Common security tools
    "nmap": "nmap",
    "sqlmap": "sqlmap",
    "nikto": "nikto",
    "dirb": "dirb",
    "hydra": "hydra",
    "gobuster": "gobuster",
    "file": "file",
}

# Tools that should be installed via pip
PIP_PACKAGES = {
    "ciphey": "ciphey",
    "hashid": "hashid",
    "pwntools": "pwntools",
}

# Tools that should be installed via gem (Ruby)
GEM_PACKAGES = {
    "zsteg": "zsteg",
}


class ToolInstaller:
    """
    Secure tool installer with human-in-the-loop confirmation and self-healing.
    
    Allows AI to request tool installations from GitHub repositories,
    system packages (apt-get), or pip packages. Supports automatic
    installation when self-healing mode is enabled.
    
    Attributes:
        install_log_file: Path to JSON file storing installation history.
        self_healing: Whether to auto-install tools without confirmation.
    """
    
    def __init__(self, self_healing: bool = None):
        """
        Initialize the tool installer.
        
        Args:
            self_healing: Override self-healing mode. If None, uses AEGIS_SELF_HEALING env var.
        """
        self.install_log_file = Path("data/tool_install_log.json")
        self.self_healing = self_healing if self_healing is not None else SELF_HEALING_MODE
        logger.info(f"🔧 ToolInstaller initialized (self_healing={self.self_healing})")
    
    def is_tool_available(self, tool_name: str) -> bool:
        """
        Check if a tool is available in the system PATH.
        
        Args:
            tool_name: Name of the tool to check
            
        Returns:
            True if tool is available, False otherwise
        """
        return shutil.which(tool_name) is not None
    
    def get_package_name(self, tool_name: str) -> Optional[str]:
        """
        Get the package name for a tool.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Package name or None if not mapped
        """
        return TOOL_TO_PACKAGE_MAP.get(tool_name)
    
    async def install_system_package(
        self,
        package_name: str,
        timeout: int = 300
    ) -> Dict[str, Any]:
        """
        Install a system package using apt-get.
        
        Args:
            package_name: Name of the package to install
            timeout: Maximum installation time in seconds
            
        Returns:
            Dictionary with installation result
        """
        logger.info(f"📦 Installing system package: {package_name}")
        
        try:
            # Update package list first
            update_cmd = ["sudo", "apt-get", "update", "-qq"]
            
            process = await asyncio.create_subprocess_exec(
                *update_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await asyncio.wait_for(process.communicate(), timeout=60)
            
            # Install the package
            install_cmd = ["sudo", "apt-get", "install", "-y", "-qq", package_name]
            
            logger.info(f"   Running: {' '.join(install_cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *install_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            if process.returncode == 0:
                logger.info(f"✅ Successfully installed: {package_name}")
                await self._log_installation(
                    f"apt:{package_name}",
                    package_name,
                    True,
                    None
                )
                return {
                    "status": "success",
                    "package": package_name,
                    "method": "apt-get",
                    "message": f"Successfully installed {package_name}"
                }
            else:
                error_msg = stderr.decode('utf-8', errors='replace')
                logger.error(f"❌ Failed to install {package_name}: {error_msg}")
                await self._log_installation(
                    f"apt:{package_name}",
                    package_name,
                    False,
                    error_msg
                )
                return {
                    "status": "error",
                    "package": package_name,
                    "method": "apt-get",
                    "error": error_msg
                }
                
        except asyncio.TimeoutError:
            error_msg = f"Installation timed out after {timeout}s"
            logger.error(f"❌ {error_msg}")
            return {"status": "error", "package": package_name, "error": error_msg}
        except Exception as e:
            logger.error(f"❌ Installation error: {e}", exc_info=True)
            return {"status": "error", "package": package_name, "error": str(e)}
    
    async def install_pip_package(
        self,
        package_name: str,
        timeout: int = 300
    ) -> Dict[str, Any]:
        """
        Install a Python package using pip.
        
        Args:
            package_name: Name of the pip package to install
            timeout: Maximum installation time in seconds
            
        Returns:
            Dictionary with installation result
        """
        logger.info(f"🐍 Installing pip package: {package_name}")
        
        try:
            cmd = ["pip", "install", package_name]
            
            logger.info(f"   Running: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            if process.returncode == 0:
                logger.info(f"✅ Successfully installed pip package: {package_name}")
                await self._log_installation(
                    f"pip:{package_name}",
                    package_name,
                    True,
                    None
                )
                return {
                    "status": "success",
                    "package": package_name,
                    "method": "pip",
                    "message": f"Successfully installed {package_name}"
                }
            else:
                error_msg = stderr.decode('utf-8', errors='replace')
                logger.error(f"❌ Failed to install {package_name}: {error_msg}")
                await self._log_installation(
                    f"pip:{package_name}",
                    package_name,
                    False,
                    error_msg
                )
                return {
                    "status": "error",
                    "package": package_name,
                    "method": "pip",
                    "error": error_msg
                }
                
        except asyncio.TimeoutError:
            error_msg = f"Installation timed out after {timeout}s"
            logger.error(f"❌ {error_msg}")
            return {"status": "error", "package": package_name, "error": error_msg}
        except Exception as e:
            logger.error(f"❌ Installation error: {e}", exc_info=True)
            return {"status": "error", "package": package_name, "error": str(e)}
    
    async def ensure_tool_available(
        self,
        tool_name: str,
        auto_install: bool = None
    ) -> Dict[str, Any]:
        """
        Ensure a tool is available, installing it if necessary.
        
        This is the main entry point for the self-healing mechanism.
        
        Args:
            tool_name: Name of the tool to ensure is available
            auto_install: Override auto-install setting
            
        Returns:
            Dictionary with status and any installation results
        """
        # Check if tool is already available
        if self.is_tool_available(tool_name):
            return {
                "status": "success",
                "tool": tool_name,
                "already_installed": True
            }
        
        # Determine if we should auto-install
        should_install = auto_install if auto_install is not None else self.self_healing
        
        if not should_install:
            logger.warning(f"⚠️ Tool '{tool_name}' not available and self-healing is disabled")
            return {
                "status": "missing",
                "tool": tool_name,
                "message": f"Tool '{tool_name}' is not installed. Enable self-healing or install manually."
            }
        
        logger.info(f"🔧 Self-healing: attempting to install '{tool_name}'...")
        
        # Determine installation method
        if tool_name in PIP_PACKAGES:
            package_name = PIP_PACKAGES[tool_name]
            return await self.install_pip_package(package_name)
        elif tool_name in GEM_PACKAGES:
            # Ruby gems - try system install
            package_name = TOOL_TO_PACKAGE_MAP.get(tool_name, tool_name)
            return await self.install_system_package(package_name)
        else:
            # Try apt-get
            package_name = TOOL_TO_PACKAGE_MAP.get(tool_name, tool_name)
            return await self.install_system_package(package_name)
    
    def _parse_github_url(self, repo_url: str) -> Dict[str, Optional[str]]:
        """
        Parse a GitHub URL to extract owner, repo, and optional commit hash.
        
        Supports formats:
        - https://github.com/owner/repo
        - https://github.com/owner/repo.git
        - https://github.com/owner/repo@commit_hash
        - https://github.com/owner/repo/tree/branch
        - https://github.com/owner/repo/commit/sha
        
        Args:
            repo_url: GitHub repository URL
            
        Returns:
            Dict with 'owner', 'repo', 'commit_hash', 'is_valid' keys
        """
        result = {
            'owner': None,
            'repo': None,
            'commit_hash': None,
            'is_valid': False,
            'error': None
        }
        
        # Remove trailing slashes and .git suffix
        url = repo_url.rstrip('/').rstrip('.git')
        
        # Check for commit hash in URL (format: url@commit)
        if '@' in url:
            url_part, commit = url.rsplit('@', 1)
            if COMMIT_HASH_PATTERN.match(commit):
                result['commit_hash'] = commit
                url = url_part
        
        # Check for /commit/ in URL
        if '/commit/' in url:
            parts = url.split('/commit/')
            if len(parts) == 2 and COMMIT_HASH_PATTERN.match(parts[1]):
                result['commit_hash'] = parts[1]
                url = parts[0]
        
        # Check for /tree/ in URL (branch - not a commit hash but we accept it)
        if '/tree/' in url:
            parts = url.split('/tree/')
            url = parts[0]
        
        # Now parse owner/repo from base URL
        if url.startswith('https://github.com/'):
            path = url[len('https://github.com/'):]
            path_parts = path.split('/')
            
            if len(path_parts) >= 2:
                result['owner'] = path_parts[0]
                result['repo'] = path_parts[1]
                result['is_valid'] = True
            else:
                result['error'] = "Invalid GitHub URL: missing owner or repo"
        else:
            result['error'] = "Only GitHub URLs are supported (must start with https://github.com/)"
        
        return result
    
    def _is_trusted_repo(self, owner: str, repo: str) -> tuple[bool, str]:
        """
        Check if a repository is from a trusted source.
        
        Args:
            owner: GitHub organization/user
            repo: Repository name
            
        Returns:
            Tuple of (is_trusted, trust_reason)
        """
        # Check if owner is in trusted organizations
        if owner.lower() in {org.lower() for org in TRUSTED_GITHUB_ORGS}:
            return True, f"Organization '{owner}' is in trusted list"
        
        # Check if specific repo is trusted
        repo_key = f"{owner}/{repo}"
        if repo_key in TRUSTED_REPOS:
            return True, f"Repository '{repo_key}' is explicitly trusted"
        
        return False, "Not in trusted list"
    
    async def request_install_from_github(
        self,
        repo_url: str,
        description: str,
        package_name: Optional[str] = None,
        commit_hash: Optional[str] = None,
        skip_trust_check: bool = False
    ) -> str:
        """
        Request installation of a tool from GitHub with security validation.
        
        This method validates the repository against a trusted list and
        optionally requires a commit hash for reproducibility and security.
        
        Security features:
        - Validates URL format and extracts owner/repo
        - Checks against trusted organizations and repositories
        - Optionally requires commit hash for untrusted repos
        - Logs all installation requests for audit
        
        Args:
            repo_url: GitHub repository URL (e.g., 'https://github.com/user/repo')
            description: What this tool does and why it's needed
            package_name: Optional package name if different from repo name
            commit_hash: Optional specific commit hash for reproducible installs
            skip_trust_check: If True, skip trust validation (for testing)
            
        Returns:
            JSON string with confirmation_required flag and trust status
        """
        logger.info(f"🔧 Tool installation requested: {repo_url}")
        logger.info(f"   Description: {description}")
        
        # Parse and validate the GitHub URL
        parsed = self._parse_github_url(repo_url)
        
        if not parsed['is_valid']:
            return json.dumps({
                "confirmation_required": False,
                "status": "error",
                "error": parsed.get('error', "Invalid GitHub URL")
            })
        
        owner = parsed['owner']
        repo = parsed['repo']
        
        # Use provided commit hash or the one parsed from URL
        effective_commit = commit_hash or parsed['commit_hash']
        
        # Check if repo is trusted
        is_trusted, trust_reason = self._is_trusted_repo(owner, repo)
        
        # For untrusted repos, require commit hash if enforcement is enabled
        if not is_trusted and not skip_trust_check and REQUIRE_COMMIT_HASH_FOR_UNTRUSTED:
            if not effective_commit:
                return json.dumps({
                    "confirmation_required": False,
                    "status": "error",
                    "error": (
                        f"Repository '{owner}/{repo}' is not trusted. "
                        f"A specific commit hash is required for untrusted repositories. "
                        f"Use format: {repo_url}@<commit_hash> or provide commit_hash parameter. "
                        f"Set AEGIS_REQUIRE_COMMIT_HASH=false to disable this requirement."
                    ),
                    "trusted": False,
                    "owner": owner,
                    "repo": repo
                })
        
        # Validate commit hash format if provided
        if effective_commit and not COMMIT_HASH_PATTERN.match(effective_commit):
            return json.dumps({
                "confirmation_required": False,
                "status": "error",
                "error": f"Invalid commit hash format: {effective_commit}. Must be 7-40 hex characters."
            })
        
        # Extract repo name from URL if not provided
        if not package_name:
            package_name = repo
        
        # Build the install URL with optional commit hash
        if effective_commit:
            install_url = f"git+https://github.com/{owner}/{repo}.git@{effective_commit}"
        else:
            install_url = f"git+https://github.com/{owner}/{repo}.git"
        
        # Build trust status message
        if is_trusted:
            trust_status = f"✅ TRUSTED ({trust_reason})"
            trust_icon = "✅"
        else:
            trust_status = f"⚠️  UNTRUSTED - Review carefully before approving"
            trust_icon = "⚠️"
        
        # Build the confirmation request
        confirmation_request = {
            "confirmation_required": True,
            "action": "install_tool",
            "repo_url": repo_url,
            "owner": owner,
            "repo": repo,
            "package_name": package_name,
            "description": description,
            "commit_hash": effective_commit,
            "trusted": is_trusted,
            "trust_reason": trust_reason,
            "install_command": f"pip install {install_url}",
            "message": f"""
{trust_icon} TOOL INSTALLATION REQUEST
{'='*40}
Package: {package_name}
Repository: https://github.com/{owner}/{repo}
Commit: {effective_commit or 'latest (HEAD)'}
Trust Status: {trust_status}

Description: {description}

Command to execute:
  pip install {install_url}

{'⚠️  WARNING: This repository is not in the trusted list. Review the source code before approving.' if not is_trusted else ''}
This action requires your approval to proceed.
"""
        }
        
        logger.info(f"📋 Installation request prepared (trusted={is_trusted}), awaiting confirmation")
        
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


def require_tool(tool_name: str, auto_install: bool = None):
    """
    Self-healing decorator that ensures a tool is available before execution.
    
    If the tool is not available and self-healing is enabled, attempts to
    install the tool automatically.
    
    Args:
        tool_name: Name of the required tool
        auto_install: Override auto-install setting (None = use global setting)
        
    Returns:
        Decorator function
        
    Usage:
        @require_tool("radare2")
        async def analyze_binary(filepath):
            # r2 is guaranteed to be available here
            pass
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            installer = get_tool_installer()
            
            # Check if tool is available
            if not installer.is_tool_available(tool_name):
                logger.warning(f"⚠️ Required tool '{tool_name}' not available")
                
                # Determine if we should auto-install
                should_install = auto_install if auto_install is not None else installer.self_healing
                
                if should_install:
                    logger.info(f"🔧 Self-healing: installing '{tool_name}'...")
                    result = await installer.ensure_tool_available(tool_name, auto_install=True)
                    
                    if result.get("status") != "success":
                        logger.error(f"❌ Failed to install '{tool_name}': {result.get('error')}")
                        return {
                            "status": "error",
                            "error": f"Required tool '{tool_name}' could not be installed: {result.get('error')}",
                            "tool_missing": tool_name
                        }
                    
                    logger.info(f"✅ Tool '{tool_name}' installed successfully")
                else:
                    return {
                        "status": "error",
                        "error": f"Required tool '{tool_name}' is not installed. Enable AEGIS_SELF_HEALING=true or install manually.",
                        "tool_missing": tool_name
                    }
            
            # Tool is available, execute the function
            return await func(*args, **kwargs)
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            installer = get_tool_installer()
            
            # Check if tool is available
            if not installer.is_tool_available(tool_name):
                logger.warning(f"⚠️ Required tool '{tool_name}' not available")
                
                # Determine if we should auto-install
                should_install = auto_install if auto_install is not None else installer.self_healing
                
                if should_install:
                    logger.info(f"🔧 Self-healing: installing '{tool_name}' (sync mode)...")
                    # Run async installation in sync context
                    try:
                        loop = asyncio.get_running_loop()
                    except RuntimeError:
                        loop = None
                    
                    if loop and loop.is_running():
                        # Can't run async in running loop from sync function
                        logger.warning("Cannot auto-install from sync context in running event loop")
                        return {
                            "status": "error",
                            "error": f"Required tool '{tool_name}' is not installed. Run from async context for auto-install.",
                            "tool_missing": tool_name
                        }
                    else:
                        result = asyncio.run(installer.ensure_tool_available(tool_name, auto_install=True))
                        
                        if result.get("status") != "success":
                            logger.error(f"❌ Failed to install '{tool_name}': {result.get('error')}")
                            return {
                                "status": "error",
                                "error": f"Required tool '{tool_name}' could not be installed: {result.get('error')}",
                                "tool_missing": tool_name
                            }
                        
                        logger.info(f"✅ Tool '{tool_name}' installed successfully")
                else:
                    return {
                        "status": "error",
                        "error": f"Required tool '{tool_name}' is not installed. Enable AEGIS_SELF_HEALING=true or install manually.",
                        "tool_missing": tool_name
                    }
            
            # Tool is available, execute the function
            return func(*args, **kwargs)
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def require_tools(*tool_names: str, auto_install: bool = None):
    """
    Self-healing decorator that ensures multiple tools are available.
    
    Args:
        *tool_names: Names of required tools
        auto_install: Override auto-install setting
        
    Returns:
        Decorator function
        
    Usage:
        @require_tools("radare2", "gdb", "objdump")
        async def full_binary_analysis(filepath):
            pass
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            installer = get_tool_installer()
            missing_tools = []
            
            for tool_name in tool_names:
                if not installer.is_tool_available(tool_name):
                    missing_tools.append(tool_name)
            
            if missing_tools:
                should_install = auto_install if auto_install is not None else installer.self_healing
                
                if should_install:
                    logger.info(f"🔧 Self-healing: installing {len(missing_tools)} missing tools...")
                    failed_tools = []
                    
                    for tool_name in missing_tools:
                        result = await installer.ensure_tool_available(tool_name, auto_install=True)
                        if result.get("status") != "success":
                            failed_tools.append(tool_name)
                    
                    if failed_tools:
                        return {
                            "status": "error",
                            "error": f"Failed to install required tools: {', '.join(failed_tools)}",
                            "tools_missing": failed_tools
                        }
                else:
                    return {
                        "status": "error",
                        "error": f"Required tools not installed: {', '.join(missing_tools)}. Enable AEGIS_SELF_HEALING=true.",
                        "tools_missing": missing_tools
                    }
            
            return await func(*args, **kwargs)
        
        return async_wrapper
    
    return decorator
