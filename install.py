#!/usr/bin/env python3
"""
Automated Installation Script for Aegis Agent
==============================================

Installs all tools, packages, and dependencies required by the Aegis Agent.

This script provides a convenient way for users to set up the entire environment
with a single command, checking for prerequisites and handling errors gracefully.

Usage:
    python3 install.py
    
Requirements:
    - Python 3.8 or higher
    - Go 1.18 or higher (for security tools)
    - sudo privileges (for system packages)
"""

import os
import sys
import subprocess
import shutil
import logging
from pathlib import Path
from typing import List, Tuple, Optional

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'
)
logger = logging.getLogger(__name__)

# Minimum required Python version
MINIMUM_PYTHON_VERSION = (3, 8)


class AegisInstaller:
    """Automated installer for Aegis Agent dependencies."""
    
    def __init__(self):
        """Initialize the installer."""
        self.errors = []
        self.warnings = []
        self.python_version = sys.version_info
        self.go_version = None
        
    def check_python_version(self) -> bool:
        """Check if Python version is compatible."""
        logger.info("🔍 Checking Python version...")
        if self.python_version < MINIMUM_PYTHON_VERSION:
            logger.error(f"❌ Python {MINIMUM_PYTHON_VERSION[0]}.{MINIMUM_PYTHON_VERSION[1]}+ required, found {self.python_version.major}.{self.python_version.minor}")
            return False
        logger.info(f"✅ Python {self.python_version.major}.{self.python_version.minor}.{self.python_version.micro}")
        return True
    
    def check_go_installed(self) -> bool:
        """Check if Go is installed."""
        logger.info("🔍 Checking Go installation...")
        go_path = shutil.which("go")
        if not go_path:
            logger.error("❌ Go is not installed. Please install Go 1.18+ from https://go.dev/dl/")
            return False
        
        try:
            result = subprocess.run(
                ["go", "version"],
                capture_output=True,
                text=True,
                check=True
            )
            version_output = result.stdout.strip()
            logger.info(f"✅ {version_output}")
            return True
        except subprocess.CalledProcessError:
            logger.error("❌ Failed to verify Go installation")
            return False
    
    def run_command(self, cmd: List[str], description: str, check: bool = True) -> Tuple[bool, Optional[str]]:
        """
        Run a command and log the result.
        
        Args:
            cmd: Command and arguments as a list
            description: Human-readable description of what the command does
            check: Whether to raise an exception on non-zero exit code
            
        Returns:
            Tuple of (success: bool, error_message: Optional[str])
        """
        logger.info(f"  • {description}...")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=check
            )
            if result.returncode == 0:
                logger.info(f"    ✅ {description} - Done")
                return True, None
            else:
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                logger.warning(f"    ⚠️ {description} - Failed: {error_msg}")
                return False, error_msg
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip() if e.stderr else str(e)
            logger.error(f"    ❌ {description} - Error: {error_msg}")
            return False, error_msg
        except FileNotFoundError as e:
            error_msg = f"Command not found: {cmd[0]}"
            logger.error(f"    ❌ {description} - {error_msg}")
            return False, error_msg
    
    def install_system_dependencies(self) -> bool:
        """Install system-level dependencies using apt."""
        logger.info("\n📦 Installing System Dependencies...")
        
        # Update package list
        success, _ = self.run_command(
            ["sudo", "apt-get", "update"],
            "Updating package list"
        )
        if not success:
            self.warnings.append("Failed to update package list")
        
        # Install critical packages
        packages = [
            "nmap",
            "sqlmap",
            "libpcap-dev",       # For Naabu
            "python3-venv",      # Python virtual environments
            "python3-pip",       # Python package manager
            "build-essential",   # Compilation tools
            "libffi-dev",        # Foreign Function Interface library
            "python3-dev",       # Python development headers
            "git",               # Version control
        ]
        
        success, error = self.run_command(
            ["sudo", "apt-get", "install", "-y"] + packages,
            f"Installing {len(packages)} system packages"
        )
        
        if not success:
            self.errors.append(f"Failed to install system packages: {error}")
            return False
        
        return True
    
    def install_python_dependencies(self) -> bool:
        """Install Python dependencies from requirements.txt."""
        logger.info("\n🐍 Installing Python Dependencies...")
        
        requirements_file = Path(__file__).parent / "requirements.txt"
        
        if not requirements_file.exists():
            logger.warning(f"⚠️ requirements.txt not found at {requirements_file}")
            self.warnings.append("requirements.txt not found")
            return True  # Not fatal
        
        success, error = self.run_command(
            [sys.executable, "-m", "pip", "install", "-r", str(requirements_file)],
            "Installing Python packages from requirements.txt"
        )
        
        if not success:
            self.errors.append(f"Failed to install Python packages: {error}")
            return False
        
        return True
    
    def install_go_tools(self) -> bool:
        """Install security tools written in Go."""
        logger.info("\n🔧 Installing Go-based Security Tools...")
        
        # Set up Go environment
        gopath = subprocess.run(
            ["go", "env", "GOPATH"],
            capture_output=True,
            text=True
        ).stdout.strip()
        
        if gopath:
            logger.info(f"  GOPATH: {gopath}")
        
        go_tools = [
            ("subfinder", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
            ("nuclei", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
            ("naabu", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
            ("httpx", "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
            ("waybackurls", "github.com/tomnomnom/waybackurls@latest"),
            ("gau", "github.com/lc/gau/v2/cmd/gau@latest"),
        ]
        
        failed_tools = []
        for tool_name, package in go_tools:
            success, error = self.run_command(
                ["go", "install", "-v", package],
                f"Installing {tool_name}"
            )
            if not success:
                failed_tools.append(tool_name)
                self.warnings.append(f"Failed to install {tool_name}: {error}")
        
        if failed_tools:
            logger.warning(f"\n⚠️ Some tools failed to install: {', '.join(failed_tools)}")
            logger.warning("The agent will still work but with reduced capabilities.")
        
        return True  # Not fatal if some tools fail
    
    def install_playwright(self) -> bool:
        """Install Playwright and browser dependencies."""
        logger.info("\n🎭 Installing Playwright and Browser Dependencies...")
        
        # Install Playwright Python package
        success, error = self.run_command(
            [sys.executable, "-m", "pip", "install", "playwright"],
            "Installing Playwright package"
        )
        
        if not success:
            self.warnings.append(f"Failed to install Playwright: {error}")
            return True  # Not fatal
        
        # Install Chromium browser with system dependencies
        success, error = self.run_command(
            [sys.executable, "-m", "playwright", "install", "--with-deps", "chromium"],
            "Installing Chromium browser with dependencies"
        )
        
        if not success:
            self.warnings.append(f"Failed to install Chromium: {error}")
            return True  # Not fatal
        
        return True
    
    def setup_path(self) -> bool:
        """Add Go bin directory to PATH in shell config files."""
        logger.info("\n🛤️ Setting up PATH...")
        
        try:
            gopath = subprocess.run(
                ["go", "env", "GOPATH"],
                capture_output=True,
                text=True
            ).stdout.strip()
            
            if not gopath:
                logger.warning("⚠️ Could not determine GOPATH")
                return True  # Not fatal
            
            gobin = os.path.join(gopath, "bin")
            path_export = f'export PATH=$PATH:{gobin}'
            
            # Add to .bashrc
            bashrc = Path.home() / ".bashrc"
            if bashrc.exists():
                with open(bashrc, 'r') as f:
                    content = f.read()
                if gobin not in content:
                    with open(bashrc, 'a') as f:
                        f.write(f'\n# Added by Aegis Agent installer\n{path_export}\n')
                    logger.info(f"  ✅ Added {gobin} to .bashrc")
            
            # Add to .zshrc if it exists
            zshrc = Path.home() / ".zshrc"
            if zshrc.exists():
                with open(zshrc, 'r') as f:
                    content = f.read()
                if gobin not in content:
                    with open(zshrc, 'a') as f:
                        f.write(f'\n# Added by Aegis Agent installer\n{path_export}\n')
                    logger.info(f"  ✅ Added {gobin} to .zshrc")
            
            # Also set for current session
            os.environ['PATH'] = f"{os.environ.get('PATH', '')}:{gobin}"
            
            return True
        except Exception as e:
            logger.warning(f"⚠️ Failed to setup PATH: {e}")
            self.warnings.append(f"Failed to setup PATH: {e}")
            return True  # Not fatal
    
    def verify_installation(self) -> bool:
        """Verify that key tools were installed successfully."""
        logger.info("\n✅ Verifying Installation...")
        
        tools_to_check = [
            "subfinder",
            "nuclei",
            "naabu",
            "httpx",
            "waybackurls",
            "gau",
            "nmap",
            "sqlmap",
        ]
        
        installed = []
        missing = []
        
        for tool in tools_to_check:
            if shutil.which(tool):
                installed.append(tool)
                logger.info(f"  ✅ {tool}")
            else:
                missing.append(tool)
                logger.warning(f"  ⚠️ {tool} not found in PATH")
        
        logger.info(f"\n📊 Installation Summary:")
        logger.info(f"  Installed: {len(installed)}/{len(tools_to_check)}")
        
        if missing:
            logger.warning(f"  Missing: {', '.join(missing)}")
            logger.warning(f"  Note: You may need to restart your shell or run: source ~/.bashrc")
        
        return True
    
    def run(self) -> int:
        """
        Run the full installation process.
        
        Returns:
            Exit code (0 for success, 1 for failure)
        """
        logger.info("=" * 70)
        logger.info("🛡️  AEGIS AGENT - AUTOMATED INSTALLER")
        logger.info("=" * 70)
        logger.info("")
        
        # Check prerequisites
        if not self.check_python_version():
            return 1
        
        if not self.check_go_installed():
            logger.error("\n❌ Installation cannot proceed without Go")
            logger.error("Please install Go from: https://go.dev/dl/")
            return 1
        
        # Run installation steps
        steps = [
            ("System Dependencies", self.install_system_dependencies),
            ("Python Dependencies", self.install_python_dependencies),
            ("Go Security Tools", self.install_go_tools),
            ("Playwright", self.install_playwright),
            ("PATH Setup", self.setup_path),
            ("Verification", self.verify_installation),
        ]
        
        for step_name, step_func in steps:
            try:
                success = step_func()
                if not success and step_name in ["System Dependencies", "Python Dependencies"]:
                    logger.error(f"\n❌ Critical step '{step_name}' failed")
                    logger.error("Installation cannot continue")
                    return 1
            except Exception as e:
                logger.error(f"\n❌ Unexpected error in '{step_name}': {e}")
                self.errors.append(f"{step_name}: {e}")
                if step_name in ["System Dependencies", "Python Dependencies"]:
                    return 1
        
        # Final summary
        logger.info("\n" + "=" * 70)
        if self.errors:
            logger.error(f"❌ Installation completed with {len(self.errors)} error(s):")
            for error in self.errors:
                logger.error(f"  • {error}")
            return 1
        elif self.warnings:
            logger.warning(f"⚠️ Installation completed with {len(self.warnings)} warning(s):")
            for warning in self.warnings:
                logger.warning(f"  • {warning}")
            logger.info("\n✅ Aegis Agent is ready to use (with some optional features disabled)")
        else:
            logger.info("✅ Installation completed successfully!")
            logger.info("🎉 Aegis Agent is ready to use!")
        
        logger.info("\nNext steps:")
        logger.info("  1. Restart your shell or run: source ~/.bashrc")
        logger.info("  2. Copy .env.example to .env and configure your API keys")
        logger.info("  3. Run: python3 main.py")
        logger.info("=" * 70)
        
        return 0


def main():
    """Main entry point."""
    installer = AegisInstaller()
    exit_code = installer.run()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
