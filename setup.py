#!/usr/bin/env python3
"""
Aegis Agent - Automated Setup Script
=====================================

This script automates the complete setup process for the Aegis Agent:
1. Checks system requirements
2. Installs Python dependencies
3. Installs security tools (Go-based tools, Playwright, etc.)
4. Configures environment variables
5. Initializes databases and directories
6. Verifies installation

Usage:
    python setup.py

After setup, start the agent with:
    python main.py
"""

import os
import sys
import subprocess
import shutil
import logging
from pathlib import Path
from typing import List, Tuple, Optional, Dict
import json

# Setup logging with colors
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'
)
logger = logging.getLogger(__name__)

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Minimum required versions
MINIMUM_PYTHON_VERSION = (3, 8)
MINIMUM_GO_VERSION = "1.18"


class AegisSetup:
    """Comprehensive setup automation for Aegis Agent."""
    
    def __init__(self):
        """Initialize the setup manager."""
        self.script_dir = Path(__file__).parent.resolve()
        self.errors = []
        self.warnings = []
        self.installed_tools = []
        self.failed_tools = []
        
    def print_header(self):
        """Print setup header."""
        print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.HEADER}   Aegis Agent v8.0 - Automated Setup{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.HEADER}   Full-Spectrum Cyber Operations Platform{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
        
    def print_section(self, title: str):
        """Print section header."""
        print(f"\n{Colors.BOLD}{Colors.OKCYAN}▶ {title}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}{'─'*70}{Colors.ENDC}")
        
    def print_success(self, message: str):
        """Print success message."""
        print(f"{Colors.OKGREEN}✅ {message}{Colors.ENDC}")
        
    def print_error(self, message: str):
        """Print error message."""
        print(f"{Colors.FAIL}❌ {message}{Colors.ENDC}")
        self.errors.append(message)
        
    def print_warning(self, message: str):
        """Print warning message."""
        print(f"{Colors.WARNING}⚠️  {message}{Colors.ENDC}")
        self.warnings.append(message)
        
    def print_info(self, message: str):
        """Print info message."""
        print(f"{Colors.OKBLUE}ℹ️  {message}{Colors.ENDC}")
        
    def run_command(self, cmd: List[str], description: str, check: bool = True, 
                    capture_output: bool = True) -> Tuple[bool, Optional[str]]:
        """
        Run a command and return success status.
        
        Args:
            cmd: Command and arguments as list
            description: Description of what the command does
            check: Whether to check return code
            capture_output: Whether to capture stdout/stderr
            
        Returns:
            Tuple of (success, output/error)
        """
        try:
            result = subprocess.run(
                cmd,
                capture_output=capture_output,
                text=True,
                check=check,
                cwd=str(self.script_dir)
            )
            if result.returncode == 0:
                return True, result.stdout if capture_output else None
            return False, result.stderr if capture_output else None
        except subprocess.CalledProcessError as e:
            return False, str(e)
        except FileNotFoundError:
            return False, f"Command not found: {cmd[0]}"
        except Exception as e:
            return False, str(e)
            
    def check_python_version(self) -> bool:
        """Check if Python version meets requirements."""
        self.print_section("1. Checking Python Version")
        
        version = sys.version_info
        if version < MINIMUM_PYTHON_VERSION:
            self.print_error(
                f"Python {MINIMUM_PYTHON_VERSION[0]}.{MINIMUM_PYTHON_VERSION[1]}+ required, "
                f"found {version.major}.{version.minor}.{version.micro}"
            )
            return False
            
        self.print_success(
            f"Python {version.major}.{version.minor}.{version.micro} detected"
        )
        return True
        
    def check_go_installation(self) -> bool:
        """Check if Go is installed."""
        self.print_section("2. Checking Go Installation")
        
        if not shutil.which("go"):
            self.print_warning(
                "Go is not installed. Some security tools will be unavailable."
            )
            self.print_info("Install Go from: https://go.dev/dl/")
            return False
            
        success, output = self.run_command(["go", "version"], "Check Go version")
        if success and output:
            self.print_success(output.strip())
            return True
        return False
        
    def install_python_dependencies(self) -> bool:
        """Install Python dependencies from requirements.txt."""
        self.print_section("3. Installing Python Dependencies")
        
        requirements_file = self.script_dir / "requirements.txt"
        if not requirements_file.exists():
            self.print_error("requirements.txt not found")
            return False
            
        self.print_info("Installing packages from requirements.txt...")
        success, output = self.run_command(
            [sys.executable, "-m", "pip", "install", "-r", str(requirements_file)],
            "Install Python dependencies",
            capture_output=False
        )
        
        if success:
            self.print_success("Python dependencies installed successfully")
            return True
        else:
            self.print_error("Failed to install Python dependencies")
            return False
            
    def install_playwright_browsers(self) -> bool:
        """Install Playwright browsers."""
        self.print_section("4. Installing Playwright Browsers")
        
        self.print_info("Installing Chromium for Playwright...")
        success, output = self.run_command(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            "Install Playwright Chromium",
            capture_output=False
        )
        
        if success:
            self.print_success("Playwright Chromium installed successfully")
            return True
        else:
            self.print_warning("Failed to install Playwright browsers (optional)")
            return False
            
    def install_go_security_tools(self) -> bool:
        """Install Go-based security tools."""
        self.print_section("5. Installing Go-Based Security Tools (Optional)")
        
        if not shutil.which("go"):
            self.print_warning("Go not available, skipping Go tools installation")
            return False
            
        go_tools = [
            ("github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "Subfinder"),
            ("github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "Nuclei"),
            ("github.com/projectdiscovery/httpx/cmd/httpx@latest", "HTTPX"),
            ("github.com/lc/gau/v2/cmd/gau@latest", "GAU"),
            ("github.com/tomnomnom/waybackurls@latest", "Waybackurls"),
        ]
        
        for tool_path, tool_name in go_tools:
            self.print_info(f"Installing {tool_name}...")
            success, output = self.run_command(
                ["go", "install", "-v", tool_path],
                f"Install {tool_name}",
                check=False
            )
            
            if success:
                self.print_success(f"{tool_name} installed")
                self.installed_tools.append(tool_name)
            else:
                self.print_warning(f"Failed to install {tool_name} (optional)")
                self.failed_tools.append(tool_name)
                
        return len(self.installed_tools) > 0
        
    def setup_environment_file(self) -> bool:
        """Setup .env file from example."""
        self.print_section("6. Configuring Environment Variables")
        
        env_example = self.script_dir / ".env.example"
        env_file = self.script_dir / ".env"
        
        if env_file.exists():
            self.print_info(".env file already exists")
            
            response = input(f"{Colors.WARNING}   Overwrite existing .env? (y/N): {Colors.ENDC}").strip().lower()
            if response != 'y':
                self.print_info("Keeping existing .env file")
                return True
                
        if not env_example.exists():
            self.print_error(".env.example not found")
            return False
            
        # Copy .env.example to .env
        shutil.copy(env_example, env_file)
        self.print_success("Created .env file from template")
        
        # Prompt for OpenRouter API key
        print(f"\n{Colors.BOLD}   Configuration Required:{Colors.ENDC}")
        print(f"   {Colors.OKBLUE}To use Aegis Agent, you need an OpenRouter API key.{Colors.ENDC}")
        print(f"   {Colors.OKBLUE}Get one at: https://openrouter.ai/{Colors.ENDC}\n")
        
        api_key = input(f"   Enter your OpenRouter API key (or press Enter to skip): ").strip()
        
        if api_key:
            # Update .env file with API key
            with open(env_file, 'r') as f:
                content = f.read()
            
            content = content.replace(
                "OPENROUTER_API_KEY=your_openrouter_api_key_here",
                f"OPENROUTER_API_KEY={api_key}"
            )
            
            with open(env_file, 'w') as f:
                f.write(content)
            
            self.print_success("API key configured in .env")
        else:
            self.print_warning("API key not configured. You'll need to edit .env manually.")
            
        return True
        
    def create_directories(self) -> bool:
        """Create necessary directories."""
        self.print_section("7. Creating Directory Structure")
        
        directories = [
            "logs",
            "data",
            "data/sessions",
            "data/screenshots",
            "data/reports",
            "data/http_memory",
            "output",
            "results",
        ]
        
        for dir_name in directories:
            dir_path = self.script_dir / dir_name
            dir_path.mkdir(parents=True, exist_ok=True)
            
        self.print_success("Directory structure created")
        return True
        
    def verify_installation(self) -> bool:
        """Verify installation by checking key files and imports."""
        self.print_section("8. Verifying Installation")
        
        # Check key Python imports
        test_imports = [
            "aiohttp",
            "aiofiles",
            "httpx",
            "dotenv",
            "beautifulsoup4",
            "selenium",
            "playwright",
            "networkx",
            "json_repair",
        ]
        
        failed_imports = []
        for module_name in test_imports:
            try:
                # Special handling for some module names
                import_name = module_name
                if module_name == "dotenv":
                    import_name = "dotenv"
                elif module_name == "beautifulsoup4":
                    import_name = "bs4"
                elif module_name == "json_repair":
                    import_name = "json_repair"
                    
                __import__(import_name)
            except ImportError:
                failed_imports.append(module_name)
                
        if failed_imports:
            self.print_warning(f"Some modules failed to import: {', '.join(failed_imports)}")
        else:
            self.print_success("All Python modules verified")
            
        # Check key files
        key_files = [
            "main.py",
            "app.py",
            "agents/enhanced_ai_core.py",
            "agents/conversational_agent.py",
            "tools/tool_manager.py",
        ]
        
        missing_files = []
        for file_path in key_files:
            if not (self.script_dir / file_path).exists():
                missing_files.append(file_path)
                
        if missing_files:
            self.print_error(f"Missing key files: {', '.join(missing_files)}")
            return False
        else:
            self.print_success("All key files verified")
            
        return True
        
    def print_summary(self):
        """Print setup summary."""
        print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.HEADER}   Setup Summary{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
        
        if self.installed_tools:
            print(f"{Colors.OKGREEN}Installed Go Tools ({len(self.installed_tools)}):{Colors.ENDC}")
            for tool in self.installed_tools:
                print(f"  ✅ {tool}")
                
        if self.failed_tools:
            print(f"\n{Colors.WARNING}Failed Go Tools ({len(self.failed_tools)}):{Colors.ENDC}")
            for tool in self.failed_tools:
                print(f"  ⚠️  {tool} (optional)")
                
        if self.warnings:
            print(f"\n{Colors.WARNING}Warnings ({len(self.warnings)}):{Colors.ENDC}")
            for warning in self.warnings:
                print(f"  ⚠️  {warning}")
                
        if self.errors:
            print(f"\n{Colors.FAIL}Errors ({len(self.errors)}):{Colors.ENDC}")
            for error in self.errors:
                print(f"  ❌ {error}")
            print(f"\n{Colors.FAIL}Setup completed with errors. Please fix them before running.{Colors.ENDC}")
        else:
            print(f"\n{Colors.OKGREEN}{Colors.BOLD}✅ Setup completed successfully!{Colors.ENDC}\n")
            print(f"{Colors.OKBLUE}Next steps:{Colors.ENDC}")
            print(f"  1. Review and edit .env file if needed")
            print(f"  2. Start the agent: {Colors.BOLD}python main.py{Colors.ENDC}")
            print(f"  3. Or use the web UI: {Colors.BOLD}streamlit run app.py{Colors.ENDC}\n")
            
    def run_setup(self) -> int:
        """Run the complete setup process."""
        self.print_header()
        
        # Step 1: Check Python version
        if not self.check_python_version():
            return 1
            
        # Step 2: Check Go installation
        self.check_go_installation()
        
        # Step 3: Install Python dependencies
        if not self.install_python_dependencies():
            return 1
            
        # Step 4: Install Playwright browsers
        self.install_playwright_browsers()
        
        # Step 5: Install Go security tools
        self.install_go_security_tools()
        
        # Step 6: Setup environment file
        if not self.setup_environment_file():
            return 1
            
        # Step 7: Create directories
        if not self.create_directories():
            return 1
            
        # Step 8: Verify installation
        self.verify_installation()
        
        # Print summary
        self.print_summary()
        
        return 0 if not self.errors else 1


def main():
    """Main entry point."""
    setup = AegisSetup()
    return setup.run_setup()


if __name__ == "__main__":
    sys.exit(main())
