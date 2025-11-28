import shutil
import logging
import sys
import os

logger = logging.getLogger(__name__)

def check_dependencies():
    """
    Checks if critical external tools are installed and available in PATH.
    Returns True if all critical tools are found, False otherwise.
    """
    critical_tools = [
        "node",       # Required for JS sandboxing
        "nmap",       # Required for port scanning
    ]

    recommended_tools = [
        "nuclei",     # Vulnerability scanning
        "subfinder",  # Subdomain enumeration
        "naabu",      # Port scanning
        "httpx",      # Web probing
        "sqlmap"      # SQL injection
    ]

    missing_critical = []
    missing_recommended = []

    print("\n🔍 Checking system dependencies...")

    # Check critical tools
    for tool in critical_tools:
        if shutil.which(tool):
            print(f"  ✅ Found {tool}")
        else:
            print(f"  ❌ Missing CRITICAL tool: {tool}")
            missing_critical.append(tool)

    # Check recommended tools
    for tool in recommended_tools:
        if shutil.which(tool):
            print(f"  ✅ Found {tool}")
        else:
            print(f"  ⚠️  Missing recommended tool: {tool}")
            missing_recommended.append(tool)

    # Check for Chrome/Chromium (custom check for multiple paths)
    chrome_paths = [
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/snap/bin/chromium",
        "/usr/local/bin/google-chrome",
    ]

    chrome_found = False
    for path in chrome_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            print(f"  ✅ Found Chrome/Chromium at {path}")
            chrome_found = True
            break

    if not chrome_found:
        # Try 'which'
        if shutil.which("google-chrome") or shutil.which("chromium"):
             print(f"  ✅ Found Chrome/Chromium via PATH")
             chrome_found = True
        else:
             print("  ❌ Missing CRITICAL tool: Chrome/Chromium (Required for Selenium)")
             missing_critical.append("chrome")

    print("")

    if missing_critical:
        print("❌ CRITICAL ERROR: Missing required dependencies.")
        print(f"   Please install: {', '.join(missing_critical)}")
        print("   The agent cannot function correctly without these tools.")
        return False

    if missing_recommended:
        print("⚠️  WARNING: Some recommended tools are missing.")
        print("   The agent will work, but with reduced capabilities.")
        print(f"   Consider installing: {', '.join(missing_recommended)}")

    return True
