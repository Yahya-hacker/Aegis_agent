#!/bin/bash
set -e

echo "🔧 Installing missing tools..."

echo "🔧 Installing System Dependencies (Critical)..."
sudo apt-get update
# Added libpcap-dev (for Naabu) and python3-venv, build-essential for compilation
sudo apt-get install -y nmap sqlmap libpcap-dev python3-venv build-essential libffi-dev python3-dev git

# Install Go tools
echo "📦 Installing Go tools..."

# Check if go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go first."
    exit 1
fi

# Install ProjectDiscovery tools
echo "  • Installing subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "  • Installing nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo "  • Installing naabu..."
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

echo "  • Installing httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install other tools
echo "  • Installing waybackurls..."
go install github.com/tomnomnom/waybackurls@latest

echo "  • Installing gau..."
go install github.com/lc/gau/v2/cmd/gau@latest

# Add Go bin to PATH if not already there
export PATH=$PATH:$(go env GOPATH)/bin
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.zshrc
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc

echo "🔧 Installing Playwright System Dependencies..."
# This is the missing magic line for the 'Cannot find Chrome' error
pip install playwright
playwright install --with-deps chromium

echo "✅ Environment is battle-ready."
