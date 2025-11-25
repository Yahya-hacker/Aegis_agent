#!/bin/bash
set -e

echo "🔧 Installing missing tools..."

# Update apt
sudo apt-get update

# Install Nmap and SQLMap
echo "📦 Installing Nmap and SQLMap..."
sudo apt-get install -y nmap sqlmap

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

echo "✅ All tools installed successfully!"
