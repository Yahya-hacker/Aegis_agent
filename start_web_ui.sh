#!/bin/bash
# =============================================================================
# Aegis AI - Modern Web Interface Startup Script
# =============================================================================
# This script starts both the backend API server and the frontend React app
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${PURPLE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║         🛡️  AEGIS AI - Modern Web Interface                   ║"
echo "║         Autonomous Penetration Testing Agent                  ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check for .env file
if [ ! -f ".env" ]; then
    echo -e "${RED}Warning: .env file not found!${NC}"
    echo "Please copy .env.example to .env and configure your API keys."
    echo ""
fi

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to start backend
start_backend() {
    echo -e "${BLUE}🔧 Starting Backend API Server...${NC}"
    
    # Check for Python
    if ! command_exists python3; then
        echo -e "${RED}Error: Python 3 is required but not installed.${NC}"
        exit 1
    fi
    
    # Check/create virtual environment
    if [ ! -d "venv" ]; then
        echo "Creating virtual environment..."
        python3 -m venv venv
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Install backend dependencies
    echo "Installing backend dependencies..."
    pip install -q -r backend/requirements.txt 2>/dev/null || pip install -q -r requirements.txt 2>/dev/null
    
    # Start backend server (bind to localhost for security)
    echo -e "${GREEN}✓ Backend starting on http://localhost:8000${NC}"
    cd backend
    uvicorn server:app --host 127.0.0.1 --port 8000 --reload &
    BACKEND_PID=$!
    cd ..
    
    echo "Backend PID: $BACKEND_PID"
}

# Function to start frontend
start_frontend() {
    echo -e "${CYAN}🎨 Starting Frontend React App...${NC}"
    
    # Check for Node.js
    if ! command_exists node; then
        echo -e "${RED}Error: Node.js is required but not installed.${NC}"
        echo "Please install Node.js 18+ from https://nodejs.org"
        exit 1
    fi
    
    # Check for yarn or npm
    cd frontend
    
    if command_exists yarn; then
        PACKAGE_MANAGER="yarn"
    else
        PACKAGE_MANAGER="npm"
    fi
    
    # Install dependencies if node_modules doesn't exist
    if [ ! -d "node_modules" ]; then
        echo "Installing frontend dependencies with $PACKAGE_MANAGER..."
        $PACKAGE_MANAGER install
    fi
    
    # Start frontend
    echo -e "${GREEN}✓ Frontend starting on http://localhost:3000${NC}"
    $PACKAGE_MANAGER start &
    FRONTEND_PID=$!
    cd ..
    
    echo "Frontend PID: $FRONTEND_PID"
}

# Function to cleanup on exit
cleanup() {
    echo -e "\n${PURPLE}Shutting down Aegis AI...${NC}"
    
    # Kill backend
    if [ ! -z "$BACKEND_PID" ]; then
        kill $BACKEND_PID 2>/dev/null || true
    fi
    
    # Kill frontend
    if [ ! -z "$FRONTEND_PID" ]; then
        kill $FRONTEND_PID 2>/dev/null || true
    fi
    
    # Kill any remaining processes on ports
    lsof -ti:8000 | xargs kill -9 2>/dev/null || true
    lsof -ti:3000 | xargs kill -9 2>/dev/null || true
    
    echo -e "${GREEN}✓ Aegis AI shutdown complete.${NC}"
    exit 0
}

# Set up trap for cleanup
trap cleanup SIGINT SIGTERM

# Main execution
echo ""
echo -e "${PURPLE}Starting Aegis AI services...${NC}"
echo ""

# Parse command line arguments
case "${1:-all}" in
    backend)
        start_backend
        wait $BACKEND_PID
        ;;
    frontend)
        start_frontend
        wait $FRONTEND_PID
        ;;
    all|*)
        start_backend
        sleep 2  # Wait for backend to start
        start_frontend
        
        echo ""
        echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║  🛡️  Aegis AI is running!                                      ║${NC}"
        echo -e "${GREEN}║                                                               ║${NC}"
        echo -e "${GREEN}║  Frontend:  http://localhost:3000                             ║${NC}"
        echo -e "${GREEN}║  Backend:   http://localhost:8000                             ║${NC}"
        echo -e "${GREEN}║  API Docs:  http://localhost:8000/docs                        ║${NC}"
        echo -e "${GREEN}║                                                               ║${NC}"
        echo -e "${GREEN}║  Press Ctrl+C to stop all services                            ║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        # Wait for processes
        wait
        ;;
esac
