#!/bin/bash

# Start the FastAPI backend with admin privileges
# This script will attempt to run with sudo for packet capture capabilities

echo "Starting NetSen Backend Server..."
echo "Note: Sudo privileges may be required for packet capture functionality"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if uvicorn is available
if ! command -v uvicorn &> /dev/null; then
    echo "Error: uvicorn not found. Please install it with: pip install uvicorn"
    exit 1
fi

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed or not in PATH.${NC}"
    exit 1
fi

# Check if we're in the correct directory
if [ ! -f "main.py" ]; then
    echo -e "${RED}Error: main.py not found. Please run this script from the project root directory.${NC}"
    exit 1
fi

# Function to kill processes on port 8000
kill_port_8000() {
    echo -e "${YELLOW}Checking for processes running on port 8000...${NC}"

    # Find processes using port 8000
    PIDS=$(lsof -ti:8000)

    if [ -n "$PIDS" ]; then
        echo -e "${YELLOW}Found processes running on port 8000. Killing them...${NC}"
        echo "$PIDS" | xargs kill -9
        sleep 2
        echo -e "${GREEN}Port 8000 is now free.${NC}"
    else
        echo -e "${GREEN}Port 8000 is already free.${NC}"
    fi
}

# Function to start the server
start_server() {
    echo -e "${GREEN}Starting FastAPI server on http://localhost:8000${NC}"
    echo -e "${GREEN}Access the test dashboard at: http://localhost:8000/test-dashboard${NC}"
    echo ""
    echo -e "${YELLOW}Press Ctrl+C to stop the server${NC}"
    echo "----------------------------------------"

    # Start the server with reload for development
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload
}

# Main execution
echo "========================================="
echo "       FastAPI Server Startup Script    "
echo "========================================="

# Kill any existing processes on port 8000
kill_port_8000

# Ask user if they want to run with sudo for packet capture
echo ""
echo "Do you want to run with sudo privileges? (recommended for packet capture)"
echo "y) Yes - Run with sudo (enables real packet capture)"
echo "n) No  - Run without sudo (uses mock data for testing)"
echo ""
read -p "Choose [y/n]: " choice

case $choice in
    [Yy]* )
        echo "Starting with sudo privileges..."
        sudo bash -c "$(declare -f start_server); start_server"
        ;;
    [Nn]* )
        echo "Starting without sudo (mock data mode)..."
        start_server
        ;;
    * )
        echo "Invalid choice. Starting without sudo..."
        start_server
        ;;
esac
