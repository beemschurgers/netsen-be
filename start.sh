#!/bin/bash

# Start the FastAPI backend with admin privileges
# This script will attempt to run with sudo for packet capture capabilities

echo "Starting NetSen Backend Server..."
echo "Note: Sudo privileges may be required for packet capture functionality"

# Check if uvicorn is available
if ! command -v uvicorn &> /dev/null; then
    echo "Error: uvicorn not found. Please install it with: pip install uvicorn"
    exit 1
fi

# Check if we're in the correct directory
if [ ! -f "main.py" ]; then
    echo "Error: main.py not found. Please run this script from the project root directory."
    exit 1
fi

# Function to start the server
start_server() {
    echo "Starting FastAPI server on http://localhost:8000"
    echo "Access the test dashboard at: http://localhost:8000/test-dashboard"
    echo ""
    echo "Press Ctrl+C to stop the server"
    echo "----------------------------------------"

    # Start the server with reload for development
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload
}

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
