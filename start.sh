#!/bin/bash

# CyberSec Assistant Portable - Linux/Mac Launcher
# Cross-platform startup script for Unix-like systems

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║                    🛡️  CYBERSEC ASSISTANT PORTABLE                 ║"
echo "║                                                                  ║"
echo "║              Comprehensive Portable Cybersecurity Toolkit       ║"
echo "║                         Legal Use Only                          ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# Get the directory where this script is located
PORTABLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "📍 Portable Directory: $PORTABLE_DIR"

# Change to portable directory
cd "$PORTABLE_DIR"

# Check for Python
echo "🔍 Checking system requirements..."
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
    echo "✅ Python3 found: $(python3 --version)"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
    echo "✅ Python found: $(python --version)"
else
    echo "❌ Python not found! Please install Python 3.8+ first"
    echo ""
    echo "💡 Installation instructions:"
    echo "   Ubuntu/Debian: sudo apt install python3 python3-pip"
    echo "   CentOS/RHEL:   sudo yum install python3 python3-pip"
    echo "   macOS:         brew install python3"
    echo "   Or download from: https://www.python.org/downloads/"
    echo ""
    read -p "Press Enter to exit..."
    exit 1
fi

# Check for pip
if ! $PYTHON_CMD -m pip --version &> /dev/null; then
    echo "❌ pip not found! Python installation may be incomplete"
    echo "Try: $PYTHON_CMD -m ensurepip --upgrade"
    read -p "Press Enter to exit..."
    exit 1
fi

# Install required packages if needed
echo "📦 Installing required packages..."
$PYTHON_CMD -m pip install requests --quiet

# Make the Python script executable and run it
echo "🚀 Starting CyberSec Assistant..."
$PYTHON_CMD start-portable.py

# Handle exit code
if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Application completed successfully"
else
    echo ""
    echo "❌ Application encountered an error"
fi

echo ""
echo "Press Enter to exit..."
read