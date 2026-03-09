#!/bin/bash
# Sandbox setup script for secure Lua execution

set -e

echo "=== Katymio Dumper - Sandbox Setup ==="
echo

# Check for Lua installation
if ! command -v lua &> /dev/null && ! command -v lua5.4 &> /dev/null; then
    echo "❌ Lua interpreter not found!"
    echo "Installing Lua..."
    
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y lua5.4
    elif command -v yum &> /dev/null; then
        sudo yum install -y lua
    elif command -v brew &> /dev/null; then
        brew install lua
    else
        echo "❌ Cannot auto-install Lua. Please install manually."
        exit 1
    fi
fi

echo "✓ Lua interpreter found"

# Verify Python
if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    echo "❌ Python not found!"
    exit 1
fi

echo "✓ Python found"

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

echo
echo "✓ Setup complete!"
echo
echo "To run the bot:"
echo "  1. Copy .env.example to .env"
echo "  2. Add your DISCORD_TOKEN to .env"
echo "  3. Run: python bot.py"
echo
echo "For Railway deployment:"
echo "  1. Push to GitHub"
echo "  2. Connect Railway to your repo"
echo "  3. Add DISCORD_TOKEN environment variable in Railway"
echo "  4. Railway will auto-deploy"
echo
