#!/bin/bash
# Node.js setup script for Katymio Dumper

set -e

echo "=== Katymio Dumper - Node.js Setup ==="
echo

# Check for Node.js installation
if ! command -v node &> /dev/null; then
    echo "❌ Node.js not found!"
    echo "Please install Node.js 18+ from https://nodejs.org/"
    exit 1
fi

NODE_VERSION=$(node -e "process.stdout.write(process.versions.node)")
MAJOR_VERSION=$(echo "$NODE_VERSION" | cut -d. -f1)
if [ "$MAJOR_VERSION" -lt 18 ]; then
    echo "❌ Node.js 18+ is required (found $NODE_VERSION)"
    exit 1
fi

echo "✓ Node.js $NODE_VERSION found"

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
        echo "❌ Cannot auto-install Lua. Please install manually from https://lua.org/"
        exit 1
    fi
fi

echo "✓ Lua interpreter found"

# Install Node.js dependencies
echo "Installing Node.js dependencies..."
npm install

echo
echo "✓ Setup complete!"
echo
echo "To run the bot:"
echo "  1. Copy .env.example to .env"
echo "  2. Add your DISCORD_TOKEN to .env"
echo "  3. Run: node bot.js   (or: npm start)"
echo
