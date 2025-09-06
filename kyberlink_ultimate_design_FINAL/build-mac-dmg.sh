#!/bin/bash
set -euo pipefail

# KyberLink VPN - macOS DMG Build Script
# Run this script on your MacBook to build the .dmg installer

echo "🍎 Building KyberLink VPN for macOS..."

# Check if we're on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo "❌ Error: This script must be run on macOS to build .dmg files"
    exit 1
fi

# Verify we're in the correct directory
if [ ! -f "package.json" ] || [ ! -f "electron.js" ]; then
    echo "❌ Error: Run this script from the project root containing package.json and electron.js"
    exit 1
fi

# Create downloads directory
mkdir -p static/downloads/mac

# Install dependencies if not present
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies..."
    npm ci
fi

# Build React frontend
echo "⚛️  Building React frontend..."
npm run build

# Build macOS DMG installer
echo "📱 Building macOS DMG installer..."
npm run dist -- --mac

# Get the built DMG (using proper glob handling)
shopt -s nullglob
dmg_files=(dist/KyberLinkVPN-*.dmg)
if [[ ${#dmg_files[@]} -eq 0 ]]; then
    echo "❌ Error: DMG file was not created"
    echo "Expected: dist/KyberLinkVPN-*.dmg"
    ls -la dist/ || true
    exit 1
fi

dmg_file="${dmg_files[0]}"
echo "✅ macOS DMG built successfully!"
echo "📂 Location: $dmg_file"

# Copy to downloads folder for Flask
cp "$dmg_file" static/downloads/mac/latest.dmg
echo "📋 Copied to static/downloads/mac/latest.dmg"

echo ""
echo "🚀 Next steps:"
echo "1. Update VPS_IP in upload-to-vps.sh with your server IP"
echo "2. Run ./upload-to-vps.sh to upload to your VPS"
echo "3. The Flask server will serve it at /downloads/KyberLinkVPN.dmg"