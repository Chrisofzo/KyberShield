#!/bin/bash

echo "🚀 Building KyberShield VPN Desktop Applications"
echo "================================================"

# Clean previous builds
rm -rf dist/

# Build for all platforms
echo ""
echo "📦 Building for Windows..."
npm run build:win || echo "Windows build skipped (requires Windows or Wine)"

echo ""
echo "🍎 Building for macOS..."
npm run build:mac || echo "macOS build skipped (requires macOS)"

echo ""
echo "🐧 Building for Linux..."
npm run build:linux

echo ""
echo "✅ Build complete! Check the 'dist' directory for installers."
echo ""
echo "Available installers:"
ls -la dist/ 2>/dev/null || echo "No builds found. Please run on appropriate platform."