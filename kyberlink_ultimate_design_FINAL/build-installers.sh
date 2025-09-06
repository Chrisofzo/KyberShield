#!/bin/bash
# KyberLink VPN - Automated Installer Build Script

echo "🚀 KyberLink VPN - Building Cross-Platform Installers"
echo "=================================================="

# Build React app
echo "📦 Building React application..."
npm run build

if [ $? -ne 0 ]; then
    echo "❌ React build failed"
    exit 1
fi

echo "✅ React build completed"

# Build Electron installers
echo "🔧 Building Electron installers for all platforms..."
npm run dist

if [ $? -ne 0 ]; then
    echo "❌ Electron build failed"
    exit 1
fi

echo "✅ Electron installers built successfully"

# Copy installers to downloads directory
echo "📋 Copying installers to downloads directory..."

# Create downloads directory if it doesn't exist
mkdir -p static/downloads/{windows,mac,linux}

# Find and copy the latest installers
if [ -f "dist/KyberLink VPN Setup *.exe" ]; then
    cp "dist/KyberLink VPN Setup"*.exe static/downloads/windows/latest.exe
    echo "✅ Windows installer copied"
fi

if [ -f "dist/KyberLink VPN-*.dmg" ]; then
    cp "dist/KyberLink VPN-"*.dmg static/downloads/mac/latest.dmg
    echo "✅ macOS installer copied"
fi

if [ -f "dist/KyberLink VPN-*.AppImage" ]; then
    cp "dist/KyberLink VPN-"*.AppImage static/downloads/linux/latest.AppImage
    echo "✅ Linux installer copied"
fi

echo "🎉 Build process completed!"
echo "Installers are now available at:"
echo "  • Windows: /downloads/windows/latest.exe"
echo "  • macOS: /downloads/mac/latest.dmg"
echo "  • Linux: /downloads/linux/latest.AppImage"