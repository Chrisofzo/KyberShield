#!/bin/bash
set -euo pipefail

# KyberLink VPN - VPS Upload Script
# Upload the built DMG file to your VPS server

# Configuration - Update these with your VPS details
VPS_IP="${VPS_IP:-YOUR_VPS_IP}"
VPS_USER="${VPS_USER:-root}"  # or your VPS username
VPS_PATH="/opt/kyberlink/static/downloads/mac/"

echo "🚀 Uploading KyberLink VPN DMG to VPS..."

# Validate configuration
if [ "$VPS_IP" = "YOUR_VPS_IP" ]; then
    echo "❌ Error: Please set VPS_IP to your actual server IP address"
    echo "Usage: VPS_IP=1.2.3.4 ./upload-to-vps.sh"
    echo "Or edit this script and change VPS_IP=YOUR_VPS_IP to your actual IP"
    exit 1
fi

# Check if DMG file exists
if [ ! -f "static/downloads/mac/latest.dmg" ]; then
    echo "❌ Error: latest.dmg not found in static/downloads/mac/"
    echo "Please build the DMG first using ./build-mac-dmg.sh"
    exit 1
fi

# Create directory on VPS if it doesn't exist
echo "📁 Creating directory on VPS..."
ssh $VPS_USER@$VPS_IP "mkdir -p $VPS_PATH"

# Upload atomically (temp file then move to avoid partial downloads)
echo "📤 Uploading latest.dmg..."
scp static/downloads/mac/latest.dmg $VPS_USER@$VPS_IP:$VPS_PATH/temp.dmg
ssh $VPS_USER@$VPS_IP "cd $VPS_PATH && mv temp.dmg latest.dmg && chmod 644 latest.dmg"

# Verify upload
echo "✅ Upload complete! Testing download URL..."
if curl -f -s -I "http://$VPS_IP/downloads/KyberLinkVPN.dmg" > /dev/null; then
    echo "✅ DMG is accessible at download URL"
else
    echo "⚠️  Warning: Could not verify download URL accessibility"
fi

echo "🌐 Your DMG is available at: http://$VPS_IP/downloads/KyberLinkVPN.dmg"

echo ""
echo "📝 Upload Summary:"
echo "   Local file: static/downloads/mac/latest.dmg"
echo "   VPS location: $VPS_PATH/latest.dmg"
echo "   Download URL: http://$VPS_IP/downloads/KyberLinkVPN.dmg"