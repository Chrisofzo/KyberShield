#!/bin/bash

# KyberLink VPN - Manual Git Sync Script
# Use this script to manually trigger a complete Git sync

echo "🚀 KyberLink VPN - Manual Git Sync"
echo "=================================="

# Navigate to project directory
cd "$(dirname "$0")"

# Show current status
echo "📊 Current Git Status:"
git status --short

echo ""
echo "🔄 Performing manual sync..."

# Pull latest changes
echo "1️⃣ Pulling from GitHub..."
git pull origin main

# Add all changes
echo "2️⃣ Staging all changes..."
git add .

# Show what will be committed
echo "📝 Files to be committed:"
git diff --cached --name-only

# Commit with manual message
echo "3️⃣ Committing changes..."
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
git commit -m "Manual update: KyberLink VPN - $TIMESTAMP" || {
    echo "ℹ️  No changes to commit."
    exit 0
}

# Push to remote
echo "4️⃣ Pushing to GitHub (QuantumVPN repository)..."
git push origin main

echo ""
echo "✅ Manual sync completed successfully!"
echo "🌐 Repository: https://github.com/Chrisofzo/QuantumVPN"