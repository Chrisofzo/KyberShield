#!/bin/bash

# KyberLink VPN - Automated Git Sync Script
# This script automatically syncs changes with the QuantumVPN GitHub repository

set -e  # Exit on any error

echo "🔄 KyberLink VPN - Auto Git Sync Starting..."

# Navigate to project directory
cd "$(dirname "$0")"

# Function to get changed files for commit message
get_changed_files() {
    git diff --cached --name-only | head -3 | tr '\n' ' ' | sed 's/ *$//'
}

# Function to generate commit message based on changed files
generate_commit_message() {
    local changed_files=$(get_changed_files)
    if [[ -n "$changed_files" ]]; then
        echo "Update: $changed_files - KyberLink VPN improvements"
    else
        echo "Update: KyberLink VPN - general improvements and fixes"
    fi
}

# Pull latest changes from remote (avoid conflicts)
echo "📥 Pulling latest changes from GitHub..."
git fetch origin main
git pull origin main --rebase --autostash || {
    echo "⚠️  Pull conflicts detected. Attempting to resolve..."
    git rebase --abort 2>/dev/null || true
    git pull origin main --no-rebase
}

# Check if there are any changes to commit
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "📝 Changes detected. Staging files..."
    
    # Add all changes
    git add .
    
    # Generate commit message
    COMMIT_MSG=$(generate_commit_message)
    echo "💬 Commit message: $COMMIT_MSG"
    
    # Commit changes
    git commit -m "$COMMIT_MSG" || {
        echo "ℹ️  Nothing new to commit."
        exit 0
    }
    
    # Push to GitHub
    echo "📤 Pushing to GitHub (QuantumVPN repository)..."
    git push origin main
    
    echo "✅ Successfully synced KyberLink VPN to GitHub!"
else
    echo "ℹ️  No changes detected. Repository is up to date."
fi

echo "🎉 Auto-sync complete!"