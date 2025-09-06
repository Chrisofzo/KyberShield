#!/bin/bash

# KyberLink VPN - Quick Commit Script
# Quickly commit and push specific changes

if [ "$#" -eq 0 ]; then
    echo "Usage: ./git-quick-commit.sh \"Your commit message\""
    echo "Example: ./git-quick-commit.sh \"Fix navigation bug\""
    exit 1
fi

echo "⚡ Quick Commit: KyberLink VPN"

# Navigate to project directory
cd "$(dirname "$0")"

# Add all changes
git add .

# Commit with provided message
git commit -m "Update: $1"

# Push to remote
git push origin main

echo "✅ Quick commit completed: $1"