#!/bin/bash

# KyberLink VPN - Git Command Aliases
# Source this file to get easy Git commands: source ./git-aliases.sh

echo "🔗 Loading KyberLink VPN Git Aliases..."

# Alias for automatic sync
alias gitsync='./git-auto-sync.sh'

# Alias for manual sync  
alias gitmanual='./git-manual-sync.sh'

# Alias for quick commit
alias gitquick='./git-quick-commit.sh'

# Traditional git shortcuts
alias gitstatus='git status'
alias gitlog='git log --oneline -10'
alias gitremote='git remote -v'

echo "✅ Git aliases loaded! Available commands:"
echo "  🔄 gitsync     - Auto sync with GitHub"
echo "  🚀 gitmanual   - Manual full sync"  
echo "  ⚡ gitquick    - Quick commit with message"
echo "  📊 gitstatus   - Show git status"
echo "  📜 gitlog      - Show recent commits"
echo "  🌐 gitremote   - Show remote URLs"
echo ""
echo "Examples:"
echo "  gitsync"
echo "  gitquick 'Fixed dashboard bug'"
echo "  gitmanual"