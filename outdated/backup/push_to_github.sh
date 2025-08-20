#!/bin/bash

# Wireshark MCP GitHub Push Script
# Run this after creating the GitHub repositories

echo "🚀 Pushing Wireshark MCP to GitHub repositories..."

# Update remotes with correct URLs
echo "📋 Setting up remotes..."

# Remotes already set correctly, just verify
echo "✅ Remotes already configured correctly"

echo "🔄 Current remotes:"
git remote -v

echo ""
echo "📡 Pushing to personal repository (origin)..."
git push -u origin master

if [ $? -eq 0 ]; then
    echo "✅ Successfully pushed to personal repository"
else
    echo "❌ Failed to push to personal repository"
    echo "Make sure the repository exists: https://github.com/PriestlyPython/wireshark-mcp"
    exit 1
fi

echo ""
echo "📡 Pushing to organization repository (org)..."
git push -u org master

if [ $? -eq 0 ]; then
    echo "✅ Successfully pushed to organization repository"
else
    echo "❌ Failed to push to organization repository"
    echo "Make sure the repository exists: https://github.com/optinampout/wireshark-mcp"
    exit 1
fi

echo ""
echo "🎉 Successfully pushed to both repositories!"
echo "📋 Repositories:"
echo "  - Personal: https://github.com/PriestlyPython/wireshark-mcp"
echo "  - Organization: https://github.com/optinampout/wireshark-mcp"