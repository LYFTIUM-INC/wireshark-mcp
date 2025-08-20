# Create GitHub Repositories

## Step 1: Create Personal Repository
1. Go to https://github.com/PriestlyPython
2. Click "New repository"
3. Repository name: `wireshark-mcp`
4. Description: "🦈 Wireshark MCP Server - Enhanced Edition v2.0"
5. Make it Public
6. Don't initialize with README (we have our own)
7. Click "Create repository"

## Step 2: Create Organization Repository
1. Go to https://github.com/optinampout (or correct organization)
2. Click "New repository"
3. Repository name: `wireshark-mcp`
4. Description: "🦈 Wireshark MCP Server - Enhanced Edition v2.0"
5. Make it Public
6. Don't initialize with README (we have our own)
7. Click "Create repository"

## Step 3: Run Push Script
After creating both repositories, run:
```bash
bash push_to_github.sh
```

## Repository URLs to create:
- Personal: https://github.com/PriestlyPython/wireshark-mcp
- Organization: https://github.com/optinampout/wireshark-mcp

Once created, the push script will handle the rest automatically.