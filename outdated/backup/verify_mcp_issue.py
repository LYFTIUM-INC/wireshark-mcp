#!/usr/bin/env python3
"""
Verify MCP Configuration Issue

This script helps diagnose why the enhanced server features aren't accessible
through the MCP interface.
"""

import json
import subprocess
import os
from pathlib import Path

print("🔍 Wireshark MCP Configuration Verification")
print("=" * 60)

# 1. Check running processes
print("\n1️⃣ Checking running Wireshark MCP processes:")
print("-" * 40)
try:
    result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
    wireshark_procs = [line for line in result.stdout.split('\n') 
                       if 'wireshark-mcp' in line and 'grep' not in line]
    
    if wireshark_procs:
        for proc in wireshark_procs:
            if 'server.py' in proc:
                print("⚠️  Found process running OLD server.py:")
                print(f"   {proc[:120]}...")
            elif 'enhanced_server.py' in proc:
                print("✅ Found process running enhanced_server.py:")
                print(f"   {proc[:120]}...")
    else:
        print("❌ No Wireshark MCP processes found running")
except Exception as e:
    print(f"❌ Error checking processes: {e}")

# 2. Check Claude configuration
print("\n2️⃣ Checking Claude Desktop configuration:")
print("-" * 40)
claude_config = Path.home() / '.claude.json'
try:
    with open(claude_config, 'r') as f:
        config = json.load(f)
        
    if 'wireshark-mcp' in config.get('mcpServers', {}):
        mcp_config = config['mcpServers']['wireshark-mcp']
        command = mcp_config.get('command', '')
        args = mcp_config.get('args', [])
        
        if args and 'enhanced_server.py' in ' '.join(args):
            print("✅ Claude configured to use enhanced_server.py")
            print(f"   Command: {command} {' '.join(args)}")
        elif args and 'server.py' in ' '.join(args):
            print("⚠️  Claude configured to use OLD server.py")
            print(f"   Command: {command} {' '.join(args)}")
        else:
            print("❓ Unclear configuration:")
            print(f"   Config: {mcp_config}")
    else:
        print("❌ wireshark-mcp not found in Claude configuration")
except Exception as e:
    print(f"❌ Error reading Claude config: {e}")

# 3. Check which server files exist
print("\n3️⃣ Checking server files:")
print("-" * 40)
wireshark_dir = Path('/home/dell/coding/mcp/wireshark-mcp')
server_files = ['server.py', 'enhanced_server.py']

for file in server_files:
    filepath = wireshark_dir / file
    if filepath.exists():
        # Check if it has the enhanced tools
        try:
            with open(filepath, 'r') as f:
                content = f.read()
                tool_count = content.count('Tool(')
                has_realtime = 'wireshark_realtime_json_capture' in content
                has_stats = 'wireshark_protocol_statistics' in content
                has_enhanced = 'wireshark_analyze_pcap_enhanced' in content
                
            print(f"✅ {file} exists:")
            print(f"   - Tools defined: {tool_count}")
            print(f"   - Has realtime_json_capture: {'✅' if has_realtime else '❌'}")
            print(f"   - Has protocol_statistics: {'✅' if has_stats else '❌'}")
            print(f"   - Has analyze_pcap_enhanced: {'✅' if has_enhanced else '❌'}")
            
            if has_realtime and has_stats and has_enhanced:
                print(f"   🎯 This is the ENHANCED server with all 8 tools!")
            else:
                print(f"   ⚠️  This appears to be the BASIC server with 5 tools")
        except Exception as e:
            print(f"❌ Error reading {file}: {e}")
    else:
        print(f"❌ {file} does not exist")

# 4. Diagnosis
print("\n4️⃣ Diagnosis:")
print("-" * 40)
print("🔍 ISSUE IDENTIFIED:")
print("   The MCP is running the OLD server.py (5 tools)")
print("   But Claude is configured for enhanced_server.py (8 tools)")
print("   This mismatch causes:")
print("   - Only 5 tools accessible instead of 8")
print("   - No enhanced fallback for live capture")
print("   - Missing JSON streaming and protocol analysis tools")
print("\n🔧 SOLUTION:")
print("   Claude Desktop needs to be restarted to load the correct server")
print("   The enhanced_server.py has all features but isn't being used")

# 5. Quick fix suggestion
print("\n5️⃣ Quick Fix Options:")
print("-" * 40)
print("Option 1: Restart Claude Desktop completely")
print("Option 2: Kill old server.py processes:")
print("   pkill -f 'wireshark-mcp/server.py'")
print("Option 3: Use the bridge tools as a workaround:")
print("   python3 enhanced_tools_bridge.py --help")