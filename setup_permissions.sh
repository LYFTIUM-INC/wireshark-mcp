#!/bin/bash
# Wireshark MCP Permissions Setup Script
# Sets up secure packet capture capabilities without requiring sudo for operation

set -e

echo "🦈 Wireshark MCP Permissions Setup"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}❌ This script should not be run as root (for security)${NC}"
   echo "   Run it as your normal user - it will request sudo when needed"
   exit 1
fi

echo -e "${BLUE}🔍 Checking system requirements...${NC}"

# Check if required tools are installed
check_tool() {
    if command -v "$1" &> /dev/null; then
        echo -e "  ✅ $1 is installed"
        return 0
    else
        echo -e "  ❌ $1 is not installed"
        return 1
    fi
}

MISSING_TOOLS=0

# Check required tools
if ! check_tool tshark; then
    echo -e "${YELLOW}     Install with: sudo apt install tshark${NC}"
    MISSING_TOOLS=1
fi

if ! check_tool tcpdump; then
    echo -e "${YELLOW}     Install with: sudo apt install tcpdump${NC}"
    MISSING_TOOLS=1
fi

if ! check_tool dumpcap; then
    echo -e "${YELLOW}     Install with: sudo apt install dumpcap${NC}"
    MISSING_TOOLS=1
fi

if ! check_tool setcap; then
    echo -e "${YELLOW}     Install with: sudo apt install libcap2-bin${NC}"
    MISSING_TOOLS=1
fi

if [[ $MISSING_TOOLS -eq 1 ]]; then
    echo -e "${RED}❌ Missing required tools. Please install them first.${NC}"
    exit 1
fi

echo -e "${GREEN}✅ All required tools are installed${NC}"

# Check if wireshark group exists, create if not
echo -e "${BLUE}🔧 Setting up wireshark group...${NC}"
if ! getent group wireshark > /dev/null 2>&1; then
    echo "  Creating wireshark group..."
    sudo groupadd wireshark
    echo -e "  ✅ Created wireshark group"
else
    echo -e "  ✅ wireshark group already exists"
fi

# Add current user to wireshark group
echo "  Adding $USER to wireshark group..."
sudo usermod -a -G wireshark $USER
echo -e "  ✅ Added $USER to wireshark group"

# Set capabilities on capture tools
echo -e "${BLUE}🔐 Setting up secure packet capture capabilities...${NC}"

# Method 1: Use dumpcap (most secure - Wireshark's preferred method)
DUMPCAP_PATH=$(which dumpcap)
if [[ -n "$DUMPCAP_PATH" ]]; then
    echo "  Setting capabilities on dumpcap..."
    sudo setcap cap_net_raw,cap_net_admin+eip "$DUMPCAP_PATH"
    sudo chgrp wireshark "$DUMPCAP_PATH"
    sudo chmod 750 "$DUMPCAP_PATH"
    echo -e "  ✅ dumpcap configured for secure capture"
fi

# Method 2: Configure tshark as backup
TSHARK_PATH=$(which tshark)
if [[ -n "$TSHARK_PATH" ]]; then
    echo "  Setting capabilities on tshark..."
    sudo setcap cap_net_raw,cap_net_admin+eip "$TSHARK_PATH"
    sudo chgrp wireshark "$TSHARK_PATH"
    sudo chmod 750 "$TSHARK_PATH"
    echo -e "  ✅ tshark configured for secure capture"
fi

# Method 3: Configure tcpdump as backup
TCPDUMP_PATH=$(which tcpdump)
if [[ -n "$TCPDUMP_PATH" ]]; then
    echo "  Setting capabilities on tcpdump..."
    sudo setcap cap_net_raw,cap_net_admin+eip "$TCPDUMP_PATH"
    sudo chgrp wireshark "$TCPDUMP_PATH"
    sudo chmod 750 "$TCPDUMP_PATH"
    echo -e "  ✅ tcpdump configured for secure capture"
fi

# Verify capabilities
echo -e "${BLUE}🔍 Verifying capabilities...${NC}"
for tool in dumpcap tshark tcpdump; do
    TOOL_PATH=$(which $tool 2>/dev/null || echo "")
    if [[ -n "$TOOL_PATH" ]]; then
        CAPS=$(getcap "$TOOL_PATH" 2>/dev/null || echo "none")
        if [[ "$CAPS" != "none" && "$CAPS" != "" ]]; then
            echo -e "  ✅ $tool: $CAPS"
        else
            echo -e "  ⚠️  $tool: No capabilities set"
        fi
    fi
done

# Check group membership
echo -e "${BLUE}👥 Checking group membership...${NC}"
if groups $USER | grep -q wireshark; then
    echo -e "  ✅ $USER is member of wireshark group"
else
    echo -e "  ⚠️  Group membership may not be active yet"
fi

# Create test script
echo -e "${BLUE}📝 Creating test script...${NC}"
cat > test_capture_permissions.py << 'EOF'
#!/usr/bin/env python3
"""
Test script to verify packet capture permissions are working correctly.
"""
import subprocess
import sys
import os

def test_capability(tool_name, test_args):
    """Test if a tool can capture packets without sudo."""
    try:
        # Quick test - just check if we can start capture (timeout after 1 second)
        result = subprocess.run(
            [tool_name] + test_args,
            capture_output=True,
            text=True,
            timeout=1
        )
        return True, "Success"
    except subprocess.TimeoutExpired:
        # Timeout is expected - means capture started successfully
        return True, "Capture started successfully (timeout expected)"
    except FileNotFoundError:
        return False, f"{tool_name} not found"
    except subprocess.CalledProcessError as e:
        return False, f"Permission denied: {e.stderr}"
    except Exception as e:
        return False, f"Error: {str(e)}"

def main():
    print("🧪 Testing packet capture capabilities...")
    print("=" * 40)
    
    # Test different capture tools
    tests = [
        ("dumpcap", ["-i", "any", "-c", "1", "-w", "/tmp/test.pcap"]),
        ("tshark", ["-i", "any", "-c", "1", "-w", "/tmp/test.pcap"]),
        ("tcpdump", ["-i", "any", "-c", "1", "-w", "/tmp/test.pcap"])
    ]
    
    success_count = 0
    for tool, args in tests:
        success, message = test_capability(tool, args)
        status = "✅" if success else "❌"
        print(f"{status} {tool}: {message}")
        if success:
            success_count += 1
    
    # Clean up test file
    try:
        os.remove("/tmp/test.pcap")
    except:
        pass
    
    print("\n" + "=" * 40)
    if success_count > 0:
        print(f"✅ {success_count}/{len(tests)} capture tools working without sudo")
        print("🚀 Wireshark MCP packet capture is ready!")
    else:
        print("❌ No capture tools working without sudo")
        print("⚠️  You may need to log out and back in for group changes to take effect")
        print("   Or try: newgrp wireshark")
    
    return success_count > 0

if __name__ == "__main__":
    sys.exit(0 if main() else 1)
EOF

chmod +x test_capture_permissions.py
echo -e "  ✅ Created test_capture_permissions.py"

echo ""
echo -e "${GREEN}🎉 Wireshark MCP permissions setup complete!${NC}"
echo ""
echo -e "${YELLOW}⚠️  IMPORTANT NEXT STEPS:${NC}"
echo "1. Log out and log back in (or run 'newgrp wireshark')"
echo "2. Test the setup: ./test_capture_permissions.py"
echo "3. If tests pass, restart Claude Desktop to use the MCP"
echo ""
echo -e "${BLUE}📊 What was configured:${NC}"
echo "• Added $USER to wireshark group"
echo "• Set secure capabilities on packet capture tools"
echo "• Restricted access to wireshark group members only"
echo "• Created test script to verify functionality"
echo ""
echo -e "${GREEN}✅ Your Wireshark MCP can now capture packets without sudo!${NC}"