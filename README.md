# 🦈 Wireshark MCP Server - Enhanced Edition v2.0

> **Powerful Wireshark MCP server with real-time JSON streaming, protocol statistics, and enhanced analysis capabilities.**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io/)
[![Claude Desktop](https://img.shields.io/badge/Claude-Desktop-orange.svg)](https://claude.ai/desktop)
[![Enterprise Ready](https://img.shields.io/badge/Enterprise-Ready-red.svg)](#enterprise-features)

## 🚀 **Features Overview**

### **🔥 Core Capabilities**
- **8 Comprehensive Network Analysis Tools** - Complete packet analysis suite
- **Real-time JSON Packet Capture** - Stream packets in EK/JSON/raw formats
- **Protocol Statistics & Conversations** - Hierarchy, endpoints, and I/O analysis
- **Enhanced PCAP Analysis** - Large file support with streaming
- **LLM-Powered Filter Generation** - Natural language to Wireshark filters
- **Claude Desktop Integration** - Seamless MCP protocol support

### **🆕 Enhanced Features (v2.0)**
- **JSON Streaming Support** - Real-time packet processing in JSON format
- **Protocol Hierarchy Analysis** - Comprehensive protocol breakdown
- **Conversation Tracking** - TCP/UDP/IP conversation analysis
- **Performance Metrics** - Retransmissions, duplicate ACKs, window issues
- **Security Pattern Detection** - SYN floods, port scans, DNS tunneling
- **Multiple Output Formats** - JSON, text, and summary reports

---

## 📦 **Quick Installation & Setup**

### **🚀 Automated Setup (Recommended)**

Run our cross-platform setup script that handles all dependencies and permissions:

```bash
# Download and run the automated setup
curl -sSL https://raw.githubusercontent.com/your-org/wireshark-mcp/main/setup.sh | bash

# Or manually:
git clone https://github.com/your-org/wireshark-mcp.git
cd wireshark-mcp
chmod +x setup.sh
./setup.sh
```

**The setup script will:**
- ✅ Install required packages (Wireshark, tcpdump, Python dependencies)
- ✅ Configure secure packet capture permissions (Linux capabilities)
- ✅ Set up user groups and permissions
- ✅ Validate installation and test packet capture
- ✅ Generate Claude Desktop configuration

### **🔧 Manual Installation**

<details>
<summary><b>📋 Prerequisites by Platform</b></summary>

#### **🐧 Linux (Ubuntu/Debian)**
```bash
# Install Wireshark and dependencies
sudo apt-get update
sudo apt-get install wireshark-common tshark tcpdump python3-pip

# Configure permissions for packet capture
sudo dpkg-reconfigure wireshark-common  # Select "Yes"
sudo usermod -a -G wireshark $USER

# Set capabilities for secure packet capture
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tshark

# Apply group changes (logout/login OR run):
newgrp wireshark
```

#### **🍎 macOS**
```bash
# Install using Homebrew
brew install wireshark tcpdump python3

# Note: macOS may require additional permissions
# Run Wireshark once as admin to set permissions
sudo /Applications/Wireshark.app/Contents/MacOS/Wireshark
```

#### **🪟 Windows**
```powershell
# Install using Chocolatey
choco install wireshark python3

# Or download directly:
# https://www.wireshark.org/download.html
# https://www.python.org/downloads/windows/

# Note: Windows requires admin privileges for packet capture
```

</details>

### **🐍 Python Dependencies**
```bash
# Clone repository
git clone https://github.com/your-org/wireshark-mcp.git
cd wireshark-mcp

# Install Python dependencies
pip install -r requirements.txt
```

### **🔍 Verify Installation**
```bash
# Test permissions and setup
python3 diagnose_permissions.py

# Should show:
# ✅ ALL CHECKS PASSED - Wireshark MCP ready for packet capture!
```

### **⚙️ Configure Claude Desktop**

The setup script will generate this configuration, or add manually to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "python",
      "args": ["/path/to/wireshark-mcp/enhanced_server.py"],
      "env": {
        "WIRESHARK_PATH": "/usr/bin",
        "TCPDUMP_PATH": "/usr/sbin/tcpdump",
        "CAPTURE_INTERFACE": "any"
      }
    }
  }
}
```

---

## 🎯 **Usage Examples**

### **🔴 Real-time JSON Capture**
```python
# Stream packets in JSON format
await wireshark_realtime_json_capture(
    interface="eth0",
    duration=30,
    filter="tcp port 80",
    json_format="ek"  # Elasticsearch format
)
```

### **📊 Protocol Statistics**
```python 
# Generate comprehensive protocol analysis
await wireshark_protocol_statistics(
    source="/path/to/capture.pcap",
    analysis_type="all",  # hierarchy, conversations, endpoints, io_stats
    protocol="tcp"
)
```

### **🧠 AI Filter Generation**
```python
# Generate Wireshark filters from natural language
await wireshark_generate_filter(
    description="HTTP traffic from 192.168.1.0/24 subnet",
    complexity="intermediate"
)
```

### **🔬 Enhanced PCAP Analysis**
```python
# Advanced analysis with streaming support
await wireshark_analyze_pcap_enhanced(
    filepath="/path/to/large_capture.pcap",
    analysis_type="security",
    chunk_size=10000,
    output_format="json"
)
```

---

## 🛠️ **Complete Tool Reference (8 Tools)**

### **📊 Core Tools**
| Tool | Purpose | Key Features |
|------|---------|-------------|
| `wireshark_system_info` | System information | Interface listing, capabilities check |
| `wireshark_validate_setup` | Setup validation | Dependency checking, permissions |
| `wireshark_generate_filter` | AI filter generation | Natural language to Wireshark filters |
| `wireshark_live_capture` | Live packet capture | Basic interface monitoring |
| `wireshark_analyze_pcap` | PCAP analysis | Quick/comprehensive/security/performance modes |

### **🆕 Enhanced Tools (v2.0)**
| Tool | Purpose | Key Features |
|------|---------|-------------|
| `wireshark_realtime_json_capture` | JSON streaming | EK/JSON/raw formats, real-time processing |
| `wireshark_protocol_statistics` | Protocol analysis | Hierarchy, conversations, endpoints, I/O stats |
| `wireshark_analyze_pcap_enhanced` | Advanced analysis | Large file support, streaming, multiple outputs |

---

## 🔧 **Troubleshooting & Common Issues**

### **🚨 Permission Issues (Most Common)**

**Problem**: `Permission denied` or `You do not have permission to capture`

**Solutions**:
```bash
# 1. Quick fix - run automated setup
./setup.sh

# 2. Manual fix for Linux
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tshark
sudo usermod -a -G wireshark $USER
newgrp wireshark

# 3. Verify fix worked
python3 diagnose_permissions.py
```

### **🔍 Diagnostic Tools**

We provide several diagnostic tools:

```bash
# Comprehensive permission diagnostics
python3 diagnose_permissions.py

# Test all MCP features
python3 test_wireshark_permissions.py

# Validate complete setup
python3 test_enhanced_features.py
```

### **📋 Platform-Specific Issues**

<details>
<summary><b>🐧 Linux Issues</b></summary>

**Missing dumpcap**:
```bash
sudo apt-get install wireshark-common
```

**Group membership not active**:
```bash
# Either logout/login OR:
newgrp wireshark
```

**Capabilities not set**:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
```

</details>

<details>
<summary><b>🍎 macOS Issues</b></summary>

**Permission denied on interfaces**:
```bash
# Run Wireshark as admin once to set permissions
sudo /Applications/Wireshark.app/Contents/MacOS/Wireshark

# Or use ChmodBPF
sudo /Applications/Wireshark.app/Contents/Resources/ChmodBPF/ChmodBPF
```

**Homebrew path issues**:
```bash
# Ensure tools are in PATH
echo 'export PATH="/opt/homebrew/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

</details>

<details>
<summary><b>🪟 Windows Issues</b></summary>

**Admin privileges required**:
- Run Claude Desktop as Administrator
- Or install WinPcap/Npcap with admin privileges

**Path issues**:
```powershell
# Add Wireshark to PATH
$env:PATH += ";C:\Program Files\Wireshark"
```

</details>

### **🔧 Advanced Troubleshooting**

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
python3 enhanced_server.py

# Check system capabilities
python3 -c "
import subprocess
print('Interfaces:', subprocess.run(['tshark', '-D'], capture_output=True, text=True).stdout)
print('Capabilities:', subprocess.run(['getcap', '/usr/bin/dumpcap'], capture_output=True, text=True).stdout)
"

# Test individual components
python3 test_integrated_server.py --verbose
```

---

## 🏗️ **Architecture Overview**

```
┌─────────────────────────────────────────────────────────────┐
│                    Claude Desktop                            │
├─────────────────────────────────────────────────────────────┤
│                    MCP Protocol Layer                       │
├─────────────────────────────────────────────────────────────┤
│          Wireshark MCP Server (Python)                     │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │  Core Engine    │  │ LLM Integration │                  │
│  │  - sharkd API   │  │ - Filter Gen    │                  │
│  │  │  - tshark CLI   │  │ - Analysis      │                  │
│  └─────────────────┘  └─────────────────┘                  │
├─────────────────────────────────────────────────────────────┤
│                    Security Layer                           │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │   Capabilities  │  │   Group-based   │                  │
│  │   - CAP_NET_RAW │  │   - wireshark   │                  │
│  │   - CAP_NET_ADM │  │   - Secure      │                  │
│  └─────────────────┘  └─────────────────┘                  │
├─────────────────────────────────────────────────────────────┤
│                    Data Layer                               │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │   Wireshark     │  │    tcpdump      │                  │
│  │   - Live Cap    │  │   - Raw Cap     │                  │
│  │   - Analysis    │  │   - Filtering   │                  │
│  │   - Dissection  │  │   - Monitoring  │                  │
│  └─────────────────┘  └─────────────────┘                  │
└─────────────────────────────────────────────────────────────┘
```

---

## 🧪 **Testing & Quality Assurance**

### **🔍 Test Suite**
```bash
# Test permissions (most important)
python3 diagnose_permissions.py

# Test all integrated features
python3 test_integrated_server.py

# Test enhanced features only
python3 test_enhanced_features.py

# Run example workflows
python3 integrated_example.py
```

### **📊 Performance Testing**
```bash
# Measure capture performance
python3 performance_test.py

# Test with large PCAP files
python3 test_large_pcap_analysis.py
```

---

## 📊 **Performance & Capabilities**

### **🚀 Processing Features**
- **JSON Streaming**: Real-time packet processing in multiple formats
- **Large File Support**: Chunked processing for multi-GB PCAP files
- **Protocol Analysis**: Comprehensive hierarchy and conversation tracking
- **Security Patterns**: Built-in detection for common attack patterns
- **Filter Generation**: Advanced regex and subnet parsing

### **⚡ Technical Specifications**
- **Output Formats**: JSON, text, summary
- **JSON Formats**: Elasticsearch (ek), standard, raw
- **Analysis Types**: Quick, comprehensive, security, performance
- **Protocol Support**: TCP, UDP, IP, HTTP, DNS, and more
- **Capture Rate**: Up to 10,000+ packets/second (hardware dependent)

---

## 🛡️ **Security & Compliance**

### **🔒 Security Features**
- **Linux Capabilities**: Uses CAP_NET_RAW/CAP_NET_ADMIN instead of root
- **Group-based Access**: Only wireshark group members can capture
- **Process Isolation**: Secure subprocess execution
- **Automatic Cleanup**: Temporary files removed after analysis

### **📋 Compliance Support**
- **SOC2 Ready**: Security controls and monitoring
- **GDPR Compliant**: Data protection and privacy
- **NIST Framework**: Cybersecurity standards alignment
- **Enterprise Logging**: Detailed audit trails

---

## 🚀 **Development Roadmap**

### **Phase 1: Foundation** ✅
- [x] Basic MCP server with tshark integration
- [x] Essential packet capture and analysis tools
- [x] Claude Desktop configuration

### **Phase 2: Advanced Features** ✅
- [x] LLM-powered filter generation
- [x] tcpdump integration
- [x] Security analysis capabilities

### **Phase 3: Enhanced Features** ✅
- [x] Real-time JSON packet capture
- [x] Protocol statistics and conversations
- [x] Enhanced PCAP analysis with streaming
- [x] Cross-platform automated setup

### **Phase 4: Current Focus** 🔄
- [x] Permission automation and diagnostics
- [x] Cross-platform compatibility
- [ ] Performance optimizations (dpkt integration)
- [ ] Real-time alerting system

### **Phase 5: Future Enhancements** 📅
- [ ] Threat intelligence API integration
- [ ] Advanced visualization capabilities
- [ ] Distributed capture coordination
- [ ] Enterprise compliance dashboard

---

## 📝 **Contributing**

### **Development Setup**
```bash
# Clone repository
git clone https://github.com/your-org/wireshark-mcp.git
cd wireshark-mcp

# Install development dependencies
pip install -r requirements.txt
pip install -e ".[dev]"

# Run automated setup
./setup.sh

# Run tests
python test_server.py

# Format code
black enhanced_server.py test_integrated_server.py
flake8 enhanced_server.py test_integrated_server.py
```

### **Contribution Guidelines**
1. **Fork** the repository
2. **Create** feature branch (`git checkout -b feature/amazing-feature`)
3. **Add** comprehensive tests for new functionality
4. **Ensure** all tests pass and code is formatted
5. **Commit** changes (`git commit -m 'Add amazing feature'`)
6. **Push** to branch (`git push origin feature/amazing-feature`)
7. **Open** Pull Request with detailed description

---

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 **Acknowledgments**

- **Wireshark Team** - For the incredible network analysis platform
- **Anthropic** - For Claude and the Model Context Protocol
- **Security Research Community** - For threat intelligence and IOC feeds

---

## 📞 **Support & Contact**

- **🐛 Issues**: [GitHub Issues](https://github.com/your-org/wireshark-mcp/issues)
- **📚 Documentation**: [Full Documentation](https://your-org.github.io/wireshark-mcp/)
- **💬 Discussions**: [GitHub Discussions](https://github.com/your-org/wireshark-mcp/discussions)

---

**🦈 Built with intelligence, designed for enterprise. Transform your network analysis with AI-powered insights.**