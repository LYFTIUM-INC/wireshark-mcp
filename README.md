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

## 📦 **Installation & Setup**

### **🐍 Python Dependencies**
```bash
# Clone repository
git clone https://github.com/your-org/wireshark-mcp.git
cd wireshark-mcp

# Install Python dependencies
pip install -r requirements.txt
# or with pyproject tooling
pip install .
```

### **🔧 System Prereqs**
- Wireshark/tshark and tcpdump must be installed
- Configure Linux capabilities for non-root capture:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
sudo usermod -a -G wireshark $USER && newgrp wireshark
```

### **⚙️ Configure Claude Desktop**
Add this MCP server to Claude Desktop, pointing to `server.py`.

---

## 🎯 **Usage Examples**

### **🔴 Real-time JSON Capture**
Use the `wireshark_realtime_json_capture` tool via MCP, or run tests locally:
```bash
python test_enhanced_tools.py
```

### **📊 Protocol Statistics**
Use the tool `wireshark_protocol_statistics` with a pcap file path.

### **🔬 Enhanced PCAP Analysis**
Tool: `wireshark_analyze_pcap_enhanced` supports large files and JSON output.

---

## 🧪 **Testing & Quality Assurance**

- Run unit tests: `pytest`
- Lint and format: `ruff check .` and `black .`
- CI runs on GitHub Actions across Python 3.9–3.12

---

## 🛡️ **Security Notes**
- Default capture path uses capability-based `tcpdump` then parses with `tshark`.
- Optional `sg wireshark` fallback is disabled by default. Enable with `WIRESHARK_ENABLE_SG=1` if you understand the risks.

---

## 📄 **License**

MIT License. See `LICENSE`.

---

## 📞 **Support & Contact**

- **Issues**: open on GitHub
- **Documentation**: project README and code docstrings