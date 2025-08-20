# 🦈 Wireshark MCP Packet Capture Setup Guide

## 🚀 Quick Start - Enable Packet Capture

The Wireshark MCP now includes **automatic permissions handling** and **real packet capture capabilities**!

### **Step 1: Run the Setup Script**
```bash
cd /home/dell/coding/mcp/wireshark-mcp
./setup_permissions.sh
```

### **Step 2: Activate Group Membership**
```bash
# Either log out and back in, OR run:
newgrp wireshark
```

### **Step 3: Test Permissions**
```bash
./test_capture_permissions.py
```

### **Step 4: Restart Claude Desktop**
Close Claude Desktop completely and reopen it.

---

## 🔧 What the Setup Does

### **Secure Permissions Configuration**
- ✅ Creates `wireshark` group for secure access control
- ✅ Adds your user to the wireshark group
- ✅ Sets Linux capabilities on capture tools (dumpcap, tshark, tcpdump)
- ✅ Restricts access to group members only
- ✅ No need for sudo during operation

### **Security Features**
- 🛡️ **Group-based access** - Only wireshark group members can capture
- 🛡️ **Capability-based permissions** - No root privileges required
- 🛡️ **Tool isolation** - Only capture tools have elevated capabilities
- 🛡️ **Automatic cleanup** - Temporary files cleaned up after analysis

---

## 📡 Live Packet Capture Features

### **Automatic Permission Detection**
The Wireshark MCP now automatically detects if you have packet capture permissions:

- ✅ **With Permissions**: Real packet capture using dumpcap/tshark
- ⚠️ **Without Permissions**: Provides setup instructions

### **Real Packet Capture**
```bash
# Through Claude Desktop MCP interface:
"Capture live packets on interface wlp2s0 for 30 seconds with HTTP filter"
```

**Capabilities:**
- 📊 **Live capture** on any network interface
- 🎯 **Smart filtering** using Wireshark display filters
- ⏱️ **Duration control** (default: 60 seconds)
- 📦 **Packet limits** (default: 1000 packets)
- 🧹 **Automatic cleanup** of temporary files

---

## 📈 PCAP File Analysis Features

### **Comprehensive Analysis Types**
1. **Quick Analysis** - Basic packet counts and protocols
2. **Security Analysis** - Threat detection and suspicious patterns
3. **Performance Analysis** - Network health and TCP issues
4. **Comprehensive Analysis** - All of the above combined

### **Security Pattern Detection**
- 🚨 TCP SYN flood detection
- 🔍 Port scan indicators
- 🕳️ DNS tunneling detection
- 📊 Large HTTP request analysis
- ⚠️ Non-standard port usage

### **Performance Metrics**
- 📉 TCP retransmissions
- 🔄 Duplicate ACK analysis
- ⏸️ Zero window conditions
- 💓 Keep-alive patterns
- 🏥 Overall network health assessment

---

## 🧪 Testing Your Setup

### **Test Script Results**
After running `./test_capture_permissions.py`, you should see:
```
🧪 Testing packet capture capabilities...
========================================
✅ dumpcap: Capture started successfully (timeout expected)
✅ tshark: Capture started successfully (timeout expected)  
✅ tcpdump: Capture started successfully (timeout expected)

========================================
✅ 3/3 capture tools working without sudo
🚀 Wireshark MCP packet capture is ready!
```

### **Troubleshooting**
If tests fail:
1. **Log out and back in** (group membership activation)
2. **Check group membership**: `groups $USER`
3. **Verify capabilities**: `getcap $(which dumpcap)`
4. **Re-run setup**: `./setup_permissions.sh`

---

## 🎯 Usage Examples

### **Through Claude Desktop**
Once setup is complete, you can use natural language commands:

**System Information:**
```
"Get Wireshark MCP system information"
```

**Live Capture:**
```
"Capture HTTP traffic on ethernet interface for 30 seconds"
"Capture DNS queries on any interface with 100 packet limit"
```

**Filter Generation:**
```
"Generate a Wireshark filter for HTTPS traffic to Google"
"Create a filter for slow TCP connections"
```

**PCAP Analysis:**
```
"Analyze /path/to/capture.pcap for security threats"
"Perform quick analysis on /tmp/network.pcapng"
```

---

## 🔒 Security Considerations

### **What's Protected**
- ✅ Only wireshark group members can capture packets
- ✅ Capabilities limited to network capture only
- ✅ No system-wide root privileges granted
- ✅ Temporary files automatically cleaned up

### **What's Accessible**
- 📡 All network interfaces on the system
- 📊 Raw packet data (same as tcpdump/wireshark)
- 🔍 Network traffic analysis capabilities

### **Best Practices**
- 🎯 Use specific interfaces when possible (not "any")
- ⏱️ Limit capture duration for large networks
- 🧹 Captured files are automatically cleaned up after 5 minutes
- 🔒 Only add trusted users to wireshark group

---

## ✅ Success Indicators

After successful setup, your Wireshark MCP will provide:

1. **✅ Real Packet Capture** - No more simulation mode
2. **🔍 Intelligent Analysis** - Security, performance, and comprehensive insights
3. **🎯 Smart Filtering** - Natural language to Wireshark filters
4. **🛡️ Secure Operation** - No sudo required during operation
5. **🧹 Automatic Cleanup** - Temporary files managed automatically

---

**🎉 Your Wireshark MCP is now ready for professional network analysis!**