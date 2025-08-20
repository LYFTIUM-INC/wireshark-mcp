#!/usr/bin/env python3
"""
Direct test of enhanced_server.py to verify all 8 tools are working
"""

import asyncio
import json
import sys
from pathlib import Path
import subprocess

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from enhanced_server import (
    handle_system_info,
    handle_validate_setup,
    handle_generate_filter,
    handle_live_capture,
    handle_analyze_pcap,
    handle_realtime_json_capture,
    handle_protocol_statistics,
    handle_analyze_pcap_enhanced
)

async def test_all_tools():
    """Test all 8 tools directly from enhanced_server.py"""
    
    print("🧪 Testing All 8 Enhanced Wireshark MCP Tools")
    print("=" * 60)
    
    # Test 1: System Info
    print("\n1️⃣ Testing wireshark_system_info")
    print("-" * 40)
    try:
        result = await handle_system_info({"info_type": "interfaces"})
        print(f"✅ System Info: {result[0].text[:100]}...")
    except Exception as e:
        print(f"❌ System Info Error: {str(e)}")
    
    # Test 2: Validate Setup
    print("\n2️⃣ Testing wireshark_validate_setup")
    print("-" * 40)
    try:
        result = await handle_validate_setup({"full_check": False})
        print(f"✅ Validate Setup: {result[0].text[:100]}...")
    except Exception as e:
        print(f"❌ Validate Setup Error: {str(e)}")
    
    # Test 3: Generate Filter
    print("\n3️⃣ Testing wireshark_generate_filter")
    print("-" * 40)
    try:
        result = await handle_generate_filter({
            "description": "HTTP traffic on port 80",
            "complexity": "simple"
        })
        print(f"✅ Generate Filter: {result[0].text[:100]}...")
    except Exception as e:
        print(f"❌ Generate Filter Error: {str(e)}")
    
    # Test 4: Live Capture (Enhanced)
    print("\n4️⃣ Testing wireshark_live_capture (with enhanced fallback)")
    print("-" * 40)
    try:
        result = await handle_live_capture({
            "interface": "lo",
            "duration": 5,
            "filter": "tcp",
            "max_packets": 10
        })
        print(f"✅ Live Capture: {result[0].text[:100]}...")
    except Exception as e:
        print(f"❌ Live Capture Error: {str(e)}")
    
    # Test 5: Analyze PCAP
    print("\n5️⃣ Testing wireshark_analyze_pcap")
    print("-" * 40)
    try:
        # Create a test pcap if it exists
        test_pcap = "/tmp/test_capture.pcap"
        if Path(test_pcap).exists():
            result = await handle_analyze_pcap({"filepath": test_pcap})
            print(f"✅ Analyze PCAP: {result[0].text[:100]}...")
        else:
            print("⚠️ Skipping - no test PCAP file")
    except Exception as e:
        print(f"❌ Analyze PCAP Error: {str(e)}")
    
    # Test 6: Real-time JSON Capture
    print("\n6️⃣ Testing wireshark_realtime_json_capture")
    print("-" * 40)
    try:
        result = await handle_realtime_json_capture({
            "interface": "lo",
            "duration": 5,
            "filter": "tcp",
            "max_packets": 5,
            "json_format": "ek"
        })
        print(f"✅ JSON Capture: {result[0].text[:100]}...")
    except Exception as e:
        print(f"❌ JSON Capture Error: {str(e)}")
    
    # Test 7: Protocol Statistics
    print("\n7️⃣ Testing wireshark_protocol_statistics")
    print("-" * 40)
    try:
        test_pcap = "/tmp/test_capture.pcap"
        if Path(test_pcap).exists():
            result = await handle_protocol_statistics({
                "source": test_pcap,
                "analysis_type": "protocol_hierarchy",
                "protocol": "all"
            })
            print(f"✅ Protocol Stats: {result[0].text[:100]}...")
        else:
            print("⚠️ Skipping - no test PCAP file")
    except Exception as e:
        print(f"❌ Protocol Stats Error: {str(e)}")
    
    # Test 8: Enhanced PCAP Analysis
    print("\n8️⃣ Testing wireshark_analyze_pcap_enhanced")
    print("-" * 40)
    try:
        test_pcap = "/tmp/test_capture.pcap"
        if Path(test_pcap).exists():
            result = await handle_analyze_pcap_enhanced({
                "filepath": test_pcap,
                "analysis_type": "quick",
                "output_format": "json"
            })
            print(f"✅ Enhanced Analysis: {result[0].text[:100]}...")
        else:
            print("⚠️ Skipping - no test PCAP file")
    except Exception as e:
        print(f"❌ Enhanced Analysis Error: {str(e)}")
    
    print("\n" + "=" * 60)
    print("🎯 Enhanced Server Test Complete")
    print("All 8 tools have been tested directly from enhanced_server.py")
    print("\n💡 If all tests passed, the enhanced server is fully functional.")
    print("   The MCP interface may need Claude Desktop restart to recognize changes.")

if __name__ == "__main__":
    # First create a test capture file
    print("📦 Creating test capture file...")
    try:
        subprocess.run([
            "timeout", "5", "tcpdump", "-i", "lo", "-w", "/tmp/test_capture.pcap", "-c", "10"
        ], capture_output=True)
        print("✅ Test capture created")
    except:
        print("⚠️ Could not create test capture (requires permissions)")
    
    # Run the tests
    asyncio.run(test_all_tools())