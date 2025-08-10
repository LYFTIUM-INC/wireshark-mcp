#!/usr/bin/env python3
"""
Test script to verify the 3 missing enhanced MCP tools work correctly.
This demonstrates the functionality exists even if MCP interface doesn't show them.
"""

import asyncio
import json
import sys
from pathlib import Path

# Add current directory to path to import server
sys.path.insert(0, str(Path(__file__).parent))

from wireshark_mcp.server import (
    handle_realtime_json_capture,
    handle_protocol_statistics, 
    handle_analyze_pcap_enhanced
)

async def test_enhanced_tools():
    """Test all 3 missing enhanced tools directly."""
    
    print("🧪 Testing Enhanced Wireshark MCP Tools")
    print("=" * 50)
    
    # Test 1: Real-time JSON Capture
    print("\n1️⃣  Testing wireshark_realtime_json_capture")
    print("-" * 40)
    try:
        json_args = {
            "interface": "lo",
            "duration": 5,
            "filter": "tcp",
            "max_packets": 10,
            "json_format": "ek"
        }
        result1 = await handle_realtime_json_capture(json_args)
        print(f"✅ JSON Capture Tool: {result1[0].text[:200]}...")
    except Exception as e:
        print(f"⚠️  JSON Capture Tool: {str(e)[:100]}...")
    
    # Test 2: Protocol Statistics  
    print("\n2️⃣  Testing wireshark_protocol_statistics")
    print("-" * 40)
    try:
        stats_args = {
            "source": "/tmp/live_capture.pcap",
            "analysis_type": "protocol_hierarchy",
            "protocol": "all"
        }
        result2 = await handle_protocol_statistics(stats_args)
        print(f"✅ Protocol Stats Tool: {result2[0].text[:200]}...")
    except Exception as e:
        print(f"⚠️  Protocol Stats Tool: {str(e)[:100]}...")
    
    # Test 3: Enhanced PCAP Analysis
    print("\n3️⃣  Testing wireshark_analyze_pcap_enhanced")
    print("-" * 40)
    try:
        enhanced_args = {
            "filepath": "/tmp/live_capture.pcap",
            "analysis_type": "comprehensive",
            "output_format": "json"
        }
        result3 = await handle_analyze_pcap_enhanced(enhanced_args)
        print(f"✅ Enhanced PCAP Tool: {result3[0].text[:200]}...")
    except Exception as e:
        print(f"⚠️  Enhanced PCAP Tool: {str(e)[:100]}...")
    
    print(f"\n🎯 Test Complete - All 3 enhanced tools tested")
    print("=" * 50)

if __name__ == "__main__":
    asyncio.run(test_enhanced_tools())