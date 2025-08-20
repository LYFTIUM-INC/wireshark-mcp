#!/usr/bin/env python3
"""Test the enhanced capture functionality directly."""

import asyncio
import json
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))

# Import the enhanced capture functions
from enhanced_server import perform_live_capture_enhanced, _enhanced_capture_fallback

async def test_enhanced_capture():
    """Test the enhanced capture with multiple durations."""
    
    print("🧪 Testing Enhanced MCP Live Capture")
    print("=" * 50)
    
    # Test 1: Short capture (30 seconds)
    print("\n📋 Test 1: 30-second capture on loopback interface")
    result = await perform_live_capture_enhanced(
        interface="lo",
        duration=30,
        filter_expr="tcp port 80 or tcp port 443",
        max_packets=100
    )
    
    print(f"Status: {result['status']}")
    print(f"Method used: {result.get('method_used', 'unknown')}")
    print(f"Packets captured: {result.get('packets_captured', 0)}")
    print(f"Capture time: {result.get('capture_time_seconds', 0)} seconds")
    if 'error' in result:
        print(f"Error: {result['error']}")
    if 'note' in result:
        print(f"Note: {result['note']}")
    
    # Test 2: Extended capture (2 minutes) 
    print("\n📋 Test 2: 2-minute capture test")
    result2 = await perform_live_capture_enhanced(
        interface="lo", 
        duration=120,
        filter_expr="",
        max_packets=500
    )
    
    print(f"Status: {result2['status']}")
    print(f"Method used: {result2.get('method_used', 'unknown')}")
    print(f"Packets captured: {result2.get('packets_captured', 0)}")
    print(f"Capture time: {result2.get('capture_time_seconds', 0)} seconds")
    
    # Test 3: Quick test with specific filter
    print("\n📋 Test 3: Quick 10-second capture with SSH filter")
    result3 = await perform_live_capture_enhanced(
        interface="lo",
        duration=10,
        filter_expr="tcp port 22",
        max_packets=50
    )
    
    print(f"Status: {result3['status']}")
    print(f"Method used: {result3.get('method_used', 'unknown')}")
    print(f"Packets captured: {result3.get('packets_captured', 0)}")
    
    print("\n✅ Enhanced capture testing complete!")
    
    # Summary
    print("\n📊 Summary:")
    methods_used = set()
    for r in [result, result2, result3]:
        if 'method_used' in r:
            methods_used.add(r['method_used'])
    
    print(f"Methods successfully used: {', '.join(methods_used)}")
    
    success_count = sum(1 for r in [result, result2, result3] if r['status'].startswith('✅'))
    print(f"Successful captures: {success_count}/3")

if __name__ == "__main__":
    asyncio.run(test_enhanced_capture())