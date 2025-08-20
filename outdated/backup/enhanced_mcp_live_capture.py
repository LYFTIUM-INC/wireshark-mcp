#!/usr/bin/env python3
"""
Enhanced MCP Live Capture Implementation
========================================

Drop-in replacement for MCP live capture that supports extended duration
and works around permission limitations.
"""

import asyncio
import tempfile
import os
import json
import time
from typing import Dict, Any

async def wireshark_live_capture_enhanced(
    interface: str = "lo",
    duration: int = 60,
    max_packets: int = 1000,
    filter_expr: str = ""
) -> Dict[str, Any]:
    """
    Enhanced MCP live capture using multiple fallback methods.
    Supports extended duration captures up to 5+ minutes.
    
    This function can be used as a drop-in replacement for the standard
    MCP live capture function with enhanced capabilities.
    """
    results = {
        "status": "",
        "method_used": "",
        "interface": interface,
        "duration": duration,
        "filter": filter_expr,
        "max_packets": max_packets,
        "packets_captured": 0,
        "packets": [],
        "file_path": "",
        "capture_time_seconds": 0
    }
    
    start_time = time.time()
    
    # Method 1: Try tcpdump + tshark (most reliable)
    try:
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            pcap_file = tmp.name
        
        # Build tcpdump command
        cmd = [
            'timeout', str(duration),
            'tcpdump', '-i', interface,
            '-w', pcap_file,
            '-c', str(max_packets),
            '-q'
        ]
        
        if filter_expr:
            cmd.append(filter_expr)
        
        # Capture with tcpdump
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await proc.communicate()
        
        if proc.returncode in [0, 124]:  # Success or timeout
            # Parse with tshark
            parse_cmd = ['tshark', '-r', pcap_file, '-T', 'json', '-c', str(min(10, max_packets))]
            parse_proc = await asyncio.create_subprocess_exec(
                *parse_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            parse_stdout, _ = await parse_proc.communicate()
            
            if parse_proc.returncode == 0:
                packets = json.loads(parse_stdout.decode()) if parse_stdout else []
                
                results.update({
                    "status": "✅ Success",
                    "method_used": "tcpdump + tshark analysis",
                    "packets_captured": len(packets),
                    "packets": packets,
                    "file_path": pcap_file,
                    "capture_time_seconds": time.time() - start_time,
                    "note": "Enhanced capture supports extended duration (up to 5+ minutes)"
                })
                
                return results
        
        # Clean up temp file if failed
        if os.path.exists(pcap_file):
            os.unlink(pcap_file)
            
    except Exception as e:
        results["tcpdump_error"] = str(e)
    
    # Method 2: Try sg wireshark
    try:
        cmd = [
            'sg', 'wireshark', '-c',
            f'timeout {duration} tshark -i {interface} -c {max_packets} -T json'
        ]
        
        if filter_expr:
            cmd[-1] += f' -f "{filter_expr}"'
        
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await proc.communicate()
        
        if proc.returncode in [0, 124]:
            packets = json.loads(stdout.decode()) if stdout else []
            
            results.update({
                "status": "✅ Success",
                "method_used": "sg wireshark + tshark",
                "packets_captured": len(packets),
                "packets": packets,
                "capture_time_seconds": time.time() - start_time,
                "note": "Used group switching for direct tshark access"
            })
            
            return results
    
    except Exception as e:
        results["sg_error"] = str(e)
    
    # If all methods fail
    results.update({
        "status": "❌ All methods failed",
        "method_used": "none",
        "capture_time_seconds": time.time() - start_time,
        "recommendations": [
            "Run ./fix_permissions.sh to setup permissions",
            "Restart Claude Desktop to activate wireshark group", 
            "Use async background capture for long captures",
            "Verify tcpdump capabilities with: getcap /usr/bin/tcpdump"
        ],
        "fallback_options": [
            "Use: python async_long_capture.py for background captures",
            "Use: tcpdump + analyze PCAP workflow",
            "Check permission status with: python sudo_permission_test.py"
        ]
    })
    
    return results

# Test function for the enhanced capture
async def test_enhanced_capture():
    """Test the enhanced MCP live capture function"""
    print("🧪 Testing Enhanced MCP Live Capture")
    print("=" * 45)
    
    # Test 1: Short capture (30 seconds)
    print("\n📡 Test 1: 30-second capture...")
    result1 = await wireshark_live_capture_enhanced(
        interface="lo",
        duration=30,
        max_packets=20,
        filter_expr="port 3000 or port 8080 or port 7444"
    )
    
    print(f"Status: {result1['status']}")
    print(f"Method: {result1['method_used']}")
    print(f"Packets: {result1['packets_captured']}")
    print(f"Time: {result1['capture_time_seconds']:.1f}s")
    
    # Test 2: Extended capture (2 minutes)  
    print("\n📡 Test 2: 2-minute extended capture...")
    result2 = await wireshark_live_capture_enhanced(
        interface="lo",
        duration=120,  # 2 minutes
        max_packets=100,
        filter_expr=""  # Capture all traffic
    )
    
    print(f"Status: {result2['status']}")
    print(f"Method: {result2['method_used']}")
    print(f"Packets: {result2['packets_captured']}")
    print(f"Time: {result2['capture_time_seconds']:.1f}s")
    
    # Clean up test files
    for result in [result1, result2]:
        if result.get('file_path') and os.path.exists(result['file_path']):
            try:
                os.unlink(result['file_path'])
                print(f"Cleaned up: {result['file_path']}")
            except Exception as e:
                print(f"Cleanup error: {e}")
    
    print(f"\n✅ Enhanced MCP capture testing complete!")
    return [result1, result2]

# Integration guide
def print_integration_guide():
    """Print guide for integrating enhanced capture into MCP server"""
    guide = '''
🔧 INTEGRATION GUIDE: Enhanced MCP Live Capture
==============================================

1. REPLACE EXISTING MCP FUNCTION:
   
   Replace the existing wireshark_live_capture function in your MCP server with:
   wireshark_live_capture_enhanced()
   
2. BENEFITS GAINED:
   
   ✅ Extended duration support (up to 5+ minutes)
   ✅ Multiple fallback capture methods  
   ✅ Better error handling and user guidance
   ✅ Works around permission limitations
   ✅ Compatible with existing MCP interface
   
3. NO BREAKING CHANGES:
   
   • Same function signature and return format
   • Enhanced status reporting
   • Additional metadata provided
   
4. IMPLEMENTATION EFFORT:
   
   ⏱️ Time: ~30 minutes
   🔧 Complexity: Very Low
   📋 Steps: Copy function, replace import, test
   
5. TESTING COMMANDS:
   
   python enhanced_mcp_live_capture.py
   
6. FALLBACK OPTIONS:
   
   If enhanced capture fails, users get clear guidance on:
   • Permission fixes
   • Alternative capture methods  
   • Background capture options
'''
    print(guide)

if __name__ == "__main__":
    print_integration_guide()
    
    # Run tests
    test_results = asyncio.run(test_enhanced_capture())
    
    print(f"\n📊 SUMMARY:")
    print(f"Tests run: {len(test_results)}")
    for i, result in enumerate(test_results, 1):
        print(f"Test {i}: {result['status']} - {result['method_used']}")