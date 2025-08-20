#!/usr/bin/env python3
"""Verify all 18 Wireshark MCP tools are implemented."""

import re

def verify_tools():
    with open('enhanced_server.py', 'r') as f:
        content = f.read()
    
    # Find all tool definitions in list_tools
    tool_pattern = r'Tool\(\s*name="([^"]+)"'
    tool_definitions = re.findall(tool_pattern, content)
    
    # Find all handler cases (including if statements)
    handler_pattern = r'(?:if|elif) name == "([^"]+)":'
    handler_cases = re.findall(handler_pattern, content)
    
    # Expected tools
    expected_tools = [
        # Original 8
        "wireshark_system_info",
        "wireshark_validate_setup", 
        "wireshark_generate_filter",
        "wireshark_live_capture",
        "wireshark_analyze_pcap",
        "wireshark_realtime_json_capture",
        "wireshark_protocol_statistics",
        "wireshark_analyze_pcap_enhanced",
        # Advanced 10
        "wireshark_pcap_time_slice",
        "wireshark_pcap_splitter",
        "wireshark_pcap_merger",
        "wireshark_hex_to_pcap",
        "wireshark_http_analyzer",
        "wireshark_dns_analyzer",
        "wireshark_ssl_inspector",
        "wireshark_latency_profiler",
        "wireshark_threat_detector",
        "wireshark_remote_capture"
    ]
    
    print("🔍 Verification Report")
    print("=" * 50)
    
    print(f"\n📋 Tool Definitions Found: {len(tool_definitions)}")
    for tool in tool_definitions:
        status = "✅" if tool in expected_tools else "❌"
        print(f"  {status} {tool}")
    
    print(f"\n🔧 Handler Cases Found: {len(handler_cases)}")
    for handler in handler_cases:
        if handler.startswith("wireshark_"):
            status = "✅" if handler in expected_tools else "❌"
            print(f"  {status} {handler}")
    
    # Check for missing tools
    missing_definitions = set(expected_tools) - set(tool_definitions)
    missing_handlers = set(expected_tools) - set(handler_cases)
    
    if missing_definitions:
        print(f"\n❌ Missing Tool Definitions:")
        for tool in missing_definitions:
            print(f"  - {tool}")
    
    if missing_handlers:
        print(f"\n❌ Missing Handler Cases:")
        for tool in missing_handlers:
            print(f"  - {tool}")
    
    # Summary
    print(f"\n📊 Summary:")
    print(f"  Expected Tools: {len(expected_tools)}")
    print(f"  Tool Definitions: {len(tool_definitions)}")
    print(f"  Handler Cases: {len([h for h in handler_cases if h.startswith('wireshark_')])}")
    
    if len(tool_definitions) == 18 and len([h for h in handler_cases if h.startswith('wireshark_')]) == 18:
        print("\n✅ All 18 tools are properly implemented!")
    else:
        print("\n❌ Implementation incomplete!")
    
    # Check if handler functions exist
    print(f"\n🔍 Checking handler function implementations...")
    for tool in expected_tools:
        # Skip the first 8 original tools as they have different function names
        if tool in ["wireshark_system_info", "wireshark_validate_setup", 
                   "wireshark_generate_filter", "wireshark_live_capture",
                   "wireshark_analyze_pcap", "wireshark_realtime_json_capture",
                   "wireshark_protocol_statistics", "wireshark_analyze_pcap_enhanced"]:
            continue
            
        handler_func = f"handle_{tool[10:]}"  # Remove 'wireshark_' prefix
        if f"async def {handler_func}" in content:
            print(f"  ✅ {handler_func} found")
        else:
            print(f"  ❌ {handler_func} missing")

if __name__ == "__main__":
    verify_tools()