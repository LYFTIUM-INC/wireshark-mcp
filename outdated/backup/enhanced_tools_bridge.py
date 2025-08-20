#!/usr/bin/env python3
"""
Enhanced Wireshark MCP Tools Bridge
===================================

This script provides direct access to the 3 enhanced tools that exist in the codebase
but aren't accessible through the MCP interface due to caching/connection issues.

Usage:
  python3 enhanced_tools_bridge.py realtime_json_capture --interface=lo --duration=10
  python3 enhanced_tools_bridge.py protocol_statistics --source=/path/to/file.pcap 
  python3 enhanced_tools_bridge.py analyze_pcap_enhanced --filepath=/path/to/file.pcap
"""

import asyncio
import json
import sys
import argparse
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from enhanced_server import (
    handle_realtime_json_capture,
    handle_protocol_statistics,
    handle_analyze_pcap_enhanced
)

async def main():
    parser = argparse.ArgumentParser(description="Enhanced Wireshark MCP Tools Bridge")
    
    subparsers = parser.add_subparsers(dest='tool', help='Available enhanced tools')
    
    # Real-time JSON Capture
    json_parser = subparsers.add_parser('realtime_json_capture', 
                                       help='Real-time JSON packet capture')
    json_parser.add_argument('--interface', required=True, help='Network interface')
    json_parser.add_argument('--duration', type=int, default=10, help='Duration in seconds')
    json_parser.add_argument('--filter', default='', help='BPF filter')
    json_parser.add_argument('--max_packets', type=int, default=100, help='Max packets')
    json_parser.add_argument('--json_format', choices=['ek', 'json', 'jsonraw'], 
                           default='ek', help='JSON format')
    
    # Protocol Statistics
    stats_parser = subparsers.add_parser('protocol_statistics',
                                        help='Protocol statistics and conversations')
    stats_parser.add_argument('--source', required=True, help='PCAP file path or "live"')
    stats_parser.add_argument('--analysis_type', 
                            choices=['protocol_hierarchy', 'conversations', 'endpoints', 'io_stats', 'all'],
                            default='all', help='Analysis type')
    stats_parser.add_argument('--protocol', choices=['tcp', 'udp', 'ip', 'all'],
                            default='all', help='Protocol filter')
    
    # Enhanced PCAP Analysis
    enhanced_parser = subparsers.add_parser('analyze_pcap_enhanced',
                                          help='Enhanced PCAP file analysis')
    enhanced_parser.add_argument('--filepath', required=True, help='PCAP file path')
    enhanced_parser.add_argument('--analysis_type',
                               choices=['quick', 'comprehensive', 'security', 'performance', 'conversations', 'statistics'],
                               default='comprehensive', help='Analysis type')
    enhanced_parser.add_argument('--chunk_size', type=int, default=10000,
                               help='Processing chunk size')
    enhanced_parser.add_argument('--output_format', choices=['text', 'json', 'summary'],
                               default='json', help='Output format')
    
    args = parser.parse_args()
    
    if not args.tool:
        parser.print_help()
        return
    
    print(f"🚀 Running Enhanced Tool: {args.tool}")
    print("=" * 60)
    
    try:
        if args.tool == 'realtime_json_capture':
            tool_args = {
                'interface': args.interface,
                'duration': args.duration,
                'filter': args.filter,
                'max_packets': args.max_packets,
                'json_format': args.json_format
            }
            result = await handle_realtime_json_capture(tool_args)
            
        elif args.tool == 'protocol_statistics':
            tool_args = {
                'source': args.source,
                'analysis_type': args.analysis_type,
                'protocol': args.protocol
            }
            result = await handle_protocol_statistics(tool_args)
            
        elif args.tool == 'analyze_pcap_enhanced':
            tool_args = {
                'filepath': args.filepath,
                'analysis_type': args.analysis_type,
                'chunk_size': args.chunk_size,
                'output_format': args.output_format
            }
            result = await handle_analyze_pcap_enhanced(tool_args)
        
        # Print results
        for content in result:
            print(content.text)
            
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())