#!/usr/bin/env python3
"""
Advanced Tools Integration for Wireshark MCP Server
==================================================

This module integrates the 10 advanced Wireshark tools into the MCP server.

Tools included:
1. PCAP Time Slicer - Extract specific time windows from captures
2. PCAP Splitter - Split large captures by packets/time/size
3. PCAP Merger - Intelligently merge multiple captures
4. Hex-to-PCAP Converter - Convert hex dumps to analyzable format
5. HTTP Deep Analyzer - Deep HTTP/HTTPS transaction analysis
6. DNS Query Analyzer - DNS traffic intelligence and tunneling detection
7. SSL/TLS Inspector - Certificate analysis and traffic decryption
8. Latency Profiler - Network performance profiling
9. Threat Detector - AI-powered security threat detection
10. Remote Capture - Distributed packet capture via SSH
"""

from typing import List, Dict, Any
from mcp.types import Tool

# Import the advanced tools implementations
from advanced_tools_implementation import (
    WiresharkPCAPTimeSlicer,
    WiresharkPCAPSplitter,
    WiresharkPCAPMerger,
    WiresharkHexToPCAP,
    WiresharkHTTPAnalyzer,
    WiresharkDNSAnalyzer,
    WiresharkSSLInspector,
    WiresharkLatencyProfiler,
    WiresharkThreatDetector,
    WiresharkRemoteCapture
)

# Initialize tool instances
pcap_slicer = WiresharkPCAPTimeSlicer()
pcap_splitter = WiresharkPCAPSplitter()
pcap_merger = WiresharkPCAPMerger()
hex_converter = WiresharkHexToPCAP()
http_analyzer = WiresharkHTTPAnalyzer()
dns_analyzer = WiresharkDNSAnalyzer()
ssl_inspector = WiresharkSSLInspector()
latency_profiler = WiresharkLatencyProfiler()
threat_detector = WiresharkThreatDetector()
remote_capture = WiresharkRemoteCapture()


def get_advanced_tool_definitions() -> List[Tool]:
    """Get MCP tool definitions for all advanced tools."""
    return [
        # 1. PCAP Time Slicer
        Tool(
            name="wireshark_pcap_time_slice",
            description="Extract specific time windows from PCAP captures using editcap",
            inputSchema={
                "type": "object",
                "properties": {
                    "input_file": {
                        "type": "string",
                        "description": "Input PCAP file path"
                    },
                    "start_time": {
                        "type": "string",
                        "description": "Start time (ISO format: YYYY-MM-DDThh:mm:ss or Unix epoch)"
                    },
                    "end_time": {
                        "type": "string",
                        "description": "End time (ISO format: YYYY-MM-DDThh:mm:ss or Unix epoch)"
                    },
                    "output_file": {
                        "type": "string",
                        "description": "Output file path (optional)",
                        "default": None
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["time_range", "duration", "relative"],
                        "description": "Slicing mode",
                        "default": "time_range"
                    },
                    "duration_seconds": {
                        "type": "integer",
                        "description": "Duration in seconds (for duration mode)",
                        "default": 60
                    },
                    "start_offset": {
                        "type": "number",
                        "description": "Start offset in seconds (for relative mode)",
                        "default": 0
                    },
                    "end_offset": {
                        "type": "number",
                        "description": "End offset in seconds (for relative mode)",
                        "default": 60
                    }
                },
                "required": ["input_file", "start_time"],
                "additionalProperties": False
            }
        ),
        
        # 2. PCAP Splitter
        Tool(
            name="wireshark_pcap_split",
            description="Split large PCAP files by packets, time, or size",
            inputSchema={
                "type": "object",
                "properties": {
                    "input_file": {
                        "type": "string",
                        "description": "Input PCAP file path"
                    },
                    "split_by": {
                        "type": "string",
                        "enum": ["packets", "time", "size"],
                        "description": "Split criteria",
                        "default": "packets"
                    },
                    "value": {
                        "type": "integer",
                        "description": "Split value (packets count, seconds, or MB)",
                        "default": 1000
                    },
                    "output_prefix": {
                        "type": "string",
                        "description": "Output file prefix (optional)",
                        "default": None
                    }
                },
                "required": ["input_file"],
                "additionalProperties": False
            }
        ),
        
        # 3. PCAP Merger
        Tool(
            name="wireshark_pcap_merge",
            description="Intelligently merge multiple PCAP files",
            inputSchema={
                "type": "object",
                "properties": {
                    "input_files": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of PCAP files to merge"
                    },
                    "output_file": {
                        "type": "string",
                        "description": "Output file path (optional)",
                        "default": None
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["chronological", "append"],
                        "description": "Merge mode",
                        "default": "chronological"
                    },
                    "remove_duplicates": {
                        "type": "boolean",
                        "description": "Remove duplicate packets",
                        "default": False
                    }
                },
                "required": ["input_files"],
                "additionalProperties": False
            }
        ),
        
        # 4. Hex-to-PCAP Converter
        Tool(
            name="wireshark_hex_to_pcap",
            description="Convert hex dumps to analyzable PCAP format",
            inputSchema={
                "type": "object",
                "properties": {
                    "hex_input": {
                        "type": "string",
                        "description": "Hex dump string or file path"
                    },
                    "output_file": {
                        "type": "string",
                        "description": "Output PCAP file path (optional)",
                        "default": None
                    },
                    "encapsulation": {
                        "type": "string",
                        "enum": ["ethernet", "ip", "udp", "tcp"],
                        "description": "Encapsulation type",
                        "default": "ethernet"
                    },
                    "add_fake_headers": {
                        "type": "boolean",
                        "description": "Add fake headers for incomplete data",
                        "default": True
                    }
                },
                "required": ["hex_input"],
                "additionalProperties": False
            }
        ),
        
        # 5. HTTP Deep Analyzer
        Tool(
            name="wireshark_http_analyze",
            description="Deep HTTP/HTTPS transaction analysis",
            inputSchema={
                "type": "object",
                "properties": {
                    "input_file": {
                        "type": "string",
                        "description": "Input PCAP file path"
                    },
                    "analysis_type": {
                        "type": "string",
                        "enum": ["flows", "performance", "objects"],
                        "description": "Type of HTTP analysis",
                        "default": "flows"
                    },
                    "include_bodies": {
                        "type": "boolean",
                        "description": "Include HTTP request/response bodies",
                        "default": True
                    },
                    "decode_gzip": {
                        "type": "boolean",
                        "description": "Decode gzip-compressed content",
                        "default": True
                    },
                    "output_dir": {
                        "type": "string",
                        "description": "Output directory for extracted objects",
                        "default": None
                    }
                },
                "required": ["input_file"],
                "additionalProperties": False
            }
        ),
        
        # 6. DNS Query Analyzer
        Tool(
            name="wireshark_dns_analyze",
            description="DNS traffic intelligence and tunneling detection",
            inputSchema={
                "type": "object",
                "properties": {
                    "input_file": {
                        "type": "string",
                        "description": "Input PCAP file path"
                    },
                    "analysis_type": {
                        "type": "string",
                        "enum": ["queries", "tunneling", "response"],
                        "description": "Type of DNS analysis",
                        "default": "queries"
                    },
                    "group_by_domain": {
                        "type": "boolean",
                        "description": "Group results by domain",
                        "default": True
                    },
                    "entropy_threshold": {
                        "type": "number",
                        "description": "Entropy threshold for tunneling detection",
                        "default": 3.5
                    }
                },
                "required": ["input_file"],
                "additionalProperties": False
            }
        ),
        
        # 7. SSL/TLS Inspector
        Tool(
            name="wireshark_ssl_inspect",
            description="SSL/TLS certificate analysis and traffic decryption",
            inputSchema={
                "type": "object",
                "properties": {
                    "input_file": {
                        "type": "string",
                        "description": "Input PCAP file path"
                    },
                    "analysis_type": {
                        "type": "string",
                        "enum": ["handshakes", "decrypt", "certificates"],
                        "description": "Type of SSL/TLS analysis",
                        "default": "handshakes"
                    },
                    "keylog_file": {
                        "type": "string",
                        "description": "SSL keylog file for decryption",
                        "default": None
                    },
                    "rsa_key_file": {
                        "type": "string",
                        "description": "RSA private key file for decryption",
                        "default": None
                    }
                },
                "required": ["input_file"],
                "additionalProperties": False
            }
        ),
        
        # 8. Latency Profiler
        Tool(
            name="wireshark_latency_profile",
            description="Network latency and performance profiling",
            inputSchema={
                "type": "object",
                "properties": {
                    "input_file": {
                        "type": "string",
                        "description": "Input PCAP file path"
                    },
                    "analysis_type": {
                        "type": "string",
                        "enum": ["tcp", "application", "heatmap"],
                        "description": "Type of latency analysis",
                        "default": "tcp"
                    },
                    "protocol": {
                        "type": "string",
                        "description": "Application protocol (for application analysis)",
                        "default": "http"
                    },
                    "percentiles": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Percentiles to calculate",
                        "default": [50, 90, 95, 99]
                    },
                    "time_bucket_seconds": {
                        "type": "integer",
                        "description": "Time bucket size for heatmap",
                        "default": 60
                    }
                },
                "required": ["input_file"],
                "additionalProperties": False
            }
        ),
        
        # 9. Threat Detector
        Tool(
            name="wireshark_threat_detect",
            description="AI-powered network threat detection",
            inputSchema={
                "type": "object",
                "properties": {
                    "input_file": {
                        "type": "string",
                        "description": "Input PCAP file path"
                    },
                    "threat_type": {
                        "type": "string",
                        "enum": ["port_scan", "ddos", "anomaly"],
                        "description": "Type of threat to detect",
                        "default": "port_scan"
                    },
                    "threshold_ports": {
                        "type": "integer",
                        "description": "Port threshold for scan detection",
                        "default": 10
                    },
                    "time_window": {
                        "type": "integer",
                        "description": "Time window in seconds",
                        "default": 60
                    },
                    "model_path": {
                        "type": "string",
                        "description": "ML model path for anomaly detection",
                        "default": None
                    }
                },
                "required": ["input_file"],
                "additionalProperties": False
            }
        ),
        
        # 10. Remote Capture
        Tool(
            name="wireshark_remote_capture",
            description="Distributed packet capture via SSH",
            inputSchema={
                "type": "object",
                "properties": {
                    "capture_mode": {
                        "type": "string",
                        "enum": ["single", "multi"],
                        "description": "Single or multi-host capture",
                        "default": "single"
                    },
                    "host": {
                        "type": "string",
                        "description": "Remote host for single capture"
                    },
                    "hosts": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "host": {"type": "string"},
                                "username": {"type": "string"},
                                "interface": {"type": "string", "default": "any"}
                            }
                        },
                        "description": "Host list for multi capture"
                    },
                    "username": {
                        "type": "string",
                        "description": "SSH username"
                    },
                    "password": {
                        "type": "string",
                        "description": "SSH password (optional)",
                        "default": None
                    },
                    "key_file": {
                        "type": "string",
                        "description": "SSH key file path (optional)",
                        "default": None
                    },
                    "interface": {
                        "type": "string",
                        "description": "Network interface",
                        "default": "any"
                    },
                    "filter": {
                        "type": "string",
                        "description": "Capture filter",
                        "default": ""
                    },
                    "duration": {
                        "type": "integer",
                        "description": "Capture duration in seconds",
                        "default": 60
                    },
                    "synchronized": {
                        "type": "boolean",
                        "description": "Synchronize multi-host capture",
                        "default": True
                    }
                },
                "required": ["username"],
                "additionalProperties": False
            }
        )
    ]


async def handle_advanced_tool(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Handle advanced tool calls."""
    
    # 1. PCAP Time Slicer
    if tool_name == "wireshark_pcap_time_slice":
        mode = arguments.get("mode", "time_range")
        
        if mode == "time_range":
            return await pcap_slicer.slice_by_time_range(
                arguments["input_file"],
                arguments["start_time"],
                arguments.get("end_time", arguments["start_time"]),
                arguments.get("output_file")
            )
        elif mode == "duration":
            return await pcap_slicer.slice_by_duration(
                arguments["input_file"],
                arguments["start_time"],
                arguments.get("duration_seconds", 60),
                arguments.get("output_file")
            )
        elif mode == "relative":
            return await pcap_slicer.slice_relative_time(
                arguments["input_file"],
                arguments.get("start_offset", 0),
                arguments.get("end_offset", 60),
                arguments.get("output_file")
            )
    
    # 2. PCAP Splitter
    elif tool_name == "wireshark_pcap_split":
        split_by = arguments.get("split_by", "packets")
        value = arguments.get("value", 1000)
        
        if split_by == "packets":
            return await pcap_splitter.split_by_packets(
                arguments["input_file"],
                value,
                arguments.get("output_prefix")
            )
        elif split_by == "time":
            return await pcap_splitter.split_by_time(
                arguments["input_file"],
                value,
                arguments.get("output_prefix")
            )
        elif split_by == "size":
            return await pcap_splitter.split_by_size(
                arguments["input_file"],
                value,
                arguments.get("output_prefix")
            )
    
    # 3. PCAP Merger
    elif tool_name == "wireshark_pcap_merge":
        mode = arguments.get("mode", "chronological")
        
        if mode == "chronological":
            return await pcap_merger.merge_chronological(
                arguments["input_files"],
                arguments.get("output_file"),
                arguments.get("remove_duplicates", False)
            )
        else:  # append mode
            return await pcap_merger.merge_append(
                arguments["input_files"],
                arguments.get("output_file")
            )
    
    # 4. Hex-to-PCAP Converter
    elif tool_name == "wireshark_hex_to_pcap":
        return await hex_converter.convert_hex_dump(
            arguments["hex_input"],
            arguments.get("output_file"),
            arguments.get("encapsulation", "ethernet"),
            arguments.get("add_fake_headers", True)
        )
    
    # 5. HTTP Deep Analyzer
    elif tool_name == "wireshark_http_analyze":
        analysis_type = arguments.get("analysis_type", "flows")
        
        if analysis_type == "flows":
            return await http_analyzer.extract_http_flows(
                arguments["input_file"],
                arguments.get("include_bodies", True),
                arguments.get("decode_gzip", True)
            )
        elif analysis_type == "performance":
            return await http_analyzer.analyze_http_performance(
                arguments["input_file"]
            )
        elif analysis_type == "objects":
            return await http_analyzer.extract_http_objects(
                arguments["input_file"],
                arguments.get("output_dir")
            )
    
    # 6. DNS Query Analyzer
    elif tool_name == "wireshark_dns_analyze":
        analysis_type = arguments.get("analysis_type", "queries")
        
        if analysis_type == "queries":
            return await dns_analyzer.analyze_dns_queries(
                arguments["input_file"],
                arguments.get("group_by_domain", True)
            )
        elif analysis_type == "tunneling":
            return await dns_analyzer.detect_dns_tunneling(
                arguments["input_file"],
                arguments.get("entropy_threshold", 3.5)
            )
        elif analysis_type == "response":
            return await dns_analyzer.dns_response_analysis(
                arguments["input_file"]
            )
    
    # 7. SSL/TLS Inspector
    elif tool_name == "wireshark_ssl_inspect":
        analysis_type = arguments.get("analysis_type", "handshakes")
        
        if analysis_type == "handshakes":
            return await ssl_inspector.analyze_ssl_handshakes(
                arguments["input_file"]
            )
        elif analysis_type == "decrypt":
            return await ssl_inspector.decrypt_ssl_traffic(
                arguments["input_file"],
                arguments.get("keylog_file"),
                arguments.get("rsa_key_file")
            )
        elif analysis_type == "certificates":
            return await ssl_inspector.ssl_certificate_analysis(
                arguments["input_file"]
            )
    
    # 8. Latency Profiler
    elif tool_name == "wireshark_latency_profile":
        analysis_type = arguments.get("analysis_type", "tcp")
        
        if analysis_type == "tcp":
            return await latency_profiler.analyze_tcp_latency(
                arguments["input_file"],
                arguments.get("percentiles", [50, 90, 95, 99])
            )
        elif analysis_type == "application":
            return await latency_profiler.analyze_application_latency(
                arguments["input_file"],
                arguments.get("protocol", "http")
            )
        elif analysis_type == "heatmap":
            return await latency_profiler.generate_latency_heatmap(
                arguments["input_file"],
                arguments.get("time_bucket_seconds", 60)
            )
    
    # 9. Threat Detector
    elif tool_name == "wireshark_threat_detect":
        threat_type = arguments.get("threat_type", "port_scan")
        
        if threat_type == "port_scan":
            return await threat_detector.detect_port_scans(
                arguments["input_file"],
                arguments.get("threshold_ports", 10),
                arguments.get("time_window", 60)
            )
        elif threat_type == "ddos":
            return await threat_detector.detect_ddos_patterns(
                arguments["input_file"]
            )
        elif threat_type == "anomaly":
            return await threat_detector.ml_anomaly_detection(
                arguments["input_file"],
                arguments.get("model_path")
            )
    
    # 10. Remote Capture
    elif tool_name == "wireshark_remote_capture":
        capture_mode = arguments.get("capture_mode", "single")
        
        if capture_mode == "single":
            return await remote_capture.capture_single_host(
                arguments.get("host", "localhost"),
                arguments["username"],
                arguments.get("password"),
                arguments.get("key_file"),
                arguments.get("interface", "any"),
                arguments.get("filter", ""),
                arguments.get("duration", 60)
            )
        else:  # multi mode
            return await remote_capture.capture_multi_host(
                arguments.get("hosts", []),
                arguments.get("synchronized", True)
            )
    
    return {"status": "❌ Error", "error": f"Unknown tool: {tool_name}"}