#!/usr/bin/env python3
"""
Enhanced Wireshark MCP Server v3.0 - Fully Implemented
======================================================

18 tools for comprehensive network traffic analysis via MCP protocol.
All stub implementations replaced with real tshark-based analysis.
All subprocess calls are async. Comprehensive input validation.
MCP resources and prompts registered.
"""

import asyncio
import json
import logging
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime
from collections import defaultdict

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    Tool,
    TextContent,
)

from src.utilities import (
    run_command_async,
    run_tshark_command,
    get_temp_filepath,
    delayed_cleanup,
    parse_protocol_hierarchy,
    parse_conversations,
    parse_endpoints,
    parse_io_statistics,
    parse_capinfos_machine_output,
    parse_capinfos_output,
    parse_expert_info,
    parse_http_stats,
    parse_ip_range,
    combine_filters_intelligently,
    generate_contextual_suggestions,
    generate_analysis_summary,
    generate_text_report,
)
from src.tools import (
    WiresharkPCAPTimeSlicer,
    WiresharkPCAPSplitter,
    WiresharkPCAPMerger,
    WiresharkHexToPCAP,
    WiresharkHTTPAnalyzer,
    WiresharkDNSAnalyzer,
    WiresharkSSLInspector,
    WiresharkLatencyProfiler,
    WiresharkThreatDetector,
    WiresharkRemoteCapture,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

server = Server("wireshark-mcp-enhanced")

ACTIVE_CAPTURES: Dict[str, Any] = {}


# ===== MCP RESOURCES =====

@server.list_resources()
async def list_resources() -> List[Resource]:
    """List available MCP resources."""
    return [
        Resource(
            uri="wireshark://documentation/filters",
            name="Wireshark Display Filter Reference",
            description="Common Wireshark display filters and examples for network analysis",
            mimeType="text/plain",
        ),
        Resource(
            uri="wireshark://documentation/protocols",
            name="Protocol Analysis Guide",
            description="Guide for analyzing common network protocols with tshark",
            mimeType="text/plain",
        ),
        Resource(
            uri="wireshark://status/server",
            name="Server Status",
            description="Current status of the Wireshark MCP server and available tools",
            mimeType="application/json",
        ),
    ]


@server.read_resource()
async def read_resource(uri: str) -> str:
    """Read a specific resource."""
    if uri == "wireshark://documentation/filters":
        return """# Wireshark Display Filter Quick Reference

## IP Filters
- ip.addr == 192.168.1.1          - Traffic to/from IP
- ip.src == 10.0.0.0/24           - Source subnet
- ip.dst == 8.8.8.8               - Destination IP

## Protocol Filters
- http                             - All HTTP traffic
- dns                              - All DNS traffic
- tls                              - All TLS/SSL traffic
- tcp                              - All TCP traffic
- udp                              - All UDP traffic
- icmp                             - All ICMP traffic

## TCP Analysis
- tcp.analysis.retransmission      - Retransmissions
- tcp.analysis.duplicate_ack       - Duplicate ACKs
- tcp.analysis.zero_window         - Zero window events
- tcp.analysis.ack_rtt > 0.1       - High RTT (>100ms)
- tcp.flags.syn==1 and tcp.flags.ack==0  - SYN packets only

## HTTP Analysis
- http.request.method == "GET"     - GET requests
- http.response.code >= 400        - Error responses
- http.host contains "example"     - Host filter

## Security
- tcp.port == 23                   - Telnet (insecure)
- ftp                              - FTP (cleartext)
- dns.qry.name.len > 50           - Long DNS names (tunneling)
"""
    elif uri == "wireshark://documentation/protocols":
        return """# Protocol Analysis Guide

## HTTP Analysis
Use wireshark_http_analyzer for deep HTTP inspection including:
- Transaction extraction with request/response pairs
- Performance metrics (response times, throughput)
- Security analysis (SQL injection, XSS detection)

## DNS Analysis
Use wireshark_dns_analyzer for DNS traffic analysis:
- Query extraction and domain frequency analysis
- Response code analysis (NOERROR, NXDOMAIN, SERVFAIL)
- DNS tunneling detection via long domain names and high volume patterns

## TLS/SSL Inspection
Use wireshark_ssl_inspector for encrypted traffic analysis:
- Handshake analysis with TLS version detection
- Certificate extraction (subject, validity, DNS names)
- Cipher suite analysis with weak cipher detection

## Threat Detection
Use wireshark_threat_detector for security analysis:
- 12 built-in threat signatures (port scans, floods, etc.)
- Behavioral analysis (beaconing, data exfiltration)
- Anomaly detection (volume spikes, unusual patterns)
"""
    elif uri == "wireshark://status/server":
        return json.dumps({
            "server": "wireshark-mcp-enhanced",
            "version": "3.0.0",
            "status": "active",
            "tools_count": 18,
            "capabilities": [
                "Live Capture", "PCAP Analysis", "Filter Generation",
                "Protocol Statistics", "HTTP Analysis", "DNS Analysis",
                "SSL/TLS Inspection", "Threat Detection", "Latency Profiling",
                "PCAP Manipulation", "Remote Capture",
            ],
        }, indent=2)
    return f"Resource not found: {uri}"


# ===== MCP PROMPTS =====

@server.list_prompts()
async def list_prompts() -> List[Dict[str, Any]]:
    """List available MCP prompts for guided workflows."""
    return [
        {
            "name": "analyze_network_issue",
            "description": "Guided workflow to analyze a network connectivity or performance issue",
            "arguments": [
                {"name": "pcap_file", "description": "Path to PCAP file to analyze", "required": True},
                {"name": "issue_type", "description": "Type: connectivity, performance, security", "required": False},
            ],
        },
        {
            "name": "security_audit",
            "description": "Comprehensive security audit of network traffic",
            "arguments": [
                {"name": "pcap_file", "description": "Path to PCAP file", "required": True},
            ],
        },
    ]


@server.get_prompt()
async def get_prompt(name: str, arguments: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """Get a specific prompt."""
    if name == "analyze_network_issue":
        pcap = (arguments or {}).get("pcap_file", "<pcap_file>")
        issue = (arguments or {}).get("issue_type", "general")
        return {
            "description": f"Analyze network issue in {pcap}",
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": f"""Please analyze the network capture at {pcap} for {issue} issues.
Run these tools in order:
1. wireshark_validate_setup - Verify environment
2. wireshark_analyze_pcap_enhanced with analysis_type=comprehensive
3. wireshark_protocol_statistics with analysis_type=all
4. wireshark_latency_profiler with analysis_type=comprehensive
5. wireshark_threat_detector with detection_mode=comprehensive
Summarize findings with actionable recommendations.""",
                    },
                }
            ],
        }
    elif name == "security_audit":
        pcap = (arguments or {}).get("pcap_file", "<pcap_file>")
        return {
            "description": f"Security audit of {pcap}",
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": f"""Perform a comprehensive security audit on {pcap}:
1. wireshark_threat_detector with detection_mode=comprehensive, sensitivity=high
2. wireshark_ssl_inspector with analysis_type=comprehensive
3. wireshark_http_analyzer with analysis_type=security
4. wireshark_dns_analyzer with analysis_type=comprehensive, detect_tunneling=true
Report all findings with severity ratings.""",
                    },
                }
            ],
        }
    return {"description": "Unknown prompt", "messages": []}


# ===== TOOL LISTING =====

@server.list_tools()
async def list_tools() -> List[Tool]:
    """List all available enhanced Wireshark MCP tools."""
    logger.info("Listing Enhanced Wireshark MCP tools")
    return [
        Tool(
            name="wireshark_system_info",
            description="Get system information and available network interfaces",
            inputSchema={
                "type": "object",
                "properties": {
                    "info_type": {
                        "type": "string",
                        "enum": ["interfaces", "capabilities", "system", "all"],
                        "description": "Type of system information to retrieve",
                        "default": "all",
                    }
                },
            },
        ),
        Tool(
            name="wireshark_validate_setup",
            description="Validate Wireshark installation and all dependencies",
            inputSchema={
                "type": "object",
                "properties": {
                    "full_check": {
                        "type": "boolean",
                        "description": "Perform comprehensive validation",
                        "default": False,
                    }
                },
            },
        ),
        Tool(
            name="wireshark_generate_filter",
            description="Generate Wireshark display filters from natural language descriptions",
            inputSchema={
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "Natural language description of desired traffic",
                    },
                    "complexity": {
                        "type": "string",
                        "enum": ["simple", "intermediate", "advanced"],
                        "description": "Desired filter complexity level",
                        "default": "intermediate",
                    },
                },
                "required": ["description"],
            },
        ),
        Tool(
            name="wireshark_live_capture",
            description="Capture live network traffic with intelligent filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {"type": "string", "description": "Network interface (e.g., 'eth0', 'any')"},
                    "duration": {"type": "integer", "description": "Capture duration in seconds", "default": 60},
                    "filter": {"type": "string", "description": "BPF capture filter", "default": ""},
                    "max_packets": {"type": "integer", "description": "Maximum packets to capture", "default": 1000},
                },
                "required": ["interface"],
            },
        ),
        Tool(
            name="wireshark_analyze_pcap",
            description="Analyze existing PCAP files with comprehensive reporting",
            inputSchema={
                "type": "object",
                "properties": {
                    "filepath": {"type": "string", "description": "Path to PCAP/PCAPNG file"},
                    "analysis_type": {
                        "type": "string",
                        "enum": ["quick", "comprehensive", "security", "performance"],
                        "default": "comprehensive",
                    },
                },
                "required": ["filepath"],
            },
        ),
        Tool(
            name="wireshark_realtime_json_capture",
            description="Capture live traffic in real-time JSON format with streaming support",
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {"type": "string", "description": "Network interface"},
                    "duration": {"type": "integer", "description": "Duration in seconds", "default": 30},
                    "filter": {"type": "string", "description": "BPF capture filter", "default": ""},
                    "max_packets": {"type": "integer", "description": "Max packets", "default": 1000},
                    "json_format": {
                        "type": "string", "enum": ["ek", "json", "jsonraw"],
                        "description": "JSON output format", "default": "ek",
                    },
                },
                "required": ["interface"],
            },
        ),
        Tool(
            name="wireshark_protocol_statistics",
            description="Generate comprehensive protocol statistics and conversation analysis",
            inputSchema={
                "type": "object",
                "properties": {
                    "source": {"type": "string", "description": "'live' for interface or path to PCAP"},
                    "analysis_type": {
                        "type": "string",
                        "enum": ["protocol_hierarchy", "conversations", "endpoints", "io_stats", "all"],
                        "default": "all",
                    },
                    "protocol": {"type": "string", "enum": ["tcp", "udp", "ip", "all"], "default": "all"},
                    "time_interval": {"type": "integer", "description": "I/O stats interval (seconds)", "default": 60},
                },
                "required": ["source"],
            },
        ),
        Tool(
            name="wireshark_analyze_pcap_enhanced",
            description="Enhanced PCAP analysis with streaming support for large files",
            inputSchema={
                "type": "object",
                "properties": {
                    "filepath": {"type": "string", "description": "Path to PCAP/PCAPNG file"},
                    "analysis_type": {
                        "type": "string",
                        "enum": ["quick", "comprehensive", "security", "performance", "conversations", "statistics"],
                        "default": "comprehensive",
                    },
                    "chunk_size": {"type": "integer", "description": "Packets to process at once", "default": 10000},
                    "output_format": {
                        "type": "string", "enum": ["text", "json", "summary"], "default": "json",
                    },
                },
                "required": ["filepath"],
            },
        ),
        Tool(
            name="wireshark_pcap_time_slice",
            description="Extract specific time windows from PCAP captures using editcap",
            inputSchema={
                "type": "object",
                "properties": {
                    "input_file": {"type": "string", "description": "Path to input PCAP file"},
                    "start_time": {"type": "string", "description": "Start time (ISO format)"},
                    "end_time": {"type": "string", "description": "End time (ISO format)"},
                    "output_file": {"type": "string", "description": "Output file path (optional)"},
                },
                "required": ["input_file", "start_time", "end_time"],
            },
        ),
        Tool(
            name="wireshark_pcap_splitter",
            description="Split PCAP files by various criteria using editcap",
            inputSchema={
                "type": "object",
                "properties": {
                    "input_file": {"type": "string", "description": "Path to input PCAP file"},
                    "split_type": {"type": "string", "enum": ["packets", "time", "size"], "default": "packets"},
                    "split_value": {"type": "integer", "description": "Split value (packets/seconds/MB)", "default": 1000},
                    "output_prefix": {"type": "string", "description": "Prefix for output files"},
                },
                "required": ["input_file"],
            },
        ),
        Tool(
            name="wireshark_pcap_merger",
            description="Intelligently merge multiple PCAP files using mergecap",
            inputSchema={
                "type": "object",
                "properties": {
                    "input_files": {"type": "array", "items": {"type": "string"}, "description": "PCAP files to merge"},
                    "output_file": {"type": "string", "description": "Output merged file path"},
                    "sort_chronologically": {"type": "boolean", "default": True},
                },
                "required": ["input_files", "output_file"],
            },
        ),
        Tool(
            name="wireshark_hex_to_pcap",
            description="Convert hex dumps to PCAP format using text2pcap",
            inputSchema={
                "type": "object",
                "properties": {
                    "input_source": {"type": "string", "description": "Hex data or path to hex file"},
                    "input_type": {"type": "string", "enum": ["file", "text"]},
                    "output_file": {"type": "string", "description": "Output PCAP file path"},
                    "protocol": {"type": "string", "enum": ["ethernet", "tcp", "udp"], "default": "ethernet"},
                },
                "required": ["input_source", "input_type", "output_file"],
            },
        ),
        Tool(
            name="wireshark_http_analyzer",
            description="Deep HTTP traffic analysis with performance metrics and security checks",
            inputSchema={
                "type": "object",
                "properties": {
                    "input_file": {"type": "string", "description": "Path to PCAP file"},
                    "analysis_type": {
                        "type": "string",
                        "enum": ["transactions", "performance", "security", "comprehensive"],
                        "default": "comprehensive",
                    },
                    "extract_payloads": {"type": "boolean", "default": False},
                },
                "required": ["input_file"],
            },
        ),
        Tool(
            name="wireshark_dns_analyzer",
            description="DNS query analysis with response parsing and intelligence gathering",
            inputSchema={
                "type": "object",
                "properties": {
                    "input_file": {"type": "string", "description": "Path to PCAP file"},
                    "analysis_type": {
                        "type": "string",
                        "enum": ["queries", "responses", "intelligence", "comprehensive"],
                        "default": "comprehensive",
                    },
                    "detect_tunneling": {"type": "boolean", "default": True},
                },
                "required": ["input_file"],
            },
        ),
        Tool(
            name="wireshark_ssl_inspector",
            description="SSL/TLS inspection with certificate extraction and cipher suite analysis",
            inputSchema={
                "type": "object",
                "properties": {
                    "input_file": {"type": "string", "description": "Path to PCAP file"},
                    "analysis_type": {
                        "type": "string",
                        "enum": ["handshakes", "certificates", "ciphers", "comprehensive"],
                        "default": "comprehensive",
                    },
                    "key_file": {"type": "string", "description": "Path to SSL key file (optional)"},
                },
                "required": ["input_file"],
            },
        ),
        Tool(
            name="wireshark_latency_profiler",
            description="Network latency profiling with TCP, application, and network layer analysis",
            inputSchema={
                "type": "object",
                "properties": {
                    "input_file": {"type": "string", "description": "Path to PCAP file"},
                    "analysis_type": {
                        "type": "string",
                        "enum": ["tcp", "application", "network", "comprehensive"],
                        "default": "comprehensive",
                    },
                    "time_window": {"type": "number", "description": "Time window (seconds)", "default": 1.0},
                },
                "required": ["input_file"],
            },
        ),
        Tool(
            name="wireshark_threat_detector",
            description="Threat detection with 12 signatures, behavioral analysis, and anomaly detection",
            inputSchema={
                "type": "object",
                "properties": {
                    "input_file": {"type": "string", "description": "Path to PCAP file"},
                    "detection_mode": {
                        "type": "string",
                        "enum": ["anomaly", "signature", "behavioral", "comprehensive"],
                        "default": "comprehensive",
                    },
                    "sensitivity": {"type": "string", "enum": ["low", "medium", "high"], "default": "medium"},
                },
                "required": ["input_file"],
            },
        ),
        Tool(
            name="wireshark_remote_capture",
            description="Distributed packet capture via SSH with connection validation",
            inputSchema={
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Remote host IP or hostname"},
                    "username": {"type": "string", "description": "SSH username"},
                    "interface": {"type": "string", "default": "any"},
                    "duration": {"type": "integer", "default": 60},
                    "filter": {"type": "string", "description": "Capture filter (optional)"},
                    "port": {"type": "integer", "default": 22},
                    "key_file": {"type": "string", "description": "SSH key file (optional)"},
                },
                "required": ["host", "username"],
            },
        ),
    ]


# ===== TOOL DISPATCH =====

@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Handle tool calls for enhanced Wireshark MCP operations."""
    if arguments is None:
        arguments = {}
    logger.info(f"Calling tool: {name} with args: {arguments}")
    try:
        handlers = {
            "wireshark_system_info": handle_system_info,
            "wireshark_validate_setup": handle_validate_setup,
            "wireshark_generate_filter": handle_generate_filter,
            "wireshark_live_capture": handle_live_capture,
            "wireshark_analyze_pcap": handle_analyze_pcap,
            "wireshark_realtime_json_capture": handle_realtime_json_capture,
            "wireshark_protocol_statistics": handle_protocol_statistics,
            "wireshark_analyze_pcap_enhanced": handle_analyze_pcap_enhanced,
            "wireshark_pcap_time_slice": handle_pcap_time_slice,
            "wireshark_pcap_splitter": handle_pcap_split,
            "wireshark_pcap_merger": handle_pcap_merge,
            "wireshark_hex_to_pcap": handle_hex_to_pcap,
            "wireshark_http_analyzer": handle_http_analyzer,
            "wireshark_dns_analyzer": handle_dns_analyzer,
            "wireshark_ssl_inspector": handle_ssl_inspector,
            "wireshark_latency_profiler": handle_latency_profiler,
            "wireshark_threat_detector": handle_threat_detector,
            "wireshark_remote_capture": handle_remote_capture,
        }
        handler = handlers.get(name)
        if handler:
            return await handler(arguments)
        return [TextContent(type="text", text=f"❌ Unknown tool: {name}")]
    except Exception as e:
        logger.error(f"Error calling tool {name}: {e}")
        return [TextContent(type="text", text=f"❌ Error: {str(e)}")]


# ===== HANDLER IMPLEMENTATIONS =====

async def handle_system_info(args: Dict[str, Any]) -> List[TextContent]:
    info_type = args.get("info_type", "all")
    result: Dict[str, Any] = {
        "wireshark_mcp_server": "3.0.0 Enhanced",
        "status": "✅ Active",
        "capabilities": [
            "Live Capture", "PCAP Analysis", "Filter Generation",
            "Security Analysis", "JSON Streaming", "Protocol Statistics",
            "HTTP Analysis", "DNS Analysis", "SSL/TLS Inspection",
            "Threat Detection", "Latency Profiling", "Remote Capture",
        ],
    }
    if info_type in ["interfaces", "all"]:
        try:
            proc = await asyncio.create_subprocess_exec(
                "ip", "-o", "link", "show",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            if proc.returncode == 0:
                interfaces = []
                for line in stdout.decode().strip().split("\n"):
                    match = re.match(r"\d+:\s+(\S+?)(?:@\S+)?:", line)
                    if match:
                        interfaces.append(match.group(1))
                result["network_interfaces"] = interfaces
            else:
                result["network_interfaces"] = ["Unable to retrieve interfaces"]
        except asyncio.TimeoutError:
            result["network_interfaces"] = ["Timeout retrieving interfaces"]
        except FileNotFoundError:
            result["network_interfaces"] = ["'ip' command not found"]
        except OSError as e:
            result["network_interfaces"] = [f"Error: {str(e)}"]

    if info_type in ["capabilities", "all"]:
        result["tools_available"] = [
            "System Information", "Setup Validation", "Filter Generation",
            "Live Capture", "PCAP Analysis", "Real-time JSON Capture",
            "Protocol Statistics", "Enhanced Analysis", "PCAP Time Slicer",
            "PCAP Splitter", "PCAP Merger", "Hex to PCAP",
            "HTTP Analyzer", "DNS Analyzer", "SSL/TLS Inspector",
            "Latency Profiler", "Threat Detector", "Remote Capture",
        ]

    if info_type in ["system", "all"]:
        result["python_version"] = os.sys.version.split()[0]
        result["platform"] = os.sys.platform

    return [TextContent(type="text", text=f"🦈 **Wireshark MCP System Information**\n\n{json.dumps(result, indent=2)}")]


async def handle_validate_setup(args: Dict[str, Any]) -> List[TextContent]:
    full_check = args.get("full_check", False)
    validation: Dict[str, Any] = {
        "wireshark_mcp_server": "✅ Running (Enhanced v3.0)",
        "python_version": f"✅ {os.sys.version.split()[0]}",
        "dependencies": {},
    }

    tools_to_check = ["tshark", "tcpdump", "dumpcap", "capinfos", "editcap", "mergecap", "text2pcap"]
    for tool in tools_to_check:
        try:
            proc = await asyncio.create_subprocess_exec(
                "which", tool, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            if proc.returncode == 0:
                validation["dependencies"][tool] = f"✅ {stdout.decode().strip()}"
            else:
                validation["dependencies"][tool] = "❌ Not found"
        except asyncio.TimeoutError:
            validation["dependencies"][tool] = "❌ Timeout"
        except OSError as e:
            validation["dependencies"][tool] = f"❌ Error: {str(e)}"

    try:
        proc = await asyncio.create_subprocess_exec(
            "ip", "link", "show", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
        validation["network_access"] = "✅ Available" if proc.returncode == 0 else "❌ Limited"
    except (asyncio.TimeoutError, OSError):
        validation["network_access"] = "❌ Error checking access"

    validation["enhanced_features"] = {
        "json_capture": "✅ Available",
        "protocol_statistics": "✅ Available",
        "streaming_analysis": "✅ Available",
        "threat_detection": "✅ Available (12 signatures)",
        "ssl_inspection": "✅ Available",
        "latency_profiling": "✅ Available",
    }

    return [TextContent(type="text", text=f"🔍 **Wireshark MCP Setup Validation**\n\n{json.dumps(validation, indent=2)}")]


async def handle_generate_filter(args: Dict[str, Any]) -> List[TextContent]:
    description = args.get("description", "")
    if not description or not description.strip():
        return [TextContent(
            type="text",
            text="❌ **Error**: Description is required. Please provide a natural language description of the traffic you want to filter.",
        )]

    complexity = args.get("complexity", "intermediate")
    generated_filter = await advanced_filter_generation(description, complexity)
    result = {
        "description": description,
        "generated_filter": generated_filter["filter"],
        "complexity": complexity,
        "suggestions": generated_filter["suggestions"],
        "matched_patterns": generated_filter["matched_patterns"],
        "parsing_notes": generated_filter.get("notes", []),
    }
    return [TextContent(
        type="text",
        text=f"🎯 **Generated Wireshark Filter**\n\n**Input**: {description}\n\n**Filter**: `{generated_filter['filter']}`\n\n**Details**:\n{json.dumps(result, indent=2)}",
    )]


async def handle_live_capture(args: Dict[str, Any]) -> List[TextContent]:
    interface = args.get("interface", "")
    if not interface:
        return [TextContent(type="text", text="❌ **Error**: Interface is required (e.g., 'eth0', 'lo', 'any')")]
    duration = min(max(args.get("duration", 60), 1), 300)
    filter_expr = args.get("filter", "")
    max_packets = min(max(args.get("max_packets", 1000), 1), 100000)

    try:
        capture_result = await perform_live_capture_enhanced(interface, duration, filter_expr, max_packets)
        return [TextContent(type="text", text=f"📡 **Live Packet Capture Results**\n\n{json.dumps(capture_result, indent=2)}")]
    except Exception as e:
        return [TextContent(type="text", text=f"❌ **Live Capture Failed**\n\nError: {str(e)}")]


async def handle_analyze_pcap(args: Dict[str, Any]) -> List[TextContent]:
    filepath = args.get("filepath", "")
    if not filepath:
        return [TextContent(type="text", text="❌ Error: No filepath provided")]
    if not os.path.exists(filepath):
        return [TextContent(type="text", text=f"❌ Error: File not found: {filepath}")]
    if not os.access(filepath, os.R_OK):
        return [TextContent(type="text", text=f"❌ Error: Cannot read file: {filepath}")]
    analysis_type = args.get("analysis_type", "comprehensive")

    try:
        analysis_result = await analyze_pcap_file(filepath, analysis_type)
        return [TextContent(type="text", text=f"📊 **PCAP Analysis Results**\n\n{json.dumps(analysis_result, indent=2)}")]
    except Exception as e:
        return [TextContent(type="text", text=f"❌ **PCAP Analysis Failed**\n\nError: {str(e)}")]


async def handle_realtime_json_capture(args: Dict[str, Any]) -> List[TextContent]:
    interface = args.get("interface", "")
    if not interface:
        return [TextContent(type="text", text="❌ **Error**: Interface is required")]
    duration = min(max(args.get("duration", 30), 1), 300)
    filter_expr = args.get("filter", "")
    max_packets = min(max(args.get("max_packets", 1000), 1), 100000)
    json_format = args.get("json_format", "ek")

    capture_id = f"capture_{int(time.time())}"
    try:
        tshark_cmd = ["tshark", "-i", interface, "-T", json_format, "-l", "-c", str(max_packets), "-a", f"duration:{duration}"]
        if filter_expr:
            tshark_cmd.extend(["-f", filter_expr])

        logger.info(f"Starting real-time JSON capture: {' '.join(tshark_cmd)}")
        process = await asyncio.create_subprocess_exec(
            *tshark_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        ACTIVE_CAPTURES[capture_id] = {
            "process": process, "interface": interface,
            "started_at": datetime.now().isoformat(), "packets": [],
        }

        packets_captured = 0
        packet_buffer: List[Any] = []
        start_time = time.time()
        raw_buffer = ""

        while True:
            try:
                line = await asyncio.wait_for(process.stdout.readline(), timeout=1.0)
                if not line:
                    break
                decoded = line.decode().strip()
                if not decoded:
                    continue

                # Handle both line-delimited (ek) and array-wrapped (json) formats
                if json_format == "json":
                    raw_buffer += line.decode()
                    # Try to parse accumulated buffer
                    try:
                        parsed = json.loads(raw_buffer)
                        if isinstance(parsed, list):
                            packet_buffer.extend(parsed)
                            packets_captured += len(parsed)
                        elif isinstance(parsed, dict):
                            packet_buffer.append(parsed)
                            packets_captured += 1
                        raw_buffer = ""
                    except json.JSONDecodeError:
                        continue
                else:
                    try:
                        packet_json = json.loads(decoded)
                        packet_buffer.append(packet_json)
                        packets_captured += 1
                    except json.JSONDecodeError:
                        continue

                if len(packet_buffer) >= 10:
                    ACTIVE_CAPTURES[capture_id]["packets"].extend(packet_buffer)
                    packet_buffer.clear()
                if packets_captured >= max_packets or time.time() - start_time >= duration:
                    break
            except asyncio.TimeoutError:
                if process.returncode is not None:
                    break
                continue

        # Try to parse any remaining json buffer
        if json_format == "json" and raw_buffer.strip():
            try:
                parsed = json.loads(raw_buffer)
                if isinstance(parsed, list):
                    packet_buffer.extend(parsed)
                    packets_captured += len(parsed)
                elif isinstance(parsed, dict):
                    packet_buffer.append(parsed)
                    packets_captured += 1
            except json.JSONDecodeError:
                pass

        if packet_buffer:
            ACTIVE_CAPTURES[capture_id]["packets"].extend(packet_buffer)

        if process.returncode is None:
            process.terminate()
            await process.wait()

        capture_stats: Dict[str, Any] = {
            "capture_id": capture_id,
            "status": "✅ Capture Complete",
            "interface": interface,
            "duration": f"{time.time() - start_time:.2f} seconds",
            "filter": filter_expr or "none",
            "packets_captured": packets_captured,
            "json_format": json_format,
            "sample_packets": ACTIVE_CAPTURES[capture_id]["packets"][:5],
            "total_packets_stored": len(ACTIVE_CAPTURES[capture_id]["packets"]),
        }

        if packets_captured > 0:
            protocol_summary: Dict[str, int] = {}
            for packet in ACTIVE_CAPTURES[capture_id]["packets"]:
                if not isinstance(packet, dict):
                    continue
                if json_format == "ek":
                    layers = packet.get("layers", {})
                    if isinstance(layers, dict):
                        for layer in layers:
                            protocol_summary[layer] = protocol_summary.get(layer, 0) + 1
                elif json_format in ("json", "jsonraw"):
                    source = packet.get("_source", {})
                    if isinstance(source, dict):
                        layers = source.get("layers", {})
                        if isinstance(layers, dict):
                            for layer in layers:
                                protocol_summary[layer] = protocol_summary.get(layer, 0) + 1
            capture_stats["protocol_summary"] = protocol_summary

        return [TextContent(
            type="text",
            text=f"📡 **Real-time JSON Capture Results**\n\n```json\n{json.dumps(capture_stats, indent=2)}\n```",
        )]
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"❌ **Real-time Capture Failed**\n\nError: {str(e)}\n\nTroubleshooting:\n- Verify interface with: ip link show\n- Check permissions: groups $USER",
        )]


async def handle_protocol_statistics(args: Dict[str, Any]) -> List[TextContent]:
    source = args.get("source", "")
    if not source:
        return [TextContent(type="text", text="❌ Error: No source specified")]
    analysis_type = args.get("analysis_type", "all")
    protocol = args.get("protocol", "all")
    time_interval = max(args.get("time_interval", 60), 1)
    statistics_results: Dict[str, Any] = {}

    try:
        if analysis_type in ["protocol_hierarchy", "all"]:
            cmd = ["tshark", "-q", "-z", "io,phs"]
            cmd.extend(["-r", source] if source != "live" else ["-i", "any", "-a", "duration:10"])
            result = await run_tshark_command(cmd)
            statistics_results["protocol_hierarchy"] = parse_protocol_hierarchy(result.stdout)

        if analysis_type in ["conversations", "all"]:
            conversations = {}
            protos = ["tcp", "udp", "ip"] if protocol == "all" else [protocol]
            for proto in protos:
                cmd = ["tshark", "-q", "-z", f"conv,{proto}"]
                cmd.extend(["-r", source] if source != "live" else ["-i", "any", "-a", "duration:10"])
                result = await run_tshark_command(cmd)
                conversations[proto] = parse_conversations(result.stdout)
            statistics_results["conversations"] = conversations

        if analysis_type in ["endpoints", "all"]:
            endpoints = {}
            protos = ["tcp", "udp", "ip"] if protocol == "all" else [protocol]
            for proto in protos:
                cmd = ["tshark", "-q", "-z", f"endpoints,{proto}"]
                cmd.extend(["-r", source] if source != "live" else ["-i", "any", "-a", "duration:10"])
                result = await run_tshark_command(cmd)
                endpoints[proto] = parse_endpoints(result.stdout)
            statistics_results["endpoints"] = endpoints

        if analysis_type in ["io_stats", "all"]:
            cmd = ["tshark", "-q", "-z", f"io,stat,{time_interval}"]
            cmd.extend(["-r", source] if source != "live" else ["-i", "any", "-a", "duration:60"])
            result = await run_tshark_command(cmd)
            statistics_results["io_statistics"] = parse_io_statistics(result.stdout)

        summary = {"source": source, "analysis_type": analysis_type, "timestamp": datetime.now().isoformat(), "statistics": statistics_results}
        if "protocol_hierarchy" in statistics_results:
            ph = statistics_results["protocol_hierarchy"]
            if ph.get("total_packets"):
                protos = ph.get("protocols", {})
                dominant = max(protos, key=lambda k: protos[k].get("packets", 0)) if protos else "none"
                summary["insights"] = {"total_packets": ph["total_packets"], "total_bytes": ph.get("total_bytes", 0), "dominant_protocol": dominant}

        return [TextContent(type="text", text=f"📊 **Protocol Statistics & Conversation Analysis**\n\n```json\n{json.dumps(summary, indent=2)}\n```")]
    except Exception as e:
        return [TextContent(type="text", text=f"❌ **Statistics Generation Failed**\n\nError: {str(e)}")]


async def handle_analyze_pcap_enhanced(args: Dict[str, Any]) -> List[TextContent]:
    filepath = args.get("filepath", "")
    if not filepath or not os.path.exists(filepath):
        return [TextContent(type="text", text="❌ Error: File not found")]
    analysis_type = args.get("analysis_type", "comprehensive")
    output_format = args.get("output_format", "json")
    file_size = os.path.getsize(filepath)
    analysis_results: Dict[str, Any] = {
        "file_info": {"path": filepath, "size": f"{file_size:,} bytes", "size_mb": f"{file_size / 1024 / 1024:.2f} MB"},
    }

    try:
        cmd = ["capinfos", "-M", filepath]
        result = await run_tshark_command(cmd, ignore_errors=True)
        analysis_results["file_metadata"] = parse_capinfos_machine_output(result.stdout)

        if analysis_type == "quick":
            cmd = ["tshark", "-r", filepath, "-q", "-z", "io,phs"]
            result = await run_tshark_command(cmd)
            analysis_results["quick_stats"] = parse_protocol_hierarchy(result.stdout)
        elif analysis_type == "conversations":
            conversations = {}
            for proto in ["tcp", "udp", "ip"]:
                cmd = ["tshark", "-r", filepath, "-q", "-z", f"conv,{proto}"]
                result = await run_tshark_command(cmd)
                conversations[proto] = parse_conversations(result.stdout)
            analysis_results["conversations"] = conversations
        elif analysis_type == "statistics":
            cmd = ["tshark", "-r", filepath, "-q", "-z", "io,phs"]
            result = await run_tshark_command(cmd)
            analysis_results["protocol_hierarchy"] = parse_protocol_hierarchy(result.stdout)
            cmd = ["tshark", "-r", filepath, "-q", "-z", "expert"]
            result = await run_tshark_command(cmd, ignore_errors=True)
            analysis_results["expert_info"] = parse_expert_info(result.stdout)
            cmd = ["tshark", "-r", filepath, "-q", "-z", "http,tree"]
            result = await run_tshark_command(cmd, ignore_errors=True)
            if result.returncode == 0:
                analysis_results["http_stats"] = parse_http_stats(result.stdout)
        elif analysis_type == "security":
            analysis_results["security_analysis"] = await perform_security_analysis(filepath)
        elif analysis_type == "performance":
            analysis_results["performance_analysis"] = await perform_performance_analysis(filepath)
        else:
            cmd = ["tshark", "-r", filepath, "-q", "-z", "io,phs"]
            result = await run_tshark_command(cmd)
            analysis_results["protocol_hierarchy"] = parse_protocol_hierarchy(result.stdout)
            conversations = {}
            for proto in ["tcp", "udp"]:
                cmd = ["tshark", "-r", filepath, "-q", "-z", f"conv,{proto}"]
                result = await run_tshark_command(cmd)
                conversations[proto] = parse_conversations(result.stdout)
            analysis_results["conversations"] = conversations
            cmd = ["tshark", "-r", filepath, "-q", "-z", "expert"]
            result = await run_tshark_command(cmd, ignore_errors=True)
            analysis_results["expert_info"] = parse_expert_info(result.stdout)
            analysis_results["security_analysis"] = await perform_security_analysis(filepath)
            analysis_results["performance_analysis"] = await perform_performance_analysis(filepath)

        if output_format == "json":
            return [TextContent(type="text", text=f"📊 **Enhanced PCAP Analysis Results**\n\n```json\n{json.dumps(analysis_results, indent=2)}\n```")]
        elif output_format == "summary":
            return [TextContent(type="text", text=generate_analysis_summary(analysis_results))]
        else:
            return [TextContent(type="text", text=generate_text_report(analysis_results))]
    except Exception as e:
        return [TextContent(type="text", text=f"❌ **PCAP Analysis Failed**\n\nError: {str(e)}")]


async def handle_pcap_time_slice(args: Dict[str, Any]) -> List[TextContent]:
    try:
        slicer = WiresharkPCAPTimeSlicer()
        result = await slicer.slice_by_time_range(
            input_file=args.get("input_file", ""),
            start_time=args.get("start_time", ""),
            end_time=args.get("end_time", ""),
            output_file=args.get("output_file"),
        )
        if result["status"].startswith("✅"):
            text = f"🦈 **PCAP Time Slice Results**\n\n✅ **Operation Successful**\n\n📁 **Files:**\n- Input: {result['input_file']}\n- Output: {result['output_file']}\n\n⏰ **Time Range:**\n- Start: {result['time_range']['start']}\n- End: {result['time_range']['end']}\n\n📊 **Statistics:**\n```json\n{json.dumps(result['statistics'], indent=2)}\n```"
        else:
            text = f"❌ **PCAP Time Slice Failed**\n\nError: {result.get('error', 'Unknown error')}"
        return [TextContent(type="text", text=text)]
    except Exception as e:
        return [TextContent(type="text", text=f"❌ **PCAP Time Slice Failed**\n\nError: {str(e)}")]


async def handle_pcap_split(args: Dict[str, Any]) -> List[TextContent]:
    try:
        splitter = WiresharkPCAPSplitter()
        result = await splitter.split_pcap(
            input_file=args.get("input_file", ""),
            split_type=args.get("split_type", "packets"),
            split_value=args.get("split_value", 1000),
            output_prefix=args.get("output_prefix"),
        )
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except Exception as e:
        return [TextContent(type="text", text=f"❌ Error: {str(e)}")]


async def handle_pcap_merge(args: Dict[str, Any]) -> List[TextContent]:
    try:
        merger = WiresharkPCAPMerger()
        result = await merger.merge_pcaps(
            input_files=args.get("input_files", []),
            output_file=args.get("output_file", ""),
            sort_chronologically=args.get("sort_chronologically", True),
        )
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except Exception as e:
        return [TextContent(type="text", text=f"❌ Error: {str(e)}")]


async def handle_hex_to_pcap(args: Dict[str, Any]) -> List[TextContent]:
    try:
        converter = WiresharkHexToPCAP()
        result = await converter.convert_hex_to_pcap(
            input_source=args.get("input_source", ""),
            input_type=args.get("input_type", "text"),
            output_file=args.get("output_file", ""),
            protocol=args.get("protocol", "ethernet"),
        )
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except Exception as e:
        return [TextContent(type="text", text=f"❌ Error: {str(e)}")]


async def handle_http_analyzer(args: Dict[str, Any]) -> List[TextContent]:
    try:
        analyzer = WiresharkHTTPAnalyzer()
        result = await analyzer.analyze_http_traffic(
            input_file=args.get("input_file", ""),
            analysis_type=args.get("analysis_type", "comprehensive"),
            extract_payloads=args.get("extract_payloads", False),
        )
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except Exception as e:
        return [TextContent(type="text", text=f"❌ Error: {str(e)}")]


async def handle_dns_analyzer(args: Dict[str, Any]) -> List[TextContent]:
    try:
        analyzer = WiresharkDNSAnalyzer()
        result = await analyzer.analyze_dns_queries(
            input_file=args.get("input_file", ""),
            analysis_type=args.get("analysis_type", "comprehensive"),
            detect_tunneling=args.get("detect_tunneling", True),
        )
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except Exception as e:
        return [TextContent(type="text", text=f"❌ Error: {str(e)}")]


async def handle_ssl_inspector(args: Dict[str, Any]) -> List[TextContent]:
    try:
        inspector = WiresharkSSLInspector()
        result = await inspector.inspect_ssl_traffic(
            input_file=args.get("input_file", ""),
            analysis_type=args.get("analysis_type", "comprehensive"),
            key_file=args.get("key_file"),
        )
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except Exception as e:
        return [TextContent(type="text", text=f"❌ Error: {str(e)}")]


async def handle_latency_profiler(args: Dict[str, Any]) -> List[TextContent]:
    try:
        profiler = WiresharkLatencyProfiler()
        result = await profiler.profile_latency(
            input_file=args.get("input_file", ""),
            analysis_type=args.get("analysis_type", "comprehensive"),
            time_window=args.get("time_window", 1.0),
        )
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except Exception as e:
        return [TextContent(type="text", text=f"❌ Error: {str(e)}")]


async def handle_threat_detector(args: Dict[str, Any]) -> List[TextContent]:
    try:
        detector = WiresharkThreatDetector()
        result = await detector.detect_threats(
            input_file=args.get("input_file", ""),
            detection_mode=args.get("detection_mode", "comprehensive"),
            sensitivity=args.get("sensitivity", "medium"),
        )
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except Exception as e:
        return [TextContent(type="text", text=f"❌ Error: {str(e)}")]


async def handle_remote_capture(args: Dict[str, Any]) -> List[TextContent]:
    try:
        capturer = WiresharkRemoteCapture()
        result = await capturer.capture_remote(
            host=args.get("host", ""),
            username=args.get("username", ""),
            interface=args.get("interface", "any"),
            duration=args.get("duration", 60),
            filter=args.get("filter"),
            port=args.get("port", 22),
            key_file=args.get("key_file"),
        )
        return [TextContent(type="text", text=json.dumps(result, indent=2))]
    except Exception as e:
        return [TextContent(type="text", text=f"❌ Error: {str(e)}")]


# ===== CORE ANALYSIS FUNCTIONS =====

async def perform_security_analysis(filepath: str) -> Dict[str, Any]:
    security_findings: Dict[str, Any] = {"suspicious_patterns": {}, "threat_indicators": 0}
    checks = [
        ("TCP SYN Flood", "tcp.flags.syn==1 and tcp.flags.ack==0"),
        ("Port Scan", "tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024"),
        ("DNS Tunneling", "dns and frame.len > 512"),
        ("Suspicious HTTP", "http.request.method == POST and frame.len > 8192"),
        ("Non-standard Ports", "tcp.port > 49151 or udp.port > 49151"),
        ("ICMP Tunneling", "icmp and data.len > 48"),
        ("ARP Spoofing", "arp.opcode == 2"),
    ]
    for check_name, filter_expr in checks:
        try:
            cmd = ["tshark", "-r", filepath, "-Y", filter_expr, "-T", "fields", "-e", "frame.number"]
            result = await run_tshark_command(cmd, timeout=60, ignore_errors=True)
            if result.returncode == 0 and result.stdout.strip():
                count = len(result.stdout.strip().split("\n"))
                security_findings["suspicious_patterns"][check_name] = count
                security_findings["threat_indicators"] += 1
        except RuntimeError as e:
            logger.warning(f"Security check '{check_name}' failed: {e}")
    return security_findings


async def perform_performance_analysis(filepath: str) -> Dict[str, Any]:
    perf: Dict[str, Any] = {"tcp_issues": {}, "overall_health": "Unknown"}
    checks = [
        ("Retransmissions", "tcp.analysis.retransmission"),
        ("Duplicate ACKs", "tcp.analysis.duplicate_ack"),
        ("Zero Window", "tcp.analysis.zero_window"),
        ("Window Full", "tcp.analysis.window_full"),
        ("Out of Order", "tcp.analysis.out_of_order"),
        ("Fast Retransmission", "tcp.analysis.fast_retransmission"),
    ]
    total_issues = 0
    for check_name, filter_expr in checks:
        try:
            cmd = ["tshark", "-r", filepath, "-Y", filter_expr, "-T", "fields", "-e", "frame.number"]
            result = await run_tshark_command(cmd, timeout=60, ignore_errors=True)
            if result.returncode == 0 and result.stdout.strip():
                count = len(result.stdout.strip().split("\n"))
                perf["tcp_issues"][check_name] = count
                total_issues += count
            else:
                perf["tcp_issues"][check_name] = 0
        except RuntimeError as e:
            logger.warning(f"Performance check '{check_name}' failed: {e}")
            perf["tcp_issues"][check_name] = 0

    perf["overall_health"] = "Excellent" if total_issues == 0 else "Good" if total_issues < 100 else "Fair" if total_issues < 1000 else "Poor"
    perf["total_issues"] = total_issues
    return perf


async def analyze_pcap_file(filepath: str, analysis_type: str) -> Dict[str, Any]:
    file_info: Dict[str, Any] = {
        "file": filepath,
        "file_size": f"{os.path.getsize(filepath)} bytes",
        "analysis_type": analysis_type,
    }
    try:
        try:
            cmd = ["capinfos", filepath]
            result = await run_tshark_command(cmd, timeout=30, ignore_errors=True)
            if result.returncode == 0:
                file_info["file_details"] = parse_capinfos_output(result.stdout)
        except RuntimeError:
            pass

        if analysis_type == "quick":
            analysis_result = await quick_pcap_analysis(filepath)
        elif analysis_type == "security":
            analysis_result = await security_pcap_analysis(filepath)
        elif analysis_type == "performance":
            analysis_result = await performance_pcap_analysis(filepath)
        else:
            analysis_result = await comprehensive_pcap_analysis(filepath)

        return {"status": "✅ Analysis Complete", "file_info": file_info, **analysis_result}
    except Exception as e:
        return {"status": "❌ Analysis Error", "file_info": file_info, "error": str(e)}


async def quick_pcap_analysis(filepath: str) -> Dict[str, Any]:
    try:
        cmd = ["tshark", "-r", filepath, "-q", "-z", "io,phs"]
        result = await run_tshark_command(cmd, timeout=30)
        stats = parse_protocol_hierarchy(result.stdout)
        return {"analysis_summary": {"total_packets": stats["total_packets"], "protocols": stats["protocols"]}}
    except RuntimeError as e:
        return {"quick_analysis_error": str(e)}


async def security_pcap_analysis(filepath: str) -> Dict[str, Any]:
    try:
        security_findings: Dict[str, Any] = {}
        patterns = [
            ("TCP SYN flood", "tcp.flags.syn==1 and tcp.flags.ack==0"),
            ("Port scan indicators", "tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024"),
            ("DNS tunneling", 'dns.qry.name contains "." and frame.len > 512'),
            ("Large HTTP requests", "http.request and frame.len > 8192"),
            ("Non-standard ports", "tcp.port > 49151 or udp.port > 49151"),
        ]
        for name, filter_expr in patterns:
            try:
                cmd = ["tshark", "-r", filepath, "-Y", filter_expr, "-T", "fields", "-e", "frame.number"]
                result = await run_tshark_command(cmd, timeout=30, ignore_errors=True)
                if result.returncode == 0 and result.stdout.strip():
                    security_findings[name] = f"{len(result.stdout.strip().split(chr(10)))} occurrences"
            except RuntimeError:
                security_findings[name] = "Analysis failed"
        return {"security_analysis": security_findings, "threat_indicators": len([v for v in security_findings.values() if "occurrences" in str(v)])}
    except Exception as e:
        return {"security_analysis_error": str(e)}


async def performance_pcap_analysis(filepath: str) -> Dict[str, Any]:
    try:
        metrics: Dict[str, Any] = {}
        issues = [
            ("Retransmissions", "tcp.analysis.retransmission"),
            ("Duplicate ACKs", "tcp.analysis.duplicate_ack"),
            ("Zero Window", "tcp.analysis.zero_window"),
            ("Keep Alive", "tcp.analysis.keep_alive"),
        ]
        for name, filter_expr in issues:
            try:
                cmd = ["tshark", "-r", filepath, "-Y", filter_expr, "-T", "fields", "-e", "frame.number"]
                result = await run_tshark_command(cmd, timeout=30, ignore_errors=True)
                if result.returncode == 0 and result.stdout.strip():
                    metrics[name] = len(result.stdout.strip().split("\n"))
                else:
                    metrics[name] = 0
            except RuntimeError:
                metrics[name] = 0
        total = sum(v for v in metrics.values() if isinstance(v, int))
        return {"performance_analysis": metrics, "network_health": "Good" if total == 0 else "Issues detected"}
    except Exception as e:
        return {"performance_analysis_error": str(e)}


async def comprehensive_pcap_analysis(filepath: str) -> Dict[str, Any]:
    try:
        quick = await quick_pcap_analysis(filepath)
        security = await security_pcap_analysis(filepath)
        performance = await performance_pcap_analysis(filepath)

        comp_stats: Dict[str, Any] = {}
        try:
            cmd = ["tshark", "-r", filepath, "-q", "-z", "conv,tcp"]
            result = await run_tshark_command(cmd, timeout=30, ignore_errors=True)
            if result.returncode == 0:
                comp_stats["tcp_conversations"] = len([l for l in result.stdout.split("\n") if "<->" in l])
        except RuntimeError:
            comp_stats["tcp_conversations"] = 0

        return {"comprehensive_analysis": {**quick, **security, **performance, "additional_stats": comp_stats}}
    except Exception as e:
        return {"comprehensive_analysis_error": str(e)}


async def perform_live_capture_enhanced(interface: str, duration: int, filter_expr: str, max_packets: int) -> Dict[str, Any]:
    capture_start = asyncio.get_event_loop().time()

    # Method 1: tshark direct
    try:
        cmd = ["tshark", "-i", interface, "-c", str(max_packets), "-a", f"duration:{duration}", "-T", "json"]
        if filter_expr:
            cmd.extend(["-f", filter_expr])
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=duration + 30)
        if proc.returncode == 0:
            try:
                packets = json.loads(stdout.decode()) if stdout.decode().strip() else []
                return {
                    "status": "✅ Success", "method_used": "tshark_direct",
                    "interface": interface, "duration": duration, "filter": filter_expr,
                    "packets_captured": len(packets), "max_packets": max_packets,
                    "packets": packets[:10],
                    "capture_time_seconds": round(asyncio.get_event_loop().time() - capture_start, 2),
                }
            except json.JSONDecodeError:
                pass
        logger.info(f"tshark direct failed, trying fallback")
    except (asyncio.TimeoutError, OSError) as e:
        logger.info(f"tshark failed: {e}, trying fallback")

    # Method 2: tcpdump + tshark
    pcap_file = get_temp_filepath(prefix="capture_", suffix=".pcap")
    try:
        cmd = ["timeout", str(duration + 10), "tcpdump", "-i", interface, "-w", pcap_file, "-c", str(max_packets), "-q"]
        if filter_expr:
            cmd.append(filter_expr)
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        await asyncio.wait_for(proc.communicate(), timeout=duration + 15)
        if proc.returncode in [0, 124] and Path(pcap_file).exists() and Path(pcap_file).stat().st_size > 0:
            parse_cmd = ["tshark", "-r", pcap_file, "-T", "json", "-c", str(min(10, max_packets))]
            parse_proc = await asyncio.create_subprocess_exec(*parse_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            pout, _ = await parse_proc.communicate()
            if parse_proc.returncode == 0:
                try:
                    packets = json.loads(pout.decode()) if pout.decode().strip() else []
                    return {
                        "status": "✅ Success", "method_used": "tcpdump + tshark",
                        "interface": interface, "duration": duration, "filter": filter_expr,
                        "packets_captured": len(packets), "packets": packets,
                        "capture_time_seconds": round(asyncio.get_event_loop().time() - capture_start, 2),
                    }
                except json.JSONDecodeError:
                    pass
    except (asyncio.TimeoutError, OSError) as e:
        logger.info(f"tcpdump fallback failed: {e}")
    finally:
        if os.path.exists(pcap_file):
            os.unlink(pcap_file)

    return {
        "status": "❌ All capture methods failed",
        "interface": interface, "duration": duration, "filter": filter_expr,
        "capture_time_seconds": round(asyncio.get_event_loop().time() - capture_start, 2),
        "error": "Permission denied - all capture methods failed",
        "recommendations": [
            "sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump",
            "sudo usermod -a -G wireshark $USER",
        ],
    }


async def advanced_filter_generation(description: str, complexity: str) -> Dict[str, Any]:
    description_lower = description.lower()
    matched_patterns: List[str] = []
    filter_parts: List[str] = []
    notes: List[str] = []

    patterns = {
        "ip_address": (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", lambda m: f"ip.addr == {m.group()}"),
        "subnet_cidr": (r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b", lambda m: f"ip.addr == {m.group()}"),
        "ip_range": (r"\b(?:\d{1,3}\.){3}\d{1,3}\s*-\s*(?:\d{1,3}\.){3}\d{1,3}\b", lambda m: parse_ip_range(m.group())),
        "port_number": (r"\bport\s+(\d+)\b", lambda m: f"tcp.port == {m.group(1)} or udp.port == {m.group(1)}"),
        "port_range": (r"\bports?\s+(\d+)\s*-\s*(\d+)\b", lambda m: f"(tcp.port >= {m.group(1)} and tcp.port <= {m.group(2)}) or (udp.port >= {m.group(1)} and udp.port <= {m.group(2)})"),
        "http_traffic": (r"\bhttp\b(?!\w)", lambda m: "http"),
        "https_traffic": (r"\bhttps?\s+secure|ssl|tls\b", lambda m: "tls"),
        "dns_queries": (r"\bdns\b(?!\w)", lambda m: "dns"),
        "email_traffic": (r"\bemail|smtp|pop|imap\b", lambda m: "smtp or pop or imap"),
        "ssh_traffic": (r"\bssh\b(?!\w)", lambda m: "ssh"),
        "ftp_traffic": (r"\bftp\b(?!\w)", lambda m: "ftp"),
        "slow_connections": (r"\bslow|high\s+latency|delayed?\b", lambda m: "tcp.analysis.ack_rtt > 0.1"),
        "error_traffic": (r"\berrors?|retransmission|failed?\b", lambda m: "tcp.analysis.retransmission or tcp.analysis.duplicate_ack"),
        "large_packets": (r"\blarge\s+packets?|big\s+frames?\b", lambda m: "frame.len > 1500"),
        "hostname": (r"\b(?:host|server|domain)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b", lambda m: f'ip.host == "{m.group(1)}"'),
        "contains_domain": (r"\b(?:contains?|includes?)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b", lambda m: f'http.host contains "{m.group(1)}"'),
    }
    protocol_keywords = {
        "web": "http or tls", "tcp": "tcp", "udp": "udp", "icmp": "icmp",
        "ping": "icmp", "arp": "arp", "broadcast": "eth.dst == ff:ff:ff:ff:ff:ff",
    }

    for name, (regex, formatter) in patterns.items():
        for match in re.finditer(regex, description_lower):
            try:
                filter_parts.append(formatter(match))
                matched_patterns.append(name)
                notes.append(f"Detected {name}: {match.group()}")
            except (ValueError, IndexError) as e:
                notes.append(f"Error parsing {name}: {str(e)}")

    if not filter_parts:
        for kw, filt in protocol_keywords.items():
            if kw in description_lower:
                filter_parts.append(filt)
                matched_patterns.append(f"keyword_{kw}")

    if filter_parts:
        final_filter = filter_parts[0] if len(filter_parts) == 1 else combine_filters_intelligently(filter_parts, description_lower)
    else:
        final_filter = "tcp or udp" if any(w in description_lower for w in ["traffic", "packets", "network"]) else "tcp"
        notes.append("Used fallback filter - consider more specific description")

    return {
        "filter": final_filter,
        "matched_patterns": matched_patterns,
        "suggestions": generate_contextual_suggestions(description_lower, matched_patterns),
        "notes": notes,
    }


# ===== MAIN ENTRY POINT =====

async def main():
    """Main server entry point."""
    logger.info("Starting Enhanced Wireshark MCP Server v3.0")
    logger.info("Features: 18 tools, MCP resources, prompts, full analysis")
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
