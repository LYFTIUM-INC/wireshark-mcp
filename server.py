#!/usr/bin/env python3
"""
Enhanced Wireshark MCP Server - Core Features Implementation
===========================================================

Implements:
1. Real-time JSON Packet Capture
2. Protocol Statistics & Conversations
3. Enhanced PCAP File Analysis

No external API dependencies - pure Wireshark/TShark functionality.
"""

import asyncio
import json
import logging
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, AsyncGenerator
from datetime import datetime
import shutil

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    Tool,
    TextContent,
)

# Configure logging only if not already configured or explicitly requested
logger = logging.getLogger(__name__)
if os.getenv("WIRESHARK_MCP_CONFIGURE_LOGGING") == "1" or not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

# Initialize the MCP server
server = Server("wireshark-mcp")

# Global state for active captures
ACTIVE_CAPTURES = {}

@server.list_tools()
async def list_tools() -> List[Tool]:
    """List all available enhanced Wireshark MCP tools."""
    logger.info("📋 Listing Enhanced Wireshark MCP tools")
    
    return [
        # Original tools
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
                        "default": "all"
                    }
                }
            }
        ),
        Tool(
            name="wireshark_validate_setup",
            description="Validate Wireshark installation and dependencies",
            inputSchema={
                "type": "object",
                "properties": {
                    "full_check": {
                        "type": "boolean",
                        "description": "Perform comprehensive validation",
                        "default": False
                    }
                }
            }
        ),
        Tool(
            name="wireshark_generate_filter",
            description="Generate Wireshark display filters from natural language descriptions",
            inputSchema={
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "Natural language description of desired traffic"
                    },
                    "complexity": {
                        "type": "string",
                        "enum": ["simple", "intermediate", "advanced"],
                        "description": "Desired filter complexity level",
                        "default": "intermediate"
                    }
                },
                "required": ["description"]
            }
        ),
        Tool(
            name="wireshark_live_capture",
            description="Capture live network traffic with intelligent filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {
                        "type": "string",
                        "description": "Network interface to capture from (e.g., 'eth0', 'any')"
                    },
                    "duration": {
                        "type": "integer",
                        "description": "Capture duration in seconds",
                        "default": 60
                    },
                    "filter": {
                        "type": "string",
                        "description": "Wireshark display filter",
                        "default": ""
                    },
                    "max_packets": {
                        "type": "integer",
                        "description": "Maximum number of packets to capture",
                        "default": 1000
                    },
                    "ring_files": {
                        "type": "integer",
                        "description": "Number of ring files to use",
                        "default": 5
                    },
                    "ring_megabytes": {
                        "type": "integer",
                        "description": "Maximum size of each ring file in megabytes",
                        "default": 10
                    },
                    "quick_triage": {
                        "type": "boolean",
                        "description": "Enable quick triage mode",
                        "default": False
                    }
                },
                "required": ["interface"]
            }
        ),
        Tool(
            name="wireshark_analyze_pcap",
            description="Analyze existing PCAP files with comprehensive reporting",
            inputSchema={
                "type": "object",
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Path to PCAP/PCAPNG file"
                    },
                    "analysis_type": {
                        "type": "string",
                        "enum": ["quick", "comprehensive", "security", "performance"],
                        "description": "Type of analysis to perform",
                        "default": "comprehensive"
                    }
                },
                "required": ["filepath"]
            }
        ),
        
        # NEW: Real-time JSON Packet Capture
        Tool(
            name="wireshark_realtime_json_capture",
            description="Capture live network traffic in real-time JSON format with streaming support",
            inputSchema={
                "type": "object",
                "properties": {
                    "interface": {
                        "type": "string",
                        "description": "Network interface to capture from (e.g., 'eth0', 'any')"
                    },
                    "duration": {
                        "type": "integer",
                        "description": "Capture duration in seconds",
                        "default": 30
                    },
                    "filter": {
                        "type": "string",
                        "description": "BPF capture filter",
                        "default": ""
                    },
                    "max_packets": {
                        "type": "integer",
                        "description": "Maximum number of packets to capture",
                        "default": 1000
                    },
                    "json_format": {
                        "type": "string",
                        "enum": ["ek", "json", "jsonraw"],
                        "description": "JSON output format (ek=Elasticsearch, json=standard, jsonraw=raw)",
                        "default": "ek"
                    }
                },
                "required": ["interface"]
            }
        ),
        
        # NEW: Protocol Statistics & Conversations
        Tool(
            name="wireshark_protocol_statistics",
            description="Generate comprehensive protocol statistics and conversation analysis",
            inputSchema={
                "type": "object",
                "properties": {
                    "source": {
                        "type": "string",
                        "description": "Source: 'live' for interface or path to PCAP file"
                    },
                    "analysis_type": {
                        "type": "string",
                        "enum": ["protocol_hierarchy", "conversations", "endpoints", "io_stats", "all"],
                        "description": "Type of statistical analysis",
                        "default": "all"
                    },
                    "protocol": {
                        "type": "string",
                        "enum": ["tcp", "udp", "ip", "all"],
                        "description": "Protocol to analyze for conversations",
                        "default": "all"
                    },
                    "time_interval": {
                        "type": "integer",
                        "description": "Time interval for I/O statistics (seconds)",
                        "default": 60
                    }
                },
                "required": ["source"]
            }
        ),
        
        # ENHANCED: PCAP File Analysis with more features
        Tool(
            name="wireshark_analyze_pcap_enhanced",
            description="Advanced PCAP file analysis with streaming support for large files",
            inputSchema={
                "type": "object",
                "properties": {
                    "filepath": {
                        "type": "string",
                        "description": "Path to PCAP/PCAPNG file"
                    },
                    "analysis_type": {
                        "type": "string",
                        "enum": ["quick", "comprehensive", "security", "performance", "conversations", "statistics"],
                        "description": "Type of analysis to perform",
                        "default": "comprehensive"
                    },
                    "chunk_size": {
                        "type": "integer",
                        "description": "Number of packets to process at once (for large files)",
                        "default": 10000
                    },
                    "output_format": {
                        "type": "string",
                        "enum": ["text", "json", "summary"],
                        "description": "Output format for analysis results",
                        "default": "json"
                    }
                },
                "required": ["filepath"]
            }
        )
    ]

@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Handle tool calls for enhanced Wireshark MCP operations."""
    logger.info(f"🔧 Calling tool: {name} with args: {arguments}")
    
    try:
        # Original tools
        if name == "wireshark_system_info":
            return await handle_system_info(arguments)
        elif name == "wireshark_validate_setup":
            return await handle_validate_setup(arguments)
        elif name == "wireshark_generate_filter":
            return await handle_generate_filter(arguments)
        elif name == "wireshark_live_capture":
            return await handle_live_capture(arguments)
        elif name == "wireshark_analyze_pcap":
            return await handle_analyze_pcap(arguments)
        
        # New enhanced tools
        elif name == "wireshark_realtime_json_capture":
            return await handle_realtime_json_capture(arguments)
        elif name == "wireshark_protocol_statistics":
            return await handle_protocol_statistics(arguments)
        elif name == "wireshark_analyze_pcap_enhanced":
            return await handle_analyze_pcap_enhanced(arguments)
        
        else:
            return [TextContent(type="text", text=f"❌ Unknown tool: {name}")]
    except Exception as e:
        logger.error(f"❌ Error calling tool {name}: {e}")
        return [TextContent(type="text", text=f"❌ Error: {str(e)}")]

async def handle_realtime_json_capture(args: Dict[str, Any]) -> List[TextContent]:
    """Handle real-time JSON packet capture with streaming support."""
    interface = args.get("interface", "any")
    duration = args.get("duration", 30)
    filter_expr = args.get("filter", "")
    max_packets = args.get("max_packets", 1000)
    json_format = args.get("json_format", "ek")
    
    capture_id = f"capture_{int(time.time())}"
    
    try:
        # Create temporary file for capture
        temp_file = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
        temp_file.close()
        
        # Build TShark command for real-time JSON output
        tshark_cmd = [
            "tshark",
            "-i", interface,
            "-T", json_format,  # JSON output format
            "-l",  # Line buffering for real-time output
            "-c", str(max_packets),
            "-a", f"duration:{duration}"
        ]
        
        if filter_expr:
            tshark_cmd.extend(["-f", filter_expr])
        
        logger.info(f"Starting real-time JSON capture: {' '.join(tshark_cmd)}")
        
        # Start capture process
        process = await asyncio.create_subprocess_exec(
            *tshark_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Store active capture info
        ACTIVE_CAPTURES[capture_id] = {
            "process": process,
            "interface": interface,
            "started_at": datetime.now().isoformat(),
            "packets": []
        }
        
        # Stream packets
        packets_captured = 0
        packet_buffer = []
        start_time = time.time()
        
        while True:
            try:
                # Read line with timeout
                line = await asyncio.wait_for(
                    process.stdout.readline(),
                    timeout=1.0
                )
                
                if not line:
                    break
                
                # Parse JSON packet
                try:
                    packet_json = json.loads(line.decode())
                    packet_buffer.append(packet_json)
                    packets_captured += 1
                    
                    # Batch packets for efficiency
                    if len(packet_buffer) >= 10:
                        ACTIVE_CAPTURES[capture_id]["packets"].extend(packet_buffer)
                        packet_buffer.clear()
                
                except json.JSONDecodeError:
                    continue
                
                # Check limits
                if packets_captured >= max_packets:
                    break
                    
                if time.time() - start_time >= duration:
                    break
                    
            except asyncio.TimeoutError:
                # Check if process is still running
                if process.returncode is not None:
                    break
                continue
        
        # Flush remaining packets
        if packet_buffer:
            ACTIVE_CAPTURES[capture_id]["packets"].extend(packet_buffer)
        
        # Terminate process if still running
        if process.returncode is None:
            process.terminate()
            await process.wait()
        
        # Get capture statistics
        capture_stats = {
            "capture_id": capture_id,
            "status": "✅ Capture Complete",
            "interface": interface,
            "duration": f"{time.time() - start_time:.2f} seconds",
            "filter": filter_expr or "none",
            "packets_captured": packets_captured,
            "json_format": json_format,
            "sample_packets": ACTIVE_CAPTURES[capture_id]["packets"][:5],  # First 5 packets as sample
            "total_packets_stored": len(ACTIVE_CAPTURES[capture_id]["packets"])
        }
        
        # Generate summary statistics
        if packets_captured > 0:
            protocol_summary = {}
            for packet in ACTIVE_CAPTURES[capture_id]["packets"]:
                # Extract protocol info based on format
                if json_format == "ek":
                    layers = packet.get("layers", {})
                    for layer in layers:
                        protocol_summary[layer] = protocol_summary.get(layer, 0) + 1
                elif json_format == "json":
                    # Handle standard JSON format
                    source = packet.get("_source", {})
                    layers = source.get("layers", {})
                    for layer in layers:
                        protocol_summary[layer] = protocol_summary.get(layer, 0) + 1
            
            capture_stats["protocol_summary"] = protocol_summary
        
        return [TextContent(
            type="text",
            text=f"📡 **Real-time JSON Capture Results**\n\n```json\n{json.dumps(capture_stats, indent=2)}\n```\n\n**Note**: Full packet data stored in memory. Use capture_id '{capture_id}' to retrieve all packets."
        )]
        
    except Exception as e:
        return [TextContent(
            type="text",
            text=f"❌ **Real-time Capture Failed**\n\nError: {str(e)}\n\nTroubleshooting:\n- Verify interface with: ip link show\n- Check permissions: groups $USER\n- Ensure TShark supports JSON: tshark -T ek -h"
        )]

# Result schema helper

def make_result(tool: str, ok: bool, method: str = "", data: Dict[str, Any] | None = None,
                diagnostics: List[str] | None = None, recommendations: List[str] | None = None) -> Dict[str, Any]:
    return {
        "ok": ok,
        "tool": tool,
        "method": method,
        "data": data or {},
        "diagnostics": diagnostics or [],
        "recommendations": recommendations or [],
    }

async def handle_protocol_statistics(args: Dict[str, Any]) -> List[TextContent]:
    """Generate comprehensive protocol statistics and conversation analysis."""
    source = args.get("source", "")
    analysis_type = args.get("analysis_type", "all")
    protocol = args.get("protocol", "all")
    time_interval = args.get("time_interval", 60)
    
    if not source:
        payload = make_result("wireshark_protocol_statistics", False, data={}, diagnostics=["Missing source"])
        return [TextContent(type="text", text=json.dumps(payload, indent=2))]
    
    statistics_results = {}
    
    try:
        # Protocol Hierarchy Statistics
        if analysis_type in ["protocol_hierarchy", "all"]:
            logger.info("Generating protocol hierarchy statistics...")
            
            cmd = ["tshark", "-q", "-z", "io,phs"]
            if source != "live":
                cmd.extend(["-r", source])
            else:
                # For live capture, use temporary capture
                cmd.extend(["-i", "any", "-a", "duration:10"])
            
            result = await run_tshark_command(cmd)
            statistics_results["protocol_hierarchy"] = parse_protocol_hierarchy(result.stdout)
        
        # Conversation Analysis
        if analysis_type in ["conversations", "all"]:
            logger.info("Analyzing network conversations...")
            
            conversations = {}
            protocols_to_analyze = ["tcp", "udp", "ip"] if protocol == "all" else [protocol]
            
            for proto in protocols_to_analyze:
                cmd = ["tshark", "-q", "-z", f"conv,{proto}"]
                if source != "live":
                    cmd.extend(["-r", source])
                else:
                    cmd.extend(["-i", "any", "-a", "duration:10"])
                
                result = await run_tshark_command(cmd)
                conversations[proto] = parse_conversations(result.stdout)
            
            statistics_results["conversations"] = conversations
        
        # Endpoint Analysis
        if analysis_type in ["endpoints", "all"]:
            logger.info("Analyzing network endpoints...")
            
            endpoints = {}
            protocols_to_analyze = ["tcp", "udp", "ip"] if protocol == "all" else [protocol]
            
            for proto in protocols_to_analyze:
                cmd = ["tshark", "-q", "-z", f"endpoints,{proto}"]
                if source != "live":
                    cmd.extend(["-r", source])
                else:
                    cmd.extend(["-i", "any", "-a", "duration:10"])
                
                result = await run_tshark_command(cmd)
                endpoints[proto] = parse_endpoints(result.stdout)
            
            statistics_results["endpoints"] = endpoints
        
        # I/O Statistics (Time-based)
        if analysis_type in ["io_stats", "all"]:
            logger.info("Generating I/O statistics...")
            
            cmd = ["tshark", "-q", "-z", f"io,stat,{time_interval}"]
            if source != "live":
                cmd.extend(["-r", source])
            else:
                cmd.extend(["-i", "any", "-a", "duration:60"])
            
            result = await run_tshark_command(cmd)
            statistics_results["io_statistics"] = parse_io_statistics(result.stdout)
        
        # Generate summary
        summary = {
            "source": source,
            "analysis_type": analysis_type,
            "timestamp": datetime.now().isoformat(),
            "statistics": statistics_results
        }
        payload = make_result("wireshark_protocol_statistics", True, method="tshark", data=summary)
        return [TextContent(type="text", text=json.dumps(payload, indent=2))]
        
    except Exception as e:
        payload = make_result("wireshark_protocol_statistics", False, diagnostics=[str(e)])
        return [TextContent(type="text", text=json.dumps(payload, indent=2))]

async def handle_analyze_pcap_enhanced(args: Dict[str, Any]) -> List[TextContent]:
    """Enhanced PCAP file analysis with streaming support for large files."""
    filepath = args.get("filepath", "")
    analysis_type = args.get("analysis_type", "comprehensive")
    chunk_size = args.get("chunk_size", 10000)
    output_format = args.get("output_format", "json")
    
    if not filepath or not os.path.exists(filepath):
        payload = make_result("wireshark_analyze_pcap_enhanced", False, diagnostics=["File not found"]) 
        return [TextContent(type="text", text=json.dumps(payload, indent=2))]
    
    file_size = os.path.getsize(filepath)
    analysis_results = {
        "file_info": {
            "path": filepath,
            "size": f"{file_size:,} bytes",
            "size_mb": f"{file_size / 1024 / 1024:.2f} MB"
        }
    }
    
    try:
        # Get file info using capinfos
        logger.info("Getting PCAP file information...")
        cmd = ["capinfos", "-M", filepath]  # Machine-readable output
        result = await run_tshark_command(cmd)
        analysis_results["file_metadata"] = parse_capinfos_machine_output(result.stdout)
        
        # Perform analysis based on type
        if analysis_type == "quick":
            # Quick packet count and basic stats
            logger.info("Performing quick analysis...")
            cmd = ["tshark", "-r", filepath, "-q", "-z", "io,phs"]
            result = await run_tshark_command(cmd)
            analysis_results["quick_stats"] = parse_protocol_hierarchy(result.stdout)
            
        elif analysis_type == "conversations":
            # Detailed conversation analysis
            logger.info("Analyzing conversations...")
            conversations = {}
            for proto in ["tcp", "udp", "ip"]:
                cmd = ["tshark", "-r", filepath, "-q", "-z", f"conv,{proto}"]
                result = await run_tshark_command(cmd)
                conversations[proto] = parse_conversations(result.stdout)
            analysis_results["conversations"] = conversations
            
        elif analysis_type == "statistics":
            # Comprehensive statistics
            logger.info("Generating comprehensive statistics...")
            
            # Protocol hierarchy
            cmd = ["tshark", "-r", filepath, "-q", "-z", "io,phs"]
            result = await run_tshark_command(cmd)
            analysis_results["protocol_hierarchy"] = parse_protocol_hierarchy(result.stdout)
            
            # Expert info (warnings, errors, etc.)
            cmd = ["tshark", "-r", filepath, "-q", "-z", "expert"]
            result = await run_tshark_command(cmd)
            analysis_results["expert_info"] = parse_expert_info(result.stdout)
            
            # HTTP statistics if present
            cmd = ["tshark", "-r", filepath, "-q", "-z", "http,tree"]
            result = await run_tshark_command(cmd, ignore_errors=True)
            if result.returncode == 0:
                analysis_results["http_stats"] = parse_http_stats(result.stdout)
                
        elif analysis_type == "security":
            # Security-focused analysis
            logger.info("Performing security analysis...")
            security_findings = await perform_security_analysis(filepath)
            analysis_results["security_analysis"] = security_findings
            
        elif analysis_type == "performance":
            # Performance analysis
            logger.info("Performing performance analysis...")
            performance_metrics = await perform_performance_analysis(filepath)
            analysis_results["performance_analysis"] = performance_metrics
            
        else:  # comprehensive
            # Run all analyses
            logger.info("Performing comprehensive analysis...")
            
            # Basic statistics
            cmd = ["tshark", "-r", filepath, "-q", "-z", "io,phs"]
            result = await run_tshark_command(cmd)
            analysis_results["protocol_hierarchy"] = parse_protocol_hierarchy(result.stdout)
            
            # Conversations
            conversations = {}
            for proto in ["tcp", "udp"]:
                cmd = ["tshark", "-r", filepath, "-q", "-z", f"conv,{proto}"]
                result = await run_tshark_command(cmd)
                conversations[proto] = parse_conversations(result.stdout)
            analysis_results["conversations"] = conversations
            
            # Expert info
            cmd = ["tshark", "-r", filepath, "-q", "-z", "expert"]
            result = await run_tshark_command(cmd)
            analysis_results["expert_info"] = parse_expert_info(result.stdout)
            
            # Security checks
            analysis_results["security_analysis"] = await perform_security_analysis(filepath)
            
            # Performance metrics
            analysis_results["performance_analysis"] = await perform_performance_analysis(filepath)
        
        # Format output
        if output_format == "json":
            payload = make_result("wireshark_analyze_pcap_enhanced", True, method="tshark", data=analysis_results)
            return [TextContent(type="text", text=json.dumps(payload, indent=2))]
        elif output_format == "summary":
            summary = generate_analysis_summary(analysis_results)
            payload = make_result("wireshark_analyze_pcap_enhanced", True, method="tshark", data={"summary": summary})
            return [TextContent(type="text", text=json.dumps(payload, indent=2))]
        else:  # text
            text_output = generate_text_report(analysis_results)
            payload = make_result("wireshark_analyze_pcap_enhanced", True, method="tshark", data={"text": text_output})
            return [TextContent(type="text", text=json.dumps(payload, indent=2))]
            
    except Exception as e:
        payload = make_result("wireshark_analyze_pcap_enhanced", False, diagnostics=[str(e)])
        return [TextContent(type="text", text=json.dumps(payload, indent=2))]

# Helper functions

async def run_tshark_command(cmd: List[str], timeout: int = 300, ignore_errors: bool = False) -> subprocess.CompletedProcess:
    """Run a TShark command with timeout and error handling."""
    try:
        result = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            ),
            timeout=timeout
        )
        
        stdout, stderr = await result.communicate()
        
        if result.returncode != 0 and not ignore_errors:
            raise RuntimeError(f"Command failed: {stderr.decode()}")
        
        return subprocess.CompletedProcess(
            cmd, result.returncode, stdout.decode(), stderr.decode()
        )
        
    except asyncio.TimeoutError:
        raise RuntimeError(f"Command timed out after {timeout} seconds")

def parse_protocol_hierarchy(output: str) -> Dict[str, Any]:
    """Parse TShark protocol hierarchy statistics output."""
    lines = output.strip().split('\n')
    stats = {
        "protocols": {},
        "total_packets": 0,
        "total_bytes": 0
    }
    
    for line in lines:
        if "frames:" in line and "bytes:" in line:
            # Parse protocol line
            match = re.search(r'(\S+)\s+frames:(\d+)\s+bytes:(\d+)', line)
            if match:
                protocol = match.group(1).strip()
                frames = int(match.group(2))
                bytes_count = int(match.group(3))
                
                stats["protocols"][protocol] = {
                    "packets": frames,
                    "bytes": bytes_count
                }
                
                # Update totals for top-level protocols
                if not line.startswith(' '):
                    stats["total_packets"] += frames
                    stats["total_bytes"] += bytes_count
    
    return stats

def parse_conversations(output: str) -> Dict[str, Any]:
    """Parse TShark conversation statistics output."""
    lines = output.strip().split('\n')
    conversations = []
    
    # Find the data section
    data_started = False
    for line in lines:
        if '<->' in line and not line.startswith('='):
            data_started = True
            # Parse conversation line
            parts = line.split()
            if len(parts) >= 10:
                conversations.append({
                    "address_a": parts[0],
                    "port_a": parts[1] if len(parts) > 1 else "N/A",
                    "address_b": parts[3],
                    "port_b": parts[4] if len(parts) > 4 else "N/A",
                    "packets_a_to_b": int(parts[5]) if parts[5].isdigit() else 0,
                    "bytes_a_to_b": int(parts[6]) if parts[6].isdigit() else 0,
                    "packets_b_to_a": int(parts[8]) if len(parts) > 8 and parts[8].isdigit() else 0,
                    "bytes_b_to_a": int(parts[9]) if len(parts) > 9 and parts[9].isdigit() else 0
                })
    
    return {
        "count": len(conversations),
        "conversations": conversations[:10],  # Top 10 conversations
        "total_listed": len(conversations)
    }

def parse_endpoints(output: str) -> Dict[str, Any]:
    """Parse TShark endpoint statistics output."""
    lines = output.strip().split('\n')
    endpoints = []
    
    for line in lines:
        if re.match(r'^\d+\.\d+\.\d+\.\d+', line) or re.match(r'^[0-9a-fA-F:]+', line):
            parts = line.split()
            if len(parts) >= 3:
                endpoints.append({
                    "address": parts[0],
                    "packets": int(parts[1]) if parts[1].isdigit() else 0,
                    "bytes": int(parts[2]) if parts[2].isdigit() else 0
                })
    
    # Sort by packets
    endpoints.sort(key=lambda x: x["packets"], reverse=True)
    
    return {
        "count": len(endpoints),
        "top_talkers": endpoints[:10],  # Top 10 endpoints
        "total_endpoints": len(endpoints)
    }

def parse_io_statistics(output: str) -> Dict[str, Any]:
    """Parse TShark I/O statistics output.
    Supports lines with or without a '|' separator.
    """
    lines = output.strip().split('\n')
    intervals = []

    for line in lines:
        if "-" in line:
            # Parse interval line like: "0.000-1.000      10" or "0.000-1.000 | 10"
            match = re.search(r'(\d+\.\d+)\s*-\s*(\d+\.\d+)\s*\|?\s*(\d+)', line)
            if match:
                intervals.append({
                    "start": float(match.group(1)),
                    "end": float(match.group(2)),
                    "packets": int(match.group(3))
                })

    return {
        "interval_count": len(intervals),
        "intervals": intervals
    }

def parse_capinfos_machine_output(output: str) -> Dict[str, Any]:
    """Parse capinfos machine-readable output."""
    info = {}
    for line in output.strip().split('\n'):
        if '\t' in line:
            key, value = line.split('\t', 1)
            info[key] = value
    return info

def parse_expert_info(output: str) -> Dict[str, Any]:
    """Parse TShark expert info output."""
    expert_info = {
        "errors": 0,
        "warnings": 0,
        "notes": 0,
        "chats": 0
    }
    
    for line in output.split('\n'):
        if "Errors" in line:
            match = re.search(r'Errors\s*\((\d+)\)', line)
            if match:
                expert_info["errors"] = int(match.group(1))
        elif "Warnings" in line:
            match = re.search(r'Warnings\s*\((\d+)\)', line)
            if match:
                expert_info["warnings"] = int(match.group(1))
        elif "Notes" in line:
            match = re.search(r'Notes\s*\((\d+)\)', line)
            if match:
                expert_info["notes"] = int(match.group(1))
        elif "Chats" in line:
            match = re.search(r'Chats\s*\((\d+)\)', line)
            if match:
                expert_info["chats"] = int(match.group(1))
    
    return expert_info

def parse_http_stats(output: str) -> Dict[str, Any]:
    """Parse HTTP statistics from TShark output."""
    http_stats = {
        "requests": 0,
        "responses": 0,
        "methods": {},
        "status_codes": {}
    }
    
    # Simple parsing - can be enhanced
    for line in output.split('\n'):
        if "GET" in line:
            http_stats["methods"]["GET"] = http_stats["methods"].get("GET", 0) + 1
        elif "POST" in line:
            http_stats["methods"]["POST"] = http_stats["methods"].get("POST", 0) + 1
        # Add more parsing as needed
    
    return http_stats

async def perform_security_analysis(filepath: str) -> Dict[str, Any]:
    """Perform security-focused analysis on PCAP file."""
    security_findings = {
        "suspicious_patterns": {},
        "threat_indicators": 0
    }
    
    # Security checks
    security_checks = [
        ("TCP SYN Flood", "tcp.flags.syn==1 and tcp.flags.ack==0"),
        ("Port Scan", "tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024"),
        ("DNS Tunneling", "dns and frame.len > 512"),
        ("Suspicious HTTP", "http.request.method == POST and frame.len > 8192"),
        ("Non-standard Ports", "tcp.port > 49151 or udp.port > 49151"),
        ("ICMP Tunneling", "icmp and data.len > 48"),
        ("ARP Spoofing", "arp.opcode == 2")
    ]
    
    for check_name, filter_expr in security_checks:
        try:
            cmd = ["tshark", "-r", filepath, "-Y", filter_expr, "-T", "fields", "-e", "frame.number"]
            result = await run_tshark_command(cmd, timeout=60)
            
            if result.stdout.strip():
                count = len(result.stdout.strip().split('\n'))
                security_findings["suspicious_patterns"][check_name] = count
                security_findings["threat_indicators"] += 1
        except Exception as e:
            logger.warning(f"Security check '{check_name}' failed: {e}")
    
    return security_findings

async def perform_performance_analysis(filepath: str) -> Dict[str, Any]:
    """Perform performance-focused analysis on PCAP file."""
    performance_metrics = {
        "tcp_issues": {},
        "overall_health": "Unknown"
    }
    
    # TCP performance checks
    tcp_checks = [
        ("Retransmissions", "tcp.analysis.retransmission"),
        ("Duplicate ACKs", "tcp.analysis.duplicate_ack"),
        ("Zero Window", "tcp.analysis.zero_window"),
        ("Window Full", "tcp.analysis.window_full"),
        ("Out of Order", "tcp.analysis.out_of_order"),
        ("Fast Retransmission", "tcp.analysis.fast_retransmission")
    ]
    
    total_issues = 0
    for check_name, filter_expr in tcp_checks:
        try:
            cmd = ["tshark", "-r", filepath, "-Y", filter_expr, "-T", "fields", "-e", "frame.number"]
            result = await run_tshark_command(cmd, timeout=60)
            
            if result.stdout.strip():
                count = len(result.stdout.strip().split('\n'))
                performance_metrics["tcp_issues"][check_name] = count
                total_issues += count
        except Exception as e:
            logger.warning(f"Performance check '{check_name}' failed: {e}")
    
    # Determine overall health
    if total_issues == 0:
        performance_metrics["overall_health"] = "Excellent"
    elif total_issues < 100:
        performance_metrics["overall_health"] = "Good"
    elif total_issues < 1000:
        performance_metrics["overall_health"] = "Fair"
    else:
        performance_metrics["overall_health"] = "Poor"
    
    performance_metrics["total_issues"] = total_issues
    
    return performance_metrics

def generate_analysis_summary(results: Dict[str, Any]) -> str:
    """Generate a human-readable summary of analysis results."""
    summary = "📊 **PCAP Analysis Summary**\n\n"
    
    # File info
    if "file_info" in results:
        summary += f"**File**: {results['file_info']['path']}\n"
        summary += f"**Size**: {results['file_info']['size_mb']}\n\n"
    
    # Metadata
    if "file_metadata" in results:
        meta = results["file_metadata"]
        if "Number of packets" in meta:
            summary += f"**Total Packets**: {meta['Number of packets']}\n"
        if "Capture duration" in meta:
            summary += f"**Duration**: {meta['Capture duration']}\n\n"
    
    # Protocol summary
    if "protocol_hierarchy" in results:
        ph = results["protocol_hierarchy"]
        summary += "**Top Protocols**:\n"
        sorted_protos = sorted(
            ph["protocols"].items(),
            key=lambda x: x[1]["packets"],
            reverse=True
        )[:5]
        for proto, stats in sorted_protos:
            summary += f"- {proto}: {stats['packets']:,} packets\n"
        summary += "\n"
    
    # Security findings
    if "security_analysis" in results:
        sec = results["security_analysis"]
        if sec["threat_indicators"] > 0:
            summary += f"⚠️ **Security Alerts**: {sec['threat_indicators']} suspicious patterns detected\n"
            for pattern, count in sec["suspicious_patterns"].items():
                summary += f"- {pattern}: {count} occurrences\n"
            summary += "\n"
    
    # Performance issues
    if "performance_analysis" in results:
        perf = results["performance_analysis"]
        summary += f"**Network Health**: {perf['overall_health']}\n"
        if perf["total_issues"] > 0:
            summary += f"**Performance Issues**: {perf['total_issues']} total\n"
            for issue, count in perf["tcp_issues"].items():
                if count > 0:
                    summary += f"- {issue}: {count}\n"
    
    return summary

def generate_text_report(results: Dict[str, Any]) -> str:
    """Generate a detailed text report of analysis results."""
    report = "=" * 60 + "\n"
    report += "ENHANCED PCAP ANALYSIS REPORT\n"
    report += "=" * 60 + "\n\n"
    
    # Recursively format the results
    def format_dict(d: Dict, indent: int = 0) -> str:
        output = ""
        prefix = "  " * indent
        for key, value in d.items():
            if isinstance(value, dict):
                output += f"{prefix}{key}:\n"
                output += format_dict(value, indent + 1)
            elif isinstance(value, list):
                output += f"{prefix}{key}: [{len(value)} items]\n"
                for i, item in enumerate(value[:3]):  # Show first 3 items
                    if isinstance(item, dict):
                        output += f"{prefix}  [{i}]:\n"
                        output += format_dict(item, indent + 2)
                    else:
                        output += f"{prefix}  - {item}\n"
                if len(value) > 3:
                    output += f"{prefix}  ... and {len(value) - 3} more\n"
            else:
                output += f"{prefix}{key}: {value}\n"
        return output
    
    report += format_dict(results)
    return report

# Original handler functions from server.py

async def handle_system_info(args: Dict[str, Any]) -> List[TextContent]:
    """Handle system information requests."""
    info_type = args.get("info_type", "all")
    
    result = {
        "server_version": os.sys.version.split()[0],
    }
    
    try:
        if info_type in ["interfaces", "all"]:
            # Get network interfaces using tshark -D for capture-capable list if available
            try:
                proc = await asyncio.create_subprocess_exec(
                    'tshark', '-D', stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate()
                if proc.returncode == 0 and stdout:
                    interfaces = []
                    for line in stdout.decode().splitlines():
                        # format: "1. eth0 ..."
                        parts = line.split(". ", 1)
                        if len(parts) == 2:
                            name = parts[1].split()[0]
                            interfaces.append(name)
                    result["capture_interfaces"] = interfaces
            except Exception:
                pass
    
        if info_type in ["system", "all"]:
            result["system"] = {
                "platform": os.uname().sysname if hasattr(os, 'uname') else "unknown",
            }
        
        payload = make_result("wireshark_system_info", True, method="introspect", data=result)
        return [TextContent(type="text", text=json.dumps(payload, indent=2))]
    except Exception as e:
        payload = make_result("wireshark_system_info", False, diagnostics=[str(e)])
        return [TextContent(type="text", text=json.dumps(payload, indent=2))]

async def handle_validate_setup(args: Dict[str, Any]) -> List[TextContent]:
    """Validate Wireshark installation and setup."""
    full_check = args.get("full_check", False)
    
    results: Dict[str, Any] = {"dependencies": {}, "network_access": "unknown"}
    try:
        for tool in ["tshark", "tcpdump", "dumpcap", "capinfos"]:
            path = shutil.which(tool) if 'shutil' in globals() else None
            if not path:
                import shutil as _sh
                path = _sh.which(tool)
            results["dependencies"][tool] = path or "not-found"
        try:
            proc = await asyncio.create_subprocess_exec('ip', 'link', 'show', stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await proc.communicate()
            results["network_access"] = "available" if proc.returncode == 0 else "limited"
        except Exception:
            results["network_access"] = "unknown"
        payload = make_result("wireshark_validate_setup", True, method="probe", data=results)
        return [TextContent(type="text", text=json.dumps(payload, indent=2))]
    except Exception as e:
        payload = make_result("wireshark_validate_setup", False, diagnostics=[str(e)])
        return [TextContent(type="text", text=json.dumps(payload, indent=2))]

async def handle_generate_filter(args: Dict[str, Any]) -> List[TextContent]:
    """Generate Wireshark filters from natural language with advanced parsing."""
    description = args.get("description", "")
    complexity = args.get("complexity", "intermediate")
    
    generated = await advanced_filter_generation(description, complexity)
    payload = make_result(
        "wireshark_generate_filter",
        True,
        method="local",
        data={
            "description": description,
            "filter": generated["filter"],
            "complexity": complexity,
            "suggestions": generated.get("suggestions", []),
            "matched_patterns": generated.get("matched_patterns", []),
            "notes": generated.get("notes", []),
        },
    )
    return [TextContent(type="text", text=json.dumps(payload, indent=2))]

async def get_capture_interfaces() -> List[str]:
    try:
        proc = await asyncio.create_subprocess_exec('tshark', '-D', stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, _ = await proc.communicate()
        names: List[str] = []
        if proc.returncode == 0 and stdout:
            for line in stdout.decode().splitlines():
                parts = line.split('. ', 1)
                if len(parts) == 2:
                    names.append(parts[1].split()[0])
        return names
    except Exception:
        return []

async def handle_live_capture(args: Dict[str, Any]) -> List[TextContent]:
    """Handle live packet capture with automatic permissions detection."""
    interface = args.get("interface", "any")
    duration = int(args.get("duration", 60))
    filter_expr = args.get("filter", "")
    max_packets = int(args.get("max_packets", 1000))
    ring_files = int(args.get("ring_files", os.getenv("WIRESHARK_RING_FILES", 5)))
    ring_mb = int(args.get("ring_megabytes", os.getenv("WIRESHARK_RING_MB", 10)))
    quick_triage = bool(args.get("quick_triage", False))
    
    diagnostics: List[str] = []
    if duration <= 0 or max_packets <= 0:
        payload = make_result("wireshark_live_capture", False, diagnostics=["duration and max_packets must be > 0"])
        return [TextContent(type="text", text=json.dumps(payload, indent=2))]
    
    # Validate interface if not "any"
    if interface != "any":
        known = await get_capture_interfaces()
        if known and interface not in known:
            payload = make_result("wireshark_live_capture", False, diagnostics=[f"Unknown interface: {interface}", f"Known: {', '.join(known)}"])
            return [TextContent(type="text", text=json.dumps(payload, indent=2))]
    
    # Apply env for ring buffer if provided by args
    os.environ["WIRESHARK_RING_FILES"] = str(ring_files)
    os.environ["WIRESHARK_RING_MB"] = str(ring_mb)
    
    try:
        # For quick triage, reduce max_packets and duration lightly
        if quick_triage:
            max_packets = min(max_packets, 200)
            duration = min(duration, 10)
        capture_result = await perform_live_capture_enhanced(interface, duration, filter_expr, max_packets)
        payload = make_result("wireshark_live_capture", capture_result.get("status", "").startswith("✅"), method=capture_result.get("method_used", ""), data=capture_result)
        return [TextContent(type="text", text=json.dumps(payload, indent=2))]
    except Exception as e:
        diagnostics.append(str(e))
        payload = make_result("wireshark_live_capture", False, diagnostics=diagnostics)
        return [TextContent(type="text", text=json.dumps(payload, indent=2))]

async def handle_analyze_pcap(args: Dict[str, Any]) -> List[TextContent]:
    """Handle PCAP file analysis with real packet inspection."""
    filepath = args.get("filepath", "")
    analysis_type = args.get("analysis_type", "comprehensive")
    
    if not filepath:
        payload = make_result("wireshark_analyze_pcap", False, diagnostics=["No filepath provided"]) 
        return [TextContent(type="text", text=json.dumps(payload, indent=2))]
    
    if not os.path.exists(filepath):
        payload = make_result("wireshark_analyze_pcap", False, diagnostics=[f"File not found: {filepath}"]) 
        return [TextContent(type="text", text=json.dumps(payload, indent=2))]
    
    if not os.access(filepath, os.R_OK):
        payload = make_result("wireshark_analyze_pcap", False, diagnostics=[f"Cannot read file: {filepath}"]) 
        return [TextContent(type="text", text=json.dumps(payload, indent=2))]
    
    try:
        # Quick hierarchy as baseline
        cmd = ['tshark', '-n', '-r', filepath, '-q', '-z', 'io,phs']
        result = await run_tshark_command(cmd)
        stats = parse_protocol_hierarchy(result.stdout)
        payload = make_result("wireshark_analyze_pcap", True, method="tshark", data={"protocol_hierarchy": stats})
        return [TextContent(type="text", text=json.dumps(payload, indent=2))]
    except Exception as e:
        payload = make_result("wireshark_analyze_pcap", False, diagnostics=[str(e)])
        return [TextContent(type="text", text=json.dumps(payload, indent=2))]

# Helper functions from original server.py

async def check_capture_permissions() -> bool:
    """Check if we have permissions to capture packets without sudo."""
    try:
        # Test dumpcap first (preferred method)
        result = subprocess.run(
            ["dumpcap", "-D"],  # List interfaces
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0 and "Capture interface" in result.stdout:
            return True
    except Exception:
        pass
    
    try:
        # Test tshark as fallback
        result = subprocess.run(
            ["tshark", "-D"],  # List interfaces  
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0 and len(result.stdout.strip()) > 0:
            return True
    except Exception:
        pass
    
    return False

async def perform_live_capture(interface: str, duration: int, filter_expr: str, max_packets: int) -> Dict[str, Any]:
    """Perform actual live packet capture using available tools."""
    
    # Create temporary file for capture
    temp_file = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
    temp_file.close()
    
    try:
        # Try dumpcap first (most secure)
        capture_cmd = [
            "dumpcap",
            "-i", interface,
            "-c", str(max_packets),
            "-a", f"duration:{duration}",
            "-w", temp_file.name
        ]
        
        if filter_expr:
            capture_cmd.extend(["-f", filter_expr])
        
        logger.info(f"Starting packet capture: {' '.join(capture_cmd)}")
        
        # Run capture with timeout
        result = subprocess.run(
            capture_cmd,
            capture_output=True,
            text=True,
            timeout=duration + 10  # Extra time for cleanup
        )
        
        if result.returncode != 0:
            # Try tshark as fallback
            capture_cmd = [
                "tshark",
                "-i", interface,
                "-c", str(max_packets),
                "-a", f"duration:{duration}",
                "-w", temp_file.name
            ]
            
            if filter_expr:
                capture_cmd.extend(["-f", filter_expr])
            
            result = subprocess.run(
                capture_cmd,
                capture_output=True,
                text=True,
                timeout=duration + 10
            )
        
        # Analyze the captured file
        file_size = os.path.getsize(temp_file.name) if os.path.exists(temp_file.name) else 0
        
        if file_size > 0:
            # Get packet count using tshark
            try:
                count_result = subprocess.run(
                    ["tshark", "-r", temp_file.name, "-T", "fields", "-e", "frame.number"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                packet_count = len(count_result.stdout.strip().split('\n')) if count_result.stdout.strip() else 0
            except Exception:
                packet_count = "unknown"
            
            capture_result = {
                "status": "✅ Capture Successful",
                "interface": interface,
                "duration": f"{duration} seconds",
                "filter": filter_expr or "none",
                "packets_captured": packet_count,
                "file_size": f"{file_size} bytes",
                "capture_file": temp_file.name,
                "note": "Capture file saved temporarily - analyze quickly before cleanup"
            }
        else:
            capture_result = {
                "status": "⚠️ No Packets Captured",
                "interface": interface,
                "duration": f"{duration} seconds", 
                "filter": filter_expr or "none",
                "possible_reasons": [
                    "Interface has no traffic",
                    "Filter too restrictive",
                    "Interface not active",
                    "Permission issues"
                ]
            }
        
        return capture_result
        
    except subprocess.TimeoutExpired:
        return {
            "status": "⚠️ Capture Timeout",
            "interface": interface,
            "note": "Capture took longer than expected - may have succeeded partially"
        }
    except Exception as e:
        return {
            "status": "❌ Capture Error",
            "interface": interface,
            "error": str(e)
        }
    finally:
        # Clean up temp file after a delay (allow time for analysis)
        try:
            if os.path.exists(temp_file.name):
                # Schedule cleanup after 5 minutes
                asyncio.create_task(delayed_cleanup(temp_file.name, 300))
        except Exception:
            pass

async def perform_live_capture_enhanced(interface: str, duration: int, filter_expr: str, max_packets: int) -> Dict[str, Any]:
    """Enhanced live capture with multiple fallback methods for extended duration support."""
    
    capture_start_time = asyncio.get_event_loop().time()
    ring_files = int(os.getenv("WIRESHARK_RING_FILES", "5"))
    ring_megabytes = int(os.getenv("WIRESHARK_RING_MB", "10"))
    
    # Method 1: Try traditional tshark first
    try:
        cmd = [
            'tshark',
            '-n',  # no name resolution
            '-i', interface,
            '-c', str(max_packets),
            '-a', f'duration:{duration}',
            '-T', 'json'
        ]
        
        if filter_expr:
            cmd.extend(['-f', filter_expr])
        
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=duration + 30)
        
        if proc.returncode == 0:
            try:
                packets = json.loads(stdout.decode()) if stdout.decode().strip() else []
                capture_time = asyncio.get_event_loop().time() - capture_start_time
                return {
                    "status": "✅ Success",
                    "method_used": "tshark_direct",
                    "interface": interface,
                    "duration": duration,
                    "filter": filter_expr,
                    "packets_captured": len(packets),
                    "max_packets": max_packets,
                    "packets": packets[:10],  # Return first 10 for display
                    "capture_time_seconds": round(capture_time, 2),
                    "note": "Direct tshark capture successful"
                }
            except json.JSONDecodeError:
                return {
                    "status": "⚠️ Partial Success",
                    "method_used": "tshark_direct", 
                    "interface": interface,
                    "raw_output": stdout.decode()[:1000],
                    "error": "Could not parse JSON output"
                }
        else:
            # Try fallback methods
            logger.info(f"tshark direct failed ({stderr.decode()[:100]}...), trying fallback methods")
            return await _enhanced_capture_fallback(interface, duration, filter_expr, max_packets, capture_start_time)
            
    except asyncio.TimeoutError:
        # Try fallback methods even on timeout
        logger.info(f"tshark timed out after {duration}s, trying fallback methods")
        return await _enhanced_capture_fallback(interface, duration, filter_expr, max_packets, capture_start_time)
    except Exception as e:
        # Try fallback methods on any exception
        logger.info(f"tshark failed with exception ({str(e)}), trying fallback methods")
        return await _enhanced_capture_fallback(interface, duration, filter_expr, max_packets, capture_start_time)

async def _enhanced_capture_fallback(
    interface: str, 
    duration: int, 
    filter_expr: str, 
    max_packets: int,
    start_time: float
) -> Dict[str, Any]:
    """Enhanced fallback capture methods for when tshark fails due to permissions."""
    import tempfile
    
    ring_files = int(os.getenv("WIRESHARK_RING_FILES", "5"))
    ring_megabytes = int(os.getenv("WIRESHARK_RING_MB", "10"))
    
    # Method 2: Try tcpdump + tshark analysis (most reliable fallback)
    try:
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            pcap_file = tmp.name
        
        # Build tcpdump command
        cmd = [
            'timeout', str(duration + 10),  # Add buffer time
            'tcpdump', '-n', '-i', interface,
            '-w', pcap_file,
            '-c', str(max_packets),
            '-C', str(ring_megabytes),
            '-W', str(ring_files),
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
        
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=duration + 15)
        
        if proc.returncode in [0, 124]:  # Success or timeout (expected)
            # Parse with tshark
            parse_cmd = ['tshark', '-n', '-r', pcap_file, '-T', 'json', '-c', str(min(10, max_packets))]
            parse_proc = await asyncio.create_subprocess_exec(
                *parse_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            parse_stdout, parse_stderr = await parse_proc.communicate()
            
            if parse_proc.returncode == 0:
                try:
                    packets = json.loads(parse_stdout.decode()) if parse_stdout.decode().strip() else []
                    capture_time = asyncio.get_event_loop().time() - start_time
                    
                    # Clean up temp file
                    os.unlink(pcap_file)
                    
                    return {
                        "status": "✅ Success", 
                        "method_used": "tcpdump + tshark analysis",
                        "interface": interface,
                        "duration": duration,
                        "filter": filter_expr,
                        "packets_captured": len(packets),
                        "max_packets": max_packets,
                        "packets": packets,
                        "capture_time_seconds": round(capture_time, 2),
                        "note": "Enhanced capture with permission workaround - supports extended duration (5+ minutes)",
                        "recommendation": "Original tshark failed, used tcpdump fallback successfully"
                    }
                except json.JSONDecodeError:
                    os.unlink(pcap_file) if os.path.exists(pcap_file) else None
                    # Continue to next method
                    pass
            else:
                os.unlink(pcap_file) if os.path.exists(pcap_file) else None
                logger.info(f"tshark parse failed: {parse_stderr.decode()[:100]}")
        else:
            os.unlink(pcap_file) if os.path.exists(pcap_file) else None
            logger.info(f"tcpdump failed: {stderr.decode()[:100]}")
    except Exception as e:
        logger.info(f"tcpdump fallback failed: {str(e)}")
        if 'pcap_file' in locals() and os.path.exists(pcap_file):
            os.unlink(pcap_file)
    
    # Method 3 (optional): Try sg wireshark (group switching)
    if os.getenv("WIRESHARK_ENABLE_SG") == "1":
        try:
            cmd = [
                'sg', 'wireshark', '-c',
                f'timeout {duration + 5} tshark -i {interface} -c {max_packets} -T json'
            ]
            # Note: do NOT interpolate filter_expr into shell string to avoid injection risks
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=duration + 10)
            if proc.returncode in [0, 124]:
                try:
                    packets = json.loads(stdout.decode()) if stdout.decode().strip() else []
                    capture_time = asyncio.get_event_loop().time() - start_time
                    return {
                        "status": "✅ Success",
                        "method_used": "sg wireshark + tshark", 
                        "interface": interface,
                        "duration": duration,
                        "filter": filter_expr,
                        "packets_captured": len(packets),
                        "max_packets": max_packets,
                        "packets": packets[:10],
                        "capture_time_seconds": round(capture_time, 2),
                        "note": "Used group switching to access wireshark group",
                        "recommendation": "Consider restarting Claude Desktop to activate wireshark group permanently"
                    }
                except json.JSONDecodeError:
                    logger.info("sg wireshark: JSON decode failed")
            else:
                logger.info(f"sg wireshark failed: {stderr.decode()[:100]}")
        except Exception as e:
            logger.info(f"sg wireshark fallback failed: {str(e)}")
    
    # All methods failed
    capture_time = asyncio.get_event_loop().time() - start_time
    return {
        "status": "❌ All capture methods failed",
        "method_used": "none - all fallbacks exhausted",
        "interface": interface,
        "duration": duration,
        "filter": filter_expr,
        "max_packets": max_packets,
        "capture_time_seconds": round(capture_time, 2),
        "error": "Permission denied - tshark, tcpdump, and sg wireshark all failed",
        "recommendations": [
            "1. Run: sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump",
            "2. Run: sudo usermod -a -G wireshark $USER",
            "3. Restart Claude Desktop to activate wireshark group",
            "4. Or use async background capture with: async_long_capture.py"
        ]
    }

async def delayed_cleanup(filepath: str, delay_seconds: int):
    """Clean up temporary files after a delay."""
    try:
        await asyncio.sleep(delay_seconds)
        if os.path.exists(filepath):
            os.unlink(filepath)
            logger.info(f"Cleaned up temporary file: {filepath}")
    except Exception as e:
        logger.warning(f"Failed to clean up {filepath}: {e}")

async def analyze_pcap_file(filepath: str, analysis_type: str) -> Dict[str, Any]:
    """Analyze PCAP file using tshark for comprehensive packet inspection."""
    
    file_info = {
        "file": filepath,
        "file_size": f"{os.path.getsize(filepath)} bytes",
        "analysis_type": analysis_type
    }
    
    try:
        # Basic file info using capinfos
        try:
            capinfos_result = subprocess.run(
                ["capinfos", filepath],
                capture_output=True,
                text=True,
                timeout=30
            )
            if capinfos_result.returncode == 0:
                file_info["file_details"] = parse_capinfos_output(capinfos_result.stdout)
        except Exception:
            # Fallback to tshark for basic info
            pass
        
        # Packet analysis based on type
        if analysis_type == "quick":
            analysis_result = await quick_pcap_analysis(filepath)
        elif analysis_type == "security":
            analysis_result = await security_pcap_analysis(filepath)
        elif analysis_type == "performance":
            analysis_result = await performance_pcap_analysis(filepath)
        else:  # comprehensive
            analysis_result = await comprehensive_pcap_analysis(filepath)
        
        return {
            "status": "✅ Analysis Complete",
            "file_info": file_info,
            **analysis_result
        }
        
    except Exception as e:
        return {
            "status": "❌ Analysis Error",
            "file_info": file_info,
            "error": str(e)
        }

def parse_capinfos_output(output: str) -> Dict[str, str]:
    """Parse capinfos output into structured data."""
    info = {}
    for line in output.split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            info[key.strip()] = value.strip()
    return info

async def quick_pcap_analysis(filepath: str) -> Dict[str, Any]:
    """Quick analysis - basic packet counts and protocols."""
    try:
        # Get total packet count
        count_result = subprocess.run(
            ["tshark", "-r", filepath, "-T", "fields", "-e", "frame.number"],
            capture_output=True,
            text=True,
            timeout=30
        )
        total_packets = len(count_result.stdout.strip().split('\n')) if count_result.stdout.strip() else 0
        
        # Get protocol statistics
        proto_result = subprocess.run(
            ["tshark", "-r", filepath, "-q", "-z", "ptype,tree"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        protocols = {}
        if proto_result.returncode == 0:
            for line in proto_result.stdout.split('\n'):
                if 'frames:' in line and '%' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        protocol = parts[-1]
                        count = parts[0]
                        protocols[protocol] = count
        
        return {
            "analysis_summary": {
                "total_packets": total_packets,
                "protocols": protocols,
                "analysis_duration": "< 30 seconds"
            }
        }
        
    except Exception as e:
        return {"quick_analysis_error": str(e)}

async def security_pcap_analysis(filepath: str) -> Dict[str, Any]:
    """Security-focused analysis - suspicious patterns and threats."""
    try:
        security_findings = {}
        
        # Check for suspicious traffic patterns
        suspicious_patterns = [
            ("TCP SYN flood", "tcp.flags.syn==1 and tcp.flags.ack==0"),
            ("Port scan indicators", "tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024"),
            ("DNS tunneling", "dns.qry.name contains \".\" and frame.len > 512"),
            ("Large HTTP requests", "http.request and frame.len > 8192"),
            ("Non-standard ports", "tcp.port > 49151 or udp.port > 49151")
        ]
        
        for pattern_name, filter_expr in suspicious_patterns:
            try:
                result = subprocess.run(
                    ["tshark", "-r", filepath, "-Y", filter_expr, "-T", "fields", "-e", "frame.number"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    matches = len(result.stdout.strip().split('\n'))
                    security_findings[pattern_name] = f"{matches} occurrences"
            except Exception:
                security_findings[pattern_name] = "Analysis failed"
        
        return {
            "security_analysis": security_findings,
            "threat_indicators": len([v for v in security_findings.values() if "occurrences" in v])
        }
        
    except Exception as e:
        return {"security_analysis_error": str(e)}

async def performance_pcap_analysis(filepath: str) -> Dict[str, Any]:
    """Performance analysis - latency, throughput, errors."""
    try:
        performance_metrics = {}
        
        # Analyze TCP performance issues
        tcp_issues = [
            ("Retransmissions", "tcp.analysis.retransmission"),
            ("Duplicate ACKs", "tcp.analysis.duplicate_ack"),
            ("Zero Window", "tcp.analysis.zero_window"),
            ("Keep Alive", "tcp.analysis.keep_alive")
        ]
        
        for issue_name, filter_expr in tcp_issues:
            try:
                result = subprocess.run(
                    ["tshark", "-r", filepath, "-Y", filter_expr, "-T", "fields", "-e", "frame.number"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    count = len(result.stdout.strip().split('\n'))
                    performance_metrics[issue_name] = count
                else:
                    performance_metrics[issue_name] = 0
            except Exception:
                performance_metrics[issue_name] = "Analysis failed"
        
        return {
            "performance_analysis": performance_metrics,
            "network_health": "Good" if sum(v for v in performance_metrics.values() if isinstance(v, int)) == 0 else "Issues detected"
        }
        
    except Exception as e:
        return {"performance_analysis_error": str(e)}

async def comprehensive_pcap_analysis(filepath: str) -> Dict[str, Any]:
    """Comprehensive analysis combining all analysis types."""
    try:
        # Run all analysis types
        quick_results = await quick_pcap_analysis(filepath)
        security_results = await security_pcap_analysis(filepath)
        performance_results = await performance_pcap_analysis(filepath)
        
        # Additional comprehensive statistics
        comprehensive_stats = {}
        
        # Get conversation statistics
        try:
            conv_result = subprocess.run(
                ["tshark", "-r", filepath, "-q", "-z", "conv,tcp"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if conv_result.returncode == 0:
                lines = conv_result.stdout.split('\n')
                tcp_conversations = len([l for l in lines if '<->' in l])
                comprehensive_stats["tcp_conversations"] = tcp_conversations
        except Exception:
            comprehensive_stats["tcp_conversations"] = "Analysis failed"
        
        return {
            "comprehensive_analysis": {
                **quick_results,
                **security_results, 
                **performance_results,
                "additional_stats": comprehensive_stats
            }
        }
        
    except Exception as e:
        return {"comprehensive_analysis_error": str(e)}

async def advanced_filter_generation(description: str, complexity: str) -> Dict[str, Any]:
    """Advanced filter generation with regex patterns, subnet support, and smart parsing."""
    
    description_lower = description.lower()
    matched_patterns = []
    filter_parts = []
    notes = []
    
    # Enhanced pattern matching with regex
    patterns = {
        # Network patterns with subnet support
        "ip_address": (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', lambda m: f'ip.addr == {m.group()}'),
        "subnet_cidr": (r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b', lambda m: f'ip.addr == {m.group()}'),
        "ip_range": (r'\b(?:\d{1,3}\.){3}\d{1,3}\s*-\s*(?:\d{1,3}\.){3}\d{1,3}\b', 
                    lambda m: parse_ip_range(m.group())),
        
        # Port patterns
        "port_number": (r'\bport\s+(\d+)\b', lambda m: f'tcp.port == {m.group(1)} or udp.port == {m.group(1)}'),
        "port_range": (r'\bports?\s+(\d+)\s*-\s*(\d+)\b', 
                      lambda m: f'(tcp.port >= {m.group(1)} and tcp.port <= {m.group(2)}) or (udp.port >= {m.group(1)} and udp.port <= {m.group(2)})'),
        
        # Protocol patterns
        "http_traffic": (r'\bhttp\b(?!\w)', lambda m: 'http'),
        "https_traffic": (r'\bhttps?\s+secure|ssl|tls\b', lambda m: 'tls'),
        "dns_queries": (r'\bdns\b(?!\w)', lambda m: 'dns'),
        "email_traffic": (r'\bemail|smtp|pop|imap\b', lambda m: 'smtp or pop or imap'),
        "ssh_traffic": (r'\bssh\b(?!\w)', lambda m: 'ssh'),
        "ftp_traffic": (r'\bftp\b(?!\w)', lambda m: 'ftp'),
        
        # Advanced patterns
        "slow_connections": (r'\bslow|high\s+latency|delayed?\b', lambda m: 'tcp.analysis.ack_rtt > 0.1'),
        "error_traffic": (r'\berrors?|retransmission|failed?\b', 
                         lambda m: 'tcp.analysis.retransmission or tcp.analysis.duplicate_ack'),
        "large_packets": (r'\blarge\s+packets?|big\s+frames?\b', lambda m: 'frame.len > 1500'),
        
        # Host patterns
        "hostname": (r'\b(?:host|server|domain)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b', 
                    lambda m: f'ip.host == "{m.group(1)}"'),
        "contains_domain": (r'\b(?:contains?|includes?)\s+([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b',
                           lambda m: f'http.host contains "{m.group(1)}"'),
    }
    
    # Protocol keyword mapping (fallback)
    protocol_keywords = {
        "web": "http or tls",
        "tcp": "tcp",
        "udp": "udp", 
        "icmp": "icmp",
        "ping": "icmp",
        "arp": "arp",
        "broadcast": "eth.dst == ff:ff:ff:ff:ff:ff",
        "multicast": "ip.dst[0:4] == 0x0e"
    }
    
    # Apply regex patterns
    for pattern_name, (regex, formatter) in patterns.items():
        matches = re.finditer(regex, description_lower)
        for match in matches:
            try:
                filter_expr = formatter(match)
                filter_parts.append(filter_expr)
                matched_patterns.append(pattern_name)
                notes.append(f"Detected {pattern_name}: {match.group()}")
            except Exception as e:
                notes.append(f"Error parsing {pattern_name}: {str(e)}")
    
    # Apply keyword matching if no regex matches
    if not filter_parts:
        for keyword, filter_expr in protocol_keywords.items():
            if keyword in description_lower:
                filter_parts.append(filter_expr)
                matched_patterns.append(f"keyword_{keyword}")
    
    # Generate final filter
    if filter_parts:
        if len(filter_parts) == 1:
            final_filter = filter_parts[0]
        else:
            # Intelligently combine filters
            final_filter = combine_filters_intelligently(filter_parts, description_lower)
    else:
        # Ultimate fallback
        if any(word in description_lower for word in ["traffic", "packets", "network"]):
            final_filter = "tcp or udp"
        else:
            final_filter = "tcp"
        notes.append("Used fallback filter - consider more specific description")
    
    # Generate contextual suggestions
    suggestions = generate_contextual_suggestions(description_lower, matched_patterns)
    
    return {
        "filter": final_filter,
        "matched_patterns": matched_patterns,
        "suggestions": suggestions,
        "notes": notes
    }

def parse_ip_range(range_str: str) -> str:
    """Parse IP range like '192.168.1.1 - 192.168.1.100' into Wireshark filter."""
    try:
        start_ip, end_ip = [ip.strip() for ip in range_str.split('-')]
        return f'ip.addr >= {start_ip} and ip.addr <= {end_ip}'
    except Exception:
        return f'ip.addr == {range_str}'  # Fallback

def combine_filters_intelligently(filter_parts: List[str], description: str) -> str:
    """Intelligently combine multiple filter parts based on context."""
    
    # Check for exclusion words
    if any(word in description for word in ["not", "except", "exclude", "without"]):
        # Use NOT logic for exclusions
        if len(filter_parts) >= 2:
            return f"({filter_parts[0]}) and not ({filter_parts[1]})"
    
    # Check for OR logic indicators
    if any(word in description for word in ["or", "either", "any"]):
        return " or ".join(f"({part})" for part in filter_parts)
    
    # Default to AND logic
    return " and ".join(f"({part})" for part in filter_parts)

def generate_contextual_suggestions(description: str, matched_patterns: List[str]) -> List[str]:
    """Generate contextual suggestions based on what was detected."""
    
    suggestions = []
    
    # Basic suggestions
    suggestions.extend([
        "Use specific IP addresses: ip.addr == 192.168.1.1",
        "Filter by port: tcp.port == 80 or udp.port == 53",
        "Combine with operators: (http) and (ip.addr == 192.168.1.0/24)"
    ])
    
    # Context-specific suggestions
    if any("ip" in pattern for pattern in matched_patterns):
        suggestions.append("Try subnet notation: ip.addr == 192.168.1.0/24")
        suggestions.append("Use IP ranges: ip.addr >= 10.0.0.1 and ip.addr <= 10.0.0.100")
    
    if any("port" in pattern for pattern in matched_patterns):
        suggestions.append("Specific protocols: tcp.port == 443 (HTTPS) or udp.port == 53 (DNS)")
    
    if any("http" in pattern for pattern in matched_patterns):
        suggestions.append("HTTP methods: http.request.method == GET")
        suggestions.append("HTTP hosts: http.host == \"example.com\"")
    
    if "slow" in description or "latency" in description:
        suggestions.append("RTT analysis: tcp.analysis.ack_rtt > 0.05")
        suggestions.append("Window scaling: tcp.window_size_scalefactor > 1")
    
    return suggestions[:6]  # Limit to 6 suggestions

async def main():
    """Main server entry point."""
    logger.info("🦈 Starting Wireshark MCP Server")
    logger.info("✨ Features: JSON Capture, Protocol Statistics, Advanced Analysis")
    logger.info("📊 Total Tools Available: 8")
    
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())