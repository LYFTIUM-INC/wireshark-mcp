#!/usr/bin/env python3
"""
Enhanced Wireshark MCP Server with eBPF/XDP Integration
=======================================================

A comprehensive MCP server implementation that integrates:
- Traditional Wireshark analysis capabilities
- Ultra-high-performance eBPF/XDP packet processing (10M+ pps)
- Enterprise compliance engines (SOC2, GDPR, NIST)
- Real-time threat intelligence correlation
- Multi-core performance optimization
"""

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add src directory to path for imports
sys.path.append(str(Path(__file__).parent))

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    Resource,
    Tool,
    TextContent,
)

# Import eBPF/XDP high-performance tools
from ebpf_mcp_tools import (
    ebpf_initialize_interface,
    ebpf_start_high_speed_capture,
    ebpf_get_performance_stats,
    ebpf_update_runtime_filters,
    ebpf_validate_10m_performance,
    ebpf_stop_capture,
    ebpf_list_interfaces,
    EBPF_TOOLS,
    BCC_AVAILABLE
)

# Import compliance engines
from mcp_compliance_integration import (
    unified_compliance_assessment,
    compliance_continuous_monitoring,
    compliance_audit_reporter,
    compliance_risk_assessor
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize the enhanced MCP server
server = Server("enhanced-wireshark-mcp")

# Traditional Wireshark tools
WIRESHARK_TOOLS = [
    Tool(
        name="wireshark_system_info",
        description="Get system information and network interfaces with eBPF/XDP capabilities",
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
        description="Validate Wireshark and eBPF/XDP installation and dependencies",
        inputSchema={
            "type": "object",
            "properties": {
                "full_check": {
                    "type": "boolean",
                    "description": "Perform comprehensive validation including eBPF",
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
        description="Enhanced live network capture with extended duration support (5+ minutes) and permission fallbacks",
        inputSchema={
            "type": "object",
            "properties": {
                "interface": {
                    "type": "string",
                    "description": "Network interface to capture from (e.g., 'eth0', 'any')"
                },
                "duration": {
                    "type": "integer", 
                    "description": "Capture duration in seconds (supports up to 5+ minutes with fallback methods)",
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
    )
]

# eBPF/XDP high-performance tools
EBPF_MCP_TOOLS = [
    Tool(
        name="ebpf_initialize_interface",
        description="Initialize eBPF/XDP program on network interface for 10M+ pps processing",
        inputSchema={
            "type": "object",
            "properties": {
                "interface": {
                    "type": "string",
                    "description": "Network interface name (e.g., 'eth0', 'enp0s3')"
                },
                "program_type": {
                    "type": "string",
                    "enum": ["high_throughput", "monitoring", "filtering"],
                    "description": "eBPF program type",
                    "default": "high_throughput"
                }
            },
            "required": ["interface"]
        }
    ),
    Tool(
        name="ebpf_start_high_speed_capture",
        description="Start ultra-high-speed packet capture with eBPF/XDP (10M+ pps)",
        inputSchema={
            "type": "object",
            "properties": {
                "filters": {
                    "type": "object",
                    "description": "Optional filtering configuration",
                    "properties": {
                        "sampling_rate": {"type": "integer", "description": "Sample 1 in N packets"},
                        "rate_limit_pps": {"type": "integer", "description": "Rate limit in packets/second"},
                        "protocols_enabled": {"type": "array", "description": "Enabled protocol numbers"}
                    }
                }
            }
        }
    ),
    Tool(
        name="ebpf_get_performance_stats",
        description="Get real-time eBPF performance statistics and validate 10M+ pps target",
        inputSchema={"type": "object", "properties": {}}
    ),
    Tool(
        name="ebpf_update_runtime_filters",
        description="Update eBPF filters at runtime without restarting capture",
        inputSchema={
            "type": "object",
            "properties": {
                "config": {
                    "type": "object",
                    "description": "Filter configuration",
                    "properties": {
                        "sampling_rate": {"type": "integer"},
                        "threat_threshold": {"type": "integer"},
                        "rate_limit_pps": {"type": "integer"}
                    }
                }
            },
            "required": ["config"]
        }
    ),
    Tool(
        name="ebpf_validate_10m_performance",
        description="Comprehensive validation of 10M+ packets/second performance target",
        inputSchema={"type": "object", "properties": {}}
    ),
    Tool(
        name="ebpf_stop_capture",
        description="Stop eBPF capture and get final performance report",
        inputSchema={"type": "object", "properties": {}}
    ),
    Tool(
        name="ebpf_list_interfaces",
        description="List network interfaces with eBPF/XDP capability information",
        inputSchema={"type": "object", "properties": {}}
    )
]

# Compliance tools
COMPLIANCE_TOOLS = [
    Tool(
        name="compliance_framework_assessment",
        description="Multi-framework compliance assessment (SOC2, GDPR, NIST)",
        inputSchema={
            "type": "object",
            "properties": {
                "frameworks": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["soc2", "gdpr", "nist"]},
                    "description": "Compliance frameworks to assess",
                    "default": ["soc2", "gdpr", "nist"]
                }
            }
        }
    ),
    Tool(
        name="compliance_continuous_monitoring",
        description="Start real-time compliance monitoring with alerting",
        inputSchema={
            "type": "object",
            "properties": {
                "enable_alerts": {
                    "type": "boolean",
                    "description": "Enable real-time alerting",
                    "default": True
                },
                "monitoring_interval": {
                    "type": "integer",
                    "description": "Monitoring interval in seconds",
                    "default": 300
                }
            }
        }
    ),
    Tool(
        name="compliance_audit_reporter",
        description="Generate comprehensive compliance audit reports",
        inputSchema={
            "type": "object",
            "properties": {
                "report_type": {
                    "type": "string",
                    "enum": ["executive", "technical", "audit"],
                    "description": "Type of report to generate",
                    "default": "comprehensive"
                },
                "frameworks": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["soc2", "gdpr", "nist"]},
                    "description": "Frameworks to include",
                    "default": ["soc2", "gdpr", "nist"]
                }
            }
        }
    ),
    Tool(
        name="compliance_risk_assessor",
        description="Multi-framework risk assessment and scoring",
        inputSchema={
            "type": "object",
            "properties": {
                "scope": {
                    "type": "string",
                    "enum": ["all", "security", "privacy", "operational"],
                    "description": "Risk assessment scope",
                    "default": "all"
                }
            }
        }
    )
]

@server.list_tools()
async def list_tools() -> List[Tool]:
    """List all available tools including eBPF/XDP and compliance capabilities."""
    logger.info("📋 Listing Enhanced Wireshark MCP tools with eBPF/XDP integration")
    
    all_tools = WIRESHARK_TOOLS.copy()
    
    # Add eBPF tools if BCC is available
    if BCC_AVAILABLE:
        all_tools.extend(EBPF_MCP_TOOLS)
        logger.info("✅ eBPF/XDP tools available")
    else:
        logger.warning("⚠️ eBPF/XDP tools disabled - BCC not available")
    
    # Add compliance tools
    all_tools.extend(COMPLIANCE_TOOLS)
    logger.info("✅ Enterprise compliance tools available")
    
    return all_tools

@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Handle tool calls for all integrated functionalities."""
    logger.info(f"🔧 Calling tool: {name} with args: {arguments}")
    
    try:
        # eBPF/XDP tool calls
        if name == "ebpf_initialize_interface":
            result = await ebpf_initialize_interface(
                interface=arguments["interface"],
                program_type=arguments.get("program_type", "high_throughput")
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        
        elif name == "ebpf_start_high_speed_capture":
            result = await ebpf_start_high_speed_capture(
                filters=arguments.get("filters")
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        
        elif name == "ebpf_get_performance_stats":
            result = await ebpf_get_performance_stats()
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        
        elif name == "ebpf_update_runtime_filters":
            result = await ebpf_update_runtime_filters(
                config=arguments["config"]
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        
        elif name == "ebpf_validate_10m_performance":
            result = await ebpf_validate_10m_performance()
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        
        elif name == "ebpf_stop_capture":
            result = await ebpf_stop_capture()
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        
        elif name == "ebpf_list_interfaces":
            result = await ebpf_list_interfaces()
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        
        # Compliance tool calls
        elif name == "compliance_framework_assessment":
            result = await unified_compliance_assessment(
                frameworks=arguments.get("frameworks", ["soc2", "gdpr", "nist"])
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        
        elif name == "compliance_continuous_monitoring":
            result = await compliance_continuous_monitoring(
                enable_alerts=arguments.get("enable_alerts", True)
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        
        elif name == "compliance_audit_reporter":
            result = await compliance_audit_reporter(
                report_type=arguments.get("report_type", "comprehensive"),
                frameworks=arguments.get("frameworks", ["soc2", "gdpr", "nist"])
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        
        elif name == "compliance_risk_assessor":
            result = await compliance_risk_assessor(
                scope=arguments.get("scope", "all")
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        
        # Traditional Wireshark tool calls
        elif name == "wireshark_system_info":
            result = await _wireshark_system_info(arguments.get("info_type", "all"))
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        
        elif name == "wireshark_validate_setup":
            result = await _wireshark_validate_setup(arguments.get("full_check", False))
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        
        elif name == "wireshark_generate_filter":
            result = await _wireshark_generate_filter(
                description=arguments["description"],
                complexity=arguments.get("complexity", "intermediate")
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        
        elif name == "wireshark_live_capture":
            result = await _wireshark_live_capture(
                interface=arguments["interface"],
                duration=arguments.get("duration", 60),
                filter_expr=arguments.get("filter", ""),
                max_packets=arguments.get("max_packets", 1000)
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        
        elif name == "wireshark_analyze_pcap":
            result = await _wireshark_analyze_pcap(
                filepath=arguments["filepath"],
                analysis_type=arguments.get("analysis_type", "comprehensive")
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
        
        else:
            error_msg = f"Unknown tool: {name}"
            logger.error(error_msg)
            return [TextContent(type="text", text=json.dumps({"error": error_msg}))]
            
    except Exception as e:
        error_msg = f"Error executing {name}: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [TextContent(type="text", text=json.dumps({"error": error_msg}))]

# Traditional Wireshark tool implementations (simplified for integration)
async def _wireshark_system_info(info_type: str) -> Dict[str, Any]:
    """Get system information including eBPF capabilities."""
    import psutil
    import platform
    
    result = {
        "timestamp": str(asyncio.get_event_loop().time()),
        "info_type": info_type,
        "ebpf_available": BCC_AVAILABLE
    }
    
    if info_type in ["system", "all"]:
        result["system"] = {
            "platform": platform.system(),
            "release": platform.release(),
            "architecture": platform.machine(),
            "cpu_count": psutil.cpu_count(),
            "memory_gb": round(psutil.virtual_memory().total / (1024**3), 2)
        }
    
    if info_type in ["interfaces", "all"]:
        result["interfaces"] = []
        for interface_name, interface_info in psutil.net_if_addrs().items():
            if interface_name != 'lo':  # Skip loopback
                result["interfaces"].append({
                    "name": interface_name,
                    "addresses": [addr.address for addr in interface_info],
                    "is_up": psutil.net_if_stats().get(interface_name, {}).get('isup', False)
                })
    
    if info_type in ["capabilities", "all"]:
        result["capabilities"] = {
            "ebpf_support": BCC_AVAILABLE,
            "xdp_support": BCC_AVAILABLE,
            "high_performance_mode": BCC_AVAILABLE,
            "compliance_engines": True,
            "target_performance": "10M+ packets/second" if BCC_AVAILABLE else "Traditional mode"
        }
    
    return result

async def _wireshark_validate_setup(full_check: bool) -> Dict[str, Any]:
    """Validate Wireshark and eBPF setup."""
    validation = {
        "timestamp": str(asyncio.get_event_loop().time()),
        "full_check": full_check,
        "status": "validating"
    }
    
    # Check Wireshark/tshark availability
    try:
        proc = await asyncio.create_subprocess_exec(
            'tshark', '--version',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        
        if proc.returncode == 0:
            validation["tshark"] = {
                "available": True,
                "version": stdout.decode().split('\n')[0]
            }
        else:
            validation["tshark"] = {
                "available": False,
                "error": stderr.decode()
            }
    except Exception as e:
        validation["tshark"] = {
            "available": False,
            "error": str(e)
        }
    
    # Check eBPF/BCC availability
    validation["ebpf"] = {
        "bcc_available": BCC_AVAILABLE,
        "high_performance_mode": BCC_AVAILABLE,
        "target_performance": "10M+ pps" if BCC_AVAILABLE else "Traditional mode"
    }
    
    if full_check and BCC_AVAILABLE:
        # Additional eBPF capability checks would go here
        validation["ebpf"]["kernel_support"] = "requires_testing"
        validation["ebpf"]["xdp_support"] = "requires_interface_test"
    
    # Overall status
    if validation["tshark"]["available"] or BCC_AVAILABLE:
        validation["status"] = "ready"
        validation["recommendation"] = "Enhanced mode available" if BCC_AVAILABLE else "Traditional mode only"
    else:
        validation["status"] = "setup_required"
        validation["recommendation"] = "Install tshark or eBPF/BCC for network analysis"
    
    return validation

async def _wireshark_generate_filter(description: str, complexity: str) -> Dict[str, Any]:
    """Generate Wireshark display filters from natural language."""
    # Simplified filter generation - could be enhanced with ML/LLM integration
    filter_templates = {
        "http traffic": "http",
        "https traffic": "tls.handshake.type == 1",
        "tcp traffic": "tcp",
        "udp traffic": "udp",
        "dns queries": "dns",
        "ssh connections": "ssh",
        "ftp traffic": "ftp or ftp-data",
        "email traffic": "smtp or pop or imap",
        "web traffic": "http or tls",
        "database traffic": "mysql or postgresql or tds"
    }
    
    # Simple keyword matching
    filter_expr = "tcp"  # Default
    for keyword, filter_template in filter_templates.items():
        if keyword.lower() in description.lower():
            filter_expr = filter_template
            break
    
    return {
        "description": description,
        "complexity": complexity,
        "filter": filter_expr,
        "explanation": f"Generated filter for: {description}",
        "ebpf_compatible": True  # Most filters can be adapted for eBPF
    }

async def _wireshark_live_capture(
    interface: str, 
    duration: int, 
    filter_expr: str, 
    max_packets: int
) -> Dict[str, Any]:
    """Enhanced live capture with extended duration support and permission fallbacks."""
    
    # Enhanced implementation with multiple capture methods for reliability
    # Method 1: Try traditional tshark (existing implementation)
    # Method 2: Fallback to tcpdump + analysis for permission issues
    # Method 3: Use sg wireshark for group switching
    
    capture_start_time = asyncio.get_event_loop().time()
    
    # First try the original tshark method
    try:
        cmd = [
            'tshark', 
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
                    "recommendation": "Use eBPF tools for high-performance capture (10M+ pps)",
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
            # Original method failed - try enhanced fallback methods
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
    
    # Method 2: Try tcpdump + tshark analysis (most reliable fallback)
    try:
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            pcap_file = tmp.name
        
        # Build tcpdump command
        cmd = [
            'timeout', str(duration + 10),  # Add buffer time
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
        
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=duration + 15)
        
        if proc.returncode in [0, 124]:  # Success or timeout (expected)
            # Parse with tshark
            parse_cmd = ['tshark', '-r', pcap_file, '-T', 'json', '-c', str(min(10, max_packets))]
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
    
    # Method 3: Try sg wireshark (group switching)
    try:
        cmd = [
            'sg', 'wireshark', '-c',
            f'timeout {duration + 5} tshark -i {interface} -c {max_packets} -T json'
        ]
        
        if filter_expr:
            cmd[-1] += f' -f "{filter_expr}"'
        
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
            "4. Use eBPF tools for high-performance capture if available",
            "5. Test permissions with: python sudo_permission_test.py"
        ],
        "fallback_options": [
            "Use async background capture: python async_long_capture.py",
            "Try manual tcpdump: tcpdump -i interface -w file.pcap",
            "Check existing PCAP files with wireshark_analyze_pcap"
        ],
        "extended_capture_note": "For 5+ minute captures, use the async background system even when direct capture works"
    }

async def _wireshark_analyze_pcap(filepath: str, analysis_type: str) -> Dict[str, Any]:
    """Analyze PCAP files with tshark."""
    if not os.path.exists(filepath):
        return {
            "status": "failed",
            "error": f"File not found: {filepath}"
        }
    
    try:
        # Basic statistics
        stats_cmd = ['tshark', '-r', filepath, '-q', '-z', 'conv,tcp']
        
        proc = await asyncio.create_subprocess_exec(
            *stats_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await proc.communicate()
        
        if proc.returncode == 0:
            return {
                "status": "success",
                "filepath": filepath,
                "analysis_type": analysis_type,
                "statistics": stdout.decode(),
                "recommendation": "Use eBPF analysis for real-time processing"
            }
        else:
            return {
                "status": "failed",
                "error": stderr.decode()
            }
            
    except Exception as e:
        return {
            "status": "failed",
            "error": str(e)
        }

# Server startup with enhanced capabilities
async def main():
    """Start the enhanced Wireshark MCP server with eBPF/XDP integration."""
    logger.info("🚀 Starting Enhanced Wireshark MCP Server with eBPF/XDP Integration")
    
    # Log capabilities
    if BCC_AVAILABLE:
        logger.info("✅ eBPF/XDP high-performance mode available (10M+ pps target)")
    else:
        logger.warning("⚠️ eBPF/XDP disabled - install bcc-tools for high-performance mode")
    
    logger.info("✅ Enterprise compliance engines available (SOC2, GDPR, NIST)")
    logger.info("✅ Traditional Wireshark tools available")
    
    # Start the server
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="enhanced-wireshark-mcp",
                server_version="2.0.0",
                capabilities=server.get_capabilities(
                    notification_options=None,
                    experimental_capabilities=None,
                )
            )
        )

if __name__ == "__main__":
    # Import here to avoid issues if not available
    try:
        from mcp.server.models import InitializationOptions
    except ImportError:
        # Fallback for older MCP versions
        class InitializationOptions:
            def __init__(self, **kwargs):
                for k, v in kwargs.items():
                    setattr(self, k, v)
    
    asyncio.run(main())