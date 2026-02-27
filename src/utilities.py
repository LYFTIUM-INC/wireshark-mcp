"""
Utility functions for the Wireshark MCP Server.
Provides async subprocess execution, output parsing, and common helpers.
"""

import asyncio
import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


async def run_command_async(
    cmd: List[str], timeout: int = 300, ignore_errors: bool = False
) -> subprocess.CompletedProcess:
    """Run a shell command asynchronously with timeout and error handling."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

        if proc.returncode != 0 and not ignore_errors:
            raise RuntimeError(f"Command failed (rc={proc.returncode}): {stderr.decode()}")

        return subprocess.CompletedProcess(
            cmd, proc.returncode, stdout.decode(), stderr.decode()
        )
    except asyncio.TimeoutError:
        raise RuntimeError(f"Command timed out after {timeout} seconds: {' '.join(cmd[:3])}")


async def run_tshark_command(
    cmd: List[str], timeout: int = 300, ignore_errors: bool = False
) -> subprocess.CompletedProcess:
    """Run a TShark command asynchronously."""
    return await run_command_async(cmd, timeout=timeout, ignore_errors=ignore_errors)


def get_temp_filepath(prefix: str = "wireshark_mcp_", suffix: str = ".pcap") -> str:
    """Generate a temporary file path using tempfile module."""
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=suffix)
    os.close(fd)
    return path


async def delayed_cleanup(filepath: str, delay_seconds: int):
    """Clean up temporary files after a delay."""
    try:
        await asyncio.sleep(delay_seconds)
        if os.path.exists(filepath):
            os.unlink(filepath)
            logger.info(f"Cleaned up temporary file: {filepath}")
    except OSError as e:
        logger.warning(f"Failed to clean up {filepath}: {e}")


def parse_protocol_hierarchy(output: str) -> Dict[str, Any]:
    """Parse TShark protocol hierarchy statistics output."""
    lines = output.strip().split("\n")
    stats: Dict[str, Any] = {"protocols": {}, "total_packets": 0, "total_bytes": 0}

    for line in lines:
        if "frames:" in line and "bytes:" in line:
            match = re.search(r"(\S+)\s+frames:(\d+)\s+bytes:(\d+)", line)
            if match:
                protocol = match.group(1).strip()
                frames = int(match.group(2))
                bytes_count = int(match.group(3))
                stats["protocols"][protocol] = {
                    "packets": frames,
                    "bytes": bytes_count,
                }
                if not line.startswith(" "):
                    stats["total_packets"] += frames
                    stats["total_bytes"] += bytes_count
    return stats


def parse_conversations(output: str) -> Dict[str, Any]:
    """Parse TShark conversation statistics output."""
    lines = output.strip().split("\n")
    conversations = []

    for line in lines:
        if "<->" in line and not line.startswith("="):
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
                    "bytes_b_to_a": int(parts[9]) if len(parts) > 9 and parts[9].isdigit() else 0,
                })

    return {
        "count": len(conversations),
        "conversations": conversations[:10],
        "total_listed": len(conversations),
    }


def parse_endpoints(output: str) -> Dict[str, Any]:
    """Parse TShark endpoint statistics output."""
    lines = output.strip().split("\n")
    endpoints = []

    for line in lines:
        if re.match(r"^\d+\.\d+\.\d+\.\d+", line) or re.match(r"^[0-9a-fA-F:]+", line):
            parts = line.split()
            if len(parts) >= 3:
                endpoints.append({
                    "address": parts[0],
                    "packets": int(parts[1]) if parts[1].isdigit() else 0,
                    "bytes": int(parts[2]) if parts[2].isdigit() else 0,
                })

    endpoints.sort(key=lambda x: x["packets"], reverse=True)
    return {
        "count": len(endpoints),
        "top_talkers": endpoints[:10],
        "total_endpoints": len(endpoints),
    }


def parse_io_statistics(output: str) -> Dict[str, Any]:
    """Parse TShark I/O statistics output."""
    lines = output.strip().split("\n")
    intervals = []

    for line in lines:
        match = re.search(r"(\d+\.\d+)\s*-\s*(\d+\.\d+)\s+(\d+)", line)
        if match:
            intervals.append({
                "start": float(match.group(1)),
                "end": float(match.group(2)),
                "packets": int(match.group(3)),
            })

    return {"interval_count": len(intervals), "intervals": intervals}


def parse_capinfos_machine_output(output: str) -> Dict[str, Any]:
    """Parse capinfos machine-readable output."""
    info = {}
    for line in output.strip().split("\n"):
        if "\t" in line:
            key, value = line.split("\t", 1)
            info[key] = value
    return info


def parse_capinfos_output(output: str) -> Dict[str, str]:
    """Parse capinfos output into structured data."""
    info = {}
    for line in output.split("\n"):
        if ":" in line:
            key, value = line.split(":", 1)
            info[key.strip()] = value.strip()
    return info


def parse_expert_info(output: str) -> Dict[str, Any]:
    """Parse TShark expert info output."""
    expert_info = {"errors": 0, "warnings": 0, "notes": 0, "chats": 0}
    for line in output.split("\n"):
        for level in ["Errors", "Warnings", "Notes", "Chats"]:
            if level in line:
                match = re.search(rf"{level}\s*\((\d+)\)", line)
                if match:
                    expert_info[level.lower()] = int(match.group(1))
    return expert_info


def parse_http_stats(output: str) -> Dict[str, Any]:
    """Parse HTTP statistics from TShark output."""
    http_stats: Dict[str, Any] = {
        "requests": 0,
        "responses": 0,
        "methods": {},
        "status_codes": {},
    }
    for line in output.split("\n"):
        for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]:
            if method in line:
                http_stats["methods"][method] = http_stats["methods"].get(method, 0) + 1
    return http_stats


def parse_ip_range(range_str: str) -> str:
    """Parse IP range like '192.168.1.1 - 192.168.1.100' into Wireshark filter."""
    try:
        start_ip, end_ip = [ip.strip() for ip in range_str.split("-")]
        return f"ip.addr >= {start_ip} and ip.addr <= {end_ip}"
    except ValueError:
        return f"ip.addr == {range_str}"


def combine_filters_intelligently(filter_parts: List[str], description: str) -> str:
    """Intelligently combine multiple filter parts based on context."""
    if any(word in description for word in ["not", "except", "exclude", "without"]):
        if len(filter_parts) >= 2:
            return f"({filter_parts[0]}) and not ({filter_parts[1]})"
    if any(word in description for word in ["or", "either", "any"]):
        return " or ".join(f"({part})" for part in filter_parts)
    return " and ".join(f"({part})" for part in filter_parts)


def generate_contextual_suggestions(description: str, matched_patterns: List[str]) -> List[str]:
    """Generate contextual suggestions based on what was detected."""
    suggestions = [
        "Use specific IP addresses: ip.addr == 192.168.1.1",
        "Filter by port: tcp.port == 80 or udp.port == 53",
        "Combine with operators: (http) and (ip.addr == 192.168.1.0/24)",
    ]
    if any("ip" in pattern for pattern in matched_patterns):
        suggestions.append("Try subnet notation: ip.addr == 192.168.1.0/24")
        suggestions.append("Use IP ranges: ip.addr >= 10.0.0.1 and ip.addr <= 10.0.0.100")
    if any("port" in pattern for pattern in matched_patterns):
        suggestions.append("Specific protocols: tcp.port == 443 (HTTPS) or udp.port == 53 (DNS)")
    if any("http" in pattern for pattern in matched_patterns):
        suggestions.append('HTTP methods: http.request.method == GET')
        suggestions.append('HTTP hosts: http.host == "example.com"')
    if "slow" in description or "latency" in description:
        suggestions.append("RTT analysis: tcp.analysis.ack_rtt > 0.05")
        suggestions.append("Window scaling: tcp.window_size_scalefactor > 1")
    return suggestions[:6]


def generate_analysis_summary(results: Dict[str, Any]) -> str:
    """Generate a human-readable summary of analysis results."""
    summary = "📊 **PCAP Analysis Summary**\n\n"
    if "file_info" in results:
        summary += f"**File**: {results['file_info']['path']}\n"
        summary += f"**Size**: {results['file_info']['size_mb']}\n\n"
    if "file_metadata" in results:
        meta = results["file_metadata"]
        if "Number of packets" in meta:
            summary += f"**Total Packets**: {meta['Number of packets']}\n"
        if "Capture duration" in meta:
            summary += f"**Duration**: {meta['Capture duration']}\n\n"
    if "protocol_hierarchy" in results:
        ph = results["protocol_hierarchy"]
        summary += "**Top Protocols**:\n"
        sorted_protos = sorted(
            ph["protocols"].items(), key=lambda x: x[1]["packets"], reverse=True
        )[:5]
        for proto, stats in sorted_protos:
            summary += f"- {proto}: {stats['packets']:,} packets\n"
        summary += "\n"
    if "security_analysis" in results:
        sec = results["security_analysis"]
        if sec["threat_indicators"] > 0:
            summary += f"⚠️ **Security Alerts**: {sec['threat_indicators']} suspicious patterns detected\n"
            for pattern, count in sec["suspicious_patterns"].items():
                summary += f"- {pattern}: {count} occurrences\n"
            summary += "\n"
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

    def format_dict(d: Dict, indent: int = 0) -> str:
        output = ""
        prefix = "  " * indent
        for key, value in d.items():
            if isinstance(value, dict):
                output += f"{prefix}{key}:\n"
                output += format_dict(value, indent + 1)
            elif isinstance(value, list):
                output += f"{prefix}{key}: [{len(value)} items]\n"
                for i, item in enumerate(value[:3]):
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
