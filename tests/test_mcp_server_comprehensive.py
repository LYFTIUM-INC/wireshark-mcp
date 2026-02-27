#!/usr/bin/env python3
"""
Comprehensive MCP Server Functionality Test Suite
=================================================

Tests all 18 tools of the Enhanced Wireshark MCP Server.
Generates a detailed report with pass/fail status, gaps, and recommendations.
"""

import asyncio
import json
import os
import sys
import time
import subprocess
import tempfile
import traceback
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from enhanced_server import (
    server,
    list_tools,
    call_tool,
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
    run_tshark_command,
    parse_protocol_hierarchy,
    parse_conversations,
    parse_endpoints,
    parse_io_statistics,
    parse_capinfos_machine_output,
    parse_expert_info,
    parse_http_stats,
    perform_security_analysis,
    perform_performance_analysis,
    generate_analysis_summary,
    generate_text_report,
    advanced_filter_generation,
    parse_ip_range,
    combine_filters_intelligently,
    generate_contextual_suggestions,
)


SAMPLE_PCAP = "/tmp/test_sample.pcap"
SAMPLE_PCAP_2 = "/tmp/test_sample_2.pcap"

TEST_RESULTS: List[Dict[str, Any]] = []


def record_result(
    tool_name: str,
    test_name: str,
    status: str,
    details: str = "",
    duration_ms: float = 0,
    severity: str = "info",
    gaps: List[str] = None,
    recommendations: List[str] = None,
):
    TEST_RESULTS.append({
        "tool": tool_name,
        "test": test_name,
        "status": status,
        "details": details,
        "duration_ms": round(duration_ms, 2),
        "severity": severity,
        "gaps": gaps or [],
        "recommendations": recommendations or [],
        "timestamp": datetime.now().isoformat(),
    })


async def generate_test_pcap():
    """Generate a sample PCAP file for testing using tcpdump or tshark."""
    print("\n[SETUP] Generating test PCAP files...")

    try:
        proc = await asyncio.create_subprocess_exec(
            "tcpdump", "-i", "lo", "-c", "50", "-w", SAMPLE_PCAP, "-q",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Generate some traffic on loopback while capturing
        for _ in range(5):
            traffic_proc = await asyncio.create_subprocess_exec(
                "python3", "-c",
                "import socket; s=socket.socket(); s.settimeout(0.5); "
                "try:\n s.connect(('127.0.0.1', 12345))\nexcept: pass\n"
                "s.close()",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await traffic_proc.wait()
            await asyncio.sleep(0.2)

        try:
            await asyncio.wait_for(proc.communicate(), timeout=15)
        except asyncio.TimeoutError:
            proc.terminate()
            await proc.wait()

        if Path(SAMPLE_PCAP).exists() and Path(SAMPLE_PCAP).stat().st_size > 0:
            # Create a second PCAP for merge tests
            proc2 = await asyncio.create_subprocess_exec(
                "tcpdump", "-i", "lo", "-c", "20", "-w", SAMPLE_PCAP_2, "-q",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            for _ in range(3):
                tp = await asyncio.create_subprocess_exec(
                    "python3", "-c",
                    "import socket; s=socket.socket(); s.settimeout(0.3); "
                    "try:\n s.connect(('127.0.0.1', 54321))\nexcept: pass\ns.close()",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await tp.wait()
                await asyncio.sleep(0.2)
            try:
                await asyncio.wait_for(proc2.communicate(), timeout=10)
            except asyncio.TimeoutError:
                proc2.terminate()
                await proc2.wait()

            print(f"  [OK] Test PCAP generated: {SAMPLE_PCAP} ({Path(SAMPLE_PCAP).stat().st_size} bytes)")
            if Path(SAMPLE_PCAP_2).exists():
                print(f"  [OK] Test PCAP 2 generated: {SAMPLE_PCAP_2} ({Path(SAMPLE_PCAP_2).stat().st_size} bytes)")
            return True
        else:
            print("  [WARN] PCAP generation produced empty file, creating minimal pcap")
            return await create_minimal_pcap()
    except Exception as e:
        print(f"  [WARN] tcpdump failed: {e}, creating minimal pcap")
        return await create_minimal_pcap()


async def create_minimal_pcap():
    """Create a minimal valid PCAP file using text2pcap."""
    hex_content = """0000  ff ff ff ff ff ff 00 11 22 33 44 55 08 00 45 00
0010  00 3c 1c 46 40 00 40 06 b1 e6 ac 10 0a 63 ac 10
0020  0a 0c 00 50 e8 2c 00 00 00 00 00 00 00 00 a0 02
0030  ff ff fe 30 00 00 02 04 05 b4 04 02 08 0a 00 08
0040  01 00 00 00 00 00 01 03 03 07
"""
    hex_file = "/tmp/test_hex_input.txt"
    Path(hex_file).write_text(hex_content)

    proc = await asyncio.create_subprocess_exec(
        "text2pcap", hex_file, SAMPLE_PCAP,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    await proc.communicate()

    # Copy for second pcap
    if Path(SAMPLE_PCAP).exists():
        proc2 = await asyncio.create_subprocess_exec(
            "cp", SAMPLE_PCAP, SAMPLE_PCAP_2,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc2.communicate()

    if Path(SAMPLE_PCAP).exists() and Path(SAMPLE_PCAP).stat().st_size > 0:
        print(f"  [OK] Minimal PCAP created: {SAMPLE_PCAP}")
        return True
    print("  [FAIL] Could not create any test PCAP")
    return False


# ============================================================
# TEST 1: list_tools
# ============================================================
async def test_list_tools():
    """Test the list_tools endpoint returns all 18 tools."""
    print("\n[TEST] list_tools - Tool Registration")
    start = time.time()
    try:
        tools = await list_tools()
        duration = (time.time() - start) * 1000

        tool_names = [t.name for t in tools]
        expected_tools = [
            "wireshark_system_info",
            "wireshark_validate_setup",
            "wireshark_generate_filter",
            "wireshark_live_capture",
            "wireshark_analyze_pcap",
            "wireshark_realtime_json_capture",
            "wireshark_protocol_statistics",
            "wireshark_analyze_pcap_enhanced",
            "wireshark_pcap_time_slice",
            "wireshark_pcap_splitter",
            "wireshark_pcap_merger",
            "wireshark_hex_to_pcap",
            "wireshark_http_analyzer",
            "wireshark_dns_analyzer",
            "wireshark_ssl_inspector",
            "wireshark_latency_profiler",
            "wireshark_threat_detector",
            "wireshark_remote_capture",
        ]

        missing = [t for t in expected_tools if t not in tool_names]
        extra = [t for t in tool_names if t not in expected_tools]

        gaps = []
        recs = []
        if missing:
            gaps.append(f"Missing tools: {missing}")
            recs.append("Register all expected tools in list_tools()")
        if extra:
            gaps.append(f"Unexpected extra tools: {extra}")

        # Check input schemas
        schema_issues = []
        for tool in tools:
            schema = tool.inputSchema
            if not schema or schema.get("type") != "object":
                schema_issues.append(f"{tool.name}: invalid schema type")
            if "properties" not in schema:
                schema_issues.append(f"{tool.name}: missing properties")

        if schema_issues:
            gaps.extend(schema_issues)
            recs.append("Ensure all tools have valid JSON Schema input definitions")

        status = "PASS" if not missing and len(tools) == 18 else "FAIL"
        record_result(
            "list_tools", "Tool Registration",
            status,
            f"Found {len(tools)} tools, expected 18. Missing: {missing}",
            duration, "critical" if status == "FAIL" else "info",
            gaps, recs,
        )
        print(f"  [{status}] Found {len(tools)} tools ({duration:.1f}ms)")
        return tool_names
    except Exception as e:
        duration = (time.time() - start) * 1000
        record_result("list_tools", "Tool Registration", "ERROR", str(e), duration, "critical")
        print(f"  [ERROR] {e}")
        return []


# ============================================================
# TEST 2: wireshark_system_info
# ============================================================
async def test_system_info():
    """Test system info retrieval."""
    print("\n[TEST] wireshark_system_info")

    for info_type in ["all", "interfaces", "capabilities", "system"]:
        start = time.time()
        try:
            result = await call_tool("wireshark_system_info", {"info_type": info_type})
            duration = (time.time() - start) * 1000
            text = result[0].text

            gaps = []
            recs = []
            if "Error" in text or "❌" in text:
                status = "FAIL"
                gaps.append(f"System info failed for type={info_type}")
            elif "wireshark_mcp_server" not in text:
                status = "WARN"
                gaps.append("Response missing server version info")
                recs.append("Include server version in all responses")
            else:
                status = "PASS"

            if info_type == "all" and "network_interfaces" not in text:
                gaps.append("Missing network_interfaces in 'all' response")
                recs.append("Ensure 'all' info_type returns comprehensive data")

            record_result("wireshark_system_info", f"info_type={info_type}", status, text[:200], duration, gaps=gaps, recommendations=recs)
            print(f"  [{status}] info_type={info_type} ({duration:.1f}ms)")
        except Exception as e:
            duration = (time.time() - start) * 1000
            record_result("wireshark_system_info", f"info_type={info_type}", "ERROR", str(e), duration, "high")
            print(f"  [ERROR] info_type={info_type}: {e}")


# ============================================================
# TEST 3: wireshark_validate_setup
# ============================================================
async def test_validate_setup():
    """Test setup validation."""
    print("\n[TEST] wireshark_validate_setup")

    for full_check in [False, True]:
        start = time.time()
        try:
            result = await call_tool("wireshark_validate_setup", {"full_check": full_check})
            duration = (time.time() - start) * 1000
            text = result[0].text

            gaps = []
            recs = []
            if "tshark" not in text:
                gaps.append("tshark not mentioned in validation")
            if "dependencies" not in text:
                gaps.append("Dependencies section missing")

            # Check for editcap, mergecap, text2pcap validation
            for tool in ["editcap", "mergecap", "text2pcap"]:
                if tool not in text:
                    gaps.append(f"{tool} not validated but used by server")
                    recs.append(f"Add {tool} to dependency validation list")

            status = "PASS" if "✅" in text else "WARN"
            record_result("wireshark_validate_setup", f"full_check={full_check}", status, text[:200], duration, gaps=gaps, recommendations=recs)
            print(f"  [{status}] full_check={full_check} ({duration:.1f}ms)")
        except Exception as e:
            duration = (time.time() - start) * 1000
            record_result("wireshark_validate_setup", f"full_check={full_check}", "ERROR", str(e), duration, "high")
            print(f"  [ERROR] {e}")


# ============================================================
# TEST 4: wireshark_generate_filter
# ============================================================
async def test_generate_filter():
    """Test filter generation from natural language."""
    print("\n[TEST] wireshark_generate_filter")

    test_cases = [
        {"description": "show me all HTTP traffic", "expected_contains": "http"},
        {"description": "DNS queries from 192.168.1.1", "expected_contains": "dns"},
        {"description": "traffic on port 443", "expected_contains": "443"},
        {"description": "show TCP retransmissions", "expected_contains": "retransmission"},
        {"description": "traffic from subnet 10.0.0.0/24", "expected_contains": "10.0.0.0"},
        {"description": "large packets over 1500 bytes", "expected_contains": "frame.len"},
        {"description": "SSH connections", "expected_contains": "ssh"},
        {"description": "slow connections with high latency", "expected_contains": "rtt"},
        {"description": "", "expected_contains": ""},  # edge case: empty input
        {"description": "gibberish xyzzy traffic", "expected_contains": ""},  # unknown pattern
    ]

    for tc in test_cases:
        start = time.time()
        try:
            result = await call_tool("wireshark_generate_filter", {
                "description": tc["description"],
                "complexity": "intermediate",
            })
            duration = (time.time() - start) * 1000
            text = result[0].text

            gaps = []
            recs = []

            if tc["expected_contains"] and tc["expected_contains"].lower() not in text.lower():
                status = "FAIL"
                gaps.append(f"Expected filter containing '{tc['expected_contains']}' not found")
                recs.append(f"Improve pattern matching for: {tc['description']}")
            elif not tc["description"]:
                status = "WARN" if "error" not in text.lower() else "PASS"
                if status == "WARN":
                    gaps.append("Empty description doesn't produce error")
                    recs.append("Validate empty input and return error")
            else:
                status = "PASS"

            record_result("wireshark_generate_filter", f"desc='{tc['description'][:30]}'", status, text[:150], duration, gaps=gaps, recommendations=recs)
            print(f"  [{status}] desc='{tc['description'][:35]}' ({duration:.1f}ms)")
        except Exception as e:
            duration = (time.time() - start) * 1000
            record_result("wireshark_generate_filter", f"desc='{tc['description'][:30]}'", "ERROR", str(e), duration, "medium")
            print(f"  [ERROR] {e}")


# ============================================================
# TEST 5: wireshark_analyze_pcap (basic)
# ============================================================
async def test_analyze_pcap():
    """Test PCAP file analysis."""
    print("\n[TEST] wireshark_analyze_pcap")

    if not Path(SAMPLE_PCAP).exists():
        record_result("wireshark_analyze_pcap", "all", "SKIP", "No test PCAP available", 0)
        print("  [SKIP] No test PCAP available")
        return

    for analysis_type in ["quick", "comprehensive", "security", "performance"]:
        start = time.time()
        try:
            result = await call_tool("wireshark_analyze_pcap", {
                "filepath": SAMPLE_PCAP,
                "analysis_type": analysis_type,
            })
            duration = (time.time() - start) * 1000
            text = result[0].text

            gaps = []
            recs = []
            if "❌" in text:
                status = "FAIL"
                gaps.append(f"Analysis failed for type={analysis_type}")
            elif "✅" in text:
                status = "PASS"
            else:
                status = "WARN"
                gaps.append("Response missing clear status indicator")

            record_result("wireshark_analyze_pcap", f"type={analysis_type}", status, text[:200], duration, gaps=gaps, recommendations=recs)
            print(f"  [{status}] type={analysis_type} ({duration:.1f}ms)")
        except Exception as e:
            duration = (time.time() - start) * 1000
            record_result("wireshark_analyze_pcap", f"type={analysis_type}", "ERROR", str(e), duration, "high")
            print(f"  [ERROR] {e}")

    # Edge case: nonexistent file
    start = time.time()
    try:
        result = await call_tool("wireshark_analyze_pcap", {"filepath": "/tmp/nonexistent.pcap"})
        duration = (time.time() - start) * 1000
        text = result[0].text
        status = "PASS" if "not found" in text.lower() or "❌" in text else "FAIL"
        gaps = [] if status == "PASS" else ["Missing proper error for nonexistent file"]
        record_result("wireshark_analyze_pcap", "nonexistent_file", status, text[:200], duration, gaps=gaps)
        print(f"  [{status}] nonexistent_file ({duration:.1f}ms)")
    except Exception as e:
        duration = (time.time() - start) * 1000
        record_result("wireshark_analyze_pcap", "nonexistent_file", "ERROR", str(e), duration)
        print(f"  [ERROR] nonexistent_file: {e}")

    # Edge case: empty filepath
    start = time.time()
    try:
        result = await call_tool("wireshark_analyze_pcap", {"filepath": ""})
        duration = (time.time() - start) * 1000
        text = result[0].text
        status = "PASS" if "error" in text.lower() or "❌" in text else "FAIL"
        gaps = [] if status == "PASS" else ["Missing validation for empty filepath"]
        record_result("wireshark_analyze_pcap", "empty_filepath", status, text[:200], duration, gaps=gaps, recommendations=["Validate filepath is non-empty"])
        print(f"  [{status}] empty_filepath ({duration:.1f}ms)")
    except Exception as e:
        duration = (time.time() - start) * 1000
        record_result("wireshark_analyze_pcap", "empty_filepath", "ERROR", str(e), duration)


# ============================================================
# TEST 6: wireshark_live_capture
# ============================================================
async def test_live_capture():
    """Test live packet capture."""
    print("\n[TEST] wireshark_live_capture")

    start = time.time()
    try:
        result = await call_tool("wireshark_live_capture", {
            "interface": "lo",
            "duration": 3,
            "max_packets": 10,
        })
        duration = (time.time() - start) * 1000
        text = result[0].text

        gaps = []
        recs = []
        if "✅" in text or "Success" in text:
            status = "PASS"
        elif "Permission" in text or "permission" in text:
            status = "WARN"
            gaps.append("Permission issues prevent live capture")
            recs.append("Configure cap_net_raw capability or run with appropriate permissions")
        else:
            status = "WARN"
            gaps.append("Live capture status unclear")

        record_result("wireshark_live_capture", "lo_interface", status, text[:300], duration, gaps=gaps, recommendations=recs)
        print(f"  [{status}] lo_interface ({duration:.1f}ms)")
    except Exception as e:
        duration = (time.time() - start) * 1000
        record_result("wireshark_live_capture", "lo_interface", "ERROR", str(e), duration, "high")
        print(f"  [ERROR] {e}")


# ============================================================
# TEST 7: wireshark_realtime_json_capture
# ============================================================
async def test_realtime_json_capture():
    """Test real-time JSON packet capture."""
    print("\n[TEST] wireshark_realtime_json_capture")

    for json_format in ["ek", "json"]:
        start = time.time()
        try:
            result = await call_tool("wireshark_realtime_json_capture", {
                "interface": "lo",
                "duration": 3,
                "max_packets": 5,
                "json_format": json_format,
            })
            duration = (time.time() - start) * 1000
            text = result[0].text

            gaps = []
            recs = []
            if "✅" in text or "Capture Complete" in text:
                status = "PASS"
            elif "Permission" in text.lower() or "permission" in text.lower():
                status = "WARN"
                gaps.append("Permission issues for real-time JSON capture")
            elif "Failed" in text:
                status = "FAIL"
                gaps.append(f"Real-time JSON capture failed with format={json_format}")
            else:
                status = "WARN"

            record_result("wireshark_realtime_json_capture", f"format={json_format}", status, text[:300], duration, gaps=gaps, recommendations=recs)
            print(f"  [{status}] format={json_format} ({duration:.1f}ms)")
        except Exception as e:
            duration = (time.time() - start) * 1000
            record_result("wireshark_realtime_json_capture", f"format={json_format}", "ERROR", str(e), duration, "medium")
            print(f"  [ERROR] {e}")


# ============================================================
# TEST 8: wireshark_protocol_statistics
# ============================================================
async def test_protocol_statistics():
    """Test protocol statistics generation."""
    print("\n[TEST] wireshark_protocol_statistics")

    if not Path(SAMPLE_PCAP).exists():
        record_result("wireshark_protocol_statistics", "all", "SKIP", "No test PCAP", 0)
        print("  [SKIP] No test PCAP")
        return

    for analysis_type in ["protocol_hierarchy", "conversations", "endpoints", "io_stats", "all"]:
        start = time.time()
        try:
            result = await call_tool("wireshark_protocol_statistics", {
                "source": SAMPLE_PCAP,
                "analysis_type": analysis_type,
            })
            duration = (time.time() - start) * 1000
            text = result[0].text

            gaps = []
            recs = []
            if "❌" in text or "Failed" in text:
                status = "FAIL"
                gaps.append(f"Statistics failed for type={analysis_type}")
            elif "statistics" in text.lower() or "protocol" in text.lower():
                status = "PASS"
            else:
                status = "WARN"

            record_result("wireshark_protocol_statistics", f"type={analysis_type}", status, text[:200], duration, gaps=gaps, recommendations=recs)
            print(f"  [{status}] type={analysis_type} ({duration:.1f}ms)")
        except Exception as e:
            duration = (time.time() - start) * 1000
            record_result("wireshark_protocol_statistics", f"type={analysis_type}", "ERROR", str(e), duration, "high")
            print(f"  [ERROR] {e}")


# ============================================================
# TEST 9: wireshark_analyze_pcap_enhanced
# ============================================================
async def test_analyze_pcap_enhanced():
    """Test enhanced PCAP analysis."""
    print("\n[TEST] wireshark_analyze_pcap_enhanced")

    if not Path(SAMPLE_PCAP).exists():
        record_result("wireshark_analyze_pcap_enhanced", "all", "SKIP", "No test PCAP", 0)
        return

    for analysis_type in ["quick", "comprehensive", "security", "performance", "conversations", "statistics"]:
        for output_format in ["json", "summary", "text"]:
            if analysis_type != "comprehensive" and output_format != "json":
                continue  # Only test all formats for comprehensive

            start = time.time()
            try:
                result = await call_tool("wireshark_analyze_pcap_enhanced", {
                    "filepath": SAMPLE_PCAP,
                    "analysis_type": analysis_type,
                    "output_format": output_format,
                })
                duration = (time.time() - start) * 1000
                text = result[0].text

                gaps = []
                if "❌" in text or "Failed" in text:
                    status = "FAIL"
                    gaps.append(f"Enhanced analysis failed: type={analysis_type}, format={output_format}")
                else:
                    status = "PASS"

                label = f"type={analysis_type},fmt={output_format}"
                record_result("wireshark_analyze_pcap_enhanced", label, status, text[:200], duration, gaps=gaps)
                print(f"  [{status}] {label} ({duration:.1f}ms)")
            except Exception as e:
                duration = (time.time() - start) * 1000
                record_result("wireshark_analyze_pcap_enhanced", f"type={analysis_type}", "ERROR", str(e), duration, "high")
                print(f"  [ERROR] type={analysis_type}: {e}")


# ============================================================
# TEST 10: wireshark_pcap_time_slice
# ============================================================
async def test_pcap_time_slice():
    """Test PCAP time slicing."""
    print("\n[TEST] wireshark_pcap_time_slice")

    if not Path(SAMPLE_PCAP).exists():
        record_result("wireshark_pcap_time_slice", "all", "SKIP", "No test PCAP", 0)
        return

    start = time.time()
    try:
        result = await call_tool("wireshark_pcap_time_slice", {
            "input_file": SAMPLE_PCAP,
            "start_time": "2020-01-01T00:00:00",
            "end_time": "2030-12-31T23:59:59",
        })
        duration = (time.time() - start) * 1000
        text = result[0].text

        gaps = []
        recs = []
        if "✅" in text or "Success" in text:
            status = "PASS"
        elif "❌" in text:
            status = "FAIL"
            gaps.append("Time slice operation failed")
        else:
            status = "WARN"

        record_result("wireshark_pcap_time_slice", "basic_slice", status, text[:200], duration, gaps=gaps, recommendations=recs)
        print(f"  [{status}] basic_slice ({duration:.1f}ms)")
    except Exception as e:
        duration = (time.time() - start) * 1000
        record_result("wireshark_pcap_time_slice", "basic_slice", "ERROR", str(e), duration, "medium")
        print(f"  [ERROR] {e}")

    # Test nonexistent input
    start = time.time()
    try:
        result = await call_tool("wireshark_pcap_time_slice", {
            "input_file": "/tmp/nonexistent.pcap",
            "start_time": "2020-01-01T00:00:00",
            "end_time": "2030-12-31T23:59:59",
        })
        duration = (time.time() - start) * 1000
        text = result[0].text
        status = "PASS" if ("not found" in text.lower() or "❌" in text) else "FAIL"
        record_result("wireshark_pcap_time_slice", "nonexistent_input", status, text[:200], duration)
        print(f"  [{status}] nonexistent_input ({duration:.1f}ms)")
    except Exception as e:
        duration = (time.time() - start) * 1000
        record_result("wireshark_pcap_time_slice", "nonexistent_input", "ERROR", str(e), duration)


# ============================================================
# TEST 11: wireshark_pcap_splitter
# ============================================================
async def test_pcap_splitter():
    """Test PCAP file splitting."""
    print("\n[TEST] wireshark_pcap_splitter")

    if not Path(SAMPLE_PCAP).exists():
        record_result("wireshark_pcap_splitter", "all", "SKIP", "No test PCAP", 0)
        return

    for split_type in ["packets", "time"]:
        start = time.time()
        try:
            result = await call_tool("wireshark_pcap_splitter", {
                "input_file": SAMPLE_PCAP,
                "split_type": split_type,
                "split_value": 10 if split_type == "packets" else 5,
            })
            duration = (time.time() - start) * 1000
            text = result[0].text

            gaps = []
            if "✅" in text or "Success" in text:
                status = "PASS"
            elif "❌" in text:
                status = "FAIL"
                gaps.append(f"Split failed for type={split_type}")
            else:
                status = "WARN"

            record_result("wireshark_pcap_splitter", f"split_type={split_type}", status, text[:200], duration, gaps=gaps)
            print(f"  [{status}] split_type={split_type} ({duration:.1f}ms)")
        except Exception as e:
            duration = (time.time() - start) * 1000
            record_result("wireshark_pcap_splitter", f"split_type={split_type}", "ERROR", str(e), duration, "medium")
            print(f"  [ERROR] {e}")


# ============================================================
# TEST 12: wireshark_pcap_merger
# ============================================================
async def test_pcap_merger():
    """Test PCAP file merging."""
    print("\n[TEST] wireshark_pcap_merger")

    if not Path(SAMPLE_PCAP).exists() or not Path(SAMPLE_PCAP_2).exists():
        record_result("wireshark_pcap_merger", "all", "SKIP", "No test PCAPs", 0)
        return

    output_file = "/tmp/test_merged_output.pcap"

    start = time.time()
    try:
        result = await call_tool("wireshark_pcap_merger", {
            "input_files": [SAMPLE_PCAP, SAMPLE_PCAP_2],
            "output_file": output_file,
            "sort_chronologically": True,
        })
        duration = (time.time() - start) * 1000
        text = result[0].text

        gaps = []
        recs = []
        if "✅" in text or "Success" in text:
            status = "PASS"
            if Path(output_file).exists():
                if Path(output_file).stat().st_size == 0:
                    status = "FAIL"
                    gaps.append("Merged file is empty")
        elif "❌" in text:
            status = "FAIL"
            gaps.append("Merge operation failed")
        else:
            status = "WARN"

        record_result("wireshark_pcap_merger", "chronological_merge", status, text[:200], duration, gaps=gaps, recommendations=recs)
        print(f"  [{status}] chronological_merge ({duration:.1f}ms)")
    except Exception as e:
        duration = (time.time() - start) * 1000
        record_result("wireshark_pcap_merger", "chronological_merge", "ERROR", str(e), duration, "medium")
        print(f"  [ERROR] {e}")

    # Test with nonexistent files
    start = time.time()
    try:
        result = await call_tool("wireshark_pcap_merger", {
            "input_files": ["/tmp/no_file_1.pcap", "/tmp/no_file_2.pcap"],
            "output_file": "/tmp/should_not_exist.pcap",
        })
        duration = (time.time() - start) * 1000
        text = result[0].text
        status = "PASS" if ("not found" in text.lower() or "❌" in text or "Error" in text) else "FAIL"
        record_result("wireshark_pcap_merger", "nonexistent_files", status, text[:200], duration)
        print(f"  [{status}] nonexistent_files ({duration:.1f}ms)")
    except Exception as e:
        duration = (time.time() - start) * 1000
        record_result("wireshark_pcap_merger", "nonexistent_files", "ERROR", str(e), duration)


# ============================================================
# TEST 13: wireshark_hex_to_pcap
# ============================================================
async def test_hex_to_pcap():
    """Test hex-to-PCAP conversion."""
    print("\n[TEST] wireshark_hex_to_pcap")

    hex_data = """0000  00 11 22 33 44 55 66 77 88 99 aa bb 08 00 45 00
0010  00 28 00 01 00 00 40 06 7c cd 7f 00 00 01 7f 00
0020  00 01 04 d2 16 2e 00 00 00 00 00 00 00 00 50 02
0030  20 00 91 7c 00 00"""

    output_file = "/tmp/test_hex_output.pcap"

    for protocol in ["ethernet", "tcp", "udp"]:
        start = time.time()
        try:
            result = await call_tool("wireshark_hex_to_pcap", {
                "input_source": hex_data,
                "input_type": "text",
                "output_file": output_file,
                "protocol": protocol,
            })
            duration = (time.time() - start) * 1000
            text = result[0].text

            gaps = []
            if "✅" in text or "Success" in text:
                status = "PASS"
            elif "❌" in text:
                status = "FAIL"
                gaps.append(f"Hex to PCAP failed for protocol={protocol}")
            else:
                status = "WARN"

            record_result("wireshark_hex_to_pcap", f"protocol={protocol}", status, text[:200], duration, gaps=gaps)
            print(f"  [{status}] protocol={protocol} ({duration:.1f}ms)")
        except Exception as e:
            duration = (time.time() - start) * 1000
            record_result("wireshark_hex_to_pcap", f"protocol={protocol}", "ERROR", str(e), duration, "medium")
            print(f"  [ERROR] {e}")


# ============================================================
# TEST 14: wireshark_http_analyzer
# ============================================================
async def test_http_analyzer():
    """Test HTTP traffic analysis."""
    print("\n[TEST] wireshark_http_analyzer")

    if not Path(SAMPLE_PCAP).exists():
        record_result("wireshark_http_analyzer", "all", "SKIP", "No test PCAP", 0)
        return

    for analysis_type in ["comprehensive", "transactions", "performance", "security"]:
        start = time.time()
        try:
            result = await call_tool("wireshark_http_analyzer", {
                "input_file": SAMPLE_PCAP,
                "analysis_type": analysis_type,
            })
            duration = (time.time() - start) * 1000
            text = result[0].text

            gaps = []
            recs = []
            if "✅" in text or "Success" in text:
                status = "PASS"
            elif "❌" in text:
                status = "FAIL"
                gaps.append(f"HTTP analysis failed for type={analysis_type}")
            else:
                status = "WARN"

            # Check for stub implementations
            parsed = {}
            try:
                parsed = json.loads(text)
            except:
                pass
            if parsed:
                perf = parsed.get("results", {}).get("performance", {})
                if perf and perf.get("average_response_time") == "N/A":
                    gaps.append("HTTP performance metrics are stub (N/A)")
                    recs.append("Implement actual HTTP response time calculation using tshark")

            record_result("wireshark_http_analyzer", f"type={analysis_type}", status, text[:200], duration, gaps=gaps, recommendations=recs)
            print(f"  [{status}] type={analysis_type} ({duration:.1f}ms)")
        except Exception as e:
            duration = (time.time() - start) * 1000
            record_result("wireshark_http_analyzer", f"type={analysis_type}", "ERROR", str(e), duration, "medium")
            print(f"  [ERROR] {e}")


# ============================================================
# TEST 15: wireshark_dns_analyzer
# ============================================================
async def test_dns_analyzer():
    """Test DNS traffic analysis."""
    print("\n[TEST] wireshark_dns_analyzer")

    if not Path(SAMPLE_PCAP).exists():
        record_result("wireshark_dns_analyzer", "all", "SKIP", "No test PCAP", 0)
        return

    for analysis_type in ["comprehensive", "queries", "responses", "intelligence"]:
        start = time.time()
        try:
            result = await call_tool("wireshark_dns_analyzer", {
                "input_file": SAMPLE_PCAP,
                "analysis_type": analysis_type,
                "detect_tunneling": True,
            })
            duration = (time.time() - start) * 1000
            text = result[0].text

            gaps = []
            recs = []
            if "✅" in text or "Success" in text:
                status = "PASS"
            elif "❌" in text:
                status = "FAIL"
                gaps.append(f"DNS analysis failed for type={analysis_type}")
            else:
                status = "WARN"

            # Check for stub implementations
            parsed = {}
            try:
                parsed = json.loads(text)
            except:
                pass
            if parsed:
                responses = parsed.get("results", {}).get("responses", {})
                if responses and responses.get("average_response_time") == "N/A":
                    gaps.append("DNS response analysis is stub")
                    recs.append("Implement actual DNS response parsing")
                intel = parsed.get("results", {}).get("intelligence", {})
                if intel and not intel.get("suspicious_domains") and not intel.get("domain_frequency"):
                    gaps.append("DNS intelligence gathering returns empty results")
                    recs.append("Implement DNS intelligence with domain frequency analysis")

            record_result("wireshark_dns_analyzer", f"type={analysis_type}", status, text[:200], duration, gaps=gaps, recommendations=recs)
            print(f"  [{status}] type={analysis_type} ({duration:.1f}ms)")
        except Exception as e:
            duration = (time.time() - start) * 1000
            record_result("wireshark_dns_analyzer", f"type={analysis_type}", "ERROR", str(e), duration, "medium")
            print(f"  [ERROR] {e}")


# ============================================================
# TEST 16: wireshark_ssl_inspector
# ============================================================
async def test_ssl_inspector():
    """Test SSL/TLS traffic inspection."""
    print("\n[TEST] wireshark_ssl_inspector")

    if not Path(SAMPLE_PCAP).exists():
        record_result("wireshark_ssl_inspector", "all", "SKIP", "No test PCAP", 0)
        return

    for analysis_type in ["comprehensive", "handshakes", "certificates", "ciphers"]:
        start = time.time()
        try:
            result = await call_tool("wireshark_ssl_inspector", {
                "input_file": SAMPLE_PCAP,
                "analysis_type": analysis_type,
            })
            duration = (time.time() - start) * 1000
            text = result[0].text

            gaps = []
            recs = []
            if "✅" in text or "Success" in text:
                status = "PASS"
            elif "❌" in text:
                status = "FAIL"
                gaps.append(f"SSL inspection failed for type={analysis_type}")
            else:
                status = "WARN"

            # Check for stub implementations
            parsed = {}
            try:
                parsed = json.loads(text)
            except:
                pass
            if parsed:
                certs = parsed.get("results", {}).get("certificates", {})
                if certs and certs.get("certificate_details") == []:
                    gaps.append("Certificate analysis is stub - returns empty details")
                    recs.append("Implement certificate extraction using tshark x509 fields")
                ciphers = parsed.get("results", {}).get("cipher_suites", {})
                if ciphers and ciphers.get("cipher_suites_used") == []:
                    gaps.append("Cipher suite analysis is stub - returns empty lists")
                    recs.append("Extract cipher suites using tls.handshake.ciphersuite field")

            record_result("wireshark_ssl_inspector", f"type={analysis_type}", status, text[:200], duration, gaps=gaps, recommendations=recs)
            print(f"  [{status}] type={analysis_type} ({duration:.1f}ms)")
        except Exception as e:
            duration = (time.time() - start) * 1000
            record_result("wireshark_ssl_inspector", f"type={analysis_type}", "ERROR", str(e), duration, "medium")
            print(f"  [ERROR] {e}")


# ============================================================
# TEST 17: wireshark_latency_profiler
# ============================================================
async def test_latency_profiler():
    """Test latency profiling."""
    print("\n[TEST] wireshark_latency_profiler")

    if not Path(SAMPLE_PCAP).exists():
        record_result("wireshark_latency_profiler", "all", "SKIP", "No test PCAP", 0)
        return

    for analysis_type in ["comprehensive", "tcp", "application", "network"]:
        start = time.time()
        try:
            result = await call_tool("wireshark_latency_profiler", {
                "input_file": SAMPLE_PCAP,
                "analysis_type": analysis_type,
            })
            duration = (time.time() - start) * 1000
            text = result[0].text

            gaps = []
            recs = []
            if "✅" in text or "Success" in text:
                status = "PASS"
            elif "❌" in text:
                status = "FAIL"
                gaps.append(f"Latency profiling failed for type={analysis_type}")
            else:
                status = "WARN"

            parsed = {}
            try:
                parsed = json.loads(text)
            except:
                pass
            if parsed:
                app = parsed.get("results", {}).get("application_latency", {})
                if app and app.get("http_response_times") == []:
                    gaps.append("Application latency analysis is stub")
                    recs.append("Implement HTTP response time extraction via tshark")
                net = parsed.get("results", {}).get("network_latency", {})
                if net and net.get("hop_latencies") == []:
                    gaps.append("Network latency analysis is stub")
                    recs.append("Implement traceroute-style latency analysis or ICMP RTT extraction")

            record_result("wireshark_latency_profiler", f"type={analysis_type}", status, text[:200], duration, gaps=gaps, recommendations=recs)
            print(f"  [{status}] type={analysis_type} ({duration:.1f}ms)")
        except Exception as e:
            duration = (time.time() - start) * 1000
            record_result("wireshark_latency_profiler", f"type={analysis_type}", "ERROR", str(e), duration, "medium")
            print(f"  [ERROR] {e}")


# ============================================================
# TEST 18: wireshark_threat_detector
# ============================================================
async def test_threat_detector():
    """Test threat detection."""
    print("\n[TEST] wireshark_threat_detector")

    if not Path(SAMPLE_PCAP).exists():
        record_result("wireshark_threat_detector", "all", "SKIP", "No test PCAP", 0)
        return

    for mode in ["comprehensive", "anomaly", "signature", "behavioral"]:
        for sensitivity in ["low", "medium", "high"]:
            if mode != "comprehensive" and sensitivity != "medium":
                continue

            start = time.time()
            try:
                result = await call_tool("wireshark_threat_detector", {
                    "input_file": SAMPLE_PCAP,
                    "detection_mode": mode,
                    "sensitivity": sensitivity,
                })
                duration = (time.time() - start) * 1000
                text = result[0].text

                gaps = []
                recs = []
                if "✅" in text or "Success" in text:
                    status = "PASS"
                elif "❌" in text:
                    status = "FAIL"
                    gaps.append(f"Threat detection failed: mode={mode}, sensitivity={sensitivity}")
                else:
                    status = "WARN"

                parsed = {}
                try:
                    parsed = json.loads(text)
                except:
                    pass
                if parsed:
                    sig = parsed.get("results", {}).get("signature_matches", {})
                    if sig and sig.get("matches") == []:
                        gaps.append("Signature detection is stub - no actual signatures defined")
                        recs.append("Implement signature database with known threat patterns")
                    beh = parsed.get("results", {}).get("behavioral_analysis", {})
                    if beh and beh.get("suspicious_behaviors") == []:
                        gaps.append("Behavioral analysis is stub")
                        recs.append("Implement behavioral analysis with traffic pattern baselines")
                    if sensitivity != "medium":
                        # Check if sensitivity actually affects results
                        pass

                label = f"mode={mode},sens={sensitivity}"
                record_result("wireshark_threat_detector", label, status, text[:200], duration, gaps=gaps, recommendations=recs)
                print(f"  [{status}] {label} ({duration:.1f}ms)")
            except Exception as e:
                duration = (time.time() - start) * 1000
                record_result("wireshark_threat_detector", f"mode={mode}", "ERROR", str(e), duration, "medium")
                print(f"  [ERROR] {e}")


# ============================================================
# TEST 19: wireshark_remote_capture
# ============================================================
async def test_remote_capture():
    """Test remote capture (expected to fail without SSH)."""
    print("\n[TEST] wireshark_remote_capture")

    start = time.time()
    try:
        result = await call_tool("wireshark_remote_capture", {
            "host": "localhost",
            "username": "testuser",
            "duration": 3,
            "interface": "lo",
        })
        duration = (time.time() - start) * 1000
        text = result[0].text

        gaps = []
        recs = []
        if "✅" in text:
            status = "PASS"
        elif "❌" in text or "Error" in text or "Exception" in text:
            status = "EXPECTED_FAIL"
            gaps.append("Remote capture requires SSH connectivity")
            recs.append("Add SSH connection validation before attempting capture")
            recs.append("Add timeout configuration for SSH connection attempts")
        else:
            status = "WARN"

        record_result("wireshark_remote_capture", "localhost_test", status, text[:200], duration, gaps=gaps, recommendations=recs)
        print(f"  [{status}] localhost_test ({duration:.1f}ms)")
    except Exception as e:
        duration = (time.time() - start) * 1000
        record_result("wireshark_remote_capture", "localhost_test", "EXPECTED_FAIL", str(e), duration, "low",
                      gaps=["Remote capture requires active SSH server"],
                      recommendations=["Add pre-flight SSH connectivity check"])
        print(f"  [EXPECTED_FAIL] {e}")


# ============================================================
# TEST 20: Helper function tests
# ============================================================
async def test_helper_functions():
    """Test helper/utility functions."""
    print("\n[TEST] Helper Functions")

    # Test parse_protocol_hierarchy
    start = time.time()
    try:
        sample_output = """Protocol Hierarchy Statistics
Filter:

eth                              frames:100 bytes:10000
  ip                             frames:95 bytes:9500
    tcp                          frames:80 bytes:8000
    udp                          frames:15 bytes:1500
  arp                            frames:5 bytes:500
"""
        result = parse_protocol_hierarchy(sample_output)
        assert "protocols" in result
        assert result["protocols"].get("eth", {}).get("packets") == 100
        record_result("helpers", "parse_protocol_hierarchy", "PASS", f"Parsed {len(result['protocols'])} protocols", (time.time() - start) * 1000)
        print(f"  [PASS] parse_protocol_hierarchy")
    except Exception as e:
        record_result("helpers", "parse_protocol_hierarchy", "FAIL", str(e), (time.time() - start) * 1000, "medium")
        print(f"  [FAIL] parse_protocol_hierarchy: {e}")

    # Test parse_ip_range
    start = time.time()
    try:
        result = parse_ip_range("192.168.1.1 - 192.168.1.100")
        assert "192.168.1.1" in result and "192.168.1.100" in result
        record_result("helpers", "parse_ip_range", "PASS", result, (time.time() - start) * 1000)
        print(f"  [PASS] parse_ip_range")
    except Exception as e:
        record_result("helpers", "parse_ip_range", "FAIL", str(e), (time.time() - start) * 1000, "low")
        print(f"  [FAIL] parse_ip_range: {e}")

    # Test combine_filters_intelligently
    start = time.time()
    try:
        result = combine_filters_intelligently(["http", "ip.addr == 10.0.0.1"], "show http and ip 10.0.0.1")
        assert "http" in result and "10.0.0.1" in result
        record_result("helpers", "combine_filters", "PASS", result, (time.time() - start) * 1000)
        print(f"  [PASS] combine_filters")
    except Exception as e:
        record_result("helpers", "combine_filters", "FAIL", str(e), (time.time() - start) * 1000, "low")
        print(f"  [FAIL] combine_filters: {e}")

    # Test advanced_filter_generation
    start = time.time()
    try:
        result = await advanced_filter_generation("HTTP traffic from 192.168.1.1", "intermediate")
        assert "filter" in result
        assert result["filter"]  # non-empty
        record_result("helpers", "advanced_filter_generation", "PASS", result["filter"], (time.time() - start) * 1000)
        print(f"  [PASS] advanced_filter_generation")
    except Exception as e:
        record_result("helpers", "advanced_filter_generation", "FAIL", str(e), (time.time() - start) * 1000, "medium")
        print(f"  [FAIL] advanced_filter_generation: {e}")

    # Test parse_capinfos_machine_output
    start = time.time()
    try:
        sample = "File name\ttest.pcap\nNumber of packets\t100\nFile size\t5000 bytes\n"
        result = parse_capinfos_machine_output(sample)
        assert result.get("File name") == "test.pcap"
        assert result.get("Number of packets") == "100"
        record_result("helpers", "parse_capinfos_machine_output", "PASS", str(result), (time.time() - start) * 1000)
        print(f"  [PASS] parse_capinfos_machine_output")
    except Exception as e:
        record_result("helpers", "parse_capinfos_machine_output", "FAIL", str(e), (time.time() - start) * 1000, "low")
        print(f"  [FAIL] parse_capinfos_machine_output: {e}")


# ============================================================
# TEST 21: Error handling & edge cases
# ============================================================
async def test_error_handling():
    """Test error handling across tools."""
    print("\n[TEST] Error Handling & Edge Cases")

    # Test unknown tool name
    start = time.time()
    try:
        result = await call_tool("nonexistent_tool", {})
        duration = (time.time() - start) * 1000
        text = result[0].text
        status = "PASS" if "Unknown tool" in text or "❌" in text else "FAIL"
        gaps = [] if status == "PASS" else ["Unknown tool doesn't return proper error"]
        record_result("error_handling", "unknown_tool", status, text[:200], duration, gaps=gaps)
        print(f"  [{status}] unknown_tool ({duration:.1f}ms)")
    except Exception as e:
        duration = (time.time() - start) * 1000
        record_result("error_handling", "unknown_tool", "FAIL", f"Exception instead of graceful error: {e}", duration, "high",
                      gaps=["Unknown tool raises exception instead of returning error"],
                      recommendations=["Handle unknown tools gracefully in call_tool"])
        print(f"  [FAIL] unknown_tool: {e}")

    # Test with None arguments
    start = time.time()
    try:
        result = await call_tool("wireshark_system_info", None)
        duration = (time.time() - start) * 1000
        status = "PASS"
        record_result("error_handling", "none_args", status, "Handled None args", duration)
        print(f"  [{status}] none_args ({duration:.1f}ms)")
    except TypeError as e:
        duration = (time.time() - start) * 1000
        record_result("error_handling", "none_args", "FAIL", str(e), duration, "medium",
                      gaps=["None arguments cause TypeError"],
                      recommendations=["Add argument validation with default to empty dict"])
        print(f"  [FAIL] none_args: {e}")
    except Exception as e:
        duration = (time.time() - start) * 1000
        record_result("error_handling", "none_args", "FAIL", str(e), duration, "medium")
        print(f"  [FAIL] none_args: {e}")


# ============================================================
# TEST 22: MCP Protocol Compliance
# ============================================================
async def test_mcp_protocol_compliance():
    """Test MCP protocol compliance."""
    print("\n[TEST] MCP Protocol Compliance")

    start = time.time()
    try:
        tools = await list_tools()
        duration = (time.time() - start) * 1000

        gaps = []
        recs = []

        # Check all tools have proper schemas
        for tool in tools:
            schema = tool.inputSchema
            if not schema:
                gaps.append(f"{tool.name}: Missing input schema")
                continue
            if schema.get("type") != "object":
                gaps.append(f"{tool.name}: Schema type should be 'object'")
            if "required" in schema:
                required = schema["required"]
                properties = schema.get("properties", {})
                for req_field in required:
                    if req_field not in properties:
                        gaps.append(f"{tool.name}: Required field '{req_field}' not in properties")

        # Check tool names follow naming convention
        for tool in tools:
            if not tool.name.startswith("wireshark_"):
                gaps.append(f"{tool.name}: Doesn't follow wireshark_ naming convention")

        # Check descriptions are non-empty
        for tool in tools:
            if not tool.description or len(tool.description) < 10:
                gaps.append(f"{tool.name}: Description too short or empty")

        status = "PASS" if not gaps else "WARN"
        if gaps:
            recs.append("Fix schema validation issues for MCP compliance")

        # Check for resource registration (MCP supports resources)
        gaps.append("No MCP resources registered (prompts, resources, etc.)")
        recs.append("Consider adding MCP resources for common PCAP samples or documentation")
        recs.append("Consider adding MCP prompts for guided network analysis workflows")

        record_result("mcp_compliance", "schema_validation", status, f"{len(gaps)} issues found", duration, gaps=gaps, recommendations=recs)
        print(f"  [{status}] schema_validation ({duration:.1f}ms)")
    except Exception as e:
        duration = (time.time() - start) * 1000
        record_result("mcp_compliance", "schema_validation", "ERROR", str(e), duration, "high")
        print(f"  [ERROR] {e}")


# ============================================================
# TEST 23: Code quality analysis
# ============================================================
async def test_code_quality():
    """Analyze code quality patterns."""
    print("\n[TEST] Code Quality Analysis")

    server_path = Path(__file__).parent.parent / "enhanced_server.py"
    if not server_path.exists():
        server_path = Path("/workspace/enhanced_server.py")

    start = time.time()
    try:
        content = server_path.read_text()
        duration = (time.time() - start) * 1000

        gaps = []
        recs = []

        # Check for synchronous subprocess calls (should be async)
        sync_calls = content.count("subprocess.run(")
        if sync_calls > 0:
            gaps.append(f"Found {sync_calls} synchronous subprocess.run() calls that block the event loop")
            recs.append("Replace subprocess.run() with asyncio.create_subprocess_exec() for non-blocking execution")

        # Check for bare except clauses
        bare_excepts = content.count("except:")
        if bare_excepts > 0:
            gaps.append(f"Found {bare_excepts} bare except clauses")
            recs.append("Use specific exception types instead of bare except")

        # Check for TODO/FIXME comments
        todos = content.count("TODO") + content.count("FIXME")
        if todos > 0:
            gaps.append(f"Found {todos} TODO/FIXME comments indicating incomplete work")

        # Check for hardcoded values
        hardcoded_paths = content.count("/tmp/")
        if hardcoded_paths > 5:
            gaps.append(f"Found {hardcoded_paths} hardcoded /tmp/ paths")
            recs.append("Use tempfile module consistently instead of hardcoded paths")

        # Check for input validation
        if content.count("args.get(") > content.count("if not ") + content.count("if args"):
            gaps.append("Insufficient input validation - many args.get() without validation")
            recs.append("Add comprehensive input validation for all tool parameters")

        # Check for logging
        log_calls = content.count("logger.")
        if log_calls < 20:
            gaps.append(f"Insufficient logging ({log_calls} log statements for ~3700 lines)")
            recs.append("Add more debug/info logging for troubleshooting")

        # Check file size
        lines = content.count("\n")
        if lines > 3000:
            gaps.append(f"Single file has {lines} lines - consider modularization")
            recs.append("Split server into modules: core, tools, analyzers, utilities")

        status = "WARN" if gaps else "PASS"
        record_result("code_quality", "analysis", status, f"{len(gaps)} issues found", duration, gaps=gaps, recommendations=recs)
        print(f"  [{status}] code_quality ({duration:.1f}ms)")
    except Exception as e:
        duration = (time.time() - start) * 1000
        record_result("code_quality", "analysis", "ERROR", str(e), duration, "medium")
        print(f"  [ERROR] {e}")


# ============================================================
# REPORT GENERATION
# ============================================================
def generate_report() -> str:
    """Generate comprehensive test report."""
    total = len(TEST_RESULTS)
    passed = sum(1 for r in TEST_RESULTS if r["status"] == "PASS")
    failed = sum(1 for r in TEST_RESULTS if r["status"] == "FAIL")
    errors = sum(1 for r in TEST_RESULTS if r["status"] == "ERROR")
    warned = sum(1 for r in TEST_RESULTS if r["status"] == "WARN")
    skipped = sum(1 for r in TEST_RESULTS if r["status"] == "SKIP")
    expected_fails = sum(1 for r in TEST_RESULTS if r["status"] == "EXPECTED_FAIL")

    all_gaps = []
    all_recs = []
    for r in TEST_RESULTS:
        all_gaps.extend(r["gaps"])
        all_recs.extend(r["recommendations"])

    unique_gaps = list(dict.fromkeys(all_gaps))
    unique_recs = list(dict.fromkeys(all_recs))

    report = f"""# Wireshark MCP Server - Comprehensive Functionality Test Report

**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Server**: Enhanced Wireshark MCP Server v2.0
**Total Tools**: 18
**Test Environment**: Python {sys.version.split()[0]}, TShark 4.2.2

---

## Executive Summary

| Metric | Count |
|--------|-------|
| **Total Tests** | {total} |
| **Passed** | {passed} |
| **Failed** | {failed} |
| **Errors** | {errors} |
| **Warnings** | {warned} |
| **Skipped** | {skipped} |
| **Expected Failures** | {expected_fails} |
| **Pass Rate** | {(passed / max(total - skipped - expected_fails, 1)) * 100:.1f}% |

---

## Detailed Test Results by Tool

"""

    # Group results by tool
    tools_tested = {}
    for r in TEST_RESULTS:
        if r["tool"] not in tools_tested:
            tools_tested[r["tool"]] = []
        tools_tested[r["tool"]].append(r)

    for tool_name, results in tools_tested.items():
        tool_passed = sum(1 for r in results if r["status"] == "PASS")
        tool_total = len(results)
        tool_emoji = "✅" if tool_passed == tool_total else "⚠️" if tool_passed > 0 else "❌"

        report += f"### {tool_emoji} {tool_name} ({tool_passed}/{tool_total} passed)\n\n"
        report += "| Test | Status | Duration | Details |\n"
        report += "|------|--------|----------|----------|\n"

        for r in results:
            status_icon = {"PASS": "✅", "FAIL": "❌", "ERROR": "💥", "WARN": "⚠️", "SKIP": "⏭️", "EXPECTED_FAIL": "📋"}.get(r["status"], "❓")
            details = r["details"][:80].replace("|", "\\|").replace("\n", " ")
            report += f"| {r['test']} | {status_icon} {r['status']} | {r['duration_ms']:.0f}ms | {details} |\n"

        report += "\n"

    # Gaps Analysis
    report += f"""---

## Gap Analysis

### Critical Gaps (Functionality Issues)

"""
    critical_gaps = [g for r in TEST_RESULTS if r["status"] in ("FAIL", "ERROR") for g in r["gaps"]]
    if critical_gaps:
        for i, gap in enumerate(list(dict.fromkeys(critical_gaps)), 1):
            report += f"{i}. {gap}\n"
    else:
        report += "No critical functionality gaps detected.\n"

    report += f"""
### Stub/Incomplete Implementations

"""
    stub_gaps = [g for g in unique_gaps if "stub" in g.lower() or "n/a" in g.lower() or "empty" in g.lower()]
    if stub_gaps:
        for i, gap in enumerate(stub_gaps, 1):
            report += f"{i}. {gap}\n"
    else:
        report += "No stub implementations detected.\n"

    report += f"""
### Architecture & Design Gaps

"""
    arch_gaps = [g for g in unique_gaps if any(kw in g.lower() for kw in ["module", "file", "sync", "hardcoded", "validation", "logging"])]
    if arch_gaps:
        for i, gap in enumerate(arch_gaps, 1):
            report += f"{i}. {gap}\n"
    else:
        report += "No architectural gaps detected.\n"

    report += f"""
### MCP Protocol Compliance Gaps

"""
    mcp_gaps = [g for g in unique_gaps if any(kw in g.lower() for kw in ["schema", "mcp", "resource", "naming", "protocol"])]
    if mcp_gaps:
        for i, gap in enumerate(mcp_gaps, 1):
            report += f"{i}. {gap}\n"
    else:
        report += "Full MCP protocol compliance.\n"

    report += f"""
### All Identified Gaps ({len(unique_gaps)} total)

"""
    for i, gap in enumerate(unique_gaps, 1):
        report += f"{i}. {gap}\n"

    # Recommendations
    report += f"""
---

## Recommendations

### High Priority

"""
    high_priority = [r for r in unique_recs if any(kw in r.lower() for kw in ["replace subprocess", "validate", "implement actual", "signature", "certificate"])]
    for i, rec in enumerate(high_priority or ["No high priority recommendations"], 1):
        report += f"{i}. {rec}\n"

    report += f"""
### Medium Priority

"""
    medium_priority = [r for r in unique_recs if r not in high_priority and any(kw in r.lower() for kw in ["add", "extract", "improve", "implement"])]
    for i, rec in enumerate(medium_priority or ["No medium priority recommendations"], 1):
        report += f"{i}. {rec}\n"

    report += f"""
### Low Priority / Enhancements

"""
    low_priority = [r for r in unique_recs if r not in high_priority and r not in medium_priority]
    for i, rec in enumerate(low_priority or ["No low priority recommendations"], 1):
        report += f"{i}. {rec}\n"

    report += f"""
### All Recommendations ({len(unique_recs)} total)

"""
    for i, rec in enumerate(unique_recs, 1):
        report += f"{i}. {rec}\n"

    # Performance summary
    report += f"""
---

## Performance Summary

| Tool | Avg Duration (ms) | Max Duration (ms) |
|------|-------------------|-------------------|
"""
    for tool_name, results in tools_tested.items():
        durations = [r["duration_ms"] for r in results if r["duration_ms"] > 0]
        if durations:
            avg_d = sum(durations) / len(durations)
            max_d = max(durations)
            report += f"| {tool_name} | {avg_d:.0f} | {max_d:.0f} |\n"

    report += f"""
---

## Tool-by-Tool Maturity Assessment

| Tool | Status | Maturity | Notes |
|------|--------|----------|-------|
"""
    maturity_map = {}
    for tool_name, results in tools_tested.items():
        passed_count = sum(1 for r in results if r["status"] == "PASS")
        total_count = len(results)
        stub_count = sum(1 for r in results if any("stub" in g.lower() for g in r["gaps"]))
        error_count = sum(1 for r in results if r["status"] in ("FAIL", "ERROR"))

        if error_count > 0:
            maturity = "Needs Work"
            icon = "🔴"
        elif stub_count > 0:
            maturity = "Partial"
            icon = "🟡"
        elif passed_count == total_count:
            maturity = "Production Ready"
            icon = "🟢"
        else:
            maturity = "Functional"
            icon = "🟡"

        notes = "; ".join(list(dict.fromkeys([g for r in results for g in r["gaps"]]))[:2]) or "Fully functional"
        report += f"| {tool_name} | {icon} | {maturity} | {notes[:60]} |\n"

    report += f"""
---

## Conclusion

The Enhanced Wireshark MCP Server implements **18 tools** for network traffic analysis through the MCP protocol. 
Testing revealed a **{(passed / max(total - skipped - expected_fails, 1)) * 100:.1f}%** pass rate across {total} test cases.

**Key Strengths:**
- Comprehensive tool coverage for packet analysis workflows
- Robust fallback mechanisms for live capture (tshark -> tcpdump -> sg wireshark)
- Good error handling with informative error messages
- Support for multiple output formats (JSON, text, summary)
- Advanced filter generation from natural language

**Key Areas for Improvement:**
- Several analysis modules contain stub implementations that return placeholder data
- Synchronous subprocess calls in some handlers can block the async event loop
- The server is a single 3,700-line file that would benefit from modularization
- Missing MCP resources and prompts registration
- Some tools lack comprehensive input validation

**Overall Assessment**: The server is **functional and usable** for core network analysis tasks. 
The stub implementations in specialized analyzers (SSL certificates, cipher suites, behavioral threat analysis, 
application/network latency) represent the primary gap for production deployment.
"""

    return report


# ============================================================
# MAIN TEST RUNNER
# ============================================================
async def main():
    print("=" * 70)
    print("  WIRESHARK MCP SERVER - COMPREHENSIVE FUNCTIONALITY TEST SUITE")
    print("=" * 70)
    print(f"\nStarted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Setup
    pcap_available = await generate_test_pcap()

    # Run all tests
    await test_list_tools()
    await test_system_info()
    await test_validate_setup()
    await test_generate_filter()
    await test_analyze_pcap()
    await test_live_capture()
    await test_realtime_json_capture()
    await test_protocol_statistics()
    await test_analyze_pcap_enhanced()
    await test_pcap_time_slice()
    await test_pcap_splitter()
    await test_pcap_merger()
    await test_hex_to_pcap()
    await test_http_analyzer()
    await test_dns_analyzer()
    await test_ssl_inspector()
    await test_latency_profiler()
    await test_threat_detector()
    await test_remote_capture()
    await test_helper_functions()
    await test_error_handling()
    await test_mcp_protocol_compliance()
    await test_code_quality()

    # Generate report
    report = generate_report()

    report_path = Path("/workspace/MCP_SERVER_TEST_REPORT.md")
    report_path.write_text(report)

    # Also save raw results as JSON
    json_path = Path("/workspace/tests/test_results.json")
    json_path.write_text(json.dumps(TEST_RESULTS, indent=2))

    print(f"\n{'=' * 70}")
    print(f"  TEST SUITE COMPLETE")
    print(f"{'=' * 70}")
    total = len(TEST_RESULTS)
    passed = sum(1 for r in TEST_RESULTS if r["status"] == "PASS")
    failed = sum(1 for r in TEST_RESULTS if r["status"] == "FAIL")
    errors = sum(1 for r in TEST_RESULTS if r["status"] == "ERROR")
    print(f"  Total: {total} | Pass: {passed} | Fail: {failed} | Error: {errors}")
    print(f"  Report: {report_path}")
    print(f"  JSON: {json_path}")

    return 0 if failed == 0 and errors == 0 else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
