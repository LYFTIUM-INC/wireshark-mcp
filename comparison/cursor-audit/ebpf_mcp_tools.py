#!/usr/bin/env python3
"""
Mock eBPF MCP Tools for testing cursor audit server
"""

# Mock availability flag
BCC_AVAILABLE = False

# Mock eBPF tools list
EBPF_TOOLS = []

# Mock eBPF functions
async def ebpf_initialize_interface(*args, **kwargs):
    return {
        "success": False,
        "error": "eBPF/BCC not available in test environment",
        "message": "Mock implementation for testing purposes"
    }

async def ebpf_start_high_speed_capture(*args, **kwargs):
    return {"success": False, "error": "eBPF not available"}

async def ebpf_get_performance_stats(*args, **kwargs):
    return {"success": False, "error": "eBPF not available"}

async def ebpf_update_runtime_filters(*args, **kwargs):
    return {"success": False, "error": "eBPF not available"}

async def ebpf_validate_10m_performance(*args, **kwargs):
    return {"success": False, "error": "eBPF not available"}

async def ebpf_stop_capture(*args, **kwargs):
    return {"success": False, "error": "eBPF not available"}

async def ebpf_list_interfaces(*args, **kwargs):
    return {"success": False, "error": "eBPF not available"}