import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from wireshark_mcp.server import list_tools, server


def test_tools_registry_contains_expected():
    tools = [t.name for t in (await_list_tools())]
    expected = {
        "wireshark_system_info",
        "wireshark_validate_setup",
        "wireshark_generate_filter",
        "wireshark_live_capture",
        "wireshark_analyze_pcap",
        "wireshark_realtime_json_capture",
        "wireshark_protocol_statistics",
        "wireshark_analyze_pcap_enhanced",
    }
    assert expected.issubset(set(tools))


def await_list_tools():
    # Helper to run the async list_tools without bringing an event loop fixture
    import asyncio

    return asyncio.get_event_loop().run_until_complete(list_tools())