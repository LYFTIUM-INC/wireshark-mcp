import asyncio
import json
from pathlib import Path


def test_generate_filter_integration():
    from wireshark_mcp.server import handle_generate_filter
    res = asyncio.get_event_loop().run_until_complete(
        handle_generate_filter({"description": "http traffic from 192.168.1.1", "complexity": "intermediate"})
    )
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert "filter" in payload["data"]


def test_filter_preset_integration():
    from wireshark_mcp.server import handle_filter_preset
    res = asyncio.get_event_loop().run_until_complete(handle_filter_preset({"preset": "port_scan"}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert "tcp.flags.syn" in payload["data"]["filter"]


def test_ioc_enrichment_integration(tmp_path):
    fake_pcap = tmp_path / "fake.pcap"
    fake_pcap.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_ioc_enrichment
    res = asyncio.get_event_loop().run_until_complete(
        handle_ioc_enrichment({
            "filepath": str(fake_pcap),
            "domains": ["mal.example"],
            "ip_addresses": ["10.0.0.1"],
            "ja3_hashes": ["abcd"]
        })
    )
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["domains"] == ["mal.example"]


def test_tls_decrypt_summary_integration(tmp_path):
    fake_pcap = tmp_path / "fake2.pcap"
    fake_pcap.write_bytes(b"\x00\x00")
    keylog = tmp_path / "keys.log"
    keylog.write_text("CLIENT_RANDOM a b\nCLIENT_RANDOM c d\n")
    from wireshark_mcp.server import handle_tls_decrypt_summary
    res = asyncio.get_event_loop().run_until_complete(
        handle_tls_decrypt_summary({"filepath": str(fake_pcap), "keylog_file": str(keylog)})
    )
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["decrypted_flows"] == 2


def test_system_info_integration():
    from wireshark_mcp.server import handle_system_info
    res = asyncio.get_event_loop().run_until_complete(handle_system_info({"info_type": "all"}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True


def test_validate_setup_integration():
    from wireshark_mcp.server import handle_validate_setup
    res = asyncio.get_event_loop().run_until_complete(handle_validate_setup({"full_check": False}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True