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
        "wireshark_export_objects",
        "wireshark_follow_stream",
        "wireshark_detect_port_scans",
        "wireshark_detect_dns_tunneling",
        "wireshark_http_statistics",
        "wireshark_tls_ja3_fingerprints",
        "wireshark_detect_cleartext_credentials",
        "wireshark_tls_decrypt_summary",
        "wireshark_tcp_metrics",
        "wireshark_beaconing_exfil_detection",
        "wireshark_ioc_enrichment",
        "wireshark_tcp_flow_metrics",
        "wireshark_beaconing_detector",
        "wireshark_dns_anomalies",
        "wireshark_http_exfil_anomalies",
        "wireshark_export_and_hash_objects",
        "wireshark_filter_preset",
        "wireshark_alpn_quic_summary",
        "wireshark_doh_dot_detection",
        "wireshark_domain_fronting_detection",
        "wireshark_smb_lateral_detection",
        "wireshark_auth_bruteforce_detection",
        "wireshark_icmp_exfil_detection",
        "wireshark_quic_spin_rtt_metrics",
        "wireshark_tls_decrypt_sessions",
        "wireshark_tls_ech_detection",
        "wireshark_http_h2_h3_anomalies",
        "wireshark_dns_sequence_anomalies",
        "wireshark_c2_signature_scan",
        "wireshark_ja4_fingerprints",
        "wireshark_kerberos_auth_spikes",
        "wireshark_ntlmssp_spikes",
        "wireshark_dcerpc_uuid_hotspots",
    }
    assert expected.issubset(set(tools))


def await_list_tools():
    # Helper to run the async list_tools without bringing an event loop fixture
    import asyncio

    return asyncio.get_event_loop().run_until_complete(list_tools())