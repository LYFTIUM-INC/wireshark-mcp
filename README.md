# 🦈 Wireshark MCP Server

> Wireshark MCP server with real-time JSON streaming, protocol statistics, and advanced PCAP analysis.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io/)

## Features
- Core tools: system info, setup validation, filter generation, live capture, PCAP analysis
- Advanced: real-time JSON capture, protocol statistics/conversations/endpoints/IO, enhanced PCAP analysis
- Safe fallbacks for permissions (tcpdump + tshark); optional sg-fallback gated

## Install
```bash
git clone <repo>
cd wireshark-mcp
pip install -r requirements.txt
# or
pip install .
```

System prereqs (Linux):
```bash
sudo apt-get install wireshark-common tshark tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
sudo usermod -a -G wireshark $USER && newgrp wireshark
```

## Run
- CLI entrypoint: `wireshark-mcp-server`
- MCP server module: `python server.py`
- Tool bridge: `python tools_bridge.py --help`

## Tools
- Core:
  - wireshark_system_info, wireshark_validate_setup, wireshark_generate_filter, wireshark_live_capture, wireshark_analyze_pcap
- Advanced analytics:
  - wireshark_realtime_json_capture, wireshark_protocol_statistics, wireshark_analyze_pcap_enhanced, wireshark_export_objects, wireshark_follow_stream
- Blue-team detections:
  - wireshark_detect_port_scans, wireshark_detect_dns_tunneling, wireshark_http_statistics, wireshark_tls_ja3_fingerprints, wireshark_detect_cleartext_credentials
  - wireshark_tls_decrypt_summary, wireshark_tcp_metrics, wireshark_beaconing_exfil_detection, wireshark_ioc_enrichment
  - wireshark_tcp_flow_metrics, wireshark_beaconing_detector, wireshark_dns_anomalies, wireshark_http_exfil_anomalies, wireshark_export_and_hash_objects, wireshark_filter_preset
- Red-team/advanced protocol:
  - wireshark_alpn_quic_summary, wireshark_doh_dot_detection, wireshark_domain_fronting_detection
  - wireshark_quic_spin_rtt_metrics, wireshark_tls_decrypt_sessions, wireshark_tls_ech_detection, wireshark_http_h2_h3_anomalies, wireshark_dns_sequence_anomalies, wireshark_c2_signature_scan, wireshark_ja4_fingerprints

## Integration testing
- Unit tests mock external binaries for speed/determinism: `pytest -q`
- Run real integration tests (require tshark/capinfos):
  ```bash
  INTEGRATION=1 PCAP_PATH=/abs/path/to/sample.pcap pytest -q
  ```

## Environment overrides
- Override binary paths:
  - `TSHARK`, `CAPINFOS`, `TCPDUMP`, `DUMPCAP`
- Capture ring buffer controls: `WIRESHARK_RING_FILES`, `WIRESHARK_RING_MB`
- Gate sg fallback: `WIRESHARK_ENABLE_SG=1`

## Examples
- Real-time JSON capture: via MCP tool `wireshark_realtime_json_capture`
- Protocol statistics: `wireshark_protocol_statistics` with `--analysis_type`
- Enhanced PCAP analysis: `wireshark_analyze_pcap_enhanced` (supports JSON/summary/text)

## Security notes
- Default path uses capability-based `tcpdump` + `tshark` parsing (no root). 
- sg-fallback disabled by default. Enable with `WIRESHARK_ENABLE_SG=1` if needed.

## Development
- Lint/format: `ruff check .`, `black --check .`
- Tests: `pytest -q` (mocks external tools)
- CI: GitHub Actions runs on Python 3.9–3.12

## Structure
- `server.py` – MCP server and tools
- `wireshark_mcp/cli.py` – console script entrypoint
- `tools_bridge.py` – CLI to call tools directly
- `tests/` – unit tests with subprocess mocks
- `src/wireshark_mcp_server.py` – experimental (eBPF/compliance; optional)

## License
MIT (see `LICENSE`).