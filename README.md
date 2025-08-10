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
  - wireshark_system_info
  - wireshark_validate_setup
  - wireshark_generate_filter
  - wireshark_live_capture
  - wireshark_analyze_pcap
- Advanced:
  - wireshark_realtime_json_capture
  - wireshark_protocol_statistics
  - wireshark_analyze_pcap_enhanced

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