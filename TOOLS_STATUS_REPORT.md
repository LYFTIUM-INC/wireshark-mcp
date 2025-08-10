# Tools Status Report

- All 8 tools are implemented, registered, and callable via MCP.
- Bridge script: `tools_bridge.py`

## Usage
```bash
# Real-time JSON capture with streaming
python3 tools_bridge.py realtime_json_capture --interface=eth0 --duration=30

# Comprehensive protocol analysis
python3 tools_bridge.py protocol_statistics --source=capture.pcap --analysis_type=all

# Enhanced large file analysis
python3 tools_bridge.py analyze_pcap_enhanced --filepath=large.pcap --analysis_type=security
```

## Notes
- `wireshark_analyze_pcap_enhanced` provides advanced PCAP analysis with JSON/summary/text outputs.
- sg group fallback is disabled by default for safety; enable with `WIRESHARK_ENABLE_SG=1` if required.