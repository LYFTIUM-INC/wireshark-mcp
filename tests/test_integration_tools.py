import asyncio
import json
import os
import shutil
from pathlib import Path
import pytest

INTEGRATION = os.getenv("INTEGRATION", "0") == "1"
PCAP_PATH = os.getenv("PCAP_PATH", "")

requires_integration = pytest.mark.skipif(
    not INTEGRATION,
    reason="Set INTEGRATION=1, TSHARK installed, and PCAP_PATH to run integration tests",
)


def _have_binaries() -> bool:
    return all(shutil.which(b) for b in ["tshark"])


@requires_integration
@pytest.mark.skipif(not _have_binaries(), reason="Wireshark binaries not found")
@pytest.mark.skipif(not PCAP_PATH or not Path(PCAP_PATH).exists(), reason="PCAP_PATH not set or not found")
def test_integration_analyze_and_stats():
    from wireshark_mcp.server import (
        handle_analyze_pcap,
        handle_protocol_statistics,
        handle_http_statistics,
        handle_tls_ja3_fingerprints,
    )

    pcap = PCAP_PATH

    # analyze_pcap
    res = asyncio.get_event_loop().run_until_complete(handle_analyze_pcap({"filepath": pcap}))
    payload = json.loads(res[0].text)
    assert payload["tool"] == "wireshark_analyze_pcap"

    # protocol statistics (quick IO)
    res = asyncio.get_event_loop().run_until_complete(
        handle_protocol_statistics({"source": pcap, "analysis_type": "io_stats"})
    )
    payload = json.loads(res[0].text)
    assert payload["tool"] == "wireshark_protocol_statistics"

    # http statistics (may be empty but should run)
    res = asyncio.get_event_loop().run_until_complete(handle_http_statistics({"filepath": pcap}))
    payload = json.loads(res[0].text)
    assert payload["tool"] == "wireshark_http_statistics"

    # TLS JA3 (may be empty but should run)
    res = asyncio.get_event_loop().run_until_complete(handle_tls_ja3_fingerprints({"filepath": pcap}))
    payload = json.loads(res[0].text)
    assert payload["tool"] == "wireshark_tls_ja3_fingerprints"