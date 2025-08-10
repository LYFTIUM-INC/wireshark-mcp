import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from wireshark_mcp.server import (
    parse_protocol_hierarchy,
    parse_conversations,
    parse_endpoints,
    parse_io_statistics,
)


def test_parse_protocol_hierarchy_basic():
    sample = """
Ethernet frames:100 bytes:6400
  ip frames:80 bytes:5600
    tcp frames:60 bytes:4200
    udp frames:20 bytes:1400
  arp frames:20 bytes:800
"""
    stats = parse_protocol_hierarchy(sample)
    assert stats["total_packets"] == 100
    assert "ip" in stats["protocols"]
    assert stats["protocols"]["tcp"]["packets"] == 60


def test_parse_conversations_basic():
    sample = """
================================================================================
  10.0.0.1 12345   <->   10.0.0.2 80     42     6000   0   40     5800
  10.0.0.3 55555   <->   10.0.0.4 22     10     1200   0   12     1400
================================================================================
"""
    conv = parse_conversations(sample)
    assert conv["count"] >= 2
    assert len(conv["conversations"]) >= 2
    first = conv["conversations"][0]
    assert first["address_a"] == "10.0.0.1"


def test_parse_endpoints_basic():
    sample = """
10.0.0.1  100  6400
10.0.0.2  80   5600
fe80::1   5    400
"""
    eps = parse_endpoints(sample)
    assert eps["count"] == 3
    assert eps["top_talkers"][0]["packets"] >= eps["top_talkers"][1]["packets"]


def test_parse_io_statistics_basic():
    sample = """
Interval: 1.000 secs
0.000-1.000      10
1.000-2.000      5
"""
    io = parse_io_statistics(sample)
    assert io["interval_count"] == 2
    assert io["intervals"][0]["packets"] == 10