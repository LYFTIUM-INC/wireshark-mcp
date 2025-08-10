import asyncio
import os
import sys
from pathlib import Path

# Add project root to import path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from enhanced_server import advanced_filter_generation, combine_filters_intelligently


def test_combine_filters_and_logic():
    parts = ["tcp", "port 443"]
    combined = combine_filters_intelligently(parts, "http and https")
    assert combined == " and ".join(f"({p})" for p in parts)


def test_combine_filters_or_logic():
    parts = ["tcp", "udp"]
    combined = combine_filters_intelligently(parts, "either tcp or udp")
    assert combined == " or ".join(f"({p})" for p in parts)


def test_advanced_filter_generation_basic_event_loop():
    async def run():
        result = await advanced_filter_generation(
            "capture http traffic from 192.168.1.1 to port 443", "intermediate"
        )
        assert isinstance(result, dict)
        assert result.get("filter")
    asyncio.get_event_loop().run_until_complete(run())