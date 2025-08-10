import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from wireshark_mcp.server import (
    list_tools,
    call_tool,
    handle_filter_preset,
    handle_tls_decrypt_sessions,
)


def test_filter_preset_unknown():
    res = asyncio.get_event_loop().run_until_complete(handle_filter_preset({"preset": "does_not_exist"}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is False
    assert "Unknown preset" in " ".join(payload.get("diagnostics", []))


def test_call_tool_unknown():
    res = asyncio.get_event_loop().run_until_complete(call_tool("non_existing_tool", {}))
    assert res and res[0].type == "text"
    assert "Unknown tool" in res[0].text


def test_tls_decrypt_sessions_errors(tmp_path):
    # file not found
    res = asyncio.get_event_loop().run_until_complete(handle_tls_decrypt_sessions({"filepath": str(tmp_path / "x.pcap"), "keylog_file": str(tmp_path / "k.log")}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is False
    # keylog missing
    fake = tmp_path / "ok.pcap"; fake.write_bytes(b"\x00\x00")
    res = asyncio.get_event_loop().run_until_complete(handle_tls_decrypt_sessions({"filepath": str(fake)}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is False


def test_run_tshark_command_env_override(monkeypatch):
    # Ensure env override replaces the binary name passed to create_subprocess_exec
    called = {}

    async def fake_create(*cmd, **kwargs):
        called["cmd0"] = cmd[0]
        class P:
            returncode = 0
            async def communicate(self):
                return b"", b""
        return P()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create)
    os.environ["TSHARK"] = "/usr/bin/custom-tshark"
    from wireshark_mcp.server import run_tshark_command
    asyncio.get_event_loop().run_until_complete(run_tshark_command(["tshark", "--version"], ignore_errors=True))
    assert called.get("cmd0") == "/usr/bin/custom-tshark"


@pytest.mark.asyncio
async def test_list_tools_no_duplicates():
    names = [t.name for t in (await list_tools())]
    assert len(names) == len(set(names))