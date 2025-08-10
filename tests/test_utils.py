import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from wireshark_mcp.server import run_tshark_command, handle_generate_filter


class FakeProcess:
    def __init__(self, returncode: int, stdout: bytes = b"", stderr: bytes = b""):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr

    async def communicate(self):
        return self._stdout, self._stderr


def test_run_tshark_command_success(monkeypatch):
    async def create_ok(*cmd, **kwargs):
        return FakeProcess(0, stdout=b"ok", stderr=b"")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_ok)
    cp = asyncio.get_event_loop().run_until_complete(run_tshark_command(["tshark", "--version"]))
    assert cp.returncode == 0
    assert cp.stdout == "ok"


def test_run_tshark_command_failure(monkeypatch):
    async def create_fail(*cmd, **kwargs):
        return FakeProcess(1, stdout=b"", stderr=b"boom")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_fail)
    try:
        asyncio.get_event_loop().run_until_complete(run_tshark_command(["tshark", "--badflag"]))
        assert False, "Expected RuntimeError"
    except RuntimeError as e:
        assert "Command failed" in str(e)


def test_run_tshark_command_timeout(monkeypatch):
    async def wait_for_timeout(coro, timeout):
        raise asyncio.TimeoutError

    monkeypatch.setattr(asyncio, "wait_for", wait_for_timeout)
    try:
        asyncio.get_event_loop().run_until_complete(run_tshark_command(["tshark"]))
        assert False, "Expected RuntimeError"
    except RuntimeError as e:
        assert "timed out" in str(e)


def test_handle_generate_filter_text_output():
    args = {"description": "http traffic from 192.168.1.1", "complexity": "intermediate"}
    res = asyncio.get_event_loop().run_until_complete(handle_generate_filter(args))
    assert res and res[0].type == "text"
    assert "filter" in res[0].text.lower()