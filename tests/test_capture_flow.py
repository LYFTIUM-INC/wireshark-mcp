import asyncio
import json
import os
from pathlib import Path

# Import target
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from server import perform_live_capture_enhanced


class FakeProcess:
    def __init__(self, returncode: int, stdout: bytes = b"", stderr: bytes = b""):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr

    async def communicate(self):
        return self._stdout, self._stderr


def make_create_subprocess_exec_mock(sequence):
    """
    sequence: list of tuples (matcher, process)
    matcher(cmd_list) -> bool indicates which fake process to return
    """

    async def _create_subprocess_exec(*cmd, **kwargs):
        for matcher, process in sequence:
            try:
                if matcher(list(cmd)):
                    return process
            except Exception:
                continue
        # Default: non-zero
        return FakeProcess(returncode=1, stdout=b"", stderr=b"error")

    return _create_subprocess_exec


def test_capture_success_tshark_direct(monkeypatch):
    # Simulate tshark direct success with JSON packet list
    packets = [{"_index": 1}, {"_index": 2}]
    tshark_ok = FakeProcess(returncode=0, stdout=json.dumps(packets).encode())

    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and "-T" in cmd

    monkeypatch.setattr(
        asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, tshark_ok)])
    )

    result = asyncio.get_event_loop().run_until_complete(
        perform_live_capture_enhanced(interface="lo", duration=1, filter_expr="", max_packets=5)
    )
    assert result["status"].startswith("✅")
    assert result["method_used"] == "tshark_direct"
    assert result["packets_captured"] == 2


def test_capture_fallback_tcpdump_then_parse(monkeypatch):
    # First tshark fails, tcpdump returns code 124 (timeout ok), parse tshark returns JSON
    def is_tshark_direct(cmd):
        return len(cmd) and cmd[0] == "tshark" and "-a" in cmd

    def is_tcpdump(cmd):
        return len(cmd) >= 3 and cmd[0] == "timeout" and cmd[2] == "tcpdump"

    def is_tshark_parse(cmd):
        return len(cmd) and cmd[0] == "tshark" and "-r" in cmd

    tshark_fail = FakeProcess(returncode=1, stdout=b"", stderr=b"fail")
    tcpdump_timeout = FakeProcess(returncode=124, stdout=b"", stderr=b"")
    parsed_packets = FakeProcess(returncode=0, stdout=json.dumps([{"p": 1}]).encode())

    monkeypatch.setattr(
        asyncio,
        "create_subprocess_exec",
        make_create_subprocess_exec_mock(
            [
                (is_tshark_direct, tshark_fail),
                (is_tcpdump, tcpdump_timeout),
                (is_tshark_parse, parsed_packets),
            ]
        ),
    )

    result = asyncio.get_event_loop().run_until_complete(
        perform_live_capture_enhanced(interface="lo", duration=1, filter_expr="", max_packets=5)
    )
    assert result["status"].startswith("✅")
    assert result["method_used"].startswith("tcpdump")
    assert result["packets_captured"] == 1


def test_sg_fallback_is_gated_off_by_default(monkeypatch):
    # Ensure env var gating prevents sg invocation
    os.environ.pop("WIRESHARK_ENABLE_SG", None)

    def is_sg(cmd):
        return len(cmd) and cmd[0] == "sg"

    def create_and_fail_if_sg_called(*cmd, **kwargs):
        if is_sg(list(cmd)):
            raise AssertionError("sg fallback should not be called when WIRESHARK_ENABLE_SG is not set")
        return FakeProcess(returncode=1)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_and_fail_if_sg_called)

    # With everything failing, the function should return overall failure without calling sg
    result = asyncio.get_event_loop().run_until_complete(
        perform_live_capture_enhanced(interface="lo", duration=1, filter_expr="", max_packets=1)
    )
    assert result["status"].startswith("❌")