import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import handle_protocol_statistics, handle_analyze_pcap_enhanced


class FakeProcess:
    def __init__(self, returncode: int, stdout: bytes = b"", stderr: bytes = b""):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr

    async def communicate(self):
        return self._stdout, self._stderr


def make_create_subprocess_exec_mock(sequence):
    async def _create_subprocess_exec(*cmd, **kwargs):
        for matcher, process in sequence:
            if matcher(list(cmd)):
                return process
        return FakeProcess(returncode=1, stdout=b"", stderr=b"error")

    return _create_subprocess_exec


def test_protocol_statistics_io_stats(monkeypatch, tmp_path):
    # Simulate tshark invocations for IO stats
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark"

    io_output = b"IO STATISTICS\nInterval: 1.000 secs\n..."
    fake = FakeProcess(returncode=0, stdout=io_output)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))

    args = {
        "source": str(tmp_path / "dummy.pcap"),
        "analysis_type": "io_stats",
        "protocol": "all",
    }
    result = asyncio.get_event_loop().run_until_complete(handle_protocol_statistics(args))
    assert result and result[0].type == "text"
    assert "io_statistics" in result[0].text


def test_analyze_pcap_enhanced_json_output(monkeypatch, tmp_path):
    # Simulate capinfos and tshark calls
    def is_capinfos(cmd):
        return len(cmd) and cmd[0] == "capinfos"

    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark"

    capinfos_ok = FakeProcess(returncode=0, stdout=b"File type\tpcap\nCapture duration\t10\n")
    tshark_ok = FakeProcess(returncode=0, stdout=b"")

    monkeypatch.setattr(
        asyncio,
        "create_subprocess_exec",
        make_create_subprocess_exec_mock([(is_capinfos, capinfos_ok), (is_tshark, tshark_ok)]),
    )

    # Ensure file path exists for handler validation
    pcap_file = tmp_path / "file.pcap"
    pcap_file.write_bytes(b"\x00\x00")

    args = {
        "filepath": str(pcap_file),
        "analysis_type": "comprehensive",
        "output_format": "json",
        "chunk_size": 1000,
    }
    result = asyncio.get_event_loop().run_until_complete(handle_analyze_pcap_enhanced(args))
    assert result and result[0].type == "text"
    assert "file_info" in result[0].text