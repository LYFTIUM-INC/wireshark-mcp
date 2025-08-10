import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from wireshark_mcp.server import (
    handle_protocol_statistics,
    handle_analyze_pcap_enhanced,
    handle_system_info,
    handle_validate_setup,
    handle_live_capture,
    handle_analyze_pcap,
)


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
    payload = json.loads(result[0].text)
    assert payload["ok"] is True
    assert payload["tool"] == "wireshark_protocol_statistics"
    assert "io_statistics" in payload["data"]["statistics"]


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
    payload = json.loads(result[0].text)
    assert payload["ok"] is True
    assert payload["tool"] == "wireshark_analyze_pcap_enhanced"
    assert "file_info" in payload["data"]


def test_system_info_minimal(monkeypatch):
    # tshark -D returns two interfaces
    def is_tshark_D(cmd):
        return len(cmd) >= 2 and cmd[0] == "tshark" and cmd[1] == "-D"

    tshark_D = FakeProcess(returncode=0, stdout=b"1. eth0\n2. lo\n")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark_D, tshark_D)]))

    res = asyncio.get_event_loop().run_until_complete(handle_system_info({"info_type": "interfaces"}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert "capture_interfaces" in payload["data"]


def test_validate_setup_probes(monkeypatch):
    # ip link show ok
    def is_ip_link(cmd):
        return len(cmd) >= 2 and cmd[0] == "ip" and cmd[1] == "link"

    ip_ok = FakeProcess(returncode=0, stdout=b"link info")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_ip_link, ip_ok)]))
    res = asyncio.get_event_loop().run_until_complete(handle_validate_setup({}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert "dependencies" in payload["data"]


def test_live_capture_envelope(monkeypatch):
    # tshark success mock in perform_live_capture_enhanced path
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark"

    tshark_ok = FakeProcess(returncode=0, stdout=b"[]")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, tshark_ok)]))

    res = asyncio.get_event_loop().run_until_complete(handle_live_capture({"interface": "lo", "duration": 1, "max_packets": 1}))
    payload = json.loads(res[0].text)
    assert payload["tool"] == "wireshark_live_capture"
    assert "data" in payload


def test_analyze_pcap_envelope(monkeypatch, tmp_path):
    # tshark -z io,phs ok
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark"

    tshark_ok = FakeProcess(returncode=0, stdout=b"ip frames:1 bytes:100")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, tshark_ok)]))

    pcap = tmp_path / "a.pcap"
    pcap.write_bytes(b"\x00\x00")
    res = asyncio.get_event_loop().run_until_complete(handle_analyze_pcap({"filepath": str(pcap)}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert "protocol_hierarchy" in payload["data"]


def test_live_capture_interface_validation(monkeypatch):
    # tshark -D returns eth0 only
    def is_tshark_D(cmd):
        return len(cmd) >= 2 and cmd[0] == "tshark" and cmd[1] == "-D"

    tshark_D = FakeProcess(returncode=0, stdout=b"1. eth0\n")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark_D, tshark_D)]))

    res = asyncio.get_event_loop().run_until_complete(handle_live_capture({"interface": "lo", "duration": 1, "max_packets": 1}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is False
    assert "Unknown interface" in " ".join(payload["diagnostics"]) 


def test_live_capture_quick_triage_and_ring(monkeypatch):
    # tshark direct success
    call_log = []

    async def _create(*cmd, **kwargs):
        call_log.append(list(cmd))
        # Return empty JSON for tshark direct, or success for tcpdump/tshark parse
        if cmd[0] == "tshark":
            return FakeProcess(0, stdout=b"[]")
        return FakeProcess(0, stdout=b"")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _create)
    res = asyncio.get_event_loop().run_until_complete(handle_live_capture({
        "interface": "any", "duration": 5, "max_packets": 1000, "quick_triage": True, "ring_files": 3, "ring_megabytes": 2
    }))
    payload = json.loads(res[0].text)
    assert payload["ok"] in [True, False]  # envelope present
    # Ensure tshark was invoked (with -n)
    assert any(c[0] == "tshark" and "-n" in c for c in call_log)


def test_export_objects(monkeypatch, tmp_path):
    # Mock tshark export writing files by simulating command success
    outputs_dir = tmp_path / "out"
    outputs_dir.mkdir()
    # Pre-create files to simulate export
    (outputs_dir / "file1.bin").write_bytes(b"a")
    (outputs_dir / "file2.bin").write_bytes(b"b")

    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and "--export-objects" in cmd

    fake = FakeProcess(returncode=0, stdout=b"")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))

    # Need a pcap file to exist
    pcap = tmp_path / "a.pcap"
    pcap.write_bytes(b"\x00\x00")

    from wireshark_mcp.server import handle_export_objects
    res = asyncio.get_event_loop().run_until_complete(handle_export_objects({
        "filepath": str(pcap), "protocol": "http", "destination": str(outputs_dir)
    }))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert set(payload["data"]["files"]) >= {"file1.bin", "file2.bin"}


def test_follow_stream(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and "follow," in ",".join(cmd)

    fake_out = b"some stream payload text"
    fake = FakeProcess(returncode=0, stdout=fake_out)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))

    pcap = tmp_path / "b.pcap"
    pcap.write_bytes(b"\x00\x00")

    from wireshark_mcp.server import handle_follow_stream
    res = asyncio.get_event_loop().run_until_complete(handle_follow_stream({
        "filepath": str(pcap), "protocol": "tcp", "stream_index": 0, "bytes_limit": 10
    }))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["bytes"]


def test_detect_port_scans(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and 'tcp.flags.syn==1' in ' '.join(cmd)
    # simulate two syns from same src to two ports
    fake = FakeProcess(0, stdout=b"192.168.1.10\t80\n192.168.1.10\t443\n")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))
    p = tmp_path / "p.pcap"; p.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_detect_port_scans
    res = asyncio.get_event_loop().run_until_complete(handle_detect_port_scans({"filepath": str(p), "syn_threshold": 1, "distinct_ports_threshold": 1}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["suspects"]


def test_detect_dns_tunneling(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and 'dns && dns.qry.name' in ' '.join(cmd)
    fake = FakeProcess(0, stdout=b"verylonglabelverylonglabel.example.com\nshort.com\n")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))
    p = tmp_path / "d.pcap"; p.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_detect_dns_tunneling
    res = asyncio.get_event_loop().run_until_complete(handle_detect_dns_tunneling({"filepath": str(p), "length_threshold": 10, "label_length_threshold": 10}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["suspicious"]


def test_http_statistics(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and 'http' in cmd
    fake = FakeProcess(0, stdout=b"example.com\tGET\t200\nexample.com\tPOST\t404\n")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))
    p = tmp_path / "h.pcap"; p.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_http_statistics
    res = asyncio.get_event_loop().run_until_complete(handle_http_statistics({"filepath": str(p)}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["top_hosts"]


def test_tls_ja3_fingerprints(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and 'tls.handshake' in ' '.join(cmd)
    fake = FakeProcess(0, stdout=b"ja3hash\tja3shash\nja3hash\t\n")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))
    p = tmp_path / "t.pcap"; p.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_tls_ja3_fingerprints
    res = asyncio.get_event_loop().run_until_complete(handle_tls_ja3_fingerprints({"filepath": str(p)}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["ja3"]