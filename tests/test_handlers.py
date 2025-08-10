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


def test_tls_decrypt_summary(tmp_path):
    keylog = tmp_path / "keys.log"
    keylog.write_text("CLIENT_RANDOM a b\nCLIENT_RANDOM c d\n")
    pcap = tmp_path / "t.pcap"
    pcap.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_tls_decrypt_summary
    res = asyncio.get_event_loop().run_until_complete(handle_tls_decrypt_summary({
        "filepath": str(pcap), "keylog_file": str(keylog)
    }))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["decrypted_flows"] == 2


def test_tcp_metrics(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and "-e" in cmd
    # Provide six lines for six metrics
    fake = FakeProcess(0, stdout=b"1\n2\n3\n4\n5\n6\n")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))
    pcap = tmp_path / "m.pcap"; pcap.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_tcp_metrics
    res = asyncio.get_event_loop().run_until_complete(handle_tcp_metrics({"filepath": str(pcap)}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["retransmissions"] == 1


def test_beaconing_exfil_detection(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and 'tcp.flags.syn==1' in ' '.join(cmd)
    fake = FakeProcess(0, stdout=b"1.2.3.4\t443\t120\n")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))
    pcap = tmp_path / "bex.pcap"; pcap.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_beaconing_exfil_detection
    res = asyncio.get_event_loop().run_until_complete(handle_beaconing_exfil_detection({"filepath": str(pcap), "min_flows": 1}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["outliers"]


def test_ioc_enrichment(tmp_path):
    pcap = tmp_path / "ioc.pcap"; pcap.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_ioc_enrichment
    res = asyncio.get_event_loop().run_until_complete(handle_ioc_enrichment({
        "filepath": str(pcap),
        "domains": ["evil.example"],
        "ip_addresses": ["10.0.0.1"],
        "ja3_hashes": ["abcd"]
    }))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["domains"] == ["evil.example"]


def test_detect_cleartext_credentials(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and '-Y' in cmd
    # Separate lines to populate each column position:
    # http.authorization, ftp.request.command, imap.request, pop.request, telnet
    fake = FakeProcess(0, stdout=(
        b"Basic abc\t\t\t\t\n"      # http_basic
        b"\tUSER\t\t\t\n"            # ftp USER
        b"\t\tLOGIN\t\t\n"           # imap LOGIN
        b"\t\t\t\t1\n"               # telnet
    ))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))
    pcap = tmp_path / "c.pcap"; pcap.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_detect_cleartext_credentials
    res = asyncio.get_event_loop().run_until_complete(handle_detect_cleartext_credentials({"filepath": str(pcap)}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["findings"]["http_basic"] >= 1
    assert payload["data"]["findings"]["ftp"] >= 1
    assert payload["data"]["findings"]["imap_pop"] >= 1
    assert payload["data"]["findings"]["telnet"] >= 1


def test_tcp_flow_metrics(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and 'tcp.stream' in ' '.join(cmd)
    fake = FakeProcess(0, stdout=(
        b"0\t0.01\t\n"
        b"0\t0.02\t1\n"
        b"1\t0.10\t\n"
    ))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))
    pcap = tmp_path / "f.pcap"; pcap.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_tcp_flow_metrics
    res = asyncio.get_event_loop().run_until_complete(handle_tcp_flow_metrics({"filepath": str(pcap), "top_n": 2}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["flows"]


def test_beaconing_detector(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and 'frame.time_relative' in ' '.join(cmd)
    fake = FakeProcess(0, stdout=(
        b"1.1.1.1\t2.2.2.2\t0.0\t60\n"
        b"1.1.1.1\t2.2.2.2\t5.0\t60\n"
        b"1.1.1.1\t2.2.2.2\t10.0\t60\n"
        b"1.1.1.1\t2.2.2.2\t15.0\t60\n"
        b"1.1.1.1\t2.2.2.2\t20.0\t60\n"
    ))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))
    pcap = tmp_path / "b2.pcap"; pcap.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_beaconing_detector
    res = asyncio.get_event_loop().run_until_complete(handle_beaconing_detector({"filepath": str(pcap), "min_events": 5}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["suspects"][0]["regularity"] > 0.5


def test_dns_anomalies(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and 'dns' in ' '.join(cmd)
    fake = FakeProcess(0, stdout=(
        b"rare.tldx\t0\t\n"
        b"abcdabcdabcdabcdabcd.example.com\t0\t\n"  # base-like label
        b"name\t3\t\n"  # NXDOMAIN
        b"foo.com\t0\tverylongtxtpayloadoverfiftycharacters................................\n"
    ))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))
    pcap = tmp_path / "dns.pcap"; pcap.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_dns_anomalies
    res = asyncio.get_event_loop().run_until_complete(handle_dns_anomalies({"filepath": str(pcap)}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["nxdomain"] >= 1
    assert "tldx" in payload["data"]["rare_tlds"]


def test_http_exfil_anomalies(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and 'http.request' in ' '.join(cmd)
    fake = FakeProcess(0, stdout=(
        b"exfil.com\tPOST\t200000\tapplication/octet-stream\t1.0\n"
        b"ok.com\tGET\t10\ttext/html\t2.0\n"
    ))
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))
    pcap = tmp_path / "http.pcap"; pcap.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_http_exfil_anomalies
    res = asyncio.get_event_loop().run_until_complete(handle_http_exfil_anomalies({"filepath": str(pcap), "size_threshold": 100000}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert any(f["host"] == "exfil.com" for f in payload["data"]["findings"]) 


def test_export_and_hash_objects(monkeypatch, tmp_path):
    outdir = tmp_path / "out"; outdir.mkdir()
    # Create files to hash after export
    (outdir / "a.bin").write_bytes(b"A")
    (outdir / "b.bin").write_bytes(b"BB")
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and '--export-objects' in cmd
    fake = FakeProcess(0, stdout=b"")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))
    pcap = tmp_path / "obj.pcap"; pcap.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_export_and_hash_objects
    res = asyncio.get_event_loop().run_until_complete(handle_export_and_hash_objects({
        "filepath": str(pcap), "protocol": "http", "destination": str(outdir)
    }))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert set(payload["data"]["hashes"].keys()) >= {"a.bin", "b.bin"}


def test_filter_preset():
    from wireshark_mcp.server import handle_filter_preset
    res = asyncio.get_event_loop().run_until_complete(handle_filter_preset({"preset": "port_scan"}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert "tcp.flags.syn" in payload["data"]["filter"]


def test_alpn_quic_summary(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and ('tls || quic' in ' '.join(cmd))
    fake = FakeProcess(0, stdout=b"h2\t0x1\texample.com\nhttp/1.1\t\tother.com\n")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))
    p = tmp_path / "q.pcap"; p.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_alpn_quic_summary
    res = asyncio.get_event_loop().run_until_complete(handle_alpn_quic_summary({"filepath": str(p)}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["alpn"]


def test_doh_dot_detection(monkeypatch, tmp_path):
    def matcher(cmd):
        return len(cmd) and cmd[0] == "tshark"
    fake_doh = FakeProcess(0, stdout=b"doh.example\t/dns-query\tapplication/dns-message\n")
    fake_dot = FakeProcess(0, stdout=b"1.1.1.1\tcloudflare-dns.com\n")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(matcher, fake_doh), (matcher, fake_dot)]))
    p = tmp_path / "doh.pcap"; p.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_doh_dot_detection
    res = asyncio.get_event_loop().run_until_complete(handle_doh_dot_detection({"filepath": str(p)}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["doh"] or payload["data"]["dot"]


def test_domain_fronting_detection(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark"
    fake_sni = FakeProcess(0, stdout=b"1\tsni.example\n")
    fake_host = FakeProcess(0, stdout=b"1\thost.example\n")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake_sni), (is_tshark, fake_host)]))
    p = tmp_path / "front.pcap"; p.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_domain_fronting_detection
    res = asyncio.get_event_loop().run_until_complete(handle_domain_fronting_detection({"filepath": str(p)}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert isinstance(payload["data"]["mismatches"], list)


def test_smb_lateral_detection(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and ('smb2' in ' '.join(cmd) or 'smb ' in ' '.join(cmd))
    fake = FakeProcess(0, stdout=b"10.0.0.5\t10.0.0.10\t\n10.0.0.5\t10.0.0.11\t\n")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))
    p = tmp_path / "smb.pcap"; p.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_smb_lateral_detection
    res = asyncio.get_event_loop().run_until_complete(handle_smb_lateral_detection({"filepath": str(p), "distinct_hosts_threshold": 2}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["suspects"]


def test_auth_bruteforce_detection(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and 'tcp.port==' in ' '.join(cmd)
    fake = FakeProcess(0, stdout=b"10.0.0.2\t10.0.0.3\n" * 12)
    # Return same fake for multiple ports
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake), (is_tshark, fake), (is_tshark, fake), (is_tshark, fake)]))
    p = tmp_path / "bf.pcap"; p.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_auth_bruteforce_detection
    res = asyncio.get_event_loop().run_until_complete(handle_auth_bruteforce_detection({"filepath": str(p), "min_attempts": 10}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert any(payload["data"]["suspects"].values())


def test_icmp_exfil_detection(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and 'icmp' in ' '.join(cmd)
    fake = FakeProcess(0, stdout=b"1.1.1.1\t2.2.2.2\t200\n")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))
    p = tmp_path / "icmp.pcap"; p.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_icmp_exfil_detection
    res = asyncio.get_event_loop().run_until_complete(handle_icmp_exfil_detection({"filepath": str(p), "size_threshold": 100}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["hits"]


def test_quic_spin_rtt_metrics(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and 'quic' in ' '.join(cmd)
    # Sequence with spin flips 0->1->0 at fixed intervals
    fake = FakeProcess(0, stdout=b"1.1.1.1\t2.2.2.2\t0.0\t0\n1.1.1.1\t2.2.2.2\t0.05\t1\n1.1.1.1\t2.2.2.2\t0.10\t0\n")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))
    p = tmp_path / "quic.pcap"; p.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_quic_spin_rtt_metrics
    res = asyncio.get_event_loop().run_until_complete(handle_quic_spin_rtt_metrics({"filepath": str(p)}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["flows"][0]["rtt_estimate_ms"] >= 50.0


def test_tls_decrypt_sessions(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and 'tls.keylog_file' in ' '.join(cmd)
    fake = FakeProcess(0, stdout=b"example.com\tja3hash\nexample.com\tja3hash\n")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))
    p = tmp_path / "tls.pcap"; p.write_bytes(b"\x00\x00")
    keylog = tmp_path / "keys.log"; keylog.write_text("CLIENT_RANDOM a b\n")
    from wireshark_mcp.server import handle_tls_decrypt_sessions
    res = asyncio.get_event_loop().run_until_complete(handle_tls_decrypt_sessions({"filepath": str(p), "keylog_file": str(keylog)}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["by_sni"][0][0] == "example.com"


def test_tls_ech_detection(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and 'tls.handshake' in ' '.join(cmd) and 'tls.extension.type' in ' '.join(cmd)
    fake = FakeProcess(0, stdout=b"encrypted_client_hello\nother\n0xfe0d\n")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))
    p = tmp_path / "ech.pcap"; p.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_tls_ech_detection
    res = asyncio.get_event_loop().run_until_complete(handle_tls_ech_detection({"filepath": str(p)}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["ech_suspected"] >= 2


def test_http_h2_h3_anomalies(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and ('http2' in ' '.join(cmd) or 'http3' in ' '.join(cmd))
    fake = FakeProcess(0, stdout=b"h2\ta.example\t\tcurl/8.0\t\t\t/very/long/path" + b"x"*210 + b"\n")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))
    p = tmp_path / "h23.pcap"; p.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_http_h2_h3_anomalies
    res = asyncio.get_event_loop().run_until_complete(handle_http_h2_h3_anomalies({"filepath": str(p), "path_length_threshold": 200}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["anomalies"]


def test_dns_sequence_anomalies(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and 'dns' in ' '.join(cmd) and 'frame.time_relative' in ' '.join(cmd)
    fake = FakeProcess(0, stdout=b"ex.example\t0.00\nex.example\t0.50\nex.example\t0.80\nex.example\t1.20\nex.example\t1.90\n")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))
    p = tmp_path / "dnsseq.pcap"; p.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_dns_sequence_anomalies
    res = asyncio.get_event_loop().run_until_complete(handle_dns_sequence_anomalies({"filepath": str(p), "window_seconds": 2.0, "burst_min": 5}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["bursty_domains"]


def test_c2_signature_scan(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and '-e' in cmd
    fake = FakeProcess(0, stdout=b"Mozilla\t/jquery-3.3.1.min.js\t\n")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))
    p = tmp_path / "c2.pcap"; p.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_c2_signature_scan
    res = asyncio.get_event_loop().run_until_complete(handle_c2_signature_scan({"filepath": str(p)}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["matches"]


def test_ja4_fingerprints(monkeypatch, tmp_path):
    def is_tshark(cmd):
        return len(cmd) and cmd[0] == "tshark" and 'tls.handshake' in ' '.join(cmd) and 'tls.handshake.ja3' in ' '.join(cmd)
    fake = FakeProcess(0, stdout=b"3.3.3.3\t443\tja3hash\n")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", make_create_subprocess_exec_mock([(is_tshark, fake)]))
    p = tmp_path / "ja4.pcap"; p.write_bytes(b"\x00\x00")
    from wireshark_mcp.server import handle_ja4_fingerprints
    res = asyncio.get_event_loop().run_until_complete(handle_ja4_fingerprints({"filepath": str(p)}))
    payload = json.loads(res[0].text)
    assert payload["ok"] is True
    assert payload["data"]["entries"][0]["ja4"].startswith("ja4:")