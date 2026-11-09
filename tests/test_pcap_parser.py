"""Tests for the PCAP parser agent."""

import pytest

from agents.pcap_parser import PcapParser


@pytest.fixture
def tmp_pcap(tmp_path):
    from scapy.all import ICMP, IP, TCP, UDP, wrpcap

    packets = [
        IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, flags="S"),
        IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, flags="SA"),
        IP(src="192.168.1.2", dst="10.0.0.1") / UDP(sport=54321, dport=53),
        IP(src="10.0.0.1", dst="192.168.1.1") / ICMP(),
        IP(src="192.168.1.3", dst="10.0.0.1") / TCP(sport=11111, dport=443, flags="S"),
    ]
    path = tmp_path / "test.pcap"
    wrpcap(str(path), packets)
    return str(path)


@pytest.fixture
def parser():
    return PcapParser()


def test_parse_packet_count(parser, tmp_pcap):
    result = parser.parse(tmp_pcap)
    assert result.packet_count == 5


def test_parse_protocols(parser, tmp_pcap):
    result = parser.parse(tmp_pcap)
    assert "TCP" in result.protocol_distribution
    assert "UDP" in result.protocol_distribution
    assert "ICMP" in result.protocol_distribution


def test_parse_ip_extraction(parser, tmp_pcap):
    result = parser.parse(tmp_pcap)
    src_ips = {p.src_ip for p in result.packets}
    dst_ips = {p.dst_ip for p in result.packets}
    assert len(src_ips) == 4  # 192.168.1.1, .2, .3 + 10.0.0.1 (ICMP reply)
    assert len(dst_ips) == 2
    assert result.unique_src_ips == 4
    assert result.unique_dst_ips == 2


def test_parse_tcp_flags(parser, tmp_pcap):
    result = parser.parse(tmp_pcap)
    first_packet = result.packets[0]
    assert "SYN" in first_packet.tcp_flags


def test_parse_flows(parser, tmp_pcap):
    result = parser.parse(tmp_pcap)
    assert len(result.flows) >= 3
    flow_keys = {(f.src_ip, f.dst_ip, f.src_port, f.dst_port) for f in result.flows}
    assert ("192.168.1.1", "10.0.0.1", 12345, 80) in flow_keys


def test_parse_file_not_found(parser):
    with pytest.raises(FileNotFoundError):
        parser.parse("/nonexistent/path/to/file.pcap")


def test_parse_time_range(parser, tmp_pcap):
    result = parser.parse(tmp_pcap)
    assert " \u2013 " in result.time_range


# --- packet limit -----------------------------------------------------------


def _write_pcap(path, count):
    from scapy.all import IP, TCP, wrpcap

    packets = [
        IP(src=f"192.168.1.{i % 250 + 1}", dst="10.0.0.1") / TCP(sport=1000 + i, dport=80)
        for i in range(count)
    ]
    wrpcap(str(path), packets)
    return str(path)


def test_parse_stops_at_the_packet_limit_and_says_so(tmp_path):
    # Regression: rdpcap() loaded every packet, so a big upload could exhaust memory.
    path = _write_pcap(tmp_path / "ten.pcap", 10)
    result = PcapParser(max_packets=4).parse(path)
    assert result.packet_count == 4
    assert len(result.packets) == 4
    assert len(result.warnings) == 1
    assert "truncated" in result.warnings[0]
    assert "4" in result.warnings[0]


def test_capture_exactly_at_the_limit_is_not_reported_as_truncated(tmp_path):
    path = _write_pcap(tmp_path / "five.pcap", 5)
    result = PcapParser(max_packets=5).parse(path)
    assert result.packet_count == 5
    assert result.warnings == []


def test_limit_can_be_disabled(tmp_path):
    path = _write_pcap(tmp_path / "ten.pcap", 10)
    result = PcapParser(max_packets=None).parse(path)
    assert result.packet_count == 10
    assert result.warnings == []


def test_default_limit_is_the_module_constant():
    from agents.pcap_parser import MAX_PACKETS

    # Peak memory was measured at this size, raising it needs a new measurement.
    assert PcapParser().max_packets == MAX_PACKETS
    assert 0 < MAX_PACKETS <= 50_000


def test_limit_counts_packets_read_not_only_ip_packets(tmp_path):
    # Non-IP frames cost time and memory too, so they must not bypass the bound.
    from scapy.all import ARP, IP, TCP, Ether, wrpcap

    packets = [Ether() / ARP() for _ in range(3)] + [
        Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP() for _ in range(3)
    ]
    path = tmp_path / "mixed.pcap"
    wrpcap(str(path), packets)
    result = PcapParser(max_packets=4).parse(str(path))
    assert result.packet_count == 1
    assert result.warnings


def test_gzip_compressed_capture_is_bounded_too(tmp_path):
    # scapy opens gzip captures transparently, whatever the file name says,
    # so a small .pcap upload can inflate to a huge capture. The packet limit
    # must stop the reading early.
    import gzip

    raw = _write_pcap(tmp_path / "raw.pcap", 10)
    gz_path = tmp_path / "bomb.pcap"
    with open(raw, "rb") as src, gzip.open(gz_path, "wb") as dst:
        dst.write(src.read())
    result = PcapParser(max_packets=3).parse(str(gz_path))
    assert result.packet_count == 3
    assert result.warnings


def test_cli_orchestrator_keeps_the_whole_capture(monkeypatch, tmp_pcap):
    # The CLI reads trusted local files, so it must not cut them at the web limit.
    from agents import orchestrator

    seen = []

    class SpyParser(PcapParser):
        def __init__(self, max_packets=-1):
            seen.append(max_packets)
            super().__init__(max_packets)

        def parse(self, filepath):
            raise RuntimeError("stop after construction")

    monkeypatch.setattr(orchestrator, "PcapParser", SpyParser)
    with pytest.raises(RuntimeError, match="stop after construction"):
        orchestrator.ThreatAnalysisOrchestrator().run([tmp_pcap])
    assert seen == [None]
