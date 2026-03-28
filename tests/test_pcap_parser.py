"""Tests for the PCAP parser agent."""

import pytest

from agents.pcap_parser import PcapParser


@pytest.fixture
def tmp_pcap(tmp_path):
    from scapy.all import IP, TCP, UDP, ICMP, wrpcap
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
