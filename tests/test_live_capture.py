"""Tests for LiveCaptureAgent — structure and helper methods.

Note: Actual packet capture requires elevated privileges and a network
interface. These tests verify the agent's internal logic using mock packets.
"""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from scapy.all import IP, TCP, UDP, DNS, Ether

from agents.live_capture import LiveCaptureAgent
from models.network import PacketRecord, ParseResult


@pytest.fixture
def agent():
    return LiveCaptureAgent()


@pytest.fixture
def mock_packets():
    """Create a list of mock scapy packets."""
    packets = []

    # TCP SYN packet
    pkt1 = Ether() / IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=12345, dport=80, flags="S")
    pkt1.time = datetime(2025, 1, 15, 10, 0, 0, tzinfo=timezone.utc).timestamp()
    packets.append(pkt1)

    # TCP ACK packet
    pkt2 = Ether() / IP(src="10.0.0.1", dst="192.168.1.10") / TCP(sport=80, dport=12345, flags="A")
    pkt2.time = datetime(2025, 1, 15, 10, 0, 1, tzinfo=timezone.utc).timestamp()
    packets.append(pkt2)

    # UDP packet
    pkt3 = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=5353, dport=53)
    pkt3.time = datetime(2025, 1, 15, 10, 0, 2, tzinfo=timezone.utc).timestamp()
    packets.append(pkt3)

    return packets


class TestPacketProcessing:
    def test_process_tcp_packet(self, agent, mock_packets):
        agent._process_packet(mock_packets[0])
        assert len(agent._records) == 1
        record = agent._records[0]
        assert record.src_ip == "192.168.1.10"
        assert record.dst_ip == "10.0.0.1"
        assert record.src_port == 12345
        assert record.dst_port == 80
        assert record.protocol == "TCP"
        assert "SYN" in record.tcp_flags

    def test_process_udp_packet(self, agent, mock_packets):
        agent._process_packet(mock_packets[2])
        assert len(agent._records) == 1
        record = agent._records[0]
        assert record.protocol == "UDP"
        assert record.dst_port == 53

    def test_process_multiple_packets(self, agent, mock_packets):
        for pkt in mock_packets:
            agent._process_packet(pkt)
        assert len(agent._records) == 3

    def test_stop_event_prevents_processing(self, agent, mock_packets):
        agent._stop_event.set()
        agent._process_packet(mock_packets[0])
        assert len(agent._records) == 0


class TestFlowBuilding:
    def test_builds_flows(self, agent, mock_packets):
        for pkt in mock_packets:
            agent._process_packet(pkt)
        flows = agent._build_flows()
        # 3 packets should form 3 different flows (different src/dst combos)
        assert len(flows) >= 2

    def test_flow_has_correct_fields(self, agent, mock_packets):
        for pkt in mock_packets:
            agent._process_packet(pkt)
        flows = agent._build_flows()
        for flow in flows:
            assert flow.packet_count > 0
            assert flow.total_bytes > 0
            assert flow.protocol in ("TCP", "UDP", "DNS", "ICMP", "OTHER")


class TestProtocolCounting:
    def test_counts_protocols(self, agent, mock_packets):
        for pkt in mock_packets:
            agent._process_packet(pkt)
        dist = agent._count_protocols()
        assert "TCP" in dist
        assert "UDP" in dist
        assert dist["TCP"] == 2
        assert dist["UDP"] == 1


class TestProtocolDetection:
    def test_detect_tcp(self, agent):
        pkt = IP() / TCP()
        assert agent._detect_protocol(pkt) == "TCP"

    def test_detect_udp(self, agent):
        pkt = IP() / UDP()
        assert agent._detect_protocol(pkt) == "UDP"

    def test_detect_dns(self, agent):
        pkt = IP() / UDP() / DNS()
        assert agent._detect_protocol(pkt) == "DNS"


class TestPortExtraction:
    def test_tcp_ports(self, agent):
        pkt = IP() / TCP(sport=1234, dport=443)
        src, dst = agent._extract_ports(pkt)
        assert src == 1234
        assert dst == 443

    def test_udp_ports(self, agent):
        pkt = IP() / UDP(sport=5353, dport=53)
        src, dst = agent._extract_ports(pkt)
        assert src == 5353
        assert dst == 53

    def test_no_ports_for_icmp(self, agent):
        from scapy.all import ICMP
        pkt = IP() / ICMP()
        src, dst = agent._extract_ports(pkt)
        assert src == 0
        assert dst == 0


class TestCaptureParameters:
    def test_duration_clamped_max(self, agent):
        with patch("agents.live_capture.sniff") as mock_sniff:
            mock_sniff.return_value = []
            try:
                agent.capture(duration=999, max_packets=1)
            except ValueError:
                pass
            call_kwargs = mock_sniff.call_args[1]
            assert call_kwargs["timeout"] == 300

    def test_duration_clamped_min(self, agent):
        with patch("agents.live_capture.sniff") as mock_sniff:
            mock_sniff.return_value = []
            try:
                agent.capture(duration=-5, max_packets=1)
            except ValueError:
                pass
            call_kwargs = mock_sniff.call_args[1]
            assert call_kwargs["timeout"] == 1
