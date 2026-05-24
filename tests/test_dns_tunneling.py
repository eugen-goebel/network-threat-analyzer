"""Tests for the DNS tunneling detection rule."""

import pytest

from models.network import PacketRecord, ParseResult
from rules import dns_tunneling
from agents.rule_engine import RuleEngine


def _dns_packet(
    src_ip: str = "192.168.1.50",
    dst_ip: str = "8.8.8.8",
    timestamp: str = "2026-03-15T10:00:00",
    payload_size: int = 40,
    protocol: str = "DNS",
    dst_port: int = 53,
) -> PacketRecord:
    return PacketRecord(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=44444,
        dst_port=dst_port,
        protocol=protocol,
        size=payload_size + 28,  # rough UDP header overhead
        payload_size=payload_size,
    )


@pytest.fixture
def high_volume_dns_packets():
    """150 DNS queries from one source within 30 seconds — above the volume threshold."""
    return [
        _dns_packet(
            src_ip="10.0.0.99",
            timestamp=f"2026-03-15T10:00:{i // 5:02d}.{(i % 5) * 200000:06d}",
            payload_size=50,
        )
        for i in range(150)
    ]


@pytest.fixture
def oversized_dns_packets():
    """25 large DNS queries from one source — above the size threshold."""
    return [
        _dns_packet(
            src_ip="10.0.0.42",
            timestamp=f"2026-03-15T10:00:{i:02d}",
            payload_size=200,
        )
        for i in range(25)
    ]


@pytest.fixture
def normal_dns_packets():
    """Five small DNS queries — well below any threshold."""
    return [
        _dns_packet(timestamp=f"2026-03-15T10:00:{i*10:02d}", payload_size=40)
        for i in range(5)
    ]


class TestVolumePattern:
    def test_high_volume_triggers_alert(self, high_volume_dns_packets):
        alerts = dns_tunneling.detect(high_volume_dns_packets, flows=[])
        volume_alerts = [a for a in alerts if a.rule_name == "dns_tunneling_volume"]
        assert len(volume_alerts) == 1
        alert = volume_alerts[0]
        assert alert.source_ips == ["10.0.0.99"]
        assert alert.category == "DNS_TUNNELING"
        assert alert.severity == "high"
        assert alert.evidence["queries_in_window"] > 100

    def test_one_alert_per_source(self, high_volume_dns_packets):
        """Detector should not emit a volume alert for every window — one per source."""
        alerts = dns_tunneling.detect(high_volume_dns_packets, flows=[])
        volume_alerts = [a for a in alerts if a.rule_name == "dns_tunneling_volume"]
        assert len(volume_alerts) == 1

    def test_below_threshold_no_alert(self, normal_dns_packets):
        alerts = dns_tunneling.detect(normal_dns_packets, flows=[])
        assert [a for a in alerts if a.rule_name == "dns_tunneling_volume"] == []


class TestOversizedPattern:
    def test_oversized_triggers_alert(self, oversized_dns_packets):
        alerts = dns_tunneling.detect(oversized_dns_packets, flows=[])
        size_alerts = [
            a for a in alerts if a.rule_name == "dns_tunneling_oversized_queries"
        ]
        assert len(size_alerts) == 1
        alert = size_alerts[0]
        assert alert.source_ips == ["10.0.0.42"]
        assert alert.evidence["large_query_count"] == 25
        assert alert.evidence["average_payload_bytes"] == pytest.approx(200.0)

    def test_few_large_queries_below_threshold(self):
        """10 large queries is below the count threshold of 20 — no alert."""
        packets = [
            _dns_packet(
                src_ip="10.0.0.42",
                timestamp=f"2026-03-15T10:00:{i:02d}",
                payload_size=200,
            )
            for i in range(10)
        ]
        alerts = dns_tunneling.detect(packets, flows=[])
        assert [
            a for a in alerts if a.rule_name == "dns_tunneling_oversized_queries"
        ] == []


class TestDetection:
    def test_empty_packets(self):
        assert dns_tunneling.detect([], flows=[]) == []

    def test_dns_detected_by_dst_port_53(self):
        """Even if scapy didn't label the packet 'DNS', port 53 alone should match."""
        packets = [
            _dns_packet(
                src_ip="10.0.0.7",
                timestamp=f"2026-03-15T10:00:{i:02d}",
                payload_size=200,
                protocol="UDP",  # not labelled DNS
                dst_port=53,
            )
            for i in range(25)
        ]
        alerts = dns_tunneling.detect(packets, flows=[])
        assert any(a.rule_name == "dns_tunneling_oversized_queries" for a in alerts)

    def test_non_dns_traffic_ignored(self):
        """HTTP packets on port 80 must not produce DNS tunneling alerts."""
        packets = [
            PacketRecord(
                timestamp=f"2026-03-15T10:00:{i:02d}",
                src_ip="10.0.0.5",
                dst_ip="93.184.216.34",
                src_port=33333,
                dst_port=80,
                protocol="TCP",
                size=200,
                payload_size=180,
            )
            for i in range(200)
        ]
        assert dns_tunneling.detect(packets, flows=[]) == []


class TestRuleEngineIntegration:
    def test_engine_dispatches_to_dns_tunneling(self, oversized_dns_packets):
        parse_result = ParseResult(
            source_file="test.pcap",
            file_type="pcap",
            packet_count=len(oversized_dns_packets),
            time_range="2026-03-15T10:00:00 – 2026-03-15T10:00:24",
            unique_src_ips=1,
            unique_dst_ips=1,
            protocol_distribution={"DNS": len(oversized_dns_packets)},
            packets=oversized_dns_packets,
            flows=[],
        )
        engine = RuleEngine()
        alerts = engine.analyze(parse_result)
        dns_alerts = [a for a in alerts if a.category == "DNS_TUNNELING"]
        assert dns_alerts, "RuleEngine should surface DNS_TUNNELING alerts"
