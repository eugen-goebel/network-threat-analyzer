"""Tests for the rule engine — port scans, brute force, suspicious connections."""

import pytest

from agents.rule_engine import RuleEngine
from models.network import (
    ConnectionFlow,
    LogEntry,
    LogParseResult,
    PacketRecord,
    ParseResult,
)


@pytest.fixture
def port_scan_packets():
    """25 TCP SYN packets from one source to one dest, each on a different port."""
    return [
        PacketRecord(
            timestamp=f"2026-03-15T10:00:{i:02d}",
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=40000,
            dst_port=i + 1,
            protocol="TCP",
            size=54,
            tcp_flags=["SYN"],
        )
        for i in range(25)
    ]


@pytest.fixture
def port_scan_flows():
    return [
        ConnectionFlow(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=40000,
            dst_port=i + 1,
            protocol="TCP",
            packet_count=1,
            total_bytes=54,
            duration_seconds=0.0,
            start_time=f"2026-03-15T10:00:{i:02d}",
            end_time=f"2026-03-15T10:00:{i:02d}",
        )
        for i in range(25)
    ]


@pytest.fixture
def port_scan_parse_result(port_scan_packets, port_scan_flows):
    return ParseResult(
        source_file="scan.pcap",
        file_type="pcap",
        packet_count=len(port_scan_packets),
        time_range="2026-03-15T10:00:00 \u2013 2026-03-15T10:00:24",
        unique_src_ips=1,
        unique_dst_ips=1,
        protocol_distribution={"TCP": 25},
        packets=port_scan_packets,
        flows=port_scan_flows,
    )


@pytest.fixture
def brute_force_log_entries():
    """6 failed SSH log entries from the same IP within 60 seconds."""
    return [
        LogEntry(
            timestamp=f"2026-03-15T10:00:{i * 5:02d}",
            source_ip="10.99.88.77",
            message=f"Failed password for root from 10.99.88.77 port {44230 + i} ssh2",
            severity="high",
            service="sshd",
        )
        for i in range(6)
    ]


@pytest.fixture
def brute_force_log_result(brute_force_log_entries):
    return LogParseResult(
        source_file="auth.log",
        log_format="syslog",
        entry_count=len(brute_force_log_entries),
        time_range="2026-03-15T10:00:00 \u2013 2026-03-15T10:00:25",
        entries=brute_force_log_entries,
        error_entries=brute_force_log_entries,
    )


@pytest.fixture
def clean_packets():
    """Normal diverse traffic that should not trigger any alert."""
    return [
        PacketRecord(
            timestamp="2026-03-15T10:00:00",
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            size=1200,
            tcp_flags=["SYN", "ACK"],
        ),
        PacketRecord(
            timestamp="2026-03-15T10:00:05",
            src_ip="192.168.1.20",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=53,
            protocol="UDP",
            size=72,
        ),
        PacketRecord(
            timestamp="2026-03-15T10:00:10",
            src_ip="192.168.1.30",
            dst_ip="10.0.0.1",
            src_port=0,
            dst_port=0,
            protocol="ICMP",
            size=84,
        ),
    ]


@pytest.fixture
def clean_flows():
    return [
        ConnectionFlow(
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            packet_count=1,
            total_bytes=1200,
            duration_seconds=0.0,
            start_time="2026-03-15T10:00:00",
            end_time="2026-03-15T10:00:00",
        ),
        ConnectionFlow(
            src_ip="192.168.1.20",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=53,
            protocol="UDP",
            packet_count=1,
            total_bytes=72,
            duration_seconds=0.0,
            start_time="2026-03-15T10:00:05",
            end_time="2026-03-15T10:00:05",
        ),
    ]


@pytest.fixture
def clean_parse_result(clean_packets, clean_flows):
    return ParseResult(
        source_file="normal.pcap",
        file_type="pcap",
        packet_count=len(clean_packets),
        time_range="2026-03-15T10:00:00 \u2013 2026-03-15T10:00:10",
        unique_src_ips=3,
        unique_dst_ips=2,
        protocol_distribution={"TCP": 1, "UDP": 1, "ICMP": 1},
        packets=clean_packets,
        flows=clean_flows,
    )


@pytest.fixture
def suspicious_port_packets():
    return [
        PacketRecord(
            timestamp="2026-03-15T10:00:00",
            src_ip="192.168.1.50",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=4444,
            protocol="TCP",
            size=200,
            tcp_flags=["SYN", "ACK"],
        ),
    ]


@pytest.fixture
def suspicious_port_flows():
    return [
        ConnectionFlow(
            src_ip="192.168.1.50",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=4444,
            protocol="TCP",
            packet_count=1,
            total_bytes=200,
            duration_seconds=0.0,
            start_time="2026-03-15T10:00:00",
            end_time="2026-03-15T10:00:00",
        ),
    ]


@pytest.fixture
def suspicious_port_parse_result(suspicious_port_packets, suspicious_port_flows):
    return ParseResult(
        source_file="suspicious.pcap",
        file_type="pcap",
        packet_count=1,
        time_range="2026-03-15T10:00:00 \u2013 2026-03-15T10:00:00",
        unique_src_ips=1,
        unique_dst_ips=1,
        protocol_distribution={"TCP": 1},
        packets=suspicious_port_packets,
        flows=suspicious_port_flows,
    )


@pytest.fixture
def beaconing_packets():
    """8 packets at regular 10-second intervals from same source to same dest."""
    return [
        PacketRecord(
            timestamp=f"2026-03-15T10:0{i // 6}:{(i * 10) % 60:02d}",
            src_ip="192.168.1.200",
            dst_ip="203.0.113.99",
            src_port=50000,
            dst_port=443,
            protocol="TCP",
            size=100,
            tcp_flags=["PSH", "ACK"],
        )
        for i in range(8)
    ]


@pytest.fixture
def beaconing_flows():
    return [
        ConnectionFlow(
            src_ip="192.168.1.200",
            dst_ip="203.0.113.99",
            src_port=50000,
            dst_port=443,
            protocol="TCP",
            packet_count=8,
            total_bytes=800,
            duration_seconds=70.0,
            start_time="2026-03-15T10:00:00",
            end_time="2026-03-15T10:01:10",
        ),
    ]


@pytest.fixture
def beaconing_parse_result(beaconing_packets, beaconing_flows):
    return ParseResult(
        source_file="beacon.pcap",
        file_type="pcap",
        packet_count=len(beaconing_packets),
        time_range="2026-03-15T10:00:00 \u2013 2026-03-15T10:01:10",
        unique_src_ips=1,
        unique_dst_ips=1,
        protocol_distribution={"TCP": 8},
        packets=beaconing_packets,
        flows=beaconing_flows,
    )


@pytest.fixture
def engine():
    return RuleEngine()


def test_detect_vertical_port_scan(engine, port_scan_parse_result):
    alerts = engine.analyze(port_scan_parse_result)
    port_scan_alerts = [a for a in alerts if "PORT_SCAN" in a.category]
    assert len(port_scan_alerts) >= 1
    evidence = port_scan_alerts[0].evidence
    assert evidence.get("scan_type") == "vertical" or evidence.get("ports_scanned", 0) >= 20


def test_detect_syn_scan(engine, port_scan_parse_result):
    alerts = engine.analyze(port_scan_parse_result)
    syn_alerts = [
        a for a in alerts
        if a.rule_name == "syn_scan" or (a.category == "PORT_SCAN" and a.evidence.get("scan_type") == "syn")
    ]
    assert len(syn_alerts) >= 1
    assert syn_alerts[0].evidence.get("syn_ratio", 0) > 0.8


def test_detect_ssh_brute_force(engine, port_scan_parse_result, brute_force_log_result):
    alerts = engine.analyze(port_scan_parse_result, log_result=brute_force_log_result)
    bf_alerts = [a for a in alerts if a.category == "BRUTE_FORCE"]
    assert len(bf_alerts) >= 1
    assert bf_alerts[0].rule_name == "ssh_brute_force"


def test_no_alerts_clean_traffic(engine, clean_parse_result):
    alerts = engine.analyze(clean_parse_result)
    assert alerts == []


def test_alert_severity_order(engine, port_scan_parse_result, brute_force_log_result):
    alerts = engine.analyze(port_scan_parse_result, log_result=brute_force_log_result)
    if len(alerts) < 2:
        pytest.skip("Need at least 2 alerts to test ordering")
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for i in range(len(alerts) - 1):
        current = severity_order.get(alerts[i].severity, 99)
        next_val = severity_order.get(alerts[i + 1].severity, 99)
        assert current <= next_val


def test_detect_suspicious_port(engine, suspicious_port_parse_result):
    alerts = engine.analyze(suspicious_port_parse_result)
    suspicious_alerts = [a for a in alerts if a.category == "SUSPICIOUS_CONNECTION"]
    assert len(suspicious_alerts) >= 1
    port_numbers = [a.evidence.get("port") for a in suspicious_alerts]
    assert 4444 in port_numbers


def test_detect_beaconing(engine, beaconing_parse_result):
    alerts = engine.analyze(beaconing_parse_result)
    beacon_alerts = [
        a for a in alerts
        if a.rule_name == "beaconing" or a.evidence.get("detection_type") == "beaconing"
    ]
    assert len(beacon_alerts) >= 1
    assert beacon_alerts[0].evidence.get("std_deviation", 999) < 5


def test_rule_engine_no_logs(engine, port_scan_parse_result):
    alerts = engine.analyze(port_scan_parse_result, log_result=None)
    assert isinstance(alerts, list)


def test_alert_has_evidence(engine, port_scan_parse_result):
    alerts = engine.analyze(port_scan_parse_result)
    assert len(alerts) > 0
    for alert in alerts:
        assert isinstance(alert.evidence, dict)
        assert len(alert.evidence) > 0


def test_alert_has_source_ips(engine, port_scan_parse_result):
    alerts = engine.analyze(port_scan_parse_result)
    assert len(alerts) > 0
    for alert in alerts:
        assert isinstance(alert.source_ips, list)
        assert len(alert.source_ips) > 0
