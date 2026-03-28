"""Tests for Pydantic models in models/network.py and models/threats.py."""

import pytest
from pydantic import ValidationError

from models.network import (
    ConnectionFlow,
    LogEntry,
    LogParseResult,
    PacketRecord,
    ParseResult,
)
from models.threats import ClassifiedThreat, RuleAlert, ThreatReport


def test_packet_record_valid():
    record = PacketRecord(
        timestamp="2026-03-15T10:00:00",
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=80,
        protocol="TCP",
        size=60,
        tcp_flags=["SYN"],
        payload_size=20,
    )
    assert record.src_ip == "192.168.1.1"
    assert record.dst_port == 80
    assert record.protocol == "TCP"
    assert record.tcp_flags == ["SYN"]
    assert record.payload_size == 20


def test_packet_record_defaults():
    record = PacketRecord(
        timestamp="2026-03-15T10:00:00",
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=80,
        protocol="TCP",
        size=60,
    )
    assert record.tcp_flags == []
    assert record.payload_size == 0


def test_connection_flow_valid():
    flow = ConnectionFlow(
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=80,
        protocol="TCP",
        packet_count=10,
        total_bytes=5000,
        duration_seconds=3.5,
        start_time="2026-03-15T10:00:00",
        end_time="2026-03-15T10:00:03",
    )
    assert flow.packet_count == 10
    assert flow.total_bytes == 5000
    assert flow.duration_seconds == 3.5


def test_parse_result_valid(sample_packets, sample_flows):
    result = ParseResult(
        source_file="capture.pcap",
        file_type="pcap",
        packet_count=len(sample_packets),
        time_range="2026-03-15T10:00:00 \u2013 2026-03-15T10:00:25",
        unique_src_ips=4,
        unique_dst_ips=3,
        protocol_distribution={"TCP": 5, "UDP": 2, "ICMP": 2},
        packets=sample_packets,
        flows=sample_flows,
    )
    assert result.packet_count == 10
    assert result.file_type == "pcap"
    assert result.unique_src_ips == 4


def test_log_entry_valid():
    entry = LogEntry(
        timestamp="Mar 15 10:00:10",
        source_ip="10.99.88.77",
        message="Failed password for root from 10.99.88.77",
        severity="high",
        service="sshd",
        raw_line="Mar 15 10:00:10 server sshd[1235]: Failed password for root",
    )
    assert entry.severity == "high"
    assert entry.service == "sshd"


def test_log_entry_severity_literal():
    with pytest.raises(ValidationError):
        LogEntry(
            timestamp="Mar 15 10:00:10",
            source_ip="10.0.0.1",
            message="test message",
            severity="invalid_level",
        )


def test_log_parse_result_valid(sample_log_entries):
    error_entries = [e for e in sample_log_entries if e.severity == "high"]
    result = LogParseResult(
        source_file="test.log",
        log_format="syslog",
        entry_count=len(sample_log_entries),
        time_range="Mar 15 10:00:01 \u2013 Mar 15 10:00:30",
        entries=sample_log_entries,
        error_entries=error_entries,
    )
    assert result.entry_count == 8
    assert result.log_format == "syslog"
    assert len(result.error_entries) == 3


def test_rule_alert_valid():
    alert = RuleAlert(
        rule_name="SSH_BRUTE_FORCE",
        severity="high",
        category="BRUTE_FORCE",
        description="Multiple SSH login failures detected",
        source_ips=["10.99.88.77"],
        dest_ips=["192.168.1.1"],
        timestamps=["2026-03-15T10:00:10", "2026-03-15T10:00:11"],
        evidence={"failed_attempts": 5},
    )
    assert alert.rule_name == "SSH_BRUTE_FORCE"
    assert alert.severity == "high"
    assert len(alert.timestamps) == 2


def test_rule_alert_severity_literal():
    with pytest.raises(ValidationError):
        RuleAlert(
            rule_name="TEST_RULE",
            severity="extreme",
            category="TEST",
            description="test",
            source_ips=[],
            dest_ips=[],
            timestamps=[],
            evidence={},
        )


def test_classified_threat_severity_bounds():
    with pytest.raises(ValidationError):
        ClassifiedThreat(
            category="PORT_SCAN",
            severity_score=150,
            severity_label="critical",
            title="Port Scan Detected",
            description="Scan across multiple ports",
            source_ips=["10.0.0.1"],
            dest_ips=["192.168.1.0"],
            time_range="2026-03-15T10:00:00 \u2013 2026-03-15T10:05:00",
            evidence={"ports_scanned": 100},
            detection_method="rule",
            recommendations=["Block source IP"],
        )

    with pytest.raises(ValidationError):
        ClassifiedThreat(
            category="PORT_SCAN",
            severity_score=-1,
            severity_label="low",
            title="Port Scan",
            description="test",
            source_ips=[],
            dest_ips=[],
            time_range="",
            evidence={},
            detection_method="rule",
            recommendations=[],
        )


def test_classified_threat_category_literal():
    with pytest.raises(ValidationError):
        ClassifiedThreat(
            category="UNKNOWN_CATEGORY",
            severity_score=50,
            severity_label="medium",
            title="Test Threat",
            description="test",
            source_ips=[],
            dest_ips=[],
            time_range="",
            evidence={},
            detection_method="rule",
            recommendations=[],
        )


def test_threat_report_valid():
    threat = ClassifiedThreat(
        category="PORT_SCAN",
        severity_score=75,
        severity_label="high",
        title="Port Scan Detected",
        description="Sequential port scan from single source",
        source_ips=["10.99.88.77"],
        dest_ips=["192.168.1.1"],
        time_range="2026-03-15T10:00:00 \u2013 2026-03-15T10:05:00",
        evidence={"ports_scanned": 100},
        detection_method="rule",
        recommendations=["Block source IP at firewall"],
    )
    report = ThreatReport(
        total_threats=1,
        critical_count=0,
        high_count=1,
        medium_count=0,
        low_count=0,
        threats=[threat],
        analysis_duration_seconds=2.5,
        packets_analyzed=500,
        time_range_analyzed="2026-03-15T10:00:00 \u2013 2026-03-15T10:05:00",
    )
    assert report.total_threats == 1
    assert report.high_count == 1
    assert len(report.threats) == 1
    assert report.threats[0].severity_score == 75
