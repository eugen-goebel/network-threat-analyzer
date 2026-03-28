"""Shared test fixtures for the network-threat-analyzer test suite."""

import os

import pytest

from models.network import (
    ConnectionFlow,
    LogEntry,
    LogParseResult,
    PacketRecord,
    ParseResult,
)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def sample_pcap_path():
    path = os.path.join(PROJECT_ROOT, "data", "sample_capture.pcap")
    if not os.path.exists(path):
        pytest.skip("Sample PCAP not generated yet")
    return path


@pytest.fixture
def sample_syslog_path():
    path = os.path.join(PROJECT_ROOT, "data", "sample_syslog.log")
    if not os.path.exists(path):
        pytest.skip("Sample syslog not generated yet")
    return path


@pytest.fixture
def sample_apache_path():
    path = os.path.join(PROJECT_ROOT, "data", "sample_apache.log")
    if not os.path.exists(path):
        pytest.skip("Sample Apache log not generated yet")
    return path


@pytest.fixture
def sample_packets():
    return [
        PacketRecord(
            timestamp="2026-03-15T10:00:00",
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            size=60,
            tcp_flags=["SYN"],
            payload_size=0,
        ),
        PacketRecord(
            timestamp="2026-03-15T10:00:01",
            src_ip="10.0.0.1",
            dst_ip="192.168.1.10",
            src_port=80,
            dst_port=12345,
            protocol="TCP",
            size=60,
            tcp_flags=["SYN", "ACK"],
            payload_size=0,
        ),
        PacketRecord(
            timestamp="2026-03-15T10:00:02",
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            size=54,
            tcp_flags=["ACK"],
            payload_size=0,
        ),
        PacketRecord(
            timestamp="2026-03-15T10:00:05",
            src_ip="192.168.1.20",
            dst_ip="8.8.8.8",
            src_port=54321,
            dst_port=53,
            protocol="UDP",
            size=72,
            payload_size=18,
        ),
        PacketRecord(
            timestamp="2026-03-15T10:00:06",
            src_ip="8.8.8.8",
            dst_ip="192.168.1.20",
            src_port=53,
            dst_port=54321,
            protocol="UDP",
            size=120,
            payload_size=66,
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
        PacketRecord(
            timestamp="2026-03-15T10:00:12",
            src_ip="10.0.0.1",
            dst_ip="192.168.1.30",
            src_port=0,
            dst_port=0,
            protocol="ICMP",
            size=84,
        ),
        PacketRecord(
            timestamp="2026-03-15T10:00:15",
            src_ip="192.168.1.10",
            dst_ip="10.0.0.2",
            src_port=55555,
            dst_port=443,
            protocol="TCP",
            size=60,
            tcp_flags=["SYN"],
            payload_size=0,
        ),
        PacketRecord(
            timestamp="2026-03-15T10:00:20",
            src_ip="172.16.0.5",
            dst_ip="10.0.0.1",
            src_port=33333,
            dst_port=22,
            protocol="TCP",
            size=1500,
            tcp_flags=["PSH", "ACK"],
            payload_size=1446,
        ),
        PacketRecord(
            timestamp="2026-03-15T10:00:25",
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            size=54,
            tcp_flags=["RST"],
            payload_size=0,
        ),
    ]


@pytest.fixture
def sample_flows():
    return [
        ConnectionFlow(
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=12345,
            dst_port=80,
            protocol="TCP",
            packet_count=4,
            total_bytes=228,
            duration_seconds=25.0,
            start_time="2026-03-15T10:00:00",
            end_time="2026-03-15T10:00:25",
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
        ConnectionFlow(
            src_ip="172.16.0.5",
            dst_ip="10.0.0.1",
            src_port=33333,
            dst_port=22,
            protocol="TCP",
            packet_count=1,
            total_bytes=1500,
            duration_seconds=0.0,
            start_time="2026-03-15T10:00:20",
            end_time="2026-03-15T10:00:20",
        ),
    ]


@pytest.fixture
def sample_log_entries():
    return [
        LogEntry(
            timestamp="Mar 15 10:00:01",
            source_ip="192.168.1.10",
            message="Accepted publickey for admin from 192.168.1.10 port 22 ssh2",
            severity="info",
            service="sshd",
        ),
        LogEntry(
            timestamp="Mar 15 10:00:05",
            source_ip="server",
            message="(root) CMD (/usr/bin/check)",
            severity="info",
            service="CRON",
        ),
        LogEntry(
            timestamp="Mar 15 10:00:10",
            source_ip="10.99.88.77",
            message="Failed password for root from 10.99.88.77 port 44231 ssh2",
            severity="high",
            service="sshd",
        ),
        LogEntry(
            timestamp="Mar 15 10:00:11",
            source_ip="10.99.88.77",
            message="Failed password for root from 10.99.88.77 port 44232 ssh2",
            severity="high",
            service="sshd",
        ),
        LogEntry(
            timestamp="Mar 15 10:00:15",
            source_ip="server",
            message="[42000.123] eth0: link up",
            severity="info",
            service="kernel",
        ),
        LogEntry(
            timestamp="Mar 15 10:00:20",
            source_ip="203.0.113.50",
            message="Failed password for invalid user test from 203.0.113.50 port 22",
            severity="high",
            service="sshd",
        ),
        LogEntry(
            timestamp="Mar 15 10:00:25",
            source_ip="192.168.1.11",
            message="Connection closed by 192.168.1.11 port 443",
            severity="info",
            service="sshd",
        ),
        LogEntry(
            timestamp="Mar 15 10:00:30",
            source_ip="192.168.1.12",
            message="session opened for user admin",
            severity="info",
            service="sshd",
        ),
    ]


@pytest.fixture
def sample_parse_result(sample_packets, sample_flows):
    return ParseResult(
        source_file="test_capture.pcap",
        file_type="pcap",
        packet_count=len(sample_packets),
        time_range="2026-03-15T10:00:00 \u2013 2026-03-15T10:00:25",
        unique_src_ips=4,
        unique_dst_ips=3,
        protocol_distribution={"TCP": 5, "UDP": 2, "ICMP": 2},
        packets=sample_packets,
        flows=sample_flows,
    )


@pytest.fixture
def sample_log_parse_result(sample_log_entries):
    error_entries = [e for e in sample_log_entries if e.severity in ("critical", "high")]
    return LogParseResult(
        source_file="test.log",
        log_format="syslog",
        entry_count=len(sample_log_entries),
        time_range="Mar 15 10:00:01 \u2013 Mar 15 10:00:30",
        entries=sample_log_entries,
        error_entries=error_entries,
    )
