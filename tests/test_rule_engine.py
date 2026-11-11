"""Tests for the rule engine — port scans, brute force, suspicious connections."""

from pathlib import Path

import pytest

from agents.log_parser import LogParser
from agents.rule_engine import RuleEngine
from agents.threat_classifier import ThreatClassifier
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
        a
        for a in alerts
        if a.rule_name == "syn_scan"
        or (a.category == "PORT_SCAN" and a.evidence.get("scan_type") == "syn")
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
        a
        for a in alerts
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


# --- brute force on real parser output ---------------------------------------
# Regression: LogParser handed raw syslog/Apache timestamps to the rule, so
# datetime.fromisoformat raised ValueError for any real log file.

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "data"


def test_ssh_brute_force_is_found_in_the_sample_syslog(engine, port_scan_parse_result):
    log_result = LogParser(year=2026).parse(str(SAMPLE_DIR / "sample_syslog.log"))
    alerts = engine.analyze(port_scan_parse_result, log_result=log_result)
    ssh = [a for a in alerts if a.rule_name == "ssh_brute_force"]
    assert any(a.source_ips == ["10.99.88.77"] for a in ssh)


def _apache_line(
    ip: str, second: int, status: int, path: str = "/api/login", method: str = "POST"
) -> str:
    minute, sec = divmod(second, 60)
    return f'{ip} - - [15/Mar/2026:10:{minute:02d}:{sec:02d} +0100] "{method} {path} HTTP/1.1" {status} 10 "-" "x"\n'


def _parse_apache(tmp_path, lines: list[str]):
    path = tmp_path / "access.log"
    path.write_text("".join(lines))
    return LogParser().parse(str(path))


def _http_alerts(engine, port_scan_parse_result, log_result, rule_name: str):
    alerts = engine.analyze(port_scan_parse_result, log_result=log_result)
    return [a for a in alerts if a.rule_name == rule_name]


def test_http_brute_force_is_found_in_an_apache_log(engine, port_scan_parse_result, tmp_path):
    # Failed logins (401) from one IP: the per-IP rule fires on the status, not on severity.
    log_result = _parse_apache(tmp_path, [_apache_line("172.16.0.9", i, 401) for i in range(12)])

    http = _http_alerts(engine, port_scan_parse_result, log_result, "http_brute_force")
    assert [a.source_ips for a in http] == [["172.16.0.9"]]
    assert http[0].evidence["attempts"] == 12


def test_http_brute_force_counts_403_but_not_server_errors(
    engine, port_scan_parse_result, tmp_path
):
    forbidden = _parse_apache(tmp_path, [_apache_line("172.16.0.9", i, 403) for i in range(12)])
    assert _http_alerts(engine, port_scan_parse_result, forbidden, "http_brute_force")

    # 5xx is a server problem, not a failed login (it used to count via severity "medium").
    errors = _parse_apache(tmp_path, [_apache_line("172.16.0.9", i, 503) for i in range(12)])
    alerts = engine.analyze(port_scan_parse_result, log_result=errors)
    assert not [a for a in alerts if a.category == "BRUTE_FORCE"]


def test_http_brute_force_ignores_successful_logins_and_other_requests(
    engine, port_scan_parse_result, tmp_path
):
    lines = [_apache_line("172.16.0.9", i, 200) for i in range(6)]
    lines += [_apache_line("172.16.0.9", i, 302) for i in range(6, 12)]
    lines += [_apache_line("172.16.0.9", i, 401, method="GET") for i in range(12, 24)]
    lines += [_apache_line("172.16.0.9", i, 401, path="/api/data") for i in range(24, 36)]
    log_result = _parse_apache(tmp_path, lines)

    alerts = engine.analyze(port_scan_parse_result, log_result=log_result)
    assert not [a for a in alerts if a.category == "BRUTE_FORCE"]


def test_distributed_brute_force_is_found_in_the_sample_apache_log(engine, port_scan_parse_result):
    # 40 failed logins within 5s from 13 IPs (2-7 each): no single IP reaches the per-IP threshold.
    log_result = LogParser().parse(str(SAMPLE_DIR / "sample_apache.log"))
    alerts = engine.analyze(port_scan_parse_result, log_result=log_result)

    distributed = [a for a in alerts if a.rule_name == "http_distributed_brute_force"]
    assert len(distributed) == 1
    alert = distributed[0]
    assert alert.category == "BRUTE_FORCE"
    assert alert.severity == "high"
    assert len(alert.source_ips) == 13
    assert alert.evidence["attempts"] == 40
    assert alert.evidence["paths_targeted"] == ["/api/login"]
    assert not [a for a in alerts if a.rule_name == "http_brute_force"]


def test_distributed_brute_force_needs_enough_attempts(engine, port_scan_parse_result, tmp_path):
    # 5 IPs, 15 failed logins in total: below the 20 attempts needed.
    lines = [_apache_line(f"172.16.0.{i % 5 + 1}", i, 401) for i in range(15)]
    log_result = _parse_apache(tmp_path, lines)

    alerts = engine.analyze(port_scan_parse_result, log_result=log_result)
    assert not [a for a in alerts if a.category == "BRUTE_FORCE"]


def test_distributed_brute_force_needs_enough_sources(engine, port_scan_parse_result, tmp_path):
    # 2 IPs with 12 attempts each: the per-IP rule reports both, the distributed rule stays quiet.
    lines = [_apache_line(f"172.16.0.{i % 2 + 1}", i, 401) for i in range(24)]
    log_result = _parse_apache(tmp_path, lines)

    assert _http_alerts(engine, port_scan_parse_result, log_result, "http_brute_force")
    assert not _http_alerts(
        engine, port_scan_parse_result, log_result, "http_distributed_brute_force"
    )


def test_distributed_brute_force_needs_a_short_window(engine, port_scan_parse_result, tmp_path):
    # 30 failed logins from 10 IPs, but spread over 5 minutes (10s apart).
    lines = [_apache_line(f"172.16.0.{i % 10 + 1}", i * 10, 401) for i in range(30)]
    log_result = _parse_apache(tmp_path, lines)

    alerts = engine.analyze(port_scan_parse_result, log_result=log_result)
    assert not [a for a in alerts if a.category == "BRUTE_FORCE"]


def test_distributed_brute_force_ignores_successful_logins(
    engine, port_scan_parse_result, tmp_path
):
    lines = [
        _apache_line(f"172.16.0.{i % 10 + 1}", i // 4, 200 if i % 2 else 302) for i in range(40)
    ]
    log_result = _parse_apache(tmp_path, lines)

    alerts = engine.analyze(port_scan_parse_result, log_result=log_result)
    assert not [a for a in alerts if a.category == "BRUTE_FORCE"]


def test_distributed_brute_force_is_classified_as_brute_force(engine, port_scan_parse_result):
    log_result = LogParser().parse(str(SAMPLE_DIR / "sample_apache.log"))
    alerts = engine.analyze(port_scan_parse_result, log_result=log_result)
    report = ThreatClassifier().classify(alerts, [], 0, "", 0.0)

    threats = [t for t in report.threats if t.category == "BRUTE_FORCE"]
    assert len(threats) == 1
    assert threats[0].severity_label == "high"
    assert threats[0].title == "Distributed Brute Force from 13 sources"
    assert len(threats[0].source_ips) == 13


# --- login paths: whole words only -------------------------------------------


@pytest.mark.parametrize(
    ("path", "is_login"),
    [
        ("/api/login", True),
        ("/wp-login.php", True),
        ("/user/signin", True),
        ("/oauth/token", True),
        ("/auth", True),
        ("/api/v1/auth/login", True),
        ("/Auth/Login", True),
        ("/auth?next=/home", True),
        ("/api/userLogin", True),
        ("/sign-in", True),
        ("/account/log-in", True),
        # Border case, decided: the word "login" is in the path, so it counts.
        ("/blog/login-tips", True),
        ("/author", False),
        ("/authors/list", False),
        ("/authority/check", False),
        ("/tokenizer", False),
        ("/blogin", False),
        ("/api/data", False),
    ],
)
def test_http_brute_force_matches_login_paths_as_whole_words(
    engine, port_scan_parse_result, tmp_path, path, is_login
):
    lines = [_apache_line("172.16.0.9", i, 401, path=path) for i in range(12)]
    log_result = _parse_apache(tmp_path, lines)

    alerts = _http_alerts(engine, port_scan_parse_result, log_result, "http_brute_force")
    assert bool(alerts) is is_login


# --- bursts are not beacons, SYN floods are not HTTP floods ---------------------


def _packet_result(packets: list[PacketRecord]) -> ParseResult:
    return ParseResult(
        source_file="burst.pcap",
        file_type="pcap",
        packet_count=len(packets),
        time_range=f"{packets[0].timestamp} \u2013 {packets[-1].timestamp}",
        unique_src_ips=len({p.src_ip for p in packets}),
        unique_dst_ips=len({p.dst_ip for p in packets}),
        protocol_distribution={"TCP": len(packets)},
        packets=packets,
        flows=[],
    )


def _tcp(ts: str, src: str, flags: list[str], dst_port: int = 443) -> PacketRecord:
    return PacketRecord(
        timestamp=ts,
        src_ip=src,
        dst_ip="10.0.0.1",
        src_port=50000,
        dst_port=dst_port,
        protocol="TCP",
        size=60,
        tcp_flags=flags,
    )


def test_a_fast_regular_burst_is_not_beaconing(engine):
    # 10 packets 0.5 s apart: perfectly regular, but no timer calls home twice a second.
    packets = [
        _tcp(f"2026-03-15T10:00:{i // 2:02d}.{5 * (i % 2)}00000", "192.168.1.200", ["PSH", "ACK"])
        for i in range(10)
    ]
    alerts = engine.analyze(_packet_result(packets))
    assert [a for a in alerts if a.rule_name == "beaconing"] == []


def test_a_slow_regular_connection_is_still_beaconing(engine):
    # One packet a minute for ten minutes, the classic C2 check-in.
    packets = [
        _tcp(f"2026-03-15T10:{i:02d}:00", "192.168.1.200", ["PSH", "ACK"]) for i in range(10)
    ]
    alerts = engine.analyze(_packet_result(packets))
    beacons = [a for a in alerts if a.rule_name == "beaconing"]
    assert len(beacons) == 1
    assert beacons[0].evidence["avg_interval_seconds"] == 60


def _flood(flags: list[str], dst_port: int) -> list[PacketRecord]:
    # 150 packets from 15 sources within 3 seconds, one 10 s window.
    return [
        _tcp(
            f"2026-03-15T10:00:0{i // 50}.{(i % 50) * 2:02d}0000",
            f"172.16.0.{i % 15 + 1}",
            flags,
            dst_port=dst_port,
        )
        for i in range(150)
    ]


def test_a_syn_flood_on_port_80_is_not_also_an_http_flood(engine):
    alerts = engine.analyze(_packet_result(_flood(["SYN"], dst_port=80)))
    names = [a.rule_name for a in alerts]
    assert names.count("syn_flood") == 1
    assert "http_flood" not in names


def test_an_http_flood_is_still_found(engine):
    alerts = engine.analyze(_packet_result(_flood(["PSH", "ACK"], dst_port=80)))
    floods = [a for a in alerts if a.rule_name == "http_flood"]
    assert len(floods) == 1
    assert floods[0].evidence["source_count"] == 15
