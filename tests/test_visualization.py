"""Tests for the chart generation utilities."""

import os

import pytest

from models.reports import VisualizationResult
from models.threats import ClassifiedThreat, ThreatReport
from utils.visualization import ChartGenerator


@pytest.fixture
def threat_report():
    threats = [
        ClassifiedThreat(
            category="PORT_SCAN",
            severity_score=85,
            severity_label="critical",
            title="Vertical Port Scan from 192.168.1.100",
            description="Vertical port scan detected targeting 25 ports",
            detection_method="rule",
            source_ips=["192.168.1.100"],
            dest_ips=["10.0.0.1"],
            time_range="2026-03-15T10:00:00 \u2013 2026-03-15T10:01:00",
            evidence={"scan_type": "vertical", "ports_scanned": 25},
            recommendations=["Block source IP at firewall"],
        ),
        ClassifiedThreat(
            category="SUSPICIOUS_CONNECTION",
            severity_score=45,
            severity_label="medium",
            title="Suspicious Connection to 10.0.0.1",
            description="Traffic on suspicious port 4444",
            detection_method="rule",
            source_ips=["192.168.1.50"],
            dest_ips=["10.0.0.1"],
            time_range="2026-03-15T10:00:00 \u2013 2026-03-15T10:00:00",
            evidence={"port": 4444},
            recommendations=["Isolate affected host for investigation"],
        ),
    ]
    return ThreatReport(
        total_threats=2,
        critical_count=1,
        high_count=0,
        medium_count=1,
        low_count=0,
        threats=threats,
        analysis_duration_seconds=5.0,
        packets_analyzed=1000,
        time_range_analyzed="2026-03-15T10:00:00 \u2013 2026-03-15T10:01:00",
    )


@pytest.fixture
def protocol_dist():
    return {"TCP": 600, "UDP": 250, "ICMP": 100, "DNS": 50}


@pytest.fixture
def traffic_timeline():
    return [(f"2026-03-15T10:{i:02d}:00", float(i * 3 + 10)) for i in range(10)]


@pytest.fixture
def anomaly_scores():
    return [(f"2026-03-15T10:{i:02d}:00", 0.1 * i) for i in range(10)]


@pytest.fixture
def chart_generator(tmp_path):
    return ChartGenerator(output_dir=str(tmp_path))


def test_generate_all_creates_charts(
    chart_generator, threat_report, protocol_dist, traffic_timeline, anomaly_scores
):
    result = chart_generator.generate_all(
        threat_report=threat_report,
        protocol_dist=protocol_dist,
        traffic_timeline=traffic_timeline,
        anomaly_scores=anomaly_scores,
    )
    assert isinstance(result, VisualizationResult)
    assert len(result.charts) >= 3


def test_protocol_pie_exists(
    chart_generator, threat_report, protocol_dist, traffic_timeline, anomaly_scores
):
    chart_generator.generate_all(
        threat_report=threat_report,
        protocol_dist=protocol_dist,
        traffic_timeline=traffic_timeline,
        anomaly_scores=anomaly_scores,
    )
    path = os.path.join(chart_generator.output_dir, "protocol_distribution.png")
    assert os.path.exists(path)


def test_severity_bar_exists(
    chart_generator, threat_report, protocol_dist, traffic_timeline, anomaly_scores
):
    chart_generator.generate_all(
        threat_report=threat_report,
        protocol_dist=protocol_dist,
        traffic_timeline=traffic_timeline,
        anomaly_scores=anomaly_scores,
    )
    path = os.path.join(chart_generator.output_dir, "threat_severity.png")
    assert os.path.exists(path)


def test_anomaly_scatter_exists(
    chart_generator, threat_report, protocol_dist, traffic_timeline, anomaly_scores
):
    chart_generator.generate_all(
        threat_report=threat_report,
        protocol_dist=protocol_dist,
        traffic_timeline=traffic_timeline,
        anomaly_scores=anomaly_scores,
    )
    path = os.path.join(chart_generator.output_dir, "anomaly_scores.png")
    assert os.path.exists(path)


def test_chart_files_not_empty(
    chart_generator, threat_report, protocol_dist, traffic_timeline, anomaly_scores
):
    chart_generator.generate_all(
        threat_report=threat_report,
        protocol_dist=protocol_dist,
        traffic_timeline=traffic_timeline,
        anomaly_scores=anomaly_scores,
    )
    for name in ["protocol_distribution.png", "threat_severity.png", "anomaly_scores.png"]:
        path = os.path.join(chart_generator.output_dir, name)
        assert os.path.getsize(path) > 0


def test_generate_all_with_empty_data(chart_generator, threat_report):
    result = chart_generator.generate_all(
        threat_report=threat_report,
        protocol_dist={},
        traffic_timeline=[],
        anomaly_scores=[],
    )
    assert isinstance(result, VisualizationResult)
