"""Tests for the threat classifier — merging rule and ML alerts into a ThreatReport."""

import pytest

from agents.threat_classifier import ThreatClassifier
from models.threats import AnomalyAlert, RuleAlert


@pytest.fixture
def rule_alerts():
    return [
        RuleAlert(
            rule_name="port_scan_vertical",
            severity="high",
            category="PORT_SCAN",
            description="Vertical port scan detected",
            source_ips=["192.168.1.100"],
            dest_ips=["10.0.0.1"],
            timestamps=["2026-03-15T10:01:00"],
            evidence={"scan_type": "vertical", "ports_scanned": 25},
        ),
        RuleAlert(
            rule_name="suspicious_port",
            severity="high",
            category="SUSPICIOUS_CONNECTION",
            description="Traffic on suspicious port",
            source_ips=["192.168.1.50"],
            dest_ips=["10.0.0.1"],
            timestamps=["2026-03-15T10:00:00"],
            evidence={"port": 4444},
        ),
    ]


@pytest.fixture
def anomaly_alerts():
    return [
        AnomalyAlert(
            time_window_start="2026-03-15T10:03:00",
            time_window_end="2026-03-15T10:04:00",
            anomaly_score=0.85,
            contributing_features=["packets_per_second", "syn_ratio"],
            model_votes={
                "isolation_forest": -1,
                "local_outlier_factor": -1,
                "one_class_svm": 1,
            },
        ),
        AnomalyAlert(
            time_window_start="2026-03-15T10:05:00",
            time_window_end="2026-03-15T10:06:00",
            anomaly_score=0.62,
            contributing_features=["unique_dst_ports", "avg_packet_size"],
            model_votes={
                "isolation_forest": -1,
                "local_outlier_factor": -1,
                "one_class_svm": -1,
            },
        ),
    ]


@pytest.fixture
def classifier():
    return ThreatClassifier()


def test_classify_rule_alerts(classifier, rule_alerts):
    report = classifier.classify(
        rule_alerts=rule_alerts,
        anomaly_alerts=[],
        packets_analyzed=1000,
        time_range="2026-03-15T10:00:00 \u2013 2026-03-15T10:05:00",
        duration_seconds=300.0,
    )
    assert len(report.threats) == 2


def test_classify_anomaly_alerts(classifier, anomaly_alerts):
    report = classifier.classify(
        rule_alerts=[],
        anomaly_alerts=anomaly_alerts,
        packets_analyzed=500,
        time_range="2026-03-15T10:03:00 \u2013 2026-03-15T10:06:00",
        duration_seconds=180.0,
    )
    for threat in report.threats:
        assert threat.category == "ANOMALOUS_TRAFFIC"


def test_classify_severity_scoring(classifier, rule_alerts, anomaly_alerts):
    report = classifier.classify(
        rule_alerts=rule_alerts,
        anomaly_alerts=anomaly_alerts,
        packets_analyzed=1500,
        time_range="2026-03-15T10:00:00 \u2013 2026-03-15T10:06:00",
        duration_seconds=360.0,
    )
    for threat in report.threats:
        assert 0 <= threat.severity_score <= 100


def test_classify_empty_input(classifier):
    report = classifier.classify(
        rule_alerts=[],
        anomaly_alerts=[],
        packets_analyzed=0,
        time_range="2026-03-15T10:00:00 \u2013 2026-03-15T10:00:00",
        duration_seconds=0.0,
    )
    assert len(report.threats) == 0


def test_classify_detection_method(classifier, rule_alerts, anomaly_alerts):
    report = classifier.classify(
        rule_alerts=rule_alerts,
        anomaly_alerts=anomaly_alerts,
        packets_analyzed=1500,
        time_range="2026-03-15T10:00:00 \u2013 2026-03-15T10:06:00",
        duration_seconds=360.0,
    )
    methods = {t.detection_method for t in report.threats}
    assert "rule" in methods or "both" in methods
    assert "ml" in methods or "both" in methods


def test_classify_recommendations(classifier, rule_alerts, anomaly_alerts):
    report = classifier.classify(
        rule_alerts=rule_alerts,
        anomaly_alerts=anomaly_alerts,
        packets_analyzed=1500,
        time_range="2026-03-15T10:00:00 \u2013 2026-03-15T10:06:00",
        duration_seconds=360.0,
    )
    for threat in report.threats:
        assert isinstance(threat.recommendations, list)
        assert len(threat.recommendations) > 0
