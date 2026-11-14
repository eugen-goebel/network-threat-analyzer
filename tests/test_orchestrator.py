"""Tests for what the CLI orchestrator hands to the report charts."""

import pytest

from agents import orchestrator
from agents.anomaly_detector import AnomalyDetector
from agents.mock_data import get_mock_anomaly_windows
from agents.orchestrator import ThreatAnalysisOrchestrator
from agents.pcap_parser import PcapParser
from agents.threat_classifier import ThreatClassifier
from utils.visualization import ChartGenerator


@pytest.fixture
def spies(monkeypatch):
    """Record the chart inputs, the classifier's alerts and the ensemble runs."""
    seen = {"charts": [], "alerts": [], "analyze_calls": 0}

    real_generate_all = ChartGenerator.generate_all
    real_classify = ThreatClassifier.classify
    real_analyze = AnomalyDetector.analyze

    def generate_all(self, threat_report, protocol_dist, traffic_timeline, anomaly_windows, **kw):
        seen["charts"].append((traffic_timeline, anomaly_windows))
        return real_generate_all(
            self, threat_report, protocol_dist, traffic_timeline, anomaly_windows, **kw
        )

    def classify(self, rule_alerts, anomaly_alerts, *args, **kwargs):
        seen["alerts"] = list(anomaly_alerts)
        return real_classify(self, rule_alerts, anomaly_alerts, *args, **kwargs)

    def analyze(self, feature_matrix):
        seen["analyze_calls"] += 1
        return real_analyze(self, feature_matrix)

    monkeypatch.setattr(ChartGenerator, "generate_all", generate_all)
    monkeypatch.setattr(ThreatClassifier, "classify", classify)
    monkeypatch.setattr(AnomalyDetector, "analyze", analyze)
    return seen


def _assert_all_windows_passed_on(seen):
    ((timeline, windows),) = seen["charts"]
    # Every time window is charted, not just the flagged ones.
    assert [w[0] for w in windows] == [t[0] for t in timeline]
    flagged = {ts for ts, _, is_flagged in windows if is_flagged}
    assert flagged == {a.time_window_start for a in seen["alerts"]}
    assert 0 < len(flagged) < len(windows)
    scores = {a.time_window_start: a.anomaly_score for a in seen["alerts"]}
    assert all(score == scores[ts] for ts, score, f in windows if f)
    assert seen["analyze_calls"] == 1


def test_run_passes_every_window_with_its_flag_to_the_charts(spies, tmp_path, sample_pcap_path):
    ThreatAnalysisOrchestrator(output_dir=str(tmp_path)).run([sample_pcap_path])
    _assert_all_windows_passed_on(spies)


def test_run_live_passes_every_window_with_its_flag_to_the_charts(
    monkeypatch, spies, tmp_path, sample_pcap_path
):
    class FakeCapture:
        def capture(self, **kwargs):
            return PcapParser().parse(sample_pcap_path)

    monkeypatch.setattr(orchestrator, "LiveCaptureAgent", FakeCapture)
    ThreatAnalysisOrchestrator(output_dir=str(tmp_path)).run_live()
    _assert_all_windows_passed_on(spies)


def test_demo_passes_the_mock_windows_with_their_flag_to_the_charts(spies, tmp_path):
    ThreatAnalysisOrchestrator(output_dir=str(tmp_path)).run_demo()
    ((_, windows),) = spies["charts"]
    assert windows == get_mock_anomaly_windows()
