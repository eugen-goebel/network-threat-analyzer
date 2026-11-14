"""Tests for the chart generation utilities."""

import os
import re

import matplotlib.colors
import matplotlib.pyplot as plt
import pytest

from agents.anomaly_detector import MIN_WINDOWS
from models.reports import VisualizationResult
from models.threats import ClassifiedThreat, ThreatReport
from utils.visualization import COLOR_CRITICAL, COLOR_INFO, ChartGenerator


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


# Index 3 scores highest but is NOT flagged; index 8 is flagged with a low score.
# The flag is the ensemble vote, so it must not be derived from the score.
SCORES = [0.1, 0.2, 0.3, 0.9, 0.2, 0.1, 0.6, 0.2, 0.4, 0.1]
FLAGGED = {6, 8}


@pytest.fixture
def anomaly_windows():
    return [(f"2026-03-15T10:{i:02d}:00", SCORES[i], i in FLAGGED) for i in range(10)]


@pytest.fixture
def chart_generator(tmp_path):
    return ChartGenerator(output_dir=str(tmp_path))


def test_generate_all_creates_charts(
    chart_generator, threat_report, protocol_dist, traffic_timeline, anomaly_windows
):
    result = chart_generator.generate_all(
        threat_report=threat_report,
        protocol_dist=protocol_dist,
        traffic_timeline=traffic_timeline,
        anomaly_windows=anomaly_windows,
    )
    assert isinstance(result, VisualizationResult)
    assert len(result.charts) >= 3


def test_protocol_pie_exists(
    chart_generator, threat_report, protocol_dist, traffic_timeline, anomaly_windows
):
    chart_generator.generate_all(
        threat_report=threat_report,
        protocol_dist=protocol_dist,
        traffic_timeline=traffic_timeline,
        anomaly_windows=anomaly_windows,
    )
    path = os.path.join(chart_generator.output_dir, "protocol_distribution.png")
    assert os.path.exists(path)


def test_severity_bar_exists(
    chart_generator, threat_report, protocol_dist, traffic_timeline, anomaly_windows
):
    chart_generator.generate_all(
        threat_report=threat_report,
        protocol_dist=protocol_dist,
        traffic_timeline=traffic_timeline,
        anomaly_windows=anomaly_windows,
    )
    path = os.path.join(chart_generator.output_dir, "threat_severity.png")
    assert os.path.exists(path)


def test_anomaly_scatter_exists(
    chart_generator, threat_report, protocol_dist, traffic_timeline, anomaly_windows
):
    chart_generator.generate_all(
        threat_report=threat_report,
        protocol_dist=protocol_dist,
        traffic_timeline=traffic_timeline,
        anomaly_windows=anomaly_windows,
    )
    path = os.path.join(chart_generator.output_dir, "anomaly_scores.png")
    assert os.path.exists(path)


def test_chart_files_not_empty(
    chart_generator, threat_report, protocol_dist, traffic_timeline, anomaly_windows
):
    chart_generator.generate_all(
        threat_report=threat_report,
        protocol_dist=protocol_dist,
        traffic_timeline=traffic_timeline,
        anomaly_windows=anomaly_windows,
    )
    for name in ["protocol_distribution.png", "threat_severity.png", "anomaly_scores.png"]:
        path = os.path.join(chart_generator.output_dir, name)
        assert os.path.getsize(path) > 0


def test_generate_all_with_empty_data(chart_generator, threat_report):
    result = chart_generator.generate_all(
        threat_report=threat_report,
        protocol_dist={},
        traffic_timeline=[],
        anomaly_windows=[],
    )
    assert isinstance(result, VisualizationResult)


def _timeline(n):
    return [(f"2026-03-15T09:{i // 60:02d}:{i % 60:02d}.675+00:00", float(i)) for i in range(n)]


def _windows(n, flagged=()):
    return [(ts, 0.5, i in flagged) for i, (ts, _) in enumerate(_timeline(n))]


def _tick_texts(ax):
    return [t.get_text() for t in ax.get_xticklabels()]


def _legend_texts(ax):
    return [t.get_text() for t in ax.get_legend().get_texts()]


def test_timeline_shades_exactly_the_flagged_windows(
    chart_generator, traffic_timeline, anomaly_windows
):
    fig = chart_generator._timeline_figure(traffic_timeline, anomaly_windows)
    ax = fig.axes[0]
    shaded = sorted(round(p.get_x() + p.get_width() / 2) for p in ax.patches)
    plt.close(fig)
    # Window 3 has the top score but is not flagged, so it must stay plain.
    assert shaded == sorted(FLAGGED)


def test_timeline_shades_nothing_when_no_window_is_flagged(chart_generator):
    fig = chart_generator._timeline_figure(_timeline(8), _windows(8))
    patch_count = len(fig.axes[0].patches)
    plt.close(fig)
    assert patch_count == 0


def test_timeline_axis_shows_clock_time_not_iso_timestamps(chart_generator):
    fig = chart_generator._timeline_figure(_timeline(60), _windows(60))
    ticks = _tick_texts(fig.axes[0])
    plt.close(fig)
    assert ticks
    assert all(re.fullmatch(r"\d{2}:\d{2}:\d{2}", t) for t in ticks)


def test_anomaly_chart_plots_every_window(chart_generator, anomaly_windows):
    fig = chart_generator._anomaly_figure(anomaly_windows, len(anomaly_windows))
    ax = fig.axes[0]
    drawn = sum(len(c.get_offsets()) for c in ax.collections)
    line_scores = list(ax.lines[0].get_ydata())
    plt.close(fig)
    assert drawn == len(anomaly_windows)
    assert line_scores == SCORES


def test_anomaly_chart_marks_flagged_red_and_the_rest_blue(chart_generator, anomaly_windows):
    fig = chart_generator._anomaly_figure(anomaly_windows, len(anomaly_windows))
    ax = fig.axes[0]
    by_color = {}
    for coll in ax.collections:
        color = matplotlib.colors.to_hex(coll.get_facecolor()[0]).upper()
        by_color[color] = sorted(round(x) for x, _ in coll.get_offsets())
    plt.close(fig)
    assert by_color == {
        COLOR_CRITICAL: sorted(FLAGGED),
        COLOR_INFO: [i for i in range(10) if i not in FLAGGED],
    }


def test_anomaly_chart_has_a_legend_for_both_decisions(chart_generator, anomaly_windows):
    fig = chart_generator._anomaly_figure(anomaly_windows, len(anomaly_windows))
    legend = _legend_texts(fig.axes[0])
    plt.close(fig)
    assert legend == ["Not flagged", "Flagged by ensemble"]


def test_anomaly_chart_draws_no_threshold_line(chart_generator, anomaly_windows):
    fig = chart_generator._anomaly_figure(anomaly_windows, len(anomaly_windows))
    ax = fig.axes[0]
    # The only line is the score curve; a threshold would add a flat second one.
    flat = [ln for ln in ax.lines if len(set(ln.get_ydata())) == 1]
    line_count = len(ax.lines)
    texts = [ax.get_title(), ax.get_ylabel(), ax.get_xlabel(), *_legend_texts(ax)]
    plt.close(fig)
    assert line_count == 1
    assert flat == []
    assert not any("threshold" in t.lower() for t in texts)


def test_anomaly_chart_axis_shows_clock_time_not_iso_timestamps(chart_generator):
    fig = chart_generator._anomaly_figure(_windows(60), 60)
    ticks = _tick_texts(fig.axes[0])
    plt.close(fig)
    assert 0 < len(ticks) <= 25
    assert all(re.fullmatch(r"\d{2}:\d{2}:\d{2}", t) for t in ticks)


def test_anomaly_chart_without_windows_explains_why(chart_generator):
    fig = chart_generator._anomaly_figure([], 3)
    ax = fig.axes[0]
    text = " ".join(t.get_text() for t in ax.texts)
    plotted = len(ax.collections) + len(ax.lines)
    plt.close(fig)
    assert plotted == 0
    assert f"at least {MIN_WINDOWS}" in text
    assert "3" in text


def test_generate_all_without_anomaly_windows_still_writes_the_chart(
    chart_generator, threat_report, protocol_dist
):
    result = chart_generator.generate_all(
        threat_report=threat_report,
        protocol_dist=protocol_dist,
        traffic_timeline=_timeline(3),
        anomaly_windows=[],
    )
    assert os.path.getsize(os.path.join(chart_generator.output_dir, "anomaly_scores.png")) > 0
    config = next(c for c in result.charts if c.filename == "anomaly_scores.png")
    assert "no anomaly scores" in config.description.lower()


def test_anomaly_description_states_score_and_vote_without_threshold(
    chart_generator, threat_report, protocol_dist, traffic_timeline, anomaly_windows
):
    result = chart_generator.generate_all(
        threat_report=threat_report,
        protocol_dist=protocol_dist,
        traffic_timeline=traffic_timeline,
        anomaly_windows=anomaly_windows,
    )
    config = next(c for c in result.charts if c.filename == "anomaly_scores.png")
    text = config.description.lower()
    assert "isolation forest" in text
    assert "two of the three" in text
    assert "threshold" not in text
    timeline = next(c for c in result.charts if c.filename == "traffic_timeline.png")
    assert "flagged" in timeline.description.lower()
