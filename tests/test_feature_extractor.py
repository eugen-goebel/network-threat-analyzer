"""Tests for the feature extraction agent."""

from pathlib import Path

import pytest

from agents.feature_extractor import FEATURE_NAMES, FeatureExtractor
from agents.log_parser import LogParser
from agents.pcap_parser import PcapParser
from models.network import ParseResult


@pytest.fixture
def extractor():
    return FeatureExtractor(window_seconds=60)


def test_extract_feature_count(extractor, sample_parse_result):
    matrix = extractor.extract(sample_parse_result)
    assert len(matrix.feature_names) == 18


def test_extract_window_creation(extractor, sample_parse_result):
    matrix = extractor.extract(sample_parse_result)
    assert len(matrix.window_starts) >= 1


def test_extract_feature_matrix_shape(extractor, sample_parse_result):
    matrix = extractor.extract(sample_parse_result)
    n_windows = len(matrix.window_starts)
    assert matrix.features.shape == (n_windows, 18)


def test_extract_baseline_stats(extractor, sample_parse_result):
    matrix = extractor.extract(sample_parse_result)
    for name in FEATURE_NAMES:
        assert name in matrix.baseline_stats


def test_extract_empty_packets(extractor):
    empty_result = ParseResult(
        source_file="empty.pcap",
        file_type="pcap",
        packet_count=0,
        time_range="",
        unique_src_ips=0,
        unique_dst_ips=0,
        protocol_distribution={},
        packets=[],
        flows=[],
    )
    matrix = extractor.extract(empty_result)
    assert matrix.features.shape[0] == 0
    assert matrix.features.shape[1] == 18


def test_extract_single_window(sample_parse_result):
    extractor = FeatureExtractor(window_seconds=300)
    matrix = extractor.extract(sample_parse_result)
    assert matrix.features.shape[0] == 1


# Regression: log timestamps could not be parsed, so every log entry was dropped
# silently and http_error_count stayed 0 for any real log file.
SAMPLE_DIR = Path(__file__).resolve().parent.parent / "data"


def test_apache_log_errors_land_in_the_packet_windows(extractor):
    capture = PcapParser(max_packets=None).parse(str(SAMPLE_DIR / "sample_capture.pcap"))
    log_result = LogParser.for_capture(capture).parse(str(SAMPLE_DIR / "sample_apache.log"))

    with_logs = extractor.extract(capture, log_result)
    without_logs = extractor.extract(capture, None)

    col = FEATURE_NAMES.index("http_error_count")
    assert without_logs.features[:, col].sum() == 0
    assert with_logs.features[:, col].sum() > 0


def test_syslog_errors_land_in_the_packet_windows(extractor, tmp_path):
    capture = PcapParser(max_packets=None).parse(str(SAMPLE_DIR / "sample_capture.pcap"))
    # Syslog has no zone and is read as UTC; the capture starts at 09:00 UTC.
    path = tmp_path / "syslog.log"
    path.write_text("Mar 15 09:00:30 gateway sshd[1]: Failed password for root from 10.0.0.9\n")
    log_result = LogParser.for_capture(capture).parse(str(path))

    matrix = extractor.extract(capture, log_result)
    col = FEATURE_NAMES.index("http_error_count")
    assert matrix.features[:, col].sum() == 1
