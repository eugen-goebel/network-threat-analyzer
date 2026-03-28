"""Tests for the feature extraction agent."""

import pytest

from agents.feature_extractor import FEATURE_NAMES, FeatureExtractor
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
