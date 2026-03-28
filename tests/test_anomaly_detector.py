"""Tests for the ML-based anomaly detector ensemble."""

import pytest
import numpy as np

from agents.anomaly_detector import AnomalyDetector
from agents.feature_extractor import FeatureMatrix


@pytest.fixture
def normal_features():
    np.random.seed(42)
    features = np.random.normal(loc=5.0, scale=1.0, size=(20, 18))
    features = np.abs(features)
    # Inject 2 anomalous windows with extreme values
    features[10] = np.full(18, 50.0)
    features[15] = np.full(18, 40.0)

    feature_names = [f"feature_{i}" for i in range(18)]
    window_starts = [f"2026-03-15T10:{i:02d}:00" for i in range(20)]
    baseline_stats = {
        name: float(np.mean(features[:, i]))
        for i, name in enumerate(feature_names)
    }

    return FeatureMatrix(
        features=features,
        feature_names=feature_names,
        window_starts=window_starts,
        window_seconds=60,
        baseline_stats=baseline_stats,
    )


@pytest.fixture
def empty_features():
    return FeatureMatrix(
        features=np.empty((0, 18)),
        feature_names=[f"feature_{i}" for i in range(18)],
        window_starts=[],
        window_seconds=60,
        baseline_stats={f"feature_{i}": 0.0 for i in range(18)},
    )


@pytest.fixture
def few_window_features():
    np.random.seed(99)
    features = np.random.normal(loc=5.0, scale=1.0, size=(3, 18))
    features = np.abs(features)
    feature_names = [f"feature_{i}" for i in range(18)]
    window_starts = [f"2026-03-15T10:{i:02d}:00" for i in range(3)]
    baseline_stats = {
        name: float(np.mean(features[:, i]))
        for i, name in enumerate(feature_names)
    }
    return FeatureMatrix(
        features=features,
        feature_names=feature_names,
        window_starts=window_starts,
        window_seconds=60,
        baseline_stats=baseline_stats,
    )


@pytest.fixture
def uniform_features():
    row = np.full(18, 3.0)
    features = np.tile(row, (20, 1))
    feature_names = [f"feature_{i}" for i in range(18)]
    window_starts = [f"2026-03-15T10:{i:02d}:00" for i in range(20)]
    baseline_stats = {name: 3.0 for name in feature_names}
    return FeatureMatrix(
        features=features,
        feature_names=feature_names,
        window_starts=window_starts,
        window_seconds=60,
        baseline_stats=baseline_stats,
    )


@pytest.fixture
def detector():
    return AnomalyDetector(sensitivity=0.1)


def test_detect_anomalies_found(detector, normal_features):
    alerts = detector.detect(normal_features)
    assert len(alerts) >= 1


def test_anomaly_score_range(detector, normal_features):
    alerts = detector.detect(normal_features)
    assert len(alerts) >= 1
    for alert in alerts:
        assert 0.0 <= alert.anomaly_score <= 1.0


def test_anomaly_has_contributing_features(detector, normal_features):
    alerts = detector.detect(normal_features)
    assert len(alerts) >= 1
    for alert in alerts:
        assert isinstance(alert.contributing_features, list)
        assert len(alert.contributing_features) > 0


def test_anomaly_has_model_votes(detector, normal_features):
    alerts = detector.detect(normal_features)
    assert len(alerts) >= 1
    for alert in alerts:
        assert isinstance(alert.model_votes, dict)
        assert "isolation_forest" in alert.model_votes
        assert "local_outlier_factor" in alert.model_votes
        assert "one_class_svm" in alert.model_votes


def test_detect_empty_features(detector, empty_features):
    alerts = detector.detect(empty_features)
    assert alerts == []


def test_detect_too_few_windows(detector, few_window_features):
    alerts = detector.detect(few_window_features)
    assert alerts == []


def test_detect_all_normal(detector, uniform_features):
    alerts = detector.detect(uniform_features)
    assert len(alerts) <= 2
