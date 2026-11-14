"""Tests for the ML-based anomaly detector ensemble."""

import numpy as np
import pytest

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
    baseline_stats = {name: float(np.mean(features[:, i])) for i, name in enumerate(feature_names)}

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
    baseline_stats = {name: float(np.mean(features[:, i])) for i, name in enumerate(feature_names)}
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


# --- scores of every window --------------------------------------------------


def test_analyze_scores_every_window(detector, normal_features):
    result = detector.analyze(normal_features)
    assert len(result.windows) == len(normal_features.window_starts) == 20
    assert [w.time_window_start for w in result.windows] == normal_features.window_starts
    assert all(0.0 <= w.anomaly_score <= 1.0 for w in result.windows)


def test_analyze_flags_exactly_the_windows_detect_reports(detector, normal_features):
    alerts = detector.detect(normal_features)
    result = AnomalyDetector(sensitivity=0.1).analyze(normal_features)

    assert alerts, "the fixture must produce at least one alert"
    assert result.alerts == alerts
    flagged = [w for w in result.windows if w.flagged]
    assert [w.time_window_start for w in flagged] == [a.time_window_start for a in alerts]
    assert [w.anomaly_score for w in flagged] == [a.anomaly_score for a in alerts]


def test_flag_is_the_ensemble_vote_not_a_score_cutoff(detector, normal_features):
    result = detector.analyze(normal_features)
    by_start = {a.time_window_start: a for a in result.alerts}
    for w in result.windows:
        assert w.flagged == (w.models_flagged >= 2)
        if w.flagged:
            votes = by_start[w.time_window_start].model_votes
            assert w.models_flagged == sum(1 for v in votes.values() if v == -1)


def test_analyze_runs_the_ensemble_once(monkeypatch, normal_features):
    import agents.anomaly_detector as module

    fits = []

    class CountingForest(module.IsolationForest):
        def fit_predict(self, *args, **kwargs):
            fits.append(1)
            return super().fit_predict(*args, **kwargs)

    monkeypatch.setattr(module, "IsolationForest", CountingForest)
    AnomalyDetector(sensitivity=0.1).analyze(normal_features)
    assert len(fits) == 1


def test_analyze_has_no_scores_for_too_few_or_no_windows(
    detector, empty_features, few_window_features
):
    for features in (empty_features, few_window_features):
        result = detector.analyze(features)
        assert result.windows == []
        assert result.alerts == []
