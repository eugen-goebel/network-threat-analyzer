"""ML-based anomaly detection — ensemble of Isolation Forest, LOF, and One-Class SVM."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from agents.feature_extractor import FeatureMatrix
from models.threats import AnomalyAlert

# Below this many time windows the ensemble is not run and no scores exist.
MIN_WINDOWS = 5
VOTES_NEEDED = 2


@dataclass(frozen=True)
class WindowScore:
    """Score and ensemble decision of one time window."""

    time_window_start: str
    # Isolation Forest score scaled to 0-1 within this capture (1 = most unusual).
    anomaly_score: float
    # How many of the three models voted outlier for this window.
    models_flagged: int
    # The ensemble decision: models_flagged >= VOTES_NEEDED. It is a vote, not a
    # cut-off on anomaly_score, so a flagged window can score below an unflagged one.
    flagged: bool


@dataclass(frozen=True)
class AnomalyResult:
    """Everything one ensemble run produced."""

    alerts: list[AnomalyAlert] = field(default_factory=list)
    # One entry per time window, in window order. Empty when the capture has
    # fewer than MIN_WINDOWS windows.
    windows: list[WindowScore] = field(default_factory=list)


class AnomalyDetector:
    def __init__(self, sensitivity: float = 0.05):
        self.sensitivity = sensitivity
        self.scaler = StandardScaler()

    def detect(self, feature_matrix: FeatureMatrix) -> list[AnomalyAlert]:
        """Return the alerts for the windows the ensemble flags."""
        return self.analyze(feature_matrix).alerts

    def analyze(self, feature_matrix: FeatureMatrix) -> AnomalyResult:
        """Run the ensemble once and return the alerts plus the score of every window."""
        if feature_matrix.features.size == 0 or feature_matrix.features.shape[0] < MIN_WINDOWS:
            return AnomalyResult()

        scaled = self.scaler.fit_transform(feature_matrix.features)
        n_samples = len(scaled)

        iso_forest = IsolationForest(
            n_estimators=200,
            contamination=self.sensitivity,
            random_state=42,
        )
        lof = LocalOutlierFactor(
            n_neighbors=min(20, n_samples - 1),
            contamination=self.sensitivity,
        )
        svm = OneClassSVM(kernel="rbf", nu=self.sensitivity, gamma="scale")

        iso_pred = iso_forest.fit_predict(scaled)
        lof_pred = lof.fit_predict(scaled)
        svm_pred = svm.fit(scaled).predict(scaled)

        iso_scores = iso_forest.decision_function(scaled)

        # Normalize isolation forest scores to 0-1 (1 = most anomalous)
        min_score = iso_scores.min()
        max_score = iso_scores.max()
        norm_scores = 1 - (iso_scores - min_score) / (max_score - min_score + 1e-10)

        # Feature stats for z-score calculation
        feat_mean = np.mean(feature_matrix.features, axis=0)
        feat_std = np.std(feature_matrix.features, axis=0)
        feat_std[feat_std == 0] = 1e-10

        alerts: list[AnomalyAlert] = []
        windows: list[WindowScore] = []
        for i in range(n_samples):
            votes = [iso_pred[i], lof_pred[i], svm_pred[i]]
            anomaly_votes = sum(1 for v in votes if v == -1)
            flagged = anomaly_votes >= VOTES_NEEDED
            windows.append(
                WindowScore(
                    time_window_start=feature_matrix.window_starts[i],
                    anomaly_score=float(norm_scores[i]),
                    models_flagged=anomaly_votes,
                    flagged=flagged,
                )
            )
            if not flagged:
                continue

            # Contributing features: top 3 by absolute z-score
            z_scores = (feature_matrix.features[i] - feat_mean) / feat_std
            abs_z = np.abs(z_scores)
            top_indices = np.argsort(abs_z)[::-1][:3]

            contributing = []
            for idx in top_indices:
                name = feature_matrix.feature_names[idx]
                ratio = abs(z_scores[idx])
                direction = "above" if z_scores[idx] > 0 else "below"
                contributing.append(f"{name} ({ratio:.1f}x {direction} baseline)")

            w_start = feature_matrix.window_starts[i]
            w_end_dt = datetime.fromisoformat(w_start) + timedelta(
                seconds=feature_matrix.window_seconds
            )

            alerts.append(
                AnomalyAlert(
                    time_window_start=w_start,
                    time_window_end=w_end_dt.isoformat(),
                    anomaly_score=float(norm_scores[i]),
                    contributing_features=contributing,
                    model_votes={
                        "isolation_forest": int(iso_pred[i]),
                        "local_outlier_factor": int(lof_pred[i]),
                        "one_class_svm": int(svm_pred[i]),
                    },
                )
            )

        return AnomalyResult(alerts=alerts, windows=windows)
