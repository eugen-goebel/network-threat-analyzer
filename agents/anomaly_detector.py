"""ML-based anomaly detection — ensemble of Isolation Forest, LOF, and One-Class SVM."""

from datetime import datetime, timedelta

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from agents.feature_extractor import FeatureMatrix
from models.threats import AnomalyAlert


class AnomalyDetector:
    def __init__(self, sensitivity: float = 0.05):
        self.sensitivity = sensitivity
        self.scaler = StandardScaler()

    def detect(self, feature_matrix: FeatureMatrix) -> list[AnomalyAlert]:
        if feature_matrix.features.size == 0 or feature_matrix.features.shape[0] < 5:
            return []

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
        for i in range(n_samples):
            votes = [iso_pred[i], lof_pred[i], svm_pred[i]]
            anomaly_votes = sum(1 for v in votes if v == -1)
            if anomaly_votes < 2:
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

        return alerts
