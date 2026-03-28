"""Threat classifier — merges rule-based and ML alerts, deduplicates, and assigns severity scores."""

from datetime import datetime

from models.threats import RuleAlert, AnomalyAlert, ClassifiedThreat, ThreatReport

_RULE_RECOMMENDATIONS = {
    "PORT_SCAN": [
        "Block source IP at firewall",
        "Review firewall rules for exposed ports",
        "Enable IDS/IPS signatures for scan detection",
    ],
    "DDOS_ATTACK": [
        "Enable rate limiting on affected services",
        "Configure SYN cookies",
        "Contact upstream provider for traffic scrubbing",
    ],
    "BRUTE_FORCE": [
        "Implement account lockout policies",
        "Enable fail2ban or similar",
        "Enforce strong passwords and MFA",
    ],
    "SUSPICIOUS_CONNECTION": [
        "Isolate affected host for investigation",
        "Block communication to suspicious destination",
        "Conduct forensic analysis of the endpoint",
    ],
}

_BASE_SEVERITY_SCORES = {
    "critical": 80,
    "high": 60,
    "medium": 40,
    "low": 20,
}


class ThreatClassifier:

    def classify(
        self,
        rule_alerts: list[RuleAlert],
        anomaly_alerts: list[AnomalyAlert],
        packets_analyzed: int,
        time_range: str,
        duration_seconds: float,
    ) -> ThreatReport:
        threats: list[ClassifiedThreat] = []

        for alert in rule_alerts:
            threats.append(self._from_rule_alert(alert))

        for alert in anomaly_alerts:
            threats.append(self._from_anomaly_alert(alert))

        threats = self._deduplicate(threats)
        threats.sort(key=lambda t: t.severity_score, reverse=True)

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for t in threats:
            severity_counts[t.severity_label] = severity_counts.get(t.severity_label, 0) + 1

        return ThreatReport(
            total_threats=len(threats),
            critical_count=severity_counts["critical"],
            high_count=severity_counts["high"],
            medium_count=severity_counts["medium"],
            low_count=severity_counts["low"],
            threats=threats,
            analysis_duration_seconds=duration_seconds,
            packets_analyzed=packets_analyzed,
            time_range_analyzed=time_range,
        )

    def _from_rule_alert(self, alert: RuleAlert) -> ClassifiedThreat:
        category = alert.category
        base_score = _BASE_SEVERITY_SCORES.get(alert.severity, 20)
        recommendations = _RULE_RECOMMENDATIONS.get(category, [])

        if category == "PORT_SCAN" and alert.source_ips:
            title = f"Vertical Port Scan from {alert.source_ips[0]}"
        elif category == "DDOS_ATTACK":
            title = f"DDoS Attack targeting {alert.dest_ips[0]}" if alert.dest_ips else "DDoS Attack detected"
        elif category == "BRUTE_FORCE" and alert.source_ips:
            title = f"Brute Force from {alert.source_ips[0]}"
        elif category == "SUSPICIOUS_CONNECTION" and alert.dest_ips:
            title = f"Suspicious Connection to {alert.dest_ips[0]}"
        else:
            title = f"{category.replace('_', ' ').title()} detected"

        return ClassifiedThreat(
            category=category,
            severity_score=base_score,
            severity_label=alert.severity,
            title=title,
            description=alert.description,
            detection_method="rule",
            source_ips=list(alert.source_ips),
            dest_ips=list(alert.dest_ips),
            time_range=f"{alert.timestamps[0]} \u2013 {alert.timestamps[-1]}" if alert.timestamps else "",
            evidence=alert.evidence,
            recommendations=recommendations,
        )

    def _from_anomaly_alert(self, alert: AnomalyAlert) -> ClassifiedThreat:
        severity_score = int(alert.anomaly_score * 80)

        if severity_score >= 80:
            severity_label = "critical"
        elif severity_score >= 60:
            severity_label = "high"
        elif severity_score >= 40:
            severity_label = "medium"
        else:
            severity_label = "low"

        top_features = ", ".join(alert.contributing_features[:3])

        return ClassifiedThreat(
            category="ANOMALOUS_TRAFFIC",
            severity_score=severity_score,
            severity_label=severity_label,
            title=f"Anomalous Traffic Detected ({alert.time_window_start})",
            description=f"ML ensemble flagged unusual network behavior. Contributing factors: {top_features}",
            detection_method="ml",
            source_ips=[],
            dest_ips=[],
            time_range=f"{alert.time_window_start} \u2013 {alert.time_window_end}",
            evidence={
                "anomaly_score": alert.anomaly_score,
                "model_votes": alert.model_votes,
                "contributing_features": alert.contributing_features,
            },
            recommendations=[
                "Investigate traffic patterns in the flagged time window",
                "Correlate with system logs for additional context",
                "Review baseline thresholds and adjust if needed",
            ],
        )

    def _deduplicate(self, threats: list[ClassifiedThreat]) -> list[ClassifiedThreat]:
        groups: dict[tuple, list[ClassifiedThreat]] = {}

        for threat in threats:
            key = (threat.category, frozenset(threat.source_ips))
            groups.setdefault(key, []).append(threat)

        deduplicated: list[ClassifiedThreat] = []

        for group in groups.values():
            if len(group) == 1:
                deduplicated.append(group[0])
                continue

            merged_indices: set[int] = set()

            for i in range(len(group)):
                if i in merged_indices:
                    continue

                winner = group[i]

                for j in range(i + 1, len(group)):
                    if j in merged_indices:
                        continue

                    if not self._time_ranges_overlap(winner.time_range, group[j].time_range):
                        continue

                    merged_indices.add(j)
                    other = group[j]

                    if other.severity_score > winner.severity_score:
                        winner = other

                    methods = {winner.detection_method, other.detection_method}
                    if methods == {"rule", "ml"}:
                        winner.detection_method = "both"
                        winner.severity_score = min(winner.severity_score + 15, 100)

                    winner.source_ips = list(set(winner.source_ips) | set(other.source_ips))
                    winner.dest_ips = list(set(winner.dest_ips) | set(other.dest_ips))
                    winner.evidence = {**other.evidence, **winner.evidence}

                deduplicated.append(winner)

        return deduplicated

    @staticmethod
    def _time_ranges_overlap(range_a: str, range_b: str) -> bool:
        try:
            a_start, a_end = [s.strip() for s in range_a.split("\u2013")]
            b_start, b_end = [s.strip() for s in range_b.split("\u2013")]
            return a_start <= b_end and b_start <= a_end
        except (ValueError, AttributeError):
            return False
