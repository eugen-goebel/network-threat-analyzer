"""Mock analysis data for demo mode — enables running without input files."""

from models.threats import ClassifiedThreat, ThreatReport
from models.reports import AnalysisSummary


def get_mock_report() -> ThreatReport:
    threats = [
        ClassifiedThreat(
            category="DDOS_ATTACK",
            severity_score=90,
            severity_label="critical",
            title="SYN Flood targeting 10.0.0.1:80",
            description=(
                "High-rate SYN packets from 15 unique sources targeting HTTP service. "
                "Classic volumetric DDoS pattern."
            ),
            source_ips=["172.16.0.1", "172.16.0.5", "172.16.0.8", "172.16.0.12", "172.16.0.15"],
            dest_ips=["10.0.0.1"],
            time_range="2026-03-15T10:03:00 – 2026-03-15T10:03:10",
            evidence={"flood_type": "syn", "packets_per_second": 80.0, "source_count": 15},
            detection_method="rule",
            recommendations=[
                "Enable rate limiting on affected services",
                "Configure SYN cookies",
                "Contact upstream provider for traffic scrubbing",
            ],
        ),
        ClassifiedThreat(
            category="SUSPICIOUS_CONNECTION",
            severity_score=85,
            severity_label="critical",
            title="C2 Beaconing to 198.51.100.1:8888",
            description=(
                "Regular 60-second interval connections to external host on non-standard port. "
                "Consistent with command-and-control beaconing."
            ),
            source_ips=["192.168.1.50"],
            dest_ips=["198.51.100.1"],
            time_range="2026-03-15T10:00:30 – 2026-03-15T10:04:30",
            evidence={
                "detection_type": "beaconing",
                "avg_interval_seconds": 60.0,
                "std_deviation": 0.5,
                "beacon_count": 5,
                "port": 8888,
            },
            detection_method="rule",
            recommendations=[
                "Isolate affected host for investigation",
                "Block communication to suspicious destination",
                "Conduct forensic analysis of the endpoint",
            ],
        ),
        ClassifiedThreat(
            category="PORT_SCAN",
            severity_score=75,
            severity_label="high",
            title="Vertical Port Scan from 192.168.1.100",
            description=(
                "Sequential scan of 80 ports on 10.0.0.1 within 30 seconds. "
                "Typical reconnaissance activity."
            ),
            source_ips=["192.168.1.100"],
            dest_ips=["10.0.0.1"],
            time_range="2026-03-15T10:01:00 – 2026-03-15T10:01:30",
            evidence={"scan_type": "vertical", "ports_scanned": 80, "duration_seconds": 30},
            detection_method="both",
            recommendations=[
                "Block source IP at firewall",
                "Review firewall rules for exposed ports",
                "Enable IDS/IPS signatures for scan detection",
            ],
        ),
        ClassifiedThreat(
            category="BRUTE_FORCE",
            severity_score=65,
            severity_label="high",
            title="SSH Brute Force from 10.99.88.77",
            description=(
                "12 failed SSH login attempts for root within 45 seconds, "
                "followed by successful authentication."
            ),
            source_ips=["10.99.88.77"],
            dest_ips=["10.0.0.1"],
            time_range="2026-03-15T10:02:00 – 2026-03-15T10:02:45",
            evidence={
                "attack_type": "ssh",
                "attempts": 12,
                "duration_seconds": 45,
                "success_after_brute": True,
            },
            detection_method="rule",
            recommendations=[
                "Implement account lockout policies",
                "Enable fail2ban or similar",
                "Enforce strong passwords and MFA",
            ],
        ),
        ClassifiedThreat(
            category="SUSPICIOUS_CONNECTION",
            severity_score=60,
            severity_label="high",
            title="Potential Data Exfiltration to 203.0.113.99",
            description=(
                "Large outbound data transfer from internal host to external "
                "destination over HTTPS."
            ),
            source_ips=["192.168.1.30"],
            dest_ips=["203.0.113.99"],
            time_range="2026-03-15T10:04:00 – 2026-03-15T10:04:05",
            evidence={
                "detection_type": "data_exfiltration",
                "bytes_transferred": 7500,
                "destination": "203.0.113.99",
            },
            detection_method="rule",
            recommendations=[
                "Investigate data transfer contents",
                "Review DLP policies",
                "Check for unauthorized cloud storage usage",
            ],
        ),
        ClassifiedThreat(
            category="ANOMALOUS_TRAFFIC",
            severity_score=55,
            severity_label="medium",
            title="Anomalous Traffic Detected (10:03:00)",
            description=(
                "ML ensemble flagged unusual network behavior. Contributing factors: "
                "packets_per_second (8.2x above baseline), unique_src_ips (5.1x above baseline)"
            ),
            source_ips=[],
            dest_ips=[],
            time_range="2026-03-15T10:03:00 – 2026-03-15T10:04:00",
            evidence={
                "anomaly_score": 0.82,
                "model_votes": {
                    "isolation_forest": -1,
                    "local_outlier_factor": -1,
                    "one_class_svm": -1,
                },
            },
            detection_method="ml",
            recommendations=[
                "Investigate traffic patterns in the flagged time window",
                "Correlate with system logs for additional context",
            ],
        ),
    ]

    return ThreatReport(
        total_threats=6,
        critical_count=2,
        high_count=3,
        medium_count=1,
        low_count=0,
        threats=threats,
        analysis_duration_seconds=3.2,
        packets_analyzed=485,
        time_range_analyzed="2026-03-15T10:00:00 – 2026-03-15T10:05:00",
    )


def get_mock_summary() -> AnalysisSummary:
    return AnalysisSummary(
        source_files=["sample_capture.pcap", "sample_syslog.log"],
        total_packets=485,
        total_log_entries=200,
        time_range="2026-03-15T10:00:00 – 2026-03-15T10:05:00",
        unique_ips=42,
        protocol_breakdown={"TCP": 350, "UDP": 80, "ICMP": 30, "DNS": 25},
        threat_summary=get_mock_report(),
    )


def get_mock_protocol_dist() -> dict[str, int]:
    return {"TCP": 350, "UDP": 80, "ICMP": 30, "DNS": 25}


def get_mock_timeline() -> list[tuple[str, float]]:
    return [
        ("10:00", 1.5),
        ("10:01", 3.2),
        ("10:02", 1.8),
        ("10:03", 12.5),
        ("10:04", 2.1),
    ]


def get_mock_anomaly_scores() -> list[tuple[str, float]]:
    return [
        ("10:00", 0.15),
        ("10:01", 0.35),
        ("10:02", 0.22),
        ("10:03", 0.82),
        ("10:04", 0.28),
    ]
