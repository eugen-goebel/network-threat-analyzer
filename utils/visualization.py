"""Chart generation for threat analysis reports and dashboard."""

import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.colors
import numpy as np

from models.threats import ThreatReport, ClassifiedThreat
from models.reports import ChartConfig, VisualizationResult

COLOR_CRITICAL = "#C62828"
COLOR_HIGH = "#E65100"
COLOR_MEDIUM = "#F9A825"
COLOR_LOW = "#0D7377"
COLOR_INFO = "#1565C0"
COLOR_BG = "#FAFAFA"


class ChartGenerator:

    def __init__(self, output_dir: str = "output/charts"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_all(
        self,
        threat_report: ThreatReport,
        protocol_dist: dict[str, int],
        traffic_timeline: list[tuple[str, float]],
        anomaly_scores: list[tuple[str, float]],
        port_counts: dict[int, int] = None,
    ) -> VisualizationResult:
        charts = []

        charts.append(self._protocol_pie(protocol_dist))
        charts.append(self._severity_bar(threat_report))

        anomaly_times = [
            ts for ts, score in anomaly_scores if score > 0.5
        ]
        charts.append(self._traffic_timeline(traffic_timeline, anomaly_times))
        charts.append(self._anomaly_scatter(anomaly_scores))

        if port_counts is not None:
            charts.append(self._top_ports_bar(port_counts))

        return VisualizationResult(chart_dir=self.output_dir, charts=charts)

    def _protocol_pie(self, protocol_dist: dict[str, int]) -> ChartConfig:
        color_map = {
            "TCP": "#1565C0",
            "UDP": "#2E7D32",
            "ICMP": "#C62828",
            "DNS": "#F9A825",
        }
        labels = list(protocol_dist.keys())
        sizes = list(protocol_dist.values())
        colors = [color_map.get(label.upper(), "#757575") for label in labels]

        fig = plt.figure(figsize=(8, 6), facecolor=COLOR_BG)
        ax = fig.add_subplot(111)
        ax.set_facecolor(COLOR_BG)
        ax.pie(
            sizes,
            labels=labels,
            colors=colors,
            autopct="%1.1f%%",
            startangle=140,
            textprops={"fontsize": 10},
        )
        ax.set_title("Protocol Distribution", fontsize=14, fontweight="bold")
        fig.tight_layout()

        path = os.path.join(self.output_dir, "protocol_distribution.png")
        plt.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)

        return ChartConfig(
            filename="protocol_distribution.png",
            chart_type="pie",
            title="Protocol Distribution",
            description="Breakdown of captured packets by network protocol.",
        )

    def _traffic_timeline(
        self,
        timeline: list[tuple[str, float]],
        anomaly_times: list[str],
    ) -> ChartConfig:
        labels = [t[0] for t in timeline]
        values = [t[1] for t in timeline]

        fig = plt.figure(figsize=(12, 5), facecolor=COLOR_BG)
        ax = fig.add_subplot(111)
        ax.set_facecolor(COLOR_BG)

        ax.plot(range(len(values)), values, color=COLOR_INFO, linewidth=1.5)
        ax.fill_between(range(len(values)), values, alpha=0.15, color=COLOR_INFO)

        for i, label in enumerate(labels):
            if label in anomaly_times:
                ax.axvspan(i - 0.5, i + 0.5, color=COLOR_CRITICAL, alpha=0.15)

        ax.set_xlabel("Time Window", fontsize=10)
        ax.set_ylabel("Packets/sec", fontsize=10)
        ax.set_title("Traffic Timeline", fontsize=14, fontweight="bold")

        tick_step = max(1, len(labels) // 20)
        ax.set_xticks(range(0, len(labels), tick_step))
        ax.set_xticklabels(labels[::tick_step], rotation=45, ha="right", fontsize=7)

        fig.tight_layout()
        path = os.path.join(self.output_dir, "traffic_timeline.png")
        plt.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)

        return ChartConfig(
            filename="traffic_timeline.png",
            chart_type="line",
            title="Traffic Timeline",
            description="Packets per second over time with anomalous windows highlighted.",
        )

    def _severity_bar(self, threat_report: ThreatReport) -> ChartConfig:
        categories = ["Critical", "High", "Medium", "Low"]
        counts = [
            threat_report.critical_count,
            threat_report.high_count,
            threat_report.medium_count,
            threat_report.low_count,
        ]
        colors = [COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW]

        fig = plt.figure(figsize=(8, 5), facecolor=COLOR_BG)
        ax = fig.add_subplot(111)
        ax.set_facecolor(COLOR_BG)

        bars = ax.barh(categories, counts, color=colors, edgecolor="white", height=0.6)
        for bar, count in zip(bars, counts):
            if count > 0:
                ax.text(
                    bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                    str(count), va="center", fontsize=10, fontweight="bold",
                )

        ax.set_xlabel("Number of Threats", fontsize=10)
        ax.set_title("Threats by Severity", fontsize=14, fontweight="bold")
        ax.invert_yaxis()

        fig.tight_layout()
        path = os.path.join(self.output_dir, "threat_severity.png")
        plt.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)

        return ChartConfig(
            filename="threat_severity.png",
            chart_type="bar",
            title="Threats by Severity",
            description="Horizontal bar chart of threat counts grouped by severity level.",
        )

    def _top_ports_bar(self, port_counts: dict[int, int]) -> ChartConfig:
        sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:15]
        ports = [str(p[0]) for p in sorted_ports]
        counts = [p[1] for p in sorted_ports]

        fig = plt.figure(figsize=(8, 6), facecolor=COLOR_BG)
        ax = fig.add_subplot(111)
        ax.set_facecolor(COLOR_BG)

        ax.barh(ports, counts, color=COLOR_INFO, edgecolor="white", height=0.6)
        ax.set_xlabel("Connection Count", fontsize=10)
        ax.set_title("Top 15 Destination Ports", fontsize=14, fontweight="bold")
        ax.invert_yaxis()

        fig.tight_layout()
        path = os.path.join(self.output_dir, "top_ports.png")
        plt.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)

        return ChartConfig(
            filename="top_ports.png",
            chart_type="bar",
            title="Top 15 Destination Ports",
            description="Most frequently targeted destination ports by connection count.",
        )

    def _anomaly_scatter(self, anomaly_scores: list[tuple[str, float]]) -> ChartConfig:
        indices = list(range(len(anomaly_scores)))
        scores = [s[1] for s in anomaly_scores]

        point_colors = []
        for score in scores:
            if score > 0.7:
                point_colors.append(COLOR_CRITICAL)
            elif score > 0.4:
                point_colors.append(COLOR_HIGH)
            else:
                point_colors.append(COLOR_LOW)

        fig = plt.figure(figsize=(10, 5), facecolor=COLOR_BG)
        ax = fig.add_subplot(111)
        ax.set_facecolor(COLOR_BG)

        ax.scatter(indices, scores, c=point_colors, s=30, alpha=0.8, edgecolors="white", linewidths=0.5)
        ax.axhline(y=0.5, color=COLOR_CRITICAL, linestyle="--", linewidth=1, alpha=0.6)

        ax.set_xlabel("Time Window Index", fontsize=10)
        ax.set_ylabel("Anomaly Score", fontsize=10)
        ax.set_ylim(-0.05, 1.05)
        ax.set_title("Anomaly Score Distribution", fontsize=14, fontweight="bold")

        fig.tight_layout()
        path = os.path.join(self.output_dir, "anomaly_scores.png")
        plt.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)

        return ChartConfig(
            filename="anomaly_scores.png",
            chart_type="scatter",
            title="Anomaly Score Distribution",
            description="Per-window anomaly scores with threshold line at 0.5.",
        )
