"""Chart generation for threat analysis reports and dashboard."""

import math
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.colors
import matplotlib.pyplot as plt
from matplotlib.figure import Figure

from models.reports import ChartConfig, VisualizationResult
from models.threats import ThreatReport
from utils.timefmt import short_time

COLOR_CRITICAL = "#C62828"
COLOR_HIGH = "#E65100"
COLOR_MEDIUM = "#F9A825"
COLOR_LOW = "#0D7377"
COLOR_INFO = "#1565C0"
COLOR_BG = "#FAFAFA"
COLOR_NEUTRAL = "#9aa5b1"

ANOMALY_FLAGGED = "Flagged by ensemble"
ANOMALY_NORMAL = "Not flagged"

# Same wording as the dashboard caption in app.py. The flag is a vote, not a
# cut-off on the score, so no threshold is drawn or mentioned.
ANOMALY_DESCRIPTION = (
    "Isolation Forest score of every time window, scaled within this capture "
    "(1 = most unusual window, so the top window always reads 1.0). A window "
    "is flagged (red) when at least two of the three models vote outlier, so a "
    "flagged window does not always have the highest score."
)
TIMELINE_DESCRIPTION = (
    "Packets per second over time. Shaded windows were flagged by the anomaly "
    "ensemble (at least two of the three models voted outlier); without shading "
    "no window was flagged."
)

# One (time window start, score, flagged by the ensemble) entry per time window.
AnomalyWindows = list[tuple[str, float, bool]]


def _time_ticks(labels: list[str]) -> tuple[list[int], list[str]]:
    """Tick positions and clock-time labels, thinned to about 20 ticks."""
    step = max(1, math.ceil(len(labels) / 20))
    positions = list(range(0, len(labels), step))
    return positions, [short_time(labels[i]) for i in positions]


def _no_scores_message(window_count: int) -> str:
    # Imported here: agents/__init__ imports the orchestrator, which imports this module.
    from agents.anomaly_detector import MIN_WINDOWS

    return (
        f"No anomaly scores: the models need at least {MIN_WINDOWS} time windows "
        f"and this capture has {window_count}."
    )


class ChartGenerator:
    def __init__(self, output_dir: str = "output/charts"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_all(
        self,
        threat_report: ThreatReport,
        protocol_dist: dict[str, int],
        traffic_timeline: list[tuple[str, float]],
        anomaly_windows: AnomalyWindows,
        port_counts: dict[int, int] = None,
    ) -> VisualizationResult:
        """Write all report charts.

        anomaly_windows holds every time window with its score and the ensemble
        decision; it is empty when the capture is too short to score.
        """
        charts = []

        charts.append(self._protocol_pie(protocol_dist))
        charts.append(self._severity_bar(threat_report))

        charts.append(self._traffic_timeline(traffic_timeline, anomaly_windows))
        charts.append(self._anomaly_scatter(anomaly_windows, len(traffic_timeline)))

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
        # matplotlib 3.11 raises "All wedge sizes are zero" when every value is
        # zero or the data is empty, so fall back to a placeholder in that case.
        if sum(sizes) > 0:
            ax.pie(
                sizes,
                labels=labels,
                colors=colors,
                autopct="%1.1f%%",
                startangle=140,
                textprops={"fontsize": 10},
            )
        else:
            ax.text(
                0.5,
                0.5,
                "No protocol data",
                ha="center",
                va="center",
                fontsize=12,
                color="#757575",
            )
            ax.axis("off")
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

    def _timeline_figure(
        self,
        timeline: list[tuple[str, float]],
        anomaly_windows: AnomalyWindows,
    ) -> Figure:
        labels = [t[0] for t in timeline]
        values = [t[1] for t in timeline]
        # Shade what the ensemble flagged, never a window picked by its score.
        flagged = {ts for ts, _, is_flagged in anomaly_windows if is_flagged}

        fig = plt.figure(figsize=(12, 5), facecolor=COLOR_BG)
        ax = fig.add_subplot(111)
        ax.set_facecolor(COLOR_BG)

        ax.plot(range(len(values)), values, color=COLOR_INFO, linewidth=1.5)
        ax.fill_between(range(len(values)), values, alpha=0.15, color=COLOR_INFO)

        shaded = False
        for i, label in enumerate(labels):
            if label in flagged:
                ax.axvspan(
                    i - 0.5,
                    i + 0.5,
                    color=COLOR_CRITICAL,
                    alpha=0.15,
                    label=None if shaded else ANOMALY_FLAGGED,
                )
                shaded = True
        if shaded:
            ax.legend(loc="upper right")

        ax.set_xlabel("Time Window", fontsize=10)
        ax.set_ylabel("Packets/sec", fontsize=10)
        ax.set_title("Traffic Timeline", fontsize=14, fontweight="bold")

        positions, tick_labels = _time_ticks(labels)
        ax.set_xticks(positions)
        ax.set_xticklabels(tick_labels, rotation=45, ha="right", fontsize=7)

        fig.tight_layout()
        return fig

    def _traffic_timeline(
        self,
        timeline: list[tuple[str, float]],
        anomaly_windows: AnomalyWindows,
    ) -> ChartConfig:
        fig = self._timeline_figure(timeline, anomaly_windows)
        path = os.path.join(self.output_dir, "traffic_timeline.png")
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)

        return ChartConfig(
            filename="traffic_timeline.png",
            chart_type="line",
            title="Traffic Timeline",
            description=TIMELINE_DESCRIPTION,
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
        for bar, count in zip(bars, counts, strict=False):
            if count > 0:
                ax.text(
                    bar.get_width() + 0.3,
                    bar.get_y() + bar.get_height() / 2,
                    str(count),
                    va="center",
                    fontsize=10,
                    fontweight="bold",
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

    def _anomaly_figure(self, windows: AnomalyWindows, window_count: int) -> Figure:
        fig = plt.figure(figsize=(10, 5), facecolor=COLOR_BG)
        ax = fig.add_subplot(111)
        ax.set_facecolor(COLOR_BG)
        # pad leaves room for the legend between the title and the plot
        ax.set_title("Anomaly Scores per Time Window", fontsize=14, fontweight="bold", pad=26)

        if not windows:
            ax.text(
                0.5,
                0.5,
                _no_scores_message(window_count),
                ha="center",
                va="center",
                fontsize=12,
                color="#757575",
            )
            ax.axis("off")
            fig.tight_layout()
            return fig

        scores = [w[1] for w in windows]
        # The curve shows the score of every window; the flag is the ensemble vote.
        ax.plot(range(len(scores)), scores, color=COLOR_NEUTRAL, linewidth=1.2, zorder=1)
        for flagged, color, label in (
            (False, COLOR_INFO, ANOMALY_NORMAL),
            (True, COLOR_CRITICAL, ANOMALY_FLAGGED),
        ):
            idx = [i for i, w in enumerate(windows) if w[2] == flagged]
            ax.scatter(
                idx,
                [scores[i] for i in idx],
                color=color,
                label=label,
                s=45,
                zorder=2,
                edgecolors="white",
                linewidths=0.5,
            )

        ax.set_xlabel("Time window start", fontsize=10)
        ax.set_ylabel("Anomaly score (scaled Isolation Forest)", fontsize=10)
        ax.set_ylim(-0.05, 1.05)
        positions, tick_labels = _time_ticks([w[0] for w in windows])
        ax.set_xticks(positions)
        ax.set_xticklabels(tick_labels, rotation=45, ha="right", fontsize=7)
        ax.legend(loc="lower right", bbox_to_anchor=(1.0, 1.0), ncol=2, frameon=False)

        fig.tight_layout()
        return fig

    def _anomaly_scatter(self, windows: AnomalyWindows, window_count: int) -> ChartConfig:
        fig = self._anomaly_figure(windows, window_count)
        path = os.path.join(self.output_dir, "anomaly_scores.png")
        fig.savefig(path, dpi=150, bbox_inches="tight")
        plt.close(fig)

        description = ANOMALY_DESCRIPTION if windows else _no_scores_message(window_count)
        return ChartConfig(
            filename="anomaly_scores.png",
            chart_type="scatter",
            title="Anomaly Scores per Time Window",
            description=description,
        )
