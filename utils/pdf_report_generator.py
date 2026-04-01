"""PDF threat report generator using fpdf2."""

import os
from datetime import datetime

from fpdf import FPDF

from models.threats import ThreatReport, ClassifiedThreat
from models.reports import AnalysisSummary, VisualizationResult

BULLET = "-"

SEVERITY_COLORS = {
    "critical": (198, 40, 40),
    "high": (230, 81, 0),
    "medium": (249, 168, 37),
    "low": (13, 115, 119),
}

_UNICODE_REPLACEMENTS = {
    "\u2013": "-",
    "\u2014": "--",
    "\u2018": "'",
    "\u2019": "'",
    "\u201c": '"',
    "\u201d": '"',
    "\u2026": "...",
    "\u2022": "-",
    "\u20ac": "EUR",
    "\u00fc": "ue",
    "\u00e4": "ae",
    "\u00f6": "oe",
    "\u00dc": "Ue",
    "\u00c4": "Ae",
    "\u00d6": "Oe",
    "\u00df": "ss",
}


def _sanitize(text: str) -> str:
    """Replace Unicode characters that are not latin-1 compatible."""
    for char, replacement in _UNICODE_REPLACEMENTS.items():
        text = text.replace(char, replacement)
    return text.encode("latin-1", errors="replace").decode("latin-1")


class _ReportPDF(FPDF):

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Network Threat Analysis Report  |  Page {self.page_no()}", align="C")


class PDFReportGenerator:

    def __init__(self, output_dir: str = "output"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate(self, summary: AnalysisSummary, viz: VisualizationResult) -> str:
        pdf = _ReportPDF()
        pdf.set_auto_page_break(auto=True, margin=20)

        self._add_cover_page(pdf, summary)
        self._add_executive_summary(pdf, summary)
        self._add_traffic_overview(pdf, summary)
        self._add_protocol_analysis(pdf, summary, viz)
        self._add_threat_summary(pdf, summary)
        self._add_threat_details(pdf, summary)
        self._add_timeline_analysis(pdf, viz)
        self._add_recommendations(pdf, summary)
        self._add_methodology(pdf)

        filename = f"threat_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        filepath = os.path.join(self.output_dir, filename)
        pdf.output(filepath)
        return filepath

    def _add_cover_page(self, pdf: _ReportPDF, summary: AnalysisSummary):
        pdf.add_page()
        pdf.ln(50)
        pdf.set_font("Helvetica", "B", 28)
        pdf.set_text_color(26, 35, 126)
        pdf.cell(0, 14, _sanitize("NETWORK THREAT"), align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 14, _sanitize("ANALYSIS REPORT"), align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(10)

        pdf.set_font("Helvetica", "", 14)
        pdf.set_text_color(117, 117, 117)
        pdf.cell(0, 10, datetime.now().strftime("%B %d, %Y"), align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(15)

        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(66, 66, 66)
        lines = [
            f"Source files: {', '.join(summary.source_files)}",
            f"Total packets analyzed: {summary.total_packets:,}",
            f"Threats detected: {summary.threat_summary.total_threats}",
        ]
        for line in lines:
            pdf.cell(0, 8, _sanitize(line), align="C", new_x="LMARGIN", new_y="NEXT")

    def _add_heading(self, pdf: _ReportPDF, text: str, level: int = 1):
        if level == 1:
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 16)
            pdf.set_text_color(26, 35, 126)
        elif level == 2:
            pdf.ln(6)
            pdf.set_font("Helvetica", "B", 13)
            pdf.set_text_color(26, 35, 126)
        else:
            pdf.ln(4)
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(66, 66, 66)

        pdf.cell(0, 10, _sanitize(text), new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(26, 35, 126)
        pdf.set_line_width(0.4)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.ln(4)

    def _add_body_text(self, pdf: _ReportPDF, text: str):
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(33, 33, 33)
        pdf.multi_cell(0, 6, _sanitize(text))
        pdf.ln(3)

    def _add_bullet_list(self, pdf: _ReportPDF, items: list[str]):
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(33, 33, 33)
        for item in items:
            pdf.cell(5)
            pdf.cell(0, 6, _sanitize(f"{BULLET}  {item}"), new_x="LMARGIN", new_y="NEXT")

    def _add_executive_summary(self, pdf: _ReportPDF, summary: AnalysisSummary):
        self._add_heading(pdf, "Executive Summary")

        ts = summary.threat_summary
        categories = {}
        for threat in ts.threats:
            categories[threat.category] = categories.get(threat.category, 0) + 1
        top_category = max(categories, key=categories.get) if categories else "N/A"

        text = (
            f"Analysis of {summary.total_packets:,} packets over {summary.time_range} "
            f"identified {ts.total_threats} threats "
            f"({ts.critical_count} critical, {ts.high_count} high). "
            f"{top_category} was the most prevalent threat category."
        )
        self._add_body_text(pdf, text)

    def _add_traffic_overview(self, pdf: _ReportPDF, summary: AnalysisSummary):
        self._add_heading(pdf, "Traffic Overview")

        col_w = 90
        row_h = 8
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(26, 35, 126)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(col_w, row_h, "Metric", border=1, fill=True)
        pdf.cell(col_w, row_h, "Value", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(33, 33, 33)
        rows_data = [
            ("Total Packets", f"{summary.total_packets:,}"),
            ("Unique IPs", f"{summary.unique_ips:,}"),
            ("Time Range", summary.time_range),
            ("Protocols", ", ".join(summary.protocol_breakdown.keys())),
        ]
        for i, (label, value) in enumerate(rows_data):
            if i % 2 == 0:
                pdf.set_fill_color(245, 245, 245)
            else:
                pdf.set_fill_color(255, 255, 255)
            pdf.cell(col_w, row_h, _sanitize(label), border=1, fill=True)
            pdf.cell(col_w, row_h, _sanitize(value), border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

    def _add_protocol_analysis(
        self, pdf: _ReportPDF, summary: AnalysisSummary, viz: VisualizationResult,
    ):
        self._add_heading(pdf, "Protocol Analysis")

        total = sum(summary.protocol_breakdown.values()) or 1
        lines = []
        for proto, count in sorted(
            summary.protocol_breakdown.items(), key=lambda x: x[1], reverse=True,
        ):
            pct = count / total * 100
            lines.append(f"{proto}: {count:,} packets ({pct:.1f}%)")
        self._add_body_text(pdf, "\n".join(lines))

        chart_path = os.path.join(viz.chart_dir, "protocol_distribution.png")
        if os.path.exists(chart_path):
            pdf.image(chart_path, x=30, w=150)
            pdf.ln(5)

    def _add_threat_summary(self, pdf: _ReportPDF, summary: AnalysisSummary):
        self._add_heading(pdf, "Threat Summary")

        threats = summary.threat_summary.threats
        if not threats:
            self._add_body_text(pdf, "No threats detected.")
            return

        col_widths = [25, 40, 55, 35, 30]
        headers = ["Severity", "Category", "Title", "Source IPs", "Detection"]
        row_h = 7

        pdf.set_font("Helvetica", "B", 8)
        pdf.set_fill_color(26, 35, 126)
        pdf.set_text_color(255, 255, 255)
        for i, header in enumerate(headers):
            pdf.cell(col_widths[i], row_h, header, border=1, fill=True)
        pdf.ln()

        pdf.set_font("Helvetica", "", 8)
        for threat in threats:
            r, g, b = SEVERITY_COLORS.get(threat.severity_label, (117, 117, 117))
            pdf.set_fill_color(r, g, b)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(col_widths[0], row_h, threat.severity_label.upper(), border=1, fill=True)

            pdf.set_fill_color(255, 255, 255)
            pdf.set_text_color(33, 33, 33)
            pdf.cell(col_widths[1], row_h, _sanitize(threat.category), border=1)

            title_text = threat.title[:30] + "..." if len(threat.title) > 33 else threat.title
            pdf.cell(col_widths[2], row_h, _sanitize(title_text), border=1)

            ips_text = ", ".join(threat.source_ips[:2])
            if len(threat.source_ips) > 2:
                ips_text += f" (+{len(threat.source_ips) - 2})"
            pdf.cell(col_widths[3], row_h, _sanitize(ips_text), border=1)

            pdf.cell(col_widths[4], row_h, threat.detection_method, border=1, new_x="LMARGIN", new_y="NEXT")

    def _add_threat_details(self, pdf: _ReportPDF, summary: AnalysisSummary):
        self._add_heading(pdf, "Threat Details")

        threats = summary.threat_summary.threats[:10]
        for i, threat in enumerate(threats, 1):
            self._add_heading(pdf, f"{i}. {threat.title}", level=2)
            self._add_body_text(pdf, threat.description)

            if threat.evidence:
                self._add_heading(pdf, "Evidence", level=3)
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(33, 33, 33)
                for key, value in threat.evidence.items():
                    pdf.cell(5)
                    pdf.cell(0, 6, _sanitize(f"{BULLET}  {key}: {value}"), new_x="LMARGIN", new_y="NEXT")
                pdf.ln(2)

            if threat.source_ips:
                self._add_heading(pdf, "Affected IPs", level=3)
                self._add_body_text(pdf, ", ".join(threat.source_ips))

            if threat.recommendations:
                self._add_heading(pdf, "Recommendations", level=3)
                self._add_bullet_list(pdf, threat.recommendations)

    def _add_timeline_analysis(self, pdf: _ReportPDF, viz: VisualizationResult):
        self._add_heading(pdf, "Timeline Analysis")

        chart_path = os.path.join(viz.chart_dir, "traffic_timeline.png")
        if os.path.exists(chart_path):
            pdf.image(chart_path, x=15, w=180)
            pdf.ln(5)

        anomaly_path = os.path.join(viz.chart_dir, "anomaly_scores.png")
        if os.path.exists(anomaly_path):
            pdf.image(anomaly_path, x=15, w=180)
            pdf.ln(5)

        if not os.path.exists(chart_path) and not os.path.exists(anomaly_path):
            self._add_body_text(pdf, "No timeline charts available.")

    def _add_recommendations(self, pdf: _ReportPDF, summary: AnalysisSummary):
        self._add_heading(pdf, "Recommendations")

        seen = set()
        prioritized = []
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        sorted_threats = sorted(
            summary.threat_summary.threats,
            key=lambda t: severity_order.get(t.severity_label, 4),
        )
        for threat in sorted_threats:
            for rec in threat.recommendations:
                if rec not in seen:
                    seen.add(rec)
                    prioritized.append((threat.severity_label, rec))

        if not prioritized:
            self._add_body_text(pdf, "No specific recommendations at this time.")
            return

        col_widths = [10, 25, 150]
        row_h = 7

        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(26, 35, 126)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(col_widths[0], row_h, "#", border=1, fill=True)
        pdf.cell(col_widths[1], row_h, "Priority", border=1, fill=True)
        pdf.cell(col_widths[2], row_h, "Recommendation", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "", 9)
        for i, (severity, rec) in enumerate(prioritized, 1):
            pdf.set_text_color(33, 33, 33)
            pdf.cell(col_widths[0], row_h, str(i), border=1)

            r, g, b = SEVERITY_COLORS.get(severity, (117, 117, 117))
            pdf.set_fill_color(r, g, b)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(col_widths[1], row_h, severity.upper(), border=1, fill=True)

            pdf.set_text_color(33, 33, 33)
            pdf.cell(col_widths[2], row_h, _sanitize(rec), border=1, new_x="LMARGIN", new_y="NEXT")

    def _add_methodology(self, pdf: _ReportPDF):
        self._add_heading(pdf, "Methodology")

        paragraphs = [
            "This analysis employed a dual-layer detection approach combining "
            "rule-based signature matching with machine learning ensemble models.",
            "Rule-based detection applied protocol-aware pattern matching against "
            "known attack signatures, including port scan heuristics, volumetric "
            "thresholds for DDoS identification, and brute-force attempt correlation.",
            "The ML ensemble combined Isolation Forest, Local Outlier Factor, and "
            "One-Class SVM models trained on baseline traffic profiles. Anomaly "
            "scores were computed as weighted consensus across model votes, with "
            "a detection threshold of 0.5.",
            "Threats flagged by both detection layers received elevated confidence "
            "scoring. Final severity classification incorporated threat category, "
            "affected scope, and temporal persistence.",
        ]
        for text in paragraphs:
            self._add_body_text(pdf, text)
