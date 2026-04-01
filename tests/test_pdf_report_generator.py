"""Tests for the PDF report generator."""

import os

import pytest

from models.reports import AnalysisSummary, VisualizationResult
from models.threats import ClassifiedThreat, ThreatReport
from utils.pdf_report_generator import PDFReportGenerator, _sanitize


@pytest.fixture
def threat_report_with_threats():
    threats = [
        ClassifiedThreat(
            category="PORT_SCAN",
            severity_score=85,
            severity_label="critical",
            title="Vertical Port Scan from 192.168.1.100",
            description="Vertical port scan detected targeting 25 ports",
            detection_method="rule",
            source_ips=["192.168.1.100"],
            dest_ips=["10.0.0.1"],
            time_range="2026-03-15T10:00:00 - 2026-03-15T10:01:00",
            evidence={"scan_type": "vertical", "ports_scanned": 25},
            recommendations=["Block source IP at firewall"],
        ),
        ClassifiedThreat(
            category="SUSPICIOUS_CONNECTION",
            severity_score=45,
            severity_label="medium",
            title="Suspicious Connection to 10.0.0.1",
            description="Traffic on suspicious port 4444",
            detection_method="rule",
            source_ips=["192.168.1.50"],
            dest_ips=["10.0.0.1"],
            time_range="2026-03-15T10:00:00 - 2026-03-15T10:00:00",
            evidence={"port": 4444},
            recommendations=["Isolate affected host for investigation"],
        ),
    ]
    return ThreatReport(
        total_threats=2,
        critical_count=1,
        high_count=0,
        medium_count=1,
        low_count=0,
        threats=threats,
        analysis_duration_seconds=5.0,
        packets_analyzed=1000,
        time_range_analyzed="2026-03-15T10:00:00 - 2026-03-15T10:01:00",
    )


@pytest.fixture
def empty_threat_report():
    return ThreatReport(
        total_threats=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        threats=[],
        analysis_duration_seconds=1.0,
        packets_analyzed=100,
        time_range_analyzed="2026-03-15T10:00:00 - 2026-03-15T10:00:10",
    )


@pytest.fixture
def analysis_summary(threat_report_with_threats):
    return AnalysisSummary(
        source_files=["test_capture.pcap"],
        total_packets=1000,
        total_log_entries=50,
        time_range="2026-03-15T10:00:00 - 2026-03-15T10:01:00",
        unique_ips=15,
        protocol_breakdown={"TCP": 600, "UDP": 250, "ICMP": 100, "DNS": 50},
        threat_summary=threat_report_with_threats,
    )


@pytest.fixture
def empty_analysis_summary(empty_threat_report):
    return AnalysisSummary(
        source_files=["empty.pcap"],
        total_packets=100,
        total_log_entries=0,
        time_range="2026-03-15T10:00:00 - 2026-03-15T10:00:10",
        unique_ips=5,
        protocol_breakdown={"TCP": 80, "UDP": 20},
        threat_summary=empty_threat_report,
    )


@pytest.fixture
def viz_result(tmp_path):
    return VisualizationResult(chart_dir=str(tmp_path), charts=[])


@pytest.fixture
def pdf_generator(tmp_path):
    output_dir = str(tmp_path / "reports")
    return PDFReportGenerator(output_dir=output_dir)


class TestPDFGeneration:

    def test_generate_creates_pdf(self, pdf_generator, analysis_summary, viz_result):
        filepath = pdf_generator.generate(analysis_summary, viz_result)
        assert os.path.exists(filepath)
        assert filepath.endswith(".pdf")

    def test_pdf_header(self, pdf_generator, analysis_summary, viz_result):
        filepath = pdf_generator.generate(analysis_summary, viz_result)
        with open(filepath, "rb") as f:
            header = f.read(5)
        assert header == b"%PDF-"

    def test_file_not_empty(self, pdf_generator, analysis_summary, viz_result):
        filepath = pdf_generator.generate(analysis_summary, viz_result)
        assert os.path.getsize(filepath) > 1000

    def test_filename_format(self, pdf_generator, analysis_summary, viz_result):
        filepath = pdf_generator.generate(analysis_summary, viz_result)
        filename = os.path.basename(filepath)
        assert filename.startswith("threat_analysis_")
        assert filename.endswith(".pdf")

    def test_creates_output_directory(self, tmp_path, analysis_summary, viz_result):
        nested_dir = str(tmp_path / "deep" / "nested" / "output")
        generator = PDFReportGenerator(output_dir=nested_dir)
        filepath = generator.generate(analysis_summary, viz_result)
        assert os.path.exists(filepath)

    def test_zero_threats(self, pdf_generator, empty_analysis_summary, viz_result):
        filepath = pdf_generator.generate(empty_analysis_summary, viz_result)
        assert os.path.exists(filepath)
        assert os.path.getsize(filepath) > 1000

    def test_special_characters(self, pdf_generator, viz_result):
        """Ensure Unicode in fields does not crash the generator."""
        threats = [
            ClassifiedThreat(
                category="PORT_SCAN",
                severity_score=70,
                severity_label="high",
                title="Scan from Muellerstrasse",
                description="Port scan with 500+ connections",
                detection_method="both",
                source_ips=["10.0.0.1"],
                dest_ips=["10.0.0.2"],
                time_range="2026-03-15T10:00:00 - 2026-03-15T10:05:00",
                evidence={"connections": 512},
                recommendations=["Block offending IP range"],
            ),
        ]
        report = ThreatReport(
            total_threats=1, critical_count=0, high_count=1, medium_count=0,
            low_count=0, threats=threats, analysis_duration_seconds=2.0,
            packets_analyzed=500, time_range_analyzed="2026-03-15T10:00:00 - 2026-03-15T10:05:00",
        )
        summary = AnalysisSummary(
            source_files=["capture.pcap"],
            total_packets=500,
            total_log_entries=0,
            time_range="2026-03-15T10:00:00 - 2026-03-15T10:05:00",
            unique_ips=10,
            protocol_breakdown={"TCP": 400, "UDP": 100},
            threat_summary=report,
        )
        filepath = pdf_generator.generate(summary, viz_result)
        assert os.path.exists(filepath)


class TestSanitize:

    def test_replaces_en_dash(self):
        assert _sanitize("2026\u201303\u201315") == "2026-03-15"

    def test_replaces_smart_quotes(self):
        assert _sanitize("\u201chello\u201d") == '"hello"'

    def test_passes_through_ascii(self):
        assert _sanitize("hello world 123") == "hello world 123"

    def test_replaces_umlaut(self):
        assert _sanitize("M\u00fcller") == "Mueller"
