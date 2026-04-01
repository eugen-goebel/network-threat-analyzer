"""Pipeline orchestrator — coordinates the 7-phase threat analysis workflow."""

import os
import time

from agents.pcap_parser import PcapParser
from agents.log_parser import LogParser
from agents.feature_extractor import FeatureExtractor
from agents.rule_engine import RuleEngine
from agents.anomaly_detector import AnomalyDetector
from agents.threat_classifier import ThreatClassifier
from agents.mock_data import (
    get_mock_report,
    get_mock_summary,
    get_mock_protocol_dist,
    get_mock_timeline,
    get_mock_anomaly_scores,
)
from utils.visualization import ChartGenerator
from utils.report_generator import ReportGenerator
from utils.pdf_report_generator import PDFReportGenerator
from models.reports import AnalysisSummary


class ThreatAnalysisOrchestrator:

    def __init__(self, output_dir: str = "output", report_format: str = "docx"):
        self.output_dir = output_dir
        self.report_format = report_format

    def run(self, filepaths: list[str]) -> str:
        start_time = time.time()

        # Phase 1-2: Parse inputs
        print("\n[1/7] Parsing input files...")
        parse_result = None
        log_result = None

        for fp in filepaths:
            ext = os.path.splitext(fp)[1].lower()
            if ext in (".pcap", ".pcapng") and parse_result is None:
                print(f"  Parsing PCAP: {fp}")
                parse_result = PcapParser().parse(fp)
                print(f"  {parse_result.packet_count} packets, {parse_result.unique_src_ips} unique sources")
            elif ext == ".log" and log_result is None:
                print(f"  Parsing log: {fp}")
                log_result = LogParser().parse(fp)
                print(f"  {log_result.entry_count} log entries")

        if parse_result is None:
            raise ValueError("At least one PCAP file is required")

        # Phase 3: Extract features
        print("\n[3/7] Extracting features...")
        extractor = FeatureExtractor()
        feature_matrix = extractor.extract(parse_result, log_result)
        print(f"  {len(feature_matrix.window_starts)} time windows, {len(feature_matrix.feature_names)} features")

        # Phase 4: Rule-based detection
        print("\n[4/7] Running rule-based detection...")
        engine = RuleEngine()
        rule_alerts = engine.analyze(parse_result, log_result)
        print(f"  {len(rule_alerts)} rule-based alerts")

        # Phase 5: ML anomaly detection
        print("\n[5/7] Running ML anomaly detection...")
        detector = AnomalyDetector()
        anomaly_alerts = detector.detect(feature_matrix)
        print(f"  {len(anomaly_alerts)} anomalous time windows")

        # Phase 6: Classify threats
        print("\n[6/7] Classifying threats...")
        classifier = ThreatClassifier()
        duration = time.time() - start_time
        threat_report = classifier.classify(
            rule_alerts, anomaly_alerts,
            parse_result.packet_count, parse_result.time_range, duration,
        )
        print(f"  {threat_report.total_threats} threats identified ({threat_report.critical_count} critical)")

        # Phase 7: Generate report
        print("\n[7/7] Generating report...")

        source_files = [os.path.basename(fp) for fp in filepaths]
        summary = AnalysisSummary(
            source_files=source_files,
            total_packets=parse_result.packet_count,
            total_log_entries=log_result.entry_count if log_result else 0,
            time_range=parse_result.time_range,
            unique_ips=parse_result.unique_src_ips + parse_result.unique_dst_ips,
            protocol_breakdown=parse_result.protocol_distribution,
            threat_summary=threat_report,
        )

        # Build traffic timeline from feature matrix
        pps_idx = feature_matrix.feature_names.index("packets_per_second")
        traffic_timeline = [
            (ws, float(feature_matrix.features[i][pps_idx]))
            for i, ws in enumerate(feature_matrix.window_starts)
        ]

        anomaly_scores = [
            (a.time_window_start, a.anomaly_score)
            for a in anomaly_alerts
        ]

        chart_gen = ChartGenerator(os.path.join(self.output_dir, "charts"))
        viz = chart_gen.generate_all(threat_report, parse_result.protocol_distribution, traffic_timeline, anomaly_scores)

        if self.report_format == "pdf":
            report_gen = PDFReportGenerator(self.output_dir)
        else:
            report_gen = ReportGenerator(self.output_dir)
        report_path = report_gen.generate(summary, viz)

        print(f"  Report saved to {report_path}")
        print(f"\nAnalysis complete in {duration:.1f}s")
        return report_path

    def run_demo(self) -> str:
        """Run with mock data for demonstration."""
        print("\n[Demo Mode] Using sample analysis data...\n")

        mock_report = get_mock_report()
        mock_summary = get_mock_summary()

        chart_gen = ChartGenerator(os.path.join(self.output_dir, "charts"))
        viz = chart_gen.generate_all(
            mock_report,
            get_mock_protocol_dist(),
            get_mock_timeline(),
            get_mock_anomaly_scores(),
        )

        if self.report_format == "pdf":
            report_gen = PDFReportGenerator(self.output_dir)
        else:
            report_gen = ReportGenerator(self.output_dir)
        report_path = report_gen.generate(mock_summary, viz)

        print(f"  Threats detected: {mock_report.total_threats}")
        print(f"    Critical: {mock_report.critical_count}")
        print(f"    High:     {mock_report.high_count}")
        print(f"    Medium:   {mock_report.medium_count}")
        print(f"    Low:      {mock_report.low_count}")
        print(f"\n  Report saved to {report_path}")
        return report_path
