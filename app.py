"""Network Threat Analyzer — Streamlit dashboard for interactive threat analysis."""

import os
import tempfile

import streamlit as st
import pandas as pd

from agents.orchestrator import ThreatAnalysisOrchestrator
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
from models.reports import AnalysisSummary

st.set_page_config(page_title="Network Threat Analyzer", page_icon="🛡", layout="wide")

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

st.sidebar.title("Network Threat Analyzer")
st.sidebar.markdown("---")

uploaded_files = st.sidebar.file_uploader(
    "Upload PCAP or Log files",
    type=["pcap", "pcapng", "log"],
    accept_multiple_files=True,
)

st.sidebar.markdown("---")
demo_clicked = st.sidebar.button("Load Demo Data", use_container_width=True)
st.sidebar.markdown("---")

with st.sidebar.expander("Settings"):
    sensitivity = st.sidebar.slider("Anomaly Sensitivity", 0.01, 0.15, 0.05, 0.01)
    window_size = st.sidebar.selectbox("Time Window", [30, 60, 120], index=1)

# ---------------------------------------------------------------------------
# Helper — build threat table
# ---------------------------------------------------------------------------


def _threats_dataframe(threats):
    rows = []
    for t in threats:
        rows.append(
            {
                "Severity": t.severity_label.upper(),
                "Category": t.category,
                "Title": t.title,
                "Source IPs": ", ".join(t.source_ips) if t.source_ips else "N/A",
                "Detection": t.detection_method,
            }
        )
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Helper — display results
# ---------------------------------------------------------------------------


def display_results(threat_report, protocol_dist, timeline, anomaly_scores):
    # --- Header metrics ---
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Threats", threat_report.total_threats)
    c2.metric("Critical", threat_report.critical_count)
    c3.metric("High", threat_report.high_count)
    c4.metric("Packets Analyzed", threat_report.packets_analyzed)

    # --- Tabs ---
    tab_overview, tab_details = st.tabs(["Threat Overview", "Analysis Details"])

    # Tab 1 — Threat Overview
    with tab_overview:
        threats = threat_report.threats
        if threats:
            df_threats = _threats_dataframe(threats)
            st.dataframe(
                df_threats,
                column_config={
                    "Severity": st.column_config.TextColumn("Severity", width="small"),
                    "Category": st.column_config.TextColumn("Category"),
                    "Title": st.column_config.TextColumn("Title"),
                    "Source IPs": st.column_config.TextColumn("Source IPs"),
                    "Detection": st.column_config.TextColumn("Detection"),
                },
                use_container_width=True,
                hide_index=True,
            )

            for t in threats:
                with st.expander(f"{t.severity_label.upper()} — {t.title}"):
                    st.markdown(f"**Description:** {t.description}")
                    st.markdown("**Evidence:**")
                    st.json(t.evidence)
                    st.markdown("**Recommendations:**")
                    for rec in t.recommendations:
                        st.markdown(f"- {rec}")
        else:
            st.info("No threats detected in the analyzed data.")

    # Tab 2 — Analysis Details
    with tab_details:
        st.subheader("Protocol Distribution")
        left, right = st.columns(2)
        with left:
            df_proto = pd.DataFrame(
                list(protocol_dist.items()), columns=["Protocol", "Count"]
            ).set_index("Protocol")
            st.bar_chart(df_proto)
        with right:
            for proto, count in protocol_dist.items():
                st.metric(proto, count)

        st.subheader("Traffic Timeline")
        df_timeline = pd.DataFrame(timeline)
        if "timestamp" in df_timeline.columns:
            df_timeline = df_timeline.set_index("timestamp")
        st.line_chart(df_timeline)

        st.subheader("Anomaly Scores")
        df_anomaly = pd.DataFrame(anomaly_scores)
        if "timestamp" in df_anomaly.columns:
            df_anomaly = df_anomaly.set_index("timestamp")
        st.line_chart(df_anomaly)

    # --- Report download ---
    st.markdown("---")
    report_gen = ReportGenerator()
    docx_bytes = report_gen.generate_docx(threat_report)
    st.download_button(
        label="Download DOCX Report",
        data=docx_bytes,
        file_name="threat_report.docx",
        mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )


# ---------------------------------------------------------------------------
# Helper — run full analysis pipeline
# ---------------------------------------------------------------------------


def run_analysis(file_paths, sensitivity_val, window):
    orchestrator = ThreatAnalysisOrchestrator(
        pcap_parser=PcapParser(),
        log_parser=LogParser(),
        feature_extractor=FeatureExtractor(),
        rule_engine=RuleEngine(),
        anomaly_detector=AnomalyDetector(sensitivity=sensitivity_val),
        threat_classifier=ThreatClassifier(),
    )

    with st.spinner("Parsing input files..."):
        parsed = orchestrator.parse(file_paths)

    with st.spinner("Extracting features..."):
        features = orchestrator.extract_features(parsed)

    with st.spinner("Running rule-based detection..."):
        rule_hits = orchestrator.apply_rules(features)

    with st.spinner("Running anomaly detection..."):
        anomalies = orchestrator.detect_anomalies(features, window_size=window)

    with st.spinner("Classifying threats..."):
        report = orchestrator.classify(rule_hits, anomalies, features)

    protocol_dist = features.protocol_distribution
    timeline_data = features.traffic_timeline
    anomaly_data = features.anomaly_scores

    return report, protocol_dist, timeline_data, anomaly_data


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------

if demo_clicked or st.session_state.get("demo_loaded"):
    st.session_state.demo_loaded = True

    threat_report = get_mock_report()
    protocol_dist = get_mock_protocol_dist()
    timeline = get_mock_timeline()
    anomaly_scores = get_mock_anomaly_scores()

    display_results(threat_report, protocol_dist, timeline, anomaly_scores)

elif uploaded_files:
    with tempfile.TemporaryDirectory() as tmpdir:
        file_paths = []
        for uf in uploaded_files:
            path = os.path.join(tmpdir, uf.name)
            with open(path, "wb") as f:
                f.write(uf.getbuffer())
            file_paths.append(path)

        report, proto, tl, anom = run_analysis(file_paths, sensitivity, window_size)

    st.session_state.last_report = report
    st.session_state.last_proto = proto
    st.session_state.last_timeline = tl
    st.session_state.last_anomaly = anom

    display_results(report, proto, tl, anom)

elif "last_report" in st.session_state:
    display_results(
        st.session_state.last_report,
        st.session_state.last_proto,
        st.session_state.last_timeline,
        st.session_state.last_anomaly,
    )

else:
    st.title("Network Threat Analyzer")
    st.markdown(
        "Upload PCAP or log files to start analysis, or click "
        "**Load Demo Data** to see a sample report."
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        st.subheader("Rule-Based Detection")
        st.markdown(
            "- Port Scans\n"
            "- DDoS Patterns\n"
            "- Brute Force Attempts\n"
            "- Suspicious Connections"
        )

    with col2:
        st.subheader("ML Anomaly Detection")
        st.markdown(
            "- Isolation Forest\n"
            "- Local Outlier Factor\n"
            "- One-Class SVM"
        )

    with col3:
        st.subheader("Professional Reports")
        st.markdown(
            "- DOCX Reports\n"
            "- Interactive Charts\n"
            "- Actionable Recommendations"
        )
