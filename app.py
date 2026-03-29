"""Network Threat Analyzer — Streamlit dashboard for interactive threat analysis."""

import os
import time
import tempfile

import streamlit as st
import pandas as pd

from agents.pcap_parser import PcapParser
from agents.log_parser import LogParser
from agents.feature_extractor import FeatureExtractor
from agents.rule_engine import RuleEngine
from agents.anomaly_detector import AnomalyDetector
from agents.threat_classifier import ThreatClassifier
from agents.mock_data import (
    get_mock_report,
    get_mock_protocol_dist,
    get_mock_timeline,
    get_mock_anomaly_scores,
)

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
        df_timeline = pd.DataFrame(timeline, columns=["Time", "Packets/s"]).set_index("Time")
        st.line_chart(df_timeline)

        st.subheader("Anomaly Scores")
        df_anomaly = pd.DataFrame(anomaly_scores, columns=["Time", "Score"]).set_index("Time")
        st.line_chart(df_anomaly)


# ---------------------------------------------------------------------------
# Helper — run full analysis pipeline
# ---------------------------------------------------------------------------


def run_analysis(file_paths):
    start_time = time.time()

    with st.spinner("Parsing input files..."):
        parse_result = None
        log_result = None
        for fp in file_paths:
            ext = os.path.splitext(fp)[1].lower()
            if ext in (".pcap", ".pcapng") and parse_result is None:
                parse_result = PcapParser().parse(fp)
            elif ext == ".log" and log_result is None:
                log_result = LogParser().parse(fp)

        if parse_result is None:
            st.error("At least one PCAP file is required.")
            return None, None, None, None

    with st.spinner("Extracting features..."):
        feature_matrix = FeatureExtractor().extract(parse_result, log_result)

    with st.spinner("Running rule-based detection..."):
        rule_alerts = RuleEngine().analyze(parse_result, log_result)

    with st.spinner("Running anomaly detection..."):
        anomaly_alerts = AnomalyDetector(sensitivity=sensitivity).detect(feature_matrix)

    with st.spinner("Classifying threats..."):
        duration = time.time() - start_time
        threat_report = ThreatClassifier().classify(
            rule_alerts, anomaly_alerts,
            parse_result.packet_count, parse_result.time_range, duration,
        )

    protocol_dist = parse_result.protocol_distribution

    pps_idx = feature_matrix.feature_names.index("packets_per_second")
    timeline_data = [
        (ws, float(feature_matrix.features[i][pps_idx]))
        for i, ws in enumerate(feature_matrix.window_starts)
    ]

    anomaly_data = [
        (a.time_window_start, a.anomaly_score) for a in anomaly_alerts
    ]

    return threat_report, protocol_dist, timeline_data, anomaly_data


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

        report, proto, tl, anom = run_analysis(file_paths)
        if report is None:
            st.stop()

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
