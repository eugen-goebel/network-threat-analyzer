"""Network Threat Analyzer — Streamlit dashboard for interactive threat analysis."""

import os
import tempfile
import time
from datetime import datetime

import altair as alt
import pandas as pd
import streamlit as st

from agents.anomaly_detector import MIN_WINDOWS, AnomalyDetector
from agents.feature_extractor import FeatureExtractor
from agents.log_parser import LogParser
from agents.mock_data import (
    get_mock_anomaly_windows,
    get_mock_protocol_dist,
    get_mock_report,
    get_mock_timeline,
)
from agents.pcap_parser import PcapParser
from agents.rule_engine import RuleEngine
from agents.threat_classifier import ThreatClassifier

st.set_page_config(page_title="Network Threat Analyzer", page_icon="🛡", layout="wide")

# The per-file limit is server.maxUploadSize in .streamlit/config.toml (25 MB).
# The uploader accepts several files, so the total needs a limit of its own.
MAX_TOTAL_UPLOAD_MB = 50

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
demo_clicked = st.sidebar.button("Load Demo Data", width="stretch")
st.sidebar.markdown("---")

with st.sidebar.expander("Settings"):
    # st.sidebar.slider inside this block would target the sidebar directly and
    # bypass the expander, leaving an empty "Settings" box with a stray slider
    # underneath it. Inside a context manager the plain st.* call is correct.
    sensitivity = st.slider(
        "Anomaly Sensitivity",
        0.01,
        0.15,
        0.05,
        0.01,
        help=(
            "Share of traffic windows the anomaly models may flag. "
            "Lower means fewer, higher-confidence alerts; higher catches more "
            "but raises false positives. Default 0.05 = 5 percent."
        ),
    )

# ---------------------------------------------------------------------------
# Helper — build threat table
# ---------------------------------------------------------------------------


def _format_source_ips(source_ips, shown: int = 2) -> str:
    """Summarise a source-IP list so the table column stays readable.

    A SYN flood carries 15 sources. Joining them all produced a string the
    column silently cut mid-address ("172.16.0.1, 172.16.0.5, 172..."), which
    reads like a broken value. Show the first few and count the rest instead;
    the full list stays available in the detail view.
    """
    if not source_ips:
        return "N/A"
    if len(source_ips) <= shown:
        return ", ".join(source_ips)
    return f"{', '.join(source_ips[:shown])} +{len(source_ips) - shown} more"


def _upload_size_error(files, limit_mb: int = MAX_TOTAL_UPLOAD_MB) -> str | None:
    """Return an error message if the uploaded files together exceed the limit."""
    total = sum(f.size for f in files)
    if total <= limit_mb * 1024 * 1024:
        return None
    return (
        f"The uploaded files total {total / 1024 / 1024:.1f} MB, more than the "
        f"{limit_mb} MB limit for one analysis. Remove some files or upload a smaller capture."
    )


def _upload_path(tmpdir: str, name: str, index: int) -> str:
    """Where an uploaded file is written, always inside tmpdir.

    Streamlit does not sanitize UploadedFile.name, so a crafted request can send
    "../x" or an absolute path. Only the base name is kept.
    """
    base = os.path.basename(name.replace("\\", "/"))
    if base in ("", ".", ".."):
        base = f"upload_{index}"
    return os.path.join(tmpdir, base)


def _show_warnings() -> None:
    for message in st.session_state.get("last_warnings", []):
        st.warning(message)


def _threats_dataframe(threats):
    rows = []
    for t in threats:
        rows.append(
            {
                "Severity": t.severity_label.upper(),
                "Category": t.category,
                "Title": t.title,
                "Source IPs": _format_source_ips(t.source_ips),
                "Detection": t.detection_method,
            }
        )
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Helper — display results
# ---------------------------------------------------------------------------


_MODEL_LABELS = {
    "isolation_forest": "Isolation Forest",
    "local_outlier_factor": "Local Outlier Factor",
    "one_class_svm": "One-Class SVM",
}


def _render_ml_evidence(evidence: dict) -> None:
    """Show the anomaly ensemble's decision in plain language.

    scikit-learn encodes an outlier as -1 and an inlier as 1, which means
    nothing to a reader, so translate it into how many of the three models
    flagged the window and which features drove the score.
    """
    votes = evidence.get("model_votes", {})
    flagged = sum(1 for v in votes.values() if v == -1)
    score = evidence.get("anomaly_score")

    left, right = st.columns(2)
    if score is not None:
        left.metric(
            "Anomaly score",
            f"{score:.2f}",
            help=(
                "Isolation Forest score scaled to 0-1 within this capture (1 = most "
                "unusual window). The decision itself is the vote on the right."
            ),
        )
    right.metric("Models in agreement", f"{flagged} of {len(votes)}")

    st.markdown("**Ensemble votes:**")
    for key, vote in votes.items():
        label = _MODEL_LABELS.get(key, key)
        st.markdown(f"- {'🚩 flagged' if vote == -1 else '✅ normal'} — {label}")

    features = evidence.get("contributing_features")
    if features:
        st.markdown("**Top contributing features:**")
        for feat in features:
            st.markdown(f"- {feat}")


ANOMALY_FLAGGED = "Flagged by ensemble"
ANOMALY_NORMAL = "Not flagged"


def _short_time(ts: str) -> str:
    """'2026-03-15T09:03:01.675+00:00' -> '09:03:01' for axis labels; other text stays."""
    try:
        return datetime.fromisoformat(ts).strftime("%H:%M:%S")
    except ValueError:
        return ts


def _anomaly_frame(windows) -> pd.DataFrame:
    """One row per time window: score and whether the ensemble flagged it."""
    df = pd.DataFrame(windows, columns=["Time", "Score", "Flagged"])
    df["Decision"] = df["Flagged"].map({True: ANOMALY_FLAGGED, False: ANOMALY_NORMAL})
    # Full ISO timestamps on the axis are unreadable at 20 windows; keep them in the tooltip.
    df["Window"] = df["Time"].map(_short_time)
    return df[["Time", "Window", "Score", "Decision"]]


def _anomaly_chart(df: pd.DataFrame) -> alt.Chart:
    """Score of every window as a line; flagged windows are red points."""
    x = alt.X(
        "Window:N",
        sort=None,
        title=None,
        axis=alt.Axis(grid=False, labelAngle=-45, labelOverlap=True),
    )
    y = alt.Y("Score:Q", title=None, scale=alt.Scale(domain=[0, 1]))
    base = alt.Chart(df).encode(x=x, y=y)
    line = base.mark_line(color="#9aa5b1")
    points = base.mark_point(filled=True, size=65, opacity=1).encode(
        color=alt.Color(
            "Decision:N",
            scale=alt.Scale(
                domain=[ANOMALY_NORMAL, ANOMALY_FLAGGED],
                range=["#1565C0", "#C62828"],
            ),
            legend=alt.Legend(title=None, orient="top"),
        ),
        tooltip=["Time:N", alt.Tooltip("Score:Q", format=".2f"), "Decision:N"],
    )
    return line + points


def _render_anomaly_scores(anomaly_windows, window_count: int) -> None:
    if not anomaly_windows:
        st.info(
            f"No anomaly scores: the models need at least {MIN_WINDOWS} time windows "
            f"and this capture has {window_count}. Upload a longer capture."
        )
        return
    st.altair_chart(_anomaly_chart(_anomaly_frame(anomaly_windows)), width="stretch")
    st.caption(
        "Isolation Forest score of every time window, scaled within this capture "
        "(1 = most unusual window, so the top window always reads 1.0). A window "
        "is flagged when at least two of the three models vote outlier, so a "
        "flagged window does not always have the highest score."
    )


def display_results(threat_report, protocol_dist, timeline, anomaly_windows):
    # --- Header metrics ---
    # The severity cards have to add up to "Total Threats". Showing only
    # Critical and High left a reader with 2 + 3 against a total of 6 and no
    # way to tell where the missing threat went, so every severity is listed.
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Total Threats", threat_report.total_threats)
    c2.metric("Critical", threat_report.critical_count)
    c3.metric("High", threat_report.high_count)
    c4.metric("Medium", threat_report.medium_count)
    c5.metric("Low", threat_report.low_count)
    c6.metric("Packets Analyzed", f"{threat_report.packets_analyzed:,}")

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
                width="stretch",
                hide_index=True,
            )

            # The expanders repeat every row of the table above. Without a
            # heading they read as a duplicate list rather than the drill-down
            # they are.
            st.subheader("Threat details")
            st.caption("One entry per row above: evidence, affected hosts and recommended action.")
            for t in threats:
                with st.expander(f"{t.severity_label.upper()} — {t.title}"):
                    st.markdown(f"**Description:** {t.description}")
                    if t.source_ips:
                        st.markdown(f"**Source IPs:** {', '.join(t.source_ips)}")
                    if t.detection_method in ("ml", "both") and t.evidence.get("model_votes"):
                        _render_ml_evidence(t.evidence)
                    else:
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
        _render_anomaly_scores(anomaly_windows, len(timeline))


# ---------------------------------------------------------------------------
# Helper — run full analysis pipeline
# ---------------------------------------------------------------------------


def run_analysis(file_paths):
    start_time = time.time()

    with st.spinner("Parsing input files..."):
        parse_result = None
        log_path = None
        for fp in file_paths:
            ext = os.path.splitext(fp)[1].lower()
            if ext in (".pcap", ".pcapng") and parse_result is None:
                parse_result = PcapParser().parse(fp)
            elif ext == ".log" and log_path is None:
                log_path = fp

        if parse_result is None:
            st.error("At least one PCAP file is required.")
            return None, None, None, None

        # Parsed after the PCAP so syslog lines (no year) get the capture's year.
        log_result = LogParser.for_capture(parse_result).parse(log_path) if log_path else None

        # Kept in session state so the notice also shows when the report is
        # redisplayed after the upload is removed.
        st.session_state.last_warnings = list(parse_result.warnings)

    with st.spinner("Extracting features..."):
        feature_matrix = FeatureExtractor().extract(parse_result, log_result)

    with st.spinner("Running rule-based detection..."):
        rule_alerts = RuleEngine().analyze(parse_result, log_result)

    with st.spinner("Running anomaly detection..."):
        anomaly_result = AnomalyDetector(sensitivity=sensitivity).analyze(feature_matrix)
        anomaly_alerts = anomaly_result.alerts

    with st.spinner("Classifying threats..."):
        duration = time.time() - start_time
        threat_report = ThreatClassifier().classify(
            rule_alerts,
            anomaly_alerts,
            parse_result.packet_count,
            parse_result.time_range,
            duration,
        )

    protocol_dist = parse_result.protocol_distribution

    pps_idx = feature_matrix.feature_names.index("packets_per_second")
    timeline_data = [
        (ws, float(feature_matrix.features[i][pps_idx]))
        for i, ws in enumerate(feature_matrix.window_starts)
    ]

    # Every window, not only the flagged ones, so the chart shows the rest too.
    anomaly_data = [
        (w.time_window_start, w.anomaly_score, w.flagged) for w in anomaly_result.windows
    ]

    return threat_report, protocol_dist, timeline_data, anomaly_data


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------

st.title("Network Threat Analyzer")

# A first-time visitor should land on a full sample report rather than an
# empty page, so the demo is shown by default. Uploading a file takes over,
# and a click on "Load Demo Data" always returns to the sample report.
if uploaded_files:
    size_error = _upload_size_error(uploaded_files)
    if size_error:
        st.error(size_error)
        st.stop()
    st.session_state.demo_loaded = False
    with tempfile.TemporaryDirectory() as tmpdir:
        file_paths = []
        for i, uf in enumerate(uploaded_files):
            path = _upload_path(tmpdir, uf.name, i)
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

    _show_warnings()
    display_results(report, proto, tl, anom)

elif st.session_state.get("last_report") is not None and not demo_clicked:
    _show_warnings()
    display_results(
        st.session_state.last_report,
        st.session_state.last_proto,
        st.session_state.last_timeline,
        st.session_state.last_anomaly,
    )

else:
    st.session_state.demo_loaded = True
    st.caption(
        "Demo mode. A sample capture with detected threats is preloaded. "
        "Upload your own PCAP or log files in the sidebar to analyze real traffic."
    )
    display_results(
        get_mock_report(),
        get_mock_protocol_dist(),
        get_mock_timeline(),
        get_mock_anomaly_windows(),
    )


st.divider()
st.markdown(
    "<div style='text-align:center; color:gray; font-size:0.85rem;'>"
    "Built by Eugen Goebel &middot; "
    "<a href='https://github.com/eugen-goebel' target='_blank'>GitHub</a> &middot; "
    "<a href='https://www.linkedin.com/in/eugen-goebel/' target='_blank'>LinkedIn</a>"
    "</div>",
    unsafe_allow_html=True,
)
