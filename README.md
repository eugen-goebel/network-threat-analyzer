# Network Threat Analyzer

Multi-agent network threat detection system combining rule-based signature matching with ML anomaly detection to analyze PCAP files and server logs.

![CI](https://github.com/eugen-goebel/network-threat-analyzer/actions/workflows/tests.yml/badge.svg)
![Python 3.10+](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.5+-F7931E?logo=scikit-learn&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B?logo=streamlit&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-blue)
[![Live Demo](https://img.shields.io/badge/Live_Demo-Streamlit_Cloud-FF4B4B?style=flat)](https://eugen-goebel-network-threat-analyzer.streamlit.app/)

> **Try it live:** [eugen-goebel-network-threat-analyzer.streamlit.app](https://eugen-goebel-network-threat-analyzer.streamlit.app/). Opens in demo mode with a sample capture already analyzed, so the rule-based and ML detections are visible without uploading anything.


---

## Screenshots

**Start Screen**: upload PCAP/log files or load demo data, rule-based + ML detection
![Start](docs/screenshots/01-start.png)

**Threat Analysis**: severity-ranked threat overview with rule and ML-based detections
![Threat Analysis](docs/screenshots/02-threat-analysis.png)

---

## Architecture

```
PCAP / Log Files
      │
 ┌────┴────────┐
 ▼              ▼
PCAP Parser    Log Parser         Phase 1-2: Parse input files
(scapy)        (regex)
 └──────┬──────┘
        ▼
 Feature Extractor                Phase 3: 18 ML features per time window
 (pandas, numpy)
  ┌─────┴──────┐
  ▼            ▼
Rule Engine   Anomaly Detector    Phase 4-5: Dual detection
(signatures)  (ML ensemble)
  └─────┬──────┘
        ▼
 Threat Classifier                Phase 6: Merge, deduplicate, score 0-100
        ▼
 Report Generator                 Phase 7: DOCX report + charts
```

| Agent | Role | Technology |
|-------|------|-----------|
| **PCAP Parser** | Extracts packets, flows, and protocol statistics from capture files | scapy |
| **Log Parser** | Parses syslog and Apache/Nginx access logs with severity classification | regex |
| **Feature Extractor** | Computes 18 traffic features per time window for ML analysis | pandas, numpy |
| **Rule Engine** | Signature-based detection of known attack patterns | Custom rules |
| **Anomaly Detector** | Unsupervised ML ensemble for detecting unknown threats | scikit-learn |
| **Threat Classifier** | Merges detections, deduplicates, and assigns severity scores | Pydantic |
| **Report Generator** | Creates professional DOCX reports with embedded charts | python-docx, matplotlib |

> No API key required, all analysis runs locally using unsupervised machine learning.

---

## Detection Capabilities

### Rule-Based Detection

| Threat | Detection Method | Severity |
|--------|-----------------|----------|
| Vertical Port Scan | >20 ports scanned on single target in 60s | High |
| Horizontal Port Scan | Same port probed on >10 targets in 60s | High |
| SYN Scan | >20 TCP packets from single source, >80% of them SYN-only | Medium |
| XMAS Scan | TCP packets with FIN+PSH+URG flags | High |
| SYN Flood | >100 SYN-only packets to one target from >5 sources in 10s | Critical |
| UDP Flood | >500 UDP packets to one target in 10s | Critical |
| ICMP Flood | >50 ICMP packets to one target in 10s | High |
| HTTP Flood | >100 packets to one target on port 80/443 from >5 sources in 10s, SYN-only packets not counted | Critical |
| SSH Brute Force | ≥5 failed logins from same IP in 60s | High |
| HTTP Brute Force | ≥10 failed logins (POST to a login path, status 401/403) from same IP in 60s | High |
| Distributed HTTP Brute Force | ≥20 failed logins on the same login path from ≥3 IPs in 60s | High |
| Directory Traversal | Any Apache request whose URL-decoded path or query has a `..` segment or names a system file (`/etc/passwd`, `win.ini`), one request is enough, per source IP | High |
| Recon Scanning | ≥5 different known probe paths (`/.env`, `/.git`, `/wp-admin`, `/phpmyadmin`, `*.sql`, ...) answered with 403/404 from the same IP in 60s | Medium |
| C2 Beaconing | >5 packets per source/destination pair, average interval ≥10s, std dev < 5s | Critical |
| Data Exfiltration | >10,000,000 bytes in one flow from internal to external IP | High |
| Malicious Ports | Traffic from or to known backdoor/IRC ports (4444, 5555, 8888, 1337, 31337, 6667, 6697) | High |
| DNS Tunneling (Volume) | >100 DNS queries from single source in 60s | High |
| DNS Tunneling (Oversized) | ≥20 DNS packets with payload >100 bytes per source | High |

A login path has one of the words `login`, `signin`, `logon`, `auth`, `authenticate`, `oauth` or `token` as a whole word. The path is split at `/`, `-`, `_`, `.` and camelCase, and two neighbouring words also count joined: `/wp-login.php`, `/api/userLogin` and `/sign-in` match, `/author` does not.

The two web rules read Apache log entries only. Paths are decoded repeatedly (`%2e%2e%2f`, `..%252f`, overlong UTF-8), lowercased and compared as whole segments, never as substrings: `/admin` is a probe, `/admin-guide` and `/catalog` are not. Directory traversal is reported for any status (2xx answers are counted in the evidence), and a traversal request does not also count as a probe. A scan slower than 5 paths per minute stays below the recon threshold. The thresholds are heuristics, not calibrated on real traffic.

### ML Anomaly Detection

| Algorithm | Strength | Weight |
|-----------|----------|--------|
| Isolation Forest | Global anomalies in high-dimensional data | 0.4 |
| Local Outlier Factor | Local density-based anomalies | 0.35 |
| One-Class SVM | Decision boundary for normal behavior | 0.25 |

Ensemble uses majority voting: a time window is flagged when 2+ models agree.

---

## Features

- **Dual Detection**: Rule-based signatures + unsupervised ML ensemble
- **PCAP Analysis**: Deep packet inspection (protocols, flags, payloads)
- **Multi-Format Log Parsing**: Syslog, Apache/Nginx access logs
- **18-Feature Extraction**: Entropy, ratios, rates, flow stats per time window
- **Severity Scoring**: 0-100 scale with automatic prioritization
- **Interactive Dashboard**: Streamlit interface with real-time analysis
- **Professional Reports**: DOCX output with embedded charts
- **Demo Mode**: Pre-built sample data for quick exploration

---

## Quickstart

```bash
# 1. Clone the repo
git clone https://github.com/eugen-goebel/network-threat-analyzer.git
cd network-threat-analyzer

# 2. Setup environment
python3 -m venv venv && source venv/bin/activate
uv sync

# 3. Run demo analysis
uv run main.py --demo

# 4. Analyze your own files
uv run main.py capture.pcap server.log

# 5. Launch dashboard
uv run streamlit run app.py
```

---

## Dashboard

The Streamlit dashboard provides:
- Real-time threat metrics (total, critical, high counts)
- Interactive threat table with severity filtering
- Protocol distribution charts
- Traffic timeline with anomaly highlighting
- DOCX report download
- Upload limits: 25 MB per file, 50 MB in total, and only the first 50,000 packets of a capture are analyzed (a warning is shown when a capture is cut). The CLI reads local files in full.

---

## Testing

```bash
pytest -v
```

54+ tests covering all agents, rules, ML pipeline, and report generation. No external dependencies required for testing.

---

## Sample Data

The included sample data contains intentional attack patterns:

| Pattern | Source | Details |
|---------|--------|---------|
| Port Scan | 192.168.1.100 | Sequential scan of ports 1-80 |
| SYN Flood | 172.16.0.x (15 IPs) | 150 SYN packets in 4 seconds |
| C2 Beaconing | 192.168.1.50 | 60-second interval to port 8888 |
| SSH Brute Force | 10.99.88.77 | 15 failed attempts + 1 success |
| Directory Traversal | 10.99.88.77 | 15 `../` requests for `/etc/passwd`, `/etc/shadow` and other system files, plain and encoded, all answered 403 |
| Recon Scanning | 203.0.113.50 | 31 probes (`/wp-admin`, `/.env`, `/.git/config`, `*.sql`, ...), all 404; 22 of them are on the rule's list |

All three files share one timeline that starts at 2026-03-15 09:00 UTC (PCAP in epoch time, syslog in UTC without a zone, Apache as `10:00 +0100`), independent of the time zone of the machine that generates them.

Generate fresh sample data (optional argument: output directory):
```bash
python data/generate_samples.py
```

---

## Project Structure

```
network-threat-analyzer/
├── main.py                    CLI entry point
├── app.py                     Streamlit dashboard
├── agents/
│   ├── orchestrator.py        7-phase pipeline coordinator
│   ├── pcap_parser.py         PCAP file parser (scapy)
│   ├── log_parser.py          Syslog/Apache log parser
│   ├── feature_extractor.py   ML feature computation
│   ├── rule_engine.py         Rule dispatch engine
│   ├── anomaly_detector.py    ML ensemble detector
│   ├── threat_classifier.py   Threat scoring and classification
│   └── mock_data.py           Demo mode data
├── models/
│   ├── network.py             Network data models
│   ├── threats.py             Threat detection models
│   └── reports.py             Report structure models
├── rules/
│   ├── port_scan.py           Port scan signatures
│   ├── ddos.py                DDoS pattern rules
│   ├── brute_force.py         Brute force detection
│   ├── web_attacks.py         Directory traversal, recon scanning
│   └── suspicious_connections.py  C2, exfiltration, malicious ports
├── utils/
│   ├── visualization.py       Chart generation
│   └── report_generator.py    DOCX report builder
├── data/
│   ├── generate_samples.py    Sample data generator
│   ├── sample_capture.pcap    Demo PCAP file
│   ├── sample_syslog.log      Demo syslog
│   └── sample_apache.log      Demo Apache log
└── tests/                     54+ tests
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Packet Analysis | scapy |
| ML Detection | scikit-learn (Isolation Forest, LOF, One-Class SVM) |
| Feature Engineering | pandas, numpy |
| Dashboard | Streamlit |
| Reports | python-docx, matplotlib |
| Type Safety | Pydantic v2 |
| Testing | pytest |

---

## Report Sections

1. Executive Summary
2. Traffic Overview
3. Protocol Analysis
4. Threat Summary Table (color-coded severity)
5. Detailed Threat Analysis (evidence, IPs, recommendations)
6. Timeline Analysis
7. Recommendations (prioritized action items)
8. Methodology

---

## License

MIT
