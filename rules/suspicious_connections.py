"""Suspicious connection detection — malicious ports, beaconing, data exfiltration."""

import statistics
from collections import defaultdict
from datetime import datetime

from models.network import PacketRecord, ConnectionFlow
from models.threats import RuleAlert

MALICIOUS_PORTS = {4444, 5555, 8888, 1337, 31337, 6667, 6697}


def _is_internal_ip(ip: str) -> bool:
    """Check if an IP address falls within RFC 1918 private ranges."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False

    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    return False


def detect(packets: list[PacketRecord], flows: list[ConnectionFlow]) -> list[RuleAlert]:
    """Run suspicious connection detection rules."""
    alerts: list[RuleAlert] = []

    # --- Malicious ports ---
    port_hits: dict[int, list[PacketRecord]] = defaultdict(list)
    for pkt in packets:
        if pkt.dst_port in MALICIOUS_PORTS:
            port_hits[pkt.dst_port].append(pkt)
        if pkt.src_port in MALICIOUS_PORTS:
            port_hits[pkt.src_port].append(pkt)

    for port, pkts in port_hits.items():
        src_ips = list({p.src_ip for p in pkts})
        dst_ips = list({p.dst_ip for p in pkts})
        alerts.append(RuleAlert(
            rule_name="malicious_port",
            severity="high",
            category="SUSPICIOUS_CONNECTION",
            description=f"Traffic on suspicious port {port}: {len(pkts)} packets",
            source_ips=src_ips,
            dest_ips=dst_ips,
            timestamps=[pkts[0].timestamp, pkts[-1].timestamp],
            evidence={
                "detection_type": "malicious_port",
                "port": port,
                "connections": len(pkts),
            },
        ))

    # --- Beaconing detection ---
    pair_times: dict[tuple[str, str], list[datetime]] = defaultdict(list)
    for pkt in packets:
        pair_times[(pkt.src_ip, pkt.dst_ip)].append(
            datetime.fromisoformat(pkt.timestamp)
        )

    for (src_ip, dst_ip), timestamps in pair_times.items():
        if len(timestamps) <= 5:
            continue
        sorted_ts = sorted(timestamps)
        intervals = [
            (sorted_ts[i + 1] - sorted_ts[i]).total_seconds()
            for i in range(len(sorted_ts) - 1)
        ]
        if len(intervals) < 2:
            continue
        avg = statistics.mean(intervals)
        std = statistics.stdev(intervals)
        if std < 5:
            alerts.append(RuleAlert(
                rule_name="beaconing",
                severity="critical",
                category="SUSPICIOUS_CONNECTION",
                description=f"Potential C2 beaconing: {src_ip} -> {dst_ip} (avg interval {avg:.1f}s, std {std:.1f}s)",
                source_ips=[src_ip],
                dest_ips=[dst_ip],
                timestamps=[sorted_ts[0].isoformat(), sorted_ts[-1].isoformat()],
                evidence={
                    "detection_type": "beaconing",
                    "avg_interval_seconds": round(avg, 2),
                    "std_deviation": round(std, 2),
                    "beacon_count": len(sorted_ts),
                },
            ))

    # --- Data exfiltration ---
    for flow in flows:
        if flow.total_bytes > 10_000_000 and _is_internal_ip(flow.src_ip) and not _is_internal_ip(flow.dst_ip):
            alerts.append(RuleAlert(
                rule_name="data_exfiltration",
                severity="high",
                category="SUSPICIOUS_CONNECTION",
                description=f"Large outbound transfer: {flow.src_ip} -> {flow.dst_ip} ({flow.total_bytes:,} bytes)",
                source_ips=[flow.src_ip],
                dest_ips=[flow.dst_ip],
                timestamps=[flow.start_time, flow.end_time],
                evidence={
                    "detection_type": "data_exfiltration",
                    "bytes_transferred": flow.total_bytes,
                    "destination": flow.dst_ip,
                },
            ))

    return alerts
