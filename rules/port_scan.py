"""Port scan detection rules — vertical, horizontal, SYN, and XMAS scans."""

from collections import defaultdict
from datetime import datetime, timedelta

from models.network import PacketRecord, ConnectionFlow
from models.threats import RuleAlert


def _group_by_time_window(timestamps: list[datetime], window_seconds: int = 60):
    """Yield groups of indices within consecutive time windows."""
    if not timestamps:
        return
    sorted_ts = sorted(enumerate(timestamps), key=lambda x: x[1])
    window_start = sorted_ts[0][1]
    current = []
    for idx, ts in sorted_ts:
        if ts - window_start <= timedelta(seconds=window_seconds):
            current.append((idx, ts))
        else:
            yield current
            window_start = ts
            current = [(idx, ts)]
    if current:
        yield current


def detect(packets: list[PacketRecord], flows: list[ConnectionFlow]) -> list[RuleAlert]:
    """Run all port scan detection rules against packet data."""
    alerts: list[RuleAlert] = []

    by_src: dict[str, list[PacketRecord]] = defaultdict(list)
    for pkt in packets:
        by_src[pkt.src_ip].append(pkt)

    # --- Vertical scan ---
    for src_ip, pkts in by_src.items():
        by_dst: dict[str, list[PacketRecord]] = defaultdict(list)
        for pkt in pkts:
            by_dst[pkt.dst_ip].append(pkt)

        for dst_ip, dst_pkts in by_dst.items():
            timestamps = [datetime.fromisoformat(p.timestamp) for p in dst_pkts]
            for window in _group_by_time_window(timestamps, 60):
                ports = {dst_pkts[i].dst_port for i, _ in window}
                if len(ports) > 20:
                    ts_list = [t for _, t in window]
                    duration = (max(ts_list) - min(ts_list)).total_seconds()
                    alerts.append(RuleAlert(
                        rule_name="vertical_port_scan",
                        severity="high",
                        category="PORT_SCAN",
                        description=f"Vertical port scan from {src_ip} to {dst_ip}: {len(ports)} ports in {duration:.0f}s",
                        source_ips=[src_ip],
                        dest_ips=[dst_ip],
                        timestamps=[dst_pkts[i].timestamp for i, _ in window],
                        evidence={
                            "scan_type": "vertical",
                            "ports_scanned": len(ports),
                            "target": dst_ip,
                            "duration_seconds": duration,
                        },
                    ))

    # --- Horizontal scan ---
    for src_ip, pkts in by_src.items():
        by_port: dict[int, list[PacketRecord]] = defaultdict(list)
        for pkt in pkts:
            by_port[pkt.dst_port].append(pkt)

        for port, port_pkts in by_port.items():
            timestamps = [datetime.fromisoformat(p.timestamp) for p in port_pkts]
            for window in _group_by_time_window(timestamps, 60):
                targets = {port_pkts[i].dst_ip for i, _ in window}
                if len(targets) > 10:
                    ts_list = [t for _, t in window]
                    duration = (max(ts_list) - min(ts_list)).total_seconds()
                    alerts.append(RuleAlert(
                        rule_name="horizontal_port_scan",
                        severity="high",
                        category="PORT_SCAN",
                        description=f"Horizontal scan from {src_ip} on port {port}: {len(targets)} targets",
                        source_ips=[src_ip],
                        dest_ips=list(targets),
                        timestamps=[port_pkts[i].timestamp for i, _ in window],
                        evidence={
                            "scan_type": "horizontal",
                            "targets_scanned": len(targets),
                            "port": port,
                        },
                    ))

    # --- SYN scan ---
    for src_ip, pkts in by_src.items():
        tcp_pkts = [p for p in pkts if p.protocol.upper() == "TCP"]
        if len(tcp_pkts) <= 20:
            continue
        syn_only = [p for p in tcp_pkts if "SYN" in p.tcp_flags and "ACK" not in p.tcp_flags]
        ratio = len(syn_only) / len(tcp_pkts)
        if ratio > 0.8:
            alerts.append(RuleAlert(
                rule_name="syn_scan",
                severity="medium",
                category="PORT_SCAN",
                description=f"SYN scan from {src_ip}: {ratio:.0%} SYN-only packets ({len(tcp_pkts)} total)",
                source_ips=[src_ip],
                dest_ips=list({p.dst_ip for p in tcp_pkts}),
                timestamps=[tcp_pkts[0].timestamp, tcp_pkts[-1].timestamp],
                evidence={
                    "scan_type": "syn",
                    "syn_ratio": round(ratio, 3),
                    "packet_count": len(tcp_pkts),
                },
            ))

    # --- XMAS scan ---
    xmas_pkts = [p for p in packets if all(f in p.tcp_flags for f in ("FIN", "PSH", "URG"))]
    if xmas_pkts:
        by_xmas_src: dict[str, list[PacketRecord]] = defaultdict(list)
        for pkt in xmas_pkts:
            by_xmas_src[pkt.src_ip].append(pkt)
        for src_ip, src_pkts in by_xmas_src.items():
            alerts.append(RuleAlert(
                rule_name="xmas_scan",
                severity="high",
                category="PORT_SCAN",
                description=f"XMAS scan from {src_ip}: {len(src_pkts)} packets with FIN+PSH+URG",
                source_ips=[src_ip],
                dest_ips=list({p.dst_ip for p in src_pkts}),
                timestamps=[p.timestamp for p in src_pkts],
                evidence={
                    "scan_type": "xmas",
                    "packet_count": len(src_pkts),
                },
            ))

    return alerts
