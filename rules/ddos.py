"""DDoS pattern detection — SYN flood, UDP flood, ICMP flood, HTTP flood."""

from collections import defaultdict
from datetime import datetime, timedelta

from models.network import PacketRecord, ConnectionFlow
from models.threats import RuleAlert

WINDOW_SECONDS = 10


def _bucket_key(ts: datetime, base: datetime) -> int:
    """Return the time-window index for a timestamp."""
    return int((ts - base).total_seconds() // WINDOW_SECONDS)


def detect(packets: list[PacketRecord], flows: list[ConnectionFlow]) -> list[RuleAlert]:
    """Run all DDoS detection rules against packet data."""
    alerts: list[RuleAlert] = []

    if not packets:
        return alerts

    parsed = [(pkt, datetime.fromisoformat(pkt.timestamp)) for pkt in packets]
    base_time = min(ts for _, ts in parsed)

    # Bucket packets into 10-second windows
    windows: dict[int, list[PacketRecord]] = defaultdict(list)
    for pkt, ts in parsed:
        windows[_bucket_key(ts, base_time)].append(pkt)

    for bucket_idx, w_pkts in windows.items():
        window_start = base_time + timedelta(seconds=bucket_idx * WINDOW_SECONDS)
        window_ts = window_start.isoformat()

        # --- SYN flood ---
        syn_by_dst: dict[str, list[PacketRecord]] = defaultdict(list)
        for pkt in w_pkts:
            if "SYN" in pkt.tcp_flags and "ACK" not in pkt.tcp_flags:
                syn_by_dst[pkt.dst_ip].append(pkt)

        for dst_ip, syn_pkts in syn_by_dst.items():
            src_ips = {p.src_ip for p in syn_pkts}
            if len(syn_pkts) > 100 and len(src_ips) > 5:
                rate = round(len(syn_pkts) / WINDOW_SECONDS, 1)
                alerts.append(RuleAlert(
                    rule_name="syn_flood",
                    severity="critical",
                    category="DDOS_ATTACK",
                    description=f"SYN flood targeting {dst_ip}: {rate} pkt/s from {len(src_ips)} sources",
                    source_ips=list(src_ips),
                    dest_ips=[dst_ip],
                    timestamps=[window_ts],
                    evidence={
                        "flood_type": "syn",
                        "packets_per_second": rate,
                        "source_count": len(src_ips),
                        "target": dst_ip,
                    },
                ))

        # --- UDP flood ---
        udp_by_dst: dict[str, list[PacketRecord]] = defaultdict(list)
        for pkt in w_pkts:
            if pkt.protocol.upper() == "UDP":
                udp_by_dst[pkt.dst_ip].append(pkt)

        for dst_ip, udp_pkts in udp_by_dst.items():
            if len(udp_pkts) > 500:
                rate = round(len(udp_pkts) / WINDOW_SECONDS, 1)
                alerts.append(RuleAlert(
                    rule_name="udp_flood",
                    severity="critical",
                    category="DDOS_ATTACK",
                    description=f"UDP flood targeting {dst_ip}: {rate} pkt/s",
                    source_ips=list({p.src_ip for p in udp_pkts}),
                    dest_ips=[dst_ip],
                    timestamps=[window_ts],
                    evidence={
                        "flood_type": "udp",
                        "packets_per_second": rate,
                        "target": dst_ip,
                    },
                ))

        # --- ICMP flood ---
        icmp_by_dst: dict[str, list[PacketRecord]] = defaultdict(list)
        for pkt in w_pkts:
            if pkt.protocol.upper() == "ICMP":
                icmp_by_dst[pkt.dst_ip].append(pkt)

        for dst_ip, icmp_pkts in icmp_by_dst.items():
            if len(icmp_pkts) > 50:
                rate = round(len(icmp_pkts) / WINDOW_SECONDS, 1)
                alerts.append(RuleAlert(
                    rule_name="icmp_flood",
                    severity="high",
                    category="DDOS_ATTACK",
                    description=f"ICMP flood targeting {dst_ip}: {rate} pkt/s",
                    source_ips=list({p.src_ip for p in icmp_pkts}),
                    dest_ips=[dst_ip],
                    timestamps=[window_ts],
                    evidence={
                        "flood_type": "icmp",
                        "packets_per_second": rate,
                        "target": dst_ip,
                    },
                ))

        # --- HTTP flood ---
        http_by_dst: dict[str, list[PacketRecord]] = defaultdict(list)
        for pkt in w_pkts:
            if pkt.dst_port in (80, 443):
                http_by_dst[pkt.dst_ip].append(pkt)

        for dst_ip, http_pkts in http_by_dst.items():
            src_ips = {p.src_ip for p in http_pkts}
            if len(http_pkts) > 100 and len(src_ips) > 5:
                rate = round(len(http_pkts) / WINDOW_SECONDS, 1)
                alerts.append(RuleAlert(
                    rule_name="http_flood",
                    severity="critical",
                    category="DDOS_ATTACK",
                    description=f"HTTP flood targeting {dst_ip}: {rate} req/s from {len(src_ips)} sources",
                    source_ips=list(src_ips),
                    dest_ips=[dst_ip],
                    timestamps=[window_ts],
                    evidence={
                        "flood_type": "http",
                        "request_rate": rate,
                        "source_count": len(src_ips),
                    },
                ))

    return alerts
