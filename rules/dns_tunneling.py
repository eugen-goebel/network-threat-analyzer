"""DNS tunneling detection — excessive query volume and oversized DNS packets.

DNS tunneling embeds payload data inside DNS queries to bypass perimeter
defences. Two signals raise an alert here:

1. A source IP generates more than VOLUME_THRESHOLD DNS queries within a
   60-second window.
2. A source IP sends at least LARGE_QUERY_COUNT DNS packets with
   payload_size above LARGE_QUERY_PAYLOAD_BYTES (legitimate queries are
   typically below ~80 bytes; tunnelling encodes data into long subdomain
   labels, inflating the packet).
"""

from collections import defaultdict
from datetime import datetime, timedelta

from models.network import ConnectionFlow, PacketRecord
from models.threats import RuleAlert

DNS_PORT = 53
WINDOW_SECONDS = 60
VOLUME_THRESHOLD = 100
LARGE_QUERY_PAYLOAD_BYTES = 100
LARGE_QUERY_COUNT_THRESHOLD = 20


def _is_dns(pkt: PacketRecord) -> bool:
    return pkt.protocol.upper() == "DNS" or pkt.dst_port == DNS_PORT


def detect(packets: list[PacketRecord], flows: list[ConnectionFlow]) -> list[RuleAlert]:
    """Run DNS tunneling detection rules against packet data."""
    alerts: list[RuleAlert] = []

    dns_packets_by_source: dict[str, list[PacketRecord]] = defaultdict(list)
    for pkt in packets:
        if _is_dns(pkt):
            dns_packets_by_source[pkt.src_ip].append(pkt)

    for src_ip, dns_packets in dns_packets_by_source.items():
        if not dns_packets:
            continue

        # --- Volume check: many queries in a short window ---
        timestamps = sorted(datetime.fromisoformat(p.timestamp) for p in dns_packets)
        for i, start in enumerate(timestamps):
            window_end = start + timedelta(seconds=WINDOW_SECONDS)
            in_window = [t for t in timestamps[i:] if t <= window_end]
            if len(in_window) > VOLUME_THRESHOLD:
                dest_ips = sorted({p.dst_ip for p in dns_packets})
                alerts.append(RuleAlert(
                    rule_name="dns_tunneling_volume",
                    severity="high",
                    category="DNS_TUNNELING",
                    description=(
                        f"DNS tunneling suspected from {src_ip}: "
                        f"{len(in_window)} queries in {WINDOW_SECONDS}s"
                    ),
                    source_ips=[src_ip],
                    dest_ips=dest_ips,
                    timestamps=[in_window[0].isoformat(), in_window[-1].isoformat()],
                    evidence={
                        "pattern": "high_query_volume",
                        "queries_in_window": len(in_window),
                        "window_seconds": WINDOW_SECONDS,
                        "threshold": VOLUME_THRESHOLD,
                    },
                ))
                break  # one volume alert per source is enough

        # --- Size check: many unusually large queries ---
        large_packets = [
            p for p in dns_packets if p.payload_size > LARGE_QUERY_PAYLOAD_BYTES
        ]
        if len(large_packets) >= LARGE_QUERY_COUNT_THRESHOLD:
            avg_size = sum(p.payload_size for p in large_packets) / len(large_packets)
            dest_ips = sorted({p.dst_ip for p in large_packets})
            sorted_timestamps = sorted(p.timestamp for p in large_packets)
            alerts.append(RuleAlert(
                rule_name="dns_tunneling_oversized_queries",
                severity="high",
                category="DNS_TUNNELING",
                description=(
                    f"DNS tunneling suspected from {src_ip}: "
                    f"{len(large_packets)} oversized queries "
                    f"(avg {avg_size:.0f} bytes payload)"
                ),
                source_ips=[src_ip],
                dest_ips=dest_ips,
                timestamps=[sorted_timestamps[0], sorted_timestamps[-1]],
                evidence={
                    "pattern": "oversized_queries",
                    "large_query_count": len(large_packets),
                    "average_payload_bytes": round(avg_size, 1),
                    "payload_threshold_bytes": LARGE_QUERY_PAYLOAD_BYTES,
                },
            ))

    return alerts
