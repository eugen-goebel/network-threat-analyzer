"""Feature extraction — transforms parsed traffic into ML-ready feature vectors."""

import math
from datetime import datetime, timedelta
from typing import Any

import numpy as np
import pandas as pd
from pydantic import BaseModel, Field

from models.network import PacketRecord, ParseResult, LogParseResult


class FeatureMatrix(BaseModel):
    model_config = {"arbitrary_types_allowed": True}

    features: Any
    feature_names: list[str]
    window_starts: list[str]
    window_seconds: int
    baseline_stats: dict[str, float]


FEATURE_NAMES = [
    "packets_per_second",
    "unique_dst_ips",
    "unique_dst_ports",
    "syn_ratio",
    "rst_ratio",
    "icmp_ratio",
    "avg_packet_size",
    "packet_size_std",
    "small_packet_ratio",
    "large_packet_ratio",
    "unique_src_ips",
    "tcp_flag_entropy",
    "port_entropy",
    "dns_query_count",
    "http_error_count",
    "bytes_per_second",
    "connection_count",
    "avg_flow_packets",
]


class FeatureExtractor:
    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds

    def extract(
        self,
        parse_result: ParseResult,
        log_result: LogParseResult | None = None,
    ) -> FeatureMatrix:
        packets = parse_result.packets
        if not packets:
            return FeatureMatrix(
                features=np.empty((0, len(FEATURE_NAMES))),
                feature_names=FEATURE_NAMES,
                window_starts=[],
                window_seconds=self.window_seconds,
                baseline_stats={name: 0.0 for name in FEATURE_NAMES},
            )

        timestamps = [datetime.fromisoformat(p.timestamp) for p in packets]
        t_min = min(timestamps)
        t_max = max(timestamps)

        # Build windows
        window_starts: list[datetime] = []
        current = t_min
        while current <= t_max:
            window_starts.append(current)
            current += timedelta(seconds=self.window_seconds)
        if not window_starts:
            window_starts.append(t_min)

        # Pre-parse log timestamps if available
        log_entries_parsed = []
        if log_result:
            for entry in log_result.entries:
                try:
                    log_entries_parsed.append(
                        (datetime.fromisoformat(entry.timestamp), entry)
                    )
                except (ValueError, TypeError):
                    continue

        rows = []
        for w_start in window_starts:
            w_end = w_start + timedelta(seconds=self.window_seconds)

            wp = [
                (p, ts)
                for p, ts in zip(packets, timestamps)
                if w_start <= ts < w_end
            ]
            if not wp:
                rows.append([0.0] * len(FEATURE_NAMES))
                continue

            w_packets = [item[0] for item in wp]
            total = len(w_packets)

            dst_ips = {p.dst_ip for p in w_packets}
            dst_ports = {p.dst_port for p in w_packets}
            src_ips = {p.src_ip for p in w_packets}
            sizes = [p.size for p in w_packets]

            tcp_packets = [p for p in w_packets if p.tcp_flags]
            all_flags = [f for p in tcp_packets for f in p.tcp_flags]

            syn_count = sum(1 for p in w_packets if "SYN" in p.tcp_flags)
            rst_count = sum(1 for p in w_packets if "RST" in p.tcp_flags)
            icmp_count = sum(1 for p in w_packets if p.protocol == "ICMP")
            dns_count = sum(1 for p in w_packets if p.protocol == "DNS")

            avg_size = np.mean(sizes)
            std_size = float(np.std(sizes)) if total > 1 else 0.0
            small_ratio = sum(1 for s in sizes if s < 100) / total
            large_ratio = sum(1 for s in sizes if s > 1400) / total

            flows = {(p.src_ip, p.dst_ip, p.dst_port) for p in w_packets}
            conn_count = len(flows)
            avg_flow = total / conn_count if conn_count > 0 else 0.0

            # Log-based error count
            error_count = 0
            if log_entries_parsed:
                for log_ts, entry in log_entries_parsed:
                    if w_start <= log_ts < w_end and entry.severity in (
                        "medium",
                        "high",
                        "critical",
                    ):
                        error_count += 1

            row = [
                total / self.window_seconds,                 # packets_per_second
                len(dst_ips),                                # unique_dst_ips
                len(dst_ports),                              # unique_dst_ports
                syn_count / total if tcp_packets else 0.0,   # syn_ratio
                rst_count / total if tcp_packets else 0.0,   # rst_ratio
                icmp_count / total,                          # icmp_ratio
                float(avg_size),                             # avg_packet_size
                std_size,                                    # packet_size_std
                small_ratio,                                 # small_packet_ratio
                large_ratio,                                 # large_packet_ratio
                len(src_ips),                                # unique_src_ips
                self._shannon_entropy(all_flags),            # tcp_flag_entropy
                self._shannon_entropy([p.dst_port for p in w_packets]),  # port_entropy
                dns_count,                                   # dns_query_count
                error_count,                                 # http_error_count
                sum(sizes) / self.window_seconds,            # bytes_per_second
                conn_count,                                  # connection_count
                avg_flow,                                    # avg_flow_packets
            ]
            rows.append(row)

        feature_array = np.array(rows, dtype=np.float64)

        baseline_stats = {}
        for i, name in enumerate(FEATURE_NAMES):
            baseline_stats[name] = float(np.mean(feature_array[:, i]))

        return FeatureMatrix(
            features=feature_array,
            feature_names=FEATURE_NAMES,
            window_starts=[ws.isoformat() for ws in window_starts],
            window_seconds=self.window_seconds,
            baseline_stats=baseline_stats,
        )

    def _shannon_entropy(self, values: list) -> float:
        if len(values) <= 1:
            return 0.0
        counts: dict = {}
        for v in values:
            counts[v] = counts.get(v, 0) + 1
        total = len(values)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
