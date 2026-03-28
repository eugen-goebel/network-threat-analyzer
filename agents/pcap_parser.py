"""PCAP file parser — extracts packet records and connection flows using scapy."""

import os
from collections import defaultdict
from datetime import datetime, timezone

from scapy.all import DNS, ICMP, IP, TCP, UDP, rdpcap

from models.network import ConnectionFlow, PacketRecord, ParseResult

FLAG_MAP = {"S": "SYN", "A": "ACK", "R": "RST", "F": "FIN", "P": "PSH", "U": "URG"}


class PcapParser:

    def parse(self, filepath: str) -> ParseResult:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"PCAP file not found: {filepath}")

        try:
            packets = rdpcap(filepath)
        except Exception as exc:
            raise ValueError(f"Not a valid PCAP file: {filepath}") from exc

        if not packets:
            raise ValueError(f"No packets found in {filepath}")

        records: list[PacketRecord] = []
        flow_buckets: dict[tuple, list[PacketRecord]] = defaultdict(list)

        for pkt in packets:
            if not pkt.haslayer(IP):
                continue

            ip = pkt[IP]
            ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).isoformat()

            protocol = self._detect_protocol(pkt)
            src_port, dst_port = self._extract_ports(pkt)
            tcp_flags = self._extract_tcp_flags(pkt)

            try:
                payload_size = len(pkt.payload.payload)
            except Exception:
                payload_size = 0

            record = PacketRecord(
                timestamp=ts,
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                size=len(pkt),
                tcp_flags=tcp_flags,
                payload_size=payload_size,
            )
            records.append(record)
            key = (ip.src, ip.dst, src_port, dst_port, protocol)
            flow_buckets[key].append(record)

        flows = self._build_flows(flow_buckets)
        protocol_distribution = self._count_protocols(records)

        unique_src = {r.src_ip for r in records}
        unique_dst = {r.dst_ip for r in records}
        time_range = f"{records[0].timestamp} \u2013 {records[-1].timestamp}" if records else ""

        return ParseResult(
            source_file=filepath,
            file_type="pcap",
            packet_count=len(records),
            time_range=time_range,
            unique_src_ips=len(unique_src),
            unique_dst_ips=len(unique_dst),
            protocol_distribution=protocol_distribution,
            packets=records,
            flows=flows,
        )

    @staticmethod
    def _detect_protocol(pkt) -> str:
        if pkt.haslayer(DNS):
            return "DNS"
        if pkt.haslayer(TCP):
            return "TCP"
        if pkt.haslayer(UDP):
            return "UDP"
        if pkt.haslayer(ICMP):
            return "ICMP"
        return "OTHER"

    @staticmethod
    def _extract_ports(pkt) -> tuple[int, int]:
        if pkt.haslayer(TCP):
            return pkt[TCP].sport, pkt[TCP].dport
        if pkt.haslayer(UDP):
            return pkt[UDP].sport, pkt[UDP].dport
        return 0, 0

    @staticmethod
    def _extract_tcp_flags(pkt) -> list[str]:
        if not pkt.haslayer(TCP):
            return []
        raw = str(pkt[TCP].flags)
        return [FLAG_MAP[ch] for ch in raw if ch in FLAG_MAP]

    @staticmethod
    def _build_flows(buckets: dict[tuple, list[PacketRecord]]) -> list[ConnectionFlow]:
        flows = []
        for (src_ip, dst_ip, src_port, dst_port, protocol), pkts in buckets.items():
            timestamps = [p.timestamp for p in pkts]
            start, end = min(timestamps), max(timestamps)
            start_dt = datetime.fromisoformat(start)
            end_dt = datetime.fromisoformat(end)
            duration = (end_dt - start_dt).total_seconds()

            flows.append(ConnectionFlow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_count=len(pkts),
                total_bytes=sum(p.size for p in pkts),
                duration_seconds=duration,
                start_time=start,
                end_time=end,
            ))
        return flows

    @staticmethod
    def _count_protocols(records: list[PacketRecord]) -> dict[str, int]:
        dist: dict[str, int] = defaultdict(int)
        for r in records:
            dist[r.protocol] += 1
        return dict(dist)
