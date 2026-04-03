"""
Live Capture Agent — Real-time packet sniffing with scapy.

Captures network packets from a specified interface, converts them
to the same PacketRecord/ConnectionFlow format as PcapParser, and
optionally saves the capture to a PCAP file for later analysis.

Requires elevated privileges (root/admin) for raw socket access.
"""

import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from threading import Event

from scapy.all import DNS, ICMP, IP, TCP, UDP, sniff, wrpcap

from models.network import ConnectionFlow, PacketRecord, ParseResult

FLAG_MAP = {"S": "SYN", "A": "ACK", "R": "RST", "F": "FIN", "P": "PSH", "U": "URG"}


class LiveCaptureAgent:
    """
    Captures live network traffic and produces a ParseResult
    compatible with the existing analysis pipeline.

    Usage:
        agent = LiveCaptureAgent()
        result = agent.capture(interface="en0", duration=30, max_packets=1000)
    """

    def __init__(self):
        self._records: list[PacketRecord] = []
        self._raw_packets: list = []
        self._stop_event = Event()

    def capture(
        self,
        interface: str | None = None,
        duration: int = 30,
        max_packets: int = 10000,
        bpf_filter: str = "",
        save_path: str | None = None,
    ) -> ParseResult:
        """
        Capture live packets from a network interface.

        Args:
            interface:   Network interface (e.g., "en0", "eth0"). None for default.
            duration:    Capture duration in seconds (max 300).
            max_packets: Maximum packets to capture (max 100000).
            bpf_filter:  BPF filter string (e.g., "tcp port 80").
            save_path:   If set, save captured packets to this PCAP file.

        Returns:
            ParseResult with captured packets and flows.

        Raises:
            PermissionError: If not running with sufficient privileges.
            ValueError: If no packets were captured.
        """
        duration = min(max(1, duration), 300)
        max_packets = min(max(1, max_packets), 100000)

        self._records = []
        self._raw_packets = []
        self._stop_event.clear()

        sniff_kwargs = {
            "prn": self._process_packet,
            "store": True,
            "timeout": duration,
            "count": max_packets,
        }

        if interface:
            sniff_kwargs["iface"] = interface
        if bpf_filter:
            sniff_kwargs["filter"] = bpf_filter

        try:
            captured = sniff(**sniff_kwargs)
        except PermissionError:
            raise PermissionError(
                "Packet capture requires elevated privileges. "
                "Run with sudo or as administrator."
            )

        self._raw_packets = list(captured)

        if save_path and self._raw_packets:
            os.makedirs(os.path.dirname(save_path) or ".", exist_ok=True)
            wrpcap(save_path, self._raw_packets)

        if not self._records:
            raise ValueError(
                "No IP packets captured. Check the interface name and filters."
            )

        flows = self._build_flows()
        protocol_dist = self._count_protocols()

        unique_src = {r.src_ip for r in self._records}
        unique_dst = {r.dst_ip for r in self._records}
        time_range = (
            f"{self._records[0].timestamp} – {self._records[-1].timestamp}"
            if self._records else ""
        )

        source_label = f"live:{interface or 'default'}"

        return ParseResult(
            source_file=source_label,
            file_type="pcap",
            packet_count=len(self._records),
            time_range=time_range,
            unique_src_ips=len(unique_src),
            unique_dst_ips=len(unique_dst),
            protocol_distribution=protocol_dist,
            packets=self._records,
            flows=flows,
        )

    def stop(self):
        """Signal the capture to stop early."""
        self._stop_event.set()

    def _process_packet(self, pkt):
        """Callback for each captured packet — extract and store as PacketRecord."""
        if self._stop_event.is_set():
            return

        if not pkt.haslayer(IP):
            return

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
        self._records.append(record)

    def _build_flows(self) -> list[ConnectionFlow]:
        """Group captured packets into connection flows."""
        buckets: dict[tuple, list[PacketRecord]] = defaultdict(list)
        for r in self._records:
            key = (r.src_ip, r.dst_ip, r.src_port, r.dst_port, r.protocol)
            buckets[key].append(r)

        flows = []
        for (src_ip, dst_ip, src_port, dst_port, protocol), pkts in buckets.items():
            timestamps = [p.timestamp for p in pkts]
            start, end = min(timestamps), max(timestamps)
            start_dt = datetime.fromisoformat(start)
            end_dt = datetime.fromisoformat(end)
            duration_sec = (end_dt - start_dt).total_seconds()

            flows.append(ConnectionFlow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_count=len(pkts),
                total_bytes=sum(p.size for p in pkts),
                duration_seconds=duration_sec,
                start_time=start,
                end_time=end,
            ))
        return flows

    def _count_protocols(self) -> dict[str, int]:
        dist: dict[str, int] = defaultdict(int)
        for r in self._records:
            dist[r.protocol] += 1
        return dict(dist)

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
