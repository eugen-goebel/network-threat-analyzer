"""Pydantic models for parsed network traffic and log data."""

from typing import Literal

from pydantic import BaseModel


class PacketRecord(BaseModel):
    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    size: int
    tcp_flags: list[str] = []
    payload_size: int = 0


class ConnectionFlow(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_count: int
    total_bytes: int
    duration_seconds: float
    start_time: str
    end_time: str


class ParseResult(BaseModel):
    source_file: str
    file_type: Literal["pcap", "syslog", "apache", "nginx"]
    packet_count: int
    time_range: str
    unique_src_ips: int
    unique_dst_ips: int
    protocol_distribution: dict[str, int]
    packets: list[PacketRecord]
    flows: list[ConnectionFlow]


class LogEntry(BaseModel):
    timestamp: str
    source_ip: str
    message: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    service: str = ""
    raw_line: str = ""


class LogParseResult(BaseModel):
    source_file: str
    log_format: str
    entry_count: int
    time_range: str
    entries: list[LogEntry]
    error_entries: list[LogEntry]
