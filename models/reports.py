"""Pydantic models for report generation and visualization config."""

from pydantic import BaseModel

from models.threats import ThreatReport


class ChartConfig(BaseModel):
    filename: str
    chart_type: str
    title: str
    description: str


class VisualizationResult(BaseModel):
    chart_dir: str
    charts: list[ChartConfig]


class AnalysisSummary(BaseModel):
    source_files: list[str]
    total_packets: int
    total_log_entries: int
    time_range: str
    unique_ips: int
    protocol_breakdown: dict[str, int]
    threat_summary: ThreatReport
