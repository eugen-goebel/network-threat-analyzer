"""Pydantic models for threat detection and classification results."""

from typing import Literal

from pydantic import BaseModel, Field


class RuleAlert(BaseModel):
    rule_name: str
    severity: Literal["critical", "high", "medium", "low"]
    category: str
    description: str
    source_ips: list[str]
    dest_ips: list[str]
    timestamps: list[str]
    evidence: dict


class AnomalyAlert(BaseModel):
    time_window_start: str
    time_window_end: str
    anomaly_score: float
    contributing_features: list[str]
    model_votes: dict[str, int]


class ClassifiedThreat(BaseModel):
    category: Literal[
        "PORT_SCAN",
        "DDOS_ATTACK",
        "BRUTE_FORCE",
        "SUSPICIOUS_CONNECTION",
        "ANOMALOUS_TRAFFIC",
    ]
    severity_score: int = Field(ge=0, le=100)
    severity_label: Literal["critical", "high", "medium", "low"]
    title: str
    description: str
    source_ips: list[str]
    dest_ips: list[str]
    time_range: str
    evidence: dict
    detection_method: Literal["rule", "ml", "both"]
    recommendations: list[str]


class ThreatReport(BaseModel):
    total_threats: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    threats: list[ClassifiedThreat]
    analysis_duration_seconds: float
    packets_analyzed: int
    time_range_analyzed: str
