
from typing import List, Optional

from pydantic import BaseModel, Field


class TrustedDemandRequest(BaseModel):
    edge_id: Optional[str] = Field(
        default=None,
        description="CDN edge ID. Omit to analyze all edges.",
    )
    window_size: int = Field(
        default=50,
        ge=10,
        le=1000,
        description="Number of events in each traffic-classification window.",
    )
    max_events: int = Field(
        default=100000,
        ge=10,
        le=500000,
        description="Maximum number of recent events to analyze.",
    )


class ContentTrustedDemand(BaseModel):
    edge_id: str
    content_id: str

    total_requests: int
    trusted_requests: float
    suspicious_requests: float
    attack_requests: float

    trusted_demand_score: float
    trust_ratio: float

    cache_hits: int
    cache_misses: int
    average_latency_ms: float
    response_size_bytes: int

    classification_counts: dict
    demand_status: str
    explanation: List[str]


class EdgeTrustedDemandSummary(BaseModel):
    edge_id: str
    total_requests: int
    trusted_requests: float
    suspicious_requests: float
    attack_requests: float
    unique_content_count: int
    trusted_content_count: int
    average_trust_ratio: float


class TrustedDemandResponse(BaseModel):
    events_analyzed: int
    windows_analyzed: int
    results_count: int
    edge_summaries: List[EdgeTrustedDemandSummary]
    content_demand: List[ContentTrustedDemand]
    classification_weights: dict
    message: str
