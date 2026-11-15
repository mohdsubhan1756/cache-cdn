
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class RecoveryRequest(BaseModel):
    edge_id: Optional[str] = None
    max_events: int = Field(default=100000, ge=1, le=500000)
    min_content_requests: int = Field(default=2, ge=1, le=100000)
    attack_ratio_threshold: float = Field(default=0.50, ge=0.0, le=1.0)
    min_trust_ratio: float = Field(default=0.60, ge=0.0, le=1.0)
    max_evictions_per_edge: int = Field(default=20, ge=0, le=1000)
    max_replications_per_edge: int = Field(default=10, ge=0, le=1000)
    coordinate_edges: bool = True
    apply_recovery: bool = False


class ContentRecoveryAction(BaseModel):
    edge_id: str
    content_id: str
    action: str
    status: str
    total_requests: int = 0
    trusted_requests: int = 0
    attack_requests: int = 0
    attack_ratio: float = 0.0
    trust_ratio: float = 0.0
    content_size_bytes: int = 0
    reason: str


class EdgeRecoverySummary(BaseModel):
    edge_id: str
    events_analyzed: int = 0
    unique_contents_seen: int = 0
    suspicious_contents: int = 0
    trusted_contents: int = 0
    evictions_proposed: int = 0
    evictions_completed: int = 0
    replications_proposed: int = 0
    replications_completed: int = 0
    recovery_status: str
    message: str


class RecoveryResponse(BaseModel):
    success: bool
    mode: str
    events_analyzed: int
    edges_analyzed: int
    attack_events: int
    trusted_events: int
    actions: List[ContentRecoveryAction]
    edge_summaries: List[EdgeRecoverySummary]
    coordination_enabled: bool
    recovery_applied: bool
    message: str


class RecoveryHistoryResponse(BaseModel):
    total_runs: int
    runs: List[Dict]
