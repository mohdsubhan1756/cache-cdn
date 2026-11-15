
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class PlacementRequest(BaseModel):
    edge_id: Optional[str] = Field(
        default=None,
        description="Target edge ID. Omit to evaluate all CDN edges.",
    )
    prediction_limit: int = Field(default=100, ge=1, le=10000)
    max_events: int = Field(default=100000, ge=10, le=500000)
    window_size: int = Field(default=50, ge=10, le=1000)
    uncertainty_penalty: float = Field(default=1.0, ge=0.0, le=10.0)
    apply_placement: bool = Field(
        default=False,
        description=(
            "When true, insert the highest-ranked eligible content "
            "into the existing edge caches."
        ),
    )


class PlacementCandidate(BaseModel):
    edge_id: str
    content_id: str
    content_size_bytes: int

    historical_requests: int
    predicted_requests_next_window: float
    trusted_demand_score: float
    trust_ratio: float

    predicted_trusted_demand: float
    network_benefit: float
    uncertainty: float
    placement_score: float

    eligible: bool
    placement_status: str
    explanation: List[str]


class EdgePlacementSummary(BaseModel):
    edge_id: str
    cache_capacity_bytes: int
    cache_capacity_mb: float
    candidates_evaluated: int
    eligible_candidates: int
    placements_attempted: int
    placements_inserted: int
    selected_content_ids: List[str]
    message: str


class PlacementResponse(BaseModel):
    model_trained: bool
    algorithm: str
    apply_placement: bool
    uncertainty_penalty: float
    candidates_count: int
    candidates: List[PlacementCandidate]
    edge_summaries: List[EdgePlacementSummary]
    message: str
