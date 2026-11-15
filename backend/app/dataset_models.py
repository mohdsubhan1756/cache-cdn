from typing import Optional

from pydantic import BaseModel, Field


class NormalizedRequest(BaseModel):
    dataset: str
    request_id: str
    timestamp: Optional[float] = None
    content_id: str
    response_size_bytes: int = Field(ge=0)
    client_id: Optional[str] = None
    method: Optional[str] = None
    status_code: Optional[int] = None
    response_time_seconds: Optional[float] = None
    scenario: Optional[str] = None
    event_type: Optional[str] = None
    is_attack: Optional[bool] = None


class DatasetInfo(BaseModel):
    name: str
    description: str
    file_exists: bool
    path: str


class DatasetPreviewResponse(BaseModel):
    dataset: str
    records: list[NormalizedRequest]
    returned_records: int
    skipped_records: int


class DatasetReplayRequest(BaseModel):
    dataset: str
    edge_id: str = "edge-hyd"
    limit: int = Field(default=100, ge=1, le=10000)


class DatasetReplayResponse(BaseModel):
    dataset: str
    edge_id: str
    requested_limit: int
    processed_requests: int
    skipped_records: int
    attack_labeled_requests: int
    scenario_counts: dict[str, int]
    cache_hits: int
    origin_requests: int
    origin_bytes_transferred: int
    average_latency_ms: float
    results: list[dict]