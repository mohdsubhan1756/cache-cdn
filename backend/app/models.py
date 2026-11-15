
from pydantic import BaseModel, Field


class SimulateRequest(BaseModel):
    edge_id: str = Field(
        ...,
        description="Target edge node ID",
        examples=["edge-hyd"],
    )

    content_id: str = Field(
        ...,
        min_length=1,
        description="Identifier of the requested content",
        examples=["article-1001"],
    )

    response_size_bytes: int = Field(
        ...,
        ge=0,
        description="Content size in bytes",
        examples=[69334],
    )


class SimulateResponse(BaseModel):
    request_id: str
    edge_id: str
    content_id: str
    response_size_bytes: int
    cache_hit: bool
    served_by: str
    origin_latency_ms: float
    edge_processing_latency_ms: float
    total_latency_ms: float
    origin_bytes_transferred: int
    cache_strategy: str
    message: str


class ResetResponse(BaseModel):
    message: str
    reset: bool
