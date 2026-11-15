
from typing import Literal

from pydantic import BaseModel, Field


AttackScenario = Literal[
    "cache_pollution",
    "distributed_low_rate",
    "flash_crowd",
]


class AttackSimulationRequest(BaseModel):
    scenario: AttackScenario

    edge_id: str = Field(
        default="edge-hyd",
        min_length=1,
        max_length=64,
    )

    request_count: int = Field(
        default=200,
        ge=10,
        le=5000,
        description="Total number of simulated requests.",
    )

    seed: int = Field(
        default=42,
        ge=0,
        le=2147483647,
        description="Seed for reproducible traffic generation.",
    )


class AttackSimulationResponse(BaseModel):
    scenario: AttackScenario
    edge_id: str
    seed: int
    requested_count: int
    processed_requests: int
    attack_requests: int
    legitimate_requests: int
    cache_hits: int
    cache_misses: int
    hit_ratio: float
    origin_requests: int
    origin_bytes_transferred: int
    average_latency_ms: float
    attack_content_count: int
    simulated_clients: int
    message: str
