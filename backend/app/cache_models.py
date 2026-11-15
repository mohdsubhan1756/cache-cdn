from typing import Literal

from pydantic import BaseModel, Field


CacheStrategy = Literal["LRU", "LFU", "FIFO", "PREDICTIVE"]


class CacheStrategyRequest(BaseModel):
    strategy: CacheStrategy


class CacheConfigurationResponse(BaseModel):
    edge_id: str
    strategy: CacheStrategy
    capacity_bytes: int
    used_bytes: int
    object_count: int
    utilization_percent: float


class CacheObjectResponse(BaseModel):
    content_id: str
    size_bytes: int
    frequency: int
    inserted_at: int
    last_accessed_at: int
    predictive_score: float


class CacheStatsResponse(BaseModel):
    edge_id: str
    strategy: CacheStrategy
    requests: int
    hits: int
    misses: int
    hit_ratio: float
    evictions: int
    objects_cached: int
    used_bytes: int
    capacity_bytes: int
    utilization_percent: float