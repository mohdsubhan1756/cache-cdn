
from typing import Optional

from pydantic import BaseModel, Field


class AnomalyTrainingRequest(BaseModel):
    window_size: int = Field(default=25, ge=5, le=10000)
    max_events: int = Field(default=100000, ge=10, le=500000)


class AnomalyEvaluationRequest(BaseModel):
    window_size: int = Field(default=25, ge=5, le=10000)
    max_events: int = Field(default=100000, ge=10, le=500000)
    train_ratio: float = Field(default=0.8, gt=0.5, lt=0.95)
    attack_ratio_threshold: float = Field(default=0.01, gt=0, le=1)


class AnomalyTrainingResponse(BaseModel):
    trained: bool
    algorithm: str
    historical_requests: int
    training_windows: int
    edges_analyzed: int
    window_size: int
    trained_at: Optional[str] = None
    message: str


class AnomalyWindowResult(BaseModel):
    edge_id: str
    window_requests: int
    unique_content_count: int
    unique_content_ratio: float
    cache_miss_ratio: float
    mean_content_size_mb: float
    content_size_variation: float
    client_diversity_ratio: float
    content_entropy: float
    dominant_content_ratio: float
    anomaly_score: float
    is_anomaly: bool
    severity: str
    reasons: list[str]
    detection_method: str


class AnomalyAnalysisResponse(BaseModel):
    model_trained: bool
    algorithm: str
    window_size: int
    windows_analyzed: int
    anomalies_detected: int
    results: list[AnomalyWindowResult]
    message: str


class AnomalyModelStatusResponse(BaseModel):
    trained: bool
    algorithm: str
    historical_requests: int
    training_windows: int
    edges_analyzed: int
    window_size: int
    trained_at: Optional[str] = None
    last_error: Optional[str] = None
