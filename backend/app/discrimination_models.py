
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class DiscriminationRequest(BaseModel):
    edge_id: Optional[str] = None

    window_size: int = Field(
        default=50,
        ge=10,
        le=1000,
    )

    max_events: int = Field(
        default=100000,
        ge=10,
        le=500000,
    )


class TrafficFeatures(BaseModel):
    request_count: int
    unique_content_count: int
    unique_content_ratio: float
    cache_miss_ratio: float
    dominant_content_ratio: float
    content_entropy: float
    mean_content_size_mb: float


class DiscriminationResult(BaseModel):
    edge_id: str
    classification: str
    confidence: float
    features: TrafficFeatures
    reasons: List[str]
    window_start: Optional[str] = None
    window_end: Optional[str] = None
    detection_method: str = "ExplainableRuleBasedClassifier"


class DiscriminationResponse(BaseModel):
    windows_analyzed: int
    results: List[DiscriminationResult]
    message: str


class DiscriminationEvaluationRequest(BaseModel):
    window_size: int = Field(
        default=50,
        ge=10,
        le=1000,
    )

    max_events: int = Field(
        default=100000,
        ge=10,
        le=500000,
    )

    edge_id: Optional[str] = None


class DiscriminationEvaluationResponse(BaseModel):
    evaluation_windows: int
    correctly_classified: int
    accuracy: float
    confusion_matrix: Dict[str, Dict[str, int]]
    per_class: Dict[str, Dict[str, float]]
    message: str
