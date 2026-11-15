
from typing import Optional

from pydantic import BaseModel, Field


class DemandTrainingRequest(BaseModel):
    window_size: int = Field(
        default=25,
        ge=5,
        le=10000,
        description="Number of requests in each historical demand window.",
    )
    max_events: int = Field(
        default=100000,
        ge=10,
        le=500000,
        description="Maximum number of recorded request events to use.",
    )


class DemandEvaluationRequest(BaseModel):
    window_size: int = Field(default=25, ge=5, le=10000)
    max_events: int = Field(default=100000, ge=30, le=500000)
    train_ratio: float = Field(default=0.8, gt=0.5, lt=0.95)


class DemandTrainingResponse(BaseModel):
    trained: bool
    algorithm: str
    training_samples: int
    historical_requests: int
    content_edge_pairs: int
    window_size: int
    trained_at: Optional[str] = None
    message: str


class DemandPredictionItem(BaseModel):
    edge_id: str
    content_id: str
    content_size_bytes: int
    historical_requests: int
    recent_requests: int
    predicted_requests_next_window: float
    demand_score: float
    prediction_method: str


class DemandPredictionResponse(BaseModel):
    model_trained: bool
    algorithm: str
    edge_id: Optional[str] = None
    window_size: int
    predictions_count: int
    predictions: list[DemandPredictionItem]
    message: str


class DemandModelStatusResponse(BaseModel):
    trained: bool
    algorithm: str
    training_samples: int
    historical_requests: int
    content_edge_pairs: int
    window_size: int
    trained_at: Optional[str] = None
    last_error: Optional[str] = None
