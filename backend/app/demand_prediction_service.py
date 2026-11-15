
from collections import defaultdict
from datetime import datetime, timezone
from threading import RLock
from typing import Any

import numpy as np
from sklearn.ensemble import RandomForestRegressor

from app.demand_models import (
    DemandPredictionItem,
    DemandPredictionResponse,
    DemandTrainingResponse,
)


class DemandPredictionService:
    """
    Module 5: AI-based demand prediction.

    Historical request events are divided into sequential windows.
    The model learns to predict the number of requests for a
    content-edge pair in the next window.

    The fallback predictor uses recency-weighted historical demand
    when insufficient training samples are available.
    """

    ALGORITHM = "RandomForestRegressor"
    ZERO_WINDOW_SAMPLE_RATIO = 10

    FEATURE_NAMES = [
        "lag_1",
        "lag_2",
        "lag_3",
        "mean_last_3",
        "demand_trend",
        "historical_total",
        "content_size_mb",
        "edge_index",
    ]

    def __init__(self):
        self._lock = RLock()

        self.model = None
        self.trained = False
        self.training_samples = 0
        self.historical_requests = 0
        self.content_edge_pairs = 0
        self.window_size = 25
        self.trained_at = None
        self.last_error = None

        self.events = []
        self.bucket_counts = {}
        self.content_sizes = {}
        self.edge_ids = []
        self.edge_indices = {}
        self.bucket_count = 0

    @staticmethod
    def _valid_event(event: dict[str, Any]) -> bool:
        return (
            isinstance(event, dict)
            and bool(event.get("edge_id"))
            and event.get("content_id") is not None
            and str(event.get("content_id")).strip() != ""
        )

    @staticmethod
    def _event_size(event: dict[str, Any]) -> int:
        try:
            return max(0, int(event.get("response_size_bytes", 0) or 0))
        except (TypeError, ValueError, OverflowError):
            return 0

    def _features(
        self,
        counts: list[int],
        target_index: int,
        content_size_bytes: int,
        edge_index: int,
    ) -> list[float]:
        """
        Construct features using only windows preceding target_index.
        Missing earlier windows are treated as zero demand.
        """
        lag_1 = counts[target_index - 1] if target_index >= 1 else 0
        lag_2 = counts[target_index - 2] if target_index >= 2 else 0
        lag_3 = counts[target_index - 3] if target_index >= 3 else 0

        mean_last_3 = (lag_1 + lag_2 + lag_3) / 3.0
        demand_trend = float(lag_1 - lag_2)
        historical_total = float(sum(counts[:target_index]))

        return [
            float(lag_1),
            float(lag_2),
            float(lag_3),
            float(mean_last_3),
            demand_trend,
            historical_total,
            float(content_size_bytes) / (1024 * 1024),
            float(edge_index),
        ]

    @classmethod
    def _sample_window_targets(
        cls,
        counts: list[int],
        start_index: int,
        end_index: int,
    ) -> list[tuple[int, float]]:
        """Bound zero-demand examples while preserving their total weight."""
        positive_indices = []
        zero_indices = []

        for target_index in range(
            max(1, start_index),
            min(end_index, len(counts)),
        ):
            if counts[target_index] > 0:
                positive_indices.append(target_index)
            else:
                zero_indices.append(target_index)

        sample_limit = max(
            1,
            len(positive_indices) * cls.ZERO_WINDOW_SAMPLE_RATIO,
        )
        if len(zero_indices) > sample_limit:
            sample_positions = np.linspace(
                0,
                len(zero_indices) - 1,
                num=sample_limit,
                dtype=int,
            )
            sampled_zero_indices = [
                zero_indices[position] for position in sample_positions
            ]
        else:
            sampled_zero_indices = zero_indices

        samples = [(index, 1.0) for index in positive_indices]
        if sampled_zero_indices:
            zero_sample_weight = len(zero_indices) / len(sampled_zero_indices)
            samples.extend(
                (index, zero_sample_weight)
                for index in sampled_zero_indices
            )
        return samples

    @staticmethod
    def _normalize_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized = []

        for event in events:
            if not DemandPredictionService._valid_event(event):
                continue

            normalized.append(
                {
                    "edge_id": str(event["edge_id"]),
                    "content_id": str(event["content_id"]),
                    "response_size_bytes": DemandPredictionService._event_size(
                        event
                    ),
                }
            )

        return normalized

    def train(
        self,
        events: list[dict[str, Any]],
        window_size: int = 25,
    ) -> DemandTrainingResponse:
        with self._lock:
            self.last_error = None

            try:
                if window_size < 5:
                    raise ValueError("window_size must be at least 5.")

                normalized = self._normalize_events(events)

                if len(normalized) < 10:
                    raise ValueError(
                        "At least 10 valid request events are required. "
                        "Replay a dataset or submit more requests first."
                    )

                self.events = normalized
                self.window_size = window_size
                self.historical_requests = len(normalized)

                self.edge_ids = sorted(
                    {event["edge_id"] for event in normalized}
                )
                self.edge_indices = {
                    edge_id: index
                    for index, edge_id in enumerate(self.edge_ids)
                }

                number_of_windows = (
                    len(normalized) + window_size - 1
                ) // window_size

                counts = defaultdict(
                    lambda: [0] * number_of_windows
                )
                sizes = defaultdict(list)

                for request_index, event in enumerate(normalized):
                    bucket_index = request_index // window_size
                    pair = (
                        event["edge_id"],
                        event["content_id"],
                    )

                    counts[pair][bucket_index] += 1

                    if event["response_size_bytes"] > 0:
                        sizes[pair].append(
                            event["response_size_bytes"]
                        )

                self.bucket_counts = {
                    pair: values
                    for pair, values in counts.items()
                }
                self.content_sizes = {
                    pair: int(np.median(values))
                    for pair, values in sizes.items()
                }
                self.bucket_count = number_of_windows
                self.content_edge_pairs = len(counts)

                features = []
                targets = []
                sample_weights = []

                for pair, demand_counts in self.bucket_counts.items():
                    edge_id, _ = pair
                    size_bytes = self.content_sizes.get(pair, 0)
                    edge_index = self.edge_indices[edge_id]

                    # Each target is a historical window. All features
                    # are calculated exclusively from earlier windows.
                    for target_index, sample_weight in (
                        self._sample_window_targets(
                            demand_counts,
                            1,
                            number_of_windows,
                        )
                    ):
                        row = self._features(
                            demand_counts,
                            target_index,
                            size_bytes,
                            edge_index,
                        )

                        features.append(row)
                        targets.append(
                            float(demand_counts[target_index])
                        )
                        sample_weights.append(sample_weight)

                self.training_samples = len(features)
                self.model = None
                self.trained = False

                if len(features) >= 10:
                    model = RandomForestRegressor(
                        n_estimators=120,
                        max_depth=12,
                        min_samples_leaf=2,
                        random_state=42,
                        n_jobs=-1,
                    )

                    model.fit(
                        np.asarray(features, dtype=float),
                        np.asarray(targets, dtype=float),
                        sample_weight=np.asarray(sample_weights, dtype=float),
                    )

                    self.model = model
                    self.trained = True

                self.trained_at = datetime.now(
                    timezone.utc
                ).isoformat()

                message = (
                    "Random Forest demand model trained successfully. "
                    "Sparse zero-demand windows were deterministically "
                    "sampled and weighted."
                    if self.trained
                    else
                    "Historical demand was loaded, but there are fewer "
                    "than 10 training samples. Predictions will use "
                    "the recency-weighted fallback until more history "
                    "is available."
                )

                return DemandTrainingResponse(
                    trained=self.trained,
                    algorithm=self.ALGORITHM,
                    training_samples=self.training_samples,
                    historical_requests=self.historical_requests,
                    content_edge_pairs=self.content_edge_pairs,
                    window_size=self.window_size,
                    trained_at=self.trained_at,
                    message=message,
                )

            except Exception as exc:
                self.last_error = str(exc)
                raise

    def _fallback_prediction(
        self,
        counts: list[int],
    ) -> float:
        if not counts:
            return 0.0

        recent = list(reversed(counts[-3:]))

        weights = [0.6, 0.3, 0.1]
        weighted_sum = 0.0
        weight_sum = 0.0

        for index, weight in enumerate(weights):
            if index < len(recent):
                weighted_sum += recent[index] * weight
                weight_sum += weight

        if weight_sum == 0:
            return 0.0

        return max(0.0, weighted_sum / weight_sum)

    def evaluate(
        self,
        events: list[dict[str, Any]],
        window_size: int = 25,
        train_ratio: float = 0.8,
    ) -> dict[str, Any]:
        with self._lock:
            if window_size < 5:
                raise ValueError("window_size must be at least 5.")
            if not 0.5 < train_ratio < 0.95:
                raise ValueError("train_ratio must be between 0.5 and 0.95.")

            normalized = self._normalize_events(events)
            number_of_windows = len(normalized) // window_size

            if number_of_windows < 3:
                raise ValueError(
                    "At least 3 complete demand windows are required "
                    "for chronological evaluation."
                )

            normalized = normalized[:number_of_windows * window_size]
            split_index = int(number_of_windows * train_ratio)
            split_index = max(2, min(number_of_windows - 1, split_index))
            counts_by_pair = defaultdict(
                lambda: [0] * number_of_windows
            )
            training_sizes = defaultdict(list)

            for event_index, event in enumerate(normalized):
                bucket_index = event_index // window_size
                pair = (event["edge_id"], event["content_id"])
                counts_by_pair[pair][bucket_index] += 1

                if (
                    bucket_index < split_index
                    and event["response_size_bytes"] > 0
                ):
                    training_sizes[pair].append(
                        event["response_size_bytes"]
                    )

            edge_ids = sorted({pair[0] for pair in counts_by_pair})
            edge_indices = {
                edge_id: index for index, edge_id in enumerate(edge_ids)
            }
            training_features = []
            training_targets = []
            training_weights = []
            test_features = []
            test_targets = []
            test_weights = []
            baseline_predictions = []

            for pair, demand_counts in counts_by_pair.items():
                edge_id, _ = pair
                size_bytes = (
                    int(np.median(training_sizes[pair]))
                    if training_sizes[pair]
                    else 0
                )

                for target_index, sample_weight in (
                    self._sample_window_targets(
                        demand_counts,
                        1,
                        split_index,
                    )
                ):
                    row = self._features(
                        demand_counts,
                        target_index,
                        size_bytes,
                        edge_indices[edge_id],
                    )
                    target = float(demand_counts[target_index])

                    if target_index < split_index:
                        training_features.append(row)
                        training_targets.append(target)
                        training_weights.append(sample_weight)

                for target_index, sample_weight in (
                    self._sample_window_targets(
                        demand_counts,
                        split_index,
                        number_of_windows,
                    )
                ):
                    row = self._features(
                        demand_counts,
                        target_index,
                        size_bytes,
                        edge_indices[edge_id],
                    )
                    target = float(demand_counts[target_index])
                    test_features.append(row)
                    test_targets.append(target)
                    test_weights.append(sample_weight)
                    baseline_predictions.append(
                        self._fallback_prediction(
                            demand_counts[:target_index]
                        )
                    )

            if len(training_features) < 10:
                raise ValueError(
                    "At least 10 training samples are required for "
                    "evaluation. Replay more requests or increase "
                    "the window count."
                )
            if not test_features:
                raise ValueError(
                    "The chronological split produced no test samples."
                )

            model = RandomForestRegressor(
                n_estimators=120,
                max_depth=12,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1,
            )
            model.fit(
                np.asarray(training_features, dtype=float),
                np.asarray(training_targets, dtype=float),
                sample_weight=np.asarray(training_weights, dtype=float),
            )
            actual = np.asarray(test_targets, dtype=float)
            forest_predictions = np.maximum(
                0.0,
                model.predict(np.asarray(test_features, dtype=float)),
            )
            baseline = np.asarray(baseline_predictions, dtype=float)

            def error_metrics(predictions):
                errors = actual - predictions
                return {
                    "mae": round(
                        float(np.average(np.abs(errors), weights=test_weights)),
                        6,
                    ),
                    "rmse": round(
                        float(
                            np.sqrt(
                                np.average(errors ** 2, weights=test_weights)
                            )
                        ),
                        6,
                    ),
                }

            forest_metrics = error_metrics(forest_predictions)
            baseline_metrics = error_metrics(baseline)
            baseline_mae = baseline_metrics["mae"]
            improvement = (
                round(
                    100.0
                    * (baseline_mae - forest_metrics["mae"])
                    / baseline_mae,
                    2,
                )
                if baseline_mae > 0
                else 0.0
            )

            return {
                "algorithm": self.ALGORITHM,
                "baseline": "RecencyWeightedFallback",
                "window_size": window_size,
                "train_ratio": train_ratio,
                "complete_windows": number_of_windows,
                "training_samples": len(training_features),
                "test_samples": len(test_features),
                "training_windows": split_index,
                "test_windows": number_of_windows - split_index,
                "random_forest": forest_metrics,
                "recency_weighted_baseline": baseline_metrics,
                "mae_improvement_percent": improvement,
                "message": (
                    "Metrics use a chronological holdout. Content sizes "
                    "are computed from training events only. Sparse "
                    "zero-demand windows are deterministically sampled "
                    "and weighted. Lower MAE and RMSE are better."
                ),
            }

    def predict(
        self,
        edge_id: str | None = None,
        limit: int = 100,
    ) -> DemandPredictionResponse:
        with self._lock:
            if not self.bucket_counts:
                raise ValueError(
                    "No demand history is available. "
                    "Train the model after recording or replaying requests."
                )

            if edge_id is not None and edge_id not in self.edge_indices:
                raise ValueError(
                    f"No historical demand exists for edge '{edge_id}'."
                )

            predictions = []
            feature_rows = []

            for pair, demand_counts in self.bucket_counts.items():
                pair_edge_id, content_id = pair

                if edge_id is not None and pair_edge_id != edge_id:
                    continue

                content_size = self.content_sizes.get(pair, 0)
                edge_index = self.edge_indices[pair_edge_id]

                row = self._features(
                    demand_counts,
                    len(demand_counts),
                    content_size,
                    edge_index,
                )

                if self.trained and self.model is not None:
                    feature_rows.append(row)
                    method = self.ALGORITHM
                else:
                    prediction = self._fallback_prediction(
                        demand_counts
                    )
                    method = "RecencyWeightedFallback"

                predictions.append(
                    {
                        "edge_id": pair_edge_id,
                        "content_id": content_id,
                        "content_size_bytes": content_size,
                        "historical_requests": int(
                            sum(demand_counts)
                        ),
                        "recent_requests": int(
                            sum(demand_counts[-3:])
                        ),
                        "predicted_requests_next_window": (
                            None
                            if self.trained and self.model is not None
                            else round(max(0.0, prediction), 4)
                        ),
                        "prediction_method": method,
                    }
                )

            if self.trained and self.model is not None and predictions:
                model_predictions = self.model.predict(
                    np.asarray(feature_rows, dtype=float)
                )
                for item, prediction in zip(predictions, model_predictions):
                    item["predicted_requests_next_window"] = round(
                        max(0.0, float(prediction)),
                        4,
                    )

            predictions.sort(
                key=lambda item: item[
                    "predicted_requests_next_window"
                ],
                reverse=True,
            )

            max_prediction = max(
                (
                    item["predicted_requests_next_window"]
                    for item in predictions
                ),
                default=0.0,
            )

            for item in predictions:
                if max_prediction > 0:
                    item["demand_score"] = round(
                        100.0
                        * item["predicted_requests_next_window"]
                        / max_prediction,
                        2,
                    )
                else:
                    item["demand_score"] = 0.0

            predictions = predictions[:limit]

            return DemandPredictionResponse(
                model_trained=self.trained,
                algorithm=self.ALGORITHM,
                edge_id=edge_id,
                window_size=self.window_size,
                predictions_count=len(predictions),
                predictions=[
                    DemandPredictionItem(**item)
                    for item in predictions
                ],
                message=(
                    "Predicted demand for the next request window."
                    if self.trained
                    else
                    "Predictions use historical recency weighting "
                    "because the training sample count was insufficient."
                ),
            )

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "trained": self.trained,
                "algorithm": self.ALGORITHM,
                "training_samples": self.training_samples,
                "historical_requests": self.historical_requests,
                "content_edge_pairs": self.content_edge_pairs,
                "window_size": self.window_size,
                "trained_at": self.trained_at,
                "last_error": self.last_error,
            }

    def get_historical_edges(self) -> list[str]:
        with self._lock:
            return list(self.edge_ids)

    def reset(self) -> None:
        with self._lock:
            self.model = None
            self.trained = False
            self.training_samples = 0
            self.historical_requests = 0
            self.content_edge_pairs = 0
            self.window_size = 25
            self.trained_at = None
            self.last_error = None
            self.events = []
            self.bucket_counts = {}
            self.content_sizes = {}
            self.edge_ids = []
            self.edge_indices = {}
            self.bucket_count = 0


demand_prediction_service = DemandPredictionService()
