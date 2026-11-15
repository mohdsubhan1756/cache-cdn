
from collections import Counter, defaultdict
from datetime import datetime, timezone
from math import log
from threading import RLock
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from app.anomaly_models import (
    AnomalyAnalysisResponse,
    AnomalyTrainingResponse,
    AnomalyWindowResult,
)


class AnomalyDetectionService:
    ALGORITHM = "IsolationForest"

    FEATURE_NAMES = [
        "log_request_count",
        "unique_content_ratio",
        "cache_miss_ratio",
        "mean_content_size_mb",
        "content_size_variation",
        "client_diversity_ratio",
        "content_entropy",
        "dominant_content_ratio",
        "request_rate",
    ]

    def __init__(self):
        self._lock = RLock()
        self.model = None
        self.trained = False
        self.events = []
        self.window_size = 25
        self.training_windows = 0
        self.historical_requests = 0
        self.edges_analyzed = 0
        self.trained_at = None
        self.last_error = None
        self.training_feature_mean = None
        self.training_feature_std = None

    @staticmethod
    def _valid_event(event: dict[str, Any]) -> bool:
        return (
            isinstance(event, dict)
            and bool(event.get("edge_id"))
            and event.get("content_id") is not None
            and str(event.get("content_id")).strip() != ""
        )

    @staticmethod
    def _as_int(value, default=0):
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return default

    @staticmethod
    def _as_float(value, default=0.0):
        try:
            number = float(value)
            if np.isfinite(number):
                return number
        except (TypeError, ValueError, OverflowError):
            pass
        return default

    @staticmethod
    def _timestamp_seconds(value):
        if not value:
            return None

        try:
            if isinstance(value, (int, float)):
                return float(value)

            text = str(value).strip()
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"

            parsed = datetime.fromisoformat(text)

            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)

            return parsed.timestamp()
        except (TypeError, ValueError, OverflowError):
            return None

    @classmethod
    def _normalize_events(cls, events):
        normalized = []

        for event in events:
            if not cls._valid_event(event):
                continue

            normalized.append({
                "edge_id": str(event["edge_id"]),
                "content_id": str(event["content_id"]),
                "response_size_bytes": max(
                    0,
                    cls._as_int(
                        event.get("response_size_bytes", 0)
                    ),
                ),
                "cache_hit": bool(event.get("cache_hit", False)),
                "client_id": str(event.get("client_id") or "unknown"),
                "timestamp": (
                    event.get("source_timestamp")
                    if event.get("source_timestamp") is not None
                    else event.get("timestamp")
                ),
                "scenario": str(event.get("scenario") or ""),
                "is_attack": (
                    event.get("is_attack") is True
                    or str(event.get("is_attack", "")).strip().lower()
                    in {"1", "true", "yes", "attack"}
                ),
            })

        return normalized

    @staticmethod
    def _normalized_entropy(counts):
        total = sum(counts.values())

        if total <= 1 or len(counts) <= 1:
            return 0.0

        entropy = 0.0

        for count in counts.values():
            probability = count / total
            entropy -= probability * log(probability)

        maximum_entropy = log(len(counts))

        if maximum_entropy <= 0:
            return 0.0

        return float(entropy / maximum_entropy)

    def _extract_features(self, window):
        count = len(window)

        if count == 0:
            raise ValueError("Cannot extract features from an empty window.")

        content_counts = Counter(
            item["content_id"] for item in window
        )
        client_counts = Counter(
            item["client_id"] for item in window
        )

        sizes = np.asarray(
            [item["response_size_bytes"] for item in window],
            dtype=float,
        )

        mean_size = float(np.mean(sizes))
        size_std = float(np.std(sizes))

        size_variation = (
            size_std / mean_size if mean_size > 0 else 0.0
        )

        cache_misses = sum(
            1 for item in window if not item["cache_hit"]
        )

        unique_content_ratio = len(content_counts) / count
        client_diversity_ratio = len(client_counts) / count
        dominant_content_ratio = max(content_counts.values()) / count
        entropy = self._normalized_entropy(content_counts)

        timestamps = [
            self._timestamp_seconds(item.get("timestamp"))
            for item in window
        ]
        valid_timestamps = [
            value for value in timestamps if value is not None
        ]

        duration = (
            max(valid_timestamps) - min(valid_timestamps)
            if len(valid_timestamps) >= 2
            else 0.0
        )

        request_rate = count / max(duration, 1.0)

        features = [
            float(np.log1p(count)),
            float(unique_content_ratio),
            float(cache_misses / count),
            float(mean_size / (1024 * 1024)),
            float(size_variation),
            float(client_diversity_ratio),
            float(entropy),
            float(dominant_content_ratio),
            float(np.log1p(request_rate)),
        ]

        reasons = []

        if unique_content_ratio >= 0.90 and count >= 10:
            reasons.append("Very high unique-content ratio")

        if cache_misses / count >= 0.90:
            reasons.append("Very high cache-miss ratio")

        if client_diversity_ratio >= 0.90 and count >= 10:
            reasons.append("High client diversity")

        if size_variation >= 2.0 and mean_size > 0:
            reasons.append("Highly variable content sizes")

        if entropy >= 0.90 and len(content_counts) >= 10:
            reasons.append("Requests spread across many content items")

        return {
            "features": features,
            "window_requests": count,
            "unique_content_count": len(content_counts),
            "unique_content_ratio": unique_content_ratio,
            "cache_miss_ratio": cache_misses / count,
            "mean_content_size_mb": mean_size / (1024 * 1024),
            "content_size_variation": size_variation,
            "client_diversity_ratio": client_diversity_ratio,
            "content_entropy": entropy,
            "dominant_content_ratio": dominant_content_ratio,
            "reasons": reasons,
        }

    @staticmethod
    def _group_by_edge(events):
        groups = defaultdict(list)

        for event in events:
            groups[event["edge_id"]].append(event)

        return groups

    def train(self, events, window_size=25):
        with self._lock:
            self.last_error = None

            try:
                if window_size < 5:
                    raise ValueError(
                        "window_size must be at least 5."
                    )

                normalized = self._normalize_events(events)

                if len(normalized) < window_size * 2:
                    raise ValueError(
                        f"At least {window_size * 2} valid events are "
                        "required to train and reserve a recent window."
                    )

                self.events = normalized
                self.window_size = window_size
                self.historical_requests = len(normalized)

                grouped = self._group_by_edge(normalized)
                feature_rows = []

                # Reserve the latest window at each edge for analysis.
                # Earlier windows are used to fit the detector.
                for edge_id, edge_events in grouped.items():
                    for start in range(
                        0,
                        len(edge_events) - window_size,
                        window_size,
                    ):
                        window = edge_events[
                            start:start + window_size
                        ]

                        if len(window) != window_size:
                            continue

                        feature_rows.append(
                            self._extract_features(window)["features"]
                        )

                self.training_windows = len(feature_rows)
                self.edges_analyzed = len(grouped)
                self.model = None
                self.trained = False

                if len(feature_rows) < 10:
                    raise ValueError(
                        "At least 10 complete historical training "
                        "windows are required. Replay more requests "
                        "or reduce window_size."
                    )

                matrix = np.asarray(feature_rows, dtype=float)

                self.training_feature_mean = np.mean(matrix, axis=0)
                self.training_feature_std = np.std(matrix, axis=0)

                # Prevent division by zero during fallback scoring.
                self.training_feature_std = np.where(
                    self.training_feature_std < 1e-9,
                    1.0,
                    self.training_feature_std,
                )

                self.model = IsolationForest(
                    n_estimators=150,
                    contamination="auto",
                    random_state=42,
                    n_jobs=-1,
                )
                self.model.fit(matrix)

                self.trained = True
                self.trained_at = datetime.now(
                    timezone.utc
                ).isoformat()

                return AnomalyTrainingResponse(
                    trained=True,
                    algorithm=self.ALGORITHM,
                    historical_requests=self.historical_requests,
                    training_windows=self.training_windows,
                    edges_analyzed=self.edges_analyzed,
                    window_size=self.window_size,
                    trained_at=self.trained_at,
                    message=(
                        "Isolation Forest trained on historical "
                        "request windows. The latest window for each "
                        "edge is reserved for anomaly analysis."
                    ),
                )

            except Exception as exc:
                self.last_error = str(exc)
                raise

    def evaluate_labeled(
        self,
        events,
        window_size=25,
        train_ratio=0.8,
        attack_ratio_threshold=0.01,
    ):
        if window_size < 5:
            raise ValueError("window_size must be at least 5.")
        if not 0.5 < train_ratio < 0.95:
            raise ValueError("train_ratio must be between 0.5 and 0.95.")
        if not 0 < attack_ratio_threshold <= 1:
            raise ValueError(
                "attack_ratio_threshold must be greater than 0 and at most 1."
            )

        normalized = self._normalize_events(events)
        if not any(event["scenario"] for event in normalized):
            raise ValueError(
                "Labeled scenario events are required. Replay the bundled "
                "synthetic scenarios before evaluating the anomaly detector."
            )

        grouped = self._group_by_edge(normalized)
        normal_windows = []
        test_windows = []
        known_scenarios = {
            "normal",
            "flash_crowd",
            "cache_pollution",
            "distributed_low_rate",
            "distributed_low_rate_pollution",
        }

        for edge_id, edge_events in grouped.items():
            complete_window_count = len(edge_events) // window_size
            edge_windows = []

            for window_index in range(complete_window_count):
                start = window_index * window_size
                window = edge_events[start:start + window_size]
                scenario_counts = Counter(
                    event["scenario"]
                    for event in window
                    if event["scenario"] in known_scenarios
                )
                if not scenario_counts:
                    continue

                scenario, scenario_count = scenario_counts.most_common(1)[0]
                if scenario_count / len(window) < 0.8:
                    continue

                attack_ratio = sum(
                    event["is_attack"] for event in window
                ) / len(window)
                edge_windows.append({
                    "scenario": scenario,
                    "features": self._extract_features(window)["features"],
                    "is_attack": attack_ratio >= attack_ratio_threshold,
                })

            normal_indices = [
                index
                for index, window in enumerate(edge_windows)
                if window["scenario"] == "normal" and not window["is_attack"]
            ]
            train_count = int(len(normal_indices) * train_ratio)
            if normal_indices:
                train_count = max(1, min(len(normal_indices) - 1, train_count))
            training_indices = set(normal_indices[:train_count])

            for index, window in enumerate(edge_windows):
                if index in training_indices:
                    normal_windows.append(window["features"])
                elif window["scenario"] in known_scenarios:
                    test_windows.append(window)

        if len(normal_windows) < 5:
            raise ValueError(
                "At least 5 labeled normal training windows are required. "
                "Replay more synthetic normal traffic or use a smaller window."
            )
        if not test_windows:
            raise ValueError(
                "No labeled holdout windows are available for evaluation."
            )

        model = IsolationForest(
            n_estimators=150,
            contamination="auto",
            random_state=42,
            n_jobs=-1,
        )
        training_matrix = np.asarray(normal_windows, dtype=float)
        model.fit(training_matrix)

        test_matrix = np.asarray(
            [window["features"] for window in test_windows],
            dtype=float,
        )
        actual = np.asarray(
            [window["is_attack"] for window in test_windows],
            dtype=bool,
        )
        predicted = model.predict(test_matrix) == -1

        true_positive = int(np.sum(actual & predicted))
        false_positive = int(np.sum(~actual & predicted))
        false_negative = int(np.sum(actual & ~predicted))
        true_negative = int(np.sum(~actual & ~predicted))
        precision = (
            true_positive / (true_positive + false_positive)
            if true_positive + false_positive
            else 0.0
        )
        recall = (
            true_positive / (true_positive + false_negative)
            if true_positive + false_negative
            else 0.0
        )
        f1_score = (
            2 * precision * recall / (precision + recall)
            if precision + recall
            else 0.0
        )

        return {
            "algorithm": self.ALGORITHM,
            "window_size": window_size,
            "train_ratio": train_ratio,
            "attack_ratio_threshold": attack_ratio_threshold,
            "training_normal_windows": len(normal_windows),
            "test_windows": len(test_windows),
            "positive_test_windows": int(np.sum(actual)),
            "confusion_matrix": {
                "true_positive": true_positive,
                "false_positive": false_positive,
                "false_negative": false_negative,
                "true_negative": true_negative,
            },
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1_score, 4),
            "message": (
                "Isolation Forest was fit only on labeled normal windows. "
                "A test window is attack-positive when its labeled attack "
                "request ratio meets the configured threshold. These are "
                "synthetic scenario metrics, not real-world accuracy."
            ),
        }

    def _score_window(self, edge_id, window):
        extracted = self._extract_features(window)
        features = np.asarray(
            [extracted["features"]],
            dtype=float,
        )

        if self.trained and self.model is not None:
            decision_score = float(
                self.model.decision_function(features)[0]
            )
            is_anomaly = int(self.model.predict(features)[0]) == -1

            # A bounded 0-100 score, with larger values indicating
            # a more unusual request window.
            anomaly_score = float(
                np.clip(50.0 - decision_score * 100.0, 0.0, 100.0)
            )
            method = self.ALGORITHM

        else:
            standardized = (
                features[0] - self.training_feature_mean
            ) / self.training_feature_std

            anomaly_score = float(
                np.clip(np.mean(np.abs(standardized)) * 20.0, 0.0, 100.0)
            )
            is_anomaly = anomaly_score >= 50.0
            method = "StandardizedFeatureFallback"

        reasons = list(extracted["reasons"])

        if is_anomaly:
            reasons.append(
                "Traffic feature combination deviates from learned patterns"
            )

        if not reasons:
            reasons.append("No strong individual traffic indicator detected")

        if anomaly_score >= 80:
            severity = "HIGH"
        elif anomaly_score >= 60:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return AnomalyWindowResult(
            edge_id=edge_id,
            window_requests=extracted["window_requests"],
            unique_content_count=extracted["unique_content_count"],
            unique_content_ratio=round(
                extracted["unique_content_ratio"], 4
            ),
            cache_miss_ratio=round(
                extracted["cache_miss_ratio"], 4
            ),
            mean_content_size_mb=round(
                extracted["mean_content_size_mb"], 4
            ),
            content_size_variation=round(
                extracted["content_size_variation"], 4
            ),
            client_diversity_ratio=round(
                extracted["client_diversity_ratio"], 4
            ),
            content_entropy=round(
                extracted["content_entropy"], 4
            ),
            dominant_content_ratio=round(
                extracted["dominant_content_ratio"], 4
            ),
            anomaly_score=round(anomaly_score, 2),
            is_anomaly=is_anomaly,
            severity=severity,
            reasons=reasons,
            detection_method=method,
        )

    def analyze(self, edge_id=None):
        with self._lock:
            if not self.events:
                raise ValueError(
                    "No request history is available. Replay a dataset first."
                )

            if not self.trained or self.model is None:
                raise ValueError(
                    "The anomaly detector is not trained. "
                    "Call POST /api/v1/ai/anomaly/train first."
                )

            grouped = self._group_by_edge(self.events)

            if edge_id is not None and edge_id not in grouped:
                raise ValueError(
                    f"No historical requests found for edge '{edge_id}'."
                )

            results = []

            for current_edge_id, edge_events in grouped.items():
                if edge_id is not None and current_edge_id != edge_id:
                    continue

                latest_window = edge_events[-self.window_size:]

                if not latest_window:
                    continue

                results.append(
                    self._score_window(
                        current_edge_id,
                        latest_window,
                    )
                )

            results.sort(
                key=lambda item: item.anomaly_score,
                reverse=True,
            )

            anomaly_count = sum(
                1 for result in results if result.is_anomaly
            )

            return AnomalyAnalysisResponse(
                model_trained=self.trained,
                algorithm=self.ALGORITHM,
                window_size=self.window_size,
                windows_analyzed=len(results),
                anomalies_detected=anomaly_count,
                results=results,
                message=(
                    "Traffic windows analyzed. An anomaly indicates "
                    "unusual behavior, not confirmed malicious activity."
                ),
            )

    def get_status(self):
        with self._lock:
            return {
                "trained": self.trained,
                "algorithm": self.ALGORITHM,
                "historical_requests": self.historical_requests,
                "training_windows": self.training_windows,
                "edges_analyzed": self.edges_analyzed,
                "window_size": self.window_size,
                "trained_at": self.trained_at,
                "last_error": self.last_error,
            }

    def reset(self):
        with self._lock:
            self.model = None
            self.trained = False
            self.events = []
            self.window_size = 25
            self.training_windows = 0
            self.historical_requests = 0
            self.edges_analyzed = 0
            self.trained_at = None
            self.last_error = None
            self.training_feature_mean = None
            self.training_feature_std = None


anomaly_detection_service = AnomalyDetectionService()
