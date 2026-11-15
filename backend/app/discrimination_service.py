
import math
from collections import Counter
from typing import Dict, List, Optional, Tuple

from app.discrimination_models import (
    DiscriminationEvaluationResponse,
    DiscriminationRequest,
    DiscriminationResult,
    DiscriminationResponse,
    TrafficFeatures,
)
from app.metrics_service import metrics_service
from app.simulator import simulator


class TrafficDiscriminationService:
    """
    Module 8: Explainable flash-crowd versus cache-pollution
    discrimination using request-window statistics.

    Ground-truth scenario labels are used only for evaluation,
    never as classifier input.
    """

    CLASSES = [
        "NORMAL",
        "LEGITIMATE_FLASH_CROWD",
        "CACHE_POLLUTION",
        "DISTRIBUTED_LOW_RATE_POLLUTION",
        "SUSPICIOUS",
    ]

    SCENARIO_TO_CLASS = {
        "normal": "NORMAL",
        "flash_crowd": "LEGITIMATE_FLASH_CROWD",
        "cache_pollution": "CACHE_POLLUTION",
        "distributed_low_rate": "DISTRIBUTED_LOW_RATE_POLLUTION",
    }

    @staticmethod
    def _safe_float(value, default=0.0) -> float:
        try:
            result = float(value)
            if math.isfinite(result):
                return result
        except (TypeError, ValueError):
            pass
        return default

    @staticmethod
    def _event_time(event: dict) -> Optional[str]:
        value = event.get("timestamp")
        return str(value) if value is not None else None

    @staticmethod
    def _content_id(event: dict) -> str:
        value = event.get("content_id")
        return str(value) if value is not None else "UNKNOWN_CONTENT"

    @staticmethod
    def _is_cache_hit(event: dict) -> bool:
        value = event.get("cache_hit")
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, str):
            return value.strip().lower() in {"true", "1", "yes"}
        return False

    def _features(self, events: List[dict]) -> TrafficFeatures:
        count = len(events)

        if count == 0:
            return TrafficFeatures(
                request_count=0,
                unique_content_count=0,
                unique_content_ratio=0.0,
                cache_miss_ratio=0.0,
                dominant_content_ratio=0.0,
                content_entropy=0.0,
                mean_content_size_mb=0.0,
            )

        content_counts = Counter(
            self._content_id(event) for event in events
        )

        unique_count = len(content_counts)
        unique_ratio = unique_count / count
        hit_count = sum(self._is_cache_hit(event) for event in events)
        miss_ratio = (count - hit_count) / count
        dominant_ratio = max(content_counts.values()) / count

        # Normalized Shannon entropy: 0 means one dominant item;
        # 1 means all observed items occur equally often.
        entropy = 0.0
        if count > 1 and unique_count > 1:
            raw_entropy = 0.0
            for frequency in content_counts.values():
                probability = frequency / count
                raw_entropy -= probability * math.log2(probability)

            entropy = raw_entropy / math.log2(unique_count)

        sizes = [
            self._safe_float(event.get("response_size_bytes"))
            for event in events
        ]
        sizes = [size for size in sizes if size > 0]

        mean_size_mb = (
            sum(sizes) / len(sizes) / (1024 * 1024)
            if sizes
            else 0.0
        )

        return TrafficFeatures(
            request_count=count,
            unique_content_count=unique_count,
            unique_content_ratio=round(unique_ratio, 4),
            cache_miss_ratio=round(miss_ratio, 4),
            dominant_content_ratio=round(dominant_ratio, 4),
            content_entropy=round(entropy, 4),
            mean_content_size_mb=round(mean_size_mb, 4),
        )



    def _classify(
        self,
        edge_id: str,
        events: List[dict],
    ) -> DiscriminationResult:
        features = self._features(events)

        unique_ratio = features.unique_content_ratio
        miss_ratio = features.cache_miss_ratio
        dominant_ratio = features.dominant_content_ratio
        entropy = features.content_entropy

        reasons = []
        classification = "NORMAL"
        confidence = 0.60

        if len(events) < 10:
            classification = "SUSPICIOUS"
            confidence = 0.20
            reasons.append(
                "Too few requests for reliable classification."
            )

        # Detect mixed traffic first: a popular object exists, but
        # substantial unique-content traffic and misses coexist.
        elif (
            unique_ratio >= 0.15
            and unique_ratio < 0.80
            and miss_ratio >= 0.15
            and dominant_ratio >= 0.15
            and dominant_ratio < 0.85
        ):
            classification = "DISTRIBUTED_LOW_RATE_POLLUTION"
            confidence = 0.70
            reasons.extend([
                "Repeated popular content coexists with unique content.",
                "Cache misses remain elevated.",
                "Mixed traffic is consistent with distributed low-rate pollution.",
            ])

        # Pure cache pollution: almost every request is for a
        # different item, and most requests miss the cache.
        elif (
            unique_ratio >= 0.80
            and miss_ratio >= 0.65
        ):
            classification = "CACHE_POLLUTION"
            confidence = 0.68
            reasons.extend([
                "Very high unique-content ratio.",
                "Very high cache-miss ratio.",
                "Requests have low content reuse.",
            ])

            if entropy >= 0.90:
                reasons.append(
                    "Content requests have high normalized entropy."
                )
                confidence = 0.75

        # Flash crowd: many requests are concentrated on one item,
        # and unique-content traffic is limited.
        elif (
            dominant_ratio >= 0.60
            and unique_ratio <= 0.40
        ):
            classification = "LEGITIMATE_FLASH_CROWD"
            confidence = 0.75
            reasons.extend([
                "Requests are concentrated on a dominant content item.",
                "Content diversity is relatively low.",
            ])

            if miss_ratio >= 0.80:
                reasons.append(
                    "Cache misses are high; inspect the traffic before "
                    "confirming a legitimate flash crowd."
                )
                confidence = 0.60

        elif miss_ratio >= 0.50 and unique_ratio >= 0.50:
            classification = "SUSPICIOUS"
            confidence = 0.50
            reasons.extend([
                "Cache misses and content diversity are elevated.",
                "The available features do not establish the cause.",
            ])

        else:
            classification = "NORMAL"
            confidence = 0.75
            reasons.append(
                "No strong flash-crowd or cache-pollution pattern was found."
            )

        return DiscriminationResult(
            edge_id=edge_id,
            classification=classification,
            confidence=round(confidence, 4),
            features=features,
            reasons=reasons,
            window_start=(
                self._event_time(events[0]) if events else None
            ),
            window_end=(
                self._event_time(events[-1]) if events else None
            ),
        )



    def _load_events(
        self,
        max_events: int,
        edge_id: Optional[str] = None,
    ) -> List[dict]:
        events = metrics_service.get_events()

        if edge_id is not None:
            if edge_id not in simulator.edges:
                raise ValueError(
                    f"Unknown edge '{edge_id}'. Available edges: "
                    f"{', '.join(simulator.edges.keys())}"
                )

            events = [
                event
                for event in events
                if event.get("edge_id") == edge_id
            ]

        return events[-max_events:]

    @staticmethod
    def _group_by_edge(events: List[dict]) -> Dict[str, List[dict]]:
        grouped: Dict[str, List[dict]] = {}

        for event in events:
            edge_id = str(event.get("edge_id", "unknown-edge"))
            grouped.setdefault(edge_id, []).append(event)

        return grouped

    def analyze(
        self,
        request: DiscriminationRequest,
    ) -> DiscriminationResponse:
        events = self._load_events(
            max_events=request.max_events,
            edge_id=request.edge_id,
        )

        grouped = self._group_by_edge(events)
        results = []

        for edge_id, edge_events in grouped.items():
            window = edge_events[-request.window_size:]
            results.append(self._classify(edge_id, window))

        return DiscriminationResponse(
            windows_analyzed=len(results),
            results=results,
            message=(
                "Analyzed the latest request window for each selected "
                "edge. Scenario labels were not used to classify traffic."
            ),
        )

    def evaluate(
        self,
        *,
        window_size: int,
        max_events: int,
        edge_id: Optional[str] = None,
    ) -> DiscriminationEvaluationResponse:
        """
        Evaluate on Module 7's known synthetic scenarios.

        Uses non-overlapping windows. A window is evaluated only when
        at least 80% of its events belong to the same recognized scenario.
        The known labels are evaluation targets only.
        """
        events = self._load_events(max_events, edge_id)
        grouped = self._group_by_edge(events)

        matrix = {
            actual: {predicted: 0 for predicted in self.CLASSES}
            for actual in self.CLASSES
        }

        evaluated = 0
        correct = 0

        for current_edge_events in grouped.values():
            for start in range(0, len(current_edge_events), window_size):
                window = current_edge_events[start:start + window_size]

                if len(window) < window_size:
                    continue

                scenario_counts = Counter(
                    event.get("scenario")
                    for event in window
                    if event.get("scenario") in self.SCENARIO_TO_CLASS
                )

                if not scenario_counts:
                    continue

                scenario, scenario_count = scenario_counts.most_common(1)[0]

                # Skip windows that cross scenario boundaries too much.
                if scenario_count / len(window) < 0.80:
                    continue

                actual = self.SCENARIO_TO_CLASS[scenario]
                edge_id_value = str(
                    window[0].get("edge_id", "unknown-edge")
                )
                prediction = self._classify(
                    edge_id_value,
                    window,
                ).classification

                matrix[actual][prediction] += 1
                evaluated += 1

                if prediction == actual:
                    correct += 1

        per_class: Dict[str, Dict[str, float]] = {}

        for label in self.CLASSES:
            true_positive = matrix[label][label]
            false_positive = sum(
                matrix[actual][label]
                for actual in self.CLASSES
                if actual != label
            )
            false_negative = sum(
                matrix[label][predicted]
                for predicted in self.CLASSES
                if predicted != label
            )

            precision_denominator = true_positive + false_positive
            recall_denominator = true_positive + false_negative

            precision = (
                true_positive / precision_denominator
                if precision_denominator
                else 0.0
            )
            recall = (
                true_positive / recall_denominator
                if recall_denominator
                else 0.0
            )
            f1 = (
                2 * precision * recall / (precision + recall)
                if precision + recall
                else 0.0
            )

            per_class[label] = {
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4),
                "support": float(sum(matrix[label].values())),
            }

        return DiscriminationEvaluationResponse(
            evaluation_windows=evaluated,
            correctly_classified=correct,
            accuracy=round(correct / evaluated, 4) if evaluated else 0.0,
            confusion_matrix=matrix,
            per_class=per_class,
            message=(
                "Evaluation uses Module 7 scenario labels as ground truth. "
                "These are synthetic labels, not real-world attack labels. "
                "Run multiple scenarios before interpreting the metrics."
                if evaluated
                else
                "No complete labeled windows were found. Run Module 7 "
                "scenarios and keep their events in metrics history, then "
                "call this endpoint again."
            ),
        )


traffic_discrimination_service = TrafficDiscriminationService()
