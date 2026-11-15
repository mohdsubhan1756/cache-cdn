
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Tuple

from app.metrics_service import metrics_service
from app.discrimination_service import traffic_discrimination_service

from app.trusted_demand_models import (
    TrustedDemandRequest,
    TrustedDemandResponse,
    ContentTrustedDemand,
    EdgeTrustedDemandSummary,
)
from app.simulator import simulator


CLASSIFICATION_WEIGHTS = {
    "NORMAL": 1.0,
    "LEGITIMATE_FLASH_CROWD": 1.0,
    "SUSPICIOUS": 0.35,
    "DISTRIBUTED_LOW_RATE_POLLUTION": 0.10,
    "CACHE_POLLUTION": 0.0,
}

class TrustedDemandService:
    """
    Estimates trusted content demand from recorded CDN request events.

    Module 4 supplies request events.
    Module 8 supplies traffic classifications.
    Module 7 attack labels override classification weights.
    """

    def __init__(self):
        self.classification_weights = dict(CLASSIFICATION_WEIGHTS)

    @staticmethod
    def _safe_float(value, default=0.0) -> float:
        try:
            result = float(value)
            return result if result >= 0 else default
        except (TypeError, ValueError, OverflowError):
            return default

    @staticmethod
    def _safe_int(value, default=0) -> int:
        try:
            result = int(value)
            return result if result >= 0 else default
        except (TypeError, ValueError, OverflowError):
            return default

    def _load_events(
        self,
        max_events: int,
        edge_id: Optional[str],
    ) -> List[dict]:
        # Module 4 exposes get_events() without arguments.
        events = metrics_service.get_events()

        if not isinstance(events, list):
            return []

        if edge_id:
            events = [
                event for event in events
                if event.get("edge_id") == edge_id
            ]

        return events[-max_events:]

    def _classify_event_windows(
        self,
        events: List[dict],
        request: TrustedDemandRequest,
    ) -> Tuple[List[str], int]:
        edge_indices = defaultdict(list)
        for index, event in enumerate(events):
            edge_indices[str(event.get("edge_id", "unknown-edge"))].append(index)

        labels = ["SUSPICIOUS"] * len(events)
        windows_analyzed = 0

        for edge_id, indices in edge_indices.items():
            for start in range(0, len(indices), request.window_size):
                window_indices = indices[start:start + request.window_size]
                window = [events[index] for index in window_indices]
                result = traffic_discrimination_service._classify(
                    edge_id,
                    window,
                )
                classification = result.classification
                if classification not in self.classification_weights:
                    classification = "SUSPICIOUS"
                for index in window_indices:
                    labels[index] = classification
                windows_analyzed += 1

        return labels, windows_analyzed

    def estimate(
        self,
        request: TrustedDemandRequest,
    ) -> TrustedDemandResponse:
        if request.edge_id and request.edge_id not in simulator.edges:
            raise ValueError(f"Unknown edge '{request.edge_id}'.")

        events = self._load_events(
            max_events=request.max_events,
            edge_id=request.edge_id,
        )

        if not events:
            return TrustedDemandResponse(
                events_analyzed=0,
                windows_analyzed=0,
                results_count=0,
                edge_summaries=[],
                content_demand=[],
                classification_weights=self.classification_weights,
                message=(
                    "No request events are available. Generate traffic "
                    "using the existing CDN or attack simulation endpoints."
                ),
            )

        event_labels, windows_analyzed = (
            self._classify_event_windows(events, request)
        )

        # Aggregate demand per edge and content.
        aggregates = defaultdict(lambda: {
            "total_requests": 0,
            "trusted_requests": 0.0,
            "suspicious_requests": 0.0,
            "attack_requests": 0.0,
            "cache_hits": 0,
            "cache_misses": 0,
            "latency_sum": 0.0,
            "response_size_bytes": 0,
            "classification_counts": Counter(),
            "scenarios": Counter(),
        })

        edge_aggregates = defaultdict(lambda: {
            "total_requests": 0,
            "trusted_requests": 0.0,
            "suspicious_requests": 0.0,
            "attack_requests": 0.0,
            "contents": set(),
            "trusted_contents": set(),
            "trust_ratios": [],
        })

        for event, classification in zip(events, event_labels):
            edge = str(event.get("edge_id", "unknown-edge"))
            content = str(event.get("content_id", "unknown-content"))
            key = (edge, content)

            scenario = str(event.get("scenario", "")).lower()
            is_attack = bool(event.get("is_attack", False))

            # Explicit attack labels take precedence over window labels.
            if is_attack:
                weight = 0.0
                request_type = "attack"
            else:
                weight = self.classification_weights.get(
                    classification,
                    0.35,
                )

                if classification == "CACHE_POLLUTION":
                    request_type = "attack"
                elif classification in {
                    "DISTRIBUTED_LOW_RATE_POLLUTION",
                    "SUSPICIOUS",
                }:
                    request_type = "suspicious"
                else:
                    request_type = "trusted"

            item = aggregates[key]
            item["total_requests"] += 1
            item["trusted_requests"] += weight
            item["classification_counts"][classification] += 1
            item["scenarios"][scenario or "unspecified"] += 1

            if request_type == "attack":
                item["attack_requests"] += 1.0
            elif request_type == "suspicious":
                item["suspicious_requests"] += 1.0

            if bool(event.get("cache_hit", False)):
                item["cache_hits"] += 1
            else:
                item["cache_misses"] += 1

            item["latency_sum"] += self._safe_float(
                event.get("total_latency_ms")
            )
            item["response_size_bytes"] += self._safe_int(
                event.get("response_size_bytes")
            )

            edge_item = edge_aggregates[edge]
            edge_item["total_requests"] += 1
            edge_item["trusted_requests"] += weight
            edge_item["contents"].add(content)

            if request_type == "attack":
                edge_item["attack_requests"] += 1.0
            elif request_type == "suspicious":
                edge_item["suspicious_requests"] += 1.0

        content_results = []

        for (edge, content), item in aggregates.items():
            total = item["total_requests"]
            trusted = item["trusted_requests"]
            trust_ratio = trusted / total if total else 0.0

            # Score is trusted request-equivalents per observed content.
            # It is a demand score, not a probability.
            demand_score = round(trusted, 4)

            if trusted >= 10 and trust_ratio >= 0.70:
                status = "HIGH_TRUSTED_DEMAND"
            elif trusted >= 3 and trust_ratio >= 0.50:
                status = "MODERATE_TRUSTED_DEMAND"
            elif trusted > 0:
                status = "LOW_TRUSTED_DEMAND"
            else:
                status = "UNTRUSTED_OR_ATTACK_DOMINATED"

            explanation = [
                f"Observed {total} requests for this content at this edge.",
                (
                    f"Trusted demand contribution: {trusted:.2f} "
                    f"weighted requests."
                ),
                (
                    f"Trust ratio: {trust_ratio:.2%} after applying "
                    "classification weights and attack labels."
                ),
            ]

            if item["attack_requests"] > 0:
                explanation.append(
                    f"{int(item['attack_requests'])} requests received "
                    "zero trusted-demand weight as attack traffic."
                )

            if item["suspicious_requests"] > 0:
                explanation.append(
                    f"{int(item['suspicious_requests'])} requests were "
                    "classified as suspicious."
                )

            content_results.append(
                ContentTrustedDemand(
                    edge_id=edge,
                    content_id=content,
                    total_requests=total,
                    trusted_requests=round(trusted, 4),
                    suspicious_requests=round(
                        item["suspicious_requests"], 4
                    ),
                    attack_requests=round(
                        item["attack_requests"], 4
                    ),
                    trusted_demand_score=demand_score,
                    trust_ratio=round(trust_ratio, 4),
                    cache_hits=item["cache_hits"],
                    cache_misses=item["cache_misses"],
                    average_latency_ms=round(
                        item["latency_sum"] / total, 4
                    ),
                    response_size_bytes=item["response_size_bytes"],
                    classification_counts=dict(
                        item["classification_counts"]
                    ),
                    demand_status=status,
                    explanation=explanation,
                )
            )

            edge_aggregates[edge]["trust_ratios"].append(trust_ratio)

            if trusted > 0:
                edge_aggregates[edge]["trusted_contents"].add(content)

        content_results.sort(
            key=lambda result: (
                result.trusted_demand_score,
                result.total_requests,
            ),
            reverse=True,
        )

        edge_summaries = []

        for edge, item in edge_aggregates.items():
            ratios = item["trust_ratios"]

            edge_summaries.append(
                EdgeTrustedDemandSummary(
                    edge_id=edge,
                    total_requests=item["total_requests"],
                    trusted_requests=round(
                        item["trusted_requests"], 4
                    ),
                    suspicious_requests=round(
                        item["suspicious_requests"], 4
                    ),
                    attack_requests=round(
                        item["attack_requests"], 4
                    ),
                    unique_content_count=len(item["contents"]),
                    trusted_content_count=len(
                        item["trusted_contents"]
                    ),
                    average_trust_ratio=round(
                        sum(ratios) / len(ratios) if ratios else 0.0,
                        4,
                    ),
                )
            )

        edge_summaries.sort(key=lambda result: result.edge_id)

        return TrustedDemandResponse(
            events_analyzed=len(events),
            windows_analyzed=windows_analyzed,
            results_count=len(content_results),
            edge_summaries=edge_summaries,
            content_demand=content_results,
            classification_weights=self.classification_weights,
            message=(
                "Trusted-demand estimation completed. Scores represent "
                "weighted observed request demand, not probabilities. "
                "Module 7 attack labels receive zero trusted-demand weight."
            ),
        )


trusted_demand_service = TrustedDemandService()
