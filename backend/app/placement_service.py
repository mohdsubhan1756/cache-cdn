
import math
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from app.simulator import simulator
from app.demand_prediction_service import demand_prediction_service
from app.trusted_demand_models import TrustedDemandRequest
from app.trusted_demand_service import trusted_demand_service

from app.placement_models import (
    PlacementRequest,
    PlacementResponse,
    PlacementCandidate,
    EdgePlacementSummary,
)


class AttackResistantPlacementService:
    """
    Ranks content for CDN cache placement using:
    - Module 5: predicted content demand
    - Module 9: trusted-demand estimates
    - Existing per-edge cache capacities and insert operations
    """

    ALGORITHM_NAME = "TRUSTED_DEMAND_UNCERTAINTY_AWARE_PLACEMENT"

    def __init__(self):
        pass

    @staticmethod
    def _value(obj: Any, name: str, default=None):
        if isinstance(obj, dict):
            return obj.get(name, default)
        return getattr(obj, name, default)

    @staticmethod
    def _nonnegative_float(value: Any, default: float = 0.0) -> float:
        try:
            number = float(value)
            if math.isfinite(number) and number >= 0:
                return number
        except (TypeError, ValueError):
            pass
        return default

    @staticmethod
    def _nonnegative_int(value: Any, default: int = 0) -> int:
        try:
            number = int(value)
            if number >= 0:
                return number
        except (TypeError, ValueError):
            pass
        return default

    @staticmethod
    def _cache_objects(cache) -> List[Any]:
        objects = cache.get_objects()
        if isinstance(objects, dict):
            return list(objects.values())
        if isinstance(objects, list):
            return objects
        return []

    @classmethod
    def _is_cached(cls, cache, content_id: str) -> bool:
        for entry in cls._cache_objects(cache):
            entry_id = cls._value(entry, "content_id")
            if entry_id is None and isinstance(entry, str):
                entry_id = entry
            if str(entry_id) == content_id:
                return True
        return False

    @staticmethod
    def _cache_capacity(cache) -> int:
        capacity = getattr(cache, "capacity_bytes", 0)
        try:
            return max(0, int(capacity))
        except (TypeError, ValueError):
            return 0

    @classmethod
    def _cache_used(cls, cache) -> int:
        try:
            return max(0, int(getattr(cache, "used_bytes", 0)))
        except (TypeError, ValueError):
            return 0

    def _trusted_demand_map(
        self,
        request: PlacementRequest,
    ) -> Dict[Tuple[str, str], Any]:
        trusted_response = trusted_demand_service.estimate(
            TrustedDemandRequest(
                edge_id=request.edge_id,
                window_size=request.window_size,
                max_events=request.max_events,
            )
        )

        demand_map = {}

        for item in trusted_response.content_demand:
            edge_id = str(item.edge_id)
            content_id = str(item.content_id)
            demand_map[(edge_id, content_id)] = item

        return demand_map

    def _get_prediction_response(
        self,
        request: PlacementRequest,
        edge_id: Optional[str],
    ):
        return demand_prediction_service.predict(
            edge_id=edge_id,
            limit=request.prediction_limit,
        )

    def _build_candidate(
        self,
        prediction: Any,
        trusted_item: Any,
        edge_id: str,
        uncertainty_penalty: float,
        cache,
    ) -> PlacementCandidate:
        content_id = str(
            self._value(prediction, "content_id", "unknown-content")
        )

        size = self._nonnegative_int(
            self._value(prediction, "content_size_bytes", 0)
        )

        if size == 0 and trusted_item is not None:
            size = self._nonnegative_int(
                self._value(trusted_item, "response_size_bytes", 0)
            )

        historical_requests = self._nonnegative_int(
            self._value(prediction, "historical_requests", 0)
        )

        predicted_requests = self._nonnegative_float(
            self._value(
                prediction,
                "predicted_requests_next_window",
                0.0,
            )
        )

        trusted_score = self._nonnegative_float(
            self._value(trusted_item, "trusted_demand_score", 0.0)
        )

        trust_ratio = self._nonnegative_float(
            self._value(trusted_item, "trust_ratio", 0.5),
            default=0.5,
        )
        trust_ratio = min(1.0, trust_ratio)

        # If no observed trusted-demand record exists, use a neutral
        # trust ratio and penalize uncertainty instead of assuming
        # the content is definitely legitimate or definitely malicious.
        has_trusted_history = trusted_item is not None

        if not has_trusted_history:
            trust_ratio = 0.5

        predicted_trusted_demand = predicted_requests * trust_ratio

        # A bounded latency-based benefit proxy. If no observed latency
        # exists, the neutral benefit is 1.0.
        average_latency = self._nonnegative_float(
            self._value(trusted_item, "average_latency_ms", 0.0)
            if trusted_item is not None
            else 0.0
        )
        network_benefit = 1.0 + min(average_latency, 100.0) / 100.0

        # Lower historical support means greater uncertainty.
        uncertainty = 1.0 / (1.0 + historical_requests)

        denominator = max(1, size) * (
            1.0 + uncertainty_penalty * uncertainty
        )

        placement_score = (
            predicted_trusted_demand * network_benefit / denominator
        )

        cache_capacity = self._cache_capacity(cache)
        available_capacity = max(
            0,
            cache_capacity - self._cache_used(cache),
        )
        already_cached = self._is_cached(cache, content_id)
        eligible = (
            size > 0
            and size <= available_capacity
            and predicted_trusted_demand > 0
            and placement_score > 0
            and not already_cached
        )

        reasons = [
            (
                f"Predicted demand: {predicted_requests:.4f}; "
                f"trust ratio: {trust_ratio:.4f}."
            ),
            (
                f"Predicted trusted demand: "
                f"{predicted_trusted_demand:.4f}."
            ),
            (
                f"Network benefit: {network_benefit:.4f}; "
                f"uncertainty: {uncertainty:.4f}."
            ),
            (
                f"Content size: {size} bytes; "
                f"edge capacity: {cache_capacity} bytes."
            ),
        ]

        if not has_trusted_history:
            reasons.append(
                "No trusted-demand record was found; a neutral trust "
                "ratio of 0.5 was used and uncertainty was penalized."
            )

        if trusted_item is not None:
            attack_requests = self._nonnegative_float(
                self._value(trusted_item, "attack_requests", 0.0)
            )
            if attack_requests > 0:
                reasons.append(
                    f"Observed attack requests for this content: "
                    f"{attack_requests:.2f}."
                )

        if size <= 0:
            status = "REJECTED_INVALID_SIZE"
        elif size > cache_capacity:
            status = "REJECTED_EXCEEDS_CAPACITY"
        elif predicted_trusted_demand <= 0:
            status = "REJECTED_NO_TRUSTED_DEMAND"
        elif already_cached:
            status = "ALREADY_CACHED"
        elif size > available_capacity:
            status = "REJECTED_INSUFFICIENT_AVAILABLE_CAPACITY"
        else:
            status = "ELIGIBLE"

        return PlacementCandidate(
            edge_id=edge_id,
            content_id=content_id,
            content_size_bytes=size,
            historical_requests=historical_requests,
            predicted_requests_next_window=round(
                predicted_requests, 6
            ),
            trusted_demand_score=round(trusted_score, 6),
            trust_ratio=round(trust_ratio, 6),
            predicted_trusted_demand=round(
                predicted_trusted_demand, 6
            ),
            network_benefit=round(network_benefit, 6),
            uncertainty=round(uncertainty, 6),
            placement_score=round(placement_score, 12),
            eligible=eligible,
            placement_status=status,
            explanation=reasons,
        )

    def place(
        self,
        request: PlacementRequest,
    ) -> PlacementResponse:
        caches = simulator.caches

        if not isinstance(caches, dict) or not caches:
            return PlacementResponse(
                model_trained=False,
                algorithm=self.ALGORITHM_NAME,
                apply_placement=request.apply_placement,
                uncertainty_penalty=request.uncertainty_penalty,
                candidates_count=0,
                candidates=[],
                edge_summaries=[],
                message="No CDN edge caches are available in the simulator.",
            )

        target_edges = (
            [request.edge_id]
            if request.edge_id
            else list(caches.keys())
        )

        invalid_edges = [
            edge_id for edge_id in target_edges
            if edge_id not in caches
        ]

        if invalid_edges:
            raise ValueError(
                "Unknown edge_id: " + ", ".join(invalid_edges)
            )

        historical_edges = set(
            demand_prediction_service.get_historical_edges()
        )
        if request.edge_id and request.edge_id not in historical_edges:
            raise ValueError(
                f"No demand history exists for edge '{request.edge_id}'. "
                "Train the demand model with events from this edge."
            )
        if not historical_edges:
            demand_prediction_service.predict(
                edge_id=request.edge_id,
                limit=request.prediction_limit,
            )

        trusted_map = self._trusted_demand_map(request)

        candidates_by_edge = defaultdict(list)
        model_trained = bool(
            demand_prediction_service.get_status()["trained"]
        )

        for edge_id in target_edges:
            if edge_id not in historical_edges:
                continue

            prediction_response = self._get_prediction_response(
                request,
                edge_id,
            )

            predictions = self._value(
                prediction_response,
                "predictions",
                [],
            ) or []

            cache = caches[edge_id]

            for prediction in predictions:
                predicted_edge = self._value(
                    prediction,
                    "edge_id",
                    edge_id,
                )
                predicted_edge = str(predicted_edge or edge_id)

                # Do not place an item returned for a different edge.
                if predicted_edge != edge_id:
                    continue

                content_id = str(
                    self._value(
                        prediction,
                        "content_id",
                        "unknown-content",
                    )
                )

                trusted_item = trusted_map.get(
                    (edge_id, content_id)
                )

                candidate = self._build_candidate(
                    prediction=prediction,
                    trusted_item=trusted_item,
                    edge_id=edge_id,
                    uncertainty_penalty=request.uncertainty_penalty,
                    cache=cache,
                )

                candidates_by_edge[edge_id].append(candidate)

        all_candidates = []
        edge_summaries = []

        for edge_id in target_edges:
            cache = caches[edge_id]
            capacity = self._cache_capacity(cache)

            edge_candidates = candidates_by_edge[edge_id]
            edge_candidates.sort(
                key=lambda item: (
                    item.placement_score,
                    item.predicted_trusted_demand,
                ),
                reverse=True,
            )

            remaining_bytes = max(
                0,
                capacity - self._cache_used(cache),
            )
            for candidate in edge_candidates:
                if candidate.placement_status != "ELIGIBLE":
                    continue
                if candidate.content_size_bytes > remaining_bytes:
                    candidate.eligible = False
                    candidate.placement_status = (
                        "REJECTED_INSUFFICIENT_AVAILABLE_CAPACITY"
                    )
                    candidate.explanation.append(
                        "Higher-ranked candidates already use the remaining "
                        "available cache capacity."
                    )
                else:
                    remaining_bytes -= candidate.content_size_bytes

            placements_attempted = 0
            placements_inserted = 0
            selected_content_ids = []

            eligible_candidates = [
                candidate for candidate in edge_candidates
                if candidate.eligible
                and candidate.placement_status == "ELIGIBLE"
            ]

            if request.apply_placement:
                for candidate in eligible_candidates:
                    if self._is_cached(cache, candidate.content_id):
                        candidate.placement_status = "ALREADY_CACHED"
                        continue

                    placements_attempted += 1

                    try:
                        cache.insert(
                            content_id=candidate.content_id,
                            size_bytes=candidate.content_size_bytes,
                        )
                        if self._is_cached(cache, candidate.content_id):
                            placements_inserted += 1
                            selected_content_ids.append(
                                candidate.content_id
                            )
                            candidate.placement_status = "PLACED"
                        else:
                            candidate.placement_status = "PLACEMENT_FAILED"
                            candidate.explanation.append(
                                "Cache insert returned without storing the content."
                            )
                    except Exception as exc:
                        candidate.placement_status = "PLACEMENT_FAILED"
                        candidate.explanation.append(
                            f"Cache insertion failed: {str(exc)}"
                        )

            all_candidates.extend(edge_candidates)

            edge_summaries.append(
                EdgePlacementSummary(
                    edge_id=edge_id,
                    cache_capacity_bytes=capacity,
                    cache_capacity_mb=round(
                        capacity / (1024 * 1024), 4
                    ),
                    candidates_evaluated=len(edge_candidates),
                    eligible_candidates=len(eligible_candidates),
                    placements_attempted=placements_attempted,
                    placements_inserted=placements_inserted,
                    selected_content_ids=selected_content_ids,
                    message=(
                        f"No demand history exists for {edge_id}; no "
                        "placement candidates were generated."
                        if edge_id not in historical_edges
                        else
                        "Placement was applied to the existing edge cache."
                        if request.apply_placement
                        else (
                            "Placement was evaluated only; no cache "
                            "contents were changed."
                        )
                    ),
                )
            )

        all_candidates.sort(
            key=lambda item: (
                item.placement_score,
                item.predicted_trusted_demand,
            ),
            reverse=True,
        )

        if not any(
            candidates_by_edge.values()
        ):
            message = (
                "No prediction candidates were returned. The demand "
                "prediction model may not be trained, or no content "
                "predictions are available for the selected edge."
            )
        elif request.apply_placement:
            message = (
                "Attack-resistant placement completed. Eligible content "
                "was ranked by predicted trusted demand, network benefit, "
                "size, and uncertainty, then inserted into the existing "
                "edge caches."
            )
        else:
            message = (
                "Placement ranking completed without changing cache "
                "contents. Set apply_placement to true to apply the ranking."
            )

        return PlacementResponse(
            model_trained=model_trained,
            algorithm=self.ALGORITHM_NAME,
            apply_placement=request.apply_placement,
            uncertainty_penalty=request.uncertainty_penalty,
            candidates_count=len(all_candidates),
            candidates=all_candidates,
            edge_summaries=edge_summaries,
            message=message,
        )


attack_resistant_placement_service = AttackResistantPlacementService()
