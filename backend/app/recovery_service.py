
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.metrics_service import metrics_service
from app.simulator import simulator

from app.recovery_models import (
    ContentRecoveryAction,
    EdgeRecoverySummary,
    RecoveryHistoryResponse,
    RecoveryRequest,
    RecoveryResponse,
)


class AdaptiveRecoveryService:
    """
    Module 11:
    - Finds content associated with attack-labelled request events.
    - Proposes or applies cache evictions.
    - Coordinates trusted, repeatedly requested content across edges.
    - Uses existing Module 4 request-event history.

    Cache modifications are disabled unless apply_recovery=True.
    """

    ATTACK_SCENARIOS = {
        "cache_pollution",
        "distributed_low_rate",
        "distributed_low_rate_pollution",
    }

    def __init__(self):
        self._run_history: List[Dict[str, Any]] = []

    @staticmethod
    def _value(obj: Any, *names: str, default=None):
        """Read a field from either a dict or an object."""
        for name in names:
            if isinstance(obj, dict) and name in obj:
                return obj[name]
            if hasattr(obj, name):
                return getattr(obj, name)
        return default

    @staticmethod
    def _as_int(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return default

    @staticmethod
    def _as_float(value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except (TypeError, ValueError, OverflowError):
            return default

    def _load_events(
        self,
        max_events: int,
        edge_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Load the event list recorded by Module 4.

        This module expects get_events() to return the list of request events,
        as established by the existing metrics service.
        """
        raw_events = metrics_service.get_events()

        if not raw_events:
            return []

        events = []
        for raw in raw_events:
            if isinstance(raw, dict):
                event = raw
            elif hasattr(raw, "model_dump"):
                event = raw.model_dump()
            elif hasattr(raw, "dict"):
                event = raw.dict()
            else:
                continue

            if edge_id and str(event.get("edge_id", "")) != edge_id:
                continue

            if not event.get("content_id"):
                continue

            events.append(event)

        return events[-max_events:]

    def _get_cache(self, edge_id: str):
        caches = getattr(simulator, "caches", None)
        return caches.get(edge_id) if isinstance(caches, dict) else None

    @staticmethod
    def _object_map(cache) -> Dict[str, Any]:
        if cache is None:
            return {}

        getter = getattr(cache, "get_objects", None)
        if not callable(getter):
            return {}

        try:
            objects = getter()
        except (TypeError, ValueError):
            return {}

        if isinstance(objects, dict):
            return {str(key): value for key, value in objects.items()}

        result = {}
        if isinstance(objects, (list, tuple, set)):
            for item in objects:
                if isinstance(item, str):
                    result[item] = item
                    continue

                content_id = AdaptiveRecoveryService._value(
                    item, "content_id", "id", "key"
                )
                if content_id is not None:
                    result[str(content_id)] = item

        return result

    def _cache_contains(self, cache, content_id: str) -> bool:
        objects = self._object_map(cache)
        if content_id in objects:
            return True

        for method_name in ("contains", "has", "has_content", "exists"):
            method = getattr(cache, method_name, None)
            if callable(method):
                try:
                    if method(content_id):
                        return True
                except (KeyError, TypeError, ValueError):
                    pass

        return False

    def _evict(self, cache, content_id: str) -> Tuple[bool, str]:
        """
        Try the eviction methods exposed by the existing cache implementation.
        Returns (completed, detail).
        """
        if cache is None:
            return False, "Cache object could not be resolved for this edge."

        for method_name in ("remove", "evict", "delete", "remove_object"):
            method = getattr(cache, method_name, None)
            if not callable(method):
                continue

            try:
                result = method(content_id)

                # A cache API may return False when the object was absent.
                if result is False:
                    return False, f"{method_name} reported that the content was not removed."

                return True, f"Removed using cache.{method_name}()."
            except (KeyError, TypeError, ValueError) as exc:
                return False, f"cache.{method_name}() failed: {exc}"

        return False, (
            "The existing cache does not expose a supported remove/evict method; "
            "no direct cache structure was modified."
        )

    def _insert(
        self,
        cache,
        content_id: str,
        size_bytes: int,
    ) -> Tuple[bool, str]:
        if cache is None:
            return False, "Cache object could not be resolved for this edge."

        if self._cache_contains(cache, content_id):
            return False, "Content is already present in the destination cache."

        insert = getattr(cache, "insert", None)
        if not callable(insert):
            return False, "The existing cache does not expose insert()."

        try:
            result = insert(
                content_id=content_id,
                size_bytes=max(1, size_bytes),
            )
            if result is False:
                return False, "Cache insert() declined the content."
            if self._cache_contains(cache, content_id):
                return True, "Inserted using cache.insert()."
            return False, "Cache insert() returned without storing the content."
        except TypeError:
            # Support common positional signatures without changing the cache.
            try:
                result = insert(content_id, max(1, size_bytes))
                if result is False:
                    return False, "Cache insert() declined the content."
                if self._cache_contains(cache, content_id):
                    return True, "Inserted using positional cache.insert()."
                return False, "Cache insert() returned without storing the content."
            except Exception as exc:
                return False, f"Cache insertion failed: {exc}"
        except Exception as exc:
            return False, f"Cache insertion failed: {exc}"

    def _content_stats(
        self,
        events: List[Dict[str, Any]],
    ) -> Dict[Tuple[str, str], Dict[str, Any]]:
        stats = {}

        for event in events:
            edge_id = str(event.get("edge_id", "unknown-edge"))
            content_id = str(event.get("content_id", ""))
            if not content_id:
                continue

            key = (edge_id, content_id)
            row = stats.setdefault(
                key,
                {
                    "edge_id": edge_id,
                    "content_id": content_id,
                    "total": 0,
                    "attack": 0,
                    "trusted": 0,
                    "suspicious": 0,
                    "size": 0,
                    "hits": 0,
                    "misses": 0,
                },
            )

            row["total"] += 1
            row["size"] = max(
                row["size"],
                self._as_int(event.get("response_size_bytes"), 0),
            )

            scenario = str(event.get("scenario", "")).lower()
            is_attack = event.get("is_attack")

            if is_attack is True:
                row["attack"] += 1
            elif is_attack is False:
                row["trusted"] += 1
            elif scenario in self.ATTACK_SCENARIOS:
                row["suspicious"] += 1
            else:
                row["trusted"] += 1

            if bool(event.get("cache_hit", False)):
                row["hits"] += 1
            else:
                row["misses"] += 1

        return stats

    def recover(self, request: RecoveryRequest) -> RecoveryResponse:
        if request.edge_id and request.edge_id not in simulator.edges:
            raise ValueError(f"Unknown edge '{request.edge_id}'.")

        events = self._load_events(
            max_events=request.max_events,
            edge_id=request.edge_id,
        )

        if not events:
            return RecoveryResponse(
                success=False,
                mode="APPLY" if request.apply_recovery else "DRY_RUN",
                events_analyzed=0,
                edges_analyzed=0,
                attack_events=0,
                trusted_events=0,
                actions=[],
                edge_summaries=[],
                coordination_enabled=request.coordinate_edges,
                recovery_applied=False,
                message=(
                    "No request events are available. Generate traffic using the "
                    "existing CDN request or attack simulation endpoints, then retry."
                ),
            )

        stats = self._content_stats(events)
        edge_ids = sorted({str(event.get("edge_id", "unknown-edge")) for event in events})
        attack_events = sum(
            row["attack"] for row in stats.values()
        )
        trusted_events = sum(
            row["trusted"] for row in stats.values()
        )

        actions: List[ContentRecoveryAction] = []
        edge_summaries: List[EdgeRecoverySummary] = []

        # First, evaluate each edge's content and identify attack-heavy objects.
        suspicious_keys = set()
        trusted_keys = set()
        completed_evictions = defaultdict(int)
        completed_replications = defaultdict(int)

        for edge_id in edge_ids:
            edge_rows = [
                row for (row_edge, _), row in stats.items()
                if row_edge == edge_id
            ]

            cache = self._get_cache(edge_id)
            suspicious_count = 0
            trusted_count = 0
            evictions_proposed = 0
            replications_proposed = 0

            for row in sorted(edge_rows, key=lambda item: item["total"], reverse=True):
                total = row["total"]
                if total < request.min_content_requests:
                    continue

                content_id = row["content_id"]
                attack_ratio = row["attack"] / total if total else 0.0
                trust_ratio = row["trusted"] / total if total else 0.0
                content_size = max(1, row["size"])

                if attack_ratio >= request.attack_ratio_threshold:
                    suspicious_count += 1
                    suspicious_keys.add((edge_id, content_id))

                    if self._cache_contains(cache, content_id):
                        status = "PROPOSED"
                        reason = (
                            "Attack-labelled requests exceed the configured attack "
                            "ratio threshold for this content."
                        )

                        if evictions_proposed < request.max_evictions_per_edge:
                            evictions_proposed += 1
                            if request.apply_recovery:
                                completed, detail = self._evict(cache, content_id)
                                status = "COMPLETED" if completed else "FAILED"
                                reason = f"{reason} {detail}"
                                if completed:
                                    completed_evictions[edge_id] += 1
                        else:
                            status = "LIMIT_REACHED"
                            reason = "Per-edge eviction limit reached."

                        actions.append(
                            ContentRecoveryAction(
                                edge_id=edge_id,
                                content_id=content_id,
                                action="EVICT_ATTACK_ASSOCIATED_CONTENT",
                                status=status,
                                total_requests=total,
                                trusted_requests=row["trusted"],
                                attack_requests=row["attack"],
                                attack_ratio=round(attack_ratio, 4),
                                trust_ratio=round(trust_ratio, 4),
                                content_size_bytes=content_size,
                                reason=reason,
                            )
                        )

                elif trust_ratio >= request.min_trust_ratio:
                    trusted_count += 1
                    trusted_keys.add((edge_id, content_id))

            edge_summaries.append(
                EdgeRecoverySummary(
                    edge_id=edge_id,
                    events_analyzed=sum(row["total"] for row in edge_rows),
                    unique_contents_seen=len(edge_rows),
                    suspicious_contents=suspicious_count,
                    trusted_contents=trusted_count,
                    evictions_proposed=evictions_proposed,
                    evictions_completed=completed_evictions[edge_id],
                    replications_proposed=0,
                    replications_completed=0,
                    recovery_status=(
                        "RECOVERY_APPLIED"
                        if request.apply_recovery
                        else "DRY_RUN"
                    ),
                    message=(
                        "Attack-associated content was evaluated against recorded "
                        "request labels."
                    ),
                )
            )

        # Coordinate trusted content between edge caches.
        # A destination is eligible only if the recorded history contains
        # enough trusted demand for that exact content at that destination.
        if request.coordinate_edges and request.max_replications_per_edge > 0:
            for target_edge in edge_ids:
                target_cache = self._get_cache(target_edge)
                target_rows = [
                    row for (row_edge, _), row in stats.items()
                    if row_edge == target_edge
                ]

                summary = next(
                    (item for item in edge_summaries if item.edge_id == target_edge),
                    None,
                )
                if summary is None:
                    continue

                candidates = sorted(
                    [
                        row for row in target_rows
                        if row["total"] >= request.min_content_requests
                        and row["trusted"] / max(1, row["total"]) >= request.min_trust_ratio
                        and (target_edge, row["content_id"]) in trusted_keys
                        and (target_edge, row["content_id"]) not in suspicious_keys
                    ],
                    key=lambda row: (
                        row["trusted"],
                        row["hits"],
                        row["total"],
                    ),
                    reverse=True,
                )

                for row in candidates:
                    content_id = row["content_id"]
                    if self._cache_contains(target_cache, content_id):
                        continue

                    if summary.replications_proposed >= request.max_replications_per_edge:
                        break

                    # Only replicate an object if it is present at a source edge.
                    source_edge = None
                    for other_edge in edge_ids:
                        if other_edge == target_edge:
                            continue
                        source_cache = self._get_cache(other_edge)
                        if self._cache_contains(source_cache, content_id):
                            source_edge = other_edge
                            break

                    if source_edge is None:
                        continue

                    summary.replications_proposed += 1
                    status = "PROPOSED"
                    reason = (
                        f"Trusted demand was observed at {target_edge}; the content "
                        f"is already cached at source edge {source_edge}."
                    )

                    if request.apply_recovery:
                        completed, detail = self._insert(
                            target_cache,
                            content_id,
                            row["size"],
                        )
                        status = "COMPLETED" if completed else "FAILED"
                        reason = f"{reason} {detail}"
                        if completed:
                            completed_replications[target_edge] += 1

                    actions.append(
                        ContentRecoveryAction(
                            edge_id=target_edge,
                            content_id=content_id,
                            action="COORDINATE_TRUSTED_CONTENT",
                            status=status,
                            total_requests=row["total"],
                            trusted_requests=row["trusted"],
                            attack_requests=row["attack"],
                            attack_ratio=round(
                                row["attack"] / max(1, row["total"]), 4
                            ),
                            trust_ratio=round(
                                row["trusted"] / max(1, row["total"]), 4
                            ),
                            content_size_bytes=max(1, row["size"]),
                            reason=reason,
                        )
                    )

                summary.replications_completed = completed_replications[target_edge]

        for summary in edge_summaries:
            summary.evictions_completed = completed_evictions[summary.edge_id]
            summary.replications_completed = completed_replications[summary.edge_id]
            summary.recovery_status = (
                "RECOVERY_APPLIED" if request.apply_recovery else "DRY_RUN"
            )

        response = RecoveryResponse(
            success=True,
            mode="APPLY" if request.apply_recovery else "DRY_RUN",
            events_analyzed=len(events),
            edges_analyzed=len(edge_ids),
            attack_events=attack_events,
            trusted_events=trusted_events,
            actions=actions,
            edge_summaries=edge_summaries,
            coordination_enabled=request.coordinate_edges,
            recovery_applied=request.apply_recovery,
            message=(
                "Recovery analysis completed. Cache changes were applied."
                if request.apply_recovery
                else "Recovery analysis completed in dry-run mode. No cache changes were requested."
            ),
        )

        self._run_history.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "mode": response.mode,
                "events_analyzed": response.events_analyzed,
                "edges_analyzed": response.edges_analyzed,
                "attack_events": response.attack_events,
                "trusted_events": response.trusted_events,
                "actions_proposed": len(response.actions),
                "recovery_applied": response.recovery_applied,
            }
        )

        # Keep the in-memory audit list bounded.
        self._run_history = self._run_history[-100:]

        return response

    def get_history(self) -> RecoveryHistoryResponse:
        return RecoveryHistoryResponse(
            total_runs=len(self._run_history),
            runs=list(reversed(self._run_history)),
        )


adaptive_recovery_service = AdaptiveRecoveryService()
