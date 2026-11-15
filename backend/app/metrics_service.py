import csv
import io
import json
import math
import statistics
import time
from collections import defaultdict
from datetime import datetime, timezone
from threading import Lock
from typing import Optional


class MetricsService:
    MAX_EVENTS = 500_000

    def __init__(self):
        self._lock = Lock()
        self._events = []
        self._started_at = time.perf_counter()
        self._started_utc = datetime.now(timezone.utc).isoformat()

    def reset(self):
        with self._lock:
            self._events.clear()
            self._started_at = time.perf_counter()
            self._started_utc = datetime.now(timezone.utc).isoformat()

    def record_request(
        self,
        result: dict,
        source: str = "manual",
        scenario: Optional[str] = None,
        is_attack: Optional[bool] = None,
    ):
        """
        Record one completed simulated request.

        The simulator provides latency and byte counters. Throughput
        is calculated from the wall-clock measurement of the experiment.
        """
        recorded_at = datetime.now(timezone.utc).isoformat()
        event = {
            "recorded_at": recorded_at,
            "timestamp": recorded_at,
            "source_timestamp": result.get(
                "source_timestamp",
                result.get("timestamp"),
            ),
            "edge_id": result.get("edge_id", "unknown"),
            "content_id": str(result.get("content_id", "")),
            "client_id": result.get("client_id"),
            "cache_hit": bool(result.get("cache_hit", False)),
            "served_by": result.get("served_by", "unknown"),
            "response_size_bytes": int(
                result.get("response_size_bytes", 0)
            ),
            "origin_bytes_transferred": int(
                result.get("origin_bytes_transferred", 0)
            ),
            "origin_latency_ms": float(
                result.get("origin_latency_ms", 0.0)
            ),
            "total_latency_ms": float(
                result.get("total_latency_ms", 0.0)
            ),
            "cache_strategy": result.get("cache_strategy", "unknown"),
            "source": source,
            "scenario": scenario or result.get("scenario"),
            "is_attack": (
                is_attack if is_attack is not None
                else result.get("is_attack")
            ),
        }

        with self._lock:
            self._events.append(event)
            if len(self._events) > self.MAX_EVENTS:
                del self._events[:len(self._events) - self.MAX_EVENTS]

    @staticmethod
    def _percentile(values: list[float], percentile: float) -> float:
        """
        Calculate a linearly interpolated percentile.
        For p95, percentile is 95.
        """
        if not values:
            return 0.0

        ordered = sorted(values)

        if len(ordered) == 1:
            return float(ordered[0])

        position = (len(ordered) - 1) * percentile / 100.0
        lower = math.floor(position)
        upper = math.ceil(position)

        if lower == upper:
            return float(ordered[lower])

        fraction = position - lower

        return float(
            ordered[lower] * (1 - fraction)
            + ordered[upper] * fraction
        )

    @staticmethod
    def _summarize(events: list[dict]) -> dict:
        count = len(events)

        if count == 0:
            return {
                "requests": 0,
                "cache_hits": 0,
                "cache_misses": 0,
                "cache_hit_ratio": 0.0,
                "cache_miss_ratio": 0.0,
                "average_latency_ms": 0.0,
                "min_latency_ms": 0.0,
                "max_latency_ms": 0.0,
                "p95_latency_ms": 0.0,
                "origin_requests": 0,
                "origin_bytes_transferred": 0,
                "origin_bandwidth_mb": 0.0,
                "average_response_size_bytes": 0.0,
            }

        latencies = [
            max(0.0, float(event["total_latency_ms"]))
            for event in events
        ]

        hits = sum(event["cache_hit"] for event in events)
        misses = count - hits

        origin_requests = sum(
            not event["cache_hit"] for event in events
        )

        origin_bytes = sum(
            max(0, event["origin_bytes_transferred"])
            for event in events
        )

        response_bytes = sum(
            max(0, event["response_size_bytes"])
            for event in events
        )

        return {
            "requests": count,
            "cache_hits": hits,
            "cache_misses": misses,
            "cache_hit_ratio": round(hits / count, 6),
            "cache_miss_ratio": round(misses / count, 6),
            "average_latency_ms": round(
                statistics.fmean(latencies), 6
            ),
            "min_latency_ms": round(min(latencies), 6),
            "max_latency_ms": round(max(latencies), 6),
            "p95_latency_ms": round(
                MetricsService._percentile(latencies, 95), 6
            ),
            "origin_requests": origin_requests,
            "origin_bytes_transferred": origin_bytes,
            "origin_bandwidth_mb": round(
                origin_bytes / (1024 * 1024), 6
            ),
            "average_response_size_bytes": round(
                response_bytes / count, 2
            ),
        }

    def get_report(self, elapsed_seconds: Optional[float] = None) -> dict:
        with self._lock:
            events = [dict(event) for event in self._events]
            started_at = self._started_at
            started_utc = self._started_utc

        elapsed = (
            max(0.0, elapsed_seconds)
            if elapsed_seconds is not None
            else max(0.0, time.perf_counter() - started_at)
        )

        summary = self._summarize(events)

        summary["elapsed_seconds"] = round(elapsed, 6)
        summary["requests_per_second"] = round(
            summary["requests"] / elapsed if elapsed > 0 else 0.0,
            6,
        )

        # This is simulated response payload traffic, not measured
        # network-interface throughput.
        summary["origin_mbps_estimate"] = round(
            (
                summary["origin_bytes_transferred"] * 8
                / elapsed / 1_000_000
            ) if elapsed > 0 else 0.0,
            6,
        )

        edge_groups = defaultdict(list)
        strategy_groups = defaultdict(list)
        scenario_groups = defaultdict(list)

        for event in events:
            edge_groups[event["edge_id"]].append(event)
            strategy_groups[event["cache_strategy"]].append(event)

            if event["scenario"]:
                scenario_groups[event["scenario"]].append(event)

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "experiment_started_at": started_utc,
            "summary": summary,
            "by_edge": {
                edge_id: self._summarize(group)
                for edge_id, group in edge_groups.items()
            },
            "by_strategy": {
                strategy: self._summarize(group)
                for strategy, group in strategy_groups.items()
            },
            "by_scenario": {
                scenario: self._summarize(group)
                for scenario, group in scenario_groups.items()
            },
        }

    def get_events(self) -> list[dict]:
        with self._lock:
            return [dict(event) for event in self._events]

    def export_csv(self) -> str:
        events = self.get_events()

        fieldnames = [
            "recorded_at",
            "timestamp",
            "source_timestamp",
            "edge_id",
            "content_id",
            "client_id",
            "cache_hit",
            "served_by",
            "response_size_bytes",
            "origin_bytes_transferred",
            "origin_latency_ms",
            "total_latency_ms",
            "cache_strategy",
            "source",
            "scenario",
            "is_attack",
        ]

        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)

        return buffer.getvalue()

    def export_json(self) -> str:
        return json.dumps(
            self.get_report(),
            indent=2,
        )


metrics_service = MetricsService()