import math
from statistics import mean, pstdev
from time import perf_counter
from typing import Any

from app.attack_models import AttackSimulationRequest
from app.attack_simulation_service import attack_simulation_service
from app.dataset_service import iter_dataset
from app.experiment_store import ExperimentStore, experiment_store
from app.metrics_service import metrics_service
from app.simulator import simulator


CACHE_STRATEGIES = ("LRU", "LFU", "FIFO", "PREDICTIVE")


def _record_value(record: Any, name: str, default=None):
    if isinstance(record, dict):
        return record.get(name, default)
    return getattr(record, name, default)


def _resolve_cache_capacity(edge_id: str, capacity_mb: float | None) -> int:
    if capacity_mb is None:
        return simulator.caches[edge_id].capacity_bytes

    try:
        capacity_mb = float(capacity_mb)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(
            "cache_capacity_mb must be a finite non-negative value."
        ) from exc

    if not math.isfinite(capacity_mb) or capacity_mb < 0:
        raise ValueError(
            "cache_capacity_mb must be a finite non-negative value."
        )

    return int(capacity_mb * 1024 * 1024)


def _summarize_attack_results(
    results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    summaries = []
    for scenario in dict.fromkeys(row["scenario"] for row in results):
        for strategy in CACHE_STRATEGIES:
            rows = [
                row for row in results
                if row["scenario"] == scenario and row["strategy"] == strategy
            ]
            if not rows:
                continue

            def summarize(field: str) -> tuple[float, float]:
                values = [float(row[field]) for row in rows]
                return round(mean(values), 6), round(pstdev(values), 6)

            hit_mean, hit_stddev = summarize("cache_hit_ratio")
            origin_mean, origin_stddev = summarize(
                "origin_bytes_transferred"
            )
            p95_mean, p95_stddev = summarize("p95_latency_ms")
            eviction_mean, eviction_stddev = summarize("evictions")
            summaries.append({
                "scenario": scenario,
                "strategy": strategy,
                "seed_count": len(rows),
                "mean_cache_hit_ratio": hit_mean,
                "stddev_cache_hit_ratio": hit_stddev,
                "mean_origin_bytes_transferred": origin_mean,
                "stddev_origin_bytes_transferred": origin_stddev,
                "mean_p95_latency_ms": p95_mean,
                "stddev_p95_latency_ms": p95_stddev,
                "mean_evictions": eviction_mean,
                "stddev_evictions": eviction_stddev,
            })
    return summaries


def run_cache_benchmark(
    dataset: str,
    edge_id: str,
    limit: int,
    *,
    store: ExperimentStore | None = experiment_store,
    dataset_iterator=iter_dataset,
    cache_capacity_mb: float | None = None,
) -> dict[str, Any]:
    if limit < 1:
        raise ValueError("limit must be at least 1.")
    if limit > metrics_service.MAX_EVENTS:
        raise ValueError(
            f"limit cannot exceed {metrics_service.MAX_EVENTS} events."
        )
    if edge_id not in simulator.edges:
        raise ValueError(f"Unknown edge_id: {edge_id}")

    original_cache = simulator.caches[edge_id]
    original_capacity = original_cache.capacity_bytes
    original_strategy = original_cache.strategy
    cache_capacity_bytes = _resolve_cache_capacity(edge_id, cache_capacity_mb)
    results = []

    try:
        if cache_capacity_mb is not None:
            simulator.set_cache_capacity(edge_id, cache_capacity_bytes)

        for strategy in CACHE_STRATEGIES:
            simulator.reset()
            simulator.set_cache_strategy(edge_id, strategy)
            metrics_service.reset()
            started = perf_counter()
            processed = 0
            skipped = 0

            for record in dataset_iterator(dataset, limit=limit):
                method = _record_value(record, "method")
                status_code = _record_value(record, "status_code")
                if method and str(method).upper() not in {"GET", "HEAD"}:
                    skipped += 1
                    continue
                if (
                    status_code is not None
                    and not 200 <= int(status_code) < 300
                ):
                    skipped += 1
                    continue

                result = simulator.simulate_request(
                    edge_id=edge_id,
                    content_id=_record_value(record, "content_id"),
                    response_size_bytes=int(
                        _record_value(record, "response_size_bytes", 0)
                    ),
                )
                result.update({
                    "scenario": _record_value(record, "scenario"),
                    "is_attack": _record_value(record, "is_attack"),
                    "client_id": _record_value(record, "client_id"),
                })
                metrics_service.record_request(
                    result,
                    source=f"benchmark:{dataset}",
                    scenario=result["scenario"],
                    is_attack=result["is_attack"],
                )
                processed += 1

            elapsed = max(perf_counter() - started, 1e-9)
            if processed == 0:
                raise ValueError(
                    f"Dataset '{dataset}' produced no replayable requests."
                )

            network_stats = simulator.get_stats()
            metrics_report = metrics_service.get_report(elapsed_seconds=elapsed)
            cache_stats = simulator.get_cache_stats(edge_id)
            row = {
                "strategy": strategy,
                "processed_requests": processed,
                "skipped_records": skipped,
                "cache_capacity_bytes": cache_stats["capacity_bytes"],
                "cache_hit_ratio": network_stats["cache_hit_ratio"],
                "origin_bytes_transferred": network_stats[
                    "origin_bytes_transferred"
                ],
                "average_latency_ms": network_stats["average_latency_ms"],
                "p95_latency_ms": metrics_report["summary"]["p95_latency_ms"],
                "evictions": cache_stats["evictions"],
                "elapsed_seconds": round(elapsed, 6),
                "requests_per_second": round(processed / elapsed, 3),
            }
            results.append(row)

            if store is not None:
                store.record_run(
                    operation="cache_benchmark",
                    configuration={
                        "dataset": dataset,
                        "edge_id": edge_id,
                        "limit": limit,
                        "strategy": strategy,
                        "cache_capacity_bytes": cache_capacity_bytes,
                    },
                    result=row,
                )
    finally:
        if cache_capacity_mb is not None:
            simulator.reset()
            simulator.set_cache_capacity(edge_id, original_capacity)
            simulator.set_cache_strategy(edge_id, original_strategy)
            metrics_service.reset()

    return {
        "dataset": dataset,
        "edge_id": edge_id,
        "requested_limit": limit,
        "cache_capacity_bytes": cache_capacity_bytes,
        "strategies": list(CACHE_STRATEGIES),
        "results": results,
        "message": (
            "Each strategy was run against the same ordered dataset from "
            "an empty cache. Throughput is machine-dependent. "
            "A benchmark-specific capacity override does not change the "
            "configured edge capacity."
        ),
    }


def run_attack_benchmark(
    scenarios: list[str],
    seeds: list[int],
    edge_id: str,
    request_count: int,
    *,
    store: ExperimentStore | None = experiment_store,
    cache_capacity_mb: float | None = None,
) -> dict[str, Any]:
    if edge_id not in simulator.edges:
        raise ValueError(f"Unknown edge_id: {edge_id}")
    if request_count < 10 or request_count > 5000:
        raise ValueError("request_count must be between 10 and 5000.")
    if not scenarios or not seeds:
        raise ValueError("At least one scenario and seed are required.")
    if len(set(scenarios)) != len(scenarios):
        raise ValueError("scenarios must not contain duplicates.")
    if len(set(seeds)) != len(seeds):
        raise ValueError("seeds must not contain duplicates.")

    original_cache = simulator.caches[edge_id]
    original_capacity = original_cache.capacity_bytes
    original_strategy = original_cache.strategy
    cache_capacity_bytes = _resolve_cache_capacity(edge_id, cache_capacity_mb)
    results = []

    try:
        if cache_capacity_mb is not None:
            simulator.set_cache_capacity(edge_id, cache_capacity_bytes)

        for scenario in scenarios:
            for seed in seeds:
                for strategy in CACHE_STRATEGIES:
                    simulator.reset()
                    simulator.set_cache_strategy(edge_id, strategy)
                    metrics_service.reset()
                    started = perf_counter()
                    response = attack_simulation_service.simulate(
                        AttackSimulationRequest(
                            scenario=scenario,
                            edge_id=edge_id,
                            request_count=request_count,
                            seed=seed,
                        )
                    )
                    elapsed = max(perf_counter() - started, 1e-9)
                    cache_stats = simulator.get_cache_stats(edge_id)
                    metrics_report = metrics_service.get_report(
                        elapsed_seconds=elapsed
                    )
                    row = {
                        "scenario": scenario,
                        "seed": seed,
                        "strategy": strategy,
                        "processed_requests": response.processed_requests,
                        "attack_requests": response.attack_requests,
                        "cache_capacity_bytes": cache_stats["capacity_bytes"],
                        "cache_hit_ratio": response.hit_ratio,
                        "origin_bytes_transferred": (
                            response.origin_bytes_transferred
                        ),
                        "average_latency_ms": response.average_latency_ms,
                        "p95_latency_ms": (
                            metrics_report["summary"]["p95_latency_ms"]
                        ),
                        "evictions": cache_stats["evictions"],
                        "elapsed_seconds": round(elapsed, 6),
                        "requests_per_second": round(
                            response.processed_requests / elapsed,
                            3,
                        ),
                    }
                    results.append(row)

                    if store is not None:
                        store.record_run(
                            operation="attack_cache_benchmark",
                            configuration={
                                "scenario": scenario,
                                "seed": seed,
                                "edge_id": edge_id,
                                "request_count": request_count,
                                "strategy": strategy,
                                "cache_capacity_bytes": cache_capacity_bytes,
                            },
                            result=row,
                        )
    finally:
        if cache_capacity_mb is not None:
            simulator.reset()
            simulator.set_cache_capacity(edge_id, original_capacity)
            simulator.set_cache_strategy(edge_id, original_strategy)
            metrics_service.reset()

    return {
        "edge_id": edge_id,
        "cache_capacity_bytes": cache_capacity_bytes,
        "scenarios": scenarios,
        "seeds": seeds,
        "strategies": list(CACHE_STRATEGIES),
        "results": results,
        "summary": _summarize_attack_results(results),
        "message": (
            "Each scenario/seed/strategy combination started with an "
            "empty edge cache. Summary rows report mean and population "
            "standard deviation across seeds. Throughput is machine-dependent."
        ),
    }
