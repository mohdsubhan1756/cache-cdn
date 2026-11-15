import argparse
import csv
from pathlib import Path

from app.benchmark_service import (
    run_attack_benchmark,
    run_cache_benchmark,
)
from app.dataset_service import DATASET_FILES


ATTACK_SCENARIOS = (
    "cache_pollution",
    "distributed_low_rate",
    "flash_crowd",
)


def main():
    parser = argparse.ArgumentParser(
        description="Compare CDN cache strategies against bundled datasets."
    )
    parser.add_argument(
        "--datasets",
        nargs="+",
        choices=sorted(DATASET_FILES),
        default=["synthetic"],
    )
    parser.add_argument("--edge-id", default="edge-hyd")
    parser.add_argument("--limit", type=int, default=10000)
    parser.add_argument(
        "--cache-capacity-mb",
        type=float,
        default=None,
        help=(
            "Override the selected edge's cache capacity for these "
            "benchmark runs only (MiB)."
        ),
    )
    parser.add_argument(
        "--scenarios",
        nargs="*",
        choices=ATTACK_SCENARIOS,
        default=[],
        help="Also benchmark generated attack scenarios.",
    )
    parser.add_argument(
        "--seeds",
        nargs="+",
        type=int,
        default=[42, 17],
        help="Seeds used for each generated scenario.",
    )
    parser.add_argument("--request-count", type=int, default=200)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "data"
        / "cache_benchmark.csv",
    )
    args = parser.parse_args()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    rows = []

    try:
        for dataset in args.datasets:
            report = run_cache_benchmark(
                dataset=dataset,
                edge_id=args.edge_id,
                limit=args.limit,
                cache_capacity_mb=args.cache_capacity_mb,
            )
            for row in report["results"]:
                rows.append({
                    "kind": "dataset",
                    "dataset": dataset,
                    "scenario": "",
                    "seed": "",
                    "edge_id": args.edge_id,
                    **row,
                })
                print(
                    f"{dataset} {args.edge_id} {row['strategy']}: "
                    f"hit={row['cache_hit_ratio']:.4f}, "
                    f"origin={row['origin_bytes_transferred']} bytes, "
                    f"p95={row['p95_latency_ms']:.4f} ms"
                )

        if args.scenarios:
            report = run_attack_benchmark(
                scenarios=args.scenarios,
                seeds=args.seeds,
                edge_id=args.edge_id,
                request_count=args.request_count,
                cache_capacity_mb=args.cache_capacity_mb,
            )
            for row in report["results"]:
                rows.append({
                    "kind": "generated_scenario",
                    "dataset": "",
                    "edge_id": args.edge_id,
                    **row,
                })
                print(
                    f"{row['scenario']} seed={row['seed']} "
                    f"{row['strategy']}: "
                    f"hit={row['cache_hit_ratio']:.4f}, "
                    f"origin={row['origin_bytes_transferred']} bytes, "
                    f"p95={row['p95_latency_ms']:.4f} ms"
                )
            for summary in report["summary"]:
                rows.append({
                    "kind": "generated_scenario_summary",
                    "dataset": "",
                    "scenario": summary["scenario"],
                    "seed": "",
                    "edge_id": args.edge_id,
                    "strategy": summary["strategy"],
                    "seed_count": summary["seed_count"],
                    "processed_requests": args.request_count,
                    "cache_capacity_bytes": report["cache_capacity_bytes"],
                    "cache_hit_ratio": summary["mean_cache_hit_ratio"],
                    "cache_hit_ratio_stddev": (
                        summary["stddev_cache_hit_ratio"]
                    ),
                    "origin_bytes_transferred": (
                        summary["mean_origin_bytes_transferred"]
                    ),
                    "origin_bytes_stddev": (
                        summary["stddev_origin_bytes_transferred"]
                    ),
                    "p95_latency_ms": summary["mean_p95_latency_ms"],
                    "p95_latency_ms_stddev": (
                        summary["stddev_p95_latency_ms"]
                    ),
                    "evictions": summary["mean_evictions"],
                    "evictions_stddev": summary["stddev_evictions"],
                })
                print(
                    f"{summary['scenario']} summary "
                    f"{summary['strategy']} ({summary['seed_count']} seeds): "
                    f"mean_hit={summary['mean_cache_hit_ratio']:.4f} "
                    f"+/- {summary['stddev_cache_hit_ratio']:.4f}, "
                    f"mean_origin={summary['mean_origin_bytes_transferred']:.0f} "
                    f"+/- {summary['stddev_origin_bytes_transferred']:.0f} "
                    "bytes"
                )
    except ValueError as exc:
        parser.error(str(exc))

    fieldnames = [
        "kind",
        "dataset",
        "scenario",
        "seed",
        "edge_id",
        "strategy",
        "seed_count",
        "processed_requests",
        "skipped_records",
        "attack_requests",
        "cache_capacity_bytes",
        "cache_hit_ratio",
        "cache_hit_ratio_stddev",
        "origin_bytes_transferred",
        "origin_bytes_stddev",
        "average_latency_ms",
        "p95_latency_ms",
        "p95_latency_ms_stddev",
        "evictions",
        "evictions_stddev",
        "elapsed_seconds",
        "requests_per_second",
    ]
    with args.output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved {len(rows)} benchmark results to {args.output}")


if __name__ == "__main__":
    main()
