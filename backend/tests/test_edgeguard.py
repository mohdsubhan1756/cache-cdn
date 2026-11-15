import unittest
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

import app.main as main_module
from app.anomaly_detection_service import anomaly_detection_service
from app.benchmark_service import (
    run_attack_benchmark,
    run_cache_benchmark,
)
from app.demand_prediction_service import demand_prediction_service
from app.experiment_store import ExperimentStore
from app.main import app
from app.metrics_service import metrics_service
from app.metrics_service import MetricsService
from app.cache_engine import EdgeCache
from app.placement_models import PlacementRequest
from app.placement_service import attack_resistant_placement_service
from app.recovery_service import adaptive_recovery_service
from app.simulator import simulator


class EdgeGuardApiTests(unittest.TestCase):
    def setUp(self):
        simulator.reset()
        metrics_service.reset()
        demand_prediction_service.reset()
        anomaly_detection_service.reset()
        adaptive_recovery_service._run_history.clear()
        self._experiment_tempdir = tempfile.TemporaryDirectory()
        self._original_experiment_store = main_module.experiment_store
        main_module.experiment_store = ExperimentStore(
            Path(self._experiment_tempdir.name) / "api-tests.sqlite3"
        )
        self.client = TestClient(app)

    def tearDown(self):
        main_module.experiment_store = self._original_experiment_store
        self._experiment_tempdir.cleanup()

    def test_health_network_dataset_cache_and_metrics_routes(self):
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(
            self.client.get("/api/v1/network/topology").status_code,
            200,
        )
        self.assertEqual(
            self.client.get("/api/v1/network/stats").json()["requests"],
            0,
        )

        response = self.client.post(
            "/api/v1/network/simulate-request",
            json={
                "edge_id": "edge-hyd",
                "content_id": "first",
                "response_size_bytes": 1024,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["served_by"], "origin")
        self.assertEqual(response.json()["request_id"].count("-"), 4)
        self.assertTrue(
            self.client.post(
                "/api/v1/network/simulate-request",
                json={
                    "edge_id": "edge-hyd",
                    "content_id": "first",
                    "response_size_bytes": 1024,
                },
            ).json()["cache_hit"]
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/network/simulate-request",
                json={
                    "edge_id": "unknown-edge",
                    "content_id": "first",
                    "response_size_bytes": 1024,
                },
            ).status_code,
            400,
        )

        datasets = self.client.get("/api/v1/datasets").json()
        self.assertTrue(next(item for item in datasets if item["name"] == "web_logs")["file_exists"])
        self.assertEqual(
            self.client.get("/api/v1/datasets/web_logs/preview?limit=3").status_code,
            200,
        )
        for dataset in ("web_logs", "wikimedia"):
            replay = self.client.post(
                "/api/v1/datasets/replay",
                json={"dataset": dataset, "edge_id": "edge-del", "limit": 3},
            )
            self.assertEqual(replay.status_code, 200, replay.text)
            self.assertGreater(replay.json()["processed_requests"], 0)
        self.assertEqual(
            self.client.get("/api/v1/datasets/synthetic/preview?limit=3").status_code,
            200,
        )
        self.assertEqual(
            self.client.get("/api/v1/datasets/unknown/preview").status_code,
            400,
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/datasets/replay",
                json={"dataset": "synthetic", "edge_id": "edge-mum", "limit": 12},
            ).status_code,
            200,
        )

        self.assertEqual(
            self.client.get("/api/v1/cache/strategies").status_code,
            200,
        )
        for strategy in ("LRU", "LFU", "FIFO", "PREDICTIVE"):
            result = self.client.put(
                "/api/v1/cache/edge-hyd/strategy",
                json={"strategy": strategy},
            )
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.json()["strategy"], strategy)
        self.assertEqual(
            self.client.get("/api/v1/cache/stats").status_code,
            200,
        )
        self.assertEqual(
            self.client.get("/api/v1/cache/edge-hyd/stats").status_code,
            200,
        )
        objects = self.client.get("/api/v1/cache/edge-hyd/objects").json()
        self.assertGreaterEqual(objects["object_count"], 1)
        self.assertEqual(
            self.client.post("/api/v1/cache/edge-hyd/reset").status_code,
            200,
        )
        self.assertEqual(
            self.client.get("/api/v1/metrics").status_code,
            200,
        )
        self.assertEqual(
            self.client.get("/api/v1/metrics/events?limit=5").status_code,
            200,
        )
        for report in ("edges", "strategies", "scenarios"):
            self.assertEqual(
                self.client.get(f"/api/v1/metrics/{report}").status_code,
                200,
            )
        self.assertIn(
            "application/json",
            self.client.get("/api/v1/metrics/export/json").headers["content-type"],
        )
        self.assertIn(
            "text/csv",
            self.client.get("/api/v1/metrics/export/csv").headers["content-type"],
        )
        self.assertEqual(self.client.post("/api/v1/metrics/reset").status_code, 200)
        self.assertEqual(self.client.post("/api/v1/network/reset").status_code, 200)

    def test_cors_allows_configured_vite_origin(self):
        response = self.client.options(
            "/api/v1/security/attacks/simulate",
            headers={
                "Origin": "http://127.0.0.1:5173",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers["access-control-allow-origin"],
            "http://127.0.0.1:5173",
        )

    def test_metrics_preserve_client_labels_timestamps_and_bounded_history(self):
        service = MetricsService()
        service.MAX_EVENTS = 2
        for index in range(3):
            service.record_request(
                {
                    "edge_id": "edge-hyd",
                    "content_id": str(index),
                    "client_id": f"client-{index}",
                    "timestamp": index,
                    "is_attack": index == 2,
                },
                source="test",
            )
        events = service.get_events()
        self.assertEqual([event["content_id"] for event in events], ["1", "2"])
        self.assertEqual(events[-1]["client_id"], "client-2")
        self.assertTrue(events[-1]["is_attack"])
        self.assertEqual(events[-1]["source_timestamp"], 2)
        self.assertIsInstance(events[-1]["timestamp"], str)

    def test_request_timeline_returns_hit_miss_and_origin_details(self):
        first = self.client.post(
            "/api/v1/network/simulate-request",
            json={
                "edge_id": "edge-hyd",
                "content_id": "timeline-content",
                "response_size_bytes": 2048,
            },
        )
        second = self.client.post(
            "/api/v1/network/simulate-request",
            json={
                "edge_id": "edge-hyd",
                "content_id": "timeline-content",
                "response_size_bytes": 2048,
            },
        )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)

        timeline = self.client.get("/api/v1/metrics/events?limit=2")
        self.assertEqual(timeline.status_code, 200, timeline.text)
        events = timeline.json()["events"]
        self.assertEqual([event["cache_hit"] for event in events], [False, True])
        self.assertEqual(events[0]["served_by"], "origin")
        self.assertEqual(events[1]["served_by"], "edge-hyd")
        history = self.client.get("/api/v1/experiments/history?limit=10")
        self.assertEqual(history.status_code, 200, history.text)
        self.assertEqual(len(history.json()["runs"]), 2)
        self.assertEqual(
            history.json()["runs"][-1]["result"]["content_id"],
            "timeline-content",
        )

    def test_cache_benchmark_resets_each_policy_and_persists_results(self):
        records = [
            {
                "content_id": content_id,
                "response_size_bytes": 300 * 1024 * 1024,
                "method": "GET",
                "status_code": 200,
            }
            for content_id in ("a", "a", "b", "c", "a", "b")
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ExperimentStore(
                Path(temp_dir) / "benchmark.sqlite3"
            )
            result = run_cache_benchmark(
                dataset="synthetic",
                edge_id="edge-hyd",
                limit=len(records),
                store=store,
                dataset_iterator=lambda _dataset, limit: iter(
                    records[:limit]
                ),
            )

            self.assertEqual(
                result["strategies"],
                ["LRU", "LFU", "FIFO", "PREDICTIVE"],
            )
            self.assertTrue(
                all(
                    row["processed_requests"] == len(records)
                    for row in result["results"]
                )
            )
            self.assertTrue(
                all(
                    "p95_latency_ms" in row
                    and "origin_bytes_transferred" in row
                    and "evictions" in row
                    and row["cache_capacity_bytes"]
                    for row in result["results"]
                )
            )
            self.assertEqual(len(store.list_runs()), 4)

    def test_seeded_stress_benchmark_summarizes_variance_and_restores_capacity(
        self,
    ):
        configured_capacity = simulator.caches["edge-hyd"].capacity_bytes
        report = run_attack_benchmark(
            scenarios=["distributed_low_rate"],
            seeds=[42, 17],
            edge_id="edge-hyd",
            request_count=2000,
            cache_capacity_mb=64,
            store=None,
        )

        self.assertEqual(
            simulator.caches["edge-hyd"].capacity_bytes,
            configured_capacity,
        )
        self.assertTrue(
            all(
                row["cache_capacity_bytes"] == 64 * 1024 * 1024
                for row in report["results"]
            )
        )
        self.assertTrue(any(row["evictions"] > 0 for row in report["results"]))

        summary = next(
            row for row in report["summary"] if row["strategy"] == "LRU"
        )
        raw_rows = [
            row for row in report["results"] if row["strategy"] == "LRU"
        ]
        self.assertEqual(summary["seed_count"], 2)
        self.assertAlmostEqual(
            summary["mean_cache_hit_ratio"],
            sum(row["cache_hit_ratio"] for row in raw_rows) / 2,
        )
        self.assertGreater(summary["stddev_origin_bytes_transferred"], 0)
        with self.assertRaisesRegex(ValueError, "seeds must not contain duplicates"):
            run_attack_benchmark(
                scenarios=["distributed_low_rate"],
                seeds=[42, 42],
                edge_id="edge-hyd",
                request_count=10,
                store=None,
            )

    def test_attack_benchmark_is_repeatable_for_the_same_seed(self):
        first = run_attack_benchmark(
            scenarios=["distributed_low_rate"],
            seeds=[17],
            edge_id="edge-hyd",
            request_count=40,
            store=None,
        )
        second = run_attack_benchmark(
            scenarios=["distributed_low_rate"],
            seeds=[17],
            edge_id="edge-hyd",
            request_count=40,
            store=None,
        )

        stable_fields = (
            "scenario",
            "seed",
            "strategy",
            "processed_requests",
            "attack_requests",
            "cache_hit_ratio",
            "origin_bytes_transferred",
            "average_latency_ms",
            "p95_latency_ms",
            "evictions",
        )
        self.assertEqual(
            [
                tuple(row[field] for field in stable_fields)
                for row in first["results"]
            ],
            [
                tuple(row[field] for field in stable_fields)
                for row in second["results"]
            ],
        )

    def test_experiment_history_persists_after_reopening_store(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "runs.sqlite3"
            first_store = ExperimentStore(database)
            saved = first_store.record_run(
                "unit_test",
                {"seed": 42},
                {"cache_hit_ratio": 0.75},
            )

            reopened_store = ExperimentStore(database)
            history = reopened_store.list_runs()

        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["id"], saved["id"])
        self.assertEqual(history[0]["configuration"]["seed"], 42)
        self.assertEqual(history[0]["result"]["cache_hit_ratio"], 0.75)

    def test_chronological_demand_evaluation_compares_baseline(self):
        for index in range(602):
            content_id = f"content-{(index // 25 + index % 4) % 5}"
            metrics_service.record_request(
                {
                    "edge_id": "edge-hyd",
                    "content_id": content_id,
                    "response_size_bytes": 1024 + index % 3,
                    "cache_hit": index % 2 == 0,
                    "total_latency_ms": 1.5,
                },
                source="demand-evaluation-test",
            )

        response = self.client.post(
            "/api/v1/ai/demand/evaluate",
            json={
                "window_size": 5,
                "max_events": 602,
                "train_ratio": 0.8,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertEqual(result["complete_windows"], 120)
        self.assertGreater(result["training_samples"], 10)
        self.assertGreater(result["test_samples"], 0)
        self.assertIn("mae", result["random_forest"])
        self.assertIn("mae", result["recency_weighted_baseline"])

    def test_demand_training_bounds_zero_window_samples_with_weights(self):
        counts = [0] * 1000
        counts[50] = 2
        counts[700] = 1

        samples = demand_prediction_service._sample_window_targets(
            counts,
            1,
            len(counts),
        )

        self.assertEqual(
            {index for index, _ in samples if counts[index] > 0},
            {50, 700},
        )
        self.assertLessEqual(len(samples), 22)
        self.assertAlmostEqual(sum(weight for _, weight in samples), 999)

    def test_demand_predictions_batch_random_forest_inference(self):
        class BatchModel:
            def __init__(self):
                self.calls = 0
                self.rows_scored = 0

            def predict(self, features):
                self.calls += 1
                self.rows_scored = len(features)
                return [float(index + 1) for index in range(len(features))]

        model = BatchModel()
        demand_prediction_service.trained = True
        demand_prediction_service.model = model
        demand_prediction_service.bucket_counts = {
            ("edge-hyd", "content-a"): [1, 0],
            ("edge-hyd", "content-b"): [2, 0],
            ("edge-hyd", "content-c"): [3, 0],
        }
        demand_prediction_service.content_sizes = {
            pair: 1024 for pair in demand_prediction_service.bucket_counts
        }
        demand_prediction_service.edge_indices = {"edge-hyd": 0}

        response = demand_prediction_service.predict(limit=2)

        self.assertEqual(model.calls, 1)
        self.assertEqual(model.rows_scored, 3)
        self.assertEqual(response.predictions_count, 2)
        self.assertEqual(
            [item.content_id for item in response.predictions],
            ["content-c", "content-b"],
        )

    def test_labeled_anomaly_evaluation_reports_holdout_metrics(self):
        for index in range(250):
            metrics_service.record_request(
                {
                    "edge_id": "edge-hyd",
                    "content_id": f"normal-{index % 5}",
                    "response_size_bytes": 4096,
                    "cache_hit": index % 2 == 0,
                    "total_latency_ms": 1.5,
                    "scenario": "normal",
                    "is_attack": False,
                },
                source="anomaly-evaluation-test",
            )

        for scenario, count in (
            ("flash_crowd", 100),
            ("cache_pollution", 100),
            ("distributed_low_rate", 100),
        ):
            for index in range(count):
                is_attack = scenario == "cache_pollution" or (
                    scenario == "distributed_low_rate"
                    and index % 4 == 0
                )
                metrics_service.record_request(
                    {
                        "edge_id": "edge-hyd",
                        "content_id": (
                            "flash-popular"
                            if scenario == "flash_crowd"
                            else f"{scenario}-{index}"
                        ),
                        "response_size_bytes": 8192,
                        "cache_hit": False,
                        "total_latency_ms": 10.0,
                        "scenario": scenario,
                        "is_attack": is_attack,
                    },
                    source="anomaly-evaluation-test",
                )

        response = self.client.post(
            "/api/v1/ai/anomaly/evaluate",
            json={
                "window_size": 25,
                "max_events": 1000,
                "train_ratio": 0.8,
                "attack_ratio_threshold": 0.01,
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        result = response.json()
        self.assertGreaterEqual(result["training_normal_windows"], 5)
        self.assertGreater(result["test_windows"], 0)
        self.assertIn("precision", result)
        self.assertIn("recall", result)
        self.assertIn("f1_score", result)
        self.assertIn("synthetic", result["message"])

    def test_attack_classification_trusted_demand_and_evaluation(self):
        flash = self.client.post(
            "/api/v1/security/attacks/simulate",
            json={
                "scenario": "flash_crowd",
                "edge_id": "edge-hyd",
                "request_count": 40,
                "seed": 7,
            },
        ).json()
        self.assertEqual(flash["attack_requests"], 0)
        self.assertEqual(flash["legitimate_requests"], 40)

        analyzed = self.client.post(
            "/api/v1/security/discrimination/analyze",
            json={"edge_id": "edge-hyd", "window_size": 20, "max_events": 100},
        ).json()
        self.assertEqual(
            analyzed["results"][0]["classification"],
            "LEGITIMATE_FLASH_CROWD",
        )
        self.assertEqual(
            analyzed["results"][0]["detection_method"],
            "ExplainableRuleBasedClassifier",
        )
        trusted = self.client.post(
            "/api/v1/security/trusted-demand/estimate",
            json={"edge_id": "edge-hyd", "window_size": 20, "max_events": 100},
        ).json()
        self.assertEqual(trusted["events_analyzed"], 40)
        self.assertEqual(trusted["content_demand"][0]["trusted_requests"], 40)
        self.assertEqual(trusted["content_demand"][0]["attack_requests"], 0)

        attack = self.client.post(
            "/api/v1/security/attacks/simulate",
            json={
                "scenario": "cache_pollution",
                "edge_id": "edge-mum",
                "request_count": 40,
                "seed": 11,
            },
        ).json()
        self.assertEqual(attack["attack_requests"], 40)
        attack_demand = self.client.post(
            "/api/v1/security/trusted-demand/estimate",
            json={"edge_id": "edge-mum", "window_size": 20, "max_events": 100},
        ).json()
        self.assertEqual(
            sum(item["trusted_requests"] for item in attack_demand["content_demand"]),
            0,
        )
        self.assertEqual(
            sum(item["attack_requests"] for item in attack_demand["content_demand"]),
            40,
        )

        evaluation = self.client.post(
            "/api/v1/security/discrimination/evaluate",
            json={"edge_id": "edge-hyd", "window_size": 20, "max_events": 100},
        ).json()
        self.assertGreater(evaluation["evaluation_windows"], 0)
        self.assertGreater(
            evaluation["confusion_matrix"]["LEGITIMATE_FLASH_CROWD"][
                "LEGITIMATE_FLASH_CROWD"
            ],
            0,
        )

    def test_filtering_and_training_prediction_placement_anomaly_routes(self):
        for edge_id in ("edge-hyd", "edge-mum"):
            self.client.post(
                "/api/v1/security/attacks/simulate",
                json={
                    "scenario": "flash_crowd",
                    "edge_id": edge_id,
                    "request_count": 60,
                    "seed": 3,
                },
            )

        self.assertEqual(
            len(metrics_service.get_events()),
            120,
        )
        filtered = self.client.post(
            "/api/v1/security/discrimination/analyze",
            json={"edge_id": "edge-hyd", "window_size": 20, "max_events": 20},
        ).json()
        self.assertEqual(filtered["results"][0]["features"]["request_count"], 20)
        trusted = self.client.post(
            "/api/v1/security/trusted-demand/estimate",
            json={"edge_id": "edge-hyd", "window_size": 20, "max_events": 20},
        ).json()
        self.assertEqual(trusted["events_analyzed"], 20)

        demand_training = self.client.post(
            "/api/v1/ai/demand/train",
            json={"window_size": 5, "max_events": 120},
        )
        self.assertEqual(demand_training.status_code, 200, demand_training.text)
        predictions = self.client.get(
            "/api/v1/ai/demand/predictions?edge_id=edge-hyd&limit=10"
        )
        self.assertEqual(predictions.status_code, 200, predictions.text)
        self.assertGreater(predictions.json()["predictions_count"], 0)
        self.assertEqual(self.client.get("/api/v1/ai/demand/status").status_code, 200)

        anomaly_training = self.client.post(
            "/api/v1/ai/anomaly/train",
            json={"window_size": 5, "max_events": 120},
        )
        self.assertEqual(anomaly_training.status_code, 200, anomaly_training.text)
        self.assertTrue(anomaly_training.json()["trained"])
        anomaly = self.client.get("/api/v1/ai/anomaly/analyze?edge_id=edge-hyd")
        self.assertEqual(anomaly.status_code, 200, anomaly.text)
        self.assertEqual(anomaly.json()["windows_analyzed"], 1)
        self.assertEqual(self.client.get("/api/v1/ai/anomaly/status").status_code, 200)

        placement = self.client.post(
            "/api/v1/cache/placement/optimize",
            json={
                "edge_id": "edge-hyd",
                "prediction_limit": 10,
                "max_events": 120,
                "window_size": 10,
                "apply_placement": False,
            },
        )
        self.assertEqual(placement.status_code, 200, placement.text)
        self.assertGreater(placement.json()["candidates_count"], 0)
        self.assertFalse(placement.json()["apply_placement"])
        all_edges = self.client.post(
            "/api/v1/cache/placement/optimize",
            json={
                "prediction_limit": 10,
                "max_events": 120,
                "window_size": 10,
            },
        )
        self.assertEqual(all_edges.status_code, 200, all_edges.text)
        delhi_summary = next(
            item for item in all_edges.json()["edge_summaries"]
            if item["edge_id"] == "edge-del"
        )
        self.assertIn("No demand history", delhi_summary["message"])

    def test_recovery_is_dry_run_by_default_and_apply_evicts(self):
        self.client.post(
            "/api/v1/security/attacks/simulate",
            json={
                "scenario": "cache_pollution",
                "edge_id": "edge-hyd",
                "request_count": 30,
                "seed": 15,
            },
        )
        cache = simulator.caches["edge-hyd"]
        original_objects = set(cache.entries)
        self.assertGreater(len(original_objects), 0)

        dry_run = self.client.post(
            "/api/v1/cache/recovery/run",
            json={
                "edge_id": "edge-hyd",
                "min_content_requests": 1,
                "max_evictions_per_edge": 3,
                "coordinate_edges": False,
            },
        )
        self.assertEqual(dry_run.status_code, 200, dry_run.text)
        self.assertFalse(dry_run.json()["recovery_applied"])
        self.assertEqual(dry_run.json()["mode"], "DRY_RUN")
        self.assertEqual(set(cache.entries), original_objects)
        self.assertGreater(len(dry_run.json()["actions"]), 0)

        applied = self.client.post(
            "/api/v1/cache/recovery/run",
            json={
                "edge_id": "edge-hyd",
                "min_content_requests": 1,
                "max_evictions_per_edge": 3,
                "coordinate_edges": False,
                "apply_recovery": True,
            },
        )
        self.assertEqual(applied.status_code, 200, applied.text)
        self.assertTrue(applied.json()["recovery_applied"])
        self.assertEqual(applied.json()["edge_summaries"][0]["evictions_completed"], 3)
        self.assertEqual(len(original_objects) - len(cache.entries), 3)
        history = self.client.get("/api/v1/cache/recovery/history")
        self.assertEqual(history.status_code, 200, history.text)
        self.assertEqual(history.json()["total_runs"], 2)
        self.assertEqual(len(history.json()["runs"]), 2)

    def test_recovery_coordinates_trusted_content_without_mutating_dry_run(self):
        self.client.post(
            "/api/v1/network/simulate-request",
            json={
                "edge_id": "edge-hyd",
                "content_id": "shared-legitimate-content",
                "response_size_bytes": 4096,
            },
        )
        metrics_service.record_request(
            {
                "edge_id": "edge-mum",
                "content_id": "shared-legitimate-content",
                "response_size_bytes": 4096,
                "cache_hit": True,
                "total_latency_ms": 1.5,
                "is_attack": False,
            },
            source="controlled_replication_test",
        )

        dry_run = self.client.post(
            "/api/v1/cache/recovery/run",
            json={
                "min_content_requests": 1,
                "max_replications_per_edge": 1,
                "apply_recovery": False,
            },
        )
        self.assertEqual(dry_run.status_code, 200, dry_run.text)
        self.assertFalse(dry_run.json()["recovery_applied"])
        proposed = next(
            action for action in dry_run.json()["actions"]
            if action["action"] == "COORDINATE_TRUSTED_CONTENT"
        )
        self.assertEqual(proposed["status"], "PROPOSED")
        self.assertNotIn(
            "shared-legitimate-content",
            simulator.caches["edge-mum"].entries,
        )

        applied = self.client.post(
            "/api/v1/cache/recovery/run",
            json={
                "min_content_requests": 1,
                "max_replications_per_edge": 1,
                "apply_recovery": True,
            },
        )
        self.assertEqual(applied.status_code, 200, applied.text)
        self.assertIn(
            "shared-legitimate-content",
            simulator.caches["edge-mum"].entries,
        )
        replication = next(
            action for action in applied.json()["actions"]
            if action["action"] == "COORDINATE_TRUSTED_CONTENT"
        )
        self.assertEqual(replication["status"], "COMPLETED")

    def test_empty_history_and_invalid_inputs_are_explicit(self):
        empty_history = self.client.get("/api/v1/cache/recovery/history")
        self.assertEqual(empty_history.status_code, 200, empty_history.text)
        self.assertEqual(
            empty_history.json(),
            {"total_runs": 0, "runs": []},
        )
        self.assertEqual(
            self.client.post("/api/v1/cache/recovery/history").status_code,
            405,
        )

        demand = self.client.get("/api/v1/ai/demand/predictions")
        self.assertEqual(demand.status_code, 400)
        self.assertIn("No demand history", demand.json()["detail"])
        self.assertEqual(
            self.client.post(
                "/api/v1/ai/demand/train",
                json={"window_size": 5, "max_events": 10},
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.get("/api/v1/ai/anomaly/analyze").status_code,
            400,
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/ai/anomaly/train",
                json={"window_size": 5, "max_events": 10},
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/cache/placement/optimize",
                json={"apply_placement": False},
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/security/attacks/simulate",
                json={
                    "scenario": "flash_crowd",
                    "edge_id": "invalid",
                    "request_count": 10,
                },
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.post(
                "/api/v1/cache/recovery/run",
                json={"apply_recovery": False},
            ).json()["mode"],
            "DRY_RUN",
        )
        empty_trusted = self.client.post(
            "/api/v1/security/trusted-demand/estimate",
            json={"window_size": 10, "max_events": 10},
        ).json()
        self.assertEqual(empty_trusted["events_analyzed"], 0)
        self.assertEqual(empty_trusted["content_demand"], [])

    def test_cache_policies_remove_and_placement_capacity_accounting(self):
        lru = EdgeCache("edge-test", 4, "LRU")
        lru.insert("a", 2)
        lru.insert("b", 2)
        self.assertTrue(lru.access("a"))
        evicted = lru.insert("c", 2)
        self.assertEqual(evicted, ["b"])
        self.assertEqual(set(lru.entries), {"a", "c"})
        self.assertEqual(lru.used_bytes, 4)
        self.assertTrue(lru.remove("a"))
        self.assertEqual(lru.used_bytes, 2)
        self.assertFalse(lru.remove("missing"))

        fifo = EdgeCache("edge-test", 4, "FIFO")
        fifo.insert("a", 2)
        fifo.insert("b", 2)
        fifo.access("a")
        fifo.insert("c", 2)
        self.assertEqual(set(fifo.entries), {"b", "c"})

        lfu = EdgeCache("edge-test", 4, "LFU")
        lfu.insert("a", 2)
        lfu.insert("b", 2)
        lfu.access("a")
        lfu.access("a")
        lfu.insert("c", 2)
        self.assertEqual(set(lfu.entries), {"a", "c"})

        predictive = EdgeCache("edge-test", 4, "PREDICTIVE")
        predictive.insert("a", 2)
        predictive.insert("b", 2)
        self.assertTrue(predictive.access("a"))
        predictive.insert("c", 2)
        self.assertLessEqual(predictive.used_bytes, predictive.capacity_bytes)

        cache = EdgeCache("edge-test", 4, "LRU")
        cache.insert("existing", 2)
        candidate = attack_resistant_placement_service._build_candidate(
            prediction={
                "content_id": "new-content",
                "content_size_bytes": 3,
                "historical_requests": 10,
                "predicted_requests_next_window": 5,
            },
            trusted_item=None,
            edge_id="edge-test",
            uncertainty_penalty=1.0,
            cache=cache,
        )
        self.assertFalse(candidate.eligible)
        self.assertEqual(
            candidate.placement_status,
            "REJECTED_INSUFFICIENT_AVAILABLE_CAPACITY",
        )


if __name__ == "__main__":
    unittest.main()
