from collections import Counter

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from app.demand_models import (
    DemandEvaluationRequest,
    DemandModelStatusResponse,
    DemandPredictionResponse,
    DemandTrainingRequest,
    DemandTrainingResponse,
)
from app.recovery_models import (
    RecoveryRequest,
    RecoveryResponse,
    RecoveryHistoryResponse,
)
from app.recovery_service import adaptive_recovery_service
from app.placement_models import (
    PlacementRequest,
    PlacementResponse,
)
from app.placement_service import attack_resistant_placement_service
from app.trusted_demand_models import (
    TrustedDemandRequest,
    TrustedDemandResponse,
)
from app.trusted_demand_service import trusted_demand_service
from app.discrimination_models import (
    DiscriminationRequest,
    DiscriminationResponse,
    DiscriminationEvaluationRequest,
    DiscriminationEvaluationResponse,
)
from app.discrimination_service import traffic_discrimination_service
from app.anomaly_models import (
    AnomalyEvaluationRequest,
    AnomalyAnalysisResponse,
    AnomalyModelStatusResponse,
    AnomalyTrainingRequest,
    AnomalyTrainingResponse,
)
from app.experiment_store import experiment_store
from app.attack_models import (
    AttackSimulationRequest,
    AttackSimulationResponse,
)
from app.attack_simulation_service import attack_simulation_service
from app.anomaly_detection_service import anomaly_detection_service
from app.demand_prediction_service import demand_prediction_service
from app.cache_models import CacheStrategyRequest
from app.dataset_models import (
    DatasetInfo,
    DatasetPreviewResponse,
    DatasetReplayRequest,
    DatasetReplayResponse,
)
from app.dataset_service import (
    DatasetError,
    iter_dataset,
    list_datasets,
    preview_dataset,
)
from app.config import get_cors_origins
from app.metrics_service import metrics_service
from app.models import SimulateRequest, SimulateResponse
from app.simulator import simulator


app = FastAPI(
    title="Attack-Resistant Predictive CDN Simulator",
    description=(
        "Modules 1-4: CDN simulation, dataset replay, "
        "cache algorithms, and network QoS metrics."
    ),
    version="0.4.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "project": "AI-Driven Attack-Resistant Predictive Caching",
        "status": "running",
        "completed_modules": [
            "Module 1 - Distributed CDN Network Simulator",
            "Module 2 - Dataset Ingestion and Request Replay",
            "Module 3 - Cache Engine and Baseline Algorithms",
            "Module 4 - Network Performance and QoS Metrics",
        ],
        "documentation": "/docs",
    }


# =========================================================
# MODULE 1: NETWORK
# =========================================================

@app.get("/api/v1/network/topology")
def get_network_topology():
    return simulator.get_topology()


@app.get("/api/v1/network/stats")
def get_network_stats():
    return simulator.get_stats()


@app.post(
    "/api/v1/network/simulate-request",
    response_model=SimulateResponse,
)
def simulate_single_request(request: SimulateRequest):
    try:
        result = simulator.simulate_request(
            edge_id=request.edge_id,
            content_id=request.content_id,
            response_size_bytes=request.response_size_bytes,
        )

        metrics_service.record_request(
            result,
            source="manual",
        )
        experiment_store.record_run(
            operation="manual_request",
            configuration=request.model_dump(),
            result=result,
        )

        return result

    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/network/reset")
def reset_network():
    simulator.reset()
    metrics_service.reset()
    demand_prediction_service.reset()
    anomaly_detection_service.reset()

    return {
        "message": "Network, caches, and experiment metrics reset.",
        "reset": True,
    }


# =========================================================
# MODULE 2: DATASETS
# =========================================================

@app.get("/api/v1/datasets", response_model=list[DatasetInfo])
def get_datasets():
    return list_datasets()


@app.get(
    "/api/v1/datasets/{dataset_name}/preview",
    response_model=DatasetPreviewResponse,
)
def get_dataset_preview(
    dataset_name: str,
    limit: int = Query(default=5, ge=1, le=100),
):
    try:
        records, skipped = preview_dataset(dataset_name, limit)

        return DatasetPreviewResponse(
            dataset=dataset_name,
            records=records,
            returned_records=len(records),
            skipped_records=skipped,
        )

    except DatasetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Could not read dataset: {exc}",
        ) from exc


@app.post(
    "/api/v1/datasets/replay",
    response_model=DatasetReplayResponse,
)
def replay_dataset(request: DatasetReplayRequest):
    processed = 0
    skipped = 0
    attack_labeled = 0
    scenario_counts = Counter()
    results = []
    total_latency = 0.0
    origin_bytes = 0
    origin_requests = 0
    cache_hits = 0

    try:
        for record in iter_dataset(
            request.dataset,
            limit=request.limit,
        ):
            if record.method and record.method.upper() not in {
                "GET",
                "HEAD",
            }:
                skipped += 1
                continue

            if (
                record.status_code is not None
                and not 200 <= record.status_code < 300
            ):
                skipped += 1
                continue

            result = simulator.simulate_request(
                edge_id=request.edge_id,
                content_id=record.content_id,
                response_size_bytes=record.response_size_bytes,
            )

            result.update({
                "dataset": request.dataset,
                "source_request_id": record.request_id,
                "source_timestamp": record.timestamp,
                "scenario": record.scenario,
                "event_type": record.event_type,
                "is_attack": record.is_attack,
                "client_id": record.client_id,
            })

            metrics_service.record_request(
                result,
                source=f"dataset:{request.dataset}",
                scenario=record.scenario,
                is_attack=record.is_attack,
            )

            processed += 1

            if record.is_attack is True:
                attack_labeled += 1

            if record.scenario:
                scenario_counts[record.scenario] += 1

            if result["cache_hit"]:
                cache_hits += 1
            else:
                origin_requests += 1

            origin_bytes += result["origin_bytes_transferred"]
            total_latency += result["total_latency_ms"]
            results.append(result)

    except DatasetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Could not read dataset: {exc}",
        ) from exc

    response = DatasetReplayResponse(
        dataset=request.dataset,
        edge_id=request.edge_id,
        requested_limit=request.limit,
        processed_requests=processed,
        skipped_records=skipped,
        attack_labeled_requests=attack_labeled,
        scenario_counts=dict(scenario_counts),
        cache_hits=cache_hits,
        origin_requests=origin_requests,
        origin_bytes_transferred=origin_bytes,
        average_latency_ms=(
            total_latency / processed if processed else 0.0
        ),
        results=results,
    )
    experiment_store.record_run(
        operation="dataset_replay",
        configuration=request.model_dump(),
        result={
            key: value
            for key, value in response.model_dump().items()
            if key != "results"
        },
    )
    return response


# =========================================================
# MODULE 3: CACHE ENGINE
# =========================================================

@app.get("/api/v1/cache/strategies")
def get_cache_strategies():
    return {
        "strategies": [
            {
                "name": "LRU",
                "description": "Evicts the least recently used object.",
            },
            {
                "name": "LFU",
                "description": "Evicts the least frequently used object.",
            },
            {
                "name": "FIFO",
                "description": "Evicts the oldest inserted object.",
            },
            {
                "name": "PREDICTIVE",
                "description": (
                    "Baseline using observed frequency and object age."
                ),
            },
        ]
    }


@app.put("/api/v1/cache/{edge_id}/strategy")
def update_cache_strategy(
    edge_id: str,
    request: CacheStrategyRequest,
):
    try:
        return simulator.set_cache_strategy(
            edge_id=edge_id,
            strategy=request.strategy,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v1/cache/stats")
def get_all_cache_stats():
    return simulator.get_cache_stats()


@app.get("/api/v1/cache/{edge_id}/stats")
def get_edge_cache_stats(edge_id: str):
    try:
        return simulator.get_cache_stats(edge_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v1/cache/{edge_id}/objects")
def get_edge_cache_objects(edge_id: str):
    try:
        objects = simulator.get_cache_objects(edge_id)

        return {
            "edge_id": edge_id,
            "object_count": len(objects),
            "objects": objects,
        }

    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/v1/cache/{edge_id}/reset")
def reset_edge_cache(edge_id: str):
    try:
        cache = simulator.caches[edge_id]
        cache.reset()

        return {
            "edge_id": edge_id,
            "message": "Edge cache reset.",
            "reset": True,
        }

    except KeyError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown edge_id: {edge_id}",
        ) from exc


# =========================================================
# MODULE 4: PERFORMANCE AND QOS METRICS
# =========================================================

@app.get("/api/v1/metrics")
def get_performance_metrics():
    return metrics_service.get_report()


@app.get("/api/v1/metrics/events")
def get_metric_events(
    limit: int = Query(default=100, ge=1, le=10000),
):
    events = metrics_service.get_events()

    return {
        "total_events": len(events),
        "returned_events": min(len(events), limit),
        "events": events[-limit:],
    }


@app.get("/api/v1/experiments/history")
def get_experiment_history(
    limit: int = Query(default=50, ge=1, le=500),
):
    return {
        "runs": experiment_store.list_runs(limit=limit),
        "database_path": str(experiment_store.database_path),
    }


@app.get("/api/v1/metrics/edges")
def get_per_edge_metrics():
    report = metrics_service.get_report()

    return {
        "by_edge": report["by_edge"],
        "generated_at": report["generated_at"],
    }


@app.get("/api/v1/metrics/strategies")
def get_strategy_metrics():
    report = metrics_service.get_report()

    return {
        "by_strategy": report["by_strategy"],
        "generated_at": report["generated_at"],
    }


@app.get("/api/v1/metrics/scenarios")
def get_scenario_metrics():
    report = metrics_service.get_report()

    return {
        "by_scenario": report["by_scenario"],
        "generated_at": report["generated_at"],
    }


@app.get("/api/v1/metrics/export/json")
def export_metrics_json():
    content = metrics_service.export_json()

    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={
            "Content-Disposition": (
                'attachment; filename="cdn_metrics.json"'
            )
        },
    )


@app.get("/api/v1/metrics/export/csv")
def export_metrics_csv():
    content = metrics_service.export_csv()

    return StreamingResponse(
        iter([content]),
        media_type="text/csv",
        headers={
            "Content-Disposition": (
                'attachment; filename="cdn_metrics.csv"'
            )
        },
    )


@app.post("/api/v1/metrics/reset")
def reset_metrics():
    metrics_service.reset()
    demand_prediction_service.reset()
    anomaly_detection_service.reset()

    return {
        "message": "Experiment measurement records reset.",
        "reset": True,
    }



# ============================================================
# MODULE 5: AI-BASED DEMAND PREDICTION
# ============================================================


@app.post(
    "/api/v1/ai/demand/train",
    response_model=DemandTrainingResponse,
    tags=["Module 5 - AI Demand Prediction"],
)
def train_demand_model(request: DemandTrainingRequest):
    try:
        # Module 4's get_events() does not accept a limit argument.
        events = metrics_service.get_events()

        if isinstance(events, dict):
            events = events.get("events", [])

        if not isinstance(events, list):
            raise ValueError(
                "The metrics service did not return an event list."
            )

        # Keep only the most recent requested number of events.
        events = events[-request.max_events:]

        return demand_prediction_service.train(
            events=events,
            window_size=request.window_size,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Demand model training failed: {exc}",
        ) from exc


@app.post(
    "/api/v1/ai/demand/evaluate",
    tags=["Module 5 - AI Demand Prediction"],
)
def evaluate_demand_model(request: DemandEvaluationRequest):
    try:
        events = metrics_service.get_events()[-request.max_events:]
        result = demand_prediction_service.evaluate(
            events=events,
            window_size=request.window_size,
            train_ratio=request.train_ratio,
        )
        experiment_store.record_run(
            operation="demand_model_evaluation",
            configuration=request.model_dump(),
            result=result,
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Demand model evaluation failed: {exc}",
        ) from exc


@app.get(
    "/api/v1/ai/demand/predictions",
    response_model=DemandPredictionResponse,
    tags=["Module 5 - AI Demand Prediction"],
)
def get_demand_predictions(
    edge_id: str | None = Query(
        default=None,
        description="Optional edge ID, such as edge-hyd.",
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=1000,
    ),
):
    """
    Return ranked content-demand predictions.
    """
    try:
        return demand_prediction_service.predict(
            edge_id=edge_id,
            limit=limit,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Demand prediction failed: {exc}",
        ) from exc


@app.get(
    "/api/v1/ai/demand/status",
    response_model=DemandModelStatusResponse,
    tags=["Module 5 - AI Demand Prediction"],
)
def get_demand_model_status():
    """
    Return the current training state of the demand model.
    """
    return demand_prediction_service.get_status()




# ============================================================
# MODULE 6: AI-BASED TRAFFIC ANOMALY DETECTION
# ============================================================


@app.post(
    "/api/v1/ai/anomaly/train",
    response_model=AnomalyTrainingResponse,
    tags=["Module 6 - Traffic Anomaly Detection"],
)
def train_anomaly_detector(request: AnomalyTrainingRequest):
    """
    Train Isolation Forest on historical request windows.
    """
    try:
        # Module 4 returns the recorded events as an in-memory list.
        events = metrics_service.get_events()

        if isinstance(events, dict):
            events = events.get("events", [])

        if not isinstance(events, list):
            raise ValueError(
                "The metrics service did not return an event list."
            )

        events = events[-request.max_events:]

        return anomaly_detection_service.train(
            events=events,
            window_size=request.window_size,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Anomaly detector training failed: {exc}",
        ) from exc


@app.post(
    "/api/v1/ai/anomaly/evaluate",
    tags=["Module 6 - AI Anomaly Detection"],
)
def evaluate_anomaly_detector(request: AnomalyEvaluationRequest):
    try:
        events = metrics_service.get_events()[-request.max_events:]
        result = anomaly_detection_service.evaluate_labeled(
            events=events,
            window_size=request.window_size,
            train_ratio=request.train_ratio,
            attack_ratio_threshold=request.attack_ratio_threshold,
        )
        experiment_store.record_run(
            operation="anomaly_model_evaluation",
            configuration=request.model_dump(),
            result=result,
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Anomaly model evaluation failed: {exc}",
        ) from exc


@app.get(
    "/api/v1/ai/anomaly/analyze",
    response_model=AnomalyAnalysisResponse,
    tags=["Module 6 - Traffic Anomaly Detection"],
)
def analyze_traffic_anomalies(
    edge_id: str | None = Query(
        default=None,
        description="Optional edge ID, such as edge-hyd.",
    ),
):
    """
    Analyze the most recent request window for each edge.
    """
    try:
        return anomaly_detection_service.analyze(
            edge_id=edge_id
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Traffic anomaly analysis failed: {exc}",
        ) from exc


@app.get(
    "/api/v1/ai/anomaly/status",
    response_model=AnomalyModelStatusResponse,
    tags=["Module 6 - Traffic Anomaly Detection"],
)
def get_anomaly_detector_status():
    """
    Get the current anomaly detector status.
    """
    return anomaly_detection_service.get_status()




# ============================================================
# MODULE 7: CACHE-POLLUTION ATTACK SIMULATOR
# ============================================================


@app.post(
    "/api/v1/security/attacks/simulate",
    response_model=AttackSimulationResponse,
    tags=["Module 7 - Attack Simulator"],
)
def simulate_cache_attack(request: AttackSimulationRequest):
    """
    Generate controlled local attack traffic and record each
    request in Module 4 metrics.
    """
    try:
        response = attack_simulation_service.simulate(request)
        experiment_store.record_run(
            operation="attack_simulation",
            configuration=request.model_dump(),
            result=response.model_dump(),
        )
        return response

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Attack simulation failed: {exc}",
        ) from exc





@app.post(
    "/api/v1/security/trusted-demand/estimate",
    response_model=TrustedDemandResponse,
    tags=["Module 9 - Trusted Demand"],
)
def estimate_trusted_demand(
    request: TrustedDemandRequest,
) -> TrustedDemandResponse:
    try:
        return trusted_demand_service.estimate(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc



# ============================================================
# MODULE 8: FLASH-CROWD VS ATTACK DISCRIMINATION
# ============================================================


@app.post(
    "/api/v1/security/discrimination/analyze",
    response_model=DiscriminationResponse,
    tags=["Module 8 - Traffic Discrimination"],
)
def analyze_traffic_discrimination(
    request: DiscriminationRequest,
):
    """
    Classify the latest traffic window for each selected edge.
    """
    try:
        return traffic_discrimination_service.analyze(request)

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Traffic discrimination failed: {exc}",
        ) from exc


@app.post(
    "/api/v1/security/discrimination/evaluate",
    response_model=DiscriminationEvaluationResponse,
    tags=["Module 8 - Traffic Discrimination"],
)
def evaluate_traffic_discrimination(
    request: DiscriminationEvaluationRequest,
):
    """
    Evaluate classification against labeled Module 7 scenarios.
    """
    try:
        return traffic_discrimination_service.evaluate(
            window_size=request.window_size,
            max_events=request.max_events,
            edge_id=request.edge_id,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Traffic discrimination evaluation failed: {exc}",
        ) from exc



@app.post(
    "/api/v1/cache/placement/optimize",
    response_model=PlacementResponse,
    tags=["Module 10 - Attack-Resistant Placement"],
)
def optimize_cache_placement(
    request: PlacementRequest,
) -> PlacementResponse:
    try:
        return attack_resistant_placement_service.place(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc




@app.post(
    "/api/v1/cache/recovery/run",
    response_model=RecoveryResponse,
    tags=["Module 11 - Adaptive Recovery"],
)
def run_adaptive_recovery(request: RecoveryRequest) -> RecoveryResponse:
    try:
        return adaptive_recovery_service.recover(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get(
    "/api/v1/cache/recovery/history",
    response_model=RecoveryHistoryResponse,
    tags=["Module 11 - Adaptive Recovery"],
)
def get_recovery_history() -> RecoveryHistoryResponse:
    return adaptive_recovery_service.get_history()
