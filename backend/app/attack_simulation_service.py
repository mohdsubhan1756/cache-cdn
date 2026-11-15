
import random
from threading import RLock

from app.attack_models import (
    AttackSimulationRequest,
    AttackSimulationResponse,
)
from app.metrics_service import metrics_service
from app.simulator import simulator


class AttackSimulationService:
    """
    Module 7: Local, controlled CDN attack traffic generator.

    Scenarios:
      cache_pollution:
          Many one-off content requests.

      distributed_low_rate:
          Attack requests interleaved with legitimate popular-content
          requests, with simulated clients rotating across requests.

      flash_crowd:
          Many legitimate requests for the same popular content.
    """

    MIN_CONTENT_SIZE = 32 * 1024
    MAX_CONTENT_SIZE = 512 * 1024

    def __init__(self):
        self._lock = RLock()
        self.last_run = None

    @staticmethod
    def _content_size(rng: random.Random) -> int:
        return rng.randint(
            AttackSimulationService.MIN_CONTENT_SIZE,
            AttackSimulationService.MAX_CONTENT_SIZE,
        )

    @staticmethod
    def _check_edge(edge_id: str):
        if edge_id not in simulator.edges:
            raise ValueError(
                f"Unknown edge '{edge_id}'. "
                f"Available edges: {', '.join(simulator.edges.keys())}"
            )

    def _send_request(
        self,
        *,
        edge_id: str,
        content_id: str,
        size_bytes: int,
        scenario: str,
        is_attack: bool,
        client_id: str,
    ) -> dict:
        result = simulator.simulate_request(
            edge_id=edge_id,
            content_id=content_id,
            response_size_bytes=size_bytes,
        )

        # Retain simulator fields and annotate the generated event.
        result["scenario"] = scenario
        result["is_attack"] = is_attack
        result["client_id"] = client_id

        metrics_service.record_request(
            result,
            source="module7_attack_simulator",
            scenario=scenario,
            is_attack=is_attack,
        )

        return result

    def simulate(
        self,
        request: AttackSimulationRequest,
    ) -> AttackSimulationResponse:
        with self._lock:
            self._check_edge(request.edge_id)

            rng = random.Random(request.seed)
            scenario = request.scenario
            results = []

            attack_content_ids = set()
            clients = set()

            popular_content_id = (
                f"m7-popular-{request.edge_id}-{request.seed}"
            )
            popular_content_size = 128 * 1024

            if scenario == "flash_crowd":
                # The surge targets one legitimate, popular object.
                for index in range(request.request_count):
                    client_id = f"flash-client-{index % 100}"
                    clients.add(client_id)

                    results.append(
                        self._send_request(
                            edge_id=request.edge_id,
                            content_id=popular_content_id,
                            size_bytes=popular_content_size,
                            scenario=scenario,
                            is_attack=False,
                            client_id=client_id,
                        )
                    )

            elif scenario == "cache_pollution":
                # Every request targets a new object, making reuse
                # unlikely and consuming cache space.
                for index in range(request.request_count):
                    content_id = (
                        f"m7-pollution-{request.seed}-{index}"
                    )
                    client_id = f"pollution-client-{index % 20}"

                    clients.add(client_id)
                    attack_content_ids.add(content_id)

                    results.append(
                        self._send_request(
                            edge_id=request.edge_id,
                            content_id=content_id,
                            size_bytes=self._content_size(rng),
                            scenario=scenario,
                            is_attack=True,
                            client_id=client_id,
                        )
                    )

            elif scenario == "distributed_low_rate":
                # Rotate through simulated clients and interleave
                # unique attack objects with popular legitimate traffic.
                # Approximately one in four requests is attack traffic.
                attack_index = 0

                for index in range(request.request_count):
                    client_id = f"distributed-client-{index % 100}"
                    clients.add(client_id)

                    is_attack = (index % 4 == 0)

                    if is_attack:
                        content_id = (
                            f"m7-distributed-{request.seed}-"
                            f"{attack_index}"
                        )
                        size_bytes = self._content_size(rng)
                        attack_content_ids.add(content_id)
                        attack_index += 1
                    else:
                        content_id = popular_content_id
                        size_bytes = popular_content_size

                    results.append(
                        self._send_request(
                            edge_id=request.edge_id,
                            content_id=content_id,
                            size_bytes=size_bytes,
                            scenario=scenario,
                            is_attack=is_attack,
                            client_id=client_id,
                        )
                    )

            else:
                raise ValueError(
                    f"Unsupported scenario: {scenario}"
                )

            total = len(results)
            hits = sum(
                1 for result in results if result["cache_hit"]
            )
            misses = total - hits
            attack_requests = sum(
                1 for result in results if result["is_attack"]
            )
            legitimate_requests = total - attack_requests
            origin_requests = sum(
                1
                for result in results
                if result["served_by"] == "origin"
            )
            origin_bytes = sum(
                int(result.get("origin_bytes_transferred", 0))
                for result in results
            )
            average_latency = (
                sum(
                    float(result["total_latency_ms"])
                    for result in results
                ) / total
                if total
                else 0.0
            )

            response = AttackSimulationResponse(
                scenario=scenario,
                edge_id=request.edge_id,
                seed=request.seed,
                requested_count=request.request_count,
                processed_requests=total,
                attack_requests=attack_requests,
                legitimate_requests=legitimate_requests,
                cache_hits=hits,
                cache_misses=misses,
                hit_ratio=round(hits / total, 4) if total else 0.0,
                origin_requests=origin_requests,
                origin_bytes_transferred=origin_bytes,
                average_latency_ms=round(average_latency, 4),
                attack_content_count=len(attack_content_ids),
                simulated_clients=len(clients),
                message=(
                    "Traffic generated locally and recorded in "
                    "Module 4 metrics. Results describe this run; "
                    "they are not evidence of a real-world attack."
                ),
            )

            self.last_run = response.model_dump()
            return response


attack_simulation_service = AttackSimulationService()
