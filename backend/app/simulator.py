from copy import deepcopy
from uuid import uuid4

from app.cache_engine import EdgeCache
from app.config import get_edge_configs, get_origin_config


class CDNNetworkSimulator:
    def __init__(self):
        self.origin = get_origin_config()

        # Your config.py defines EDGE_CONFIGS as a list.
        self.edges = {
            edge["id"]: edge for edge in get_edge_configs()
        }

        self.caches = {}

        self.requests = 0
        self.origin_requests = 0
        self.origin_bytes_transferred = 0
        self.total_latency_ms = 0.0

        self._create_caches()

    def _create_caches(self):
        self.caches = {
            edge_id: EdgeCache(
                edge_id=edge_id,
                capacity_bytes=int(
                    edge["cache_capacity_mb"] * 1024 * 1024
                ),
                strategy="LRU",
            )
            for edge_id, edge in self.edges.items()
        }

    def _get_edge(self, edge_id):
        if edge_id not in self.edges:
            raise ValueError(f"Unknown edge_id: {edge_id}")
        return self.edges[edge_id]

    def _get_cache(self, edge_id):
        if edge_id not in self.caches:
            raise ValueError(f"Unknown edge_id: {edge_id}")
        return self.caches[edge_id]

    @staticmethod
    def _transfer_time_ms(size_bytes, bandwidth_mbps):
        if size_bytes <= 0 or bandwidth_mbps <= 0:
            return 0.0

        return (
            size_bytes * 8 / (bandwidth_mbps * 1_000_000)
        ) * 1000

    def get_topology(self):
        edge_nodes = []

        for edge_id, edge in self.edges.items():
            edge_nodes.append({
                **deepcopy(edge),
                "cache": self.caches[edge_id].get_stats(),
                "cache_engine_enabled": True,
            })

        return {
            "origin": deepcopy(self.origin),
            "edges": edge_nodes,
        }

    def simulate_request(
        self,
        edge_id,
        content_id,
        response_size_bytes,
    ):
        if not content_id or not str(content_id).strip():
            raise ValueError("content_id cannot be empty.")

        if response_size_bytes < 0:
            raise ValueError(
                "response_size_bytes cannot be negative."
            )

        edge = self._get_edge(edge_id)
        cache = self._get_cache(edge_id)

        content_id = str(content_id)
        response_size_bytes = int(response_size_bytes)

        self.requests += 1
        cache_hit = cache.access(content_id)

        if cache_hit:
            origin_latency_ms = 0.0
            origin_bytes = 0
            served_by = edge_id
            total_latency_ms = edge["processing_latency_ms"]
            message = "Cache hit: content served by edge."

        else:
            self.origin_requests += 1
            self.origin_bytes_transferred += response_size_bytes

            origin_latency_ms = (
                edge["origin_rtt_ms"]
                + self.origin["processing_latency_ms"]
                + self._transfer_time_ms(
                    response_size_bytes,
                    self.origin["bandwidth_mbps"],
                )
            )

            origin_bytes = response_size_bytes
            served_by = "origin"

            total_latency_ms = (
                origin_latency_ms
                + edge["processing_latency_ms"]
            )

            cache.insert(content_id, response_size_bytes)
            message = "Cache miss: content fetched from origin."

        self.total_latency_ms += total_latency_ms

        return {
            "request_id": str(uuid4()),
            "edge_id": edge_id,
            "content_id": content_id,
            "response_size_bytes": response_size_bytes,
            "cache_hit": cache_hit,
            "served_by": served_by,
            "origin_latency_ms": round(origin_latency_ms, 6),
            "edge_processing_latency_ms": edge[
                "processing_latency_ms"
            ],
            "total_latency_ms": round(total_latency_ms, 6),
            "origin_bytes_transferred": origin_bytes,
            "cache_strategy": cache.strategy,
            "message": message,
        }

    def set_cache_strategy(self, edge_id, strategy):
        self._get_edge(edge_id)
        cache = self._get_cache(edge_id)
        cache.set_strategy(strategy)

        return {
            "edge_id": edge_id,
            "strategy": cache.strategy,
            "message": "Cache strategy updated.",
        }

    def set_cache_capacity(self, edge_id, capacity_bytes):
        if (
            isinstance(capacity_bytes, bool)
            or not isinstance(capacity_bytes, int)
        ):
            raise ValueError("capacity_bytes must be a non-negative integer.")
        if capacity_bytes < 0:
            raise ValueError("capacity_bytes must be a non-negative integer.")

        cache = self._get_cache(edge_id)
        self.reset()
        cache.capacity_bytes = capacity_bytes
        return cache.get_stats()

    def get_cache_stats(self, edge_id=None):
        if edge_id is not None:
            return self._get_cache(edge_id).get_stats()

        return {
            key: cache.get_stats()
            for key, cache in self.caches.items()
        }

    def get_cache_objects(self, edge_id):
        return self._get_cache(edge_id).get_objects()

    def reset(self):
        self.requests = 0
        self.origin_requests = 0
        self.origin_bytes_transferred = 0
        self.total_latency_ms = 0.0

        for cache in self.caches.values():
            cache.reset()

    def get_stats(self):
        total_hits = sum(
            cache.hits for cache in self.caches.values()
        )
        total_cache_requests = sum(
            cache.requests for cache in self.caches.values()
        )
        total_evictions = sum(
            cache.evictions for cache in self.caches.values()
        )

        return {
            "requests": self.requests,
            "origin_requests": self.origin_requests,
            "origin_bytes_transferred": (
                self.origin_bytes_transferred
            ),
            "average_latency_ms": round(
                self.total_latency_ms / self.requests, 6
            ) if self.requests else 0.0,
            "cache_hits": total_hits,
            "cache_misses": total_cache_requests - total_hits,
            "cache_hit_ratio": (
                total_hits / total_cache_requests
                if total_cache_requests else 0.0
            ),
            "total_evictions": total_evictions,
            "cache_engine_enabled": True,
        }


simulator = CDNNetworkSimulator()