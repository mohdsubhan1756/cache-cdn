from collections import OrderedDict
from dataclasses import dataclass
from typing import Optional


SUPPORTED_STRATEGIES = {"LRU", "LFU", "FIFO", "PREDICTIVE"}


@dataclass
class CacheEntry:
    content_id: str
    size_bytes: int
    frequency: int
    inserted_at: int
    last_accessed_at: int
    predictive_score: float = 0.0


class EdgeCache:
    """
    A byte-capacity cache implementing LRU, LFU, FIFO, and a
    frequency/recency-based predictive baseline.

    Cache state belongs to a single edge node.
    """

    def __init__(
        self,
        edge_id: str,
        capacity_bytes: int,
        strategy: str = "LRU",
    ):
        if capacity_bytes < 0:
            raise ValueError("Cache capacity cannot be negative.")

        self.edge_id = edge_id
        self.capacity_bytes = int(capacity_bytes)
        self.strategy = self._validate_strategy(strategy)

        self.entries: dict[str, CacheEntry] = {}
        self.used_bytes = 0
        self.clock = 0

        self.requests = 0
        self.hits = 0
        self.misses = 0
        self.evictions = 0

        # LRU ordering: oldest access is first.
        self.lru_order: OrderedDict[str, None] = OrderedDict()

        # FIFO ordering: oldest insertion is first.
        self.fifo_order: OrderedDict[str, None] = OrderedDict()

    @staticmethod
    def _validate_strategy(strategy: str) -> str:
        normalized = strategy.upper()

        if normalized not in SUPPORTED_STRATEGIES:
            raise ValueError(
                f"Unsupported cache strategy '{strategy}'. "
                f"Choose one of: {', '.join(sorted(SUPPORTED_STRATEGIES))}"
            )

        return normalized

    def set_strategy(self, strategy: str) -> None:
        self.strategy = self._validate_strategy(strategy)

    def _touch(self, entry: CacheEntry) -> None:
        self.clock += 1
        previous_access = entry.last_accessed_at
        entry.frequency += 1
        entry.last_accessed_at = self.clock

        # Recency and frequency score for the baseline predictive policy.
        age = max(1, self.clock - entry.inserted_at)
        recency = 1.0 / max(1, self.clock - previous_access)
        entry.predictive_score = (
            entry.frequency / age
        ) + recency

        if entry.content_id in self.lru_order:
            self.lru_order.move_to_end(entry.content_id)

    def access(self, content_id: str) -> bool:
        """
        Return True on a cache hit and False on a miss.
        Hit/miss counters are updated for every access.
        """
        self.requests += 1
        entry = self.entries.get(content_id)

        if entry is None:
            self.misses += 1
            return False

        self.hits += 1
        self._touch(entry)
        return True

    def _select_victim(self) -> Optional[str]:
        if not self.entries:
            return None

        if self.strategy == "LRU":
            return next(iter(self.lru_order), None)

        if self.strategy == "FIFO":
            return next(iter(self.fifo_order), None)

        if self.strategy == "LFU":
            return min(
                self.entries.values(),
                key=lambda entry: (
                    entry.frequency,
                    entry.last_accessed_at,
                    entry.inserted_at,
                ),
            ).content_id

        # Baseline predictive policy: evict the object with the
        # lowest frequency/age score. Ties prefer evicting the older
        # object, then the least recently accessed object.
        return min(
            self.entries.values(),
            key=lambda entry: (
                entry.predictive_score,
                entry.last_accessed_at,
                entry.inserted_at,
            ),
        ).content_id

    def _evict_one(self) -> Optional[str]:
        victim_id = self._select_victim()

        if victim_id is None or not self.remove(victim_id):
            return None

        return victim_id

    def remove(self, content_id: str) -> bool:
        """Remove a specific cached object while preserving cache accounting."""
        entry = self.entries.pop(content_id, None)
        if entry is None:
            return False

        self.used_bytes -= entry.size_bytes
        self.lru_order.pop(content_id, None)
        self.fifo_order.pop(content_id, None)
        self.evictions += 1
        return True

    def insert(self, content_id: str, size_bytes: int) -> list[str]:
        """
        Insert an object after an origin fetch.

        Oversized objects and zero-capacity caches are not cached.
        Existing entries are not duplicated.
        Returns the content IDs evicted during this insertion.
        """
        if not content_id:
            raise ValueError("content_id cannot be empty.")

        if size_bytes < 0:
            raise ValueError("Object size cannot be negative.")

        size_bytes = int(size_bytes)

        if size_bytes == 0 or size_bytes > self.capacity_bytes:
            return []

        if content_id in self.entries:
            return []

        evicted = []

        while self.used_bytes + size_bytes > self.capacity_bytes:
            victim_id = self._evict_one()

            if victim_id is None:
                break

            evicted.append(victim_id)

        self.clock += 1

        entry = CacheEntry(
            content_id=content_id,
            size_bytes=size_bytes,
            frequency=1,
            inserted_at=self.clock,
            last_accessed_at=self.clock,
            predictive_score=1.0,
        )

        self.entries[content_id] = entry
        self.used_bytes += size_bytes
        self.lru_order[content_id] = None
        self.fifo_order[content_id] = None

        return evicted

    def reset(self) -> None:
        """Clear all cache entries and cache statistics."""
        self.entries.clear()
        self.lru_order.clear()
        self.fifo_order.clear()

        self.used_bytes = 0
        self.clock = 0

        self.requests = 0
        self.hits = 0
        self.misses = 0
        self.evictions = 0

    def get_objects(self) -> list[dict]:
        return [
            {
                "content_id": entry.content_id,
                "size_bytes": entry.size_bytes,
                "frequency": entry.frequency,
                "inserted_at": entry.inserted_at,
                "last_accessed_at": entry.last_accessed_at,
                "predictive_score": round(
                    entry.predictive_score, 6
                ),
            }
            for entry in self.entries.values()
        ]

    def get_stats(self) -> dict:
        utilization = (
            self.used_bytes / self.capacity_bytes * 100
            if self.capacity_bytes
            else 0.0
        )

        return {
            "edge_id": self.edge_id,
            "strategy": self.strategy,
            "requests": self.requests,
            "hits": self.hits,
            "misses": self.misses,
            "hit_ratio": (
                self.hits / self.requests if self.requests else 0.0
            ),
            "evictions": self.evictions,
            "objects_cached": len(self.entries),
            "used_bytes": self.used_bytes,
            "capacity_bytes": self.capacity_bytes,
            "utilization_percent": round(utilization, 2),
        }