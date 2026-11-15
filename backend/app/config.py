
from copy import deepcopy
import os

ORIGIN_CONFIG = {
    "id": "origin-01",
    "name": "Central Origin Server",
    "location": "Origin Data Center",
    "bandwidth_mbps": 1000.0,
    "processing_latency_ms": 5.0,
}

EDGE_CONFIGS = [
    {
        "id": "edge-hyd",
        "name": "Hyderabad Edge",
        "location": "Hyderabad",
        "cache_capacity_mb": 512.0,
        "origin_rtt_ms": 12.0,
        "bandwidth_mbps": 100.0,
        "processing_latency_ms": 1.5,
    },
    {
        "id": "edge-mum",
        "name": "Mumbai Edge",
        "location": "Mumbai",
        "cache_capacity_mb": 768.0,
        "origin_rtt_ms": 18.0,
        "bandwidth_mbps": 150.0,
        "processing_latency_ms": 1.5,
    },
    {
        "id": "edge-del",
        "name": "Delhi Edge",
        "location": "Delhi",
        "cache_capacity_mb": 640.0,
        "origin_rtt_ms": 24.0,
        "bandwidth_mbps": 120.0,
        "processing_latency_ms": 1.5,
    },
]


def get_origin_config():
    return deepcopy(ORIGIN_CONFIG)


def get_edge_configs():
    return deepcopy(EDGE_CONFIGS)


def get_cors_origins():
    configured = os.getenv("EDGEGUARD_CORS_ORIGINS")
    if configured:
        return [
            origin.strip().rstrip("/")
            for origin in configured.split(",")
            if origin.strip()
        ]
    return [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]
