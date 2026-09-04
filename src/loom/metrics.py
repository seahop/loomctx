"""Prometheus metrics (D-015). Scraped from GET /metrics on the engine.

One module owns every metric object so names stay consistent and any layer
(API, stores, consumer) can increment without redefining collectors.
"""

from prometheus_client import (  # noqa: F401  (CONTENT_TYPE_LATEST re-exported)
    CONTENT_TYPE_LATEST,
    Counter,
    Histogram,
    generate_latest,
)

INGEST = Counter(
    "loom_ingest_total", "Envelopes accepted", ["kind"]
)
INGEST_DEDUPED = Counter(
    "loom_ingest_deduped_total",
    "Envelopes dropped as duplicates via event_id (D-014)",
)
REJECTED = Counter(
    "loom_requests_rejected_total", "Requests denied", ["reason"]
)
PACK_SECONDS = Histogram(
    "loom_pack_build_seconds", "Context pack build latency",
    buckets=(0.005, 0.02, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
)
ANSWERS = Counter(
    "loom_answers_total", "LLM answer requests", ["outcome"]
)
