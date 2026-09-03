"""HTTP surface — the substrate all other surfaces build on (decision D-006).

Implemented: /healthz, claim ingestion, raw observation reads.
Honest 501s: document ingestion (phase 1 completion) and /v1/ask (phase 2) —
see docs/roadmap.md.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, Query, Request

from ..contracts import ClaimIn, EntityRef, IngestEnvelope
from ..store.sqlite import SqliteStore


@asynccontextmanager
async def _lifespan(app: FastAPI):
    app.state.store = SqliteStore(os.environ.get("LOOM_DB", "loom.db"))
    yield
    app.state.store.close()


app = FastAPI(title="Loom", version="0.1.0", lifespan=_lifespan)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post("/v1/ingest")
def ingest(envelope: IngestEnvelope, request: Request) -> dict:
    if isinstance(envelope, ClaimIn):
        obs = request.app.state.store.record_claim(envelope)
        return {"status": "recorded", "observation_id": obs.id}
    raise HTTPException(
        status_code=501,
        detail="document ingestion (artifact storage) is not implemented yet; "
        "see docs/roadmap.md phase 1",
    )


@app.get("/v1/entities/{etype}/{key}/observations")
def entity_observations(
    etype: str,
    key: str,
    request: Request,
    limit: Annotated[int, Query(gt=0, le=1000)] = 100,
    namespace: Annotated[str, Header(alias="X-Loom-Namespace")] = "default",
) -> dict:
    observations = request.app.state.store.observations_for(
        namespace, EntityRef(type=etype, key=key), limit=limit
    )
    return {
        "entity": {"type": etype, "key": key},
        "namespace": namespace,
        "count": len(observations),
        "observations": [o.model_dump(mode="json") for o in observations],
    }


@app.post("/v1/ask")
def ask() -> dict:
    raise HTTPException(
        status_code=501,
        detail="context packs land in phase 2; see docs/roadmap.md",
    )
