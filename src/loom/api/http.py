"""HTTP surface — the substrate all other surfaces build on (decision D-006).

Implemented: /healthz, claim + document ingestion, raw observation reads,
artifact reads, and the phase-2 read path (/v1/ask, /v1/expand).
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from ..context import build_pack, expand_pack
from ..contracts import (
    AskRequest,
    ClaimIn,
    ContextPack,
    EntityRef,
    ExpandRequest,
    IngestEnvelope,
)
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
def ingest(envelope: IngestEnvelope, request: Request):
    if isinstance(envelope, ClaimIn):
        obs = request.app.state.store.record_claim(envelope)
        return {"status": "recorded", "observation_id": obs.id}
    artifact = request.app.state.store.store_artifact(envelope)
    return JSONResponse(
        status_code=202,
        content={
            "status": "accepted",
            "artifact_id": artifact.id,
            "extraction": artifact.extraction_status,
        },
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


@app.get("/v1/artifacts/{artifact_id}")
def get_artifact(
    artifact_id: str,
    request: Request,
    namespace: Annotated[str, Header(alias="X-Loom-Namespace")] = "default",
) -> dict:
    artifact = request.app.state.store.get_artifact(namespace, artifact_id)
    if artifact is None:
        raise HTTPException(status_code=404, detail="unknown artifact")
    return artifact.model_dump(mode="json")


@app.post("/v1/ask", response_model=ContextPack)
def ask(req: AskRequest, request: Request) -> ContextPack:
    return build_pack(request.app.state.store, req)


@app.post("/v1/expand", response_model=ContextPack)
def expand(req: ExpandRequest, request: Request) -> ContextPack:
    try:
        return expand_pack(request.app.state.store, req.handle, req.budget)
    except (ValueError, KeyError, TypeError):
        raise HTTPException(status_code=400, detail="invalid expansion handle")
