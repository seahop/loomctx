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

from ..answer import UnresolvedQuestionError, build_answer
from ..context import build_pack, expand_pack
from ..contracts import (
    AnswerRequest,
    AnswerResponse,
    AskRequest,
    ClaimIn,
    ContextPack,
    EntityRef,
    ExpandRequest,
    IngestEnvelope,
)
from ..llm import LLMError, llm_from_env
from ..store.factory import store_from_env


@asynccontextmanager
async def _lifespan(app: FastAPI):
    app.state.store = store_from_env()
    app.state.llm = llm_from_env()
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


@app.get("/v1/entities/search")
def search_entities(
    q: str,
    request: Request,
    limit: Annotated[int, Query(gt=0, le=100)] = 10,
    namespace: Annotated[str, Header(alias="X-Loom-Namespace")] = "default",
) -> dict:
    matches = request.app.state.store.search_entities(namespace, q, limit=limit)
    return {
        "query": q,
        "matches": [m.model_dump(mode="json") for m in matches],
    }


@app.post("/v1/answer", response_model=AnswerResponse)
def answer(req: AnswerRequest, request: Request) -> AnswerResponse:
    llm = request.app.state.llm
    if llm is None:
        raise HTTPException(
            status_code=503,
            detail="no LLM configured: set LOOM_LLM_MODEL plus "
            "LOOM_LLM_PROVIDER or LOOM_LLM_BASE_URL (docs/decisions.md D-012)",
        )
    try:
        return build_answer(request.app.state.store, llm, req)
    except UnresolvedQuestionError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except LLMError as exc:
        raise HTTPException(status_code=502, detail=str(exc))
