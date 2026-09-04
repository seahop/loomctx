"""HTTP surface — the substrate all other surfaces build on (decision D-006).

Ingestion + reads + retrieval + answering, guarded by per-namespace API keys
(D-013; open dev mode when LOOM_API_KEYS is unset) and instrumented for
Prometheus (/metrics) with a store-probing readiness check (/readyz).
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse

from .. import metrics
from ..answer import UnresolvedQuestionError, build_answer
from ..auth import AuthConfig, extract_key
from ..context import build_pack, decode_handle, expand_pack
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
    app.state.auth = AuthConfig.from_env()
    if not app.state.auth.enabled:
        logging.getLogger("loom.auth").warning(
            "LOOM_API_KEYS unset — auth is DISABLED (open dev mode)"
        )
    yield
    app.state.store.close()


app = FastAPI(title="Loom", version="0.1.0", lifespan=_lifespan)


def _authorize(request: Request, namespace: str, action: str) -> None:
    key = extract_key(request.headers)
    if request.app.state.auth.allows(key, namespace, action):
        return
    metrics.REJECTED.labels(reason="auth").inc()
    raise HTTPException(
        status_code=401 if key is None else 403,
        detail="missing API key (X-Loom-Key or Authorization: Bearer)"
        if key is None
        else f"key not authorized for '{action}' on namespace {namespace!r}",
    )


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.get("/readyz")
def readyz(request: Request) -> dict:
    if not request.app.state.store.ping():
        raise HTTPException(status_code=503, detail="store unreachable")
    return {"status": "ready"}


@app.get("/metrics")
def prometheus_metrics() -> Response:
    return Response(
        metrics.generate_latest(), media_type=metrics.CONTENT_TYPE_LATEST
    )


@app.post("/v1/ingest")
def ingest(envelope: IngestEnvelope, request: Request):
    _authorize(request, envelope.namespace, "w")
    metrics.INGEST.labels(kind=envelope.kind).inc()
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
    _authorize(request, namespace, "r")
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
    _authorize(request, namespace, "r")
    artifact = request.app.state.store.get_artifact(namespace, artifact_id)
    if artifact is None:
        raise HTTPException(status_code=404, detail="unknown artifact")
    return artifact.model_dump(mode="json")


@app.post("/v1/ask", response_model=ContextPack)
def ask(req: AskRequest, request: Request) -> ContextPack:
    _authorize(request, req.namespace, "r")
    with metrics.PACK_SECONDS.time():
        return build_pack(request.app.state.store, req)


@app.post("/v1/expand", response_model=ContextPack)
def expand(req: ExpandRequest, request: Request) -> ContextPack:
    try:
        namespace = decode_handle(req.handle)["ns"]
    except (ValueError, KeyError, TypeError):
        raise HTTPException(status_code=400, detail="invalid expansion handle")
    _authorize(request, namespace, "r")
    with metrics.PACK_SECONDS.time():
        return expand_pack(request.app.state.store, req.handle, req.budget)


@app.get("/v1/entities/search")
def search_entities(
    q: str,
    request: Request,
    limit: Annotated[int, Query(gt=0, le=100)] = 10,
    namespace: Annotated[str, Header(alias="X-Loom-Namespace")] = "default",
) -> dict:
    _authorize(request, namespace, "r")
    matches = request.app.state.store.search_entities(namespace, q, limit=limit)
    return {
        "query": q,
        "matches": [m.model_dump(mode="json") for m in matches],
    }


@app.post("/v1/answer", response_model=AnswerResponse)
def answer(req: AnswerRequest, request: Request) -> AnswerResponse:
    _authorize(request, req.namespace, "r")
    llm = request.app.state.llm
    if llm is None:
        metrics.ANSWERS.labels(outcome="no_llm").inc()
        raise HTTPException(
            status_code=503,
            detail="no LLM configured: set LOOM_LLM_MODEL plus "
            "LOOM_LLM_PROVIDER or LOOM_LLM_BASE_URL (docs/decisions.md D-012)",
        )
    try:
        result = build_answer(request.app.state.store, llm, req)
    except UnresolvedQuestionError as exc:
        metrics.ANSWERS.labels(outcome="unresolved").inc()
        raise HTTPException(status_code=422, detail=str(exc))
    except LLMError as exc:
        metrics.ANSWERS.labels(outcome="provider_error").inc()
        raise HTTPException(status_code=502, detail=str(exc))
    metrics.ANSWERS.labels(outcome="ok").inc()
    return result
