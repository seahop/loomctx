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
from ..auth import AuthConfig, Grant, extract_key
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
from ..llm import LLMError, embedder_from_env, llm_from_env
from ..store.factory import store_from_env


@asynccontextmanager
async def _lifespan(app: FastAPI):
    app.state.store = store_from_env()
    app.state.llm = llm_from_env()
    app.state.embedder = embedder_from_env()
    app.state.auth = AuthConfig.from_env()
    if not app.state.auth.enabled:
        logging.getLogger("loom.auth").warning(
            "LOOM_API_KEYS unset — auth is DISABLED (open dev mode)"
        )
    yield
    app.state.store.close()


app = FastAPI(title="Loom", version="0.1.0", lifespan=_lifespan)


def _authorize(request: Request, namespace: str, action: str) -> Grant | None:
    """Namespace/perms check. Returns the grant (for fine-grained gates) or
    None when auth is disabled."""
    auth: AuthConfig = request.app.state.auth
    if not auth.enabled:
        return None
    key = extract_key(request.headers)
    if key is None:
        metrics.REJECTED.labels(reason="auth").inc()
        raise HTTPException(
            status_code=401,
            detail="missing API key (X-Loom-Key or Authorization: Bearer)",
        )
    grant = auth.grant_for(key)
    if grant is None or not grant.allows(namespace, action):
        metrics.REJECTED.labels(reason="auth").inc()
        raise HTTPException(
            status_code=403,
            detail=f"key not authorized for '{action}' on namespace {namespace!r}",
        )
    return grant


def _gate_entity_type(grant: Grant | None, entity_type: str) -> None:
    if grant is not None and not grant.allows_entity_type(entity_type):
        metrics.REJECTED.labels(reason="scope").inc()
        raise HTTPException(
            status_code=403,
            detail=f"key {grant.id!r} is not scoped to entity type "
            f"{entity_type!r}",
        )


def _gate_source(grant: Grant | None, source: str) -> None:
    if grant is not None and not grant.allows_source(source):
        metrics.REJECTED.labels(reason="scope").inc()
        raise HTTPException(
            status_code=403,
            detail=f"key {grant.id!r} may not write claims for source "
            f"{source!r}",
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
    grant = _authorize(request, envelope.namespace, "w")
    _gate_source(grant, envelope.source)
    if isinstance(envelope, ClaimIn):
        _gate_entity_type(grant, envelope.subject.type)
        if isinstance(envelope.object, EntityRef):
            _gate_entity_type(grant, envelope.object.type)
        metrics.INGEST.labels(kind=envelope.kind).inc()
        obs = request.app.state.store.record_claim(envelope)
        return {"status": "recorded", "observation_id": obs.id}
    metrics.INGEST.labels(kind=envelope.kind).inc()
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
    grant = _authorize(request, namespace, "r")
    _gate_entity_type(grant, etype)
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
    grant = _authorize(request, req.namespace, "r")
    for subject in [req.subject] if req.subject else req.scope.subjects:
        _gate_entity_type(grant, subject.type)
    with metrics.PACK_SECONDS.time():
        return build_pack(
            request.app.state.store, req,
            embedder=request.app.state.embedder,
        )


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
    grant = _authorize(request, namespace, "r")
    matches = request.app.state.store.search_entities(namespace, q, limit=limit)
    if grant is not None and grant.entity_types is not None:
        # scoped keys see a scoped world, not an error
        matches = [m for m in matches if m.type in grant.entity_types]
    return {
        "query": q,
        "matches": [m.model_dump(mode="json") for m in matches],
    }


@app.post("/v1/answer", response_model=AnswerResponse)
def answer(req: AnswerRequest, request: Request) -> AnswerResponse:
    grant = _authorize(request, req.namespace, "r")
    explicit = [req.subject] if req.subject else (
        req.scope.subjects if req.scope else []
    )
    for subject in explicit:
        _gate_entity_type(grant, subject.type)
    llm = request.app.state.llm
    # BYO provider key (D-013a): an agent may present its own key for the
    # configured provider (X-Loom-LLM-Key) so LLM spend bills to the caller.
    # The Loom bearer still controls what data the answer can see; the
    # provider/model choice stays server-side.
    caller_llm_key = request.headers.get("x-loom-llm-key")
    if llm is not None and caller_llm_key:
        import copy

        llm = copy.copy(llm)
        llm.api_key = caller_llm_key
    if llm is None:
        metrics.ANSWERS.labels(outcome="no_llm").inc()
        raise HTTPException(
            status_code=503,
            detail="no LLM configured: set LOOM_LLM_MODEL plus "
            "LOOM_LLM_PROVIDER or LOOM_LLM_BASE_URL (docs/decisions.md D-012)",
        )
    try:
        result = build_answer(
            request.app.state.store, llm, req,
            allowed_types=grant.entity_types if grant else None,
            embedder=request.app.state.embedder,
        )
    except UnresolvedQuestionError as exc:
        metrics.ANSWERS.labels(outcome="unresolved").inc()
        raise HTTPException(status_code=422, detail=str(exc))
    except LLMError as exc:
        metrics.ANSWERS.labels(outcome="provider_error").inc()
        raise HTTPException(status_code=502, detail=str(exc))
    metrics.ANSWERS.labels(outcome="ok").inc()
    return result
