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
from pydantic import TypeAdapter, ValidationError
from starlette.concurrency import run_in_threadpool

from .. import metrics
from ..answer import UnresolvedQuestionError, build_answer
from ..auth import AuthConfig, Grant, extract_key
from ..context import build_pack, decode_handle, expand_pack, semantic_search
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
from ..contracts import (
    MAX_BATCH_ITEMS,
    DocumentIn,
    IngestBatchResponse,
    IngestItemResult,
    SchemaRegistration,
    SemanticSearchResponse,
)
from ..llm import LLMError, embedder_from_env, llm_from_env
from ..registry import RegistryCache, validate_claim
from ..consumer import resolve_provenance
from ..store.factory import store_from_env


@asynccontextmanager
async def _lifespan(app: FastAPI):
    app.state.store = store_from_env()
    app.state.registry = RegistryCache(app.state.store)
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


def _max_body_bytes() -> int:
    raw = os.environ.get("LOOM_MAX_BODY_BYTES", "").strip()
    try:
        return int(raw) if raw else 2 * 1024 * 1024
    except ValueError:
        return 2 * 1024 * 1024


@app.middleware("http")
async def _cap_request_size(request: Request, call_next):
    """The default (no-gateway) shape had no body limit at all (H-A14):
    reject oversized uploads before parsing, like the gateway does."""
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > _max_body_bytes():
        metrics.REJECTED.labels(reason="too_large").inc()
        return JSONResponse(status_code=413, content={"detail": "body too large"})
    return await call_next(request)


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
    store = request.app.state.store
    if not store.ping():
        raise HTTPException(status_code=503, detail="store unreachable")
    return {"status": "ready", "schema_version": store.schema_version(),
            "vector_backend": store.vector_backend()}


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
        # registry validation (D-024): registered predicates enforce their
        # object types; a strict namespace rejects anything unregistered
        problem = validate_claim(
            request.app.state.registry.get(envelope.namespace), envelope)
        if problem is not None:
            metrics.REJECTED.labels(reason="schema").inc()
            raise HTTPException(status_code=422, detail=problem)
        metrics.INGEST.labels(kind=envelope.kind).inc()
        try:
            obs = request.app.state.store.record_claim(envelope)
        except ValueError as exc:  # unresolvable provenance reference (D-039)
            metrics.REJECTED.labels(reason="provenance").inc()
            raise HTTPException(status_code=422, detail=str(exc))
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


_ENVELOPE = TypeAdapter(IngestEnvelope)


def _parse_batch(raw: bytes, content_type: str) -> list:
    """A JSON array, a single object, or newline-delimited JSON — the shapes
    log shippers' HTTP outputs produce (Fluent Bit, Vector, Logstash, the
    OpenTelemetry Collector)."""
    import json as _json
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return []
    if "ndjson" in content_type or "x-ldjson" in content_type or (
        not text.startswith("[") and "\n" in text and not content_type.startswith("application/json")
    ):
        return [_json.loads(line) for line in text.splitlines() if line.strip()]
    data = _json.loads(text)
    if isinstance(data, dict):
        data = data.get("items", data.get("records", [data]))  # common wrappers
    if not isinstance(data, list):
        raise ValueError("batch body must be a JSON array, NDJSON, or one envelope")
    return data


@app.post("/v1/ingest/batch", response_model=IngestBatchResponse)
async def ingest_batch(request: Request) -> IngestBatchResponse:
    """Many envelopes in one request (D-034): a JSON array or NDJSON, up to
    LOOM_MAX_BATCH items. Each item passes the same gates as /v1/ingest and
    is reported individually — one bad record never blocks the rest. Claims
    land in one transaction per store. Idempotent per item via event_id."""
    raw = await request.body()
    try:
        items = _parse_batch(raw, request.headers.get("content-type", ""))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid batch: {exc}")
    limit = int(os.environ.get("LOOM_MAX_BATCH", "") or MAX_BATCH_ITEMS)
    if len(items) > limit:
        raise HTTPException(status_code=413, detail=f"batch of {len(items)} exceeds {limit} items")
    return await run_in_threadpool(_ingest_batch_sync, request, items)


def _ingest_batch_sync(request: Request, items: list) -> IngestBatchResponse:
    store = request.app.state.store
    registry = request.app.state.registry
    results: list[IngestItemResult] = []
    claims: list[tuple[int, ClaimIn]] = []
    grants: dict[str, Grant | None] = {}

    def gate(i: int, envelope) -> str | None:
        ns = envelope.namespace
        if ns not in grants:
            try:
                grants[ns] = _authorize(request, ns, "w")
            except HTTPException as exc:
                if exc.status_code == 401:
                    raise  # no key at all: the whole request is unauthenticated
                grants[ns] = exc  # type: ignore[assignment]
        grant = grants[ns]
        if isinstance(grant, HTTPException):
            return grant.detail
        try:
            _gate_source(grant, envelope.source)
            if isinstance(envelope, ClaimIn):
                _gate_entity_type(grant, envelope.subject.type)
                if isinstance(envelope.object, EntityRef):
                    _gate_entity_type(grant, envelope.object.type)
                problem = validate_claim(registry.get(ns), envelope)
                if problem is not None:
                    return problem
                problem = resolve_provenance(store, envelope)
                if problem is not None:
                    return problem
        except HTTPException as exc:
            return exc.detail
        return None

    for i, item in enumerate(items):
        try:
            envelope = _ENVELOPE.validate_python(item)
        except ValidationError as exc:
            errs = exc.errors(include_input=False)[:2]
            results.append(IngestItemResult(index=i, status="rejected",
                                            detail="; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in errs)))
            continue
        problem = gate(i, envelope)
        if problem is not None:
            metrics.REJECTED.labels(reason="scope").inc()
            results.append(IngestItemResult(index=i, status="rejected", detail=problem))
            continue
        if isinstance(envelope, ClaimIn):
            claims.append((i, envelope))
        else:
            artifact = store.store_artifact(envelope)
            metrics.INGEST.labels(kind="document").inc()
            results.append(IngestItemResult(index=i, status="accepted", artifact_id=artifact.id))
    if claims:
        observations = store.record_claims([c for _, c in claims])
        for (i, _), obs in zip(claims, observations):
            metrics.INGEST.labels(kind="claim").inc()
            results.append(IngestItemResult(index=i, status="recorded", observation_id=obs.id))
    results.sort(key=lambda r: r.index)
    counts = {"recorded": 0, "accepted": 0, "rejected": 0}
    for r in results:
        counts[r.status] += 1
    return IngestBatchResponse(total=len(items), results=results, **counts)


@app.get("/v1/entities/{etype}/{key:path}/observations")  # keys may hold '/'
def entity_observations(
    etype: str,
    key: str,
    request: Request,
    limit: Annotated[int, Query(gt=0, le=1000)] = 100,
    namespace: Annotated[str, Header(alias="X-Loom-Namespace")] = "default",
    namespace_q: Annotated[str | None, Query(alias="namespace")] = None,
) -> dict:
    namespace = namespace_q or namespace  # query param wins over the header (D-039)
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
    namespace_q: Annotated[str | None, Query(alias="namespace")] = None,
) -> dict:
    namespace = namespace_q or namespace  # query param wins over the header (D-039)
    grant = _authorize(request, namespace, "r")
    store = request.app.state.store
    artifact = store.get_artifact(namespace, artifact_id)
    if artifact is None:
        raise HTTPException(status_code=404, detail="unknown artifact")
    # A document has no entity type of its own; for a type-scoped reader it
    # is in scope only once it backs a fact about entities they may see
    # (H-A6). Before extraction, or if it only names other types: 403.
    if grant is not None and grant.entity_types is not None and not (
        store.artifact_cited_within(namespace, artifact_id, grant.entity_types)
    ):
        metrics.REJECTED.labels(reason="scope").inc()
        raise HTTPException(
            status_code=403,
            detail=f"key {grant.id!r} is not scoped to any entity this "
            "artifact is cited for",
        )
    return artifact.model_dump(mode="json")


def _allowed_types(grant: Grant | None) -> tuple[str, ...] | None:
    return grant.entity_types if grant is not None else None


@app.post("/v1/schemas", response_model=SchemaRegistration)
def register_schema(reg: SchemaRegistration, request: Request) -> SchemaRegistration:
    """Register (additively) the entity types and predicates of a namespace —
    the domain knowledge that keeps the core domain-agnostic (D-024).
    Requires write access to the namespace. Returns the effective registry."""
    _authorize(request, reg.namespace, "w")
    merged = request.app.state.store.put_schema(reg)
    request.app.state.registry.invalidate(reg.namespace)
    return merged


@app.get("/v1/schemas", response_model=SchemaRegistration)
def get_schema(
    request: Request,
    namespace: Annotated[str, Header(alias="X-Loom-Namespace")] = "default",
    namespace_q: Annotated[str | None, Query(alias="namespace")] = None,
) -> SchemaRegistration:
    namespace = namespace_q or namespace  # query param wins over the header (D-039)
    _authorize(request, namespace, "r")
    schema = request.app.state.store.get_schema(namespace)
    if schema is None:
        raise HTTPException(status_code=404, detail="no registry for this namespace")
    return schema


@app.post("/v1/ask", response_model=ContextPack)
def ask(req: AskRequest, request: Request) -> ContextPack:
    grant = _authorize(request, req.namespace, "r")
    for subject in [req.subject] if req.subject else req.scope.subjects:
        _gate_entity_type(grant, subject.type)
    with metrics.PACK_SECONDS.time():
        return build_pack(
            request.app.state.store, req,
            embedder=request.app.state.embedder,
            allowed_types=_allowed_types(grant),
        )


@app.post("/v1/expand", response_model=ContextPack)
def expand(req: ExpandRequest, request: Request) -> ContextPack:
    # A handle is a query the caller could have typed by hand (they are
    # forgeable unless LOOM_HANDLE_SECRET is set), so it passes exactly the
    # gates a fresh ask would: namespace, then the subject's entity type.
    try:
        meta = decode_handle(req.handle)
        subject = EntityRef(**meta["subject"])
    except (ValueError, KeyError, TypeError, AttributeError):
        raise HTTPException(status_code=400, detail="invalid expansion handle")
    grant = _authorize(request, meta["ns"], "r")
    _gate_entity_type(grant, subject.type)
    with metrics.PACK_SECONDS.time():
        return expand_pack(
            request.app.state.store, req.handle, req.budget,
            allowed_types=_allowed_types(grant),
        )


@app.get("/v1/entities/search")
def search_entities(
    q: str,
    request: Request,
    limit: Annotated[int, Query(gt=0, le=100)] = 10,
    namespace: Annotated[str, Header(alias="X-Loom-Namespace")] = "default",
    namespace_q: Annotated[str | None, Query(alias="namespace")] = None,
) -> dict:
    namespace = namespace_q or namespace  # query param wins over the header (D-039)
    grant = _authorize(request, namespace, "r")
    # scoped keys see a scoped world, not an error — filtered inside the
    # query so they still get `limit` results (H-C8)
    matches = request.app.state.store.search_entities(
        namespace, q, limit=limit, types=_allowed_types(grant)
    )
    return {
        "query": q,
        "matches": [m.model_dump(mode="json") for m in matches],
    }


@app.get("/v1/entities/semantic", response_model=SemanticSearchResponse)
def semantic_entities(
    q: str,
    request: Request,
    limit: Annotated[int, Query(gt=0, le=50)] = 10,
    namespace: Annotated[str, Header(alias="X-Loom-Namespace")] = "default",
    namespace_q: Annotated[str | None, Query(alias="namespace")] = None,
) -> SemanticSearchResponse:
    """Entities related to a question by meaning (D-025): needs an embedder
    on the serving engine (LOOM_EMBED_*) and the worker to have embedded
    the namespace; each match cites its best-matching fact."""
    namespace = namespace_q or namespace  # query param wins over the header (D-039)
    grant = _authorize(request, namespace, "r")
    embedder = request.app.state.embedder
    if embedder is None:
        raise HTTPException(
            status_code=503,
            detail="no embedder configured: set LOOM_EMBED_* on the engine (D-018)")
    with metrics.PACK_SECONDS.time():
        return semantic_search(request.app.state.store, namespace, embedder, q,
                               limit=limit, allowed_types=_allowed_types(grant))


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
        # Provider bodies can echo URLs, model names, or account details;
        # keep those in the server log and give the caller the short form.
        logging.getLogger("loom.answer").warning("LLM provider error: %s", exc)
        raise HTTPException(status_code=502, detail=exc.public)
    metrics.ANSWERS.labels(outcome="ok").inc()
    return result
