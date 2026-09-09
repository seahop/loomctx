"""The MCP surface (phase 3, decision D-006): agents plug in natively.

Wraps the same core functions the HTTP API uses — no separate logic, no
drift. Entity handles are "type:key" strings ("host:web-01") for agent
ergonomics.

Register with Claude Code (stdio, spawned per session):

    claude mcp add loom -- docker compose run --rm -T loom \
        python -m loom.mcp_server

Or serve remote agents over streamable HTTP (compose profile `mcp`):

    docker compose --profile mcp up -d mcp     # -> :8300/mcp

Auth (H-A9, D-024): stdio is local trust — the agent that spawned the
process already owns the data. The HTTP transports authenticate like the
REST API: every request must carry `X-Loom-Key` / `Authorization: Bearer`
when LOOM_AUTH_FILE / LOOM_API_KEYS is set (an ASGI gate rejects the rest
before MCP sees them), and every tool call applies the key's namespace,
perms, entity-type and source gates exactly as the HTTP routes do.

Requires the `mcp` extra (installed in the image).
"""

from __future__ import annotations

import argparse
import os
from datetime import datetime
from typing import Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from .answer import UnresolvedQuestionError, build_answer
from .auth import AuthConfig, Grant, extract_key
from .context import build_pack, decode_handle, expand_pack, semantic_search
from .contracts import AnswerRequest, AskRequest, ClaimIn, EntityRef, ScopeSpec
from .llm import LLMError, embedder_from_env, llm_from_env
from .registry import validate_claim
from .store.base import GraphStore
from .store.factory import store_from_env

_embedder_loaded = False
_embedder = None
_llm_loaded = False
_llm = None
_auth: AuthConfig | None = None
_transport = "stdio"
# The namespace tools use when a call names none. A live agent run (D-036)
# dropped the argument after two calls and spent twelve steps querying an
# empty 'default'; a deployment that serves one team sets this once.
_DEFAULT_NS = os.environ.get("LOOM_MCP_NAMESPACE", "").strip() or "default"


def _get_embedder():
    global _embedder_loaded, _embedder
    if not _embedder_loaded:
        _embedder = embedder_from_env()
        _embedder_loaded = True
    return _embedder


def _get_llm():
    """Built once per process, not per call (H-E6)."""
    global _llm_loaded, _llm
    if not _llm_loaded:
        _llm = llm_from_env()
        _llm_loaded = True
    return _llm


def _get_auth() -> AuthConfig:
    global _auth
    if _auth is None:
        _auth = AuthConfig.from_env()
    return _auth


# ------------------------------------------------------------------- auth #

def _grant(ctx, namespace: str, action: str) -> Grant | None:
    """The caller's grant for this tool call, or None when no gate applies
    (stdio transport, or auth disabled). Raises PermissionError — which the
    MCP layer returns to the agent as a tool error — when the key is
    missing, unknown, or not allowed the action on the namespace."""
    if _transport == "stdio":
        return None
    auth = _get_auth()
    if not auth.enabled:
        return None
    headers = getattr(ctx, "headers", None) if ctx is not None else None
    key = extract_key(headers or {})
    grant = auth.grant_for(key)
    if grant is None:
        raise PermissionError("missing or unknown API key: send X-Loom-Key "
                              "(or Authorization: Bearer) on every request")
    if not grant.allows(namespace, action):
        raise PermissionError(
            f"key {grant.id!r} is not authorized for {action!r} on namespace {namespace!r}")
    return grant


def _gate_type(grant: Grant | None, entity_type: str) -> None:
    if grant is not None and not grant.allows_entity_type(entity_type):
        raise PermissionError(f"key {grant.id!r} is not scoped to entity type {entity_type!r}")


def _allowed(grant: Grant | None) -> tuple[str, ...] | None:
    return grant.entity_types if grant is not None else None


class KeyGate:
    """ASGI middleware for the HTTP transports: reject requests without a
    valid key before the MCP session machinery sees them (cheap rejection,
    same order as the gateway). Tool-level gates then scope the data."""

    def __init__(self, app, auth: AuthConfig):
        self.app = app
        self.auth = auth

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and self.auth.enabled:
            headers = {k.decode().lower(): v.decode()
                       for k, v in scope.get("headers", [])}
            key = extract_key(headers)
            if key is None:
                return await self._reject(send, 401, "missing API key")
            if self.auth.grant_for(key) is None:
                return await self._reject(send, 403, "unknown, expired, or disabled API key")
        await self.app(scope, receive, send)

    @staticmethod
    async def _reject(send, status: int, detail: str) -> None:
        import json
        body = json.dumps({"detail": detail}).encode()
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})

mcp = MCPServer(
    "loom",
    instructions=(
        "Loom is a provenance-tracked context engine. Start with "
        "list_namespaces and describe_namespace to learn what data exists "
        "(entity types, predicates, and which relations to expand). Use "
        "find_entity to turn names into 'type:key' handles (find_related when "
        "you only know what you're looking for, not its name), ask/ask_scope "
        "for budgeted cited context (start small — expand pulls threads deeper "
        "via handles; multi-hop questions are ask_scope with "
        "expand_predicates), record_claim to write back facts you learn, and "
        "answer for a server-side LLM synthesis when one is configured. Pass "
        "the same namespace on every call. Conflict items mean sources "
        "disagree — never resolve them silently."
    ),
)

_store: GraphStore | None = None


def _get_store() -> GraphStore:
    global _store
    if _store is None:
        _store = store_from_env()
    return _store


def configure(store: GraphStore, auth: AuthConfig | None = None,
              transport: str = "stdio") -> None:
    """Inject a store (tests); optionally an auth config + transport so the
    tool-level gates can be exercised without a network."""
    global _store, _auth, _transport
    _store = store
    _auth = auth
    _transport = transport


_SUBJECTS_SHOWN = 20


def _agent_view(pack) -> dict:
    """A ContextPack as an agent should read it: items first, no null
    citation fields, and the reached-subject list summarized. The HTTP
    contract is unchanged; this is presentation. On a 1,077-entity scope
    the full pack was 69k chars of which 3.7k was fact text, and the subject
    list came before the items (D-036)."""
    d = pack.model_dump(mode="json", exclude_none=True)
    subjects = d.get("subjects", [])
    view = {
        "namespace": d.get("namespace"), "question": d.get("question"),
        "budget": d.get("budget"), "items": d.get("items", []),
        "handles": d.get("handles", []), "omitted_handles": d.get("omitted_handles", 0),
        "subjects_total": len(subjects),
        "subjects": subjects[:_SUBJECTS_SHOWN],
    }
    if len(subjects) > _SUBJECTS_SHOWN:
        view["subjects_note"] = (f"{len(subjects) - _SUBJECTS_SHOWN} more reached entities not listed; "
                                 "the items above already cover the ones relevant to the question")
    for key in ("subject", "as_of", "valid_at"):
        if d.get(key) is not None:
            view[key] = d[key]
    if d.get("truncated"):
        view["truncated"] = d["truncated"]
        view["coverage_warning"] = "; ".join(
            f"{t['entity']['type']}:{t['entity']['key']}: only the newest {t['gathered']:,} of "
            f"{t['total']:,} observations were examined"
            for t in d["truncated"]
        ) + " — do not conclude that something is absent for these entities; ask about them directly, narrow with valid_at, or expand a handle"
    return view


def _parse_ref(handle: str) -> EntityRef:
    etype, sep, key = handle.partition(":")
    if not sep or not etype or not key:
        raise ValueError(
            f"entity handle must be 'type:key' (e.g. 'host:web-01'), got {handle!r}"
        )
    return EntityRef(type=etype, key=key)


def _parse_time(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _known_namespace(namespace: str) -> None:
    """A query against a namespace that holds nothing is almost always a
    dropped argument, not an empty answer — say so, and say what exists."""
    summary = _get_store().namespace_summary()
    if namespace not in summary and _get_store().get_schema(namespace) is None:
        known = ", ".join(sorted(summary)) or "none yet"
        raise ValueError(f"namespace {namespace!r} holds no data; namespaces with data: {known}"
                         " — pass namespace=... on every call")


# ------------------------------------------------------------------- tools #

def list_namespaces(ctx: Context = None) -> list[dict]:
    """The namespaces this Loom holds, with entity counts by type — call this
    first when you don't know where the data lives."""
    return [{"namespace": ns, "entities": types, "total": sum(types.values())}
            for ns, types in sorted(_get_store().namespace_summary().items())]


def describe_namespace(namespace: str = _DEFAULT_NS, ctx: Context = None) -> dict:
    """What a namespace contains and how it is connected: entity types with
    counts, and the registered predicates (description, allowed object types,
    whether scopes follow it by default). Read this before choosing
    expand_predicates for a multi-hop ask_scope."""
    _grant(ctx, namespace, "r")
    _known_namespace(namespace)
    store = _get_store()
    schema = store.get_schema(namespace)
    counts = store.namespace_summary().get(namespace, {})
    return {
        "namespace": namespace,
        "entity_types": [
            {"name": t, "count": n,
             "description": next((e.description for e in (schema.entity_types if schema else [])
                                  if e.name == t), "")}
            for t, n in sorted(counts.items(), key=lambda kv: -kv[1])
        ],
        "predicates": [p.model_dump(mode="json") for p in (schema.predicates if schema else [])],
        "strict": bool(schema and schema.strict),
        "hint": "ask_scope(subjects=[...], expand_predicates=[...], depth=2) follows the named "
                "predicates in both directions: host -runs_software-> product <-affects- cve.",
    }


def find_entity(query: str, namespace: str = _DEFAULT_NS, limit: int = 10,
                ctx: Context = None) -> list[dict]:
    """Resolve a name or key fragment to entity handles. Returns matches as
    'type:key' handles usable with the other tools (exact match first)."""
    grant = _grant(ctx, namespace, "r")
    _known_namespace(namespace)
    return [
        {
            "handle": f"{e.type}:{e.key}",
            "type": e.type,
            "key": e.key,
            "provisional": e.provisional,
        }
        for e in _get_store().search_entities(namespace, query, limit=limit,
                                              types=_allowed(grant))
    ]


def find_related(question: str, namespace: str = _DEFAULT_NS, limit: int = 10,
                 ctx: Context = None) -> dict:
    """Entities related to a question by MEANING rather than by name
    ("what looks exploitable?", "who touched the finance systems?") — use
    when you don't know an entity's key. Each match cites the fact that
    matched. Needs the server to have an embedder configured."""
    grant = _grant(ctx, namespace, "r")
    embedder = _get_embedder()
    if embedder is None:
        return {"error": "no embedder configured on this Loom (set LOOM_EMBED_*);"
                         " use find_entity with a key fragment instead"}
    return semantic_search(_get_store(), namespace, embedder, question,
                           limit=limit, allowed_types=_allowed(grant)).model_dump(mode="json")


def ask(
    subject: str,
    question: str,
    budget: int = 800,
    namespace: str = _DEFAULT_NS,
    as_of: str | None = None,
    valid_at: str | None = None,
    ctx: Context = None,
) -> dict:
    """Question-scoped, token-budgeted, cited context about one entity.
    subject is a 'type:key' handle. Conflicting facts are flagged explicitly;
    'handles' in the result feed the expand tool for more detail. as_of
    (ISO timestamp) = what was KNOWN at that moment; valid_at = what was
    TRUE at that moment (e.g. which host held an IP during an incident)."""
    grant = _grant(ctx, namespace, "r")
    ref = _parse_ref(subject)
    _gate_type(grant, ref.type)
    _known_namespace(namespace)
    req = AskRequest(
        namespace=namespace,
        subject=ref,
        question=question,
        budget=budget,
        as_of=_parse_time(as_of),
        valid_at=_parse_time(valid_at),
    )
    return _agent_view(build_pack(
        _get_store(), req, embedder=_get_embedder(), allowed_types=_allowed(grant)))


def ask_scope(
    subjects: list[str],
    question: str,
    expand_predicates: list[str] | None = None,
    depth: int = 1,
    budget: int = 1200,
    namespace: str = _DEFAULT_NS,
    as_of: str | None = None,
    valid_at: str | None = None,
    ctx: Context = None,
) -> dict:
    """Context about SEVERAL entities at once — a set of hosts, or an anchor
    plus its contents ('domain:corp.local' expanded over ['member_of'] covers
    every member). subjects are 'type:key' handles; expand_predicates names
    the relations to follow outward (omit it to follow the namespace's
    registered containment predicates); depth bounds the traversal."""
    grant = _grant(ctx, namespace, "r")
    refs = [_parse_ref(s) for s in subjects]
    for ref in refs:
        _gate_type(grant, ref.type)
    _known_namespace(namespace)
    req = AskRequest(
        namespace=namespace,
        scope=ScopeSpec(subjects=refs, expand=expand_predicates or [], depth=depth),
        question=question,
        budget=budget,
        as_of=_parse_time(as_of),
        valid_at=_parse_time(valid_at),
    )
    return _agent_view(build_pack(
        _get_store(), req, embedder=_get_embedder(), allowed_types=_allowed(grant)))


def expand(handle: str, budget: int = 800, ctx: Context = None) -> dict:
    """Pull one thread deeper: pass an expansion handle id from a previous
    ask/ask_scope result (the `id` of an entry in its `handles` list) to
    fetch the observations it stands for."""
    try:
        meta = decode_handle(handle)
    except ValueError as exc:
        raise ValueError(f"{exc}: expand takes the `id` of an entry in a pack's `handles` list "
                         "(it starts with h1_ or h2_), not an observation id or an entity handle; "
                         "for more about an entity use ask, for a raw record use get_observations") from exc
    grant = _grant(ctx, meta["ns"], "r")
    _gate_type(grant, str(meta["subject"].get("type", "")))
    return _agent_view(expand_pack(_get_store(), handle, budget, allowed_types=_allowed(grant)))


def record_claim(
    subject: str,
    predicate: str,
    observed_at: str,
    source: str,
    object_ref: str | None = None,
    object_value: str | float | int | bool | None = None,
    confidence: float = 1.0,
    namespace: str = _DEFAULT_NS,
    valid_from: str | None = None,
    valid_to: str | None = None,
    ctx: Context = None,
) -> dict:
    """Write back a fact you learned. subject is 'type:key'; provide exactly
    one of object_ref (another 'type:key' entity — creates a graph edge) or
    object_value (a scalar like an OS name or port number). observed_at /
    valid_from / valid_to are ISO timestamps."""
    if (object_ref is None) == (object_value is None):
        raise ValueError("provide exactly one of object_ref or object_value")
    grant = _grant(ctx, namespace, "w")
    if grant is not None and not grant.allows_source(source):
        raise PermissionError(f"key {grant.id!r} may not write claims for source {source!r}")
    subj = _parse_ref(subject)
    _gate_type(grant, subj.type)
    obj: Any = _parse_ref(object_ref) if object_ref else object_value
    if isinstance(obj, EntityRef):
        _gate_type(grant, obj.type)
    claim = ClaimIn(
        namespace=namespace,
        subject=subj,
        predicate=predicate,
        object=obj,
        observed_at=datetime.fromisoformat(observed_at),
        valid_from=_parse_time(valid_from),
        valid_to=_parse_time(valid_to),
        source=source,
        confidence=confidence,
    )
    problem = validate_claim(_get_store().get_schema(namespace), claim)
    if problem is not None:
        raise ValueError(problem)
    obs = _get_store().record_claim(claim)
    return {"status": "recorded", "observation_id": obs.id}


def get_observations(
    subject: str, namespace: str = _DEFAULT_NS, limit: int = 50, ctx: Context = None
) -> dict:
    """Raw observations touching an entity (audit/debug — prefer ask for
    focused context)."""
    grant = _grant(ctx, namespace, "r")
    ref = _parse_ref(subject)
    _gate_type(grant, ref.type)
    observations = [
        o for o in _get_store().observations_for(namespace, ref, limit=limit)
        if grant is None or (
            grant.allows_entity_type(o.subject.type)
            and (not isinstance(o.object, EntityRef)
                 or grant.allows_entity_type(o.object.type)))
    ]
    return {
        "subject": subject,
        "count": len(observations),
        "observations": [o.model_dump(mode="json") for o in observations],
    }


def answer(
    question: str,
    subject: str | None = None,
    budget: int = 1200,
    namespace: str = _DEFAULT_NS,
    valid_at: str | None = None,
    ctx: Context = None,
) -> dict:
    """Retrieval-grounded LLM answer with citations. Entities named verbatim
    in the question are auto-resolved when subject is omitted. Requires the
    server to have LOOM_LLM_* configured; use ask when it isn't."""
    grant = _grant(ctx, namespace, "r")
    if subject:
        _gate_type(grant, _parse_ref(subject).type)
    llm = _get_llm()
    if llm is None:
        return {
            "error": "no LLM configured on this Loom (set LOOM_LLM_MODEL plus "
            "LOOM_LLM_PROVIDER or LOOM_LLM_BASE_URL); use the ask tool instead"
        }
    req = AnswerRequest(
        namespace=namespace,
        question=question,
        subject=_parse_ref(subject) if subject else None,
        budget=budget,
        valid_at=_parse_time(valid_at),
    )
    try:
        resp = build_answer(_get_store(), llm, req, embedder=_get_embedder(),
                            allowed_types=_allowed(grant))
    except UnresolvedQuestionError as exc:
        return {"error": str(exc)}
    except LLMError as exc:
        return {"error": f"provider error: {exc.public}"}
    return {
        "answer": resp.answer,
        "model": resp.model,
        "pack": _agent_view(resp.pack),
    }


TOOLS = (
    list_namespaces,
    describe_namespace,
    find_entity,
    find_related,
    ask,
    ask_scope,
    expand,
    record_claim,
    get_observations,
    answer,
)
def _surface_errors(fn):
    """The SDK reports unexpected exceptions as an opaque 'Error executing
    tool'; an agent needs the actual reason (bad handle, scope refusal,
    provider down) to recover. Wrap our expected failures as ToolError so
    the message reaches the client verbatim."""
    import functools

    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (ValueError, PermissionError, LLMError) as exc:
            raise ToolError(str(exc)) from exc

    return wrapped


for _fn in TOOLS:
    mcp.tool(name=_fn.__name__)(_surface_errors(_fn))


def main() -> None:
    parser = argparse.ArgumentParser(prog="loom.mcp_server", description=__doc__)
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http", "sse"],
        default="stdio",
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8300)
    args = parser.parse_args()
    global _transport
    _transport = args.transport
    if args.transport == "stdio":
        mcp.run(transport="stdio")
        return
    import logging
    import uvicorn
    auth = _get_auth()
    if not auth.enabled:
        logging.getLogger("loom.mcp").warning(
            "no LOOM_AUTH_FILE / LOOM_API_KEYS — MCP %s transport is OPEN; every "
            "connected agent gets full access", args.transport)
    app = (mcp.streamable_http_app(host=args.host) if args.transport == "streamable-http"
           else mcp.sse_app(host=args.host))
    uvicorn.run(KeyGate(app, auth), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
