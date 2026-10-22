"""The MCP surface (phase 3, decision D-006): agents plug in natively.

Wraps the same core functions the HTTP API uses — no separate logic, no
drift. Entity handles are "type:key" strings ("host:web-01") for agent
ergonomics.

Register with Claude Code (stdio, spawned per session):

    claude mcp add loomctx -- docker compose run --rm -T loomctx \
        python -m loomctx.mcp_server

Or serve remote agents over streamable HTTP (compose profile `mcp`):

    docker compose --profile mcp up -d mcp     # -> :8300/mcp

Auth (H-A9, D-024): stdio is local trust — the agent that spawned the
process already owns the data. The HTTP transports authenticate like the
REST API: every request must carry `X-LoomCtx-Key` / `Authorization: Bearer`
when LOOMCTX_AUTH_FILE / LOOMCTX_API_KEYS is set (an ASGI gate rejects the rest
before MCP sees them), and every tool call applies the key's namespace,
perms, entity-type and source gates exactly as the HTTP routes do. In
front of that, the engine's Host allowlist and foreign-Origin refusal
(LOOMCTX_ALLOWED_HOSTS / LOOMCTX_ALLOWED_ORIGINS, D-059) stop a browser page from
driving an open MCP server by DNS rebinding, and the engine's LOOMCTX_RATE_*
dials and per-key overrides apply per tool call (`answer` and
`find_related` also spend the LLM bucket).

MCP 2026-07-28 alignment (R-7): every tool publishes an `outputSchema`
derived from the contract models and returns `structuredContent` next to
the text mirror; every tool carries a title and annotations (read-only /
idempotent / closed-world hints); the pack tools take `format`.

Requires the `mcp` extra (installed in the image).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import threading
import time
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal, NotRequired, TypedDict

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field, RootModel

try:  # the SDK moved the wire types into their own package in 2.x
    from mcp_types import CallToolResult, TextContent, ToolAnnotations
except ImportError:  # pragma: no cover - older SDK layout
    from mcp.types import CallToolResult, TextContent, ToolAnnotations

from .answer import UnresolvedQuestionError, build_answer
from .auth import AuthConfig, Grant, extract_key
from .context import (build_pack, cite_text, decode_handle, expand_pack, find_paths,
                     label_predicates, search_by_name, semantic_search)
from .contracts import (DEFAULT_PATH_DEPTH, AnswerRequest, AskRequest, ClaimIn, EntityRef,
                        ExpansionHandle,
                        ListFilter, ListRequest, Observation, PathRequest, PredicateDef, QueryRequest,
                        ScopeSpec,
                        ScopeTruncation,
                        SemanticSearchResponse)
from .gates import check_supersedes, scope_counts, scope_schema
from .listing import list_entities as list_entities_impl
from .llm import LLMError, embedder_from_env, llm_from_env
from .queries import find_query
from .queries import resolve as resolve_query
from .queries import run_query as run_query_impl
from .metrics import REJECTED
from .ratelimit import LimiterPool, RateLimitSettings
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
_DEFAULT_NS = os.environ.get("LOOMCTX_MCP_NAMESPACE", "").strip() or "default"
# Named queries on the MCP surface (D-108): on by default. LOOMCTX_MCP_QUERIES=0
# hides run_query and the `queries` describe_namespace lists — how a run is
# measured with and without them.
_QUERIES_ON = os.environ.get("LOOMCTX_MCP_QUERIES", "1").strip().lower() not in ("0", "false", "no", "off")
# record_claim on the MCP surface: on by default. LOOMCTX_MCP_WRITES=0 hides
# it, so agents can only read. A scorecard sets it: in the 2026-10-14 run,
# agents sharing one Postgres store wrote two claims that changed what every
# later agent's describe_namespace said.
_WRITES_ON = os.environ.get("LOOMCTX_MCP_WRITES", "1").strip().lower() not in ("0", "false", "no", "off")

Format = Literal["concise", "detailed"]


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

def _caller(ctx) -> Grant | None:
    """The caller's grant, or None when no gate applies (stdio transport,
    or auth disabled). Raises PermissionError — which the MCP layer returns
    to the agent as a tool error — when the key is missing or unknown.
    Every tool call on an HTTP transport also spends one token of the
    caller's general rate bucket (D-059)."""
    if _transport == "stdio":
        return None
    auth = _get_auth()
    grant = None
    if auth.enabled:
        headers = getattr(ctx, "headers", None) if ctx is not None else None
        key = extract_key(headers or {})
        grant = auth.grant_for(key)
        if grant is None:
            raise PermissionError("missing or unknown API key: send X-LoomCtx-Key "
                                  "(or Authorization: Bearer) on every request")
    _throttle(ctx, grant)
    return grant


# ------------------------------------------------------------ rate limits #
# The engine's LOOMCTX_RATE_* dials and per-key overrides (R-10), applied per
# tool call on the HTTP transports: one general token per call, plus one
# from the stricter LLM bucket for the tools that spend LLM / embedder
# budget (answer, find_related) — the same split as /v1/answer and
# /v1/entities/semantic. stdio is local trust and is not limited. Buckets
# are per process, like the engine's.

_limits: tuple[RateLimitSettings, LimiterPool, LimiterPool] | None = None


def _get_limits() -> tuple[RateLimitSettings, LimiterPool, LimiterPool]:
    global _limits
    if _limits is None:
        _limits = (RateLimitSettings.from_env(), LimiterPool(), LimiterPool())
    return _limits


def _principal(ctx, grant: Grant | None) -> str:
    """The grant id; in open mode the client IP (as on the engine)."""
    if grant is not None:
        return grant.id
    request = getattr(getattr(ctx, "_request_context", None), "request", None)
    client = getattr(request, "client", None)
    return getattr(client, "host", None) or "unknown"


def _throttle(ctx, grant: Grant | None, llm: bool = False) -> None:
    if _transport == "stdio":
        return
    settings, general, llm_pool = _get_limits()
    key = _principal(ctx, grant)
    checks = [(general, settings.general(grant))]
    if llm:
        checks = [(llm_pool, settings.llm(grant))]   # the general token was taken in _caller
    for pool, limit in checks:
        if limit is None:
            continue
        allowed, retry = pool.allow(key, limit)
        if not allowed:
            REJECTED.labels(reason="rate").inc()
            raise ToolError(f"rate limit exceeded; retry in {retry}s")


def _grant(ctx, namespace: str, action: str) -> Grant | None:
    """`_caller` plus the namespace/action check."""
    grant = _caller(ctx)
    if grant is not None and not grant.allows(namespace, action):
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
            headers = {k.decode("latin-1").lower(): v.decode("latin-1")   # never a 500 on odd bytes
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


# The budget of a scope ask, re-derived from measurement (D-064). The old
# hint (1500) dates from before D-058, when a pack was 2.2-3.6x its budget
# on the wire and a 4000-token ask_scope spilled out of Claude Code's inline
# tool-result limit. The concise view is now ~1.0x its charged budget plus
# a fixed envelope (question echo, 20 subjects, coverage notes).
# web-01's two-hop exposure pack on the 600k-observation corpus (cl100k,
# the whole concise wire): budget 1500 -> 2,070 tokens, 17/32 KEV CVEs;
# 3000 -> 3,707, 32/32; 4000 -> 4,738; 6000 -> 6,738. The answer (~30
# items with the edges that reached them) needs ~3000, so that is the
# default. The ceiling keeps >= 3x headroom under Claude Code's default
# MAX_MCP_OUTPUT_TOKENS (25,000): the worst concise wire is ~1.15x the
# budget (tests/test_quality.py q10b) plus an envelope under 1,000 tokens,
# so 4000 -> <= 5,600 (4.5x headroom); 6000 would leave 3.2x on the
# measured corpus and less on a long question. tests/test_scope.py
# measures the synthetic-hub equivalent at 1500/3000/4000/6000.
SCOPE_BUDGET_DEFAULT = 3000
SCOPE_BUDGET_HINT = 4000
SCOPE_DEPTH_CAP = next(m.le for m in ScopeSpec.model_fields["depth"].metadata
                       if getattr(m, "le", None) is not None)       # the contract's own cap (3)

INSTRUCTIONS = (
    "LoomCtx is a provenance-tracked context engine. Start with "
    "list_namespaces and describe_namespace to learn what data exists "
    "(entity types, predicates, and which relations to expand). Use "
    "find_entity to turn names into 'type:key' handles — a key, or a name "
    "the entity carries (a group's or account's name, login, UPN), so an "
    "opaque key such as a SID is found by its name (find_related when "
    "you only know what you're looking for, not its name). ask = budgeted, "
    "cited context about ONE entity; ask_scope = several entities and/or "
    "relation hops (multi-hop questions are ask_scope with "
    "expand_predicates: chain the `links` describe_namespace lists per "
    "type, and name the attribute the answer turns on as well). A pack's "
    "`notes` say what it could not do as asked (an unknown predicate, with "
    "the closest known ones), and a `coverage:` note says what an import did "
    "not collect: report that as not collected (citing the note's id), never "
    "as none. Expand pulls a thread deeper via the "
    f"handles a pack returns. ask_scope's default budget ({SCOPE_BUDGET_DEFAULT}) "
    "carries ~30 facts with the links that reached them; keep it at "
    f"budget<={SCOPE_BUDGET_HINT} and expand handles for more — a bigger "
    "pack overflows client tool-result limits. find_path returns the edge "
    "sequence(s) that connect two entities along named predicates "
    "(reachability: host->product->cve, user->group->domain), each hop "
    "cited — it reports the paths that exist, it does not rank them. "
    "list_entities returns EVERY entity matching conditions with an exact "
    "count (a group's nested members that are enabled, computers with a "
    "flag set) — use it when the answer is a set, not a ranked pack. "
    "describe_namespace lists a namespace's named `queries` (questions it "
    "answers exactly); run one with run_query(name, params). "
    "purple_report sets a red-team operation's logged actions against the "
    "detections on the same hosts (detected / host_only / missed). Every "
    "pack tool takes format='concise' (default: "
    "12-hex `cite` tokens, subjects summarized) or 'detailed' (full 32-hex "
    "observation ids next to each cite, every reached subject listed). "
    "Cite facts by their 12-hex `cite` token (the first word of each entry "
    "in an item's `cites`). A pack's "
    "`truncated` list names entities whose observations were only partly "
    "examined — never conclude absence about those. Conflict items mean "
    "sources disagree — never resolve them silently; record_claim writes "
    "back facts you learn, and record_claim(supersedes=<cite>) records a "
    "correction of an earlier observation (recorded, never inferred). "
    "answer gives a server-side LLM synthesis when one is configured. Pass "
    "the same namespace on every call."
)

mcp = MCPServer("loomctx", instructions=INSTRUCTIONS)

_store: GraphStore | None = None


_store_lock = threading.Lock()


def _get_store() -> GraphStore:
    global _store
    if _store is None:
        with _store_lock:   # the start-up warm-up and a first tool call race here
            if _store is None:
                _store = store_from_env()
    return _store


def configure(store: GraphStore, auth: AuthConfig | None = None,
              transport: str = "stdio") -> None:
    """Inject a store (tests); optionally an auth config + transport so the
    tool-level gates can be exercised without a network."""
    global _store, _auth, _transport, _summary_cache, _limits
    _store = store
    _auth = auth
    _transport = transport
    _summary_cache = None
    _relations_cache.clear()
    _limits = None   # re-read the LOOMCTX_RATE_* dials


# namespace_summary() is a GROUP BY over every entity; every tool call ran
# it (twice for describe_namespace). Cached briefly — a namespace that
# appeared five seconds ago is not what an orienting agent is waiting on.
_SUMMARY_TTL = 5.0
_summary_cache: tuple[float, dict[str, dict[str, int]]] | None = None


def _summary() -> dict[str, dict[str, int]]:
    global _summary_cache
    now = time.monotonic()
    if _summary_cache is None or _summary_cache[0] <= now:
        _summary_cache = (now + _SUMMARY_TTL, _get_store().namespace_summary())
    return _summary_cache[1]


_SUBJECTS_SHOWN = 20
_CITE = re.compile(r"^[0-9a-f]{12}$")
_OBS_ID = re.compile(r"^[0-9a-f]{32}$")


def _observation_by_cite(namespace: str, token: str):
    """An observation from its `cite` token (12 hex, what packs show) or its
    full 32-hex id. Prefix resolution needs the store's
    `observations_by_prefix`; without it only full ids resolve."""
    store = _get_store()
    if _OBS_ID.match(token):
        found = store.observations_by_ids(namespace, [token])
    elif _CITE.match(token):
        by_prefix = getattr(store, "observations_by_prefix", None)
        if by_prefix is None:
            raise ToolError(f"{token!r} is a cite token; this LoomCtx's store resolves only full "
                            "32-hex observation ids — cite by the full id or ask about the "
                            "entity instead")
        found = list(by_prefix(namespace, token))
    else:
        return None
    if not found:
        raise ToolError(f"no observation {token!r} in namespace {namespace!r}")
    if len(found) > 1:
        raise ToolError(f"cite {token!r} is ambiguous in namespace {namespace!r}; "
                        "use the full observation id")
    return found[0]


# ----------------------------------------------------------- output shapes #
# Each tool's return annotation is what the SDK derives its `outputSchema`
# from and validates `structuredContent` against. Pack tools return the
# *agent view* — a presentation of the ContextPack contract (D-036/D-041),
# not a second contract: the HTTP surface still serializes ContextPack.
# TypedDicts keep the runtime values plain dicts (direct callers and tests
# index them) while the SDK gets a schema; nested contract models
# (EntityRef, ExpansionHandle, ScopeTruncation, Observation, PredicateDef)
# are the contract's own.

class AgentCitation(TypedDict):
    """A compact citation: `cite` (12 hex) stands for the observation or
    artifact; format='detailed' adds the full observation_id."""
    cite: str
    source: str
    observed_at: datetime
    observation_id: NotRequired[str]
    artifact_id: NotRequired[str]
    span_start: NotRequired[int]
    span_end: NotRequired[int]


class AgentItem(TypedDict):
    """format='concise': `cites` holds one compact string per citation —
    "<cite> <source> <date>", the 12-hex cite token first (an excerpt:
    "<artifact_id> @<span> <source> <date>") — the form the pack's budget
    charges (D-058). format='detailed' carries the ranking `score` and full
    `citations` objects instead, for auditing; it is not budget-sized."""
    kind: Literal["brief", "fact", "relation", "doc_excerpt", "conflict"]
    text: str
    cites: NotRequired[list[str]]
    score: NotRequired[float]
    citations: NotRequired[list[AgentCitation]]


class AgentPack(TypedDict):
    """A ContextPack as an agent reads it (items first, compact citations,
    reached subjects summarized unless format='detailed'). charged_tokens
    is what the pack charged against `budget` (D-051); in the concise
    format it is sized to what this view carries (D-058)."""
    namespace: str
    question: str | None
    budget: int
    charged_tokens: int
    format: Format
    items: list[AgentItem]
    handles: list[ExpansionHandle]
    omitted_handles: int
    subjects_total: int
    subjects: list[EntityRef]
    subjects_note: NotRequired[str]
    subject: NotRequired[EntityRef]
    as_of: NotRequired[datetime]
    valid_at: NotRequired[datetime]
    truncated: NotRequired[list[ScopeTruncation]]
    coverage_warning: NotRequired[str]
    withheld_briefs: NotRequired[int]
    notes: NotRequired[list[str]]


class AgentPathEdge(TypedDict):
    """One hop of a path in the concise view: the edge as stored
    (`subject predicate object`) and its compact citation (12-hex cite token,
    source, date). format='detailed' carries the full PathEdge instead."""
    text: str
    cite: str


class AgentPath(TypedDict):
    """A path an agent reads: the traversal rendered `A -pred-> B -pred-> C`
    and one compact citation per hop (D-067); format='detailed' adds the full
    PathEdge objects as `edges`."""
    text: str
    hops: int
    cites: list[str]
    edges: NotRequired[list[dict[str, Any]]]


# A PathPack as an agent reads it: connecting paths shortest-first, each an
# arrow string with per-hop cites; `truncated`/coverage_warning say what the
# search could not fully return, `notes` carry request advice. It reports
# paths that EXIST — no ranking, scoring, or exploitability. Functional
# TypedDict because 'from' (the start entity) is a Python keyword (D-067).
class AgentNodeStatus(TypedDict):
    """A status fact about an entity a path passes through (D-080): e.g.
    `user:x` `enabled` = False — the path is still returned, and flagged."""
    entity: str
    predicate: str
    value: Any
    cite: str


PathView = TypedDict("PathView", {
    "namespace": str,
    "from": EntityRef,
    "to": EntityRef,
    "charged_tokens": int,
    "format": Format,
    "paths": list[AgentPath],
    "node_status": NotRequired[list[AgentNodeStatus]],
    "notes": NotRequired[list[str]],
    "truncated": NotRequired[list[ScopeTruncation]],
    "coverage_warning": NotRequired[str],
})


class AgentRoute(TypedDict):
    text: str
    cites: list[str]


class AgentListRow(TypedDict):
    """One listed entity: its handle, display name, the current values the
    listing filtered on or was asked for, how far it is from `of` (`hops`,
    and `through` the entity one step closer), and the cite tokens backing
    them."""
    entity: str
    name: NotRequired[str]
    values: NotRequired[dict[str, Any]]
    hops: NotRequired[int]
    through: NotRequired[str]
    path: NotRequired[AgentRoute]
    cites: list[str]


class ListView(TypedDict):
    """A page of list_entities (D-107): `total` is every match, exact unless
    `exact` is false; continue with `next_offset`."""
    namespace: str
    total: int
    exact: bool
    offset: int
    next_offset: NotRequired[int]
    charged_tokens: int
    rows: list[AgentListRow]
    notes: NotRequired[list[str]]


class ObservationList(TypedDict):
    """Raw observations (audit view), or the single observation a cite
    token / observation id names."""
    subject: NotRequired[str]
    namespace: NotRequired[str]
    count: int
    observations: list[Observation]


class ExpandResult(RootModel[AgentPack | ObservationList]):
    """expand returns a pack for an expansion handle, or the one
    observation a cite token / observation id names."""

    @classmethod
    def __get_pydantic_json_schema__(cls, core_schema, handler):
        # an outputSchema must be an object schema at the top level; both
        # arms are objects, so saying so next to the anyOf is exact
        schema = handler(core_schema)
        handler.resolve_ref_schema(schema)["type"] = "object"
        return schema


class NamespaceInfo(TypedDict):
    namespace: str
    entities: dict[str, int]
    total: int


class EntityTypeCount(TypedDict):
    """An entity type and how it connects (D-064): `links` are the
    predicates that leave it (`-runs_software-> product`) and arrive at it
    (`<-affects- cve`) with the type at the other end, most used first;
    `attributes` are the predicates it carries with values. Chaining a
    type's links through the next type's is how a multi-hop ask_scope is
    planned."""
    name: str
    count: int
    description: str
    links: NotRequired[list[str]]
    attributes: NotRequired[list[str]]


class AgentQuery(TypedDict):
    """A named query the namespace answers exactly (D-108): run it with
    run_query(name, params)."""
    name: str
    description: str
    params: list[str]


class NamespaceDescription(TypedDict):
    namespace: str
    entity_types: list[EntityTypeCount]
    predicates: list[PredicateDef]
    strict: bool
    hint: str
    queries: NotRequired[list[AgentQuery]]
    not_collected: NotRequired[list[dict[str, str]]]


class EntityMatch(TypedDict):
    handle: str
    type: str
    key: str
    provisional: bool
    name: NotRequired[str]      # the label value it was found by (D-091): an opaque key's name


class RecordClaimResult(TypedDict):
    status: Literal["recorded"]
    observation_id: str
    event_id: str
    supersedes: NotRequired[str]


class AnswerResult(TypedDict):
    answer: str
    model: str
    pack: AgentPack


def _agent_view(pack, fmt: Format = "concise") -> AgentPack:
    """A ContextPack as an agent should read it: items first, no null
    citation fields, and the reached-subject list summarized. The HTTP
    contract is unchanged; this is presentation. On a 1,077-entity scope
    the full pack was 69k chars of which 3.7k was fact text, and the subject
    list came before the items (D-036). format='detailed' keeps the 32-hex
    observation ids next to the cite tokens and lists every reached
    subject (auditing); 'concise' is what an agent carries in context."""
    if fmt not in ("concise", "detailed"):
        raise ValueError(f"format must be 'concise' or 'detailed', got {fmt!r}")
    detailed = fmt == "detailed"
    d = pack.model_dump(mode="json", exclude_none=True)
    # a 12-hex `cite` token per citation: two of 216 scorecard task-runs
    # mangled a hand-copied 32-hex id by one character (D-041); the
    # answer route already cites by this prefix. Concise items carry each
    # citation as one string, token first — the form the pack charges
    # (D-058): citation objects with ISO timestamps and a score per item
    # made an 800-token pack ~2,200 tokens on the MCP wire. Artifact
    # citations keep their full id, which excerpt handles and get_artifact
    # take. 'detailed' keeps the objects and the 32-hex observation ids.
    if detailed:
        for item in d.get("items", []):
            for c in item.get("citations", []):
                c["cite"] = (c.get("observation_id") or c.get("artifact_id") or "")[:12]
        items = d.get("items", [])
    else:
        items = [{"kind": i.kind, "text": i.text, "cites": [cite_text(c) for c in i.citations]}
                 for i in pack.items]
    subjects = d.get("subjects", [])
    shown = len(subjects) if detailed else _SUBJECTS_SHOWN
    view: dict[str, Any] = {
        "namespace": d.get("namespace"), "question": d.get("question"),
        "budget": d.get("budget"), "charged_tokens": d.get("charged_tokens", 0),
        "format": fmt, "items": items,
        "handles": d.get("handles", []), "omitted_handles": d.get("omitted_handles", 0),
        "subjects_total": len(subjects),
        "subjects": subjects[:shown],
    }
    if len(subjects) > shown:
        view["subjects_note"] = (f"{len(subjects) - shown} more reached entities not listed; "
                                 "the items above already cover the ones relevant to the question"
                                 " (format='detailed' lists them all)")
    for key in ("subject", "as_of", "valid_at"):
        if d.get(key) is not None:
            view[key] = d[key]
    if d.get("truncated"):
        view["truncated"] = d["truncated"]
        view["coverage_warning"] = "; ".join(
            f"the scope was cut at {t['gathered']:,} entities (at least {t['total']:,} reached, "
            f"stopped while expanding {t['entity']['type']}:{t['entity']['key']})"
            if t.get("reason") == "scope_cap" else
            f"{t['entity']['type']}:{t['entity']['key']}: only the newest {t['gathered']:,} of "
            f"{t['total']:,} observations were examined"
            for t in d["truncated"]
        ) + " — do not conclude that something is absent for these entities; ask about them directly, narrow with valid_at, or expand a handle"
    if d.get("withheld_briefs"):
        view["withheld_briefs"] = d["withheld_briefs"]
    if d.get("notes"):
        # right before the items: an ignored expand predicate or a subject
        # that names nothing is the first thing an agent must read (D-064)
        head = ("namespace", "question", "budget", "charged_tokens", "format")
        view = {**{k: view[k] for k in head}, "notes": d["notes"],
                **{k: v for k, v in view.items() if k not in head}}
    return view  # type: ignore[return-value]


def _parse_ref(handle: str) -> EntityRef:
    # a handle sent JSON-quoted ('"user:S-1-…"') is the same handle: a model
    # looped to the step cap on "entity not on record" for one (final A/B)
    handle = handle.strip().strip("\"'").strip()
    etype, sep, key = handle.partition(":")
    if not sep or not etype or not key:
        raise ValueError(
            f"entity handle must be 'type:key' (e.g. 'host:web-01'), got {handle!r}"
        )
    return EntityRef(type=etype, key=key)


def _parse_time(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _visible(grant: Grant | None, namespaces) -> list[str]:
    """The namespaces a caller may read — a scoped key must not learn the
    others' names from a listing or an error message."""
    return sorted(ns for ns in namespaces if grant is None or grant.allows(ns, "r"))


def _known_namespace(namespace: str, grant: Grant | None = None) -> None:
    """A query against a namespace that holds nothing is almost always a
    dropped argument, not an empty answer — say so, and say what exists
    (among the namespaces this caller may read)."""
    summary = _summary()
    if namespace not in summary and _get_store().get_schema(namespace) is None:
        visible = _visible(grant, summary)
        known = ", ".join(visible) or "none yet"
        # an entity's name passed as the namespace (namespace="corp.local"): say
        # where it lives — Gemini 2.5 Flash read the generic error as "the data
        # is not here" and gave up on five runs out of five (final A/B, 10k)
        for ns in visible:
            hit = next((e for e in _get_store().search_entities(ns, namespace, limit=3)
                        if e.key.lower() == namespace.lower()), None)
            if hit is not None and (grant is None or grant.entity_types is None or hit.type in grant.entity_types):
                raise ValueError(f"{namespace!r} is not a namespace: it is {hit.type}:{hit.key} in namespace "
                                 f"{ns!r} — call again with namespace={ns!r}")
        raise ValueError(f"namespace {namespace!r} holds no data; namespaces with data: {known}"
                         " — pass namespace=... on every call")


# ------------------------------------------------------------------- tools #

def list_namespaces(ctx: Context = None) -> list[NamespaceInfo]:
    """The namespaces this LoomCtx holds, with entity counts by type — call this
    first when you don't know where the data lives."""
    grant = _caller(ctx)
    summary = _summary()
    out: list[NamespaceInfo] = []
    for ns in _visible(grant, summary):
        counts = scope_counts(summary[ns], grant)   # a type-scoped key counts its own world
        out.append({"namespace": ns, "entities": counts, "total": sum(counts.values())})
    return out


def describe_namespace(namespace: str = _DEFAULT_NS, ctx: Context = None) -> NamespaceDescription:
    """What a namespace contains and how it is connected: entity types with
    counts, each with its links (predicates to and from other types:
    `-runs_software-> product`, `<-affects- cve`) and its attributes
    (predicates holding values), and the registered predicates
    (description, allowed object types, whether scopes follow it by
    default). Chain the links to plan expand_predicates for a multi-hop
    ask_scope; name the attribute the answer turns on too."""
    grant = _grant(ctx, namespace, "r")
    _known_namespace(namespace, grant)
    store = _get_store()
    schema = store.get_schema(namespace)
    if schema is not None:
        schema = scope_schema(schema, grant)
    counts = scope_counts(_summary().get(namespace, {}), grant)
    allowed = _allowed(grant)
    relations = [r for r in _relations(namespace)
                 if allowed is None or (r[0] in allowed and (r[2] is None or r[2] in allowed))]
    types = []
    for t, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        entry: EntityTypeCount = {
            "name": t, "count": n,
            "description": next((e.description for e in (schema.entity_types if schema else [])
                                 if e.name == t), "")}
        links = [f"-{p}-> {o}" if s == t else f"<-{p}- {s}"
                 for s, p, o, _ in relations if o is not None and t in (s, o)]
        attributes = [p for s, p, o, _ in relations if o is None and s == t]
        if links:
            entry["links"] = _capped(list(dict.fromkeys(links)), _LINKS_SHOWN)
        if attributes:
            entry["attributes"] = _capped(attributes, _ATTRIBUTES_SHOWN)
        types.append(entry)
    view: dict[str, Any] = {
        "namespace": namespace,
        "entity_types": types,
        "predicates": [p.model_dump(mode="json") for p in (schema.predicates if schema else [])],
        "strict": bool(schema and schema.strict),
        "hint": _path_hint(relations),
    }
    if schema is not None and schema.not_collected:
        view["not_collected"] = [{"topic": g.topic, "description": g.description} for g in schema.not_collected]
    if schema is not None and schema.queries and _QUERIES_ON:
        view["queries"] = [{"name": q.name, "description": q.description,
                            "params": [_param_text(p) for p in q.params]} for q in schema.queries]
    return view  # type: ignore[return-value]


def _param_text(p) -> str:
    """A query parameter as one line: `group (entity: group) — the group`."""
    kind = f"{p.kind}: {p.entity_type}" if p.entity_type else p.kind
    text = f"{p.name} ({kind}{'' if p.default is None else f', default {p.default!r}'})"
    return text + (f" — {p.description}" if p.description else "")


# describe_namespace counts against the agent's context: a type's links and
# attributes are listed most used first, to a cap (a corpus of extracted
# documents carries dozens of one-off predicates)
_LINKS_SHOWN = 8
_ATTRIBUTES_SHOWN = 10
_RELATIONS_TTL = 600.0  # a GROUP BY over the namespace's observations (~1-3 s at 600k+ rows); a map, not facts
_relations_lock = threading.Lock()
_relations_cache: dict[str, tuple[float, list[tuple[str, str, str | None, int]]]] = {}


def _relations(namespace: str) -> list[tuple[str, str, str | None, int]]:
    hit = _relations_cache.get(namespace)
    if hit is None or hit[0] <= time.monotonic():
        with _relations_lock:   # a call during the warm-up waits for it, not a second GROUP BY
            hit = _relations_cache.get(namespace)
            if hit is None or hit[0] <= time.monotonic():
                summary = _get_store().relation_summary(namespace)
                hit = _relations_cache[namespace] = (time.monotonic() + _RELATIONS_TTL, summary)
    return hit[1]


def _warm() -> None:
    """Compute what describe_namespace reads while the agent's first model
    turn runs (D-102): a stdio server starts per session, and its first
    describe_namespace paid the namespace's GROUP BY (~3 s on the scorecard
    corpus) every time. Failures are left to the tool call to report."""
    try:
        _summary()
        _relations(_DEFAULT_NS)
    except Exception:  # noqa: BLE001 — a warm-up never takes the server down
        pass


def _capped(values: list[str], cap: int) -> list[str]:
    return values if len(values) <= cap else values[:cap] + [f"+{len(values) - cap} more"]


def _path_hint(relations: list[tuple[str, str, str | None, int]]) -> str:
    """How to ask a multi-hop question, with the two-hop paths this
    namespace actually has: the best-populated of each shape (A -p-> B
    <-q- C and A -p-> B -q-> C), starting from the rarer type — the one an
    agent anchors on."""
    edges = [(s, p, o, n) for s, p, o, n in relations if o is not None]
    best: dict[str, tuple[tuple[int, int, int], str, list[str]]] = {}
    for s1, p1, o1, n1 in edges:
        for s2, p2, o2, n2 in edges:
            if p2 == p1 or s1 == o1:
                continue
            if o2 == o1 and s2 != o1:
                shape, text = "in", f"{s1} -{p1}-> {o1} <-{p2}- {s2}"
            elif s2 == o1 and o2 != o1:
                shape, text = "out", f"{s1} -{p1}-> {o1} -{p2}-> {o2}"
            else:
                continue
            rank = (min(n1, n2), n1 + n2, -n1)
            if shape not in best or rank > best[shape][0]:
                best[shape] = (rank, text, [p1, p2])
    examples = "; ".join(f"{text} is expand_predicates={expand}, depth=2"
                         for _, text, expand in (best[k] for k in ("in", "out") if k in best))
    return ("ask_scope(subjects=[...], expand_predicates=[...], depth=N) follows the named links in "
            "both directions, N hops from the subjects; chain the entity types' `links` to choose "
            f"them.{f' In this namespace: {examples}.' if examples else ''} An attribute the answer "
            "turns on (a type's `attributes`) may be named in expand_predicates too: it becomes the "
            "pack's topic, not a link to walk.")


def find_entity(query: str, namespace: str = _DEFAULT_NS, limit: int = 10,
                ctx: Context = None) -> list[EntityMatch]:
    """Resolve a name or key fragment to entity handles: an entity's key, or
    a name it carries (a group's or account's name, sAMAccountName, UPN,
    login — whatever the namespace's schema marks as a label). Returns
    'type:key' handles usable with the other tools, exact matches first;
    `name` shows the name an opaque key (a SID, a GUID) was found by."""
    grant = _grant(ctx, namespace, "r")
    _known_namespace(namespace, grant)
    store = _get_store()
    labels = label_predicates(store, namespace)
    found, matched = search_by_name(store, namespace, query, limit=limit, types=_allowed(grant))
    names: dict[tuple[str, str], str] = {}
    # the name searched for, without the realm a retry appends ("Domain
    # Admins (corp.local)"): no label starts with that, and the pick fell to
    # whichever label row came back first — the DN on Postgres, the friendly
    # name on SQLite, for the same entity (2026-10-14 run)
    lowered = re.sub(r" \([^()]*\)$", "", matched).lower()
    by_name = [EntityRef(type=e.type, key=e.key) for e in found if not e.key.lower().startswith(lowered)]
    if by_name and labels:
        schema = store.get_schema(namespace)
        defs = schema.predicates if schema is not None else []
        order = {p: i for i, p in enumerate([d.name for d in defs if d.display]
                                            + [d.name for d in defs if d.label and not d.display])}
        rows = store.observations_for_many(namespace, by_name, limit=20, predicates=list(labels))
        for ref in by_name:
            obs = [o for o in rows.get((ref.type, ref.key), [])
                   if isinstance(o.object, str) and o.subject.key == ref.key]
            # whatever order the store returned the rows in: a label starting
            # with the name searched for, else the display label, then the
            # registry's order, then the shortest
            obs.sort(key=lambda o: (not str(o.object).lower().startswith(lowered),
                                    order.get(o.predicate, len(order)), len(str(o.object)), str(o.object)))
            if obs:
                names[(ref.type, ref.key)] = str(obs[0].object)
    return [
        {
            "handle": f"{e.type}:{e.key}",
            "type": e.type,
            "key": e.key,
            "provisional": e.provisional,
            **({"name": names[(e.type, e.key)]} if (e.type, e.key) in names else {}),
        }
        for e in found
    ]


def find_related(question: str, namespace: str = _DEFAULT_NS, limit: int = 10,
                 ctx: Context = None) -> SemanticSearchResponse:
    """Entities related to a question by MEANING rather than by name
    ("what looks exploitable?", "which campaigns hit web servers?") — use
    when you don't know an entity's key. Searches both facts and the
    passages of documents that claims cite; each match carries the fact or
    the passage that matched, cited. Needs the server to have an embedder
    configured."""
    grant = _grant(ctx, namespace, "r")
    embedder = _get_embedder()
    if embedder is None:
        raise ToolError("no embedder configured on this LoomCtx (set LOOMCTX_EMBED_*);"
                        " use find_entity with a name or key fragment instead")
    _known_namespace(namespace, grant)
    _throttle(ctx, grant, llm=True)   # embeds the question: the LLM bucket, as /v1/entities/semantic
    return semantic_search(_get_store(), namespace, embedder, question,
                           limit=limit, allowed_types=_allowed(grant))


def ask(
    subject: str,
    question: str,
    budget: int = 800,
    namespace: str = _DEFAULT_NS,
    as_of: str | None = None,
    valid_at: str | None = None,
    format: Format = "concise",
    ctx: Context = None,
) -> AgentPack:
    """Question-scoped, token-budgeted, cited context about ONE entity
    (for several entities, or relations to follow, use ask_scope instead).
    subject is a 'type:key' handle. Conflicting facts are flagged
    explicitly; 'handles' in the result feed the expand tool for more
    detail. as_of (ISO timestamp) = what was KNOWN at that moment;
    valid_at = what was TRUE at that moment (e.g. which host held an IP
    during an incident). format='concise' (default) gives 12-hex `cite`
    tokens; 'detailed' adds full observation ids for auditing."""
    grant = _grant(ctx, namespace, "r")
    ref = _parse_ref(subject)
    _gate_type(grant, ref.type)
    _known_namespace(namespace, grant)
    req = AskRequest(
        namespace=namespace,
        subject=ref,
        question=question,
        budget=budget,
        as_of=_parse_time(as_of),
        valid_at=_parse_time(valid_at),
    )
    return _agent_view(build_pack(
        _get_store(), req, embedder=_get_embedder(), allowed_types=_allowed(grant)), format)


def _listed(value: list[str] | str | None) -> list[str]:
    """A list argument, also when a model sends it as text: qwen3-coder
    passed expand_predicates="['runs_software']" on the D-064 smoke run,
    was refused twice by the schema, and fell back to one ask per product.
    JSON or Python-style list text (bracketed) is read as the list it
    spells. A bare string is ONE item — never comma-split: a key may hold
    commas (an LDAP DN, "user:CN=Bob,OU=Staff,DC=corp"), and splitting it
    asked about entities nobody named."""
    if value is None:
        return []
    if not isinstance(value, str):
        return list(value)
    text = value.strip()
    if not (text.startswith("[") and text.endswith("]")):
        return [text] if text else []
    import ast
    import json
    for parse in (json.loads, ast.literal_eval):
        try:
            parsed = parse(text)
        except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
            continue
        if isinstance(parsed, list) and all(isinstance(x, str) for x in parsed):
            return parsed
    # bracketed but unquoted ("[member_of, affects]"): clearly a list
    parts = (p.strip().strip("'\"").strip() for p in text.strip("[]").split(","))
    return [p for p in parts if p]


def ask_scope(
    subjects: list[str] | str,
    question: str = "",
    expand_predicates: list[str] | str | None = None,
    depth: int = 1,
    budget: int = SCOPE_BUDGET_DEFAULT,
    namespace: str = _DEFAULT_NS,
    as_of: str | None = None,
    valid_at: str | None = None,
    format: Format = "concise",
    siblings: bool = False,
    ctx: Context = None,
) -> AgentPack:
    """Context about SEVERAL entities at once and/or across RELATION HOPS
    (one entity, no hops: use ask). A set of hosts, or an anchor plus its
    contents ('domain:corp.local' expanded over ['member_of'] covers every
    member). subjects are 'type:key' handles; expand_predicates names the
    links to follow, in both directions (omit it to follow the namespace's
    registered containment predicates); depth bounds the hops. A walk does
    not turn back along the relation that reached an entity (from a user,
    member_of climbs to its groups, not down to every co-member) unless
    siblings=True. Chain the
    `links` describe_namespace lists per type: host has
    `-runs_software-> product`, product has `<-affects- cve`, so "which
    CVEs affect what host:web-01 runs" is expand_predicates=
    ['runs_software', 'affects'], depth=2. An attribute the answer turns
    on (a type's `attributes`, e.g. 'exploited_in_wild') may be named in
    expand_predicates too: it becomes the pack's topic. An unknown
    predicate is reported in `notes`, with the closest known ones. The
    default budget (3000) carries ~30 facts with their links; keep it at
    or under 4000 and expand handles for more — a larger pack overflows
    client tool-result limits. format as in ask; 'detailed' also lists
    every reached subject."""
    grant = _grant(ctx, namespace, "r")
    refs = [_parse_ref(s) for s in _listed(subjects)]
    for ref in refs:
        _gate_type(grant, ref.type)
    _known_namespace(namespace, grant)
    # a depth past the cap is walked to the cap and said so, not refused:
    # agents read a refusal as "cannot be done" and gave up (D-092)
    asked_depth, depth = depth, min(max(depth, 0), SCOPE_DEPTH_CAP)
    req = AskRequest(
        namespace=namespace,
        scope=ScopeSpec(subjects=refs, expand=_listed(expand_predicates), depth=depth,
                        siblings=siblings),
        question=question,
        budget=budget,
        as_of=_parse_time(as_of),
        valid_at=_parse_time(valid_at),
    )
    view = _agent_view(build_pack(
        _get_store(), req, embedder=_get_embedder(), allowed_types=_allowed(grant)), format)
    if asked_depth > SCOPE_DEPTH_CAP:
        view["notes"] = [f"depth {asked_depth} is above the cap of {SCOPE_DEPTH_CAP}: walked "
                         f"{SCOPE_DEPTH_CAP} hops; for a longer chain, ask_scope again from the "
                         "entities this one ends at", *view.get("notes", [])]
    return view


def _path_arrow(pack, edges) -> str:
    """One path rendered in traversal order: `from -pred-> B -pred-> to`. The
    edge is stored either way round; the arrow follows the walk from `from`,
    so the reader sees the reachability direction (D-067)."""
    cur = (pack.from_.type, pack.from_.key)
    parts = [f"{pack.from_.type}:{pack.from_.key}"]
    for edge in edges:
        a = (edge.subject.type, edge.subject.key)
        if isinstance(edge.object, EntityRef):
            b = (edge.object.type, edge.object.key)
        else:
            b = None
        nxt = b if (a == cur and b is not None) else a
        label = f"{nxt[0]}:{nxt[1]}" if isinstance(edge.object, EntityRef) else str(edge.object)
        parts.append(f"-{edge.predicate}-> {label}")
        cur = nxt if b is not None else cur
    return " ".join(parts)


def _path_view(pack, fmt: Format = "concise") -> PathView:
    """A PathPack as an agent should read it (D-067): each path an arrow
    string with one compact citation per hop; 'detailed' keeps full PathEdge
    objects. Presentation only — the HTTP surface serializes PathPack."""
    if fmt not in ("concise", "detailed"):
        raise ValueError(f"format must be 'concise' or 'detailed', got {fmt!r}")
    d = pack.model_dump(mode="json", by_alias=True, exclude_none=True)
    if fmt == "detailed":
        # cites too: the output schema requires them in either format, and a
        # detailed path without them failed validation (the tool errored)
        paths = [{"text": _path_arrow(pack, edges), "hops": len(edges),
                  "cites": [cite_text(e.cite) for e in edges], "edges": dp}
                 for edges, dp in zip(pack.paths, d.get("paths", []))]
    else:
        paths = [{"text": _path_arrow(pack, edges), "hops": len(edges),
                  "cites": [cite_text(e.cite) for e in edges]} for edges in pack.paths]
    view: dict[str, Any] = {
        "namespace": d.get("namespace"), "from": d.get("from"), "to": d.get("to"),
        "charged_tokens": d.get("charged_tokens", 0),
        "format": fmt, "paths": paths,
    }
    if pack.node_status:
        view["node_status"] = [{"entity": f"{n.entity.type}:{n.entity.key}",
                                "predicate": n.predicate, "value": n.value,
                                "cite": cite_text(n.cite)} for n in pack.node_status]
    if d.get("notes"):
        view = {"namespace": view["namespace"], "notes": d["notes"],
                **{k: v for k, v in view.items() if k != "namespace"}}
    if d.get("truncated"):
        view["truncated"] = d["truncated"]
        view["coverage_warning"] = "; ".join(
            f"more than {t['gathered']} connecting path(s) exist (at least {t['total']}); "
            "raise max_paths or budget" if t.get("reason") == "max_paths" else
            "the search stopped at the depth cap while more of the graph was unexplored"
            if t.get("reason") == "depth" else
            f"the walk was cut at {t['gathered']:,} entities while expanding "
            f"{t['entity']['type']}:{t['entity']['key']}" if t.get("reason") == "scope_cap" else
            f"{t['entity']['type']}:{t['entity']['key']}: only the newest {t['gathered']:,} of "
            f"{t['total']:,} observations were examined"
            for t in d["truncated"]
        ) + " — the paths shown are those found within these limits, not necessarily all that exist"
    return view  # type: ignore[return-value]


def find_path(
    from_: Annotated[str, Field(alias="from")],
    to: str,
    via: list[str] | str | None = None,
    depth: int = DEFAULT_PATH_DEPTH,
    max_paths: int = 8,
    budget: int = 2000,
    siblings: bool = False,
    namespace: str = _DEFAULT_NS,
    as_of: str | None = None,
    valid_at: str | None = None,
    format: Format = "concise",
    ctx: Context = None,
) -> PathView:
    """Enumerate the edge sequence(s) that CONNECT one entity to another along
    named relations — "what connects A to B?" (the KEV host -> product -> cve
    chain, the AD user -> group -> domain chain). `from` and `to` are
    'type:key' handles; `via` names the predicates to traverse, in both
    directions (omit it to follow the namespace's containment predicates);
    `depth` bounds the hops (default 4, capped at 6); `max_paths` bounds how
    many paths come back, shortest first. A path does not turn back along the
    same relation at an entity (user -member_of-> group <-member_of- admin is
    a shared group, not a route) unless siblings=True. `node_status` flags
    what each entity on a path is — a path through a disabled account is
    returned, with its `enabled` = False cited. Each hop is cited and
    time-scoped; as_of = what was KNOWN at T, valid_at = what was TRUE at T. This reports paths that
    EXIST in the data — it does NOT rank, score, or weight edges by
    exploitability. `notes` say what it could not do (an unknown `via`, an
    unknown endpoint); `truncated` says when more paths, more depth, or a
    larger scope was cut. Keep budget modest and raise max_paths for more.
    format='concise' (default) renders each path `A -pred-> B` with cites."""
    grant = _grant(ctx, namespace, "r")
    src, dst = _parse_ref(from_), _parse_ref(to)
    _gate_type(grant, src.type)
    _gate_type(grant, dst.type)
    _known_namespace(namespace, grant)
    req = PathRequest(
        namespace=namespace, **{"from": src}, to=dst,
        via=_listed(via), depth=depth, max_paths=max_paths, budget=budget, siblings=siblings,
        as_of=_parse_time(as_of), valid_at=_parse_time(valid_at),
    )
    return _path_view(find_paths(_get_store(), req, allowed_types=_allowed(grant)), format)


_FILTER_TEXT = re.compile(r"^\s*(!)?\s*([A-Za-z_][\w.-]*)\s*(?:(!=|~=|=)\s*(.*?)|(\?))?\s*$")


_WITHIN_TEXT = re.compile(r"^\s*([A-Za-z_][\w.-]*(?:\s*,\s*[A-Za-z_][\w.-]*)*)\s+(not\s+within|within)\s+"
                          r"(\S+?)(?:\s+depth\s*=?\s*(\d+))?\s*$",
                          re.I)


def _split_conditions(text: str) -> list[str]:
    """Conditions written as one string: ';', 'and', 'AND' or '&&' separate
    them (an uppercase AND was read as part of the value and the filter
    silently matched nothing, D-116), and commas do when no part holds a
    second '=' — a comma inside a value (an LDAP DN: CN=Bob,OU=Staff) is not
    a separator, nor is one between the predicates of a within filter."""
    out: list[str] = []
    for piece in re.split(r"\s*(?:;|&&|\band\b)\s*", text.strip(), flags=re.I):
        if _WITHIN_TEXT.match(piece):
            out.append(piece)
            continue
        parts = [p for p in re.split(r"\s*,\s*", piece) if p]
        out += parts if len(parts) > 1 and all(p.count("=") <= 1 for p in parts) else [piece]
    return [w for w in out if w]


def _filters(where) -> list[ListFilter]:
    """list_entities' `where`: objects {predicate, op, value}, or text an
    agent writes naturally — `enabled=false`, `is_dc!=true`, `name~=svc`
    (contains), `spn?` (has a value), `!spn` (has none); a JSON string of
    either is accepted too."""
    if where is None:
        return []
    if isinstance(where, str):
        text = where.strip()
        where = json.loads(text) if text.startswith(("[", "{")) else _split_conditions(text)
    if isinstance(where, dict):
        where = [where]
    # a list item can hold several conditions too: ["enabled=true AND spn?"]
    where = [piece for item in where
             for piece in (_split_conditions(item) if isinstance(item, str) else [item])]
    out: list[ListFilter] = []
    for item in where:
        if isinstance(item, dict):
            out.append(ListFilter.model_validate(item))
            continue
        w = _WITHIN_TEXT.match(str(item))
        if w is not None:
            pred, op, value, depth = w.groups()
            pred = ",".join(p.strip() for p in pred.split(","))
            out.append(ListFilter(predicate=pred, op="not_within" if op.lower().startswith("not") else "within",
                                  value=value.strip().strip("'\""), depth=int(depth) if depth else 6))
            continue
        m = _FILTER_TEXT.match(str(item))
        if m is None:
            raise ValueError(f"cannot read filter {item!r}: write predicate=value, predicate!=value, "
                             "predicate~=text, predicate?, !predicate or predicate within type:key")
        neg, pred, op, value, has = m.groups()
        if neg:
            out.append(ListFilter(predicate=pred, op="absent"))
        elif has or op is None:
            out.append(ListFilter(predicate=pred, op="exists"))
        else:
            value = value.strip().strip("'\"")
            out.append(ListFilter(predicate=pred, op={"=": "eq", "!=": "ne", "~=": "contains"}[op], value=value))
    return out


def _row_route(r) -> str:
    """A row's route as arrows from the entity, each edge as stored:
    `user:a -member_of-> group:g -has_ace-> computer:w`."""
    cur, parts = r.entity, [f"{r.entity.type}:{r.entity.key}"]
    for e in r.path:
        if (e.subject.type, e.subject.key) == (cur.type, cur.key):
            nxt, arrow = e.object, f"-{e.predicate}->"
        else:
            nxt, arrow = e.subject, f"<-{e.predicate}-"
        label = f"{nxt.type}:{nxt.key}" if isinstance(nxt, EntityRef) else str(nxt)
        parts.append(f"{arrow} {label}")
        cur = nxt if isinstance(nxt, EntityRef) else cur
    return " ".join(parts)


def _list_view(page) -> ListView:
    view: dict[str, Any] = {"namespace": page.namespace}
    if page.notes:
        view["notes"] = page.notes
    view.update(total=page.total, exact=page.exact, offset=page.offset, charged_tokens=page.charged_tokens)
    if page.next_offset is not None:
        view["next_offset"] = page.next_offset
    rows = []
    for r in page.rows:
        row: dict[str, Any] = {"entity": f"{r.entity.type}:{r.entity.key}"}
        if r.name:
            row["name"] = r.name
        if r.values:
            row["values"] = {k: (f"{v.type}:{v.key}" if isinstance(v, EntityRef) else v)
                             for k, v in r.values.items()}
        if r.hops is not None:
            row["hops"] = r.hops
        if r.through is not None:
            row["through"] = f"{r.through.type}:{r.through.key}"
        if r.path:
            row["path"] = {"text": _row_route(r), "cites": [cite_text(e.cite) for e in r.path]}
        row["cites"] = [cite_text(c) for c in r.cites]
        rows.append(row)
    view["rows"] = rows
    return view  # type: ignore[return-value]


def list_entities(
    type: str | None = None,
    of: str | None = None,
    via: list[str] | str | None = None,
    direction: Literal["in", "out", "any"] = "in",
    depth: int = 1,
    where: list[dict[str, Any] | str] | str | None = None,
    paths: bool = False,
    fields: list[str] | str | None = None,
    limit: int = 50,
    offset: int = 0,
    budget: int = 2000,
    namespace: str = _DEFAULT_NS,
    as_of: str | None = None,
    valid_at: str | None = None,
    ctx: Context = None,
) -> ListView:
    """List EVERY entity matching conditions, with an exact count — "which
    accounts are disabled?", "which members of Domain Admins (nested) are
    enabled?", "which computers allow unconstrained delegation and are not
    domain controllers?". Use it instead of ask/ask_scope when the answer is
    a set: a pack ranks what fits its budget, a listing returns all matches,
    paged. `type` keeps one entity type; `of` ('type:key') lists what is
    connected to that entity along `via` (direction 'in': entities whose
    edge points at it — a group's members; 'out': what it points at), up to
    `depth` hops (nested groups: depth 3-6). `where` filters on CURRENT
    values, all must hold: objects {predicate, op, value} with op eq / ne /
    in / contains / exists / absent / within / not_within, or text like
    "enabled=false", "is_dc!=true", "spn?", "member_of within group:<key>"
    (nested membership in that group, up to depth 6), or several edge
    predicates at once: "has_ace,member_of within computer:<key>" holds for
    every account with rights over that computer, directly or through its
    groups. Conditions join with ';' or AND. `ne` includes
    entities with no value recorded (a note counts them). `paths=true`
    gives each row of an `of` listing its cited route to `of` (an account
    reaching a machine through groups and ACL grants: via=["has_ace",
    "member_of"], direction="in"). `fields` adds predicates to show per
    row. Every row is cited; `total` counts all matches — page with
    `offset` / `next_offset`. Name filters by the predicates
    describe_namespace lists."""
    grant = _grant(ctx, namespace, "r")
    root = _parse_ref(of) if of else None
    if root is not None:
        _gate_type(grant, root.type)
    if type:
        _gate_type(grant, type)
    _known_namespace(namespace, grant)
    type = type.strip().strip("\"'").strip() if type else type
    req = ListRequest(
        namespace=namespace, type=type or None, of=root, via=_listed(via), direction=direction,
        depth=depth, where=_filters(where), paths=paths, fields=_listed(fields), limit=limit, offset=offset,
        budget=budget, as_of=_parse_time(as_of), valid_at=_parse_time(valid_at),
    )
    return _list_view(list_entities_impl(_get_store(), req, allowed_types=_allowed(grant)))


def run_query(
    name: str,
    params: dict[str, Any] | list[Any] | str | None = None,
    where: list[dict[str, Any] | str] | str | None = None,
    fields: list[str] | str | None = None,
    limit: int = 50,
    offset: int = 0,
    budget: int = 2000,
    namespace: str = _DEFAULT_NS,
    as_of: str | None = None,
    valid_at: str | None = None,
    ctx: Context = None,
) -> ListView:
    """Run one of the namespace's NAMED QUERIES — questions it answers
    exactly, listed under `queries` by describe_namespace (an AD namespace:
    effective_members(group), account_groups(account),
    unconstrained_delegation_hosts, domain_trusts, …). `params` maps each
    parameter to its value; an entity parameter takes a 'type:key' handle or
    a name. `where` and `fields` add conditions and columns to the query's
    own, written as list_entities takes them: enabled_members of Domain
    Admins with where="kerberoastable=true" is one call. Returns every match
    with an exact `total`, cited, paged like list_entities. Prefer it over
    composing the same walk by hand."""
    grant = _grant(ctx, namespace, "r")
    _known_namespace(namespace, grant)
    if isinstance(params, str):
        params = json.loads(params) if params.strip() else {}
    if isinstance(params, list):
        # positional, in the query's parameter order: ["group:…", "user"]
        query = find_query(_get_store().get_schema(namespace), namespace, name)
        params = {p.name: v for p, v in zip(query.params, params)}
    req = QueryRequest(namespace=namespace, name=name, params=params or {}, where=_filters(where),
                       fields=_listed(fields), limit=limit, offset=offset,
                       budget=budget, as_of=_parse_time(as_of), valid_at=_parse_time(valid_at))
    _, listed = resolve_query(_get_store(), req, allowed_types=_allowed(grant))
    if listed.of is not None:
        _gate_type(grant, listed.of.type)
    if listed.type:
        _gate_type(grant, listed.type)
    return _list_view(run_query_impl(_get_store(), req, allowed_types=_allowed(grant)))


class PurpleView(TypedDict):
    """Red actions of an operation against the detections around them (D-086)."""
    namespace: str
    operation: str
    summary: dict[str, Any]
    rows: list[dict[str, Any]]
    shown: int
    notes: list[str]


def purple_report(
    operation: str,
    namespace: str = _DEFAULT_NS,
    status: list[str] | str | None = None,
    before_minutes: int = 5,
    after_hours: int = 24,
    limit: int = 50,
    ctx: Context = None,
) -> PurpleView:
    """Purple-team correlation: every action a red-team operation logged
    (loomctx.connectors.oplog) set against the detections (OCSF findings) on
    the same host — resolved across tool naming, D-083 — from
    before_minutes before it to after_hours after it. Each row is
    `detected` (a finding mapping to the action's ATT&CK technique or its
    parent/sub-technique), `host_only` (something fired on that host, not
    that technique), `missed`, or `no_target`, with the first detection's
    latency and cite tokens for both sides. `status` narrows the rows
    (e.g. ['missed', 'host_only'] for the gaps); `summary` always counts
    all of them. `notes` carry coverage gaps behind the result (D-082)."""
    from . import purple
    grant = _grant(ctx, namespace, "r")
    for t in ("activity", "operation", "host", "finding", "technique"):
        _gate_type(grant, t)
    _known_namespace(namespace, grant)
    rows, notes = purple.correlate(_get_store(), namespace, operation,
                                   timedelta(minutes=before_minutes), timedelta(hours=after_hours))
    wanted = set(_listed(status)) if status else None
    shown = [r for r in rows if wanted is None or r.status in wanted][:max(1, min(limit, 500))]
    view_rows = []
    for r in shown:
        view_rows.append({
            "activity": r.activity, "performed_at": r.performed_at, "techniques": r.techniques,
            "hosts": r.hosts, "procedure": r.procedure, "status": r.status,
            "cites": [c[:12] for c in r.cites],
            "detections": [{"finding": m.finding, "title": m.title, "source": m.source,
                            "detected_at": m.detected_at, "latency_seconds": m.latency_seconds,
                            "level": m.level, "techniques": m.techniques,
                            "cites": [c[:12] for c in m.cites]} for m in r.matches[:3]]})
    return {"namespace": namespace, "operation": operation, "summary": purple.summary(rows),
            "rows": view_rows, "shown": len(view_rows), "notes": notes}


def _observation_view(namespace: str, grant: Grant | None, obs) -> ObservationList:
    """One raw observation, gated like get_observations."""
    if grant is not None and not (
            grant.allows_entity_type(obs.subject.type)
            and (not isinstance(obs.object, EntityRef) or grant.allows_entity_type(obs.object.type))):
        raise PermissionError(f"key {grant.id!r} is not scoped to that observation's entity types")
    return {"namespace": namespace, "count": 1, "observations": [obs.model_dump(mode="json")]}


def expand(handle: str, budget: int = 800, namespace: str = _DEFAULT_NS,
           format: Format = "concise", ctx: Context = None) -> ExpandResult:
    """Pull one thread deeper: pass an expansion handle id from a previous
    ask/ask_scope result (the `id` of an entry in its `handles` list) to
    fetch the observations it stands for. Handles are stateless (the
    server keeps nothing per handle), signed when the deployment sets
    LOOMCTX_HANDLE_SECRET, and never expire on their own — there is no TTL;
    only a rotation of that secret invalidates the ones issued before it.
    Size is controlled by `budget`: pass a smaller one for a tighter
    result, a larger one to drain the thread. A citation's `cite` token
    (or a full observation id) returns that one observation instead, from
    `namespace`. format as in ask."""
    if _CITE.match(handle) or _OBS_ID.match(handle):
        grant = _grant(ctx, namespace, "r")
        return _observation_view(namespace, grant, _observation_by_cite(namespace, handle))
    try:
        meta = decode_handle(handle)
    except ValueError as exc:
        raise ValueError(f"{exc}: expand takes the `id` of an entry in a pack's `handles` list "
                         "(it starts with h1_ or h2_) or a citation's 12-hex `cite` token, "
                         "not an entity handle; for more about an entity use ask, for its raw "
                         "records use get_observations") from exc
    grant = _grant(ctx, meta["ns"], "r")
    _gate_type(grant, str(meta["subject"].get("type", "")))
    return _agent_view(expand_pack(_get_store(), handle, budget, allowed_types=_allowed(grant)), format)


def _claim_event_id(namespace: str, subject: EntityRef, predicate: str, obj: Any,
                    observed_at: datetime, source: str, valid_from: datetime | None,
                    valid_to: datetime | None, supersedes: str | None) -> str:
    """Content-addressed idempotency key for a write-back: the same fact
    recorded twice by an agent that retried is one observation (D-014),
    so record_claim is idempotent without the caller managing ids."""
    obj_key = f"{obj.type}:{obj.key}" if isinstance(obj, EntityRef) else f"={type(obj).__name__}:{obj}"
    parts = (namespace, subject.type, subject.key, predicate, obj_key, observed_at.isoformat(),
             source, valid_from.isoformat() if valid_from else "",
             valid_to.isoformat() if valid_to else "", supersedes or "")
    return "mcp:" + hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


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
    supersedes: str | None = None,
    event_id: str | None = None,
    ctx: Context = None,
) -> RecordClaimResult:
    """Write back a fact you learned. subject is 'type:key'; provide exactly
    one of object_ref (another 'type:key' entity — creates a graph edge) or
    object_value (a scalar like an OS name or port number). observed_at /
    valid_from / valid_to are ISO timestamps. Idempotent: event_id is the
    dedupe key (redelivery of the same event_id records nothing new);
    omit it and one is derived from the claim's content, so repeating the
    same call is one observation. supersedes = the `cite` token (or full
    id) of an earlier observation this claim CORRECTS or replaces — a
    recorded correction, never inferred: the old observation stays for
    audit and for as_of reads before this one, but is no longer current
    and no longer counts as a conflict. Use it when you have established
    that a source's earlier statement was wrong; never to pick a side of a
    conflict you have not resolved."""
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
    superseded_id: str | None = None
    if supersedes:
        old = _observation_by_cite(namespace, supersedes)
        if old is None:
            raise ValueError(f"supersedes must be a citation's 12-hex `cite` token or a full "
                             f"32-hex observation id, got {supersedes!r}")
        superseded_id = old.id
    when = datetime.fromisoformat(observed_at)
    vf, vt = _parse_time(valid_from), _parse_time(valid_to)
    if not event_id:
        event_id = _claim_event_id(namespace, subj, predicate, obj, when, source, vf, vt, superseded_id)
    claim = ClaimIn(
        namespace=namespace,
        event_id=event_id,
        subject=subj,
        predicate=predicate,
        object=obj,
        observed_at=when,
        valid_from=vf,
        valid_to=vt,
        source=source,
        confidence=confidence,
        supersedes=superseded_id,
    )
    problem = validate_claim(_get_store().get_schema(namespace), claim)
    if problem is not None:
        raise ValueError(problem)
    # the same rule as POST /v1/ingest: a correction stays on its subject,
    # inside the key's entity types (D-050, D-059)
    problem = check_supersedes(_get_store(), claim, grant)
    if problem is not None:
        raise ValueError(problem)
    obs = _get_store().record_claim(claim)
    out: RecordClaimResult = {"status": "recorded", "observation_id": obs.id, "event_id": event_id}
    if superseded_id:
        out["supersedes"] = superseded_id
    return out


def get_observations(
    subject: str, namespace: str = _DEFAULT_NS, limit: int = 50, ctx: Context = None
) -> ObservationList:
    """Raw observations touching an entity (audit/debug — prefer ask for
    focused context). subject may also be a citation's `cite` token or a
    full observation id, which returns that single record."""
    grant = _grant(ctx, namespace, "r")
    if _CITE.match(subject) or _OBS_ID.match(subject):
        return _observation_view(namespace, grant, _observation_by_cite(namespace, subject))
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
) -> AnswerResult:
    """Retrieval-grounded LLM answer with citations. Entities named verbatim
    in the question are auto-resolved when subject is omitted. Requires the
    server to have LOOMCTX_LLM_* configured; use ask when it isn't."""
    grant = _grant(ctx, namespace, "r")
    if subject:
        _gate_type(grant, _parse_ref(subject).type)
    llm = _get_llm()
    if llm is None:
        raise ToolError("no LLM configured on this LoomCtx (set LOOMCTX_LLM_MODEL plus "
                        "LOOMCTX_LLM_PROVIDER or LOOMCTX_LLM_BASE_URL); use the ask tool instead")
    _known_namespace(namespace, grant)
    _throttle(ctx, grant, llm=True)   # LLM spend: rate_llm_per_sec / LOOMCTX_RATE_LLM_PER_SEC, as /v1/answer
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
        raise ToolError(str(exc)) from exc
    except LLMError as exc:
        raise ToolError(f"provider error: {exc.public}") from exc
    return {
        "answer": resp.answer,
        "model": resp.model,
        "pack": _agent_view(resp.pack),
    }


# tool -> (title, read-only?, idempotent?). Every tool is closed-world (it
# touches this LoomCtx's store and nothing else) and none is destructive
# (observations are append-only; record_claim only adds).
TOOL_META: dict[str, tuple[str, bool, bool]] = {
    "list_namespaces": ("List namespaces", True, True),
    "describe_namespace": ("Describe a namespace", True, True),
    "find_entity": ("Find entities by name", True, True),
    "find_related": ("Find entities by meaning", True, True),
    "ask": ("Ask about one entity", True, True),
    "ask_scope": ("Ask about a scope", True, True),
    "find_path": ("Find paths between two entities", True, True),
    "list_entities": ("List every entity matching conditions", True, True),
    "run_query": ("Run a named query", True, True),
    "expand": ("Expand a handle", True, True),
    "record_claim": ("Record a claim", False, True),
    "get_observations": ("Get raw observations", True, True),
    "answer": ("LLM answer with citations", True, False),
    "purple_report": ("Red actions vs detections", True, True),
}

TOOLS = (
    list_namespaces,
    describe_namespace,
    find_entity,
    find_related,
    ask,
    ask_scope,
    find_path,
    list_entities,
    run_query,
    expand,
    record_claim,
    get_observations,
    answer,
    purple_report,
)


def _annotations(name: str) -> ToolAnnotations:
    title, read_only, idempotent = TOOL_META[name]
    return ToolAnnotations(title=title, read_only_hint=read_only, destructive_hint=False,
                           idempotent_hint=idempotent, open_world_hint=False)


def _surface_errors(fn):
    """The SDK reports unexpected exceptions as an opaque 'Error executing
    tool'; an agent needs the actual reason (bad handle, scope refusal,
    provider down) to recover. Wrap our expected failures as ToolError so
    the message reaches the client verbatim. Every tool fails this one way
    — none returns an {"error": …} payload an agent could mistake for data."""
    import functools

    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except PermissionError as exc:
            raise ToolError(str(exc)) from exc
        except (ValueError, LLMError) as exc:
            # say how to recover: Gemini 2.5 Flash gave up on the task after
            # one failed call in most of its failing audits (D-116)
            raise ToolError(f"{exc} {_RETRY_HINT.get(fn.__name__, _RETRY_HINT_DEFAULT)}") from exc

    return wrapped


_RETRY_HINT_DEFAULT = ("(This call failed on its arguments; correct them and call again — "
                       "describe_namespace lists the types, predicates and queries.)")
_RETRY_HINT = {
    "list_entities": "(This call failed on its arguments; correct them and call again. where takes "
                     "'predicate=value', 'predicate?', '!predicate' or 'predicate within type:key', joined "
                     "by ';' or AND — describe_namespace lists the predicates.)",
    "run_query": "(This call failed on its arguments; correct them and call again — describe_namespace "
                 "lists each query's parameters, or list_entities answers the same question.)",
    "answer": "(The answer step failed; ask or ask_scope still return the cited facts.)",
}


def _compact_text(fn):
    """The SDK mirrors a structured result into its text block as JSON
    indented two spaces; on a pack a third of the tokens an agent received
    were indentation (D-058). Pack tools return their result with a
    compact mirror instead — same data, same structuredContent."""
    import functools

    import pydantic_core

    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        result = fn(*args, **kwargs)
        return CallToolResult(content=[TextContent(type="text", text=pydantic_core.to_json(
            result, fallback=str).decode())], structured_content=result)

    return wrapped


def _accept_aliases(fn):
    """A parameter published under an alias (find_path's `from_` is `from`
    on the wire — `from` is a Python keyword) reaches the function under
    that alias: the SDK's ArgModelBase.model_dump_one_level() keys the call's
    kwargs by alias, so find_path was called with from=... and failed every
    real tools/call with an opaque TypeError. Map each alias back to its
    parameter name; the schema (built from the signature) is unchanged."""
    import functools
    import typing

    renames = {
        alias: name
        for name, hint in typing.get_type_hints(fn, include_extras=True).items()
        for meta in getattr(hint, "__metadata__", ())
        if isinstance(alias := getattr(meta, "alias", None), str) and alias != name
    }
    if not renames:
        return fn

    @functools.wraps(fn)
    def wrapped(*args, **kwargs):
        for alias, name in renames.items():
            if alias in kwargs:
                kwargs[name] = kwargs.pop(alias)
        return fn(*args, **kwargs)

    return wrapped


_PACK_TOOLS = ("ask", "ask_scope", "find_path", "list_entities", "run_query", "expand", "answer")

for _fn in TOOLS:
    if (_fn is run_query and not _QUERIES_ON) or (_fn is record_claim and not _WRITES_ON):
        continue
    _impl = _accept_aliases(_fn)
    _impl = _compact_text(_impl) if _fn.__name__ in _PACK_TOOLS else _impl
    mcp.tool(name=_fn.__name__, title=TOOL_META[_fn.__name__][0],
             annotations=_annotations(_fn.__name__))(_surface_errors(_impl))


def build_http_app(transport: str, host: str, auth: AuthConfig):
    """The ASGI app for an HTTP transport, outermost gate first:
    BrowserGuard (Host allowlist + foreign-Origin refusal, D-059) ->
    KeyGate -> the SDK app.

    The SDK only turns on its own DNS-rebinding protection when bound to a
    loopback address; compose binds 0.0.0.0 (inside the container), which
    left it off. Its host list is exact-match only and cannot express the
    policy the deployments need (IP literals for probes and LAN agents,
    service names, cluster suffixes), so the settings are passed
    explicitly: the SDK check is off *because* BrowserGuard enforces
    LOOMCTX_ALLOWED_HOSTS / LOOMCTX_ALLOWED_ORIGINS in front of it, the same
    policy as the engine. The SDK still requires application/json on POST."""
    from mcp.server.transport_security import TransportSecuritySettings

    from .webguard import BrowserGuard

    security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    app = (mcp.streamable_http_app(host=host, transport_security=security)
           if transport == "streamable-http"
           else mcp.sse_app(host=host, transport_security=security))
    # DELETE (session end) and GET (event stream) carry no body; the SDK
    # validates POST content types itself
    return BrowserGuard(KeyGate(app, auth), check_content_type=False, metric=REJECTED)


def main() -> None:
    try:
        _main()
    finally:
        _close_store()


def _close_store() -> None:
    """Close the lazily opened store on the way out: a Postgres pool left to
    the interpreter's shutdown joins its worker threads too late and prints a
    PythonFinalizationError (seen on every agent_eval run on GKE, D-063)."""
    global _store
    if _store is not None:
        store, _store = _store, None
        store.close()


def _main() -> None:
    args = _arg_parser().parse_args()
    global _transport
    _transport = args.transport
    threading.Thread(target=_warm, name="loomctx-warm", daemon=True).start()
    if args.transport == "stdio":
        mcp.run(transport="stdio")
        return
    import logging
    import uvicorn
    auth = _get_auth()
    _get_limits()   # a malformed LOOMCTX_RATE_* stops start-up here, not on a tool call
    if not auth.enabled:
        logging.getLogger("loomctx.mcp").warning(
            "no LOOMCTX_AUTH_FILE / LOOMCTX_API_KEYS — MCP %s transport is OPEN; every "
            "connected agent gets full access", args.transport)
    uvicorn.run(build_http_app(args.transport, args.host, auth), host=args.host, port=args.port)


def _arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="loomctx.mcp_server", description=__doc__)
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http", "sse"],
        default="stdio",
    )
    # loopback unless told otherwise: an open (keyless) MCP server on every
    # interface is the LAN's. Compose passes --host 0.0.0.0 inside the
    # container and publishes the port on LOOMCTX_BIND (localhost by default).
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8300)
    return parser


if __name__ == "__main__":
    main()
