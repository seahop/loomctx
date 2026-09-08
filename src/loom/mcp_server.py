"""The MCP surface (phase 3, decision D-006): agents plug in natively.

Wraps the same core functions the HTTP API uses — no separate logic, no
drift. Entity handles are "type:key" strings ("host:web-01") for agent
ergonomics.

Register with Claude Code (stdio, spawned per session):

    claude mcp add loom -- docker compose run --rm -T loom \
        python -m loom.mcp_server

Or serve remote agents over streamable HTTP (compose profile `mcp`):

    docker compose --profile mcp up -d mcp     # -> :8300/mcp

Requires the `mcp` extra (installed in the image).
"""

from __future__ import annotations

import argparse
from datetime import datetime
from typing import Any

from mcp.server.mcpserver import MCPServer

from .answer import UnresolvedQuestionError, build_answer
from .context import build_pack, expand_pack
from .contracts import AnswerRequest, AskRequest, ClaimIn, EntityRef, ScopeSpec
from .llm import LLMError, embedder_from_env, llm_from_env
from .store.base import GraphStore
from .store.factory import store_from_env

_embedder_loaded = False
_embedder = None


def _get_embedder():
    global _embedder_loaded, _embedder
    if not _embedder_loaded:
        _embedder = embedder_from_env()
        _embedder_loaded = True
    return _embedder

mcp = MCPServer(
    "loom",
    instructions=(
        "Loom is a provenance-tracked context engine. Use find_entity to turn "
        "names into 'type:key' handles, ask/ask_scope for budgeted cited "
        "context (start small — expand pulls threads deeper via handles), "
        "record_claim to write back facts you learn, and answer for a "
        "server-side LLM synthesis when one is configured. Conflict items "
        "mean sources disagree — never resolve them silently."
    ),
)

_store: GraphStore | None = None


def _get_store() -> GraphStore:
    global _store
    if _store is None:
        _store = store_from_env()
    return _store


def configure(store: GraphStore) -> None:
    """Inject a store (tests)."""
    global _store
    _store = store


def _parse_ref(handle: str) -> EntityRef:
    etype, sep, key = handle.partition(":")
    if not sep or not etype or not key:
        raise ValueError(
            f"entity handle must be 'type:key' (e.g. 'host:web-01'), got {handle!r}"
        )
    return EntityRef(type=etype, key=key)


def _parse_time(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


# ------------------------------------------------------------------- tools #

def find_entity(query: str, namespace: str = "default", limit: int = 10) -> list[dict]:
    """Resolve a name or key fragment to entity handles. Returns matches as
    'type:key' handles usable with the other tools (exact match first)."""
    return [
        {
            "handle": f"{e.type}:{e.key}",
            "type": e.type,
            "key": e.key,
            "provisional": e.provisional,
        }
        for e in _get_store().search_entities(namespace, query, limit=limit)
    ]


def ask(
    subject: str,
    question: str,
    budget: int = 800,
    namespace: str = "default",
    as_of: str | None = None,
    valid_at: str | None = None,
) -> dict:
    """Question-scoped, token-budgeted, cited context about one entity.
    subject is a 'type:key' handle. Conflicting facts are flagged explicitly;
    'handles' in the result feed the expand tool for more detail. as_of
    (ISO timestamp) = what was KNOWN at that moment; valid_at = what was
    TRUE at that moment (e.g. which host held an IP during an incident)."""
    req = AskRequest(
        namespace=namespace,
        subject=_parse_ref(subject),
        question=question,
        budget=budget,
        as_of=_parse_time(as_of),
        valid_at=_parse_time(valid_at),
    )
    return build_pack(
        _get_store(), req, embedder=_get_embedder()
    ).model_dump(mode="json")


def ask_scope(
    subjects: list[str],
    question: str,
    expand_predicates: list[str] | None = None,
    depth: int = 1,
    budget: int = 1200,
    namespace: str = "default",
    as_of: str | None = None,
    valid_at: str | None = None,
) -> dict:
    """Context about SEVERAL entities at once — a set of hosts, or an anchor
    plus its contents ('domain:corp.local' expanded over ['member_of'] covers
    every member). subjects are 'type:key' handles; expand_predicates names
    the relations to follow outward (omit it to follow the namespace's
    registered containment predicates); depth bounds the traversal."""
    req = AskRequest(
        namespace=namespace,
        scope=ScopeSpec(
            subjects=[_parse_ref(s) for s in subjects],
            expand=expand_predicates or [],
            depth=depth,
        ),
        question=question,
        budget=budget,
        as_of=_parse_time(as_of),
        valid_at=_parse_time(valid_at),
    )
    return build_pack(
        _get_store(), req, embedder=_get_embedder()
    ).model_dump(mode="json")


def expand(handle: str, budget: int = 800) -> dict:
    """Pull one thread deeper: pass an expansion handle id from a previous
    ask/ask_scope result to fetch the observations it stands for."""
    return expand_pack(_get_store(), handle, budget).model_dump(mode="json")


def record_claim(
    subject: str,
    predicate: str,
    observed_at: str,
    source: str,
    object_ref: str | None = None,
    object_value: str | float | int | bool | None = None,
    confidence: float = 1.0,
    namespace: str = "default",
    valid_from: str | None = None,
    valid_to: str | None = None,
) -> dict:
    """Write back a fact you learned. subject is 'type:key'; provide exactly
    one of object_ref (another 'type:key' entity — creates a graph edge) or
    object_value (a scalar like an OS name or port number). observed_at /
    valid_from / valid_to are ISO timestamps."""
    if (object_ref is None) == (object_value is None):
        raise ValueError("provide exactly one of object_ref or object_value")
    obj: Any = _parse_ref(object_ref) if object_ref else object_value
    claim = ClaimIn(
        namespace=namespace,
        subject=_parse_ref(subject),
        predicate=predicate,
        object=obj,
        observed_at=datetime.fromisoformat(observed_at),
        valid_from=_parse_time(valid_from),
        valid_to=_parse_time(valid_to),
        source=source,
        confidence=confidence,
    )
    obs = _get_store().record_claim(claim)
    return {"status": "recorded", "observation_id": obs.id}


def get_observations(
    subject: str, namespace: str = "default", limit: int = 50
) -> dict:
    """Raw observations touching an entity (audit/debug — prefer ask for
    focused context)."""
    observations = _get_store().observations_for(
        namespace, _parse_ref(subject), limit=limit
    )
    return {
        "subject": subject,
        "count": len(observations),
        "observations": [o.model_dump(mode="json") for o in observations],
    }


def answer(
    question: str,
    subject: str | None = None,
    budget: int = 1200,
    namespace: str = "default",
    valid_at: str | None = None,
) -> dict:
    """Retrieval-grounded LLM answer with citations. Entities named verbatim
    in the question are auto-resolved when subject is omitted. Requires the
    server to have LOOM_LLM_* configured; use ask when it isn't."""
    llm = llm_from_env()
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
        resp = build_answer(_get_store(), llm, req, embedder=_get_embedder())
    except UnresolvedQuestionError as exc:
        return {"error": str(exc)}
    except LLMError as exc:
        return {"error": f"provider error: {exc.public}"}
    return {
        "answer": resp.answer,
        "model": resp.model,
        "pack": resp.pack.model_dump(mode="json"),
    }


TOOLS = (
    find_entity,
    ask,
    ask_scope,
    expand,
    record_claim,
    get_observations,
    answer,
)
for _fn in TOOLS:
    mcp.tool()(_fn)


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
    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(transport=args.transport, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
