"""Thin Python client for LoomCtx. Typed transport only — no logic (docs/sdk.md).

Deliberately stdlib-only (urllib) so pipeline devices can vendor it with zero
dependencies. Server errors surface as `LoomCtxError(status, detail)` carrying
the engine's `detail` message; everything else is a plain dict of the
contract shape (docs/contracts.md).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Union

EntityTuple = tuple[str, str]  # (type, key)
ObjectArg = Union[EntityTuple, str, int, float, bool]


class LoomCtxError(Exception):
    """A non-2xx response. `status` is the HTTP code, `detail` the engine's
    message (e.g. which gate refused a scoped key)."""

    def __init__(self, status: int, detail: str):
        super().__init__(f"HTTP {status}: {detail}")
        self.status = status
        self.detail = detail


class LoomCtx:
    def __init__(
        self,
        base_url: str,
        namespace: str = "default",
        api_key: str | None = None,
        timeout: float = 30.0,
        llm_key: str | None = None,
    ):
        """`llm_key` is an optional provider key sent as X-LoomCtx-LLM-Key on
        answer() so LLM spend bills to this caller (D-013a); the LoomCtx
        `api_key` still governs what data the answer may see."""
        self.base_url = base_url.rstrip("/")
        self.namespace = namespace
        # a key read from a mounted file ends in a newline no header may carry
        self.api_key = api_key.strip() if api_key else api_key
        self.timeout = timeout
        self.llm_key = llm_key

    # ------------------------------------------------------------- write side

    def claim(
        self,
        subject: EntityTuple,
        predicate: str,
        object: ObjectArg,
        observed_at: str,
        source: str,
        confidence: float = 1.0,
        valid_from: str | None = None,
        valid_to: str | None = None,
        event_id: str | None = None,
        attrs: dict[str, Any] | None = None,
    ) -> dict:
        obj: Any = object
        if isinstance(object, tuple):
            obj = {"type": object[0], "key": object[1]}
        return self._post(
            "/v1/ingest",
            {
                "kind": "claim",
                "namespace": self.namespace,
                "event_id": event_id,
                "subject": {"type": subject[0], "key": subject[1]},
                "predicate": predicate,
                "object": obj,
                "observed_at": observed_at,
                "valid_from": valid_from,
                "valid_to": valid_to,
                "source": source,
                "confidence": confidence,
                "attrs": attrs or {},
            },
        )

    def document(
        self,
        source: str,
        observed_at: str,
        text: str | None = None,
        content_b64: str | None = None,
        content_type: str = "text/plain",
        filename: str | None = None,
        event_id: str | None = None,
        attrs: dict[str, Any] | None = None,
    ) -> dict:
        return self._post(
            "/v1/ingest",
            {
                "kind": "document",
                "namespace": self.namespace,
                "event_id": event_id,
                "text": text,
                "content_b64": content_b64,
                "content_type": content_type,
                "filename": filename,
                "source": source,
                "observed_at": observed_at,
                "attrs": attrs or {},
            },
        )

    def ingest_batch(self, envelopes: list[dict]) -> dict:
        """Many claim/document envelopes in one request (D-034); each is
        reported individually in the returned `results`."""
        return self._post("/v1/ingest/batch", envelopes)

    # -------------------------------------------------------------- read side

    def observations(self, subject: EntityTuple, limit: int = 100) -> dict:
        etype, key = (urllib.parse.quote(part, safe="") for part in subject)
        return self._get(f"/v1/entities/{etype}/{key}/observations",
                         {"limit": limit})

    def artifact(self, artifact_id: str) -> dict:
        """The stored document, verbatim (text or content_b64)."""
        return self._get(f"/v1/artifacts/{urllib.parse.quote(artifact_id, safe='')}")

    def ask(
        self,
        subject: EntityTuple | None,
        question: str,
        budget: int = 800,
        as_of: str | None = None,
        scope: dict | None = None,
        valid_at: str | None = None,
    ) -> dict:
        """One of subject / scope. scope example:
        {"subjects": [{"type": "domain", "key": "corp.local"}],
         "expand": ["member_of"], "depth": 1}
        as_of = what was known at T; valid_at = what was true at T."""
        return self._post(
            "/v1/ask",
            {
                "namespace": self.namespace,
                "subject": (
                    {"type": subject[0], "key": subject[1]} if subject else None
                ),
                "scope": scope,
                "question": question,
                "budget": budget,
                "as_of": as_of,
                "valid_at": valid_at,
            },
        )

    def expand(self, handle_id: str, budget: int = 800) -> dict:
        return self._post("/v1/expand", {"handle": handle_id, "budget": budget})

    def list_entities(
        self,
        type: str | None = None,
        of: EntityTuple | None = None,
        via: list[str] | None = None,
        direction: str = "in",
        depth: int = 1,
        where: list[dict] | None = None,
        fields: list[str] | None = None,
        limit: int = 50,
        offset: int = 0,
        budget: int = 1500,
        as_of: str | None = None,
        valid_at: str | None = None,
    ) -> dict:
        """Every entity matching conditions, with an exact count (D-107):
        entities of `type`, or connected to `of` along `via` within `depth`
        edges, filtered on current values — `where` items are
        {"predicate", "op" (eq|ne|in|contains|exists|absent), "value"}.
        Rows are cited; page with `offset` / the response's `next_offset`."""
        return self._post(
            "/v1/list",
            {
                "namespace": self.namespace,
                "type": type,
                "of": {"type": of[0], "key": of[1]} if of else None,
                "via": via or [],
                "direction": direction,
                "depth": depth,
                "where": where or [],
                "fields": fields or [],
                "limit": limit,
                "offset": offset,
                "budget": budget,
                "as_of": as_of,
                "valid_at": valid_at,
            },
        )

    def run_query(
        self,
        name: str,
        params: dict | None = None,
        limit: int = 50,
        offset: int = 0,
        budget: int = 1500,
        as_of: str | None = None,
        valid_at: str | None = None,
    ) -> dict:
        """Run one of the namespace's named queries (D-108) — listed by its
        schema registration — with `params`; the answer is a list page."""
        return self._post(
            "/v1/query",
            {
                "namespace": self.namespace,
                "name": name,
                "params": params or {},
                "limit": limit,
                "offset": offset,
                "budget": budget,
                "as_of": as_of,
                "valid_at": valid_at,
            },
        )

    def path(
        self,
        from_: EntityTuple,
        to: EntityTuple,
        via: list[str] | None = None,
        depth: int = 3,
        max_paths: int = 8,
        budget: int = 800,
        as_of: str | None = None,
        valid_at: str | None = None,
    ) -> dict:
        """The edge sequence(s) that connect two entities along `via`
        predicates (D-067) — "what connects A to B?". Empty `via` follows the
        namespace's containment predicates. Reports paths that EXIST, each hop
        cited; it does not rank or score them. as_of / valid_at as in ask()."""
        return self._post(
            "/v1/path",
            {
                "namespace": self.namespace,
                "from": {"type": from_[0], "key": from_[1]},
                "to": {"type": to[0], "key": to[1]},
                "via": via or [],
                "depth": depth,
                "max_paths": max_paths,
                "budget": budget,
                "as_of": as_of,
                "valid_at": valid_at,
            },
        )

    def answer(
        self,
        question: str,
        subject: EntityTuple | None = None,
        scope: dict | None = None,
        budget: int = 1200,
        as_of: str | None = None,
        max_tokens: int = 1024,
        valid_at: str | None = None,
    ) -> dict:
        """Retrieval-grounded LLM answer. With neither subject nor scope,
        entities named in the question are auto-resolved server-side."""
        headers = {"X-LoomCtx-LLM-Key": self.llm_key} if self.llm_key else {}
        return self._post(
            "/v1/answer",
            {
                "namespace": self.namespace,
                "question": question,
                "subject": (
                    {"type": subject[0], "key": subject[1]} if subject else None
                ),
                "scope": scope,
                "budget": budget,
                "as_of": as_of,
                "valid_at": valid_at,
                "max_tokens": max_tokens,
            },
            extra_headers=headers,
        )

    def register_schema(self, entity_types: list[dict], predicates: list[dict],
                        strict: bool = False, queries: list[dict] | None = None,
                        not_collected: list[dict] | None = None) -> dict:
        """Register the namespace's entity types / predicates (D-024), and
        optionally its named queries (D-108) and what its sources do not
        carry (D-110). e.g. predicates=[{"name": "member_of", "object_types":
        ["domain"], "containment": True, "aliases": ["memberOf"]}]."""
        body: dict[str, Any] = {
            "namespace": self.namespace, "entity_types": entity_types,
            "predicates": predicates, "strict": strict}
        if queries is not None:
            body["queries"] = queries
        if not_collected is not None:
            body["not_collected"] = not_collected
        return self._post("/v1/schemas", body)

    def schema(self) -> dict:
        return self._get("/v1/schemas")

    def search(self, query: str, limit: int = 10) -> dict:
        return self._get("/v1/entities/search", {"q": query, "limit": limit})

    def semantic(self, question: str, limit: int = 10) -> dict:
        """Entities related to a question by meaning (D-025); each match
        cites its best-matching fact. 503 until the engine has an embedder."""
        return self._get("/v1/entities/semantic", {"q": question, "limit": limit})

    def ready(self) -> bool:
        """True when the engine is up AND its store answers (GET /readyz)."""
        try:
            return self._get("/readyz").get("status") == "ready"
        except (LoomCtxError, urllib.error.URLError, TimeoutError):
            return False

    # --------------------------------------------------------------- plumbing

    def _post(self, path: str, body: dict, extra_headers: dict | None = None) -> dict:
        req = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(body).encode(),
            headers={**self._headers(), **(extra_headers or {})},
            method="POST",
        )
        return self._send(req)

    def _get(self, path: str, params: dict | None = None) -> dict:
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        return self._send(urllib.request.Request(url, headers=self._headers()))

    def _send(self, req: urllib.request.Request) -> dict:
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                detail = json.loads(raw).get("detail", raw.decode(errors="replace"))
            except ValueError:
                detail = raw.decode(errors="replace")
            if not isinstance(detail, str):
                detail = json.dumps(detail)  # pydantic validation error lists
            raise LoomCtxError(exc.code, detail) from None

    def _headers(self) -> dict:
        headers = {
            "content-type": "application/json",
            "X-LoomCtx-Namespace": self.namespace,
        }
        if self.api_key:
            headers["X-LoomCtx-Key"] = self.api_key
        return headers
