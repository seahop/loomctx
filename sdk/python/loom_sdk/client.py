"""Thin Python client for Loom. Typed transport only — no logic (docs/sdk.md).

Deliberately stdlib-only (urllib) so pipeline devices can vendor it with zero
dependencies. Server errors surface as `LoomError(status, detail)` carrying
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


class LoomError(Exception):
    """A non-2xx response. `status` is the HTTP code, `detail` the engine's
    message (e.g. which gate refused a scoped key)."""

    def __init__(self, status: int, detail: str):
        super().__init__(f"HTTP {status}: {detail}")
        self.status = status
        self.detail = detail


class Loom:
    def __init__(
        self,
        base_url: str,
        namespace: str = "default",
        api_key: str | None = None,
        timeout: float = 30.0,
        llm_key: str | None = None,
    ):
        """`llm_key` is an optional provider key sent as X-Loom-LLM-Key on
        answer() so LLM spend bills to this caller (D-013a); the Loom
        `api_key` still governs what data the answer may see."""
        self.base_url = base_url.rstrip("/")
        self.namespace = namespace
        self.api_key = api_key
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
        headers = {"X-Loom-LLM-Key": self.llm_key} if self.llm_key else {}
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
                        strict: bool = False) -> dict:
        """Register the namespace's entity types / predicates (D-024).
        e.g. predicates=[{"name": "member_of", "object_types": ["domain"],
        "containment": True}]."""
        return self._post("/v1/schemas", {
            "namespace": self.namespace, "entity_types": entity_types,
            "predicates": predicates, "strict": strict})

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
        except (LoomError, urllib.error.URLError, TimeoutError):
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
            raise LoomError(exc.code, detail) from None

    def _headers(self) -> dict:
        headers = {
            "content-type": "application/json",
            "X-Loom-Namespace": self.namespace,
        }
        if self.api_key:
            headers["X-Loom-Key"] = self.api_key
        return headers
