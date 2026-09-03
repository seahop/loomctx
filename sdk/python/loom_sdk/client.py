"""Thin Python client for Loom. Typed transport only — no logic (docs/sdk.md).

Deliberately stdlib-only (urllib) so pipeline devices can vendor it with zero
dependencies.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any, Union

EntityTuple = tuple[str, str]  # (type, key)
ObjectArg = Union[EntityTuple, str, int, float, bool]


class Loom:
    def __init__(self, base_url: str, namespace: str = "default", timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.namespace = namespace
        self.timeout = timeout

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
        attrs: dict[str, Any] | None = None,
    ) -> dict:
        return self._post(
            "/v1/ingest",
            {
                "kind": "document",
                "namespace": self.namespace,
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
        return self._get(
            f"/v1/entities/{subject[0]}/{subject[1]}/observations?limit={limit}"
        )

    def ask(
        self,
        subject: EntityTuple,
        question: str,
        budget: int = 800,
        as_of: str | None = None,
    ) -> dict:
        return self._post(
            "/v1/ask",
            {
                "namespace": self.namespace,
                "subject": {"type": subject[0], "key": subject[1]},
                "question": question,
                "budget": budget,
                "as_of": as_of,
            },
        )

    def expand(self, handle_id: str, budget: int = 800) -> dict:
        return self._post("/v1/expand", {"handle": handle_id, "budget": budget})

    # --------------------------------------------------------------- plumbing

    def _post(self, path: str, body: dict) -> dict:
        req = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(body).encode(),
            headers=self._headers(),
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read())

    def _get(self, path: str) -> dict:
        req = urllib.request.Request(self.base_url + path, headers=self._headers())
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read())

    def _headers(self) -> dict:
        return {
            "content-type": "application/json",
            "X-Loom-Namespace": self.namespace,
        }
