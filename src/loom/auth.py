"""API keys: generation-friendly, hashed at rest, scoped by gates (D-013/D-013a).

Two configuration sources, checked in this order:

1. **Keys file** (`LOOM_AUTH_FILE=/path/keys.json`) — produced by
   `python -m loom.keys generate`. Stores only SHA-256 hashes, never
   plaintext. Each entry is a *grant* carrying the scoping gates:

       {"keys": [{
          "id": "netsec-shipper",              # names the key in logs/audit
          "sha256": "<hex of the key>",
          "namespaces": ["netsec"],            # or ["*"]
          "perms": "w",                        # r | w | rw
          "entity_types": ["host", "ip"],      # optional gate; null = any
          "sources": ["auth-log"],             # optional write gate; null = any
          "expires": "2027-01-01T00:00:00Z",   # optional
          "rate_per_sec": 5, "rate_burst": 20,   # optional per-key rate limit (R-10)
          "rate_llm_per_sec": 0.5,               # optional; /v1/answer + semantic search
          "disabled": false
       }]}

   The file is hot-reloaded on mtime change — rotate keys by rewriting the
   mounted Secret/file, no restart needed.

2. **Legacy env** (`LOOM_API_KEYS="key:namespace:perms,..."`) — the simple
   plaintext format; hashed in memory at load, no fine-grained gates.

Both unset => auth DISABLED (open dev mode, logged). Keys arrive as
`X-Loom-Key` or `Authorization: Bearer`; lookups compare SHA-256 digests in
constant time. The Go gateway parses the same file/env.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone

log = logging.getLogger("loom.auth")

ENV_KEYS = "LOOM_API_KEYS"
ENV_FILE = "LOOM_AUTH_FILE"


@dataclass(frozen=True)
class Grant:
    """What one key is allowed to do. None gates mean 'unrestricted'."""

    id: str
    namespaces: tuple[str, ...]
    perms: str
    entity_types: tuple[str, ...] | None = None
    sources: tuple[str, ...] | None = None
    expires: datetime | None = None
    # per-key rate limits (R-10); None = the LOOM_RATE_* defaults apply
    rate_per_sec: float | None = None
    rate_burst: int | None = None
    rate_llm_per_sec: float | None = None

    def allows(self, namespace: str, action: str) -> bool:
        if action not in self.perms:
            return False
        return "*" in self.namespaces or namespace in self.namespaces

    def allows_entity_type(self, entity_type: str) -> bool:
        return self.entity_types is None or entity_type in self.entity_types

    def allows_source(self, source: str) -> bool:
        return self.sources is None or source in self.sources

    def expired(self, now: datetime) -> bool:
        return self.expires is not None and now >= self.expires


def _sha256(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _parse_expires(value: str | None) -> datetime | None:
    """ISO-8601; a naive timestamp is taken as UTC (same rule as stored
    data), so a hand-edited "2027-01-01T00:00:00" can't 500 every request
    by comparing naive to aware (H-A5)."""
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _parse_rate(item: dict, field: str, integer: bool = False) -> float | int | None:
    """A per-key rate field: a positive number, or absent/null for 'use
    the default'. Zero or a negative value is a configuration error, not
    'unlimited' — the way to lift a key's cap is to remove the field."""
    value = item.get(field)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a number")
    if value <= 0:
        raise ValueError(f"{field} must be positive (remove it for the default)")
    return max(1, int(value)) if integer else float(value)


def _parse_entry(item: dict) -> tuple[str, Grant]:
    digest = str(item["sha256"]).lower()
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("sha256 is not 64 hex chars")
    perms = str(item["perms"])
    if not perms or not set(perms) <= {"r", "w"}:
        raise ValueError(f"perms must be r, w or rw, got {perms!r}")
    return (
        digest,
        Grant(
            id=str(item["id"]),
            namespaces=tuple(item["namespaces"]),
            perms=perms,
            entity_types=(
                tuple(item["entity_types"])
                if item.get("entity_types") is not None else None
            ),
            sources=(
                tuple(item["sources"])
                if item.get("sources") is not None else None
            ),
            expires=_parse_expires(item.get("expires")),
            rate_per_sec=_parse_rate(item, "rate_per_sec"),
            rate_burst=_parse_rate(item, "rate_burst", integer=True),
            rate_llm_per_sec=_parse_rate(item, "rate_llm_per_sec"),
        ),
    )


def _parse_file(raw: str) -> list[tuple[str, Grant]]:
    """One malformed entry disables THAT key (logged), never the whole
    file — the same tolerance the Go gateway applies, so both sides of a
    shared Secret see the same live key set (H-A13)."""
    data = json.loads(raw)
    entries: list[tuple[str, Grant]] = []
    for index, item in enumerate(data.get("keys", [])):
        if not isinstance(item, dict) or item.get("disabled"):
            continue
        try:
            entries.append(_parse_entry(item))
        except (KeyError, ValueError, TypeError) as exc:
            log.error("auth: skipping key entry %d (%r): %s",
                      index, item.get("id", "?"), exc)
    return entries


def _parse_env(raw: str) -> list[tuple[str, Grant]]:
    entries: list[tuple[str, Grant]] = []
    for index, item in enumerate(raw.split(",")):
        item = item.strip()
        if not item:
            continue
        parts = item.split(":")
        if len(parts) != 3 or not all(parts):
            raise ValueError(
                f"{ENV_KEYS}: bad entry {item!r} — expected key:namespace:perms"
            )
        key, namespace, perms = parts
        if not set(perms) <= {"r", "w"}:
            raise ValueError(f"{ENV_KEYS}: perms must be r, w or rw, got {perms!r}")
        entries.append((
            _sha256(key),
            Grant(id=f"env-{index}", namespaces=(namespace,), perms=perms),
        ))
    return entries


class AuthConfig:
    def __init__(
        self, entries: list[tuple[str, Grant]], path: str | None = None
    ):
        self._entries = entries
        self._path = path
        self._mtime = self._stat() if path else None

    def _stat(self) -> float | None:
        try:
            return os.stat(self._path).st_mtime
        except OSError:
            return None

    @property
    def enabled(self) -> bool:
        return bool(self._entries) or self._path is not None

    @classmethod
    def from_env(cls) -> "AuthConfig":
        path = os.environ.get(ENV_FILE, "").strip() or None
        if path:
            with open(path) as fh:
                return cls(_parse_file(fh.read()), path=path)
        raw = os.environ.get(ENV_KEYS, "").strip()
        if raw:
            return cls(_parse_env(raw))
        return cls([])

    def _maybe_reload(self) -> None:
        """Hot rotation (D-013a): pick up changes to the mounted keys file."""
        if self._path is None:
            return
        mtime = self._stat()
        if mtime is not None and mtime != self._mtime:
            # advance the marker first: a broken rewrite is reported once,
            # not re-parsed and re-logged on every request (H-A12)
            self._mtime = mtime
            try:
                with open(self._path) as fh:
                    self._entries = _parse_file(fh.read())
                log.info("auth: reloaded %d key(s) from %s",
                         len(self._entries), self._path)
            except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
                log.error("auth: reload of %s failed, keeping previous keys: %s",
                          self._path, exc)

    def grant_for(self, key: str | None) -> Grant | None:
        """Resolve a presented key to its grant; None if unknown/expired."""
        if not key:
            return None
        self._maybe_reload()
        digest = _sha256(key)
        now = datetime.now(timezone.utc)
        for stored, grant in self._entries:
            if hmac.compare_digest(stored, digest) and not grant.expired(now):
                return grant
        return None

    def allows(self, key: str | None, namespace: str, action: str) -> bool:
        if not self.enabled:
            return True
        grant = self.grant_for(key)
        return grant is not None and grant.allows(namespace, action)


def extract_key(headers) -> str | None:
    """Pull the API key from X-Loom-Key or an Authorization: Bearer header."""
    key = headers.get("x-loom-key")
    if key:
        return key
    authz = headers.get("authorization", "")
    if authz.lower().startswith("bearer "):
        return authz[7:].strip() or None
    return None
