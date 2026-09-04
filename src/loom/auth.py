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


def _parse_file(raw: str) -> list[tuple[str, Grant]]:
    data = json.loads(raw)
    entries: list[tuple[str, Grant]] = []
    for item in data.get("keys", []):
        if item.get("disabled"):
            continue
        expires = item.get("expires")
        entries.append((
            item["sha256"].lower(),
            Grant(
                id=item["id"],
                namespaces=tuple(item["namespaces"]),
                perms=item["perms"],
                entity_types=(
                    tuple(item["entity_types"])
                    if item.get("entity_types") is not None else None
                ),
                sources=(
                    tuple(item["sources"])
                    if item.get("sources") is not None else None
                ),
                expires=datetime.fromisoformat(expires) if expires else None,
            ),
        ))
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
            try:
                with open(self._path) as fh:
                    self._entries = _parse_file(fh.read())
                self._mtime = mtime
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
