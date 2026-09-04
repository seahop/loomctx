"""Per-namespace API keys (D-013).

Configuration is one env var, identical for the engine and the Go gateway:

    LOOM_API_KEYS="<key>:<namespace>:<perms>[,<key>:<namespace>:<perms>...]"

- perms is "r", "w", or "rw"
- namespace "*" grants the key every namespace
- the same key may appear in several entries (one per namespace)

Example — an ingesting agent, a read-only dashboard, and an admin key:

    LOOM_API_KEYS="agentsecret:netsec:w,dashsecret:netsec:r,rootsecret:*:rw"

Unset => auth is DISABLED (open dev mode; the engine logs a warning once).
Callers present the key as `X-Loom-Key: <key>` or `Authorization: Bearer`.
Key comparison is constant-time.
"""

from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass

log = logging.getLogger("loom.auth")

ENV_VAR = "LOOM_API_KEYS"


@dataclass(frozen=True)
class _Entry:
    key: str
    namespace: str
    perms: str


class AuthConfig:
    def __init__(self, entries: list[_Entry]):
        self._entries = entries

    @property
    def enabled(self) -> bool:
        return bool(self._entries)

    @classmethod
    def from_env(cls) -> "AuthConfig":
        raw = os.environ.get(ENV_VAR, "").strip()
        if not raw:
            return cls([])
        entries: list[_Entry] = []
        for item in raw.split(","):
            item = item.strip()
            if not item:
                continue
            parts = item.split(":")
            if len(parts) != 3 or not all(parts):
                raise ValueError(
                    f"{ENV_VAR}: bad entry {item!r} — expected key:namespace:perms"
                )
            key, namespace, perms = parts
            if not set(perms) <= {"r", "w"}:
                raise ValueError(
                    f"{ENV_VAR}: perms must be r, w or rw, got {perms!r}"
                )
            entries.append(_Entry(key=key, namespace=namespace, perms=perms))
        return cls(entries)

    def allows(self, key: str | None, namespace: str, action: str) -> bool:
        """action is 'r' or 'w'. Open (True for everything) when disabled."""
        if not self.enabled:
            return True
        if not key:
            return False
        for entry in self._entries:
            # constant-time on the secret; namespace/action checks are public
            if not secrets.compare_digest(entry.key, key):
                continue
            if entry.namespace not in ("*", namespace):
                continue
            if action in entry.perms:
                return True
        return False


def extract_key(headers) -> str | None:
    """Pull the API key from X-Loom-Key or an Authorization: Bearer header."""
    key = headers.get("x-loom-key")
    if key:
        return key
    authz = headers.get("authorization", "")
    if authz.lower().startswith("bearer "):
        return authz[7:].strip() or None
    return None
