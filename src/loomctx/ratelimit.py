"""Engine-side per-grant rate limiting (hardening R-10).

The Go gateway sheds abusive senders before the queue; in the default,
no-gateway shape nothing bounded a valid reader, and `/v1/answer` turns
every request into LLM spend. This module mirrors the gateway's model:

* authentication first — buckets are keyed by the **grant id**, never by
  the raw header value, so an unauthenticated caller cannot mint a fresh
  bucket per request by rotating bogus keys; a bad key is passed through
  untouched and the route itself answers 401/403;
* one token bucket per principal, refilled continuously, bounded map with
  eviction of the least recently used bucket as a belt-and-braces guard;
* a second, stricter bucket per principal for the routes that spend LLM /
  embedder budget (`/v1/answer`, `/v1/entities/semantic`).

Dials (unset = unlimited, so dev mode is unchanged):

    LOOMCTX_RATE_PER_SEC        requests/second per grant on every /v1 route
    LOOMCTX_RATE_BURST          bucket size (default: ceil(LOOMCTX_RATE_PER_SEC))
    LOOMCTX_RATE_LLM_PER_SEC    requests/second per grant on the LLM routes
    LOOMCTX_RATE_LLM_BURST      bucket size for the LLM routes (default: ceil(rate))

A key's grant may override the defaults (`rate_per_sec`, `rate_burst`,
`rate_llm_per_sec` in the keys file, `python -m loomctx.keys generate
--rate-per-sec ...`). An override applies even when the global dials are
unset: "unlimited by default, this key is capped". The Go gateway reads
the same fields, so one keys file serves both.

With auth disabled (open dev mode) the dials, when set, apply per client
IP; unset, nothing is limited. `/healthz`, `/readyz` and `/metrics` are
never limited (probes and scrapes).

A rejection is a 429 with `Retry-After` (whole seconds, at least 1) and
counts on `loomctx_requests_rejected_total{reason="rate"}`.

A batch of *n* envelopes costs *n* tokens, as on the gateway: the door
takes one before the body is read, and `/v1/ingest/batch` takes the other
n-1 once it has counted the items (`charge_batch`, reached through
`scope[SCOPE_KEY]`). A batch larger than the bucket can never pass and is
refused with 413 — retrying cannot help; split it or raise the burst.

Buckets live in the process. The effective ceiling for one key is the rate
× uvicorn workers (LOOMCTX_WORKERS) × engine replicas; size the dials for
that, or rate-limit at a shared ingress when the bound must be exact.

Wired as a pure-ASGI middleware: `app.add_middleware(RateLimitMiddleware)`.
"""

from __future__ import annotations

import json
import math
import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable

from .auth import Grant, extract_key
from .metrics import REJECTED

ENV_RATE = "LOOMCTX_RATE_PER_SEC"
ENV_BURST = "LOOMCTX_RATE_BURST"
ENV_LLM_RATE = "LOOMCTX_RATE_LLM_PER_SEC"
ENV_LLM_BURST = "LOOMCTX_RATE_LLM_BURST"

MAX_BUCKETS = 10_000                    # same bound as the gateway's pool
SCOPE_KEY = "loomctx.ratelimit"            # the middleware, for routes that charge extra
LLM_PATHS = frozenset({"/v1/answer", "/v1/entities/semantic"})
_EXEMPT = ("/healthz", "/readyz", "/metrics")


def _env_float(name: str) -> float | None:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {raw!r}") from exc
    if not math.isfinite(value):
        raise ValueError(f"{name} must be a finite number, got {raw!r}")
    return value if value > 0 else None


def _env_int(name: str) -> int | None:
    value = _env_float(name)
    return None if value is None else max(1, int(value))


def default_burst(per_sec: float) -> int:
    """The gateway sizes a bucket as int(rate); a fractional rate (one
    request every few seconds) still needs room for one request."""
    return max(1, math.ceil(per_sec))


@dataclass(frozen=True)
class Limit:
    per_sec: float
    burst: int


@dataclass(frozen=True)
class RateLimitSettings:
    """The global dials. None = that limit is off."""

    per_sec: float | None = None
    burst: int | None = None
    llm_per_sec: float | None = None
    llm_burst: int | None = None

    @classmethod
    def from_env(cls) -> "RateLimitSettings":
        return cls(per_sec=_env_float(ENV_RATE), burst=_env_int(ENV_BURST),
                   llm_per_sec=_env_float(ENV_LLM_RATE), llm_burst=_env_int(ENV_LLM_BURST))

    def general(self, grant: Grant | None) -> Limit | None:
        """A key's rate override brings its own burst (its `rate_burst`, or
        the default for that rate) — never the global burst sized for a
        different rate; a burst-only override rides on the global rate."""
        override = grant is not None and grant.rate_per_sec is not None
        per_sec = grant.rate_per_sec if override else self.per_sec
        if per_sec is None:
            return None
        if grant is not None and grant.rate_burst is not None:
            burst = grant.rate_burst
        else:
            burst = default_burst(per_sec) if override or self.burst is None else self.burst
        return Limit(per_sec, burst)

    def llm(self, grant: Grant | None) -> Limit | None:
        per_sec = self.llm_per_sec
        if grant is not None and grant.rate_llm_per_sec is not None:
            per_sec = grant.rate_llm_per_sec
        if per_sec is None:
            return None
        burst = self.llm_burst if self.llm_burst is not None else default_burst(per_sec)
        return Limit(per_sec, burst)


class _Bucket:
    __slots__ = ("limit", "tokens", "stamp")

    def __init__(self, limit: Limit, now: float):
        self.limit = limit
        self.tokens = float(limit.burst)
        self.stamp = now

    def _refill(self, now: float) -> None:
        elapsed = max(0.0, now - self.stamp)
        self.stamp = now
        self.tokens = min(float(self.limit.burst), self.tokens + elapsed * self.limit.per_sec)

    def retune(self, limit: Limit) -> None:
        """A hot-reloaded override changes a live bucket in place; the
        balance is kept (capped to the new burst) so a tightened key cannot
        cash in an old, larger allowance."""
        if limit != self.limit:
            self.limit = limit
            self.tokens = min(self.tokens, float(limit.burst))

    def take(self, now: float, n: int = 1) -> bool:
        self._refill(now)
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False

    def retry_after(self, now: float, n: int = 1) -> int:
        """Whole seconds until `n` tokens are available (at least 1)."""
        self._refill(now)
        missing = n - self.tokens
        if missing <= 0:
            return 1
        return max(1, math.ceil(missing / self.limit.per_sec))


class LimiterPool:
    """Buckets keyed by principal, bounded, least-recently-used eviction.
    Thread-safe: the engine serves sync routes from a thread pool."""

    def __init__(self, max_buckets: int = MAX_BUCKETS, clock: Callable[[], float] = time.monotonic):
        self._buckets: OrderedDict[str, _Bucket] = OrderedDict()
        self._max = max_buckets
        self._clock = clock
        self._lock = threading.Lock()

    def size(self) -> int:
        with self._lock:
            return len(self._buckets)

    def _bucket(self, key: str, limit: Limit, now: float) -> _Bucket:
        bucket = self._buckets.get(key)
        if bucket is None:
            while len(self._buckets) >= self._max:
                self._buckets.popitem(last=False)
            bucket = _Bucket(limit, now)
            self._buckets[key] = bucket
        else:
            bucket.retune(limit)
            self._buckets.move_to_end(key)
        return bucket

    def allow(self, key: str, limit: Limit, n: int = 1) -> tuple[bool, int]:
        """(allowed, retry_after_seconds). A request larger than the burst
        can never pass; it is refused with the time one token takes."""
        now = self._clock()
        with self._lock:
            bucket = self._bucket(key, limit, now)
            if n > limit.burst:
                return False, bucket.retry_after(now, 1)
            if bucket.take(now, n):
                return True, 0
            return False, bucket.retry_after(now, n)


class RateLimitMiddleware:
    """Pure ASGI. Sits outside the routes; `scope["app"].state.auth` (the
    engine's AuthConfig) resolves the principal, so the limiter and the
    routes agree on who is calling. Without an auth config on the app it
    behaves as open dev mode."""

    def __init__(self, app, settings: RateLimitSettings | None = None,
                 clock: Callable[[], float] = time.monotonic, max_buckets: int = MAX_BUCKETS):
        self.app = app
        self._settings = settings          # None: read the env on first use
        self.general = LimiterPool(max_buckets, clock)
        self.llm = LimiterPool(max_buckets, clock)

    @property
    def settings(self) -> RateLimitSettings:
        if self._settings is None:
            self._settings = RateLimitSettings.from_env()
        return self._settings

    @staticmethod
    def _client_ip(scope) -> str:
        client = scope.get("client")
        return client[0] if client else "unknown"

    def _principal(self, scope) -> tuple[str | None, Grant | None]:
        """(bucket key, grant). (None, None) = do not limit: the caller is
        unauthenticated and the route will reject it itself."""
        app = scope.get("app")
        auth = getattr(getattr(app, "state", None), "auth", None)
        if auth is None or not auth.enabled:
            return self._client_ip(scope), None
        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers") or []}
        grant = auth.grant_for(extract_key(headers))
        if grant is None:
            return None, None
        return grant.id, grant

    def decide(self, scope) -> int | None:
        """Retry-After seconds if this request is over budget, else None."""
        key, grant = self._principal(scope)
        if key is None:
            return None
        settings = self.settings
        limit = settings.general(grant)
        if limit is not None:
            allowed, retry = self.general.allow(key, limit)
            if not allowed:
                return retry
        if scope.get("path", "") in LLM_PATHS:
            limit = settings.llm(grant)
            if limit is not None:
                allowed, retry = self.llm.allow(key, limit)
                if not allowed:
                    return retry
        return None

    def charge_batch(self, scope, n: int) -> tuple[int, str, int] | None:
        """Charge the rest of a batch's cost (the door took one token).
        None = allowed; else (status, detail, retry_after)."""
        key, grant = self._principal(scope)
        limit = self.settings.general(grant) if key is not None else None
        if limit is None:
            return None
        if n > limit.burst:
            return (413, f"batch of {n} items exceeds this key's rate burst of {limit.burst}; "
                    "send smaller batches or raise rate_burst / LOOMCTX_RATE_BURST", 0)
        if n <= 1:
            return None
        allowed, retry = self.general.allow(key, limit, n - 1)
        return None if allowed else (429, "rate limit exceeded", retry)

    async def __call__(self, scope, receive, send):
        path = scope.get("path", "") if scope["type"] == "http" else ""
        if scope["type"] != "http" or not path.startswith("/v1/") or path.startswith(_EXEMPT):
            return await self.app(scope, receive, send)
        retry = self.decide(scope)
        if retry is None:
            scope[SCOPE_KEY] = self
            return await self.app(scope, receive, send)
        REJECTED.labels(reason="rate").inc()
        body = json.dumps({"detail": "rate limit exceeded"}).encode()
        await send({"type": "http.response.start", "status": 429, "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"retry-after", str(retry).encode()),
            (b"cache-control", b"no-store"),
        ]})
        await send({"type": "http.response.body", "body": body})
