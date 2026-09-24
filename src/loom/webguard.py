"""Browser-facing guards for the HTTP surfaces (D-059).

A Loom in open dev mode (no keys) on localhost is still reachable from any
web page the operator's browser opens. Two browser tricks turn that into
reads and writes:

* **Cross-site simple requests** — a page may POST `text/plain`, a form
  encoding, or a typeless Blob to any origin without a CORS preflight. A
  route that parses the raw body as JSON regardless of Content-Type (the
  batch route did) is writable from every tab. Fix: mutating `/v1` routes
  take JSON-family media types only (`415` otherwise) — those always need
  a preflight, which Loom never grants — and a request that carries a
  foreign `Origin` is refused outright.
* **DNS rebinding** — `evil.example` re-resolves to 127.0.0.1, so the page
  becomes *same-origin* with the local Loom and may read and write freely.
  The one thing it cannot change is the `Host` header, which names the
  attacker's domain. Fix: a Host allowlist.

The Host policy, `LOOM_ALLOWED_HOSTS` (comma-separated), *extends* a default
that is safe by construction and covers every shipped deployment shape:

* IP literals (`127.0.0.1`, `[::1]`, a pod IP a kubelet probe uses) and
  `localhost` / `*.localhost` — a rebinding page's Host is always the
  attacker's domain name, never one of these;
* single-label names (`loom`, `loom-gateway`, `mcp`: compose service names,
  same-namespace k8s Services) — public DNS cannot hand a browser those;
* cluster-internal suffixes: `*.svc`, `*.svc.cluster.local`,
  `*.cluster.local`, `*.internal`.

Anything else — the public name you put in front of Loom — must be listed:
`LOOM_ALLOWED_HOSTS=loom.example.com,*.corp.example.com`. `*` turns the
Host check off (only behind a proxy that validates Host itself). Ports are
ignored. `LOOM_ALLOWED_ORIGINS` lists browser origins
(`https://app.example.com`) allowed to call Loom cross-origin; by default
only loopback origins (`http://localhost:*`, as the MCP SDK allows, for
local tools such as the MCP Inspector) and same-origin requests pass.
Non-browser clients send no Origin and are unaffected.

The engine, the MCP HTTP transports and (in Go, same env) the gateway apply
the same policy.
"""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import urlsplit

ENV_HOSTS = "LOOM_ALLOWED_HOSTS"
ENV_ORIGINS = "LOOM_ALLOWED_ORIGINS"

DEFAULT_SUFFIXES = (".localhost", ".svc", ".svc.cluster.local", ".cluster.local", ".internal")
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})

# Media types a body-carrying /v1 request may declare. Every one of them is
# outside the CORS "simple request" set, so a cross-site page must preflight
# first — and Loom answers no preflight.
_JSON_TYPES = frozenset({
    "application/json", "application/x-ndjson", "application/ndjson",
    "application/x-ldjson", "application/jsonl", "application/x-jsonlines",
    "application/jsonlines",
})
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})


def is_json_media_type(content_type: str | None) -> bool:
    """application/json, a `+json` suffix type, or an NDJSON spelling —
    what every Loom client and the supported log shippers send."""
    if not content_type:
        return False
    media = content_type.split(";", 1)[0].strip().lower()
    return media in _JSON_TYPES or (media.startswith("application/") and media.endswith("+json"))


def _split_host(value: str) -> str:
    """The hostname of a Host header value (port dropped, brackets off,
    lowercased, trailing dot removed)."""
    value = value.strip().lower()
    if value.startswith("["):                      # [::1]:8000
        end = value.find("]")
        return value[1:end] if end > 0 else value
    if value.count(":") == 1:                      # name:port / v4:port
        value = value.split(":", 1)[0]
    return value.rstrip(".")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class HostPolicy:
    any_host: bool = False
    exact: frozenset[str] = frozenset()
    suffixes: tuple[str, ...] = DEFAULT_SUFFIXES
    origins: frozenset[str] = frozenset()
    any_origin: bool = False

    @classmethod
    def parse(cls, hosts: str = "", origins: str = "") -> "HostPolicy":
        exact: set[str] = set()
        suffixes = list(DEFAULT_SUFFIXES)
        any_host = False
        for entry in (e.strip().lower() for e in hosts.split(",")):
            if not entry:
                continue
            if entry == "*":
                any_host = True
            elif entry.startswith("*."):
                suffixes.append(entry[1:])
            elif entry.startswith("."):
                suffixes.append(entry)
            else:
                exact.add(_split_host(entry))
        allowed_origins: set[str] = set()
        any_origin = False
        for entry in (e.strip() for e in origins.split(",")):
            if entry == "*":
                any_origin = True
            elif entry:
                allowed_origins.add(entry.rstrip("/").lower())
        return cls(any_host=any_host, exact=frozenset(exact), suffixes=tuple(suffixes),
                   origins=frozenset(allowed_origins), any_origin=any_origin)

    @classmethod
    def from_env(cls) -> "HostPolicy":
        return _cached_policy(os.environ.get(ENV_HOSTS, ""), os.environ.get(ENV_ORIGINS, ""))

    def allows_host(self, header: str | None) -> bool:
        """A missing Host (HTTP/1.0 tooling) is allowed: no browser sends
        one, so it is not a rebinding vector."""
        if self.any_host or not header:
            return True
        host = _split_host(header)
        if not host or host == "localhost" or _is_ip(host) or host in self.exact:
            return True
        if "." not in host:
            return True                                # single-label service name
        return any(host.endswith(s) for s in self.suffixes)

    def allows_origin(self, origin: str | None, host_header: str | None) -> bool:
        """No Origin = not a cross-site browser request. `null` (sandboxed
        frames, file://) is foreign. Same-origin passes; others must be
        listed."""
        if origin is None or self.any_origin:
            return True
        origin = origin.strip().rstrip("/").lower()
        if origin in self.origins:
            return True
        if origin == "null":
            return False
        parts = urlsplit(origin)
        if parts.scheme in ("http", "https") and parts.hostname in _LOOPBACK:
            return True                                # local tools (the MCP Inspector)
        return bool(host_header) and bool(parts.netloc) and parts.netloc == host_header.strip().lower()


@lru_cache(maxsize=8)
def _cached_policy(hosts: str, origins: str) -> HostPolicy:
    return HostPolicy.parse(hosts, origins)


async def _reject(send, status: int, detail: str) -> None:
    body = json.dumps({"detail": detail}).encode()
    await send({"type": "http.response.start", "status": status, "headers": [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
        (b"cache-control", b"no-store"),
    ]})
    await send({"type": "http.response.body", "body": body})


def _headers(scope) -> dict[str, str]:
    return {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers") or []}


class BrowserGuard:
    """Pure ASGI, outermost on every Loom HTTP app. Rejects, in order: a
    Host outside the policy (400 — every path, probes included: they use
    IPs or localhost), a foreign Origin (403), and — on body-carrying
    methods under `body_prefix` — a non-JSON Content-Type (415). Nothing
    here reads a body. `policy=None` reads the env on each request (cached
    per value), so tests and hot env changes see the current dials."""

    def __init__(self, app, policy: HostPolicy | None = None, body_prefix: str | None = "/v1/",
                 check_content_type: bool = True, metric=None):
        self.app = app
        self._policy = policy
        self.body_prefix = body_prefix
        self.check_content_type = check_content_type
        self._metric = metric

    def _count(self, reason: str) -> None:
        if self._metric is not None:
            self._metric.labels(reason=reason).inc()

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        policy = self._policy or HostPolicy.from_env()
        headers = _headers(scope)
        host = headers.get("host")
        if not policy.allows_host(host):
            self._count("host")
            return await _reject(send, 400, "invalid Host header: add this name to "
                                 f"{ENV_HOSTS} if Loom is served under it")
        if not policy.allows_origin(headers.get("origin"), host):
            self._count("origin")
            return await _reject(send, 403, "cross-origin browser requests are not allowed: "
                                 f"list the origin in {ENV_ORIGINS} to permit it")
        if (self.check_content_type and scope["type"] == "http"
                and scope.get("method", "GET") in _BODY_METHODS
                and (self.body_prefix is None or scope.get("path", "").startswith(self.body_prefix))
                and not is_json_media_type(headers.get("content-type"))):
            self._count("content_type")
            return await _reject(send, 415, "Content-Type must be application/json "
                                 "(or application/x-ndjson on /v1/ingest/batch)")
        await self.app(scope, receive, send)
