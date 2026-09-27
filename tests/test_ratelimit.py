"""Engine-side per-grant rate limiting (hardening R-10).

The middleware is exercised around a stub app that authenticates the way
LoomCtx's routes do (X-LoomCtx-Key / Bearer resolved through app.state.auth), so
the tests pin the *contract* — auth first, buckets per grant id, never a
bucket for a bad key, LLM routes on their own budget, 429 + Retry-After —
without depending on the engine's routes."""

import json

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from loomctx import metrics
from loomctx.auth import AuthConfig, Grant, _parse_file, _sha256, extract_key
from loomctx.ratelimit import (Limit, LimiterPool, RateLimitMiddleware,
                            RateLimitSettings, default_burst)


class Clock:
    def __init__(self, now: float = 1000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def tick(self, seconds: float) -> None:
        self.now += seconds


def _auth(*grants: Grant, keys: dict[str, str] | None = None) -> AuthConfig:
    """An AuthConfig whose plaintext keys are `<grant id>-secret`."""
    entries = [(_sha256(f"{g.id}-secret"), g) for g in grants]
    return AuthConfig(entries)


def make_app(auth: AuthConfig | None, settings: RateLimitSettings, clock: Clock,
             max_buckets: int = 10_000) -> tuple[FastAPI, RateLimitMiddleware]:
    app = FastAPI()
    if auth is not None:
        app.state.auth = auth

    def authorize(request: Request) -> None:
        cfg = getattr(request.app.state, "auth", None)
        if cfg is None or not cfg.enabled:
            return
        key = extract_key(request.headers)
        if key is None:
            raise HTTPException(status_code=401, detail="missing API key")
        if cfg.grant_for(key) is None:
            raise HTTPException(status_code=403, detail="unknown key")

    @app.post("/v1/ask")
    def ask(request: Request):
        authorize(request)
        return {"items": []}

    @app.post("/v1/answer")
    def answer(request: Request):
        authorize(request)
        return {"answer": "42"}

    @app.get("/v1/entities/semantic")
    def semantic(request: Request):
        authorize(request)
        return {"matches": []}

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    holder: dict[str, RateLimitMiddleware] = {}

    def factory(inner):
        holder["mw"] = RateLimitMiddleware(inner, settings=settings, clock=clock,
                                           max_buckets=max_buckets)
        return holder["mw"]

    app.add_middleware(factory)
    # Starlette builds the stack lazily on the first request (and
    # build_middleware_stack() only *returns* it): assign it now so the
    # instance the test inspects is the one serving requests
    app.middleware_stack = app.build_middleware_stack()
    return app, holder["mw"]


READER = Grant(id="reader", namespaces=("*",), perms="r")
OTHER = Grant(id="other", namespaces=("*",), perms="r")
CAPPED = Grant(id="capped", namespaces=("*",), perms="r", rate_per_sec=1.0, rate_burst=1)


def _rejected_rate() -> float:
    return metrics.REJECTED.labels(reason="rate")._value.get()


# ------------------------------------------------------------ the bucket #

def test_bucket_burst_refill_and_retry_after():
    clock = Clock()
    pool = LimiterPool(clock=clock)
    limit = Limit(per_sec=2.0, burst=3)
    assert [pool.allow("k", limit)[0] for _ in range(3)] == [True, True, True]
    allowed, retry = pool.allow("k", limit)
    assert not allowed and retry == 1                 # half a second rounds up to 1
    clock.tick(0.5)                                   # one token back
    assert pool.allow("k", limit) == (True, 0)
    assert not pool.allow("k", limit)[0]
    clock.tick(10)                                    # never above the burst
    assert [pool.allow("k", limit)[0] for _ in range(4)] == [True, True, True, False]
    # a slow key: one request every 10 s -> Retry-After counts the wait
    slow = Limit(per_sec=0.1, burst=1)
    assert pool.allow("slow", slow)[0]
    assert pool.allow("slow", slow) == (False, 10)
    # a request bigger than the burst can never pass and says so at once
    assert pool.allow("k", limit, n=4)[0] is False


def test_pool_is_bounded_with_lru_eviction():
    clock = Clock()
    pool = LimiterPool(max_buckets=3, clock=clock)
    limit = Limit(per_sec=1.0, burst=1)
    for key in ("a", "b", "c"):
        pool.allow(key, limit)
    pool.allow("a", limit)                            # touch a: b is now the oldest
    pool.allow("d", limit)                            # evicts b
    assert pool.size() == 3
    assert not pool.allow("a", limit)[0]              # a kept its empty bucket
    assert pool.allow("b", limit)[0]                  # b was evicted -> fresh bucket


def test_settings_resolution_and_env(monkeypatch):
    assert default_burst(0.2) == 1 and default_burst(2.5) == 3
    for name in ("LOOMCTX_RATE_PER_SEC", "LOOMCTX_RATE_BURST", "LOOMCTX_RATE_LLM_PER_SEC", "LOOMCTX_RATE_LLM_BURST"):
        monkeypatch.delenv(name, raising=False)
    off = RateLimitSettings.from_env()
    assert off.general(None) is None and off.llm(None) is None       # dev mode: unlimited
    assert off.general(READER) is None
    assert off.general(CAPPED) == Limit(1.0, 1)                       # an override caps a key anyway
    monkeypatch.setenv("LOOMCTX_RATE_PER_SEC", "10")
    monkeypatch.setenv("LOOMCTX_RATE_BURST", "40")
    monkeypatch.setenv("LOOMCTX_RATE_LLM_PER_SEC", "0.5")
    on = RateLimitSettings.from_env()
    assert on.general(None) == Limit(10.0, 40)
    assert on.general(READER) == Limit(10.0, 40)
    assert on.general(CAPPED) == Limit(1.0, 1)
    # a rate-only override brings its own default burst, never the global 40
    assert on.general(Grant(id="x", namespaces=("*",), perms="r", rate_per_sec=2.5)) == Limit(2.5, 3)
    # a burst-only override rides on the global rate
    assert on.general(Grant(id="y", namespaces=("*",), perms="r", rate_burst=5)) == Limit(10.0, 5)
    assert on.llm(READER) == Limit(0.5, 1)
    assert on.llm(Grant(id="z", namespaces=("*",), perms="r", rate_llm_per_sec=3)) == Limit(3.0, 3)
    monkeypatch.setenv("LOOMCTX_RATE_PER_SEC", "0")                       # 0 = off, like the gateway
    assert RateLimitSettings.from_env().general(READER) is None
    monkeypatch.setenv("LOOMCTX_RATE_PER_SEC", "lots")
    with pytest.raises(ValueError):
        RateLimitSettings.from_env()


# ------------------------------------------------------ the middleware #

def test_burst_then_429_then_refill_per_grant():
    clock = Clock()
    app, mw = make_app(_auth(READER, OTHER), RateLimitSettings(per_sec=1.0, burst=2), clock)
    before = _rejected_rate()
    with TestClient(app) as client:
        reader = {"X-LoomCtx-Key": "reader-secret"}
        assert client.post("/v1/ask", headers=reader).status_code == 200
        assert client.post("/v1/ask", headers=reader).status_code == 200
        r = client.post("/v1/ask", headers=reader)
        assert r.status_code == 429
        assert r.headers["retry-after"] == "1"
        assert r.headers["cache-control"] == "no-store"
        assert r.json() == {"detail": "rate limit exceeded"}
        assert _rejected_rate() == before + 1
        # another principal has its own bucket (a Bearer header resolves too)
        assert client.post("/v1/ask", headers={"Authorization": "Bearer other-secret"}).status_code == 200
        # refill: one token per second
        clock.tick(1.0)
        assert client.post("/v1/ask", headers=reader).status_code == 200
        assert client.post("/v1/ask", headers=reader).status_code == 429
        # probes are never limited
        assert client.get("/healthz").status_code == 200
    assert mw.general.size() == 2


def test_no_bucket_for_a_bad_or_missing_key():
    clock = Clock()
    app, mw = make_app(_auth(READER), RateLimitSettings(per_sec=1.0, burst=1), clock)
    with TestClient(app) as client:
        for i in range(20):
            r = client.post("/v1/ask", headers={"X-LoomCtx-Key": f"bogus-{i}"})
            assert r.status_code == 403                # the route rejects it, not the limiter
        assert client.post("/v1/ask").status_code == 401
        assert mw.general.size() == 0
        assert client.post("/v1/ask", headers={"X-LoomCtx-Key": "reader-secret"}).status_code == 200
        assert mw.general.size() == 1


def test_per_key_override_beats_the_defaults_and_applies_without_them():
    clock = Clock()
    # generous defaults, one capped key
    app, _ = make_app(_auth(READER, CAPPED), RateLimitSettings(per_sec=100.0, burst=100), clock)
    with TestClient(app) as client:
        capped = {"X-LoomCtx-Key": "capped-secret"}
        assert client.post("/v1/ask", headers=capped).status_code == 200
        assert client.post("/v1/ask", headers=capped).status_code == 429
        for _ in range(10):
            assert client.post("/v1/ask", headers={"X-LoomCtx-Key": "reader-secret"}).status_code == 200
    # no defaults at all (dev-like), the override still caps that key
    app, mw = make_app(_auth(READER, CAPPED), RateLimitSettings(), clock)
    with TestClient(app) as client:
        for _ in range(10):
            assert client.post("/v1/ask", headers={"X-LoomCtx-Key": "reader-secret"}).status_code == 200
        assert client.post("/v1/ask", headers={"X-LoomCtx-Key": "capped-secret"}).status_code == 200
        assert client.post("/v1/ask", headers={"X-LoomCtx-Key": "capped-secret"}).status_code == 429
    assert mw.general.size() == 1                      # only the capped key holds a bucket


def test_override_from_a_keys_file_is_parsed_and_hot_retuned():
    doc = {"keys": [
        {"id": "a", "sha256": _sha256("a-secret"), "namespaces": ["*"], "perms": "r",
         "rate_per_sec": 2, "rate_burst": 4, "rate_llm_per_sec": 0.25},
        {"id": "b", "sha256": _sha256("b-secret"), "namespaces": ["*"], "perms": "r"},
        # zero is not "unlimited": that entry is skipped, the file still loads
        {"id": "bad", "sha256": _sha256("bad-secret"), "namespaces": ["*"], "perms": "r",
         "rate_per_sec": 0},
        {"id": "worse", "sha256": _sha256("worse-secret"), "namespaces": ["*"], "perms": "r",
         "rate_burst": "many"},
    ]}
    entries = _parse_file(json.dumps(doc))
    grants = {g.id: g for _, g in entries}
    assert set(grants) == {"a", "b"}
    assert (grants["a"].rate_per_sec, grants["a"].rate_burst, grants["a"].rate_llm_per_sec) == (2.0, 4, 0.25)
    assert (grants["b"].rate_per_sec, grants["b"].rate_burst, grants["b"].rate_llm_per_sec) == (None, None, None)

    clock = Clock()
    auth = AuthConfig(entries)
    app, _ = make_app(auth, RateLimitSettings(), clock)
    with TestClient(app) as client:
        a = {"X-LoomCtx-Key": "a-secret"}
        assert [client.post("/v1/ask", headers=a).status_code for _ in range(5)] == [200] * 4 + [429]
        # the operator tightens the key (hot reload): the live bucket is
        # retuned, the old balance is capped, nothing restarts
        auth._entries = [(h, Grant(id="a", namespaces=("*",), perms="r", rate_per_sec=1, rate_burst=1))
                         if g.id == "a" else (h, g) for h, g in entries]
        clock.tick(100)                                # would have refilled 4 under the old cap
        assert client.post("/v1/ask", headers=a).status_code == 200
        assert client.post("/v1/ask", headers=a).status_code == 429


def test_llm_routes_have_their_own_stricter_bucket():
    clock = Clock()
    settings = RateLimitSettings(per_sec=10.0, burst=10, llm_per_sec=1.0, llm_burst=1)
    app, mw = make_app(_auth(READER), settings, clock)
    with TestClient(app) as client:
        reader = {"X-LoomCtx-Key": "reader-secret"}
        assert client.post("/v1/answer", headers=reader).status_code == 200
        r = client.post("/v1/answer", headers=reader)
        assert r.status_code == 429 and r.headers["retry-after"] == "1"
        # the general budget is untouched by the LLM rejection beyond the
        # one token the attempt cost: plenty of ordinary asks still pass
        for _ in range(7):
            assert client.post("/v1/ask", headers=reader).status_code == 200
        # semantic search shares the LLM bucket (embedder spend)
        assert client.get("/v1/entities/semantic", headers=reader).status_code == 429
        clock.tick(1.0)
        assert client.get("/v1/entities/semantic", headers=reader).status_code == 200
    assert mw.llm.size() == 1 and mw.general.size() == 1

    # a per-key LLM override, with no global LLM dial
    keyed = Grant(id="agent", namespaces=("*",), perms="r", rate_llm_per_sec=1.0)
    app, _ = make_app(_auth(keyed, READER), RateLimitSettings(), clock)
    with TestClient(app) as client:
        agent = {"X-LoomCtx-Key": "agent-secret"}
        assert client.post("/v1/answer", headers=agent).status_code == 200
        assert client.post("/v1/answer", headers=agent).status_code == 429
        assert client.post("/v1/answer", headers={"X-LoomCtx-Key": "reader-secret"}).status_code == 200
        assert client.post("/v1/ask", headers=agent).status_code == 200   # general is unlimited


def test_open_dev_mode_limits_per_client_ip_only_when_dialled():
    clock = Clock()
    app, mw = make_app(None, RateLimitSettings(), clock)             # no auth, no dials
    with TestClient(app) as client:
        for _ in range(20):
            assert client.post("/v1/ask").status_code == 200
    assert mw.general.size() == 0

    app, mw = make_app(AuthConfig([]), RateLimitSettings(per_sec=1.0, burst=1), clock)
    with TestClient(app) as client:
        assert client.post("/v1/ask").status_code == 200
        assert client.post("/v1/ask").status_code == 429
    assert mw.general.size() == 1                      # one bucket for the test client's IP


def test_middleware_reads_the_env_lazily(monkeypatch):
    monkeypatch.setenv("LOOMCTX_RATE_PER_SEC", "1")
    monkeypatch.setenv("LOOMCTX_RATE_BURST", "1")
    clock = Clock()
    app = FastAPI()
    app.state.auth = AuthConfig([])

    @app.post("/v1/ask")
    def ask():
        return {}

    app.add_middleware(RateLimitMiddleware, clock=clock)
    with TestClient(app) as client:
        assert client.post("/v1/ask").status_code == 200
        assert client.post("/v1/ask").status_code == 429
