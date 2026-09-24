"""Pluggable LLM access (decisions D-007, D-012).

Nearly every provider — OpenRouter, Venice, Groq, Together, Mistral, OpenAI,
and self-hosted stacks like Ollama, vLLM, LM Studio — speaks the
OpenAI-compatible chat-completions API, so one client covers them all; the
provider shortcut just fills in the base URL. Anthropic's native API gets its
own client. Stdlib-only (urllib): no provider SDKs in the core.

Configuration (environment):
    LOOM_LLM_MODEL      required to enable answering (e.g. "qwen/qwen3-coder",
                        "claude-sonnet-5", "llama3.1:8b")
    LOOM_LLM_PROVIDER   shortcut: openrouter | venice | openai | groq |
                        together | mistral | ollama | anthropic
    LOOM_LLM_BASE_URL   custom/self-hosted endpoint; overrides the shortcut
                        (e.g. "http://my-vllm:8000/v1")
    LOOM_LLM_API_KEY    bearer/API key when the endpoint needs one
"""

from __future__ import annotations

import email.utils
import json
import logging
import os
import random
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod

log = logging.getLogger("loom.llm")

OPENAI_COMPAT_BASES = {
    "openrouter": "https://openrouter.ai/api/v1",
    "venice": "https://api.venice.ai/api/v1",
    "openai": "https://api.openai.com/v1",
    "groq": "https://api.groq.com/openai/v1",
    "together": "https://api.together.xyz/v1",
    "mistral": "https://api.mistral.ai/v1",
    "ollama": "http://localhost:11434/v1",
}


class LLMError(RuntimeError):
    """The provider call failed; the HTTP layer maps this to a 502.

    `public` is the short, safe-to-return form; str(exc) carries the full
    detail (provider body excerpt, URL) for server logs only. `transient`
    marks a failure that says nothing about the request (rate limit, 5xx,
    unreachable — after the retries): an evaluation must not score it as
    the model's answer.
    """

    def __init__(self, message: str, public: str | None = None, transient: bool = False):
        super().__init__(message)
        self.public = public or "LLM provider error (see server logs)"
        self.transient = transient


class LLMClient(ABC):
    model: str
    # Token accounting for the most recent complete(): {"prompt_tokens",
    # "completion_tokens"} as the provider reported them, None when it
    # reported nothing. The enrichment worker logs it per job.
    last_usage: dict[str, int] | None = None

    @abstractmethod
    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        """One system+user exchange; returns the assistant text."""


_RETRYABLE = {408, 409, 425, 429, 500, 502, 503, 504}
_MAX_ATTEMPTS = 3
_MAX_BACKOFF = 8.0          # exponential backoff ceiling (before jitter)
_MAX_RETRY_AFTER = 60.0     # a server-stated Retry-After is honored up to this
_JITTER = 0.25              # ±25 % on the computed backoff


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: a base URL that 30x-ed off-host would carry
    the Authorization / x-api-key header wherever it pointed. The 3xx is
    surfaced as an HTTPError and mapped to LLMError in _post_json."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(_NoRedirect())


def _urlopen(req: urllib.request.Request, timeout: float):
    """The one place provider requests leave the process (tests stub it)."""
    return _opener.open(req, timeout=timeout)


def _retry_after_seconds(value: str | None) -> float | None:
    """Retry-After as delay-seconds or an HTTP-date; None when absent or
    unreadable."""
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if when is None:
        return None
    return max(0.0, when.timestamp() - time.time())


def _post_json(url: str, body: dict, headers: dict, timeout: float = 120,
               attempts: int = _MAX_ATTEMPTS) -> dict:
    """One provider call with bounded retries on transient failures
    (rate limits, 5xx, connection errors), honoring Retry-After up to
    _MAX_RETRY_AFTER (H-D9). Redirects are refused (the credentials would
    follow them); the backoff carries ±25 % jitter so a fleet of workers
    does not retry in lock-step."""
    payload = json.dumps(body).encode()
    last: LLMError | None = None
    for attempt in range(attempts):
        req = urllib.request.Request(
            url, data=payload,
            headers={"content-type": "application/json", **headers},
            method="POST",
        )
        delay = min(_MAX_BACKOFF, 2.0 ** attempt) * random.uniform(1 - _JITTER, 1 + _JITTER)
        try:
            with _urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
            try:
                return json.loads(raw)
            except ValueError as exc:  # e.g. an HTML error page from a proxy with 200
                raise LLMError(f"provider returned non-JSON body: {raw[:200]!r}",
                               public="LLM provider returned a malformed response") from exc
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                target = exc.headers.get("Location") if exc.headers else None
                raise LLMError(
                    f"provider redirected ({exc.code}) {url} -> {target!r}; redirects are "
                    "not followed because the request carries credentials",
                    public="LLM provider endpoint redirected; check LOOM_LLM_BASE_URL",
                ) from exc
            try:
                detail = exc.read()[:500].decode(errors="replace")
            except Exception:  # noqa: BLE001 — a synthetic HTTPError may carry no body
                detail = ""
            # 402 (out of credit) says nothing about the request either —
            # not worth retrying, but never the model's answer in an eval
            last = LLMError(f"provider returned {exc.code}: {detail}",
                            public=f"LLM provider returned HTTP {exc.code}",
                            transient=exc.code in _RETRYABLE or exc.code == 402)
            if exc.code not in _RETRYABLE:
                raise last from exc
            retry_after = _retry_after_seconds(
                exc.headers.get("Retry-After") if exc.headers else None)
            if retry_after is not None:
                delay = min(_MAX_RETRY_AFTER, retry_after)
        except (urllib.error.URLError, TimeoutError) as exc:
            last = LLMError(f"provider unreachable: {exc}",
                            public="LLM provider unreachable", transient=True)
        if attempt + 1 < attempts:
            time.sleep(delay)
    assert last is not None
    raise last


def _usage(data: dict, prompt_key: str, completion_key: str) -> dict[str, int] | None:
    usage = data.get("usage") if isinstance(data, dict) else None
    if not isinstance(usage, dict):
        return None
    try:
        return {"prompt_tokens": int(usage.get(prompt_key) or 0),
                "completion_tokens": int(usage.get(completion_key) or 0)}
    except (TypeError, ValueError):
        return None


class OpenAICompatClient(LLMClient):
    def __init__(self, base_url: str, model: str, api_key: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        headers = {}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        data = _post_json(
            self.base_url + "/chat/completions",
            {
                "model": self.model,
                "max_tokens": max_tokens,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
            headers,
        )
        try:
            choice = data["choices"][0]
            content = choice["message"].get("content")
        except (KeyError, IndexError, TypeError, AttributeError) as exc:
            raise LLMError(f"unexpected provider response shape: {exc}") from exc
        self.last_usage = _usage(data, "prompt_tokens", "completion_tokens")
        if isinstance(content, list):  # some gateways return content parts
            content = "".join(p.get("text", "") for p in content
                              if isinstance(p, dict) and p.get("type", "text") == "text")
        if content is None or not str(content).strip():
            # a null/blank message is a provider hiccup or a filtered reply,
            # never a completion: callers would otherwise pass None onward
            raise LLMError(
                f"empty completion from {self.model} "
                f"(finish_reason={choice.get('finish_reason')!r})",
                public="LLM provider returned an empty completion")
        if choice.get("finish_reason") == "length":
            log.warning("completion from %s truncated at max_tokens=%d", self.model, max_tokens)
        return str(content)


class AnthropicClient(LLMClient):
    def __init__(self, model: str, api_key: str | None,
                 base_url: str | None = None):
        self.base_url = (base_url or "https://api.anthropic.com").rstrip("/")
        self.model = model
        self.api_key = api_key

    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        data = _post_json(
            self.base_url + "/v1/messages",
            {
                "model": self.model,
                "max_tokens": max_tokens,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
            {
                "x-api-key": self.api_key or "",
                "anthropic-version": "2023-06-01",
            },
        )
        blocks = data.get("content") if isinstance(data, dict) else None
        if not isinstance(blocks, list):
            raise LLMError(f"unexpected provider response shape: {str(data)[:200]!r}")
        self.last_usage = _usage(data, "input_tokens", "output_tokens")
        stop = data.get("stop_reason")
        # current models think before they answer: content[0] is a `thinking`
        # block, the text may span several blocks, and a refusal has none
        text = "".join(b.get("text", "") for b in blocks
                       if isinstance(b, dict) and b.get("type") == "text")
        if stop == "refusal":
            details = data.get("stop_details") or {}
            raise LLMError(
                f"{self.model} refused the request (category={details.get('category')!r}): "
                f"{details.get('explanation') or ''}",
                public="LLM provider declined to answer this request")
        if not text.strip():
            raise LLMError(
                f"empty completion from {self.model} (stop_reason={stop!r}, blocks="
                f"{[b.get('type') for b in blocks if isinstance(b, dict)]})",
                public="LLM provider returned an empty completion")
        if stop == "max_tokens":
            log.warning("completion from %s truncated at max_tokens=%d", self.model, max_tokens)
        return text


# ------------------------------------------------------------- embeddings #

QUERY_EMBED_TIMEOUT = float(os.environ.get("LOOM_EMBED_QUERY_TIMEOUT", "") or 10.0)


class Embedder(ABC):
    """Text -> vector, for semantic ranking (phase 4, D-018)."""

    model: str

    @abstractmethod
    def embed(self, texts: list[str]) -> list[list[float]]: ...

    def embed_query(self, text: str) -> list[float]:
        """A question at ask time: one text, on the request's critical path.
        Providers override with a short timeout and no retries — a stalled
        embedder must degrade an ask to keyword ranking, not hold it for
        the batch path's 120 s × 3 (D-039: one ask took 30 s)."""
        return self.embed([text])[0]


class OpenAICompatEmbedder(Embedder):
    """POST {base}/embeddings — OpenAI, Mistral, Together, Ollama, vLLM..."""

    def __init__(self, base_url: str, model: str, api_key: str | None = None,
                 dimensions: int | None = None):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        # Matryoshka models (text-embedding-3-*, qwen3-embedding) accept a
        # smaller output size; 512 keeps most of the quality at a third of
        # the storage and index cost (D-039)
        self.dimensions = dimensions

    def embed(self, texts: list[str]) -> list[list[float]]:
        return self._embed(texts, timeout=120, attempts=_MAX_ATTEMPTS)

    def embed_query(self, text: str) -> list[float]:
        return self._embed([text], timeout=QUERY_EMBED_TIMEOUT, attempts=1)[0]

    def _embed(self, texts: list[str], timeout: float, attempts: int) -> list[list[float]]:
        headers = {}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        body: dict = {"model": self.model, "input": texts}
        if self.dimensions:
            body["dimensions"] = self.dimensions
        data = _post_json(self.base_url + "/embeddings", body, headers, timeout=timeout, attempts=attempts)
        try:
            rows = sorted(data["data"], key=lambda r: r["index"])
            return [r["embedding"] for r in rows]
        except (KeyError, TypeError) as exc:
            raise LLMError(f"unexpected embeddings response shape: {exc}") from exc


class HashingEmbedder(Embedder):
    """Deterministic offline fallback: hashed token/bigram bag vectors.

    Not semantic — it captures token overlap, roughly matching the keyword
    ranker — but it exercises the full embedding pipeline with zero deps and
    zero network, which keeps tests and air-gapped deployments honest.
    """

    def __init__(self, dim: int = 256):
        self.dim = dim
        self.model = f"hashing-{dim}"

    def embed(self, texts: list[str]) -> list[list[float]]:
        import hashlib
        import re

        out = []
        for text in texts:
            vec = [0.0] * self.dim
            tokens = re.findall(r"[a-z0-9]+", text.lower())
            grams = tokens + [f"{a}_{b}" for a, b in zip(tokens, tokens[1:])]
            for gram in grams:
                h = int.from_bytes(
                    hashlib.blake2b(gram.encode(), digest_size=4).digest(), "big"
                )
                vec[h % self.dim] += 1.0
            norm = sum(v * v for v in vec) ** 0.5 or 1.0
            out.append([v / norm for v in vec])
        return out


def _env(name: str) -> str | None:
    return os.environ.get(name, "").strip() or None


def embedder_from_env() -> Embedder | None:
    """None when unconfigured — ranking then falls back to keyword overlap.

    LOOM_EMBED_PROVIDER: hashing | openai | mistral | together | ollama | ...
    LOOM_EMBED_BASE_URL: custom/self-hosted endpoint (overrides shortcut)
    LOOM_EMBED_MODEL:    required for API providers
    LOOM_EMBED_API_KEY:  when the endpoint needs one
    LOOM_EMBED_DIM:      optional output size for Matryoshka models (e.g. 512)
    """
    provider = (_env("LOOM_EMBED_PROVIDER") or "").lower() or None
    base_url = _env("LOOM_EMBED_BASE_URL")
    model = _env("LOOM_EMBED_MODEL")
    api_key = _env("LOOM_EMBED_API_KEY")

    if provider == "hashing":
        return HashingEmbedder()
    if base_url is None and provider is not None:
        base_url = OPENAI_COMPAT_BASES.get(provider)
    if base_url is None or model is None:
        return None
    dim = _env("LOOM_EMBED_DIM")
    return OpenAICompatEmbedder(base_url=base_url, model=model, api_key=api_key,
                                dimensions=int(dim) if dim else None)


def llm_from_env() -> LLMClient | None:
    """None when unconfigured — answering endpoints then return 503."""
    model = _env("LOOM_LLM_MODEL")
    provider = (_env("LOOM_LLM_PROVIDER") or "").lower() or None
    base_url = _env("LOOM_LLM_BASE_URL")
    api_key = _env("LOOM_LLM_API_KEY")

    if model is None:
        return None
    if provider == "anthropic":
        return AnthropicClient(model=model, api_key=api_key, base_url=base_url)
    if base_url is None and provider is not None:
        base_url = OPENAI_COMPAT_BASES.get(provider)
    if base_url is None:
        return None
    return OpenAICompatClient(base_url=base_url, model=model, api_key=api_key)
