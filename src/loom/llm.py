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

import json
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod

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
    """The provider call failed; the HTTP layer maps this to a 502."""


class LLMClient(ABC):
    model: str

    @abstractmethod
    def complete(self, system: str, user: str, max_tokens: int = 1024) -> str:
        """One system+user exchange; returns the assistant text."""


def _post_json(url: str, body: dict, headers: dict, timeout: float = 120) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read()[:500].decode(errors="replace")
        raise LLMError(f"provider returned {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise LLMError(f"provider unreachable: {exc}") from exc


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
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"unexpected provider response shape: {exc}") from exc


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
        try:
            return data["content"][0]["text"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"unexpected provider response shape: {exc}") from exc


def _env(name: str) -> str | None:
    return os.environ.get(name, "").strip() or None


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
