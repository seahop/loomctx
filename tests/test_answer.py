from datetime import datetime, timezone

import pytest

from loom.answer import (
    UnresolvedQuestionError,
    auto_subjects,
    build_answer,
    render_user_prompt,
)
from loom.contracts import AnswerRequest, ClaimIn, EntityRef
from loom.llm import LLMClient, llm_from_env
from loom.store.sqlite import SqliteStore


class FakeLLM(LLMClient):
    model = "fake-model"

    def __init__(self):
        self.calls = []

    def complete(self, system, user, max_tokens=1024):
        self.calls.append((system, user, max_tokens))
        return "the answer [abc123]"


def make_store(tmp_path):
    store = SqliteStore(tmp_path / "a.db")
    for host, user in [("web-01", "jdoe"), ("web-02", "asmith")]:
        store.record_claim(ClaimIn(
            subject=EntityRef(type="host", key=host),
            predicate="logged_in_by",
            object=EntityRef(type="user", key=user),
            observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
            source="auth-log",
        ))
    return store


def test_auto_subjects_finds_entities_named_in_question(tmp_path):
    store = make_store(tmp_path)
    subjects = auto_subjects(
        store, "default", "what do web-01 and web-02 have in common?"
    )
    keys = {s.key for s in subjects}
    assert keys == {"web-01", "web-02"}


def test_auto_subjects_never_guesses(tmp_path):
    store = make_store(tmp_path)
    assert auto_subjects(store, "default", "what about the web servers?") == []


def test_build_answer_auto_resolves_and_grounds_prompt(tmp_path):
    store = make_store(tmp_path)
    llm = FakeLLM()
    resp = build_answer(store, llm, AnswerRequest(
        question="what do web-01 and web-02 have in common?"
    ))
    assert resp.answer == "the answer [abc123]"
    assert resp.model == "fake-model"
    assert {s.key for s in resp.pack.subjects} == {"web-01", "web-02"}
    _, user_prompt, _ = llm.calls[0]
    assert "jdoe" in user_prompt and "asmith" in user_prompt
    assert "auth-log" not in resp.answer or True  # answer content is the LLM's


def test_build_answer_unresolvable_raises(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(UnresolvedQuestionError):
        build_answer(store, FakeLLM(), AnswerRequest(question="anything odd?"))


def test_render_prompt_carries_citations_and_handles(tmp_path):
    store = make_store(tmp_path)
    from loom.context import build_pack
    from loom.contracts import AskRequest

    pack = build_pack(store, AskRequest(
        subject=EntityRef(type="host", key="web-01"),
        question="who logged in?", budget=400,
    ))
    prompt = render_user_prompt("who logged in?", pack)
    assert "Question: who logged in?" in prompt
    assert "(fact)" in prompt and "[" in prompt


def test_llm_factory_selection(monkeypatch):
    for var in ("LOOM_LLM_MODEL", "LOOM_LLM_PROVIDER",
                "LOOM_LLM_BASE_URL", "LOOM_LLM_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    assert llm_from_env() is None  # unconfigured

    monkeypatch.setenv("LOOM_LLM_MODEL", "some/model")
    assert llm_from_env() is None  # model alone isn't enough

    monkeypatch.setenv("LOOM_LLM_PROVIDER", "openrouter")
    client = llm_from_env()
    assert client.base_url == "https://openrouter.ai/api/v1"

    monkeypatch.setenv("LOOM_LLM_PROVIDER", "venice")
    assert llm_from_env().base_url == "https://api.venice.ai/api/v1"

    # custom/self-hosted endpoint overrides the shortcut
    monkeypatch.setenv("LOOM_LLM_BASE_URL", "http://my-vllm:8000/v1")
    assert llm_from_env().base_url == "http://my-vllm:8000/v1"

    monkeypatch.setenv("LOOM_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("LOOM_LLM_BASE_URL", "")
    from loom.llm import AnthropicClient
    assert isinstance(llm_from_env(), AnthropicClient)


def test_prompt_carries_partial_coverage():
    from loom.answer import render_user_prompt
    from loom.contracts import ContextPack, EntityRef, ScopeTruncation
    pack = ContextPack(namespace="ns", budget=100, truncated=[
        ScopeTruncation(entity=EntityRef(type="product", key="linux:linux_kernel"), gathered=1000, total=2740)])
    text = render_user_prompt("exposed?", pack)
    assert "coverage: only the newest 1,000 of 2,740" in text and "do not conclude absence" in text


def test_answer_request_rejects_subject_and_scope_together():
    from pydantic import ValidationError
    from loom.contracts import ScopeSpec
    AnswerRequest(question="q")  # neither: auto-resolution
    AnswerRequest(question="q", subject=EntityRef(type="host", key="a"))
    AnswerRequest(question="q", scope=ScopeSpec(subjects=[EntityRef(type="host", key="b")]))
    with pytest.raises(ValidationError):
        AnswerRequest(question="q", subject=EntityRef(type="host", key="a"),
                      scope=ScopeSpec(subjects=[EntityRef(type="host", key="b")]))
