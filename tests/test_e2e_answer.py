"""End-to-end answer test against a REAL provider.

Runs only when the answering LLM is configured (copy .env.example to .env
and fill in a key); skips cleanly otherwise, so CI and keyless runs are
unaffected. Costs one small completion per run.
"""

import os
from datetime import datetime, timezone

import pytest

from loom.answer import build_answer
from loom.contracts import AnswerRequest, ClaimIn, EntityRef
from loom.llm import llm_from_env
from loom.store.sqlite import SqliteStore

pytestmark = pytest.mark.skipif(
    llm_from_env() is None,
    reason="no LLM configured — fill in .env (see .env.example) to enable",
)


def test_real_provider_grounded_answer(tmp_path):
    store = SqliteStore(tmp_path / "e2e.db")
    web01 = EntityRef(type="host", key="web-01")
    store.record_claim(ClaimIn(
        subject=web01, predicate="runs_os", object="fedora-44",
        observed_at=datetime(2026, 7, 3, tzinfo=timezone.utc),
        source="asset-inventory",
    ))
    store.record_claim(ClaimIn(
        subject=web01, predicate="runs_os", object="ubuntu-22.04",
        observed_at=datetime(2026, 8, 18, tzinfo=timezone.utc),
        source="nmap-scan", confidence=0.7,
    ))
    store.record_claim(ClaimIn(
        subject=web01, predicate="logged_in_by",
        object=EntityRef(type="user", key="jdoe"),
        observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
        source="auth-log",
    ))

    llm = llm_from_env()
    resp = build_answer(store, llm, AnswerRequest(
        question="What operating system does web-01 run?", budget=1200,
    ))

    assert resp.answer.strip(), "provider returned an empty answer"
    assert resp.model == llm.model
    # the pack the model saw must contain the planted conflict
    assert any(i.kind == "conflict" for i in resp.pack.items)
    # a grounded answer about a contested fact should mention both candidates
    lowered = resp.answer.lower()
    assert "fedora" in lowered and "ubuntu" in lowered, (
        f"answer did not surface the source conflict: {resp.answer!r}"
    )
    print(f"\n--- {resp.model} ---\n{resp.answer}\n")
