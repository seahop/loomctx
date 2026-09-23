"""Retrieval-quality harness (the quality loop, D-015/roadmap).

Golden questions against the deterministic seed corpus, scored on what the
framework promises: the right facts rank early, conflicts always surface,
time travel works, scopes cover their members. Runs in CI with no LLM, so
ranking changes (e.g. the phase-4 embedding swap) ship with before/after
evidence instead of vibes. Run with -s to see the scorecard.
"""

from datetime import datetime, timezone

import pytest

from loom.context import build_pack
from loom.contracts import AskRequest, EntityRef, ScopeSpec
from loom.seed import cmd_load
from loom.store.sqlite import SqliteStore


@pytest.fixture(scope="module")
def store(tmp_path_factory):
    db = tmp_path_factory.mktemp("quality") / "seed.db"
    cmd_load(str(db), seed=42)
    s = SqliteStore(db)
    yield s
    s.close()


def _ask(store, question, subject=None, scope=None, budget=1200, as_of=None,
         namespace="netsec"):
    return build_pack(store, AskRequest(
        namespace=namespace, subject=subject, scope=scope,
        question=question, budget=budget, as_of=as_of,
    ))


SCORECARD = []


def _score(name, passed, detail=""):
    SCORECARD.append((name, passed, detail))
    assert passed, f"{name}: {detail}"


def test_q1_conflict_always_surfaces_first(store):
    pack = _ask(store, "what operating system does web-01 run?",
                subject=EntityRef(type="host", key="web-01"), budget=600)
    first_conflict = pack.items and pack.items[0].kind == "conflict"
    _score("conflict-first", first_conflict,
           f"first item was {pack.items[0].kind if pack.items else 'nothing'}")


def test_q2_login_question_ranks_login_facts(store):
    pack = _ask(store, "who logged in to this host?",
                subject=EntityRef(type="host", key="web-01"), budget=1200)
    facts = [i for i in pack.items if i.kind == "fact"][:5]
    hits = sum("logged_in_by" in f.text for f in facts)
    _score("relevance@5-logins", hits >= 4, f"{hits}/5 top facts were logins")


def test_q3_ip_lease_history_is_complete(store):
    pack = _ask(store, "which host was assigned this ip?",
                subject=EntityRef(type="ip", key="10.0.4.7"), budget=800)
    text = " | ".join(i.text for i in pack.items)
    both = "web-01" in text and "laptop-17" in text
    windowed = "[valid" in text
    _score("lease-history", both and windowed,
           "missing a lease or validity window")


def test_q4_as_of_time_travel(store):
    pack = _ask(store, "which host was assigned this ip?",
                subject=EntityRef(type="ip", key="10.0.4.7"), budget=800,
                as_of=datetime(2026, 8, 1, tzinfo=timezone.utc))
    text = " | ".join(i.text for i in pack.items)
    _score("as-of", "web-01" in text and "laptop-17" not in text,
           "the future lease leaked into the past")


def test_q5_domain_scope_covers_members(store):
    pack = _ask(store, "what triggered on these hosts?",
                scope=ScopeSpec(subjects=[EntityRef(type="domain", key="corp.local")],
                                expand=["member_of"], depth=1),
                budget=1500)
    covered = len(pack.subjects) >= 8
    alert = any("AL-2291" in i.text for i in pack.items)
    _score("scope-coverage", covered and alert,
           f"{len(pack.subjects)} subjects, alert visible: {alert}")


def test_q6_cross_namespace_conflict(store):
    pack = _ask(store, "who owns this contract?",
                subject=EntityRef(type="vendor", key="initech"),
                budget=800, namespace="procurement")
    flagged = any(i.kind == "conflict" and "contract_owner" in i.text
                  for i in pack.items)
    _score("procurement-conflict", flagged, "owner conflict not flagged")


def test_q7_budgets_always_respected(store):
    from loom.context import est_tokens
    for budget in (120, 400, 2000):
        pack = _ask(store, "who logged in?",
                    subject=EntityRef(type="host", key="web-01"), budget=budget)
        spent = sum(est_tokens(i.text) for i in pack.items)
        _score(f"budget-{budget}", spent <= budget,
               f"spent {spent} of {budget}")


def test_q4b_valid_at_fact_time(store):
    """D-024: 'which host HELD this ip on Aug 20' — exactly one answer."""
    pack = build_pack(store, AskRequest(
        namespace="netsec", subject=EntityRef(type="ip", key="10.0.4.7"),
        question="which host was assigned this ip?", budget=800,
        valid_at=datetime(2026, 8, 20, tzinfo=timezone.utc)))
    assert pack.valid_at is not None and pack.items
    text = " | ".join(i.text for i in pack.items)
    _score("valid-at", "laptop-17" in text and "web-01" not in text,
           "fact-time filter leaked the expired lease")


def test_zz_print_scorecard(store):
    """Defined last on purpose: pytest runs a module's tests in definition
    order, and the scorecard must include every question above."""
    assert any(n == "valid-at" for n, _, _ in SCORECARD)
    width = max(len(n) for n, _, _ in SCORECARD)
    print("\n--- retrieval quality scorecard ---")
    for name, passed, _ in SCORECARD:
        print(f"  {name:<{width}}  {'PASS' if passed else 'FAIL'}")
    print(f"  {len([1 for _, p, _ in SCORECARD if p])}/{len(SCORECARD)} passing")
