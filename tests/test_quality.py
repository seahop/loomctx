"""Retrieval-quality harness (the quality loop, D-015/roadmap).

Golden questions against the deterministic seed corpus, scored on what the
framework promises: the right facts rank early, conflicts always surface,
time travel works, scopes cover their members. Runs in CI with no LLM, so
ranking changes (e.g. the phase-4 embedding swap) ship with before/after
evidence instead of vibes. Run with -s to see the scorecard.
"""

from datetime import datetime, timezone

import pytest

from loomctx.context import build_pack
from loomctx.contracts import AskRequest, EntityRef, ScopeSpec
from loomctx.seed import cmd_load
from loomctx.store.sqlite import SqliteStore


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
    from loomctx.context import est_tokens
    for budget in (120, 400, 2000):
        pack = _ask(store, "who logged in?",
                    subject=EntityRef(type="host", key="web-01"), budget=budget)
        spent = sum(est_tokens(i.text) for i in pack.items)
        _score(f"budget-{budget}", spent <= budget,
               f"spent {spent} of {budget}")


def test_q8_predicate_name_words_rank_the_predicate(store):
    """D-051: 'port' appears only inside the predicate name
    `listens_on_port`; the keyword-overlap term scored that a third of a
    match and let the newest login outrank it on recency. BM25 over the
    split predicate tokens ranks the two port facts first."""
    pack = _ask(store, "is anything listening on a port?",
                subject=EntityRef(type="host", key="web-01"), budget=1200)
    facts = [i for i in pack.items if i.kind == "fact"][:2]
    _score("predicate-name-words", all("listens_on_port" in f.text for f in facts),
           f"top facts were {[f.text[:40] for f in facts]}")


def test_q9_rare_terms_outweigh_common_ones(store):
    """D-051: 'user' names 77 login facts, 'domain'/'member' name one.
    Overlap counting gave the login two thirds of the question's weight
    and recency did the rest; IDF makes the rare match win."""
    pack = _ask(store, "which domain is this host a member of, and which user logs in?",
                subject=EntityRef(type="host", key="web-01"), budget=1200)
    facts = [i for i in pack.items if i.kind == "fact"]
    _score("rare-term-idf", bool(facts) and "member_of" in facts[0].text,
           f"top fact was {facts[0].text[:60] if facts else 'nothing'}")


def test_q10_budget_holds_under_a_real_tokenizer(store):
    """D-051: the budget used to charge item text only — citations and up
    to 32 handles rode free, so an 800-token pack was ~2,500 on the wire.
    The charged form is the compact rendering; measured with cl100k over
    the rendered prompt block it stays within 15 % of the request."""
    try:
        import tiktoken
        enc = tiktoken.get_encoding("cl100k_base")
    except Exception as exc:  # noqa: BLE001 — no package, or offline with no cached encoding
        pytest.skip(f"tiktoken encoding unavailable: {exc}")
    from loomctx.answer import render_user_prompt

    def block_tokens(prompt: str) -> int:
        lines = prompt.split("\n")
        body = lines[lines.index("<<<LOOMCTX_CONTEXT") + 1: lines.index("LOOMCTX_CONTEXT>>>")]
        return len(enc.encode("\n".join(body)))

    questions = [
        ("netsec", EntityRef(type="host", key="web-01"), "what operating system does this run?"),
        ("netsec", EntityRef(type="host", key="web-01"), "who logged in to this host?"),
        ("netsec", EntityRef(type="ip", key="10.0.4.7"), "which host was assigned this ip?"),
        ("netsec", EntityRef(type="host", key="db-01"), ""),
        ("procurement", EntityRef(type="vendor", key="initech"), "who owns this contract?"),
    ]
    worst = 0.0
    for ns, subject, question in questions:
        for budget in (200, 400, 800, 3200):
            pack = _ask(store, question, subject=subject, budget=budget, namespace=ns)
            assert pack.charged_tokens <= budget, (question, budget, pack.charged_tokens)
            real = block_tokens(render_user_prompt(question, pack))
            worst = max(worst, real / budget)
            assert real <= budget * 1.15, (question, budget, real, pack.charged_tokens)
    _score("real-tokenizer-budget", worst <= 1.15, f"worst wire/budget ratio {worst:.2f}")


def test_q10b_budget_holds_on_the_mcp_wire(store):
    """D-058: D-051 measured the answer prompt only. What an MCP agent
    received for an 800-token pack was ~2,200 tokens (indented JSON,
    citation objects, ISO timestamps, a score per item). The concise view
    is now compact and the charge is sized to it: items and handles as the
    agent receives them stay within 15 % of the budget; the envelope
    (namespace, question echo, subject list) is a fixed ~70 tokens beside
    it, not charged."""
    try:
        import tiktoken
        enc = tiktoken.get_encoding("cl100k_base")
    except Exception as exc:  # noqa: BLE001 — no package, or offline with no cached encoding
        pytest.skip(f"tiktoken encoding unavailable: {exc}")
    import pydantic_core
    from loomctx import mcp_server
    from loomctx.context import expand_pack

    def body_tokens(pack) -> int:
        view = mcp_server._agent_view(pack)
        wire = pydantic_core.to_json(view).decode()
        envelope = pydantic_core.to_json({**view, "items": [], "handles": []}).decode()
        assert len(enc.encode(envelope)) <= 200, envelope
        return len(enc.encode(wire)) - len(enc.encode(envelope))

    scope = ScopeSpec(subjects=[EntityRef(type="domain", key="corp.local")], expand=["member_of"])
    asks = [
        ("netsec", EntityRef(type="host", key="web-01"), None, "what operating system does this run?"),
        ("netsec", EntityRef(type="host", key="db-01"), None, ""),
        ("netsec", EntityRef(type="ip", key="10.0.4.7"), None, "which host was assigned this ip?"),
        ("procurement", EntityRef(type="vendor", key="initech"), None, "who owns this contract?"),
        ("netsec", None, scope, "who logged in?"),
    ]
    worst = 0.0
    for ns, subject, sc, question in asks:
        for budget in (200, 400, 800, 1200, 3200):
            pack = _ask(store, question, subject=subject, scope=sc, budget=budget, namespace=ns)
            packs = [pack] + [expand_pack(store, h.id, budget) for h in pack.handles[:2]]
            for p in packs:
                real = body_tokens(p)
                worst = max(worst, real / budget)
                assert real <= budget * 1.15, (question, budget, real, p.charged_tokens)
    _score("mcp-wire-budget", worst <= 1.15, f"worst MCP wire/budget ratio {worst:.2f}")


def test_q11_a_scope_answers_along_the_predicates_it_walks(store):
    """D-058: alert -> host -> logins, walked over triggered_on +
    logged_in_by. The pack spent every budget up to 1,600 on
    communicated_with ("host" is rare among the gathered rows, "logged" is
    on every login) and shipped the logins — what the question walks and
    asks — only as handles. An expand predicate the question names now
    ranks as the topic."""
    alert = EntityRef(type="alert", key="AL-2291")
    host = EntityRef(type="host", key="web-01")
    scope = ScopeSpec(subjects=[alert], expand=["triggered_on", "logged_in_by"], depth=2)
    question = ("Which users logged in to the host that alert:AL-2291 triggered on, on 2026-09-01? "
                "List every user as user:<key>.")
    truth = {o.object.key for o in store.observations_for("netsec", host, limit=1000)
             if o.predicate == "logged_in_by" and o.observed_at.date().isoformat() == "2026-09-01"}
    pack = _ask(store, question, scope=scope, budget=800)
    facts = [i.text for i in pack.items if i.kind in ("fact", "relation")]
    found = {t.split()[2].split(":", 1)[1] for t in facts
             if t.startswith("host:web-01 logged_in_by") and "(2026-09-01," in t}
    logins = sum(" logged_in_by " in t for t in facts)
    flows = sum(" communicated_with " in t for t in facts)
    _score("scope-walked-predicates", truth and found == truth and logins > flows,
           f"found {sorted(found)} of {sorted(truth)}; {logins} logins vs {flows} flows")
    # a scope whose walked predicate the question does not name is unchanged:
    # "who logged in?" over member_of still ranks logins, not memberships
    domain = ScopeSpec(subjects=[EntityRef(type="domain", key="corp.local")], expand=["member_of"])
    texts = [i.text for i in _ask(store, "who logged in?", scope=domain, budget=800).items if i.kind == "fact"]
    assert sum(" logged_in_by " in t for t in texts) > sum(" member_of " in t for t in texts)


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
