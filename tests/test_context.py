from datetime import datetime, timezone

from loom.context import build_pack, decode_handle, est_tokens, expand_pack
from loom.contracts import AskRequest, ClaimIn, EntityRef
from loom.store.sqlite import SqliteStore


def _at(month, day, hour=12):
    return datetime(2026, month, day, hour, tzinfo=timezone.utc)


def make_store(tmp_path):
    store = SqliteStore(tmp_path / "ctx.db")
    web01 = EntityRef(type="host", key="web-01")
    store.record_claim(ClaimIn(
        subject=web01, predicate="logged_in_by",
        object=EntityRef(type="user", key="jdoe"),
        observed_at=_at(9, 1), source="auth-log",
    ))
    for day in range(1, 21):
        store.record_claim(ClaimIn(
            subject=web01, predicate="communicated_with",
            object=EntityRef(type="host", key=f"db-{day:02d}"),
            observed_at=_at(8, day), source="netflow", confidence=0.9,
        ))
    # conflicting scalar fact
    store.record_claim(ClaimIn(
        subject=web01, predicate="runs_os", object="fedora-44",
        observed_at=_at(7, 5), source="asset-inventory",
    ))
    store.record_claim(ClaimIn(
        subject=web01, predicate="runs_os", object="ubuntu-22.04",
        observed_at=_at(8, 20), source="nmap-scan", confidence=0.7,
    ))
    return store, web01


def test_pack_fits_budget_and_cites(tmp_path):
    store, web01 = make_store(tmp_path)
    pack = build_pack(store, AskRequest(subject=web01, question="who logged in?",
                                        budget=200))
    assert sum(est_tokens(i.text) for i in pack.items) <= pack.budget == 200
    assert pack.items, "budget of 200 should fit something"
    assert all(i.citations for i in pack.items)


def test_question_relevance_ranks_login_first(tmp_path):
    store, web01 = make_store(tmp_path)
    pack = build_pack(store, AskRequest(subject=web01,
                                        question="who logged in to this host?",
                                        budget=2000))
    facts = [i for i in pack.items if i.kind == "fact"]
    assert "logged_in_by" in facts[0].text
    assert "jdoe" in facts[0].text


def test_conflict_is_surfaced_first_with_both_citations(tmp_path):
    store, web01 = make_store(tmp_path)
    pack = build_pack(store, AskRequest(subject=web01, question="what os?",
                                        budget=2000))
    assert pack.items[0].kind == "conflict"
    assert "runs_os" in pack.items[0].text
    assert len(pack.items[0].citations) == 2
    sources = {c.source for c in pack.items[0].citations}
    assert sources == {"asset-inventory", "nmap-scan"}


def test_handles_cover_whats_cut_and_expand_works(tmp_path):
    store, web01 = make_store(tmp_path)
    small = build_pack(store, AskRequest(subject=web01, question="who logged in?",
                                         budget=150))
    assert small.handles, "a tiny budget must leave expandable threads"
    handle = small.handles[0]
    meta = decode_handle(handle.id)
    assert meta["subject"] == {"type": "host", "key": "web-01"}

    expanded = expand_pack(store, handle.id, budget=3000)
    assert expanded.items
    assert all(meta["predicate"] in i.text for i in expanded.items
               if i.kind == "fact")


def test_as_of_excludes_later_observations(tmp_path):
    store, web01 = make_store(tmp_path)
    pack = build_pack(store, AskRequest(subject=web01, question="who logged in?",
                                        budget=4000, as_of=_at(8, 31)))
    assert all("logged_in_by" not in i.text for i in pack.items), \
        "the Sep 1 login must be invisible as of Aug 31"


def test_no_question_returns_recency_overview(tmp_path):
    store, web01 = make_store(tmp_path)
    pack = build_pack(store, AskRequest(subject=web01, question="", budget=500))
    assert pack.items


def test_conflict_that_does_not_fit_becomes_a_handle(tmp_path):
    """H-C4: a conflict is never dropped silently at small budgets."""
    store, web01 = make_store(tmp_path)
    pack = build_pack(store, AskRequest(subject=web01, question="what os?", budget=25))
    assert not [i for i in pack.items if i.kind == "conflict"]
    flagged = [h for h in pack.handles if h.kind == "conflict"]
    assert flagged and "runs_os" in flagged[0].hint
    expanded = expand_pack(store, flagged[0].id, budget=2000)
    assert expanded.items and expanded.items[0].kind == "conflict"


def test_document_extracted_claims_rank_below_structured(tmp_path):
    """H-C5/H-D2: a document cannot manufacture a top-ranked conflict, and
    an extracted fact scores below the same fact asserted by a sender."""
    store, web01 = make_store(tmp_path)
    store.record_claim(ClaimIn(
        subject=web01, predicate="owner", object="mallory",
        observed_at=_at(9, 2), source="doc:phish.txt", attrs={"extracted": True}))
    store.record_claim(ClaimIn(
        subject=web01, predicate="owner", object="alice",
        observed_at=_at(9, 1), source="cmdb"))
    pack = build_pack(store, AskRequest(subject=web01, question="os and owner?",
                                        budget=3000))
    conflicts = [i for i in pack.items if i.kind == "conflict"]
    assert [("runs_os" in c.text) for c in conflicts] == [True, False]
    assert conflicts[0].score == 1.0 and conflicts[1].score < 1.0
    assert "extracted from a document" in conflicts[1].text
    facts = {i.text: i.score for i in pack.items if i.kind == "fact"}
    doc_fact = next(s for t, s in facts.items() if "mallory" in t)
    cmdb_fact = next(s for t, s in facts.items() if "alice" in t)
    assert doc_fact < cmdb_fact


def test_expired_validity_is_not_a_conflict(tmp_path):
    """H-C3: a fact whose window closed is history, not a competing claim."""
    store = SqliteStore(tmp_path / "v.db")
    host = EntityRef(type="host", key="db-01")
    store.record_claim(ClaimIn(
        subject=host, predicate="role", object="primary", observed_at=_at(7, 1),
        valid_from=_at(7, 1), valid_to=_at(8, 1), source="cluster-a"))
    store.record_claim(ClaimIn(
        subject=host, predicate="role", object="replica", observed_at=_at(8, 2),
        valid_from=_at(8, 2), source="cluster-b"))
    pack = build_pack(store, AskRequest(subject=host, question="role?", budget=2000))
    assert not [i for i in pack.items if i.kind == "conflict"]
    # but as of a moment when both windows were open, it IS a conflict
    store.record_claim(ClaimIn(
        subject=host, predicate="role", object="standby", observed_at=_at(7, 15),
        valid_from=_at(7, 15), source="cluster-b"))
    pack = build_pack(store, AskRequest(subject=host, question="role?", budget=2000,
                                        as_of=_at(7, 20)))
    assert [i for i in pack.items if i.kind == "conflict"]


def test_query_embedding_is_cached():
    from loom.context import embed_query, _query_cache
    from loom.llm import HashingEmbedder
    calls = []

    class Counting(HashingEmbedder):
        def embed(self, texts):
            calls.append(texts)
            return super().embed(texts)

    _query_cache.clear()
    e = Counting()
    a = embed_query(e, "who logged in?")
    b = embed_query(e, "who logged in?")
    assert a == b and len(calls) == 1
