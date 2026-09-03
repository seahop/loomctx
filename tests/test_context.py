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
