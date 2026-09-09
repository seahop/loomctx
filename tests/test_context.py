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


def _lease_store(tmp_path):
    """ip 10.0.4.7: web-01 until Aug 10, then laptop-17; plus an un-windowed fact."""
    store = SqliteStore(tmp_path / "lease.db")
    ip = EntityRef(type="ip", key="10.0.4.7")
    store.record_claim(ClaimIn(
        subject=ip, predicate="assigned_to", object=EntityRef(type="host", key="web-01"),
        observed_at=_at(7, 1), valid_from=_at(7, 1), valid_to=_at(8, 10), source="dhcp"))
    store.record_claim(ClaimIn(
        subject=ip, predicate="assigned_to", object=EntityRef(type="host", key="laptop-17"),
        observed_at=_at(8, 10), valid_from=_at(8, 10), source="dhcp"))
    store.record_claim(ClaimIn(
        subject=ip, predicate="subnet", object="10.0.4.0/24",
        observed_at=_at(9, 1), source="ipam"))
    return store, ip


def test_valid_at_answers_what_was_true(tmp_path):
    """D-024: valid_at is fact time — exactly one lease holder per instant;
    facts without a validity window are timeless and kept."""
    store, ip = _lease_store(tmp_path)
    during = build_pack(store, AskRequest(subject=ip, question="which host?",
                                          budget=2000, valid_at=_at(8, 1)))
    text = " | ".join(i.text for i in during.items)
    assert "web-01" in text and "laptop-17" not in text and "subnet" in text
    after = build_pack(store, AskRequest(subject=ip, question="which host?",
                                         budget=2000, valid_at=_at(8, 20)))
    text = " | ".join(i.text for i in after.items)
    assert "laptop-17" in text and "web-01" not in text
    assert after.valid_at is not None
    # as_of is knowledge time: on Aug 1 we knew only the first lease AND
    # nothing recorded later (the subnet fact came on Sep 1)
    known = build_pack(store, AskRequest(subject=ip, question="which host?",
                                         budget=2000, as_of=_at(8, 1)))
    text = " | ".join(i.text for i in known.items)
    assert "web-01" in text and "laptop-17" not in text and "subnet" not in text
    # handles inherit valid_at
    tiny = build_pack(store, AskRequest(subject=ip, question="which host?",
                                        budget=40, valid_at=_at(8, 1)))
    for h in tiny.handles:
        assert decode_handle(h.id).get("valid_at")


def test_recency_is_time_decayed_not_rank_based(tmp_path):
    """H-C7: facts seconds apart score alike; a year-old one decays."""
    from loom.context import _recency
    from loom.contracts import Observation
    newest = _at(9, 1)

    def obs(when):
        return Observation(id="x", namespace="d", subject=EntityRef(type="h", key="k"),
                           predicate="p", object="v", observed_at=when,
                           recorded_at=when, source="s", confidence=1.0)
    close = [_recency(obs(datetime(2026, 9, 1, 12, 0, s, tzinfo=timezone.utc)), newest)
             for s in (0, 1, 2)]
    assert max(close) - min(close) < 1e-5
    assert _recency(obs(_at(8, 2)), newest) < 0.6
    assert _recency(obs(datetime(2025, 9, 1, tzinfo=timezone.utc)), newest) < 0.1


def test_stopwords_do_not_dilute_keyword_relevance(tmp_path):
    store, web01 = make_store(tmp_path)
    pack = build_pack(store, AskRequest(
        subject=web01, question="what is the os that this host runs?", budget=3000))
    facts = [i for i in pack.items if i.kind == "fact"]
    assert "runs_os" in facts[0].text


def test_scores_stay_comparable_when_some_vectors_are_missing(tmp_path):
    """H-C7: with an embedder serving, un-embedded facts use the same formula."""
    from loom.enrich import embed_pending
    from loom.llm import HashingEmbedder
    store, web01 = make_store(tmp_path)
    embedder = HashingEmbedder()
    embed_pending(store, embedder, batch=5)  # only SOME observations get vectors
    store.record_claim(ClaimIn(subject=web01, predicate="logged_in_by",
                               object=EntityRef(type="user", key="fresh"),
                               observed_at=_at(9, 2), source="auth-log"))
    pack = build_pack(store, AskRequest(subject=web01, question="who logged in?",
                                        budget=3000), embedder=embedder)
    scores = [i.score for i in pack.items if i.kind == "fact"]
    assert max(scores) <= 1.0 and min(scores) >= 0.0
    # nothing scores above the semantic formula's ceiling for a neutral cosine
    fresh = next(i for i in pack.items if "fresh" in i.text)
    assert fresh.score <= 0.75


def test_numpy_and_python_cosines_agree():
    from loom.context import _cosine, cosines
    q = [1.0, 2.0, 3.0]
    vecs = {"a": [1.0, 2.0, 3.0], "b": [-1.0, 0.0, 0.5], "z": [0.0, 0.0, 0.0],
            "short": [1.0, 2.0]}
    got = cosines(q, vecs)
    assert "short" not in got  # another embedding space is skipped, not scored 0
    for k in ("a", "b", "z"):
        assert abs(got[k] - _cosine(q, vecs[k])) < 1e-9, k


def test_handles_are_capped_and_the_rest_counted(tmp_path):
    """D-035: a scope over a hub entity produced 8,234 handles. Handles stay
    in priority order, stop at the cap, and the pack says how many were left."""
    from loom.context import _MAX_HANDLES
    store = SqliteStore(tmp_path / "cap.db")
    subj = EntityRef(type="host", key="busy")
    store.record_claims([
        ClaimIn(namespace="ns", subject=subj, predicate=f"pred_{i}", object=i, source="s",
                observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc))
        for i in range(_MAX_HANDLES + 20)
    ])
    pack = build_pack(store, AskRequest(namespace="ns", subject=subj, question="x", budget=1))
    assert pack.items == []
    assert len(pack.handles) == _MAX_HANDLES and pack.omitted_handles == 20
    roomy = build_pack(store, AskRequest(namespace="ns", subject=subj, question="x", budget=5000))
    assert roomy.omitted_handles == 0 and roomy.handles == []
    store.close()


def test_inbound_edges_on_a_hub_collapse_into_one_handle(tmp_path):
    """D-035: 2,700 CVEs affecting one product are one expandable thread on
    the product, not one handle per CVE."""
    store = SqliteStore(tmp_path / "hub.db")
    hub = EntityRef(type="product", key="linux:linux_kernel")
    store.record_claims([
        ClaimIn(namespace="ns", subject=EntityRef(type="cve", key=f"CVE-2026-{i}"),
                predicate="affects", object=hub, source="nvd",
                observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc))
        for i in range(40)
    ])
    pack = build_pack(store, AskRequest(namespace="ns", subject=hub, question="exploited", budget=1))
    assert len(pack.handles) == 1 and pack.omitted_handles == 0
    assert pack.handles[0].hint == "40 more 'affects' observations pointing at product:linux:linux_kernel"
    expanded = expand_pack(store, pack.handles[0].id, budget=5000)
    assert len(expanded.items) == 40 and all("affects" in i.text for i in expanded.items)
    store.close()


def test_conflicts_never_crowd_out_every_fact(tmp_path):
    """D-035: on a wide scope the conflicts alone exceeded the budget and the
    pack carried zero facts. Conflicts keep priority but take at most half
    the budget; the rest become conflict handles (H-C4 still holds)."""
    store = SqliteStore(tmp_path / "flood.db")
    t = datetime(2026, 9, 1, tzinfo=timezone.utc)
    cves = [EntityRef(type="cve", key=f"CVE-2026-{i}") for i in range(30)]
    claims = []
    for cve in cves:
        claims.append(ClaimIn(namespace="ns", subject=cve, predicate="cvss_score", object=9.8,
                              source="nvd:nist", observed_at=t))
        claims.append(ClaimIn(namespace="ns", subject=cve, predicate="cvss_score", object=5.5,
                              source="nvd:cna", observed_at=t))
        claims.append(ClaimIn(namespace="ns", subject=cve, predicate="exploited_in_wild", object=True,
                              source="cisa-kev", observed_at=t))
    store.record_claims(claims)
    from loom.contracts import ScopeSpec
    pack = build_pack(store, AskRequest(namespace="ns", question="exploited in wild", budget=900,
                                        scope=ScopeSpec(subjects=cves, depth=0)))
    kinds = [i.kind for i in pack.items]
    assert kinds[0] == "conflict" and "fact" in kinds
    assert any("exploited_in_wild" in i.text for i in pack.items)
    conflict_tokens = sum(est_tokens(i.text) for i in pack.items if i.kind == "conflict")
    assert conflict_tokens <= 450
    assert any(h.kind == "conflict" for h in pack.handles)   # the overflow is still signalled
    store.close()


def test_scope_facts_arrive_with_their_path(tmp_path):
    """D-035: on the real corpus a pack held 'CVE-X exploited_in_wild' but not
    'web-01 runs nginx' / 'CVE-X affects nginx' (fresher rows outranked them)
    and the answering model refused to connect the dots. A fact about a
    reached entity ships with the edges it was reached through."""
    from loom.contracts import ScopeSpec
    store = SqliteStore(tmp_path / "path.db")
    t = datetime(2026, 7, 1, tzinfo=timezone.utc)
    host, prod, cve = (EntityRef(type="host", key="web-01"), EntityRef(type="product", key="nginx"),
                       EntityRef(type="cve", key="CVE-2026-1"))
    claims = [
        ClaimIn(namespace="ns", subject=host, predicate="runs_software", object=prod, source="inv", observed_at=t),
        ClaimIn(namespace="ns", subject=cve, predicate="affects", object=prod, source="nvd", observed_at=t),
        ClaimIn(namespace="ns", subject=cve, predicate="exploited_in_wild", object=True, source="kev", observed_at=t),
    ]
    # fresher, irrelevant rows that outrank the old edges on recency
    claims += [ClaimIn(namespace="ns", subject=cve, predicate=f"epss_{i}", object=0.5, source="epss",
                       observed_at=datetime(2026, 9, 8, tzinfo=timezone.utc)) for i in range(6)]
    store.record_claims(claims)
    scope = ScopeSpec(subjects=[host], expand=["runs_software", "affects"], depth=2)
    pack = build_pack(store, AskRequest(namespace="ns", scope=scope, question="exploited", budget=200))
    texts = [(i.kind, i.text) for i in pack.items]
    idx = {p: n for n, (k, txt) in enumerate(texts) for p in ("runs_software", "affects", "exploited_in_wild") if p in txt}
    assert set(idx) == {"runs_software", "affects", "exploited_in_wild"}
    assert idx["runs_software"] < idx["affects"] < idx["exploited_in_wild"]
    assert [k for k, txt in texts if "runs_software" in txt or "affects" in txt] == ["relation", "relation"]
    assert sum(1 for k, _ in texts if k == "relation") == 2   # edges ship once
    store.close()


def test_naming_the_subject_does_not_boost_its_own_facts(tmp_path):
    """D-036: 'is web-01 exposed to anything exploited in the wild?' — every
    recent login *about web-01* matched as many question words as the KEV
    fact two hops away and outranked it on recency. The root subject's own
    name is the frame of the question, not its topic."""
    from loom.contracts import ScopeSpec
    store = SqliteStore(tmp_path / "frame.db")
    old, new = datetime(2026, 5, 1, tzinfo=timezone.utc), datetime(2026, 9, 2, tzinfo=timezone.utc)
    host, prod, cve = (EntityRef(type="host", key="web-01"), EntityRef(type="product", key="nginx"),
                       EntityRef(type="cve", key="CVE-2026-7"))
    claims = [
        ClaimIn(namespace="ns", subject=host, predicate="runs_software", object=prod, source="inv", observed_at=old),
        ClaimIn(namespace="ns", subject=cve, predicate="affects", object=prod, source="nvd", observed_at=old),
        ClaimIn(namespace="ns", subject=cve, predicate="exploited_in_wild", object=True, source="kev", observed_at=old),
    ] + [ClaimIn(namespace="ns", subject=host, predicate="logged_in_by", object=EntityRef(type="user", key=f"u{i}"),
                 source="auth", observed_at=new) for i in range(40)]
    store.record_claims(claims)
    scope = ScopeSpec(subjects=[host], expand=["runs_software", "affects"], depth=2)
    pack = build_pack(store, AskRequest(namespace="ns", scope=scope, budget=400,
                                       question="is host web-01 exposed to anything exploited in the wild?"))
    assert any("exploited_in_wild" in i.text for i in pack.items), [i.text for i in pack.items]
    # a question that is ONLY the subject's name keeps its tokens (nothing else to rank by)
    pack = build_pack(store, AskRequest(namespace="ns", subject=host, question="web-01", budget=400))
    assert pack.items
    store.close()


def test_handles_are_compact_and_legacy_handles_still_decode():
    import base64
    import json as _json
    from loom.context import encode_handle
    ref = EntityRef(type="product", key="linux:linux_kernel")
    h = encode_handle("netsec", ref, "affects", None, datetime(2026, 8, 20, tzinfo=timezone.utc))
    legacy_len = len("h1_" + base64.urlsafe_b64encode(_json.dumps(
        {"ns": "netsec", "subject": ref.model_dump(), "predicate": "affects", "as_of": None,
         "valid_at": "2026-08-20T00:00:00+00:00"}, sort_keys=True).encode()).decode().rstrip("="))
    assert len(h) < legacy_len * 0.8
    assert len(encode_handle("netsec", ref, "affects", None)) < 100
    meta = decode_handle(h)
    assert meta["ns"] == "netsec" and meta["subject"] == {"type": "product", "key": "linux:linux_kernel"}
    assert meta["predicate"] == "affects" and meta["valid_at"].startswith("2026-08-20") and "as_of" not in meta
    legacy = "h1_" + base64.urlsafe_b64encode(_json.dumps(
        {"ns": "netsec", "subject": {"type": "host", "key": "web-01"}, "predicate": "runs_os", "as_of": None}
    ).encode()).decode().rstrip("=")
    assert decode_handle(legacy)["subject"]["key"] == "web-01"


def test_gather_truncation_is_reported_not_silent(tmp_path, monkeypatch):
    """D-038: a hub with more observations than the gather limit yields its
    newest N; the pack says so wherever that happened (subject, scope
    expansion, expand), so a reader cannot conclude absence from it."""
    import loom.context as ctx
    from loom.contracts import ScopeSpec
    monkeypatch.setattr(ctx, "_GATHER_LIMIT", 5)
    store = SqliteStore(tmp_path / "trunc.db")
    hub = EntityRef(type="product", key="linux:linux_kernel")
    host = EntityRef(type="host", key="web-01")
    t = datetime(2026, 9, 1, tzinfo=timezone.utc)
    store.record_claims([
        ClaimIn(namespace="ns", subject=EntityRef(type="cve", key=f"CVE-2026-{i}"), predicate="affects",
                object=hub, source="nvd", observed_at=t.replace(hour=i)) for i in range(8)
    ] + [ClaimIn(namespace="ns", subject=host, predicate="runs_software", object=hub, source="inv", observed_at=t)])
    # single subject on the hub
    pack = build_pack(store, AskRequest(namespace="ns", subject=hub, question="exploited", budget=2000))
    assert [(x.entity.key, x.gathered, x.total) for x in pack.truncated] == [("linux:linux_kernel", 5, 9)]
    # reached through a scope: the host itself is small, the hub is not
    scope = ScopeSpec(subjects=[host], expand=["runs_software", "affects"], depth=2)
    pack = build_pack(store, AskRequest(namespace="ns", scope=scope, question="exploited", budget=3000))
    assert [x.entity.key for x in pack.truncated] == ["linux:linux_kernel"]
    assert len(pack.subjects) <= 1 + 1 + 5                    # the cap really did cut the expansion
    # expanding a handle on the hub carries the note too
    small = build_pack(store, AskRequest(namespace="ns", subject=hub, question="exploited", budget=1))
    more = expand_pack(store, small.handles[0].id, budget=3000)
    assert more.truncated and more.truncated[0].total == 9
    # an ordinary entity reports nothing
    assert build_pack(store, AskRequest(namespace="ns", subject=host, question="x", budget=500)).truncated == []
    store.close()


def test_a_failing_query_embedder_degrades_to_keyword_ranking(tmp_path):
    """D-039: one ask stalled 30 s behind the embedder. Provider failure at
    ask time means keyword ranking for that ask, not an error or a wait."""
    from loom.context import _query_cache
    store, web01 = make_store(tmp_path)

    class Down:
        model = "down"
        def embed(self, texts):
            raise RuntimeError("provider unreachable")
        def embed_query(self, text):
            raise RuntimeError("provider unreachable")

    _query_cache.clear()
    pack = build_pack(store, AskRequest(subject=web01, question="who logged in?", budget=800), embedder=Down())
    assert pack.items and all(i.kind != "doc_excerpt" for i in pack.items)
    assert any("logged_in_by" in i.text for i in pack.items)
