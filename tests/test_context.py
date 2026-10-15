from datetime import datetime, timezone


from loomctx.context import (
    build_pack, decode_handle, est_tokens, expand_pack, handle_tokens, item_tokens,
)
from loomctx.contracts import AskRequest, ClaimIn, EntityRef, Observation, ScopeSpec
from loomctx.store.sqlite import SqliteStore


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
    # D-051: citations and handles are charged too, and the sum is reported
    charged = sum(item_tokens(i) for i in pack.items) + sum(handle_tokens(h) for h in pack.handles)
    assert pack.charged_tokens == charged <= 200
    assert pack.handles, "what was cut is still reachable"
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
    from loomctx.context import embed_query, _query_cache
    from loomctx.llm import HashingEmbedder
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
    from loomctx.context import _recency
    from loomctx.contracts import Observation
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
    from loomctx.enrich import embed_pending
    from loomctx.llm import HashingEmbedder
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
    # D-051: the fresh, un-embedded login has no cosine rank, so it earns
    # only the lexical leg's share of the fused score — but that leg ranks
    # it first for this question, so it sits above every embedded fact that
    # does not answer it, and below the embedded login that both legs rank
    fresh = next(i for i in pack.items if "fresh" in i.text)
    jdoe = next(i for i in pack.items if "jdoe" in i.text)   # embedded login
    others = [i.score for i in pack.items if i.kind == "fact" and "logged_in_by" not in i.text]
    assert fresh.score <= jdoe.score
    assert fresh.score > max(others)


def test_numpy_and_python_cosines_agree():
    from loomctx.context import _cosine, cosines
    q = [1.0, 2.0, 3.0]
    vecs = {"a": [1.0, 2.0, 3.0], "b": [-1.0, 0.0, 0.5], "z": [0.0, 0.0, 0.0],
            "short": [1.0, 2.0]}
    got = cosines(q, vecs)
    assert "short" not in got  # another embedding space is skipped, not scored 0
    for k in ("a", "b", "z"):
        assert abs(got[k] - _cosine(q, vecs[k])) < 1e-9, k


def test_handles_are_capped_and_the_rest_counted(tmp_path, monkeypatch):
    """D-035: a scope over a hub entity produced 8,234 handles. Handles stay
    in priority order, stop at the cap, and the pack says how many were left."""
    import loomctx.context as ctx
    from loomctx.context import _MAX_HANDLES
    store = SqliteStore(tmp_path / "cap.db")
    subj = EntityRef(type="host", key="busy")
    store.record_claims([
        ClaimIn(namespace="ns", subject=subj, predicate=f"pred_{i}", object=i, source="s",
                observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc))
        for i in range(_MAX_HANDLES + 20)
    ])
    # D-051: handles are charged too, so at a budget that holds nothing the
    # pack still ships exactly one (the promise that what was cut is
    # reachable) and counts the rest
    pack = build_pack(store, AskRequest(namespace="ns", subject=subj, question="x", budget=1))
    assert pack.items == []
    assert len(pack.handles) == 1 and pack.omitted_handles == _MAX_HANDLES + 19
    assert pack.charged_tokens == handle_tokens(pack.handles[0])
    # with the handle share lifted, the cap is what bounds them: facts of
    # ~700 tokens each fit nowhere in 1,000, so every thread is a handle
    long = SqliteStore(tmp_path / "cap-long.db")
    long.record_claims([
        ClaimIn(namespace="ns", subject=subj, predicate=f"pred_{i}", object="x" * 2000, source="s",
                observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc))
        for i in range(_MAX_HANDLES + 20)
    ])
    monkeypatch.setattr(ctx, "_HANDLE_BUDGET_SHARE", 1.0)
    monkeypatch.setattr(ctx, "_MAX_HANDLES", 8)
    pack = build_pack(long, AskRequest(namespace="ns", subject=subj, question="x", budget=1000))
    assert pack.items == [] and len(pack.handles) == 8 and pack.omitted_handles == _MAX_HANDLES + 12
    assert pack.charged_tokens <= 1000
    roomy = build_pack(store, AskRequest(namespace="ns", subject=subj, question="x", budget=5000))
    assert roomy.omitted_handles == 0 and roomy.handles == []
    store.close()
    long.close()


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
    from loomctx.contracts import ScopeSpec
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
    from loomctx.contracts import ScopeSpec
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
    pack = build_pack(store, AskRequest(namespace="ns", scope=scope, question="exploited", budget=300))
    texts = [(i.kind, i.text) for i in pack.items]
    idx = {p: n for n, (k, txt) in enumerate(texts) for p in ("runs_software", "affects", "exploited_in_wild") if p in txt}
    assert set(idx) == {"runs_software", "affects", "exploited_in_wild"}
    assert idx["runs_software"] < idx["affects"] < idx["exploited_in_wild"]
    assert [k for k, txt in texts if "runs_software" in txt or "affects" in txt] == ["relation", "relation"]
    assert sum(1 for k, _ in texts if k == "relation") == 2   # edges ship once
    store.close()


def test_inbound_facts_on_a_reached_subject_carry_its_path(tmp_path):
    """S-27: a fact gathered on a reached entity as an INBOUND edge (CVE-Y
    affects nginx, 'affects' not walked) was keyed on its subject — outside
    the pack — and shipped without 'web-01 runs nginx', the edge that
    says why nginx is in the pack at all."""
    from loomctx.contracts import ScopeSpec
    store = SqliteStore(tmp_path / "inpath.db")
    t = datetime(2026, 7, 1, tzinfo=timezone.utc)
    host, prod = EntityRef(type="host", key="web-01"), EntityRef(type="product", key="nginx")
    store.record_claims([
        ClaimIn(namespace="ns", subject=host, predicate="runs_software", object=prod, source="inv", observed_at=t),
        ClaimIn(namespace="ns", subject=EntityRef(type="cve", key="CVE-2026-9"), predicate="affects",
                object=prod, source="nvd", observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc)),
    ])
    scope = ScopeSpec(subjects=[host], expand=["runs_software"], depth=1)
    pack = build_pack(store, AskRequest(namespace="ns", scope=scope, question="which cve affects it", budget=400))
    texts = [(i.kind, i.text) for i in pack.items]
    at = {p: n for n, (_, txt) in enumerate(texts) for p in ("runs_software", "affects") if p in txt}
    assert set(at) == {"runs_software", "affects"} and at["runs_software"] < at["affects"]
    assert texts[at["runs_software"]][0] == "relation" and texts[at["affects"]][0] == "fact"
    # when the chain does not fit, neither does the fact (D-035): it is a thread on nginx
    fact_only = next(i for i in pack.items if "affects" in i.text)
    tight = build_pack(store, AskRequest(namespace="ns", scope=scope, question="which cve affects it",
                                         budget=item_tokens(fact_only) + 1))
    assert not any("affects" in i.text for i in tight.items)
    store.close()


def test_naming_the_subject_does_not_boost_its_own_facts(tmp_path):
    """D-036: 'is web-01 exposed to anything exploited in the wild?' — every
    recent login *about web-01* matched as many question words as the KEV
    fact two hops away and outranked it on recency. The root subject's own
    name is the frame of the question, not its topic."""
    from loomctx.contracts import ScopeSpec
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
    from loomctx.context import encode_handle
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
    import loomctx.context as ctx
    from loomctx.contracts import ScopeSpec
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
    # expanding a thread handle on the hub carries the note too (the page
    # handle for the unexamined window comes first, D-051; lift the handle
    # share so both ship at a budget that fits nothing)
    monkeypatch.setattr(ctx, "_HANDLE_BUDGET_SHARE", 1.0)
    small = build_pack(store, AskRequest(namespace="ns", subject=hub, question="exploited", budget=300))
    thread = next(h for h in small.handles if "'affects'" in h.hint)
    more = expand_pack(store, thread.id, budget=3000)
    assert more.truncated and more.truncated[0].total == 9
    # an ordinary entity reports nothing
    assert build_pack(store, AskRequest(namespace="ns", subject=host, question="x", budget=500)).truncated == []
    store.close()


def test_a_failing_query_embedder_degrades_to_keyword_ranking(tmp_path):
    """D-039: one ask stalled 30 s behind the embedder. Provider failure at
    ask time means keyword ranking for that ask, not an error or a wait."""
    from loomctx.context import _query_cache
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


def test_as_of_is_bounded_in_the_gather_not_after_it(tmp_path, monkeypatch):
    """D-046: as_of filtered in Python after a newest-first LIMIT, so an
    entity with more than the gather limit of rows newer than T yielded an
    empty time-travel pack. The bound is the store's now; the rows as of T
    come back, and a fact scheduled for later but asserted before T is in
    the view (that is valid_at's job to hide)."""
    import loomctx.context as ctx
    monkeypatch.setattr(ctx, "_GATHER_LIMIT", 5)
    store = SqliteStore(tmp_path / "asof.db")
    host = EntityRef(type="host", key="web-01")
    t = _at(8, 1)
    store.record_claims(
        [ClaimIn(subject=host, predicate="old_fact", object=f"o{i}", source="s",
                 observed_at=_at(7, 1 + i)) for i in range(3)]
        + [ClaimIn(subject=host, predicate="scheduled", object="maintenance", source="cal",
                   observed_at=_at(7, 20), valid_from=_at(9, 1))]
        + [ClaimIn(subject=host, predicate="new_fact", object=f"n{i}", source="s",
                   observed_at=_at(8, 2 + i)) for i in range(8)])
    pack = build_pack(store, AskRequest(subject=host, question="", budget=4000, as_of=t))
    text = " | ".join(i.text for i in pack.items)
    assert text.count("old_fact") == 3 and "new_fact" not in text
    assert "scheduled" in text  # known at T, even though it applies later
    assert pack.truncated == []  # four rows as of T: the limit was not hit
    # ...and hidden by valid_at, which is the fact-time axis
    pack = build_pack(store, AskRequest(subject=host, question="", budget=4000,
                                        as_of=t, valid_at=t))
    assert "scheduled" not in " | ".join(i.text for i in pack.items)
    store.close()


def test_truncation_total_honors_as_of(tmp_path, monkeypatch):
    """D-046: the `truncated` denominator counts rows as of T, not overall."""
    import loomctx.context as ctx
    monkeypatch.setattr(ctx, "_GATHER_LIMIT", 5)
    store = SqliteStore(tmp_path / "asof-trunc.db")
    host = EntityRef(type="host", key="web-01")
    store.record_claims(
        [ClaimIn(subject=host, predicate="old", object=i, source="s", observed_at=_at(7, 1 + i))
         for i in range(7)]
        + [ClaimIn(subject=host, predicate="new", object=i, source="s", observed_at=_at(8, 1 + i))
           for i in range(6)])
    pack = build_pack(store, AskRequest(subject=host, question="", budget=4000, as_of=_at(7, 31)))
    assert [(x.gathered, x.total) for x in pack.truncated] == [(5, 7)]
    assert all("old" in i.text for i in pack.items)
    # the expanded thread handle inherits the bound
    monkeypatch.setattr(ctx, "_HANDLE_BUDGET_SHARE", 1.0)
    tiny = build_pack(store, AskRequest(subject=host, question="", budget=200, as_of=_at(7, 31)))
    thread = next(h for h in tiny.handles if "'old'" in h.hint)
    more = expand_pack(store, thread.id, budget=4000)
    assert more.truncated and more.truncated[0].total == 7
    assert all("old" in i.text for i in more.items)
    # so does the page handle for the two rows the window missed (D-051)
    page = next(h for h in tiny.handles if "not examined" in h.hint)
    assert decode_handle(page.id)["as_of"].startswith("2026-07-31")
    rest = expand_pack(store, page.id, budget=4000)
    assert all("old" in i.text for i in rest.items) and rest.truncated == []
    store.close()


def test_a_forward_dated_row_does_not_age_every_real_fact(tmp_path, monkeypatch):
    """D-046: recency decays relative to the newest gathered fact; a row
    observed in 2099 (restored from an export, or a typo'd year) made every
    real fact decades old and flattened ranking. The reference is clamped
    at now, so the real facts keep their relative recency."""
    import loomctx.context as ctx
    from loomctx.contracts import Observation
    monkeypatch.setattr(ctx, "_now", lambda: _at(9, 1))  # the newest real fact's instant
    store, web01 = make_store(tmp_path)
    before = build_pack(store, AskRequest(subject=web01, question="who logged in?", budget=3000))
    far = datetime(2099, 1, 1, tzinfo=timezone.utc)
    store.restore_observation(Observation(
        id="poison", namespace="default", subject=web01, predicate="note", object="from the future",
        observed_at=far, recorded_at=far, source="typo", confidence=1.0))
    after = build_pack(store, AskRequest(subject=web01, question="who logged in?", budget=3000))
    score = {i.text: i.score for i in after.items if i.kind == "fact"}
    for item in before.items:
        if item.kind == "fact":
            assert score[item.text] == item.score, item.text
    facts = [i for i in after.items if i.kind == "fact"]
    assert "logged_in_by" in facts[0].text


def test_expanding_a_conflict_handle_with_its_estimate_yields_the_conflict(tmp_path):
    """D-046: a conflict handle says est_tokens; expanding it with exactly
    that budget used to return nothing (the half-budget share cap applied
    to the expansion too, and dropped the very item the handle stood for)."""
    store, web01 = make_store(tmp_path)
    pack = build_pack(store, AskRequest(subject=web01, question="what os?", budget=25))
    handle = next(h for h in pack.handles if h.kind == "conflict")
    expanded = expand_pack(store, handle.id, budget=handle.est_tokens)
    conflicts = [i for i in expanded.items if i.kind == "conflict"]
    assert len(conflicts) == 1 and "runs_os" in conflicts[0].text
    assert item_tokens(conflicts[0]) == handle.est_tokens   # the estimate is the real charge
    assert expanded.charged_tokens <= expanded.budget


def test_no_vectors_at_all_means_keyword_ranking(tmp_path):
    """D-046: an embedder serving with vectors for none of the gathered
    rows (worker backlog, a different model) used to score everything with
    a neutral cosine, which cut keyword weight to 0.15 and let recency
    decide: on 'what os?' the newest login outranked the July OS fact.
    With no cosines the keyword formula ranks."""
    from loomctx.llm import HashingEmbedder
    store, web01 = make_store(tmp_path)
    pack = build_pack(store, AskRequest(subject=web01, question="what os?", budget=3000),
                      embedder=HashingEmbedder())  # nothing embedded yet
    facts = [i for i in pack.items if i.kind == "fact"]
    assert all("runs_os" in f.text for f in facts[:2]), [f.text for f in facts[:3]]


def test_unembedded_facts_rank_by_the_lexical_leg_alone(tmp_path, monkeypatch):
    """D-051: inside a partially embedded set, a fact with no vector is
    absent from the cosine leg and reciprocal rank fusion simply gives it
    nothing from that leg — no fill-in value. With no lexical match either
    it takes the relevance floor and still ships; with one it earns that
    leg's full share."""
    import loomctx.context as ctx
    monkeypatch.setattr(ctx, "_now", lambda: _at(9, 1))
    host = EntityRef(type="host", key="h")

    def obs(i):
        return Observation(id=f"o{i}", namespace="d", subject=host, predicate="p", object=f"v{i}",
                           observed_at=_at(9, 1), recorded_at=_at(9, 1), source="s", confidence=1.0)
    rows = [obs(1), obs(2), obs(3), obs(4)]
    pack = ctx._pack(namespace="d", subjects=[host], question="anything", as_of=None, budget=5000,
                     observations=rows, cos_map={"o1": 0.9, "o2": 0.1, "o3": 0.5}, semantic=True)
    score = {i.text.split()[2]: i.score for i in pack.items if i.kind == "fact"}
    assert score["v1"] > score["v3"] > score["v2"] >= score["v4"] > 0   # cosine order, then the floor
    # ranked first by the lexical leg, the un-embedded fact ties the cosine leader
    pack = ctx._pack(namespace="d", subjects=[host], question="v4", as_of=None, budget=5000,
                     observations=rows, cos_map={"o1": 0.9, "o2": 0.1, "o3": 0.5}, semantic=True)
    score = {i.text.split()[2]: i.score for i in pack.items if i.kind == "fact"}
    assert score["v4"] == score["v1"] > score["v3"]


def test_query_cache_eviction_is_safe_across_threads():
    """D-046: eviction popped the first key of a dict other threads were
    inserting into (asks run in the threadpool); the cache is now locked
    and stays bounded under concurrent misses."""
    from concurrent.futures import ThreadPoolExecutor
    from loomctx.context import _QUERY_CACHE_SIZE, _query_cache, embed_query
    from loomctx.llm import HashingEmbedder
    _query_cache.clear()
    e = HashingEmbedder()
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda i: embed_query(e, f"question number {i}"), range(_QUERY_CACHE_SIZE * 3)))
    assert len(_query_cache) <= _QUERY_CACHE_SIZE


def test_attrs_cannot_buy_keyword_rank(tmp_path):
    """D-046: the keyword scorer read attrs, which the reader never sees;
    a fact whose attrs were stuffed with the question's words outranked
    the fact that actually answers it."""
    store, web01 = make_store(tmp_path)
    store.record_claim(ClaimIn(
        subject=web01, predicate="communicated_with", object=EntityRef(type="host", key="db-99"),
        observed_at=_at(9, 3), source="netflow",
        attrs={"note": "who logged in logged in logged in host login who logged"}))
    pack = build_pack(store, AskRequest(subject=web01, question="who logged in to this host?", budget=3000))
    facts = [i for i in pack.items if i.kind == "fact"]
    assert "logged_in_by" in facts[0].text and "jdoe" in facts[0].text
    stuffed = next(i for i in facts if "db-99" in i.text)
    assert stuffed.score < facts[0].score


# ------------------------------------------------------------ D-051 packing #

def test_packing_prefers_diversity_over_twenty_identical_logins(tmp_path, monkeypatch):
    """D-051: greedy trim by score filled a pack with the newest logins
    and nothing else. Once a predicate holds three items, further items of
    it compete at half their value per token, so relevant facts of other
    kinds get in while the logins stay well represented."""
    import loomctx.context as ctx
    monkeypatch.setattr(ctx, "_now", lambda: _at(9, 1))
    store = SqliteStore(tmp_path / "diverse.db")
    host = EntityRef(type="host", key="web-01")
    claims = [ClaimIn(subject=host, predicate="logged_in_by", object=EntityRef(type="user", key=f"u{i}"),
                      source="auth-log", observed_at=_at(9, 1, hour=i % 24)) for i in range(40)]
    claims += [ClaimIn(subject=host, predicate="communicated_with", object=EntityRef(type="host", key=f"db-{i}"),
                       source="netflow", confidence=0.9, observed_at=_at(8, 22)) for i in range(5)]
    claims += [ClaimIn(subject=host, predicate="listens_on_port", object=port, source="nmap-scan",
                       observed_at=_at(7, 22)) for port in (80, 443)]
    store.record_claims(claims)
    pack = build_pack(store, AskRequest(subject=host, question="what is going on with this host?", budget=700))
    kinds = [i.text.split()[1] for i in pack.items if i.kind == "fact"]
    assert len(kinds) >= 10
    assert kinds[:3] == ["logged_in_by"] * 3                     # the best-scoring thread still leads
    assert "communicated_with" in kinds and "listens_on_port" in kinds
    assert kinds.count("logged_in_by") <= len(kinds) - 4
    assert pack.charged_tokens <= 700
    # the cut logins are still one thread
    assert any("'logged_in_by'" in h.hint for h in pack.handles)
    store.close()


def test_long_facts_are_charged_by_their_length(tmp_path):
    """D-051: value per token — a 900-character value costs what it costs,
    and a budget that holds either it or a dozen short facts takes the
    short ones when they score alike."""
    store = SqliteStore(tmp_path / "long.db")
    host = EntityRef(type="host", key="web-01")
    t = _at(9, 1)
    store.record_claims(
        [ClaimIn(subject=host, predicate="note", object="x" * 900, source="wiki", observed_at=t)]
        + [ClaimIn(subject=host, predicate=f"fact_{i}", object=i, source="s", observed_at=t) for i in range(12)])
    pack = build_pack(store, AskRequest(subject=host, question="", budget=560))
    assert not any(i.text.split()[1] == "note" for i in pack.items)
    assert sum(1 for i in pack.items if i.kind == "fact") >= 8
    assert any("'note'" in h.hint for h in pack.handles)
    store.close()


# ---------------------------------------------------------- D-051 conflicts #

def test_entity_valued_conflict_between_sources(tmp_path):
    """D-051: dhcp says the ip belongs to web-01, arp-scan says laptop-17,
    both current — a disagreement, cited on both sides. Scored a notch
    below a scalar one: as often a resolution gap as a contradiction."""
    store = SqliteStore(tmp_path / "entity-conflict.db")
    ip = EntityRef(type="ip", key="10.0.4.7")
    store.record_claims([
        ClaimIn(subject=ip, predicate="assigned_to", object=EntityRef(type="host", key="web-01"),
                observed_at=_at(8, 1), valid_from=_at(8, 1), source="dhcp"),
        ClaimIn(subject=ip, predicate="assigned_to", object=EntityRef(type="host", key="laptop-17"),
                observed_at=_at(8, 20), source="arp-scan"),
    ])
    pack = build_pack(store, AskRequest(subject=ip, question="which host?", budget=2000))
    conflicts = [i for i in pack.items if i.kind == "conflict"]
    assert len(conflicts) == 1 and "assigned_to" in conflicts[0].text
    assert {c.source for c in conflicts[0].citations} == {"dhcp", "arp-scan"}
    assert "host:web-01" in conflicts[0].text and "host:laptop-17" in conflicts[0].text
    assert conflicts[0].score == 0.95
    store.close()
    # a window that closed before the other opened is a history, not a conflict
    store, ip = _lease_store(tmp_path)
    pack = build_pack(store, AskRequest(subject=ip, question="which host?", budget=2000))
    assert not [i for i in pack.items if i.kind == "conflict"]
    store.close()


def test_single_source_lease_reassignment_is_a_time_series(tmp_path):
    """The seed's planted moment: one source (dhcp-log) hands the ip from
    web-01 to laptop-17 with adjoining windows — two facts, no conflict."""
    from loomctx.seed import cmd_load
    db = tmp_path / "seed.db"
    cmd_load(str(db), seed=42)
    store = SqliteStore(db)
    pack = build_pack(store, AskRequest(namespace="netsec", subject=EntityRef(type="ip", key="10.0.4.7"),
                                        question="which host was assigned this ip?", budget=800))
    assert not [i for i in pack.items if i.kind == "conflict"]
    text = " | ".join(i.text for i in pack.items)
    assert "web-01" in text and "laptop-17" in text and "[valid" in text
    store.close()


def test_multi_valued_edges_from_one_source_are_not_contested(tmp_path):
    """D-051: auth-log records three logins and vpn-log a fourth — a set,
    not four answers to one question. Only when every source asserts one
    current object is a differing object a disagreement."""
    store = SqliteStore(tmp_path / "multi.db")
    host = EntityRef(type="host", key="web-01")
    store.record_claims(
        [ClaimIn(subject=host, predicate="logged_in_by", object=EntityRef(type="user", key=u),
                 observed_at=_at(9, 1), source="auth-log") for u in ("jdoe", "asmith", "rlee")]
        + [ClaimIn(subject=host, predicate="logged_in_by", object=EntityRef(type="user", key="mchen"),
                   observed_at=_at(9, 1), source="vpn-log")])
    pack = build_pack(store, AskRequest(subject=host, question="who?", budget=2000))
    assert not [i for i in pack.items if i.kind == "conflict"]
    store.close()


def test_scalar_values_are_compared_normalized(tmp_path):
    """D-051: `Ubuntu` vs `ubuntu`, `True` vs `"true"`, `9.8` vs `"9.8"` are
    one value from two sources, not a conflict; `Ubuntu` vs `Fedora` is."""
    store = SqliteStore(tmp_path / "norm.db")
    host = EntityRef(type="host", key="web-01")
    store.record_claims([
        ClaimIn(subject=host, predicate="runs_os", object="Ubuntu", observed_at=_at(8, 1), source="inv"),
        ClaimIn(subject=host, predicate="runs_os", object="ubuntu ", observed_at=_at(8, 2), source="scan"),
        ClaimIn(subject=host, predicate="exploited", object=True, observed_at=_at(8, 1), source="kev"),
        ClaimIn(subject=host, predicate="exploited", object="true", observed_at=_at(8, 2), source="feed"),
        ClaimIn(subject=host, predicate="cvss", object=9.8, observed_at=_at(8, 1), source="nist"),
        ClaimIn(subject=host, predicate="cvss", object="9.8", observed_at=_at(8, 2), source="cna"),
        ClaimIn(subject=host, predicate="cvss", object=9, observed_at=_at(8, 3), source="third"),
        ClaimIn(subject=host, predicate="cvss", object="9.0", observed_at=_at(8, 4), source="fourth"),
    ])
    pack = build_pack(store, AskRequest(subject=host, question="?", budget=3000))
    conflicts = [i for i in pack.items if i.kind == "conflict"]
    assert len(conflicts) == 1 and "cvss" in conflicts[0].text        # 9.8 vs 9, not 9 vs 9.0
    assert "runs_os" not in conflicts[0].text
    store.record_claim(ClaimIn(subject=host, predicate="runs_os", object="Fedora",
                               observed_at=_at(8, 3), source="agent"))
    pack = build_pack(store, AskRequest(subject=host, question="?", budget=3000))
    assert any(i.kind == "conflict" and "runs_os" in i.text for i in pack.items)
    store.close()


def test_sequential_scalar_windows_are_not_a_conflict(tmp_path):
    """D-051: two sources whose validity windows never share an instant
    describe a succession, not a disagreement — even when both windows are
    still open as of the horizon."""
    store = SqliteStore(tmp_path / "seq.db")
    host = EntityRef(type="host", key="db-01")
    store.record_claims([
        ClaimIn(subject=host, predicate="role", object="primary", observed_at=_at(7, 1),
                valid_from=_at(9, 1), valid_to=_at(9, 10), source="plan-a"),
        ClaimIn(subject=host, predicate="role", object="replica", observed_at=_at(7, 2),
                valid_from=_at(9, 10), source="plan-b"),
    ])
    pack = build_pack(store, AskRequest(subject=host, question="role?", budget=2000, as_of=_at(8, 1)))
    assert not [i for i in pack.items if i.kind == "conflict"]
    store.close()


# --------------------------------------------------------- D-051 pagination #

def test_page_handles_reach_past_the_gather_cap(tmp_path, monkeypatch):
    """D-051: the 1,740 kernel CVEs beyond the gather window were reported
    but unreachable. A truncated entity now gets a `more` handle whose
    payload carries the window's edge; expanding it gathers the next
    window, with its own next-page handle, until the last one."""
    import loomctx.context as ctx
    monkeypatch.setattr(ctx, "_GATHER_LIMIT", 5)
    store = SqliteStore(tmp_path / "pages.db")
    hub = EntityRef(type="product", key="linux:linux_kernel")
    t = datetime(2026, 9, 1, tzinfo=timezone.utc)
    store.record_claims([
        ClaimIn(namespace="ns", subject=EntityRef(type="cve", key=f"CVE-2026-{i}"), predicate="affects",
                object=hub, source="nvd", observed_at=t.replace(hour=i)) for i in range(12)
    ])
    seen: set[str] = set()
    pack = build_pack(store, AskRequest(namespace="ns", subject=hub, question="exploited", budget=3000))
    assert pack.truncated and (pack.truncated[0].gathered, pack.truncated[0].total) == (5, 12)
    pages = 0
    while True:
        seen |= {c.observation_id for i in pack.items for c in i.citations}
        page = [h for h in pack.handles if "not examined" in h.hint]
        if not page:
            break
        meta = decode_handle(page[0].id)
        assert meta["question"] == "exploited" and meta["before"] and meta["predicate"] == ""
        assert page[0].kind == "more"
        pages += 1
        pack = expand_pack(store, page[0].id, budget=3000)
        assert pack.question == "exploited"
    assert pages == 2 and len(seen) == 12
    # with a secret set the page handle is signed like any other
    monkeypatch.setenv("LOOMCTX_HANDLE_SECRET", "s3")
    pack = build_pack(store, AskRequest(namespace="ns", subject=hub, question="exploited", budget=3000))
    page = next(h for h in pack.handles if "not examined" in h.hint)
    assert page.id.startswith("h2_") and expand_pack(store, page.id, budget=3000).items
    store.close()


def test_a_page_keeps_its_window_for_the_threads_it_cuts(tmp_path, monkeypatch):
    """A thread handle minted inside a page carries the page's edge, so
    expanding it stays in that window instead of jumping back to the
    newest rows."""
    import loomctx.context as ctx
    monkeypatch.setattr(ctx, "_GATHER_LIMIT", 5)
    store = SqliteStore(tmp_path / "page-threads.db")
    host = EntityRef(type="host", key="web-01")
    store.record_claims([
        ClaimIn(subject=host, predicate="logged_in_by", object=EntityRef(type="user", key=f"u{i}"),
                source="auth", observed_at=_at(8, 1 + i)) for i in range(12)
    ])
    first = build_pack(store, AskRequest(subject=host, question="who", budget=3000))
    page = next(h for h in first.handles if "not examined" in h.hint)
    monkeypatch.setattr(ctx, "_HANDLE_BUDGET_SHARE", 1.0)   # room for the page's own next page AND a thread
    tiny = expand_pack(store, page.id, budget=200)
    thread = next(h for h in tiny.handles if "'logged_in_by'" in h.hint)
    assert decode_handle(thread.id)["before"] == decode_handle(page.id)["before"]
    more = expand_pack(store, thread.id, budget=3000)
    users = {i.text.split()[2] for i in more.items}
    assert users <= {f"user:u{i}" for i in range(8)} and "user:u11" not in users
    store.close()


# -------------------------------------------------------- D-050 supersession #

def _obs(id, predicate, obj, when, source, supersedes=None, subject=None):
    return Observation(id=id, namespace="d", subject=subject or EntityRef(type="host", key="web-01"),
                       predicate=predicate, object=obj, observed_at=when, recorded_at=when,
                       source=source, confidence=1.0, supersedes=supersedes)


class _FakeStore:
    """Hands build_pack a fixed observation list (the store column that
    persists `supersedes` lands separately; the read path is written
    against the contract field)."""

    def __init__(self, rows):
        self.rows = rows

    def observations_for_many(self, namespace, refs, limit=100, observed_before=None, predicates=None):
        rows = [o for o in self.rows
                if (observed_before is None or o.observed_at <= observed_before)
                and (predicates is None or o.predicate in predicates)]
        return {(r.type, r.key): [o for o in rows if o.subject == r] for r in refs}

    def count_observations(self, namespace, ref, observed_before=None, allowed_types=None):
        return len(self.observations_for_many(namespace, [ref], observed_before=observed_before)[(ref.type, ref.key)])

    def resolve_refs(self, namespace, refs):
        return {}

    def corrections_of(self, namespace, ids, observed_before=None):
        return [o for o in self.rows if o.supersedes in ids
                and (observed_before is None or o.observed_at <= observed_before)]

    def get_dossier(self, namespace, ref):
        return None


def _supersession_rows():
    """asset-inventory said fedora (X), nmap-scan says ubuntu (Z): a
    conflict — until asset-inventory corrects itself with ubuntu (Y),
    naming X."""
    return [
        _obs("x" * 32, "runs_os", "fedora-44", _at(7, 5), "asset-inventory"),
        _obs("z" * 32, "runs_os", "ubuntu-22.04", _at(8, 20), "nmap-scan"),
        _obs("y" * 32, "runs_os", "ubuntu-22.04", _at(9, 1), "asset-inventory", supersedes="x" * 32),
    ]


def test_superseded_observation_is_history_not_a_side(monkeypatch):
    """D-050: a recorded supersession retires the corrected fact from
    conflict detection, ranks it as history and says so in its text."""
    import loomctx.context as ctx
    monkeypatch.setattr(ctx, "_now", lambda: _at(9, 2))
    host = EntityRef(type="host", key="web-01")
    pack = build_pack(_FakeStore(_supersession_rows()), AskRequest(
        namespace="d", subject=host, question="what os?", budget=3000))
    assert not [i for i in pack.items if i.kind == "conflict"]
    facts = {i.citations[0].observation_id: i for i in pack.items if i.kind == "fact"}
    old, new, scan = facts["x" * 32], facts["y" * 32], facts["z" * 32]
    assert old.text.endswith(f"[superseded by {'y' * 12}]")
    assert "superseded" not in new.text and "superseded" not in scan.text
    assert old.score < scan.score < new.score
    assert item_tokens(old) > item_tokens(new)   # the suffix is charged like any text
    # as of a moment before the correction, the old fact is current again:
    # the conflict is back and the suffix is gone
    past = build_pack(_FakeStore(_supersession_rows()), AskRequest(
        namespace="d", subject=host, question="what os?", budget=3000, as_of=_at(8, 25)))
    assert [i.kind for i in past.items][0] == "conflict"
    assert all("superseded" not in i.text for i in past.items)


def test_supersession_needs_the_correction_in_view():
    """Only a visible later observation retires another; a `supersedes`
    pointing outside the gathered set (redacted, another subject) does
    nothing, and self-reference is ignored."""
    import loomctx.context as ctx
    rows = _supersession_rows()
    assert set(ctx._supersession(rows)) == {"x" * 32}
    assert ctx._supersession(rows[:2]) == {}
    stray = _obs("w" * 32, "runs_os", "debian", _at(9, 3), "cmdb", supersedes="nope")
    loop = _obs("v" * 32, "runs_os", "debian", _at(9, 3), "cmdb", supersedes="v" * 32)
    assert set(ctx._supersession(rows + [stray, loop])) == {"x" * 32}
    # the newest correction wins when two name the same observation
    again = _obs("u" * 32, "runs_os", "ubuntu-24.04", _at(9, 4), "asset-inventory", supersedes="x" * 32)
    assert ctx._supersession(rows + [again])["x" * 32].id == "u" * 32


def test_superseded_fact_is_discounted_in_the_recency_overview(monkeypatch):
    """With no question the pack is a recency overview; the superseded
    fact still ranks at half, below the older fact that replaced nothing."""
    import loomctx.context as ctx
    monkeypatch.setattr(ctx, "_now", lambda: _at(9, 2))
    host = EntityRef(type="host", key="web-01")
    rows = [
        _obs("a" * 32, "owner", "alice", _at(9, 1), "cmdb"),
        _obs("b" * 32, "owner", "bob", _at(9, 1), "cmdb", supersedes="a" * 32),
        _obs("c" * 32, "note", "x", _at(8, 1), "wiki"),
    ]
    pack = ctx._pack(namespace="d", subjects=[host], question=None, as_of=None, budget=3000, observations=rows)
    score = {i.citations[0].observation_id[0]: i.score for i in pack.items}
    assert score["b"] > score["c"] > score["a"]


# ------------------------------------------------ read-path hardening (D-058)

def _claims(store, rows, namespace="default"):
    return store.record_claims([ClaimIn(namespace=namespace, **r) for r in rows])


def test_a_source_that_moved_on_is_not_a_side(tmp_path):
    """cmdb said ubuntu-20.04 in January and ubuntu-22.04 in March; nmap
    says ubuntu-22.04 in April. Every source's CURRENT claim agrees — the
    January row is cmdb's own history, not a side of a conflict."""
    store = SqliteStore(tmp_path / "moved.db")
    web01 = EntityRef(type="host", key="web-01")
    _claims(store, [
        dict(subject=web01, predicate="runs_os", object="ubuntu-20.04", observed_at=_at(1, 5), source="cmdb"),
        dict(subject=web01, predicate="runs_os", object="ubuntu-22.04", observed_at=_at(3, 5), source="cmdb"),
        dict(subject=web01, predicate="runs_os", object="ubuntu-22.04", observed_at=_at(4, 5), source="nmap"),
    ])
    pack = build_pack(store, AskRequest(subject=web01, question="what os?", budget=2000))
    assert not [i for i in pack.items if i.kind == "conflict"]
    # a real disagreement between current claims still surfaces, with only
    # the current claims as its sides
    _claims(store, [dict(subject=web01, predicate="runs_os", object="ubuntu-24.04",
                         observed_at=_at(5, 5), source="nmap")])
    pack = build_pack(store, AskRequest(subject=web01, question="what os?", budget=2000))
    conflict = next(i for i in pack.items if i.kind == "conflict")
    assert "ubuntu-24.04" in conflict.text and "ubuntu-22.04" in conflict.text
    assert "20.04" not in conflict.text and len(conflict.citations) == 2
    # several values one source asserts at one instant are a set
    _claims(store, [
        dict(subject=web01, predicate="listens_on_port", object=p, observed_at=_at(6, 1), source="nmap")
        for p in (80, 443)
    ] + [dict(subject=web01, predicate="listens_on_port", object=22, observed_at=_at(6, 2), source="cmdb")])
    pack = build_pack(store, AskRequest(subject=web01, question="ports", budget=2000))
    assert not [i for i in pack.items if i.kind == "conflict" and "listens_on_port" in i.text]
    store.close()


def test_the_planted_demo_conflicts_still_surface(tmp_path):
    """The talk's two conflict moments (src/loomctx/seed.py) survive the
    newest-claim-per-source rule."""
    from loomctx.seed import cmd_load
    cmd_load(str(tmp_path / "seed.db"), seed=42)
    store = SqliteStore(tmp_path / "seed.db")
    for ns, subject, predicate in (("netsec", EntityRef(type="host", key="web-01"), "runs_os"),
                                   ("procurement", EntityRef(type="vendor", key="initech"), "contract_owner")):
        pack = build_pack(store, AskRequest(namespace=ns, subject=subject, question=predicate, budget=800))
        assert pack.items[0].kind == "conflict" and predicate in pack.items[0].text, (ns, pack.items[:1])
    store.close()


def _dossier_store(tmp_path, n_logins=3):
    """web-01 with a host-only fact, user logins, and a brief written from all of them."""
    store = SqliteStore(tmp_path / "brief.db")
    web01 = EntityRef(type="host", key="web-01")
    rows = _claims(store, [
        dict(subject=web01, predicate="runs_os", object="ubuntu-22.04", observed_at=_at(8, 1), source="cmdb"),
    ] + [
        dict(subject=web01, predicate="logged_in_by", object=EntityRef(type="user", key=f"u{i:03d}"),
             observed_at=_at(8, 2 + i % 25, i % 24), source="auth-log")
        for i in range(n_logins)
    ])
    store.put_dossier("default", web01, "web-01 runs ubuntu; u000 and u001 log in daily", len(rows),
                      [o.id for o in rows])
    return store, web01, rows


def test_a_brief_reaches_a_type_scoped_key_only_if_it_may_see_every_citation(tmp_path):
    """The brief's prose was written from the user logins too: a host-only
    key used to receive it because ONE citation (runs_os) was visible."""
    store, web01, _ = _dossier_store(tmp_path)
    req = AskRequest(subject=web01, question="summary", budget=2000)
    scoped = build_pack(store, req, allowed_types=("host",))
    assert not [i for i in scoped.items if i.kind == "brief"]
    assert scoped.withheld_briefs == 1
    everyone = build_pack(store, req, allowed_types=("host", "user"))
    assert [i for i in everyone.items if i.kind == "brief"] and everyone.withheld_briefs == 0
    # a present-tense brief is no answer to "what was true then" either
    past = build_pack(store, req.model_copy(update={"valid_at": _at(8, 3)}))
    assert not [i for i in past.items if i.kind == "brief"] and past.withheld_briefs == 0
    store.close()


def test_a_brief_is_capped_at_a_quarter_of_the_budget(tmp_path):
    """A brief citing 100 observations charged ~1,000 tokens of an
    800-token pack before any fact. It now carries its newest supporting
    observations within a quarter of the budget, charged honestly."""
    import loomctx.context as ctx
    store, web01, rows = _dossier_store(tmp_path, n_logins=99)
    pack = build_pack(store, AskRequest(subject=web01, question="summary", budget=800))
    brief = next(i for i in pack.items if i.kind == "brief")
    assert item_tokens(brief) <= 800 * ctx._BRIEF_BUDGET_SHARE
    assert 1 <= len(brief.citations) <= ctx._BRIEF_MAX_CITES
    newest = sorted(rows, key=lambda o: o.observed_at, reverse=True)[:len(brief.citations)]
    assert [c.observation_id for c in brief.citations] == [o.id for o in newest]
    assert [i for i in pack.items if i.kind == "fact"], "facts still fit"
    assert pack.charged_tokens == sum(item_tokens(i) for i in pack.items) + sum(
        handle_tokens(h) for h in pack.handles) <= 800
    # a budget whose quarter cannot hold the brief's text withholds it, counted
    tiny = build_pack(store, AskRequest(subject=web01, question="summary", budget=60))
    assert not [i for i in tiny.items if i.kind == "brief"] and tiny.withheld_briefs == 1
    store.close()


def test_a_merged_away_name_asks_about_the_canonical_entity(tmp_path):
    """host:WEB01 folded into host:web-01: asking by the old name used to
    return the canonical rows but no conflicts (they were grouped under a
    subject nothing matched), and a scope rooted at it listed web-01 as a
    second, 'reached' subject."""
    store = SqliteStore(tmp_path / "alias.db")
    web01, alias = EntityRef(type="host", key="web-01"), EntityRef(type="host", key="WEB01")
    _claims(store, [
        dict(subject=web01, predicate="runs_os", object="fedora-44", observed_at=_at(8, 1), source="cmdb"),
        dict(subject=alias, predicate="runs_os", object="ubuntu-22.04", observed_at=_at(8, 2), source="nmap"),
        dict(subject=alias, predicate="member_of", object=EntityRef(type="domain", key="corp"),
             observed_at=_at(8, 2), source="ad"),
    ])
    assert store.merge_entities("default", alias, web01)
    pack = build_pack(store, AskRequest(subject=alias, question="what os?", budget=2000))
    assert pack.subjects == [web01] and pack.items[0].kind == "conflict"
    scope = ScopeSpec(subjects=[alias, web01], expand=["member_of"], depth=1)
    scoped = build_pack(store, AskRequest(scope=scope, question="what os?", budget=2000))
    assert [(s.type, s.key) for s in scoped.subjects] == [("host", "web-01"), ("domain", "corp")]
    assert scoped.items[0].kind == "conflict"
    # a handle minted before the merge still expands onto the canonical rows
    from loomctx.context import encode_handle
    handle = encode_handle("default", alias, "runs_os", None)
    assert expand_pack(store, handle, 2000).items
    store.close()


def test_the_scope_walk_is_capped_and_says_so(tmp_path, monkeypatch):
    """500 anchors at depth 3 over a hub reached everything in reach, each
    gathered up to 1,000 rows. The walk now stops at the entity cap and
    the ask at its row cap; both cuts are reported, never silent."""
    store = SqliteStore(tmp_path / "cap.db")
    domain = EntityRef(type="domain", key="corp")
    _claims(store, [
        dict(subject=EntityRef(type="host", key=f"h{i:02d}"), predicate="member_of", object=domain,
             observed_at=_at(8, 1 + i % 25), source="ad") for i in range(30)
    ] + [
        dict(subject=EntityRef(type="host", key=f"h{i:02d}"), predicate="runs_os", object="linux",
             observed_at=_at(8, 1), source="cmdb") for i in range(30)
    ])
    scope = ScopeSpec(subjects=[domain], expand=["member_of"], depth=1)
    req = AskRequest(scope=scope, question="os", budget=4000)
    assert build_pack(store, req).truncated == []
    monkeypatch.setenv("LOOMCTX_MAX_SCOPE_ENTITIES", "10")
    pack = build_pack(store, req)
    assert len(pack.subjects) == 10
    cut = [t for t in pack.truncated if t.reason == "scope_cap"]
    assert cut and cut[0].entity == domain and (cut[0].gathered, cut[0].total) == (10, 31)
    assert not [h for h in pack.handles if "not examined" in h.hint]   # reported, not paged
    from loomctx.answer import render_user_prompt
    assert "the scope was cut at 10 entities (at least 31 reached" in render_user_prompt("os", pack)
    # the row cap: the domain's 30 edges fill it; its members are left out, and counted
    monkeypatch.delenv("LOOMCTX_MAX_SCOPE_ENTITIES")
    monkeypatch.setenv("LOOMCTX_MAX_SCOPE_OBSERVATIONS", "30")
    pack = build_pack(store, req)
    cut = [t for t in pack.truncated if t.reason == "scope_cap"]
    assert pack.subjects == [domain] and cut and (cut[0].gathered, cut[0].total) == (1, 31)
    store.close()


def test_a_selective_topic_admits_only_its_carriers_from_a_crowded_window(tmp_path, monkeypatch):
    """At 500k objects an OU of 14,800 computers, three with unconstrained
    delegation, filled the walk's cap with non-carriers: 20 s a hop, minutes
    at depth 3. A crowded window whose topic singles out at most a fifth of
    it now admits only the carriers, and the cut is reported (D-104); an
    unselective topic still fills the cap as before."""
    store = SqliteStore(tmp_path / "sel.db")
    domain = EntityRef(type="domain", key="corp")
    hosts = [EntityRef(type="host", key=f"h{i:02d}") for i in range(60)]
    _claims(store, [dict(subject=h, predicate="member_of", object=domain, observed_at=_at(8, 1 + i % 25),
                         source="ad") for i, h in enumerate(hosts)]
            + [dict(subject=h, predicate="runs_os", object="linux", observed_at=_at(8, 1), source="cmdb")
               for h in hosts]
            + [dict(subject=hosts[i], predicate="unconstrained_delegation", object=True, observed_at=_at(8, 2),
                    source="ad") for i in (5, 31, 47)])
    # the topic vocabulary is the registry (domain knowledge is data), as a connector registers it
    from loomctx.contracts import PredicateDef, SchemaRegistration
    store.put_schema(SchemaRegistration(namespace="default", predicates=[
        PredicateDef(name="member_of"), PredicateDef(name="runs_os"),
        PredicateDef(name="unconstrained_delegation", description="trusted for unconstrained Kerberos delegation")]))
    monkeypatch.setenv("LOOMCTX_MAX_SCOPE_ENTITIES", "10")
    scope = ScopeSpec(subjects=[domain], expand=["member_of", "unconstrained_delegation"], depth=1)
    pack = build_pack(store, AskRequest(scope=scope, question="which hosts allow unconstrained delegation?",
                                        budget=4000))
    assert {s.key for s in pack.subjects} == {"corp", "h05", "h31", "h47"}
    cut = [t for t in pack.truncated if t.reason == "scope_cap"]
    assert cut and (cut[0].gathered, cut[0].total) == (4, 61)
    # every host runs linux: not selective, so the window fills the cap as before
    scope = ScopeSpec(subjects=[domain], expand=["member_of", "runs_os"], depth=1)
    pack = build_pack(store, AskRequest(scope=scope, question="which os do the hosts run?", budget=4000))
    assert len(pack.subjects) == 10
    store.close()


def test_a_large_window_is_narrowed_and_the_walk_reaches_carriers_a_hop_deeper(tmp_path):
    """A 10k forest's delegation ask took 16-20 s: the domain's OUs held
    ~2,000 accounts — under the cap, so not "crowded" — and every one was
    admitted, gathered and ranked around seven carriers; `enabled` in the
    topic (on every account) also made each account a carrier. A large
    window is now narrowed by the topic's rare predicates, keeping what
    leads on (an OU inside an OU) so carriers a hop deeper are still
    reached; leaves past the carriers are a recorded cut (D-109)."""
    store = SqliteStore(tmp_path / "large.db")
    domain = EntityRef(type="domain", key="corp")
    staff, servers, legacy = (EntityRef(type="ou", key=k) for k in ("staff", "servers", "legacy"))
    users = [EntityRef(type="user", key=f"u{i:03d}") for i in range(600)]
    hosts = [EntityRef(type="computer", key=k) for k in ("app01", "sql01", "old01", "web01")]
    rows = [dict(subject=domain, predicate="contains", object=o, observed_at=_at(8, 1), source="ad")
            for o in (staff, servers)]
    rows.append(dict(subject=servers, predicate="contains", object=legacy, observed_at=_at(8, 1), source="ad"))
    rows += [dict(subject=staff, predicate="contains", object=u, observed_at=_at(8, 1), source="ad") for u in users]
    rows += [dict(subject=servers, predicate="contains", object=h, observed_at=_at(8, 1), source="ad")
             for h in (hosts[0], hosts[1], hosts[3])]
    rows.append(dict(subject=legacy, predicate="contains", object=hosts[2], observed_at=_at(8, 1), source="ad"))
    rows += [dict(subject=e, predicate="enabled", object=True, observed_at=_at(8, 1), source="ad")
             for e in users + hosts]
    rows += [dict(subject=h, predicate="unconstrained_delegation", object=True, observed_at=_at(8, 2), source="ad")
             for h in hosts[:3]]
    _claims(store, rows)
    from loomctx.contracts import PredicateDef, SchemaRegistration
    store.put_schema(SchemaRegistration(namespace="default", predicates=[
        PredicateDef(name="contains", containment=True), PredicateDef(name="enabled", node_status=True),
        PredicateDef(name="unconstrained_delegation", description="trusted for unconstrained Kerberos delegation")]))
    scope = ScopeSpec(subjects=[domain], expand=["contains", "unconstrained_delegation", "enabled"], depth=3)
    pack = build_pack(store, AskRequest(scope=scope, question="which computers allow unconstrained delegation?",
                                        budget=4000))
    got = {s.key for s in pack.subjects}
    assert {"app01", "sql01", "old01"} <= got                 # old01 sits one OU deeper
    assert not any(k.startswith("u") for k in got) and "web01" not in got
    assert any(t.reason == "scope_cap" for t in pack.truncated)
    # no topic: the window is walked as before
    pack = build_pack(store, AskRequest(scope=ScopeSpec(subjects=[domain], expand=["contains"], depth=2),
                                        question="what is in the domain?", budget=4000))
    assert sum(1 for s in pack.subjects if s.type == "user") == 600
    store.close()


def test_a_thread_expansion_hands_back_a_conflict_that_does_not_fit(tmp_path):
    """A thread handle spends its budget on the thread and mints no
    handles — but a conflict too big for it was dropped without a trace."""
    store, web01 = make_store(tmp_path)
    pack = build_pack(store, AskRequest(subject=web01, question="os", budget=40))
    handle = next(h for h in pack.handles if h.kind == "conflict")
    more = expand_pack(store, handle.id, budget=handle.est_tokens - 1)
    assert not [i for i in more.items if i.kind == "conflict"]
    assert [h.kind for h in more.handles] == ["conflict"]
    assert expand_pack(store, handle.id, budget=handle.est_tokens).items[0].kind == "conflict"
    store.close()


def test_an_excerpt_expansion_charges_its_citations(tmp_path):
    from loomctx.context import encode_handle
    from loomctx.contracts import DocumentIn
    store = SqliteStore(tmp_path / "ex.db")
    art = store.store_artifact(DocumentIn(text="alpha beta gamma", source="ir", observed_at=_at(8, 1)))
    store.put_doc_chunks("default", art.id, "m", [(i, i * 6, i * 6 + 5, w, [1.0, 0.0])
                                                  for i, w in enumerate(("alpha", "beta", "gamma"))])
    handle = encode_handle("default", EntityRef(type="host", key="web-01"), "", None,
                           excerpt={"artifact_id": art.id, "seq": 1, "model": "m"})
    pack = expand_pack(store, handle, budget=2000)
    assert len(pack.items) == 3
    assert pack.charged_tokens == sum(item_tokens(i) for i in pack.items) > sum(
        est_tokens(i.text) for i in pack.items)
    one = sum(item_tokens(i) for i in pack.items[:1])
    assert sum(item_tokens(i) for i in expand_pack(store, handle, budget=one).items) <= one
    store.close()


def test_the_charge_exceeds_the_budget_only_by_the_first_handle(tmp_path):
    """D-051/D-058 contract: charged_tokens <= budget, except the first
    handle, which always ships and overruns by at most its own cost."""
    store, web01 = make_store(tmp_path)
    for budget in range(20, 400, 7):
        for q in ("os", "who logged in?", ""):
            pack = build_pack(store, AskRequest(subject=web01, question=q, budget=budget))
            first = handle_tokens(pack.handles[0]) if pack.handles else 0
            assert pack.charged_tokens <= budget + first, (budget, q)
            assert sum(item_tokens(i) for i in pack.items) <= budget, (budget, q)
    store.close()


def test_expansion_supersession_sees_only_what_the_reader_sees(tmp_path):
    """expand_pack derived supersession from every gathered row: a
    correction outside the reader's types still retired a fact and leaked
    its id prefix. And a page's window ends before the corrections of its
    rows were made — they are now looked up by id."""
    from loomctx.context import encode_handle
    store = SqliteStore(tmp_path / "sup.db")
    web01 = EntityRef(type="host", key="web-01")
    old = _claims(store, [dict(subject=web01, predicate="runs_os", object="fedora-44",
                               observed_at=_at(7, 1), source="cmdb")])[0]
    hidden = _claims(store, [dict(subject=web01, predicate="runs_os", object=EntityRef(type="os", key="ubuntu"),
                                  observed_at=_at(8, 1), source="cmdb", supersedes=old.id)])[0]
    thread = encode_handle("default", web01, "runs_os", None)
    scoped = expand_pack(store, thread, 2000, allowed_types=("host",))
    assert scoped.items and not [i for i in scoped.items if "superseded" in i.text]
    everyone = expand_pack(store, thread, 2000)
    assert any(f"superseded by {hidden.id[:12]}" in i.text for i in everyone.items)
    # a page window that ends before the correction still marks the row
    page = encode_handle("default", web01, "", None, before=_at(7, 15), question="os")
    paged = [i.text for i in expand_pack(store, page, 2000).items]
    assert paged and all(f"superseded by {hidden.id[:12]}" in t for t in paged)
    # ...but not by a correction made after the handle's as_of
    past = encode_handle("default", web01, "", _at(7, 20), before=_at(7, 15), question="os")
    assert not any("superseded" in i.text for i in expand_pack(store, past, 2000).items)
    store.close()


def test_a_truncation_counts_only_rows_the_reader_may_see(tmp_path, monkeypatch):
    import loomctx.context as ctx
    monkeypatch.setattr(ctx, "_GATHER_LIMIT", 5)
    store = SqliteStore(tmp_path / "vis.db")
    web01 = EntityRef(type="host", key="web-01")
    _claims(store, [
        dict(subject=web01, predicate="logged_in_by", object=EntityRef(type="user", key=f"u{i}"),
             observed_at=_at(8, 1 + i), source="auth") for i in range(6)
    ] + [
        dict(subject=web01, predicate="talks_to", object=EntityRef(type="host", key=f"h{i}"),
             observed_at=_at(7, 1 + i), source="flow") for i in range(3)
    ])
    everyone = build_pack(store, AskRequest(subject=web01, question="x", budget=2000))
    assert [(t.gathered, t.total) for t in everyone.truncated] == [(5, 9)]
    # the host-only reader saw none of the 5 gathered logins, and may see 3 rows in all
    scoped = build_pack(store, AskRequest(subject=web01, question="x", budget=2000), allowed_types=("host",))
    assert [(t.gathered, t.total) for t in scoped.truncated] == [(0, 3)]
    store.close()


def test_the_scope_walk_does_not_follow_a_superseded_edge(tmp_path):
    """An open finding (host -has_finding-> finding) that a later closed
    row supersedes is history: a valid_at walk used to follow the open row
    (its window never ends) and pull the finding in as current."""
    store = SqliteStore(tmp_path / "walk.db")
    host, finding = EntityRef(type="host", key="web-01"), EntityRef(type="finding", key="F-1")
    opened = _claims(store, [dict(subject=host, predicate="has_finding", object=finding,
                                  observed_at=_at(8, 1), valid_from=_at(8, 1), source="ocsf")])[0]
    _claims(store, [dict(subject=host, predicate="has_finding", object=finding, observed_at=_at(9, 1),
                         valid_from=_at(8, 1), valid_to=_at(8, 20), source="ocsf", supersedes=opened.id)])
    scope = ScopeSpec(subjects=[host], expand=["has_finding"], depth=1)
    after = build_pack(store, AskRequest(scope=scope, question="findings", budget=2000, valid_at=_at(9, 1)))
    assert after.subjects == [host]
    during = build_pack(store, AskRequest(scope=scope, question="findings", budget=2000, valid_at=_at(8, 10)))
    assert during.subjects == [host, finding]                   # through the closed row that covers T
    # as of before the correction, the open row is current again
    before = build_pack(store, AskRequest(scope=scope, question="findings", budget=2000, as_of=_at(8, 15)))
    assert before.subjects == [host, finding]
    store.close()


def test_a_question_ending_in_punctuation_still_names_its_entity(tmp_path):
    from loomctx.answer import auto_subjects
    from loomctx.context import _question_tokens
    store, web01 = make_store(tmp_path)
    assert auto_subjects(store, "default", "Summarize web-01.") == [web01]
    assert "web-01" in _question_tokens("is it web-01?") and "web-01." not in _question_tokens("web-01.")
    store.close()


def _cve_with_two_conflicts(tmp_path):
    """A CVE the way NVD records it: two scorers disagree on the score AND
    on the severity, and a daily feed is newer than both."""
    store = SqliteStore(tmp_path / "cve.db")
    cve = EntityRef(type="cve", key="CVE-2026-27524")
    rows = []
    for scorer, score, severity in (("nvd:nvd@nist.gov", 4.3, "medium"),
                                    ("nvd:disclosure@vulncheck.com", 2.3, "low")):
        rows += [dict(subject=cve, predicate="cvss_score", object=score, source=scorer,
                      observed_at=_at(6, 17), valid_from=_at(3, 18)),
                 dict(subject=cve, predicate="has_severity", object=severity, source=scorer,
                      observed_at=_at(6, 17), valid_from=_at(3, 18))]
    rows += [dict(subject=cve, predicate="epss_score", object=0.004 + i / 10000, source="first-epss",
                  observed_at=_at(9, 1 + i)) for i in range(6)]
    rows.append(dict(subject=cve, predicate="status", object="Modified", source="nvd",
                     observed_at=_at(6, 17)))
    store.record_claims([ClaimIn(**r) for r in rows])
    return store, cve


def test_the_conflict_on_the_asked_attribute_ships_first(tmp_path):
    """D-062: conflicts shipped in predicate-name order, so asked for the
    has_severity of a CVE a 400-token pack carried the cvss_score conflict
    and handed the asked one back as a handle. The named attribute's
    conflict comes first; the other is still there, as an item or a handle."""
    store, cve = _cve_with_two_conflicts(tmp_path)
    q = f"As of 2026-09-24, what is the has_severity of cve:{cve.key}? If sources disagree, say so."
    pack = build_pack(store, AskRequest(subject=cve, question=q, budget=250, as_of=_at(9, 24)))
    conflicts = [i for i in pack.items if i.kind == "conflict"]
    assert conflicts and "has_severity" in conflicts[0].text
    assert pack.items[0].kind == "conflict"                     # conflicts still ship first
    assert any("cvss_score" in i.text for i in conflicts) or any(
        h.kind == "conflict" and "cvss_score" in h.hint for h in pack.handles)
    assert pack.charged_tokens <= 250
    store.close()


def test_the_asked_attribute_is_not_thinned_by_the_diversity_term(tmp_path):
    """D-062: "the largest invoiced_amount ever recorded" needs every
    invoice; after three, the diversity term let a contract owner and a
    renewal date in ahead of the one that held the maximum."""
    store = SqliteStore(tmp_path / "inv.db")
    vendor = EntityRef(type="vendor", key="globex")
    amounts = [14773.89, 24903.71, 10999.5, 8963.48, 32202.95, 31365.47, 13761.09]
    store.record_claims(
        [ClaimIn(subject=vendor, predicate="invoiced_amount", object=a, source="erp-export",
                 observed_at=_at(8, 16 - 2 * i)) for i, a in enumerate(amounts)]
        + [ClaimIn(subject=vendor, predicate=p, object=v, source="contract-db", observed_at=_at(8, 20))
           for p, v in (("contract_owner", "asmith"), ("renewal_date", "2027-06-01"))])
    q = "What is the largest invoiced_amount ever recorded for vendor:globex? Answer with the number."
    pack = build_pack(store, AskRequest(subject=vendor, question=q, budget=450))
    shipped = " | ".join(i.text for i in pack.items)
    assert all(str(a) in shipped for a in amounts), shipped
    assert pack.charged_tokens <= 450
    store.close()


def test_the_asked_attribute_ships_before_a_document_excerpt(tmp_path):
    """D-062: an advisory excerpt (half the budget) and its handle filled
    a 400-token pack asked for a KEV CVE's epss_score; no fact shipped."""
    from loomctx.contracts import DocumentIn, Provenance
    from loomctx.llm import HashingEmbedder
    store = SqliteStore(tmp_path / "kev.db")
    cve = EntityRef(type="cve", key="CVE-2022-27924")
    advisory = ("CVE-2022-27924: Synacor Zimbra Collaboration Suite (ZCS) Command Injection "
                "Vulnerability. Synacor Zimbra Collaboration Suite (ZCS) allows an attacker to inject "
                "memcache commands into a targeted instance which causes an overwrite of arbitrary "
                "cached entries. Required action: apply updates per vendor instructions.")
    art = store.store_artifact(DocumentIn(text=advisory, source="cisa-kev", observed_at=_at(8, 1)))
    embedder = HashingEmbedder()
    store.put_doc_chunks("default", art.id, embedder.model,
                         [(0, 0, len(advisory), advisory, embedder.embed([advisory])[0])])
    rows = [ClaimIn(subject=cve, predicate="exploited_in_wild", object=True, source="cisa-kev",
                    observed_at=_at(8, 1), provenance=Provenance(artifact_id=art.id))]
    rows += [ClaimIn(subject=cve, predicate=p, object=v, source="first-epss", observed_at=_at(9, 20))
             for p, v in (("epss_score", 0.85398), ("epss_percentile", 0.99714))]
    rows += [ClaimIn(subject=cve, predicate="affects", object=EntityRef(type="product", key=f"zimbra:p{i}"),
                     source="nvd", observed_at=_at(9, 1)) for i in range(8)]
    store.record_claims(rows)
    q = f"What is the epss_score of cve:{cve.key}? Answer with the number."
    pack = build_pack(store, AskRequest(subject=cve, question=q, budget=400), embedder=embedder)
    assert pack.items[0].kind == "fact" and "epss_score 0.85398" in pack.items[0].text, \
        [i.text[:60] for i in pack.items]
    assert pack.charged_tokens <= 400
    store.close()


def test_a_question_naming_values_is_about_those_facts_not_the_attribute():
    """An ordering question names two facts by their values; taking every
    flow as the topic buried the one it names under the newest flows."""
    from loomctx.context import subject_attribute
    host = EntityRef(type="host", key="db-01")
    common = dict(namespace="default", recorded_at=_at(9, 1), confidence=1.0)
    rows = [
        Observation(id="a" * 32, subject=host, predicate="communicated_with",
                    object=EntityRef(type="host", key="vpn-01"), observed_at=_at(8, 15), source="netflow",
                    **common),
        Observation(id="b" * 32, subject=host, predicate="runs_os", object="rhel-9",
                    observed_at=_at(7, 2), source="asset-inventory", **common),
        Observation(id="c" * 32, subject=EntityRef(type="ip", key="10.0.4.12"), predicate="assigned_to",
                    object=host, observed_at=_at(7, 2), source="dhcp-log", **common),
    ]
    ordering = ("About host:db-01: which of these was observed first — (A) host:db-01 communicated_with "
                "host:vpn-01, per netflow; or (B) host:db-01 runs_os rhel-9, per asset-inventory?")
    assert subject_attribute(ordering, rows, set(), [host]) == frozenset()
    assert subject_attribute("what is the runs_os of host:db-01?", rows, set(), [host]) == {"runs_os"}
    # the root at an edge's far end is the frame, not a named value
    assert subject_attribute("which ip is assigned to host:db-01?", rows, set(), [host]) == {"assigned_to"}


def test_text_handles_round_trip_awkward_keys(monkeypatch):
    """D-062: handles are plain text (a base64 id tokenized at ~1.45
    characters a token: 128 tokens for a time-scoped handle, a third of a
    400-token pack). Keys holding the separator, the escape, dots, spaces
    and non-ASCII survive, signed or not, and decode as they always did."""
    from loomctx.context import encode_handle
    at = datetime(2026, 9, 24, 4, 18, 4, 790000, tzinfo=timezone.utc)
    excerpt = {"artifact_id": "a,b", "seq": 3, "model": "openai/text-embedding-3-small"}
    for key in ("linux:linux_kernel", "a~b%7Ec", "10.0.4.7", "c\\+\\+ driver", "zürich/ü", "x.y.z"):
        ref = EntityRef(type="product", key=key)
        for secret in ("", "s3"):
            monkeypatch.setenv("LOOMCTX_HANDLE_SECRET", secret)
            h = encode_handle("net~sec", ref, "affects", at, at, before=at, question="why? 100% ~sure",
                              excerpt=excerpt)
            assert h.startswith("h2_" if secret else "h1_")
            meta = decode_handle(h)
            assert meta["ns"] == "net~sec" and meta["subject"] == {"type": "product", "key": key}
            assert meta["as_of"] == meta["valid_at"] == meta["before"] == at.isoformat()
            assert meta["question"] == "why? 100% ~sure" and meta["excerpt"] == excerpt
    monkeypatch.setenv("LOOMCTX_HANDLE_SECRET", "")
    short = encode_handle("netsec", EntityRef(type="cve", key="CVE-2026-21068"), "has_severity", at)
    assert short == "h1_netsec~cve~CVE-2026-21068~has_severity~a20260924T041804.79Z"
    assert decode_handle(short)["as_of"] == at.isoformat()
    midnight = encode_handle("netsec", EntityRef(type="ip", key="10.0.4.7"), "", None,
                             datetime(2026, 8, 20, tzinfo=timezone.utc))
    assert midnight.endswith("~v20260820T00Z")
    for bad in ("h1_ns~host~web-01", "h1_ns~host~web-01~p~zjunk", "h1_ns~host~web-01~p~anever",
                "h1_ns~host~web-01~p~x1,notint,m", "h1_ns~~web-01~p"):
        try:
            decode_handle(bad)
        except ValueError:
            continue
        raise AssertionError(bad)
