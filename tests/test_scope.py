from datetime import datetime, timezone

from loom.context import build_pack, resolve_scope
from loom.contracts import AskRequest, ClaimIn, EntityRef, ScopeSpec
from loom.store.sqlite import SqliteStore


def _at(day, hour=12):
    return datetime(2026, 8, day, hour, tzinfo=timezone.utc)


def make_store(tmp_path):
    """corp.local contains web-01 and db-01; stray-01 is outside the domain."""
    store = SqliteStore(tmp_path / "scope.db")
    domain = EntityRef(type="domain", key="corp.local")
    for i, host in enumerate(["web-01", "db-01"]):
        store.record_claim(ClaimIn(
            subject=EntityRef(type="host", key=host), predicate="member_of",
            object=domain, observed_at=_at(1), source="inventory",
        ))
        store.record_claim(ClaimIn(
            subject=EntityRef(type="host", key=host), predicate="logged_in_by",
            object=EntityRef(type="user", key=f"user-{i}"),
            observed_at=_at(10 + i), source="auth-log",
        ))
    store.record_claim(ClaimIn(
        subject=EntityRef(type="host", key="stray-01"), predicate="logged_in_by",
        object=EntityRef(type="user", key="outsider"),
        observed_at=_at(20), source="auth-log",
    ))
    return store, domain


def test_scope_expansion_from_domain_anchor(tmp_path):
    store, domain = make_store(tmp_path)
    resolved = resolve_scope(store, "default", ScopeSpec(
        subjects=[domain], expand=["member_of"], depth=1,
    ))
    keys = {(r.type, r.key) for r in resolved}
    assert ("domain", "corp.local") in keys
    assert ("host", "web-01") in keys and ("host", "db-01") in keys
    assert ("host", "stray-01") not in keys


def test_depth_zero_is_just_the_subjects(tmp_path):
    store, domain = make_store(tmp_path)
    resolved = resolve_scope(store, "default", ScopeSpec(
        subjects=[domain], expand=["member_of"], depth=0,
    ))
    assert [(r.type, r.key) for r in resolved] == [("domain", "corp.local")]


def test_domain_scoped_pack_covers_members(tmp_path):
    store, domain = make_store(tmp_path)
    pack = build_pack(store, AskRequest(
        scope=ScopeSpec(subjects=[domain], expand=["member_of"], depth=1),
        question="who logged in?", budget=3000,
    ))
    text = " | ".join(i.text for i in pack.items)
    assert "user-0" in text and "user-1" in text
    assert "outsider" not in text
    assert pack.subject is None and len(pack.subjects) == 3
    # membership edges reachable from both ends must not duplicate items
    ids = [c.observation_id for i in pack.items for c in i.citations]
    assert len(ids) == len(set(ids))


def test_multi_subject_scope_without_expansion(tmp_path):
    store, _ = make_store(tmp_path)
    pack = build_pack(store, AskRequest(
        scope=ScopeSpec(subjects=[
            EntityRef(type="host", key="web-01"),
            EntityRef(type="host", key="stray-01"),
        ]),
        question="who logged in?", budget=3000,
    ))
    text = " | ".join(i.text for i in pack.items)
    assert "user-0" in text and "outsider" in text and "user-1" not in text


def test_ask_requires_exactly_one_of_subject_scope():
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        AskRequest(question="q")
    with pytest.raises(ValidationError):
        AskRequest(
            question="q",
            subject=EntityRef(type="host", key="a"),
            scope=ScopeSpec(subjects=[EntityRef(type="host", key="b")]),
        )


def _two_hop_store(tmp_path, edge_kwargs=None, edge_time=None):
    """web-01 runs nginx; CVE-1 affects nginx and is exploited."""
    store = SqliteStore(tmp_path / "hops.db")
    host, prod, cve = (EntityRef(type="host", key="web-01"), EntityRef(type="product", key="nginx"),
                       EntityRef(type="cve", key="CVE-2026-1"))
    store.record_claims([
        ClaimIn(subject=host, predicate="runs_software", object=prod, source="inv",
                observed_at=edge_time or _at(1), **(edge_kwargs or {})),
        ClaimIn(subject=cve, predicate="affects", object=prod, source="nvd", observed_at=_at(1)),
        ClaimIn(subject=cve, predicate="exploited_in_wild", object=True, source="kev", observed_at=_at(1)),
    ])
    return store, host


def _reached(pack):
    return {(s.type, s.key) for s in pack.subjects}


def test_scope_walk_honors_as_of(tmp_path):
    """D-046: an edge observed after T did not exist as of T, so nothing
    behind it is reached — the walk used to follow it and then the pack
    hid the edge, shipping the reached facts without their chain."""
    store, host = _two_hop_store(tmp_path, edge_time=_at(15))
    scope = ScopeSpec(subjects=[host], expand=["runs_software", "affects"], depth=2)
    now = build_pack(store, AskRequest(scope=scope, question="exploited", budget=3000))
    assert ("cve", "CVE-2026-1") in _reached(now)
    then = build_pack(store, AskRequest(scope=scope, question="exploited", budget=3000, as_of=_at(10)))
    assert _reached(then) == {("host", "web-01")}
    assert not any("exploited" in i.text for i in then.items)


def test_scope_walk_honors_valid_at(tmp_path):
    """D-046: an edge whose validity window misses T is not walked."""
    store, host = _two_hop_store(tmp_path, edge_kwargs={"valid_from": _at(1), "valid_to": _at(5)})
    scope = ScopeSpec(subjects=[host], expand=["runs_software", "affects"], depth=2)
    during = build_pack(store, AskRequest(scope=scope, question="exploited", budget=3000, valid_at=_at(3)))
    assert ("cve", "CVE-2026-1") in _reached(during)
    after = build_pack(store, AskRequest(scope=scope, question="exploited", budget=3000, valid_at=_at(20)))
    assert _reached(after) == {("host", "web-01")}
    assert not any("exploited" in i.text for i in after.items)


def test_scope_walk_does_not_hop_through_an_entity_the_reader_cannot_see(tmp_path):
    """D-021/D-046: a host-only reader walking member_of from web-01 must
    not reach db-01 *through* domain:corp.local — the hop is invisible to
    them, so the reached facts would arrive without their chain."""
    store, domain = make_store(tmp_path)
    scope = ScopeSpec(subjects=[EntityRef(type="host", key="web-01")], expand=["member_of"], depth=2)
    everyone = build_pack(store, AskRequest(scope=scope, question="who logged in?", budget=3000))
    assert ("host", "db-01") in _reached(everyone)
    scoped = build_pack(store, AskRequest(scope=scope, question="who logged in?", budget=3000),
                        allowed_types=("host", "user"))
    assert _reached(scoped) == {("host", "web-01")}
    text = " | ".join(i.text for i in scoped.items)
    assert "user-0" in text and "user-1" not in text and "domain:" not in text


def test_extracted_edges_do_not_steer_expansion_by_default(tmp_path):
    """D-023/D-046: a hostile document claiming 'web-01 runs product:evil'
    could otherwise pull product:evil and its CVEs into web-01's two-hop
    pack. Extracted edges are walked only when the scope opts in."""
    store, host = _two_hop_store(tmp_path)
    evil = EntityRef(type="product", key="evil")
    store.record_claims([
        ClaimIn(subject=host, predicate="runs_software", object=evil, source="doc:phish.txt",
                observed_at=_at(2), attrs={"extracted": True}),
        ClaimIn(subject=EntityRef(type="cve", key="CVE-2026-666"), predicate="affects", object=evil,
                source="nvd", observed_at=_at(2)),
    ])
    scope = ScopeSpec(subjects=[host], expand=["runs_software", "affects"], depth=2)
    pack = build_pack(store, AskRequest(scope=scope, question="exploited", budget=3000))
    assert ("cve", "CVE-2026-1") in _reached(pack)
    assert ("product", "evil") not in _reached(pack) and ("cve", "CVE-2026-666") not in _reached(pack)
    assert not any("CVE-2026-666" in i.text for i in pack.items)
    # the extracted edge itself is still a (discounted) fact about web-01
    assert any("product:evil" in i.text and i.kind == "fact" for i in pack.items)
    opted = build_pack(store, AskRequest(
        scope=ScopeSpec(subjects=[host], expand=["runs_software", "affects"], depth=2, follow_extracted=True),
        question="exploited", budget=3000))
    assert ("cve", "CVE-2026-666") in _reached(opted)


def test_scope_subjects_are_bounded():
    import pytest
    from pydantic import ValidationError
    ScopeSpec(subjects=[EntityRef(type="host", key=f"h{i}") for i in range(500)])
    with pytest.raises(ValidationError):
        ScopeSpec(subjects=[EntityRef(type="host", key=f"h{i}") for i in range(501)])


# ------------------------------------------------ scope topics (D-061) #

def test_a_predicate_is_named_when_every_word_of_it_is_asked():
    from loom.context import named_predicates
    vocab = {"runs_software", "runs_os", "exploited_in_wild", "affects", "logged_in_by", "has_weakness"}
    q = "Which CVEs that CISA lists as exploited in the wild affect software that host:web-01 runs?"
    assert named_predicates(q, vocab) == {"runs_software", "exploited_in_wild", "affects"}
    assert named_predicates("which users logged in to web-01?", vocab) == {"logged_in_by"}
    assert named_predicates("what OS does it run?", vocab) == {"runs_os"}
    # the names of the entities asked about are the frame, not the topic
    assert named_predicates("summarize host:weakness-lab", vocab,
                            [EntityRef(type="host", key="weakness-lab")]) == frozenset()
    assert named_predicates(None, vocab) == frozenset()


def _conflicted_domain(tmp_path):
    """corp.local's member web-01 carries a runs_os conflict and a login."""
    store, domain = make_store(tmp_path)
    web = EntityRef(type="host", key="web-01")
    for source, value in (("cmdb", "ubuntu-22.04"), ("nmap", "fedora-44")):
        store.record_claim(ClaimIn(subject=web, predicate="runs_os", object=value,
                                   observed_at=_at(12), source=source))
    return store, domain


def test_a_reached_entitys_conflict_ships_only_when_the_question_is_about_it(tmp_path):
    """In a scope pack, a contested fact about an entity the walk reached
    ships first only when the question names its predicate; otherwise it
    is a conflict handle — never dropped, never the budget (D-061). The
    root's own conflicts are unchanged."""
    store, domain = _conflicted_domain(tmp_path)
    scope = ScopeSpec(subjects=[domain], expand=["member_of"], depth=1)
    logins = build_pack(store, AskRequest(scope=scope, question="who logged in?", budget=3000))
    assert not [i for i in logins.items if i.kind == "conflict"]
    aside = [h for h in logins.handles if h.kind == "conflict"]
    assert aside and "host:web-01 runs_os" in aside[0].hint
    os_pack = build_pack(store, AskRequest(scope=scope, question="which OS do the hosts run?", budget=3000))
    assert [i for i in os_pack.items if i.kind == "conflict"][0].text.startswith("CONFLICT on host:web-01 runs_os")
    # asked about web-01 itself, its conflict is the frame's and ships first
    own = build_pack(store, AskRequest(subject=EntityRef(type="host", key="web-01"),
                                       question="who logged in?", budget=3000))
    assert own.items[0].kind == "conflict"


# ----------------------------------- topics named by the agent (D-064) #

def _vuln_registry(namespace="v"):
    """A vulnerability registry as a connector would declare it: links carry
    object types, attributes carry descriptions."""
    from loom.contracts import PredicateDef, SchemaRegistration
    return SchemaRegistration(namespace=namespace, predicates=[
        PredicateDef(name="runs_software", object_types=["product"], containment=True,
                     description="a host runs this product (scopes follow it by default)"),
        PredicateDef(name="affects", object_types=["product"], description="the CVE affects this product"),
        PredicateDef(name="exploited_in_wild", description="CISA KEV listing (bool)"),
        PredicateDef(name="ransomware_campaign_use", description="KEV: Known / Unknown"),
        PredicateDef(name="cvss_score", description="CVSS base score; source names the scorer "
                     "(nvd:<NIST or CNA>, or cisa-adp for CISA Vulnrichment)"),
        PredicateDef(name="ssvc_exploitation", description="CISA Vulnrichment SSVC: none / poc / active"),
        PredicateDef(name="epss_score", description="FIRST EPSS probability of exploitation in 30 days"),
    ])


def test_a_description_names_an_attribute_only_when_distinctive():
    """D-064: agents said "listed by CISA", never "exploited in the wild",
    and D-061's name match never fired. A registered attribute whose
    description the question says a good part of (two words or more, 40 %
    of its words) is named — the best match only; one shared word, or
    two of a long description's dozen ("cite observation ids ... CISA"
    against cvss_score's), is not a match."""
    from loom.context import described_predicates
    defs = _vuln_registry().predicates
    host = [EntityRef(type="host", key="web-01")]
    assert described_predicates("Which CVEs affect the software host:web-01 runs and are listed by CISA?",
                                defs, host) == {"exploited_in_wild"}
    assert described_predicates("Is it in CISA's Known Exploited Vulnerabilities catalog (KEV)?",
                                defs, host) == {"exploited_in_wild"}
    assert described_predicates("What is the probability of exploitation of CVE-1?", defs) == {"epss_score"}
    for ordinary in ("Which CVEs affect software host:web-01 runs? Name them and cite observation ids.",
                     "What does CISA say about web-01?", "what software does host:web-01 run?", None):
        assert described_predicates(ordinary, defs, host) == frozenset(), ordinary
    # links are never a topic by description, nor anything excluded
    assert described_predicates("which product does the CVE affect?", defs) == frozenset()
    assert described_predicates("listed by CISA", defs, exclude={"exploited_in_wild"}) == frozenset()


def _hub_store(tmp_path, kev_per_product=(20, 3, 3, 3, 3), per_product=120, registry=True):
    """host web-01 runs five products; `per_product` CVEs affect each, one a
    minute, with a CVSS score two scorers disagree on; the first
    `kev_per_product[i]` of product i's CVEs are KEV-listed."""
    from datetime import timedelta
    tmp_path.mkdir(parents=True, exist_ok=True)
    store = SqliteStore(tmp_path / "hub.db")
    if registry:
        store.put_schema(_vuln_registry())
    host = EntityRef(type="host", key="web-01")
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    claims, kev = [], set()
    for p, n_kev in enumerate(kev_per_product):
        product = EntityRef(type="product", key=f"vendor:product_{p}")
        claims.append(ClaimIn(namespace="v", subject=host, predicate="runs_software", object=product,
                              observed_at=t, source="inventory"))
        for i in range(per_product):
            cve = EntityRef(type="cve", key=f"CVE-2026-{p}{i:04d}")
            at = t + timedelta(minutes=10 + p * per_product + i)
            claims += [
                ClaimIn(namespace="v", subject=cve, predicate="affects", object=product, observed_at=at,
                        source="nvd", valid_from=at),
                ClaimIn(namespace="v", subject=cve, predicate="cvss_score", object=7.5, observed_at=at,
                        source="nvd:nist"),
                ClaimIn(namespace="v", subject=cve, predicate="cvss_score", object=5.0, observed_at=at,
                        source="nvd:cna")]
            if i < n_kev:
                kev.add(cve.key)
                claims.append(ClaimIn(namespace="v", subject=cve, predicate="exploited_in_wild", object=True,
                                      observed_at=at, source="cisa-kev", valid_from=at))
    store.record_claims(claims)
    return store, host, kev


def _kev_named(pack, kev):
    import re
    return set(re.findall(r"CVE-\d{4}-\d+", " ".join(i.text for i in pack.items))) & kev


def test_an_attribute_in_expand_is_the_topic_not_a_link(tmp_path, monkeypatch):
    """D-064: four of the scorecard's models wrote expand_predicates=
    ["runs_software", "affects", "exploited_in_wild"] with a question that
    never said "exploited in the wild" — the attribute named outright, and
    ignored: the pack was the recency window, one KEV CVE of 32. An
    attribute in the expand list is the topic now (hub completion and
    topic-first selection), and the pack says so in `notes`."""
    from loom import context
    from loom.context import expand_attributes
    monkeypatch.setattr(context, "_GATHER_LIMIT", 100)
    store, host, kev = _hub_store(tmp_path)
    q = "Which CVEs affect the software host:web-01 runs? Name every one."

    def ask(expand):
        return build_pack(store, AskRequest(namespace="v", question=q, budget=3000, scope=ScopeSpec(
            subjects=[host], expand=expand, depth=2)))

    plain = ask(["runs_software", "affects"])
    assert len(_kev_named(plain, kev)) < len(kev) // 2 and not plain.notes
    named = ask(["runs_software", "affects", "exploited_in_wild"])
    assert _kev_named(named, kev) == kev and named.charged_tokens <= 3000
    assert named.notes == ["expand predicate 'exploited_in_wild' holds values, not links between "
                           "entities: taken as the question's topic, not walked"]
    # unregistered, the values gathered say what it is; unseen, nothing is assumed
    bare, _, _ = _hub_store(tmp_path / "bare", registry=False)
    rows = bare.observations_for("v", EntityRef(type="cve", key="CVE-2026-00000"))
    assert expand_attributes(["affects", "exploited_in_wild"], [], rows) == {"exploited_in_wild"}
    assert expand_attributes(["affects", "exploited_in_wild"], [], []) == frozenset()


def test_the_question_naming_the_attribute_by_its_description_completes_the_hub(tmp_path, monkeypatch):
    from loom import context
    monkeypatch.setattr(context, "_GATHER_LIMIT", 100)
    store, host, kev = _hub_store(tmp_path)
    pack = build_pack(store, AskRequest(
        namespace="v", budget=3000, question="Which CVEs affect the software host:web-01 runs and are "
        "listed by CISA?", scope=ScopeSpec(subjects=[host], expand=["runs_software", "affects"], depth=2)))
    assert _kev_named(pack, kev) == kev and pack.charged_tokens <= 3000


def test_an_edge_registered_without_object_types_is_still_walked(tmp_path):
    """A STIX relationship is registered with no object types and is a
    link: seen with an entity at its far end, it is walked, not taken as
    a topic."""
    from loom.contracts import PredicateDef, SchemaRegistration
    store = SqliteStore(tmp_path / "stix.db")
    store.put_schema(SchemaRegistration(namespace="s", predicates=[PredicateDef(name="uses")]))
    actor = EntityRef(type="threat-actor", key="apt-1")
    store.record_claim(ClaimIn(namespace="s", subject=actor, predicate="uses",
                               object=EntityRef(type="malware", key="m-1"), observed_at=_at(1), source="stix"))
    pack = build_pack(store, AskRequest(namespace="s", question="what does apt-1 use?", budget=800,
                                        scope=ScopeSpec(subjects=[actor], expand=["uses"])))
    assert EntityRef(type="malware", key="m-1") in pack.subjects and not pack.notes


def test_a_pack_names_what_it_could_not_do(tmp_path):
    """D-064: an invented expand predicate was silently ignored (the
    scorecard's gemini-2.5-flash sent `cisa_known_exploited_vulnerability`
    and got a one-hop pack). The pack now names it with the closest
    predicates the namespace has, by spelling or by the words of their
    name and description; a scope that stops a hop short of what the
    question names is told which link to add; the answer prompt carries
    the notes too."""
    from loom.answer import render_user_prompt
    store, host, _ = _hub_store(tmp_path, kev_per_product=(1,), per_product=3)
    q = "Which CVEs affect the software host:web-01 runs and are exploited in the wild?"
    pack = build_pack(store, AskRequest(namespace="v", question=q, budget=800, scope=ScopeSpec(
        subjects=[host], expand=["runs_sofware", "cisa_known_exploited_vulnerability"], depth=2)))
    assert len(pack.notes) == 3, pack.notes
    assert pack.notes[0].startswith("expand predicate 'runs_sofware' is not registered in namespace 'v'")
    assert "closest: runs_software" in pack.notes[0]
    assert "closest: exploited_in_wild" in pack.notes[1]
    # the walk stopped at the root, not at its depth: the link is the advice, not a deeper walk
    assert pack.notes[2] == ("the question names 'affects', 'exploited_in_wild', which nothing this scope reached "
                             "carries, and 'runs_software', a link the reached entities have that it does "
                             "not follow: add that to expand_predicates to reach what carries the rest")
    assert "- note: expand predicate 'runs_sofware'" in render_user_prompt(q, pack)
    short = build_pack(store, AskRequest(namespace="v", question=q, budget=800, scope=ScopeSpec(
        subjects=[host], expand=["runs_software"], depth=1)))
    assert short.notes == ["the question names 'exploited_in_wild', which nothing this scope reached "
                           "carries, and 'affects', a link the reached entities have that it does not "
                           "follow: add that to expand_predicates and depth=2 to reach what carries the rest"]
    # the attribute named in expand instead of the question: the same advice
    named = build_pack(store, AskRequest(
        namespace="v", question="Which CVEs affect the software host:web-01 runs?", budget=800,
        scope=ScopeSpec(subjects=[host], expand=["runs_software", "exploited_in_wild"], depth=1)))
    assert named.notes[1] == short.notes[0]
    full = build_pack(store, AskRequest(namespace="v", question=q, budget=800, scope=ScopeSpec(
        subjects=[host], expand=["runs_software", "affects"], depth=2)))
    assert not full.notes
    # a subject that names nothing
    ghost = build_pack(store, AskRequest(namespace="v", question="?", budget=400,
                                         subject=EntityRef(type="hots", key="web-01")))
    assert ghost.notes == ["no entity 'hots:web-01' in namespace 'v'; entities with that key: host:web-01"]


def test_the_scope_budget_carries_the_answer_within_the_mcp_limit(tmp_path, monkeypatch):
    """D-064 (the scope budget, re-derived): the concise MCP wire of a
    two-hop hub pack, measured with a real tokenizer. The old hint (1500)
    cannot carry a 32-CVE answer; the default (3000) carries it, and the
    ceiling (4000) — even 6000 — stays at least 3x under Claude Code's
    default MAX_MCP_OUTPUT_TOKENS (25,000)."""
    import pydantic_core
    import pytest
    try:
        import tiktoken
        enc = tiktoken.get_encoding("cl100k_base")
    except Exception as exc:  # noqa: BLE001 — offline with no cached encoding
        pytest.skip(f"tiktoken encoding unavailable: {exc}")
    from loom import context, mcp_server
    monkeypatch.setattr(context, "_GATHER_LIMIT", 100)
    store, host, kev = _hub_store(tmp_path)
    q = ("Is host web-01 exposed to any vulnerability that CISA lists as exploited in the wild? Name every "
         "such CVE and the software it affects, and cite observation ids.")
    wire, found = {}, {}
    for budget in (1500, mcp_server.SCOPE_BUDGET_DEFAULT, mcp_server.SCOPE_BUDGET_HINT, 6000):
        pack = build_pack(store, AskRequest(namespace="v", question=q, budget=budget, scope=ScopeSpec(
            subjects=[host], expand=["runs_software", "affects"], depth=2)))
        wire[budget] = len(enc.encode(pydantic_core.to_json(mcp_server._agent_view(pack)).decode()))
        found[budget] = len(_kev_named(pack, kev))
    print("\nscope wire tokens by budget:", wire, "KEV named:", found, "of", len(kev))
    assert found[1500] < len(kev) == found[mcp_server.SCOPE_BUDGET_DEFAULT]
    limit = 25_000   # Claude Code's default MAX_MCP_OUTPUT_TOKENS
    assert wire[mcp_server.SCOPE_BUDGET_HINT] * 3 <= limit and wire[6000] * 3 <= limit
    assert all(wire[b] <= 1.15 * b + 1000 for b in wire)
