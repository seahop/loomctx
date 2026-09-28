"""What an import collected (D-082): connectors record which data their
export carried, and reads say when a predicate they walk or a status they
report was not (fully) collected — so "no path" from a partial dump is not
read as "no access", and a missing `enabled` is not read as enabled."""

import json
from datetime import datetime, timezone

from loomctx import coverage
from loomctx.connectors import ad_gen, entra, ldap, okta
from loomctx.context import build_pack, find_paths
from loomctx.contracts import AskRequest, ClaimIn, EntityRef, PathRequest, ScopeSpec
from loomctx.store.sqlite import SqliteStore


def _strip(ldif: str, *attrs: str) -> str:
    drop = tuple(a.lower() + ":" for a in attrs)
    return "\n".join(line for line in ldif.splitlines() if not line.lower().startswith(drop))


def test_an_entity_ask_says_what_its_source_did_not_collect(tmp_path):
    """D-092: agents asking about one account never saw a gap noted only on
    scope asks and find_path; an entity ask from a source that did not
    collect membership says so, citing the coverage record."""
    from loomctx import agent_eval_ext as ext
    store = SqliteStore(tmp_path / "lab.db")
    _load_ldif(store, ext.lab_ldif())
    pack = build_pack(store, AskRequest(namespace="ad", subject=EntityRef(type="user", key=f"{ext.LAB_SID}-1102"),
                                        question="which groups is it a member of?", budget=1500))
    note = next(n for n in pack.notes if n.startswith("coverage:"))
    assert "'member_of' was not collected" in note and "domain:lab.local" in note and "[" in note
    # a source that collected everything adds nothing
    ldif, _ = ad_gen.generate(7, "small")
    full = SqliteStore(tmp_path / "full.db")
    _load_ldif(full, ldif)
    da = build_pack(full, AskRequest(namespace="ad", subject=EntityRef(type="group", key=f"{ext.CORP_SID}-512"),
                                     question="who are its members?", budget=1500))
    assert not any(n.startswith("coverage:") for n in da.notes)
    # both exports in one store: a walk through corp.local does not report
    # the lab export's gap; the lab account's ask still does
    for rec in ldap.ldif_to_envelopes(ext.lab_ldif(), "ad", source="lab-export"):
        full.record_claims([rec])
    walk = build_pack(full, AskRequest(namespace="ad", question="who are its members?", budget=2000,
                                       scope=ScopeSpec(subjects=[EntityRef(type="group", key=f"{ext.CORP_SID}-512")],
                                                       expand=["member_of"], depth=2)))
    assert not any("lab-export" in n for n in walk.notes)
    lab = build_pack(full, AskRequest(namespace="ad", subject=EntityRef(type="user", key=f"{ext.LAB_SID}-1102"),
                                      question="which groups?", budget=1500))
    assert any(n.startswith("coverage:") and "lab-export" in n for n in lab.notes)
    store.close()
    full.close()


def test_a_pack_names_the_opaque_keys_it_lists_within_budget(tmp_path):
    """D-093: a Domain Admins walk listed its child-domain members as bare
    SIDs, their names in separate facts; the pack now reads
    `user:S-… (dnguyen@dev.local)` (D-097: the name with its domain), and names fill only budget the facts left over."""
    import os
    from loomctx import agent_eval_ext as ext
    ext.main(["prepare", str(tmp_path), "--scale", "small"])
    store = SqliteStore(tmp_path / "forest.db")
    _load_ldif(store, open(os.path.join(tmp_path, "forest.ldif")).read())
    for budget in (1500, 3000):
        pack = build_pack(store, AskRequest(namespace="ad", question="which dev.local accounts are effective members of Domain Admins, and are they enabled?",
                                            budget=budget, scope=ScopeSpec(
                                                subjects=[EntityRef(type="group", key=f"{ext.CORP_SID}-512")],
                                                expand=["member_of"], depth=3)))
        assert pack.charged_tokens <= budget
        sid = f"{ext.DEV_SID}-1105"
        listed = [i.text for i in pack.items if sid in i.text]
        # every entity is named at its first mention; repeats only from what is left
        assert not listed or f"{sid} (dnguyen@dev.local)" in listed[0], budget
        assert listed or budget < 3000                    # the whole chain fits at the default budget
    # the question an agent sent, at ask_scope's default budget: a walked-to
    # account's name rides on its mentions instead of shipping as its own
    # item, and the room that frees reaches all five dev.local members at
    # hop three, each with its enabled state; the asked group keeps its name facts
    pack = build_pack(store, AskRequest(namespace="ad", budget=3000, question=(
        "Which accounts from dev.local are effective members of the Domain Admins group in corp.local, "
        "directly or through nested groups? For each account, name the group it is added through and "
        "say whether the account is enabled."), scope=ScopeSpec(
            subjects=[EntityRef(type="group", key=f"{ext.CORP_SID}-512")], expand=["member_of"], depth=3)))
    assert pack.charged_tokens <= 3000
    for name in ("dlee", "dkim", "dpatel", "dgarcia", "dnguyen"):
        ref = f"user:{ext.DEV_SID}-{ext.DEV_USERS[name][0]} ({name}@dev.local)"
        assert any(ref in i.text and "enabled" in i.text for i in pack.items), name
    assert not any(f" name {n} (" in i.text for i in pack.items for n in ext.DEV_USERS)
    assert any(" name Domain Admins (" in i.text for i in pack.items)
    # D-095: a question that never says "enabled" still gets the one member
    # whose status differs from the rest, with the edge that reached it
    for budget in (800, 3000):
        pack = build_pack(store, AskRequest(namespace="ad", budget=budget, question=(
            "Which accounts from dev.local are effective members of the Domain Admins group in "
            "corp.local, directly or through nested groups?"), scope=ScopeSpec(
                subjects=[EntityRef(type="group", key=f"{ext.CORP_SID}-512")], expand=["member_of"], depth=3)))
        assert any(f"{ext.DEV_SID}-1105" in i.text and "enabled False" in i.text for i in pack.items), budget
    # the walk's own edges before the reached admins' other memberships; and
    # a topic nothing reached carries (`is_dc`, by its description "a domain
    # controller machine account") does not take the walk's focus (D-096)
    for question in ("Show all members of this group, including nested group membership",
                     "Which accounts are members of the Domain Admins group in corp.local, "
                     "directly or through nested groups?"):
        pack = build_pack(store, AskRequest(namespace="ad", budget=3000, question=question,
                                            scope=ScopeSpec(subjects=[EntityRef(type="group", key=f"{ext.CORP_SID}-512")],
                                                            expand=["member_of"], depth=3)))
        text = "\n".join(i.text for i in pack.items)
        assert all(f"{ext.DEV_SID}-{ext.DEV_USERS[n][0]}" in text
                   for n in ("dlee", "dkim", "dpatel", "dgarcia", "dnguyen")), question
    store.close()


def test_a_walk_cut_by_its_depth_says_where_it_stopped(tmp_path):
    """D-096: two hops from Domain Admins reach DEV-Ops, not its members;
    the pack says DEV-Ops links onward and that depth=3 walks there. A
    user's other memberships turn back at the user and are not onward."""
    import os
    from loomctx import agent_eval_ext as ext
    ext.main(["prepare", str(tmp_path), "--scale", "small"])
    store = SqliteStore(tmp_path / "forest.db")
    _load_ldif(store, open(os.path.join(tmp_path, "forest.ldif")).read())

    def notes(depth):
        pack = build_pack(store, AskRequest(namespace="ad", question="show all effective members", budget=2000,
                                            scope=ScopeSpec(subjects=[EntityRef(type="group", key=f"{ext.CORP_SID}-512")],
                                                            expand=["member_of"], depth=depth)))
        return [n for n in pack.notes if n.startswith("the walk stopped")]
    [note] = notes(2)
    assert f"group:{ext.DEV_SID}-1201 (DEV-Ops@dev.local) links onward along member_of" in note and "depth=3" in note
    assert notes(3) == []
    store.close()


def test_a_pack_names_what_it_mentions_and_a_walk_that_reached_nothing_widens(tmp_path):
    """D-099: a group four levels up is named though the walk stopped a hop
    short of it; a walk that reached nothing along what it named (an
    invented predicate) also follows the containment and says so; the
    LDAP domain is keyed by its DNS name."""
    import os
    from loomctx import agent_eval_ext as ext
    ext.main(["prepare", str(tmp_path), "--scale", "small"])
    store = SqliteStore(tmp_path / "forest.db")
    _load_ldif(store, open(os.path.join(tmp_path, "forest.ldif")).read())
    pack = build_pack(store, AskRequest(namespace="ad", question="What groups does mreyes belong to?", budget=3000,
                                        scope=ScopeSpec(subjects=[EntityRef(type="user", key=f"{ext.CORP_SID}-95101")],
                                                        expand=["member_of"], depth=3)))
    assert any(f"group:{ext.CORP_SID}-95007 (CORP-Remote-Apps@corp.local)" in i.text for i in pack.items)
    pack = build_pack(store, AskRequest(namespace="ad", budget=3000,
                                        question="which computer accounts are trusted for unconstrained delegation?",
                                        scope=ScopeSpec(subjects=[EntityRef(type="domain", key="corp.local")],
                                                        expand=["trusts_for_unconstrained_delegation"], depth=2)))
    assert pack.notes[0].startswith("nothing was reached along trusts_for_unconstrained_delegation")
    text = "\n".join(i.text for i in pack.items)
    assert all(h in text for h in ("APP-LEGACY01", "PRINT-HQ02", "SQL-OLD03"))
    # a walk that reached entities, none the question is about — hosts that
    # joined the domain (member_of), not the computers its OUs hold — and
    # named a predicate it could not walk (Gemini 2.5 Flash's call)
    store.record_claims([ClaimIn(namespace="ad", subject=EntityRef(type="host", key=h), predicate="member_of",
                                 object=EntityRef(type="domain", key="corp.local"), source="inventory",
                                 observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc)) for h in ("web-01", "db-01")])
    pack = build_pack(store, AskRequest(namespace="ad", budget=3000,
                                        question="which computer accounts are trusted for unconstrained delegation?",
                                        scope=ScopeSpec(subjects=[EntityRef(type="domain", key="corp.local")],
                                                        expand=["member_of", "trusted_for_unconstrained_delegation"],
                                                        depth=2)))
    assert pack.notes[0].startswith("nothing this walk reached along member_of, trusted_for_unconstrained_delegation "
                                    "carries unconstrained_delegation")
    assert all(h in "\n".join(i.text for i in pack.items) for h in ("APP-LEGACY01", "PRINT-HQ02", "SQL-OLD03"))
    # a walk along real links only is never widened
    plain = build_pack(store, AskRequest(namespace="ad", budget=3000,
                                         question="which computer accounts are trusted for unconstrained delegation?",
                                         scope=ScopeSpec(subjects=[EntityRef(type="domain", key="corp.local")],
                                                         expand=["member_of"], depth=2)))
    assert not any(n.startswith("nothing") for n in plain.notes)
    store.close()


def test_a_topic_of_many_predicates_filters_on_its_rare_ones(tmp_path):
    """D-100: "unconstrained delegation — show name, DN, is_dc, OS, enabled"
    made all six the topic, and every reached account's name filled the
    pack before the computers carrying the flag."""
    import os
    from loomctx import agent_eval_ext as ext
    ext.main(["prepare", str(tmp_path), "--scale", "small"])
    store = SqliteStore(tmp_path / "forest.db")
    _load_ldif(store, open(os.path.join(tmp_path, "forest.ldif")).read())
    pack = build_pack(store, AskRequest(namespace="ad", budget=1500, question=(
        "List all computer accounts that have unconstrained delegation enabled (unconstrained_delegation=true). "
        "For each computer, show its name, distinguishedName (dn_name), whether it is a DC (is_dc), and the OS."),
        scope=ScopeSpec(subjects=[EntityRef(type="domain", key="corp.local")],
                        expand=["contains", "unconstrained_delegation"], depth=2)))
    text = "\n".join(i.text for i in pack.items)
    assert all(h in text for h in ("APP-LEGACY01", "PRINT-HQ02", "SQL-OLD03")), text[:2000]
    store.close()


def test_a_sibling_walk_keeps_the_chain_when_the_cap_binds(tmp_path, monkeypatch):
    """D-101: `siblings: true` from Domain Admins fanned out through every
    co-member's other groups and filled the entity cap before the members
    three hops down; the chain is now walked first and ranked first."""
    import os
    from loomctx import agent_eval_ext as ext
    monkeypatch.setenv("LOOMCTX_MAX_SCOPE_ENTITIES", "60")
    ext.main(["prepare", str(tmp_path), "--scale", "small"])
    store = SqliteStore(tmp_path / "forest.db")
    _load_ldif(store, open(os.path.join(tmp_path, "forest.ldif")).read())
    pack = build_pack(store, AskRequest(namespace="ad", budget=4000,
                                        question="Which users and groups are members of Domain Admins, directly or through nested groups?",
                                        scope=ScopeSpec(subjects=[EntityRef(type="group", key=f"{ext.CORP_SID}-512")],
                                                        expand=["member_of"], depth=3, siblings=True)))
    text = "\n".join(i.text for i in pack.items)
    assert all(f"{ext.DEV_SID}-{ext.DEV_USERS[n][0]}" in text for n in ("dlee", "dkim", "dpatel", "dgarcia", "dnguyen"))
    store.close()


def test_one_pack_walks_once(tmp_path, monkeypatch):
    """D-102: build_pack builds twice (the second with room for names) and
    walked twice; the walk and gather are memoized within one call, and the
    second build keeps its own budget."""
    import os
    from loomctx import agent_eval_ext as ext
    from loomctx import context
    ext.main(["prepare", str(tmp_path), "--scale", "small"])
    store = SqliteStore(tmp_path / "forest.db")
    _load_ldif(store, open(os.path.join(tmp_path, "forest.ldif")).read())
    walks = []
    real = context._walk_scope
    monkeypatch.setattr(context, "_walk_scope", lambda *a, **k: walks.append(1) or real(*a, **k))
    req = AskRequest(namespace="ad", budget=2000, question="which dev.local accounts are members of Domain Admins?",
                     scope=ScopeSpec(subjects=[EntityRef(type="group", key=f"{ext.CORP_SID}-512")],
                                     expand=["member_of"], depth=3))
    pack = build_pack(store, req)
    assert len(walks) == 1 and pack.charged_tokens <= 2000
    assert build_pack(store, req).items == pack.items     # and a second call walks afresh, the same
    assert len(walks) == 2
    store.close()


def test_the_exceptional_status_is_the_minority_value():
    from datetime import datetime, timezone
    from loomctx.context import _exceptional_status
    from loomctx.contracts import Observation

    def obs(key, value, i):
        return Observation(id=f"o{i}", namespace="ad", subject=EntityRef(type="user", key=key),
                           predicate="enabled", object=value, source="ad-export",
                           observed_at=datetime(2026, 9, 20, tzinfo=timezone.utc),
                           recorded_at=datetime(2026, 9, 20, tzinfo=timezone.utc), confidence=1.0)
    many = [obs(f"u{i}", True, i) for i in range(5)] + [obs("off", False, 9)]
    assert _exceptional_status(many, frozenset({"enabled"})) == {"o9"}
    assert _exceptional_status(many[:5], frozenset({"enabled"})) == frozenset()      # all agree
    assert _exceptional_status([many[0], many[5]], frozenset({"enabled"})) == {"o0", "o9"}   # a tie
    assert _exceptional_status(many, frozenset()) == frozenset()


def _load_ldif(store, text):
    store.put_schema(ldap.schema("ad"))
    store.record_claims(list(ldap.ldif_to_envelopes(text, "ad")))


def _gaps(store, ns, *preds):
    return {(g.predicate, g.state) for g in coverage.gaps(store, ns, preds)}


def test_a_full_generated_dump_reads_as_fully_collected(tmp_path):
    ldif, _ = ad_gen.generate(7, "small")
    store = SqliteStore(tmp_path / "full.db")
    _load_ldif(store, ldif)
    assert _gaps(store, "ad", "has_ace", "enabled", "member_of") == set()
    assert {str(o.object) for o in coverage.records(store, "ad")} >= {"has_ace", "enabled"}
    store.close()


def test_a_dump_without_acls_or_uac_says_so(tmp_path):
    """Dumped without nTSecurityDescriptor (no READ_CONTROL, or an ldapsearch
    that did not ask) and without userAccountControl."""
    ldif, truth = ad_gen.generate(7, "small")
    store = SqliteStore(tmp_path / "partial.db")
    _load_ldif(store, _strip(ldif, "nTSecurityDescriptor", "userAccountControl"))
    assert _gaps(store, "ad", "has_ace", "enabled") == {("has_ace", "absent"), ("enabled", "absent")}

    chain = next(c for c in truth["chains"] if c["hops"] == 2)
    start, target = (EntityRef(**chain[k]) for k in ("start", "target"))
    pack = find_paths(store, PathRequest(namespace="ad", **{"from": start}, to=target,
                                         via=["member_of", "has_ace"]))
    assert pack.paths == []
    note = next(n for n in pack.notes if n.startswith("coverage:"))
    assert "'has_ace' was not collected" in note and "domain:" in note

    ask = build_pack(store, AskRequest(namespace="ad", question="who can reach it?", budget=2000,
                                       scope=ScopeSpec(subjects=[start], expand=["member_of", "has_ace"],
                                                       depth=2)))
    assert any(n.startswith("coverage:") and "has_ace" in n for n in ask.notes)
    store.close()


def test_partial_acl_collection_is_counted(tmp_path):
    ldif, _ = ad_gen.generate(7, "small")
    blocks = ldif.split("\n\n")
    thinned = "\n\n".join(_strip(b, "nTSecurityDescriptor") if i % 2 else b
                          for i, b in enumerate(blocks))
    store = SqliteStore(tmp_path / "half.db")
    _load_ldif(store, thinned)
    [gap] = coverage.gaps(store, "ad", ["has_ace"])
    assert gap.state == "partial" and 0 < gap.with_ < gap.of
    assert f"only {gap.with_:,} of {gap.of:,}" in gap.text()
    store.close()


def test_a_later_full_dump_supersedes_the_gap(tmp_path):
    ldif, _ = ad_gen.generate(7, "small")
    store = SqliteStore(tmp_path / "later.db")
    store.put_schema(ldap.schema("ad"))
    early = datetime(2026, 9, 1, tzinfo=timezone.utc)
    ldif = "\n".join(line for line in ldif.splitlines() if not line.startswith("#"))  # dated by as_of
    store.record_claims(list(ldap.ldif_to_envelopes(
        _strip(ldif, "nTSecurityDescriptor"), "ad", as_of=early)))
    assert _gaps(store, "ad", "has_ace") == {("has_ace", "absent")}
    store.record_claims(list(ldap.ldif_to_envelopes(
        ldif, "ad", as_of=datetime(2026, 9, 10, tzinfo=timezone.utc))))
    assert _gaps(store, "ad", "has_ace") == set()
    # as of before the full dump, the gap is what was known
    assert _gaps_asof(store, early) == {("has_ace", "absent")}
    store.close()


def _gaps_asof(store, when):
    return {(g.predicate, g.state) for g in coverage.gaps(store, "ad", ["has_ace"], as_of=when)}


def test_unknown_status_on_a_path_is_not_read_as_enabled(tmp_path):
    """Two users in one group, only one with `enabled` on record: the path
    through the other says its status is unknown."""
    store = SqliteStore(tmp_path / "status.db")
    doc = {"users": [{"id": "u1", "userPrincipalName": "a@x", "accountEnabled": False},
                     {"id": "u2", "userPrincipalName": "b@x"}],
           "groups": [{"id": "g1", "displayName": "ops", "securityEnabled": True,
                       "mailNickname": "ops", "members": [{"id": "u1"}, {"id": "u2"}]}]}
    store.put_schema(entra.schema("iam"))
    store.record_claims(list(entra.entra_to_envelopes(json.dumps(doc), "iam")))
    [gap] = coverage.gaps(store, "iam", ["enabled"])
    assert (gap.with_, gap.of) == (1, 2)
    known = find_paths(store, PathRequest(namespace="iam", **{"from": EntityRef(type="user", key="u1")},
                                          to=EntityRef(type="group", key="g1"), via=["member_of"]))
    assert [(s.entity.key, s.value) for s in known.node_status] == [("u1", False)]
    unknown = find_paths(store, PathRequest(namespace="iam", **{"from": EntityRef(type="user", key="u2")},
                                            to=EntityRef(type="group", key="g1"), via=["member_of"]))
    assert unknown.paths and not unknown.node_status
    assert any("no 'enabled' on record for user:u2" in n for n in unknown.notes)
    store.close()


def test_okta_export_without_factors_or_roles(tmp_path):
    doc = {"users": [{"id": "00u1", "status": "ACTIVE",
                      "profile": {"login": "a@x", "firstName": "A", "lastName": "B"}}],
           "groups": [{"id": "00g1", "type": "OKTA_GROUP", "profile": {"name": "g"},
                       "_members": [{"id": "00u1"}]}]}
    envs = [e for e in okta.okta_to_envelopes(json.dumps(doc), "iam") if e.predicate == "collected"]
    got = {(e.object, e.attrs["state"]) for e in envs}
    assert ("mfa_enrolled", "absent") in got          # factors were not exported, not "no MFA"
    assert ("has_role", "absent") in got and ("assigned_to", "absent") in got
    assert ("member_of", "complete") in got and ("enabled", "complete") in got


def test_separate_files_claim_nothing_about_collections_they_do_not_hold():
    """A plain users array (one file of several) says nothing about role
    assignments, which may be in another file."""
    users = [{"id": "u1", "userPrincipalName": "a@x", "accountEnabled": True}]
    preds = {e.object for e in entra.entra_to_envelopes(json.dumps(users), "iam")
             if e.predicate == "collected"}
    assert preds == {"enabled"}


# ------------------------------------------------------------------ drift #

def test_a_dropped_attribute_is_reported_as_drift(tmp_path):
    """The same directory exported twice; the second export (a changed tool
    or ldapsearch option) no longer carries userAccountControl."""
    ldif, _ = ad_gen.generate(7, "small")
    ldif = "\n".join(line for line in ldif.splitlines() if not line.startswith("#"))
    db = str(tmp_path / "drift.db")
    store = SqliteStore(db)
    store.put_schema(ldap.schema("ad"))
    store.record_claims(list(ldap.ldif_to_envelopes(ldif, "ad",
                                                    as_of=datetime(2026, 9, 1, tzinfo=timezone.utc))))
    store.close()
    watch = coverage.Watch()
    later = list(watch.wrap(ldap.ldif_to_envelopes(_strip(ldif, "userAccountControl"), "ad",
                                                   as_of=datetime(2026, 9, 10, tzinfo=timezone.utc))))
    found = watch.report(None, db, None)
    user = next(d for d in found if d.kind == "ldap:user")
    assert "useraccountcontrol" in user.removed and not user.added
    assert "no longer carries useraccountcontrol" in user.text()
    # once stored, the same comparison reads back from the store
    store = SqliteStore(db)
    store.record_claims(later)
    assert any(d.kind == "ldap:user" and "useraccountcontrol" in d.removed
               for d in coverage.drift(coverage.stored(store, "ad")))
    store.close()


def test_an_unchanged_reimport_is_not_drift(tmp_path):
    ldif, _ = ad_gen.generate(7, "small")
    db = str(tmp_path / "same.db")
    store = SqliteStore(db)
    store.put_schema(ldap.schema("ad"))
    envs = list(ldap.ldif_to_envelopes(ldif, "ad"))
    store.record_claims(envs)
    store.record_claims(envs)
    assert coverage.drift(coverage.stored(store, "ad")) == []
    store.close()


def test_drift_reads_earlier_shapes_from_the_engine_when_importing_through_a_gateway(monkeypatch, tmp_path):
    """The gateway serves ingest only; LOOMCTX_READ_URL names the engine the
    earlier shapes are read from."""
    seen = []

    def fake_remote(url, namespace, key=None, ref=None):
        seen.append(url)
        return []

    monkeypatch.setattr(coverage, "remote", fake_remote)
    monkeypatch.setenv("LOOMCTX_READ_URL", "http://engine:8000")
    ldif, _ = ad_gen.generate(7, "small")
    watch = coverage.Watch()
    list(watch.wrap(ldap.ldif_to_envelopes(ldif, "ad")))
    assert watch.report("http://gateway", None, "k") == [] and seen == ["http://engine:8000"]
