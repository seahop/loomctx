"""What an import collected (D-082): connectors record which data their
export carried, and reads say when a predicate they walk or a status they
report was not (fully) collected — so "no path" from a partial dump is not
read as "no access", and a missing `enabled` is not read as enabled."""

import json
from datetime import datetime, timezone

from loomctx import coverage
from loomctx.connectors import ad_gen, entra, ldap, okta
from loomctx.context import build_pack, find_paths
from loomctx.contracts import AskRequest, EntityRef, PathRequest, ScopeSpec
from loomctx.store.sqlite import SqliteStore


def _strip(ldif: str, *attrs: str) -> str:
    drop = tuple(a.lower() + ":" for a in attrs)
    return "\n".join(line for line in ldif.splitlines() if not line.lower().startswith(drop))


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
