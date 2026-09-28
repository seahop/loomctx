"""The raw-LDAP / LDIF connector (loomctx.connectors.ldap): LDIF parsing
(base64, folding, multi-valued), objectSid decode, a hand-crafted Security
Descriptor decoding to the right `has_ace` rights, userAccountControl bits, a
trust with direction / transitivity, idempotent re-import, and a round-trip
`import` -> `ask_scope` over member_of + has_ace + trusts that returns the
chain cited. No real AD data; every binary blob is crafted in the test."""

import base64
import json
import struct
from datetime import datetime, timezone
from pathlib import Path

from loomctx.connectors import ldap
from loomctx.context import build_pack
from loomctx.contracts import AskRequest, EntityRef, ScopeSpec
from loomctx.store.sqlite import SqliteStore

FIXTURE = Path(__file__).parent / "fixtures" / "corp_ad.ldif"
DOMAIN_SID = "S-1-5-21-1111111111-2222222222-3333333333"


# ---------------------------------------------------------------- binary helpers #

def encode_sid(text: str) -> bytes:
    parts = text.split("-")
    revision = int(parts[1])
    authority = int(parts[2])
    subs = [int(p) for p in parts[3:]]
    out = bytes([revision, len(subs)]) + authority.to_bytes(6, "big")
    for sub in subs:
        out += sub.to_bytes(4, "little")
    return out


def guid_bytes(text: str) -> bytes:
    h = text.split("-")
    return (int(h[0], 16).to_bytes(4, "little") + int(h[1], 16).to_bytes(2, "little")
            + int(h[2], 16).to_bytes(2, "little") + bytes.fromhex(h[3]) + bytes.fromhex(h[4]))


def allowed_ace(sid: str, mask: int) -> bytes:
    body = struct.pack("<I", mask) + encode_sid(sid)
    return struct.pack("<BBH", ldap.ACE_ACCESS_ALLOWED, 0x00, 4 + len(body)) + body


def object_ace(sid: str, mask: int, object_type: str | None) -> bytes:
    flags = ldap.ACE_OBJECT_TYPE_PRESENT if object_type else 0
    body = struct.pack("<II", mask, flags)
    if object_type:
        body += guid_bytes(object_type)
    body += encode_sid(sid)
    return struct.pack("<BBH", ldap.ACE_ACCESS_ALLOWED_OBJECT, 0x00, 4 + len(body)) + body


def build_sd(*aces: bytes) -> bytes:
    acl_body = b"".join(aces)
    acl = struct.pack("<BBHHH", 4, 0, 8 + len(acl_body), len(aces), 0) + acl_body
    # header: rev, sbz1, control (DACL present + self-relative), owner/group/sacl=0, dacl=20
    header = struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 0, 20)
    return header + acl


def b64(blob: bytes) -> str:
    return base64.b64encode(blob).decode()


# ------------------------------------------------------------------ LDIF parse #

def test_ldif_parsing_base64_folding_multivalue():
    entries, export_at = ldap.parse_ldif(FIXTURE.read_text())
    by_dn = {e.dn: e for e in entries}
    # the `# ... 2026-09-20T09:00:00Z` comment is the export timestamp
    assert export_at == datetime(2026, 9, 20, 9, 0, tzinfo=timezone.utc)
    svc = by_dn["CN=svc-sql,CN=Users,DC=corp,DC=local"]
    # a base64 value folded across two lines rejoins and decodes
    assert svc.raw("description") == b"Service account for the SQL Server service"
    # multi-valued attribute keeps every value
    assert svc.texts("serviceprincipalname") == ["MSSQLSvc/db01.corp.local:1433", "MSSQLSvc/db01.corp.local"]
    # a plain (changetype-free) entry with a base64 objectSid alias in string form
    assert svc.text("samaccountname") == "svc-sql"
    hd = by_dn["CN=Help Desk,CN=Users,DC=corp,DC=local"]
    assert hd.raw("description") == b"Help desk operators"


def test_objectsid_decode_binary_and_base64():
    blob = encode_sid(DOMAIN_SID + "-512")
    assert ldap.decode_sid(blob) == DOMAIN_SID + "-512"
    # a binary objectSid arriving base64 in LDIF decodes to the same string
    entry = ldap.LdifEntry("CN=x")
    entry.add("objectSid", base64.b64decode(b64(blob)))
    assert ldap._sid_from_entry(entry) == DOMAIN_SID + "-512"
    # well-known short SID and identifier-authority handling
    assert ldap.decode_sid(encode_sid("S-1-5-32-544")) == "S-1-5-32-544"


# --------------------------------------------------------------- SD / ACE decode #

def test_security_descriptor_decodes_to_the_right_rights():
    help_desk = DOMAIN_SID + "-1105"
    everyone = "S-1-1-0"
    sd = build_sd(
        allowed_ace(help_desk, ldap.GENERIC_ALL),                       # GenericAll
        allowed_ace(help_desk, ldap.WRITE_DAC | ldap.WRITE_OWNER),      # WriteDacl + WriteOwner
        object_ace(help_desk, ldap.ADS_RIGHT_DS_CONTROL_ACCESS, ldap.GUID_FORCE_CHANGE_PASSWORD),
        object_ace(help_desk, ldap.ADS_RIGHT_DS_WRITE_PROP, ldap.GUID_MEMBER_ATTR),   # AddMember
        object_ace(help_desk, ldap.ADS_RIGHT_DS_CONTROL_ACCESS, None),  # AllExtendedRights
        allowed_ace(everyone, 0x00020000),                             # READ_CONTROL only: skipped
    )
    aces = ldap.parse_security_descriptor(sd)
    rights = [r for ace in aces for r in ldap.decode_rights(ace)]
    assert rights == ["GenericAll", "WriteDacl", "WriteOwner", "ForceChangePassword",
                      "AddMember", "AllExtendedRights"]
    # the boring READ ACE parsed but granted nothing interesting
    assert any(a.trustee == everyone and not ldap.decode_rights(a) for a in aces)
    # object ACEs carry their GUID
    fcp = next(a for a in aces if ldap.decode_rights(a) == ["ForceChangePassword"])
    assert fcp.object_type == ldap.GUID_FORCE_CHANGE_PASSWORD


def test_mapped_generic_write_detected():
    """S-50: AD stores GenericWrite as its mapped form (0x20028 =
    READ_CONTROL | DS_SELF | DS_WRITE_PROP). The connector must detect it."""
    trustee = DOMAIN_SID + "-1105"
    sd = build_sd(allowed_ace(trustee, ldap.GENERIC_WRITE_MAPPED))
    aces = ldap.parse_security_descriptor(sd)
    rights = [r for ace in aces for r in ldap.decode_rights(ace)]
    assert "GenericWrite" in rights


def test_inherit_only_ace_skipped():
    """S-50: an inherit-only ACE (flag 0x08) applies to children, not the
    object itself. decode_rights must return [] for it."""
    trustee = DOMAIN_SID + "-1105"
    body = struct.pack("<I", ldap.GENERIC_ALL) + encode_sid(trustee)
    ace_bytes = struct.pack("<BBH", ldap.ACE_ACCESS_ALLOWED, ldap.ACE_INHERIT_ONLY,
                            4 + len(body)) + body
    sd = build_sd(ace_bytes)
    aces = ldap.parse_security_descriptor(sd)
    assert len(aces) == 1
    assert aces[0].flags & ldap.ACE_INHERIT_ONLY
    assert ldap.decode_rights(aces[0]) == []


def test_event_id_no_collision_on_long_sids():
    """S-50: event ids must not collide when SIDs are long. Two ACEs with
    different rights on the same long-SID pair must produce distinct ids."""
    long_sid = "S-1-5-21-1234567890123-1234567890123-1234567890123-99999"
    target_sid = "S-1-5-21-9876543210987-9876543210987-9876543210987-11111"
    eid1 = ldap._eid(f"ldap:{long_sid}:20260920T090000:has_ace:{target_sid}:GenericAll")
    eid2 = ldap._eid(f"ldap:{long_sid}:20260920T090000:has_ace:{target_sid}:WriteDacl")
    assert eid1 != eid2
    assert len(eid1) <= 128 and len(eid2) <= 128


# ---------------------------------------------------------------------- UAC / trust #

def _facts(store, ref):
    return {(o.predicate, json.dumps(o.object, default=str)): o
            for o in store.observations_for("ad", ref, limit=200)}


def test_useraccountcontrol_bits_decode(tmp_path):
    db = str(tmp_path / "uac.db")
    ldap.main(["import", str(FIXTURE), "--namespace", "ad", "--db", db])
    store = SqliteStore(db)
    try:
        dc = _facts(store, EntityRef(type="computer", key=DOMAIN_SID + "-1000"))
        assert ("is_dc", "true") in dc and ("unconstrained_delegation", "true") in dc
        svc = _facts(store, EntityRef(type="user", key=DOMAIN_SID + "-1106"))
        assert ("enabled", "true") in svc and ("kerberoastable", "true") in svc
        jdoe = _facts(store, EntityRef(type="user", key=DOMAIN_SID + "-1107"))
        assert ("no_preauth", "true") in jdoe
        # constrained delegation target from msDS-AllowedToDelegateTo
        web = _facts(store, EntityRef(type="computer", key=DOMAIN_SID + "-1101"))
        assert any(p == "can_delegate_to" for p, _ in web)
        # D-097: the account's name with its domain, from the DN
        assert ("principal", '"svc-sql@corp.local"') in svc
    finally:
        store.close()


def test_trust_bidirectional_emits_both_edges(tmp_path):
    """S-50: bidirectional (trustDirection 3) emits two edges so the scope
    walk / find_path can traverse in both directions."""
    db = str(tmp_path / "trust.db")
    ldap.main(["import", str(FIXTURE), "--namespace", "ad", "--db", db])
    store = SqliteStore(db)
    try:
        local_ref = EntityRef(type="domain", key="corp.local")    # keyed by DNS name (D-099)
        partner_ref = EntityRef(type="domain", key="dev.local")
        local_trusts = [o for o in store.observations_for("ad", local_ref)
                        if o.predicate == "trusts" and o.subject == local_ref]
        partner_trusts = [o for o in store.observations_for("ad", partner_ref)
                          if o.predicate == "trusts" and o.subject == partner_ref]
        assert len(local_trusts) == 1 and len(partner_trusts) == 1
        assert local_trusts[0].object == partner_ref
        assert partner_trusts[0].object == local_ref
        for t in (local_trusts[0], partner_trusts[0]):
            assert t.attrs["direction"] == "bidirectional"
            assert t.attrs["transitive"] is True
            assert t.attrs["sid_filtering"] is False
            assert t.attrs["partner"] == "dev.local"
    finally:
        store.close()


def test_trust_inbound_and_outbound_direction():
    """S-50: inbound/outbound trust direction is correctly mapped to edge
    direction. subject trusts object = subject accepts object's credentials."""
    inbound_ldif = """# 2026-09-20T09:00:00Z
dn: DC=corp,DC=local
objectClass: domainDNS
objectSid: S-1-5-21-111-222-333
name: corp.local

dn: CN=partner.local,CN=System,DC=corp,DC=local
objectClass: trustedDomain
trustPartner: partner.local
trustDirection: 1
trustAttributes: 0
"""
    outbound_ldif = inbound_ldif.replace("trustDirection: 1", "trustDirection: 2")
    for ldif_text, expect_subj_key, expect_obj_key, expect_dir in [
        (inbound_ldif, "corp.local", "partner.local", "inbound"),
        (outbound_ldif, "partner.local", "corp.local", "outbound"),
    ]:
        envs = list(ldap.ldif_to_envelopes(ldif_text, "ad"))
        trusts = [e for e in envs if e.predicate == "trusts"]
        assert len(trusts) == 1, f"expected 1 trust edge for {expect_dir}"
        t = trusts[0]
        assert t.subject.key == expect_subj_key
        assert t.object.key == expect_obj_key
        assert t.attrs["direction"] == expect_dir
        # D-098: the trust's properties as facts a pack shows, on the partner
        facts = {e.predicate: e.object for e in envs if e.subject.key == "partner.local"
                 and e.predicate.startswith("trust_")}
        assert facts == {"trust_direction": expect_dir, "trust_transitive": True, "trust_sid_filtering": False}
        # and one line on the exporting domain, for an ask about the domain itself
        [summary] = [e.object for e in envs if e.predicate == "trust_properties"]
        assert summary == f"partner.local: {expect_dir}, transitive, SID filtering off"


def test_reimport_is_idempotent(tmp_path):
    db = str(tmp_path / "idem.db")
    ldap.main(["import", str(FIXTURE), "--namespace", "ad", "--db", db])
    before = sum(1 for _ in SqliteStore(db).iter_observations("ad"))
    ldap.main(["import", str(FIXTURE), "--namespace", "ad", "--db", db])
    after = sum(1 for _ in SqliteStore(db).iter_observations("ad"))
    assert before == after and before > 0


# ---------------------------------------------------- round trip: import -> ask_scope #

def _roundtrip_ldif() -> str:
    """The fixture with svc-sql made a direct member of Domain Admins and a
    crafted nTSecurityDescriptor injected into the domain object, so the
    3-hop chain svc-sql -member_of-> Domain Admins -has_ace-> corp.local
    -trusts-> dev.local exists end to end (ScopeSpec caps depth at 3)."""
    domain_admins = DOMAIN_SID + "-512"
    dom_sd = build_sd(allowed_ace(domain_admins, ldap.GENERIC_ALL))     # Domain Admins -> corp.local
    text = FIXTURE.read_text()
    # svc-sql becomes a direct member of Domain Admins
    text = text.replace("memberOf: CN=Help Desk,CN=Users,DC=corp,DC=local\n",
                        "memberOf: CN=Help Desk,CN=Users,DC=corp,DC=local\n"
                        "memberOf: CN=Domain Admins,CN=Users,DC=corp,DC=local\n")
    # inject the SD on the domain object (its SID has no trailing RID, so the
    # match is unambiguous)
    text = text.replace(f"objectSid: {DOMAIN_SID}\nname: corp.local",
                        f"objectSid: {DOMAIN_SID}\nnTSecurityDescriptor:: {b64(dom_sd)}\nname: corp.local")
    return text


def test_import_then_ask_scope_returns_the_cited_chain(tmp_path):
    ldif = tmp_path / "corp-with-acls.ldif"
    ldif.write_text(_roundtrip_ldif())
    db = str(tmp_path / "scope.db")
    ldap.main(["import", str(ldif), "--namespace", "ad", "--db", db])
    store = SqliteStore(db)
    try:
        scope = ScopeSpec(subjects=[EntityRef(type="user", key=DOMAIN_SID + "-1106")],
                          expand=["member_of", "has_ace", "trusts"], depth=3)
        pack = build_pack(store, AskRequest(
            namespace="ad", scope=scope, budget=4000,
            question="what rights and trust path connects user svc-sql to domain dev.local?"))
        blob = "\n".join(i.text for i in pack.items)
        # the whole chain is present, each hop as its own edge
        assert "member_of" in blob and "has_ace" in blob and "trusts" in blob
        # it reaches the far domain across the trust
        assert "dev.local" in blob
        # every item is cited (hard constraint 3)
        assert pack.items and all(i.citations for i in pack.items)
        assert all(c.observation_id for i in pack.items for c in i.citations)
        # the walk actually reached Domain Admins and the trust partner
        reached = {(s.type, s.key) for s in pack.subjects}
        assert ("domain", "dev.local") in reached
    finally:
        store.close()


def test_find_path_user_to_domain_returns_the_cited_chain(tmp_path):
    """find_path (D-067) over the same corpus: svc-sql -member_of-> Domain
    Admins -has_ace-> corp.local -trusts-> dev.local, each hop cited. The
    connector carries the evidence; find_path enumerates the connecting edge
    sequence — it does not rank or score it."""
    from loomctx.context import find_paths
    from loomctx.contracts import PathRequest

    ldif = tmp_path / "corp-with-acls.ldif"
    ldif.write_text(_roundtrip_ldif())
    db = str(tmp_path / "path.db")
    ldap.main(["import", str(ldif), "--namespace", "ad", "--db", db])
    store = SqliteStore(db)
    try:
        pack = find_paths(store, PathRequest(
            namespace="ad", **{"from": EntityRef(type="user", key=DOMAIN_SID + "-1106")},
            to=EntityRef(type="domain", key="dev.local"),
            via=["member_of", "has_ace", "trusts"], depth=3, max_paths=8))
        assert pack.paths, "svc-sql reaches dev.local across member_of -> has_ace -> trusts"
        best = pack.paths[0]
        assert [e.predicate for e in best] == ["member_of", "has_ace", "trusts"]
        # every hop is cited (hard constraint 3)
        assert all(e.cite.observation_id for e in best)
        assert pack.to == EntityRef(type="domain", key="dev.local")
        keys = {(e.subject.type, e.subject.key) for e in best} | {
            (e.object.type, e.object.key) for e in best if isinstance(e.object, EntityRef)}
        assert ("group", DOMAIN_SID + "-512") in keys   # Domain Admins
        assert ("domain", "corp.local") in keys         # keyed by DNS name (D-099)
    finally:
        store.close()


def test_schema_registers_the_object_level_predicates():
    reg = ldap.schema("ad")
    preds = {p.name for p in reg.predicates}
    assert {"member_of", "has_ace", "trusts", "contains", "can_delegate_to",
            "rbcd_from", "kerberoastable"} <= preds
    types = {t.name for t in reg.entity_types}
    assert {"domain", "computer", "user", "group", "ou", "gpo", "container"} <= types
    assert reg.strict is False
    principal = next(p for p in reg.predicates if p.name == "principal")
    assert principal.label and principal.display          # shown beside the SID in packs (D-097)


def test_import_exits_nonzero_when_the_engine_refuses_envelopes(monkeypatch):
    """D-063: a loader that saw any refusal must not exit 0."""
    import pytest

    from loomctx import ingest
    from loomctx.connectors import vulns

    monkeypatch.setattr(vulns, "register", lambda *a, **k: None)

    def refusing(url, lines, size, key, timeout=60.0):
        n = sum(1 for _ in lines)
        return {"total": n, "recorded": n - 2, "accepted": 0, "rejected": 2}

    monkeypatch.setattr(ingest, "post_batches", refusing)
    with pytest.raises(SystemExit) as exc:
        ldap.main(["import", str(FIXTURE), "--namespace", "ad", "--url", "http://loomctx.invalid"])
    assert exc.value.code not in (0, None)
    assert "2 envelopes were refused" in str(exc.value.code)
