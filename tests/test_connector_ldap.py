"""The raw-LDAP / LDIF connector (loom.connectors.ldap): LDIF parsing
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

from loom.connectors import ldap
from loom.context import build_pack
from loom.contracts import AskRequest, EntityRef, ScopeSpec
from loom.store.sqlite import SqliteStore

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
    finally:
        store.close()


def test_trust_direction_and_transitivity(tmp_path):
    db = str(tmp_path / "trust.db")
    ldap.main(["import", str(FIXTURE), "--namespace", "ad", "--db", db])
    store = SqliteStore(db)
    try:
        rows = [o for o in store.observations_for("ad", EntityRef(type="domain", key=DOMAIN_SID))
                if o.predicate == "trusts"]
        assert len(rows) == 1
        trust = rows[0]
        assert trust.object == EntityRef(type="domain", key="dev.local")
        assert trust.attrs["direction"] == "bidirectional"       # trustDirection 3
        assert trust.attrs["transitive"] is True                 # trustAttributes 8, no NON_TRANSITIVE bit
        assert trust.attrs["sid_filtering"] is False
        assert trust.attrs["partner"] == "dev.local"
    finally:
        store.close()


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


def test_schema_registers_the_object_level_predicates():
    reg = ldap.schema("ad")
    preds = {p.name for p in reg.predicates}
    assert {"member_of", "has_ace", "trusts", "contains", "can_delegate_to",
            "rbcd_from", "kerberoastable"} <= preds
    types = {t.name for t in reg.entity_types}
    assert {"domain", "computer", "user", "group", "ou", "gpo", "container"} <= types
    assert reg.strict is False
