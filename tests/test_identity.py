"""One host, one person across tools (D-083): identifier normalization, the
registry merging shared predicates, and the resolution tier folding
entities that share a strong identifier — and not those that share only a
weak one, an address, or an identifier across kinds of thing."""

import json
from datetime import datetime, timezone

import pytest

from loomctx import enrich, identity
from loomctx.connectors import entra, ldap, nmap, okta
from loomctx.contracts import EntityRef, PredicateDef, SchemaRegistration
from loomctx.store import common
from loomctx.store.sqlite import SqliteStore

T0 = datetime(2026, 9, 20, 9, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _fresh_watermarks():
    enrich._identity_seen_until.clear()
    yield
    enrich._identity_seen_until.clear()


@pytest.fixture
def store(tmp_path):
    s = SqliteStore(tmp_path / "id.db")
    yield s
    s.close()


def _say(store, ref, *pairs, source="tool"):
    store.record_claims(identity.claims("net", ref, pairs, T0, source))


def _canon(store, ref):
    return store.resolve_refs("net", [ref]).get((ref.type, ref.key), ref)


# ------------------------------------------------------------ normalization #

@pytest.mark.parametrize("kind,value,want", [
    ("fqdn", "WEB-01.Corp.Local.", "web-01.corp.local"),
    ("fqdn", "web-01", None),                              # not qualified
    ("hostname", "WEB01$", "web01"),                       # AD machine account
    ("hostname", "web-01.corp.local", "web-01"),
    ("mac", "AA-BB-CC-00-11-22", "aa:bb:cc:00:11:22"),
    ("mac", "00:00:00:00:00:00", None),
    ("sid", "s-1-5-21-1-2-3-1104", "S-1-5-21-1-2-3-1104"),
    ("upn", "JDoe@Corp.COM", "jdoe@corp.com"),
    ("account", "CORP\\JDoe", "corp\\jdoe"),
    ("account", "corp.local\\jdoe", "corp\\jdoe"),         # a DNS domain -> its first label
    ("account", "NT AUTHORITY\\SYSTEM", None),             # built-in: not an identity
    ("hostname", "localhost", None),
])
def test_normalize(kind, value, want):
    assert identity.normalize(kind, value) == want


def test_an_fqdn_also_states_the_short_hostname():
    claims = identity.claims("net", EntityRef(type="host", key="x"), [("fqdn", "web-01.corp.local")],
                             T0, "t")
    assert {c.object.key for c in claims} == {"fqdn:web-01.corp.local", "hostname:web-01"}
    assert {c.attrs["strong"] for c in claims} == {True, False}


# ----------------------------------------------------------- the registry #

def test_registration_merges_a_shared_predicate_instead_of_replacing_it():
    a = SchemaRegistration(namespace="net", predicates=[
        PredicateDef(name="member_of", object_types=["group"], containment=True)])
    b = SchemaRegistration(namespace="net", predicates=[
        PredicateDef(name="member_of", object_types=["domain"], description="seed"),
        PredicateDef(name="enabled", node_status=True)])
    merged = common.merge_schema(a, b)
    by = {p.name: p for p in merged.predicates}
    assert set(by["member_of"].object_types) == {"group", "domain"}
    assert by["member_of"].containment and by["member_of"].description == "seed"
    anyone = common.merge_schema(merged, SchemaRegistration(namespace="net", predicates=[
        PredicateDef(name="member_of")]))
    assert {p.name: p for p in anyone.predicates}["member_of"].object_types == []   # any stays any


# ------------------------------------------------------------- resolution #

def test_a_scan_and_the_directory_fold_on_the_fqdn(store):
    scan, ad = EntityRef(type="host", key="10.0.4.7"), EntityRef(type="computer", key="S-1-5-21-9-1104")
    _say(store, scan, ("fqdn", "web-01.corp.local"), source="nmap")
    _say(store, ad, ("fqdn", "WEB-01.corp.local"), ("hostname", "WEB-01$"), source="ad")
    assert enrich.resolve_identities(store) == 1
    assert _canon(store, scan) == _canon(store, ad)


def test_only_a_weak_identifier_is_not_merged_without_an_adjudicator(store):
    a, b = EntityRef(type="host", key="web-01"), EntityRef(type="host", key="WEB-01 (dmz)")
    _say(store, a, ("hostname", "web-01"))
    _say(store, b, ("hostname", "web-01"))
    assert enrich.resolve_identities(store) == 0
    assert _canon(store, a) != _canon(store, b)


def test_a_shared_address_never_merges(store):
    a, b = EntityRef(type="host", key="web-01"), EntityRef(type="host", key="laptop-17")
    store.record_claims(identity.ip_claims("net", a, ["10.0.4.7"], T0, "dhcp")
                        + identity.ip_claims("net", b, ["10.0.4.7"], T0, "dhcp"))
    assert enrich.resolve_identities(store) == 0


def test_different_kinds_of_thing_sharing_an_identifier_are_not_merged(store):
    user, host = EntityRef(type="user", key="u1"), EntityRef(type="host", key="h1")
    _say(store, user, ("mail", "ops@corp.com"))
    _say(store, host, ("mail", "ops@corp.com"))
    assert enrich.resolve_identities(store) == 0


def test_a_decline_holds(store):
    a, b = EntityRef(type="user", key="u1"), EntityRef(type="user", key="u2")
    _say(store, a, ("upn", "x@corp.com"))
    _say(store, b, ("upn", "x@corp.com"))
    store.remember_decline("net", "user:u1", "user:u2", "two people")
    enrich._declined_cache.clear()
    assert enrich.resolve_identities(store) == 0


def test_a_chain_collapses_in_one_pass(store):
    a, b, c = (EntityRef(type="host", key=k) for k in ("a", "b", "c"))
    _say(store, a, ("fqdn", "a.corp.local"))
    _say(store, b, ("fqdn", "a.corp.local"), ("mac", "aa:bb:cc:dd:ee:01"))
    _say(store, c, ("mac", "AA-BB-CC-DD-EE-01"))
    enrich.resolve_identities(store)
    assert _canon(store, a) == _canon(store, b) == _canon(store, c)


def test_the_pass_is_incremental(store):
    a, b = EntityRef(type="user", key="u1"), EntityRef(type="user", key="u2")
    _say(store, a, ("upn", "x@corp.com"))
    assert enrich.resolve_identities(store) == 0
    _say(store, b, ("upn", "x@corp.com"))           # recorded after the first pass
    assert enrich.resolve_identities(store) == 1


# ------------------------------------------------------ through connectors #

NMAP = """<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -sV 10.0.4.0/24" start="1790000000">
<host><status state="up"/><address addr="10.0.4.7" addrtype="ipv4"/>
<address addr="AA:BB:CC:00:11:22" addrtype="mac"/>
<hostnames><hostname name="web-01.corp.local" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host>
</nmaprun>"""

LDIF = """dn: CN=WEB-01,OU=Servers,DC=corp,DC=local
objectClass: computer
objectSid:: AQUAAAAAAAUVAAAAAQAAAAIAAAADAAAAUAQAAA==
sAMAccountName: WEB-01$
dNSHostName: web-01.corp.local
userAccountControl: 4096

dn: CN=John Doe,OU=Staff,DC=corp,DC=local
objectClass: user
objectSid:: AQUAAAAAAAUVAAAAAQAAAAIAAAADAAAAUQQAAA==
sAMAccountName: jdoe
userPrincipalName: jdoe@corp.com
userAccountControl: 512
"""


def test_nmap_and_ldap_meet_on_the_machine(store, tmp_path):
    store.put_schema(ldap.schema("net"))
    scan = tmp_path / "scan.xml"
    scan.write_text(NMAP)
    nmap.main(["import", str(scan), "--namespace", "net", "--db", str(tmp_path / "id.db")])
    store.record_claims(list(ldap.ldif_to_envelopes(LDIF, "net")))
    enrich.resolve_identities(store)
    scanned = _canon(store, EntityRef(type="host", key="web-01.corp.local"))
    assert _canon(store, EntityRef(type="computer", key="S-1-5-21-1-2-3-1104")) == scanned
    # the address stayed a time-stamped link, not an identifier
    rows = store.observations_for("net", scanned, limit=200)
    assert any(o.predicate == "has_ip" and o.object.key == "10.0.4.7" for o in rows)


def test_a_hybrid_user_meets_across_ad_entra_and_okta(store):
    for mod in (ldap, entra, okta):
        store.put_schema(mod.schema("net"))
    store.record_claims(list(ldap.ldif_to_envelopes(LDIF, "net")))
    sid = "S-1-5-21-1-2-3-1105"
    graph = {"users": [{"id": "0f1e", "userPrincipalName": "jdoe@corp.com", "mail": "john.doe@corp.com",
                        "onPremisesSecurityIdentifier": sid, "accountEnabled": True}]}
    store.record_claims(list(entra.entra_to_envelopes(json.dumps(graph), "net")))
    okta_users = {"users": [{"id": "00u1", "status": "ACTIVE",
                             "profile": {"login": "jdoe@corp.com", "email": "john.doe@corp.com",
                                         "firstName": "John", "lastName": "Doe"}}]}
    store.record_claims(list(okta.okta_to_envelopes(json.dumps(okta_users), "net")))
    enrich.resolve_identities(store)
    one = {(c.type, c.key) for c in (_canon(store, r) for r in (
        EntityRef(type="user", key=sid), EntityRef(type="user", key="0f1e"), EntityRef(type="user", key="00u1")))}
    assert len(one) == 1


def test_weak_groups_do_not_starve_strong_ones(store):
    """Never auto-merged, weak groups used to fill every pass's limit and
    the strong ones behind them waited forever."""
    for i in range(6):
        _say(store, EntityRef(type="host", key=f"a{i}"), ("hostname", f"dup{i}"))
        _say(store, EntityRef(type="host", key=f"b{i}"), ("hostname", f"dup{i}"))
    x, y = EntityRef(type="host", key="x"), EntityRef(type="host", key="y")
    _say(store, x, ("mac", "aa:bb:cc:dd:ee:99"))
    _say(store, y, ("mac", "aa:bb:cc:dd:ee:99"))
    assert enrich.resolve_identities(store, limit=3) == 1
    assert _canon(store, x) == _canon(store, y)


def test_replicas_share_the_pass_and_together_fold_everything(store, monkeypatch):
    pairs = []
    for i in range(8):
        a, b = EntityRef(type="host", key=f"p{i}"), EntityRef(type="host", key=f"q{i}")
        _say(store, a, ("mac", f"aa:bb:cc:dd:ee:{i:02x}"))
        _say(store, b, ("mac", f"aa:bb:cc:dd:ee:{i:02x}"))
        pairs.append((a, b))
    monkeypatch.setenv("LOOMCTX_WORKER_SHARD", "0/2")
    first = enrich.resolve_identities(store)
    enrich._identity_seen_until.clear()
    monkeypatch.setenv("LOOMCTX_WORKER_SHARD", "1/2")
    second = enrich.resolve_identities(store)
    assert first + second == 8                   # each pair folded once, by one replica
    assert all(_canon(store, a) == _canon(store, b) for a, b in pairs)
