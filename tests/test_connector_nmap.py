"""The nmap scan-inventory connector (loom.connectors.nmap): parse a genuine
`nmap -oX` XML report into cited, timestamped inventory claims, and prove the
scan data FUSES with the vuln graph — a scanned host reaches its product's
KEV CVE, with the scan claim cited, over the D-067 path walk.

The two `tests/fixtures/nmap_*.xml` reports are REAL nmap 7.98 output, not
hand-written: nmap was run in a throwaway container against an nginx, an
OpenSSH and a PostgreSQL service stood up on a scratch docker network
(`nmap_inventory.xml`), and once more with `-O` for an OS match
(`nmap_os_match.xml`). The parser edge cases (IPv6, a bare IP, filtered
ports, an empty host) are exercised with small inline reports."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from loom.connectors import nmap, vulns
from loom.context import find_paths
from loom.contracts import ClaimIn, EntityRef, PathRequest
from loom.store.sqlite import SqliteStore

FIX = Path(__file__).parent / "fixtures"
INVENTORY = FIX / "nmap_inventory.xml"
OS_MATCH = FIX / "nmap_os_match.xml"


def _by_pred(envs):
    out: dict = {}
    for e in envs:
        if isinstance(e, ClaimIn):
            out.setdefault(e.predicate, []).append(e)
    return out


# ------------------------------------------------------------- parse: real fixture #

def test_parses_multiple_hosts_open_ports_and_service_cpe():
    envs = list(nmap.report_to_envelopes(INVENTORY.read_text(), "netsec"))
    claims = [e for e in envs if isinstance(e, ClaimIn) and e.subject.type == "host"]
    # every host claim carries the scan time (2026-09-26) and cites the report doc
    assert all(c.observed_at.year == 2026 for c in claims)
    assert all(c.provenance and c.provenance.artifact_event_id for c in claims)
    hosts = {c.subject.key for c in claims}
    assert hosts == {"loomnm-nginx", "loomnm-ssh", "loomnm-pg"}     # keyed by hostname

    ssh = _by_pred(c for c in claims if c.subject.key == "loomnm-ssh")
    # only the open port (2222) became a service; the closed 80/5432 did not
    services = {c.object for c in ssh["runs_service"]}
    assert services == {"tcp/2222"}
    assert {c.object for c in ssh["listens_on_port"]} == {2222}
    assert ssh["runs_service"][0].attrs["state"] == "open"
    # runs_software keyed vendor:product from the CPE, the vuln-graph node
    sw = {c.object.key: c for c in ssh["runs_software"]}
    assert "openbsd:openssh" in sw
    assert sw["openbsd:openssh"].attrs["cpe"] == "cpe:/a:openbsd:openssh:10.3"
    assert sw["openbsd:openssh"].attrs["version"] == "10.3"

    nginx = _by_pred(c for c in claims if c.subject.key == "loomnm-nginx")
    # nmap's service DB keys nginx under igor_sysoev, NOT nginx/f5 as NVD does
    # — a real entity-resolution seam, surfaced honestly (resolved by D-042)
    assert "igor_sysoev:nginx" in {c.object.key for c in nginx["runs_software"]}
    pg = _by_pred(c for c in claims if c.subject.key == "loomnm-pg")
    assert "postgresql:postgresql" in {c.object.key for c in pg["runs_software"]}


def test_product_key_normalization_matches_the_vulns_connector():
    # nmap's 2.2 URI CPE and NVD's 2.3 CPE resolve to the SAME vendor:product
    part, vendor, product = nmap.product_key_from_cpe("cpe:/a:openbsd:openssh:10.3")
    assert (part, f"{vendor}:{product}") == ("a", "openbsd:openssh")
    assert vulns.parse_cpe("cpe:2.3:a:openbsd:openssh:10.3:*:*:*:*:*:*:*") == (part, vendor, product)
    # a 2.3 CPE is handed straight to the shared parser
    assert nmap.product_key_from_cpe("cpe:2.3:a:postgresql:postgresql:16:*:*:*:*:*:*:*") == (
        "a", "postgresql", "postgresql")
    # a wildcard / empty vendor or product is no usable key
    assert nmap.product_key_from_cpe("cpe:/a:*:*") is None
    assert nmap.product_key_from_cpe("") is None


def test_os_match_is_a_lower_confidence_claim():
    envs = list(nmap.report_to_envelopes(OS_MATCH.read_text(), "netsec"))
    os_claims = [c for c in envs if isinstance(c, ClaimIn) and c.predicate == "runs_os"]
    assert len(os_claims) == 1
    os_claim = os_claims[0]
    assert os_claim.object == "Linux 4.15 - 5.19"            # the best (highest-accuracy) match
    assert os_claim.confidence < 1.0                          # below an authoritative inventory (D-035)
    assert os_claim.attrs["accuracy"] == 97
    assert os_claim.attrs["cpe"] == "cpe:/o:linux:linux_kernel:4"


def test_os_guess_conflicts_with_an_authoritative_inventory(tmp_path):
    """The scan's OS guess and an asset-inventory OS record are both current
    (append-only) — a conflict Loom surfaces, not a silent overwrite."""
    db = str(tmp_path / "osconflict.db")
    store = SqliteStore(db)
    store.record_claim(ClaimIn(namespace="netsec", subject=EntityRef(type="host", key="loomnm-nginx"),
                               predicate="runs_os", object="rhel-9", observed_at=datetime(2026, 7, 2, tzinfo=timezone.utc),
                               source="asset-inventory"))
    store.close()
    nmap.main(["import", str(OS_MATCH), "--namespace", "netsec", "--db", db])
    store = SqliteStore(db)
    try:
        rows = [o for o in store.observations_for("netsec", EntityRef(type="host", key="loomnm-nginx"))
                if o.predicate == "runs_os" and o.id not in
                {r.supersedes for r in store.observations_for("netsec", EntityRef(type="host", key="loomnm-nginx")) if r.supersedes}]
        objs = {o.object: o for o in rows}
        assert "rhel-9" in objs and "Linux 4.15 - 5.19" in objs          # both stand: a conflict
        assert objs["rhel-9"].confidence == 1.0 and objs["Linux 4.15 - 5.19"].confidence < 1.0
    finally:
        store.close()


# ------------------------------------------------------------- parse: edge cases #

OPEN_CLOSED_FILTERED = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX -" start="1790000000" startstr="Fri Sep 19 00:00:00 2026" version="7.98">
<host><status state="up"/><address addr="10.0.0.9" addrtype="ipv4"/>
<hostnames><hostname name="edge-01" type="user"/></hostnames>
<ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="23"><state state="closed"/><service name="telnet"/></port>
<port protocol="tcp" portid="443"><state state="filtered"/><service name="https"/></port>
<port protocol="udp" portid="161"><state state="open|filtered"/><service name="snmp"/></port>
</ports></host></nmaprun>"""


def test_open_closed_filtered_ports():
    envs = list(nmap.report_to_envelopes(OPEN_CLOSED_FILTERED, "netsec"))
    services = {c.object: c for c in envs if isinstance(c, ClaimIn) and c.predicate == "runs_service"}
    # only open and open|filtered survive; closed and filtered-only are dropped
    assert set(services) == {"tcp/22", "udp/161"}
    assert services["tcp/22"].attrs["state"] == "open"
    assert services["udp/161"].attrs["state"] == "open|filtered"       # attr'd, per the spec


IPV6_BARE_EMPTY = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -6 -oX -" start="1790000000" startstr="Fri Sep 19 00:00:00 2026" version="7.98">
<host><status state="up"/><address addr="fe80::1" addrtype="ipv6"/>
<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host>
<host><status state="up"/><address addr="10.0.0.50" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host>
<host><status state="up"/><address addr="10.0.0.51" addrtype="ipv4"/>
<hostnames><hostname name="quiet-01" type="user"/></hostnames>
<ports><port protocol="tcp" portid="22"><state state="closed"/></port></ports></host>
<host><status state="down"/><address addr="10.0.0.99" addrtype="ipv4"/></host>
</nmaprun>"""


def test_ipv6_bare_ip_hostname_and_empty_host():
    stats: dict = {}
    envs = list(nmap.report_to_envelopes(IPV6_BARE_EMPTY, "netsec", stats=stats))
    claims = [e for e in envs if isinstance(e, ClaimIn) and e.subject.type == "host"]
    hosts = {c.subject.key for c in claims}
    # IPv6-keyed host; bare-IPv4-keyed host (no hostname); the closed-only and
    # the down host yield nothing
    assert hosts == {"fe80::1", "10.0.0.50"}
    v6 = next(c for c in claims if c.subject.key == "fe80::1")
    assert v6.attrs["ip6"] == "fe80::1"
    bare = next(c for c in claims if c.subject.key == "10.0.0.50")
    assert bare.attrs["ip"] == "10.0.0.50" and "hostname" not in bare.attrs
    assert stats["host_empty"] == 2            # quiet-01 (closed only) + the down host


def test_reimport_is_idempotent(tmp_path):
    db = str(tmp_path / "idem.db")
    nmap.main(["import", str(INVENTORY), "--namespace", "netsec", "--db", db])
    before = sum(1 for _ in SqliteStore(db).iter_observations("netsec"))
    nmap.main(["import", str(INVENTORY), "--namespace", "netsec", "--db", db])
    after = sum(1 for _ in SqliteStore(db).iter_observations("netsec"))
    assert before == after and before > 0


def test_schema_registers_the_inventory_predicates():
    reg = nmap.schema("netsec")
    preds = {p.name for p in reg.predicates}
    assert {"listens_on_port", "runs_service", "runs_software", "runs_os"} <= preds
    sw = next(p for p in reg.predicates if p.name == "runs_software")
    assert sw.object_types == ["product"] and sw.containment is True    # fuses like the vulns edge
    assert reg.strict is False


def test_import_exits_nonzero_when_the_engine_refuses_envelopes(monkeypatch):
    """D-063 / S-36: a loader that saw any refusal must not exit 0."""
    from loom import ingest

    monkeypatch.setattr(vulns, "register", lambda *a, **k: None)

    def refusing(url, lines, size, key, timeout=60.0):
        n = sum(1 for _ in lines)
        return {"total": n, "recorded": n - 3, "accepted": 0, "rejected": 3}

    monkeypatch.setattr(ingest, "post_batches", refusing)
    with pytest.raises(SystemExit) as exc:
        nmap.main(["import", str(INVENTORY), "--namespace", "netsec", "--url", "http://loom.invalid"])
    assert exc.value.code not in (0, None)
    assert "3" in str(exc.value.code) and "refused" in str(exc.value.code)


# ---------------------------------------------------- BLIND fusion test (D-067) #

def test_scanned_host_reaches_its_products_kev_cve_cited(tmp_path):
    """The real test of "is it working": import an nmap report whose host runs
    OpenSSH, load a KEV/NVD fact for openbsd:openssh, and assert via find_path
    (D-067) that the scanned host now REACHES the product's exploited-in-wild
    CVE — with the scan claim cited on the hop. The scan and vuln data must
    fuse through the shared `product` node; if the product keys did not match
    there would be no path, and that would be the bug."""
    db = str(tmp_path / "fusion.db")
    store = SqliteStore(db)
    # a small vuln corpus for openbsd:openssh (as NVD + KEV would land it)
    product = EntityRef(type="product", key="openbsd:openssh")
    cve = EntityRef(type="cve", key="CVE-2026-77777")
    store.record_claims([
        ClaimIn(namespace="netsec", subject=cve, predicate="affects", object=product,
                observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc), source="nvd"),
        ClaimIn(namespace="netsec", subject=cve, predicate="exploited_in_wild", object=True,
                observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc), source="cisa-kev"),
    ])
    store.close()

    # the scan lands the runs_software edge onto that same product node
    nmap.main(["import", str(INVENTORY), "--namespace", "netsec", "--db", db])

    store = SqliteStore(db)
    try:
        pack = find_paths(store, PathRequest(
            namespace="netsec", **{"from": EntityRef(type="host", key="loomnm-ssh")},
            to=cve, via=["runs_software", "affects"], depth=2))
        assert pack.paths, "the scanned host must reach the KEV CVE through the shared product node"
        best = pack.paths[0]
        assert [e.predicate for e in best] == ["runs_software", "affects"]
        # the path passes through the product node both connectors write to
        keys = {(e.subject.type, e.subject.key) for e in best} | {
            (e.object.type, e.object.key) for e in best if isinstance(e.object, EntityRef)}
        assert ("product", "openbsd:openssh") in keys
        # every hop is cited, and the first hop is the SCAN claim (source nmap)
        assert all(e.cite.observation_id for e in best)
        scan_hop = best[0]
        assert scan_hop.source == "nmap" and scan_hop.subject.key == "loomnm-ssh"
    finally:
        store.close()
