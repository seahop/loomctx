"""Vulnerability connector (D-035): feed shapes -> envelopes -> a store that
answers the demo's two-hop question. Fixtures are trimmed real-feed shapes;
the live download path is exercised only with LOOM_LIVE_FEEDS=1."""

import gzip
import json
import os

import pytest

from loom.connectors import vulns
from loom.context import build_pack
from loom.contracts import AskRequest, ClaimIn, DocumentIn, EntityRef, ScopeSpec
from loom.ingest import load_direct
from loom.store.sqlite import SqliteStore

NVD_ITEM = {"cve": {
    "id": "CVE-2026-1337", "sourceIdentifier": "security@nginx.org",
    "published": "2026-01-05T10:15:00.000", "lastModified": "2026-02-01T12:00:00.000",
    "vulnStatus": "Analyzed",
    "descriptions": [{"lang": "es", "value": "no"}, {"lang": "en", "value": "Heap overflow in  nginx  " + "x" * 600}],
    "metrics": {
        "cvssMetricV31": [
            {"source": "nvd@nist.gov", "type": "Primary",
             "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N", "baseScore": 9.8, "baseSeverity": "CRITICAL"}},
            {"source": "security@nginx.org", "type": "Secondary",
             "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N", "baseScore": 7.5, "baseSeverity": "HIGH"}},
        ],
        "cvssMetricV2": [{"source": "nvd@nist.gov", "type": "Primary", "baseSeverity": "HIGH",
                          "cvssData": {"version": "2.0", "vectorString": "AV:N", "baseScore": 7.5}}],
    },
    "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary",
                    "description": [{"lang": "en", "value": "CWE-122"}, {"lang": "en", "value": "NVD-CWE-Other"}]}],
    "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", "versionEndExcluding": "1.27.4"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:nginx:nginx:1.26.0:*:*:*:*:*:*:*"},
        {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*"},
    ]}]}],
}}
REJECTED = {"cve": {"id": "CVE-2026-0002", "published": "2026-01-01T00:00:00.000",
                    "lastModified": "2026-01-02T00:00:00.000", "vulnStatus": "Rejected",
                    "descriptions": [{"lang": "en", "value": "** REJECT **"}],
                    "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
                                                   "cvssData": {"version": "3.1", "baseScore": 5.0}}]}}}
KEV_ENTRY = {"cveID": "CVE-2026-1337", "vendorProject": "Nginx", "product": "NGINX Open Source",
             "vulnerabilityName": "Nginx Heap Overflow Vulnerability", "dateAdded": "2026-03-02",
             "shortDescription": "Nginx contains a heap overflow.", "requiredAction": "Apply mitigations.",
             "dueDate": "2026-03-23", "knownRansomwareCampaignUse": "Known",
             "notes": "https://example.test/advisory", "cwes": ["CWE-122"]}
EPSS_CSV = ("#model_version:v2025.03.14,score_date:2026-09-08T00:00:00+0000\n"
            "cve,epss,percentile\nCVE-2026-1337,0.91234,0.99876\nCVE-1999-0001,0.00042,0.10000\n")


def test_nvd_mapping_one_score_per_source_and_products_from_cpes():
    claims = list(vulns.nvd_envelopes(NVD_ITEM, "netsec"))
    by_pred = {}
    for c in claims:
        by_pred.setdefault(c.predicate, []).append(c)
    assert by_pred["status"][0].object == "Analyzed"
    summary = by_pred["summary"][0]
    assert len(summary.object) == vulns.SUMMARY_CHARS and summary.attrs["truncated"]
    assert "  " not in summary.object                       # whitespace collapsed
    scores = {c.source: c.object for c in by_pred["cvss_score"]}
    assert scores == {"nvd:nvd@nist.gov": 9.8, "nvd:security@nginx.org": 7.5}   # v2 dropped for NIST
    assert {c.object for c in by_pred["has_severity"]} == {"critical", "high"}
    assert [c.object.key for c in by_pred["has_weakness"]] == ["CWE-122"]      # NVD-CWE-Other skipped
    affects = [c.object.key for c in by_pred["affects"]]
    assert affects == ["nginx:nginx"]                        # deduped, non-vulnerable CPE ignored
    assert by_pred["made_by"][0].object == EntityRef(type="vendor", key="nginx")
    assert by_pred["made_by"][0].event_id == "product:nginx:nginx:made_by"
    for c in claims:
        assert c.observed_at.isoformat().startswith("2026-02-01T12:00:00+00:00")
        if c.predicate != "made_by":
            assert c.valid_from.isoformat().startswith("2026-01-05T10:15:00+00:00")
            assert c.event_id.startswith("nvd:CVE-2026-1337:20260201T120000:")
    # a re-scored record (new lastModified) records NEW observations, an
    # unchanged one dedupes by event_id
    again = list(vulns.nvd_envelopes(NVD_ITEM, "netsec"))
    assert [c.event_id for c in again] == [c.event_id for c in claims]
    bumped = json.loads(json.dumps(NVD_ITEM))
    bumped["cve"]["lastModified"] = "2026-05-01T00:00:00.000"
    assert {c.event_id for c in vulns.nvd_envelopes(bumped, "netsec")}.isdisjoint(
        {c.event_id for c in claims if c.predicate != "made_by"})


def test_rejected_cves_keep_only_their_status():
    claims = list(vulns.nvd_envelopes(REJECTED, "netsec"))
    assert [c.predicate for c in claims] == ["status"] and claims[0].object == "Rejected"


def test_kev_mapping_flags_document_and_freehand_product_key():
    envs = list(vulns.kev_envelopes(KEV_ENTRY, "netsec"))
    claims = [e for e in envs if isinstance(e, ClaimIn)]
    docs = [e for e in envs if isinstance(e, DocumentIn)]
    preds = {c.predicate: c for c in claims}
    assert preds["exploited_in_wild"].object is True
    assert preds["exploited_in_wild"].attrs["due_date"] == "2026-03-23"
    assert preds["ransomware_campaign_use"].object == "Known"
    # KEV's freehand naming does NOT collapse onto the CPE key: that gap is
    # the entity-resolution exercise, left visible on purpose
    assert preds["affects"].object == EntityRef(type="product", key="nginx:nginx_open_source")
    assert preds["has_weakness"].object.key == "CWE-122"
    assert all(c.source == "cisa-kev" and c.observed_at.date().isoformat() == "2026-03-02" for c in claims)
    assert len(docs) == 1 and docs[0].filename == "KEV-CVE-2026-1337.txt"
    assert "heap overflow" in docs[0].text and "Required action: Apply mitigations." in docs[0].text
    assert docs[0].event_id == "kev:CVE-2026-1337:2026-03-02:doc"
    # the document comes first and every claim cites it by event id (D-039)
    assert isinstance(envs[0], DocumentIn)
    cited = [c for c in claims if c.predicate != "made_by"]           # made_by is derived, not from the text
    assert cited and all(c.provenance.artifact_event_id == docs[0].event_id for c in cited)


def test_epss_filters_to_known_cves_and_reads_the_score_date():
    known = list(vulns.epss_envelopes(EPSS_CSV.splitlines(), "netsec", {"CVE-2026-1337"}))
    assert [(c.predicate, c.object) for c in known] == [("epss_score", 0.91234), ("epss_percentile", 0.99876)]
    assert known[0].observed_at.isoformat() == "2026-09-08T00:00:00+00:00"
    assert known[0].event_id == "epss:CVE-2026-1337:2026-09-08:epss_score"
    everything = list(vulns.epss_envelopes(EPSS_CSV.splitlines(), "netsec", None))
    assert len(everything) == 4


def test_cpe_parsing_handles_escapes_and_junk():
    assert vulns.parse_cpe("cpe:2.3:a:vendor\\:inc:prod:1.0:*:*:*:*:*:*:*") == ("a", "vendor:inc", "prod")
    assert vulns.parse_cpe("cpe:2.3:a:*:prod:*") is None
    assert vulns.parse_cpe("not a cpe") is None
    assert vulns.normalize_key("  Connect Secure & Policy Secure ") == "connect_secure_policy_secure"


def test_schema_registers_the_bridge_as_containment():
    reg = vulns.schema("netsec")
    assert {t.name for t in reg.entity_types} == {"cve", "product", "vendor", "cwe"}
    by_name = {p.name: p for p in reg.predicates}
    assert by_name["affects"].object_types == ["product"] and not by_name["affects"].containment
    assert by_name["runs_software"].containment and reg.strict is False


def _write_cache(cache):
    cache.mkdir()
    (cache / "kev.json").write_text(json.dumps({"vulnerabilities": [KEV_ENTRY]}))
    with gzip.open(cache / "nvdcve-2.0-2026.json.gz", "wt") as fh:
        json.dump({"resultsPerPage": 2, "vulnerabilities": [NVD_ITEM, REJECTED]}, fh)
    with gzip.open(cache / "epss.csv.gz", "wt") as fh:
        fh.write(EPSS_CSV)


def test_stream_load_and_two_hop_question(tmp_path):
    """The dogfood path end to end: cache -> envelopes -> store; then the
    demo question 'is web-01 exposed to something actively exploited?' as a
    host -> product <- cve scope, and the real cross-scorer conflict."""
    cache = tmp_path / "feeds"
    _write_cache(cache)
    stats = {}
    envs = vulns.envelopes(cache, "netsec", [2026], {"kev", "nvd", "epss"}, "known", True, stats)
    db = tmp_path / "v.db"
    totals = load_direct(str(db), vulns.to_lines(envs), size=100)
    assert totals["skipped"] == 0 and totals["accepted"] == 1          # the KEV document
    assert stats["kev"] == 6 and stats["epss"] == 2 and stats["bridge"] == sum(map(len, vulns.SEED_SOFTWARE.values()))
    assert totals["recorded"] == sum(stats.values()) - 1

    store = SqliteStore(db)
    store.put_schema(vulns.schema("netsec"))
    cve = EntityRef(type="cve", key="CVE-2026-1337")
    pack = build_pack(store, AskRequest(namespace="netsec", subject=cve,
                                       question="how severe is this and is it exploited?", budget=1500))
    texts = [i.text for i in pack.items]
    assert any(i.kind == "conflict" and "cvss_score" in i.text and "nvd:nvd@nist.gov" in i.text
               and "nvd:security@nginx.org" in i.text for i in pack.items)
    assert any("exploited_in_wild" in t for t in texts)
    assert any("epss_score" in t for t in texts)

    # two hops from the host, following the bridge and the CVE edge
    scope = ScopeSpec(subjects=[EntityRef(type="host", key="web-01")],
                      expand=["runs_software", "affects"], depth=2)
    pack = build_pack(store, AskRequest(namespace="netsec", scope=scope,
                                       question="exploited in wild", budget=2500))
    reached = {(s.type, s.key) for s in pack.subjects}
    assert ("product", "nginx:nginx") in reached and ("cve", "CVE-2026-1337") in reached
    assert any("exploited_in_wild" in i.text for i in pack.items)
    # the default scope (no expand) follows the containment predicate only
    pack = build_pack(store, AskRequest(namespace="netsec", question="software",
                                       scope=ScopeSpec(subjects=[EntityRef(type="host", key="web-01")], depth=2),
                                       budget=1500))
    assert ("product", "nginx:nginx") in {(s.type, s.key) for s in pack.subjects}
    # loading again changes nothing
    envs = vulns.envelopes(cache, "netsec", [2026], {"kev", "nvd", "epss"}, "known", True)
    assert load_direct(str(db), vulns.to_lines(envs), size=100)["recorded"] == totals["recorded"]
    store.close()


def test_cli_emit_and_schema(tmp_path, capsys):
    cache = tmp_path / "feeds"
    _write_cache(cache)
    vulns.main(["emit", "--cache", str(cache), "--offline", "--sources", "kev"])
    out, err = capsys.readouterr()
    lines = [json.loads(l) for l in out.splitlines()]
    assert len(lines) == 6 and {l["kind"] for l in lines} == {"claim", "document"}
    assert json.loads(err)["envelopes"] == {"kev": 6}
    vulns.main(["schema"])
    assert json.loads(capsys.readouterr().out)["namespace"] == "netsec"


class _FeedResp:
    """A stubbed urlopen response: body bytes plus headers."""

    def __init__(self, body: bytes, headers: dict | None = None, fail_after: int | None = None):
        self.body, self.pos, self.fail_after = body, 0, fail_after
        import email.message
        self.headers = email.message.Message()
        for k, v in (headers or {}).items():
            self.headers[k] = v

    def read(self, n=-1):
        if self.fail_after is not None and self.pos >= self.fail_after:
            raise OSError("connection reset")
        chunk = self.body[self.pos:self.pos + n] if n and n > 0 else self.body[self.pos:]
        self.pos += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _http_error(code):
    import email.message
    import io
    import urllib.error
    return urllib.error.HTTPError("http://feed", code, "err", email.message.Message(), io.BytesIO(b""))


def _stub_feed(monkeypatch, items):
    """Each item is a response, an exception to raise, or a callable(req)."""
    seen = []

    def fake_urlopen(req, timeout=0):
        seen.append(req)
        item = items.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    monkeypatch.setattr(vulns.time, "sleep", lambda s: None)
    return seen


def test_fetch_never_caches_a_truncated_or_corrupt_body(tmp_path, monkeypatch, capsys):
    """A short gzip (connection cut, or Content-Length unmet) used to be
    renamed into place and stamped with Last-Modified, so every later run
    got a 304 and served the corrupt cache forever."""
    dest = tmp_path / "feeds" / "nvdcve-2.0-2026.json.gz"
    good = gzip.compress(json.dumps({"vulnerabilities": [NVD_ITEM]}).encode())
    stamp = "Wed, 09 Sep 2026 10:00:00 GMT"
    # 1: body shorter than Content-Length; 2: a cut-off gzip member; 3: fine
    _stub_feed(monkeypatch, [
        _FeedResp(good[:-40], {"Content-Length": str(len(good)), "Last-Modified": stamp}),
        _FeedResp(good[:-40], {"Last-Modified": stamp}),
        _FeedResp(good, {"Content-Length": str(len(good)), "Last-Modified": stamp}),
    ])
    assert vulns.fetch("http://feed", dest) == "downloaded"
    assert dest.read_bytes() == good and not dest.with_suffix(".gz.part").exists()
    assert "Content-Length said" in capsys.readouterr().err
    import email.utils
    assert abs(dest.stat().st_mtime - email.utils.parsedate_to_datetime(stamp).timestamp()) < 1   # stamped only for a valid body
    assert sum(1 for _ in vulns.iter_nvd(dest)) == 1
    # every attempt bad: no cache file appears, and the stale one is kept
    before = dest.read_bytes()
    _stub_feed(monkeypatch, [_FeedResp(b"\x1f\x8b\x08junk") for _ in range(3)])
    with pytest.raises(SystemExit, match="gzip body unreadable"):
        vulns.fetch("http://feed", dest)
    assert dest.read_bytes() == before
    # a truncated JSON feed is rejected the same way
    kev = tmp_path / "feeds" / "kev.json"
    _stub_feed(monkeypatch, [_FeedResp(b'{"vulnerabilities": [') for _ in range(3)])
    with pytest.raises(SystemExit, match="JSON body unreadable"):
        vulns.fetch("http://feed", kev)
    assert not kev.exists()
    # a connection dropped mid-body is retried
    _stub_feed(monkeypatch, [_FeedResp(good, fail_after=0), _FeedResp(good)])
    assert vulns.fetch("http://feed", dest) == "downloaded"


def test_fetch_retries_transient_failures_and_honours_304(tmp_path, monkeypatch):
    import urllib.error
    dest = tmp_path / "feeds" / "kev.json"
    body = json.dumps({"vulnerabilities": [KEV_ENTRY]}).encode()
    seen = _stub_feed(monkeypatch, [_http_error(503), urllib.error.URLError("dns"), _FeedResp(body)])
    assert vulns.fetch("http://feed", dest) == "downloaded" and len(seen) == 3
    assert "If-Modified-Since" not in seen[0].headers
    seen = _stub_feed(monkeypatch, [_http_error(304)])
    assert vulns.fetch("http://feed", dest) == "cached" and seen[0].get_header("If-modified-since")
    seen = _stub_feed(monkeypatch, [_http_error(429), _http_error(500), _http_error(502)])
    with pytest.raises(SystemExit, match="HTTP 502 .after 3 attempts"):
        vulns.fetch("http://feed", dest)
    assert len(seen) == 3
    seen = _stub_feed(monkeypatch, [_http_error(404)])
    with pytest.raises(SystemExit, match="HTTP 404"):
        vulns.fetch("http://feed", dest)
    assert len(seen) == 1                                                # not retried
    assert vulns.validate_download(dest) is None


def test_load_without_url_or_db_uses_the_environment_store(tmp_path, monkeypatch, capsys):
    """--db is an explicit override that bypasses LOOM_SHARDS / LOOM_BLOB_*;
    without it (and without --url) the connector writes where the engine
    reads: the store LOOM_DB and friends configure."""
    cache = tmp_path / "feeds"
    _write_cache(cache)
    monkeypatch.setenv("LOOM_DB", str(tmp_path / "env.db"))
    monkeypatch.delenv("LOOM_SHARDS", raising=False)
    vulns.main(["load", "--cache", str(cache), "--offline", "--sources", "kev"])
    out = capsys.readouterr().out
    assert json.loads(out.splitlines()[-1])["recorded"] == 5
    store = SqliteStore(tmp_path / "env.db")
    assert store.get_schema("netsec") is not None
    assert store.count_observations("netsec", EntityRef(type="cve", key="CVE-2026-1337")) >= 3
    store.close()


@pytest.mark.skipif(not os.environ.get("LOOM_LIVE_FEEDS"), reason="set LOOM_LIVE_FEEDS=1 to hit the real feeds")
def test_live_pull_is_conditional(tmp_path):
    cache = tmp_path / "feeds"
    first = vulns.pull(cache, [], {"kev"})
    second = vulns.pull(cache, [], {"kev"})
    assert first == {"kev": "downloaded"} and second == {"kev": "cached"}
    assert sum(1 for _ in vulns.iter_kev(cache / "kev.json")) > 1000


def test_kev_advisory_ranks_as_an_excerpt_for_its_cve(tmp_path):
    """D-039 end to end: the KEV claims cite their advisory, the worker
    chunks it, and the CVE's pack carries the advisory's own words."""
    from loom.enrich import chunk_artifacts
    from loom.llm import HashingEmbedder
    cache = tmp_path / "feeds"
    _write_cache(cache)
    db = tmp_path / "x.db"
    load_direct(str(db), vulns.to_lines(vulns.envelopes(cache, "netsec", [2026], {"kev"})), size=100)
    store = SqliteStore(db)
    cve = EntityRef(type="cve", key="CVE-2026-1337")
    kev_obs = [o for o in store.observations_for("netsec", cve) if o.source == "cisa-kev"]
    assert kev_obs and all(o.provenance and o.provenance.artifact_id for o in kev_obs)
    embedder = HashingEmbedder()
    assert chunk_artifacts(store, embedder, limit=10) >= 1
    pack = build_pack(store, AskRequest(namespace="netsec", subject=cve, budget=1500,
                                       question="what is the required action?"), embedder=embedder)
    excerpts = [i for i in pack.items if i.kind == "doc_excerpt"]
    assert excerpts and "Required action" in excerpts[0].text and excerpts[0].citations[0].artifact_id
    store.close()
