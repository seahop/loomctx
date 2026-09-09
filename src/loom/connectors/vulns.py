"""Vulnerability intelligence connector (D-035): CISA KEV + NVD + EPSS → Loom.

Three public feeds, no API keys, one command:

    python -m loom.connectors.vulns load --db /data/loom.db                # pull + load
    python -m loom.connectors.vulns load --url http://loom:8000 --key ...  # via the batch API
    python -m loom.connectors.vulns emit > vulns.jsonl                     # NDJSON, load later
    python -m loom.connectors.vulns pull                                   # refresh the cache only
    python -m loom.connectors.vulns schema                                 # the registry it declares

What each source contributes (all into ONE namespace, `netsec` by default,
so the facts join the seed hosts):

  * NVD 2.0 yearly feeds (`--years`): per CVE — status, a trimmed summary,
    one `cvss_score` + `has_severity` per *scoring source* (NIST and the CNA
    routinely disagree, so real cross-source conflicts surface, uninvented),
    `has_weakness` -> cwe, `affects` -> product parsed from vulnerable CPEs,
    `made_by` product -> vendor. Streamed with ijson: the feeds are 25 MB
    gzipped / ~300 MB JSON each and never fully in memory.
  * CISA KEV: `exploited_in_wild`, `ransomware_campaign_use`, `affects`
    (KEV names vendors/products freehand — "Microsoft"/"Windows" vs the CPE's
    microsoft:windows_10 — which is exactly the entity-resolution mess a
    demo should show honestly), plus one *document* per entry (the advisory
    text) so excerpt retrieval has something real to cite.
  * FIRST EPSS: `epss_score` / `epss_percentile` for the CVEs already
    present (300k orphan CVE rows would drown the namespace; `--epss all`
    if you want them).

`--bridge-seed-hosts` adds `runs_software` claims from the seed hosts to
common products (kernel, nginx, openssh, postgresql, chrome, ...) so the
demo question becomes a two-hop traversal: host -> product <- cve, KEV-flagged.

Every envelope carries a deterministic event_id that includes the record's
own modification stamp: re-running is idempotent, and a *changed* record
(NVD re-scores constantly) records a NEW observation — the corpus gains
history over time instead of being overwritten. Run it on a schedule
(deploy/k8s/jobs/vulns-refresh.yaml) and `as_of` questions become real.
"""

from __future__ import annotations

import argparse
import csv
import email.utils
import gzip
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Iterator

from ..contracts import (ClaimIn, DocumentIn, EntityRef, EntityTypeDef,
                         PredicateDef, Provenance, SchemaRegistration)

FEEDS = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "nvd": "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz",
    "epss": "https://epss.cyentia.com/epss_scores-current.csv.gz",
}
USER_AGENT = "loom-connector/0.1 (+https://github.com/seahop/Loom)"
DEFAULT_CACHE = os.environ.get("LOOM_FEED_CACHE", "/data/feeds")
SUMMARY_CHARS = 400
SOURCE_NVD = "nvd"
SOURCE_KEV = "cisa-kev"
SOURCE_EPSS = "first-epss"
SOURCE_BRIDGE = "asset-inventory"

# Products the seed hosts plausibly run, keyed the way NVD CPEs key them
# (vendor:product). Chosen for CVE volume so the joins are never empty.
SEED_SOFTWARE = {
    # nginx is filed as nginx:nginx historically and f5:nginx_open_source since
    # the F5 era; curl as haxx:curl — one product, two keys, a resolution
    # exercise the demo should not hide
    "web-01": ["linux:linux_kernel", "nginx:nginx", "f5:nginx_open_source", "openssl:openssl", "openbsd:openssh"],
    "web-02": ["linux:linux_kernel", "nginx:nginx", "f5:nginx_open_source", "openssl:openssl", "openbsd:openssh"],
    "web-03": ["linux:linux_kernel", "apache:http_server", "openssl:openssl", "openbsd:openssh"],
    "db-01": ["linux:linux_kernel", "postgresql:postgresql", "openbsd:openssh", "redhat:enterprise_linux"],
    "db-02": ["linux:linux_kernel", "postgresql:postgresql", "openbsd:openssh", "redhat:enterprise_linux"],
    "vpn-01": ["openbsd:openbsd", "wireguard:wireguard"],
    "laptop-17": ["linux:linux_kernel", "google:chrome", "mozilla:firefox", "haxx:curl", "curl:curl"],
}


# ------------------------------------------------------------------- schema #

def schema(namespace: str) -> SchemaRegistration:
    """The registry this connector declares. Not strict: the seed's own
    types (host, user, ip, ...) share the namespace."""
    return SchemaRegistration(
        namespace=namespace,
        entity_types=[
            EntityTypeDef(name="cve", description="a CVE record (NVD id)"),
            EntityTypeDef(name="product", description="software, keyed vendor:product as in CPE 2.3"),
            EntityTypeDef(name="vendor", description="the maker of a product"),
            EntityTypeDef(name="cwe", description="a weakness class (CWE id)"),
        ],
        predicates=[
            PredicateDef(name="status", description="NVD vulnStatus"),
            PredicateDef(name="summary", description="NVD description, trimmed"),
            PredicateDef(name="cvss_score", description="CVSS base score; source names the scorer"),
            PredicateDef(name="has_severity", description="CVSS base severity (lowercase)"),
            PredicateDef(name="has_weakness", object_types=["cwe"]),
            PredicateDef(name="affects", object_types=["product"],
                         description="the CVE affects this product"),
            PredicateDef(name="made_by", object_types=["vendor"]),
            PredicateDef(name="exploited_in_wild", description="CISA KEV listing (bool)"),
            PredicateDef(name="ransomware_campaign_use", description="KEV: Known / Unknown"),
            PredicateDef(name="epss_score", description="FIRST EPSS probability of exploitation in 30 days"),
            PredicateDef(name="epss_percentile"),
            PredicateDef(name="runs_software", object_types=["product"], containment=True,
                         description="a host runs this product (scopes follow it by default)"),
        ],
    )


# ------------------------------------------------------------------- fetch #

def _http_date(ts: float) -> str:
    return email.utils.formatdate(ts, usegmt=True)


def fetch(url: str, dest: Path, timeout: float = 120.0) -> str:
    """Download `url` to `dest` unless the server says it is unchanged since
    the cached copy's mtime (which we set to its Last-Modified). Returns
    'fresh', 'cached' or 'downloaded'."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    headers = {"User-Agent": USER_AGENT}
    if dest.exists():
        headers["If-Modified-Since"] = _http_date(dest.stat().st_mtime)
    req = urllib.request.Request(url, headers=headers)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        if exc.code == 304 and dest.exists():
            return "cached"
        raise SystemExit(f"{url}: HTTP {exc.code}")
    tmp = dest.with_suffix(dest.suffix + ".part")
    with resp, open(tmp, "wb") as out:
        while chunk := resp.read(1 << 20):
            out.write(chunk)
    os.replace(tmp, dest)
    last = resp.headers.get("Last-Modified")
    if last:
        stamp = email.utils.parsedate_to_datetime(last).timestamp()
        os.utime(dest, (stamp, stamp))
    return "downloaded"


def cache_paths(cache: Path, years: list[int]) -> dict[str, Path]:
    paths = {"kev": cache / "kev.json", "epss": cache / "epss.csv.gz"}
    for year in years:
        paths[f"nvd:{year}"] = cache / f"nvdcve-2.0-{year}.json.gz"
    return paths


def pull(cache: Path, years: list[int], sources: set[str]) -> dict[str, str]:
    results = {}
    for name, path in cache_paths(cache, years).items():
        kind = name.split(":")[0]
        if kind not in sources:
            continue
        url = FEEDS["nvd"].format(year=name.split(":")[1]) if kind == "nvd" else FEEDS[kind]
        t0 = time.monotonic()
        results[name] = fetch(url, path)
        print(f"{name}: {results[name]} ({path.stat().st_size / 1e6:.1f} MB, {time.monotonic() - t0:.1f}s)",
              file=sys.stderr)
    return results


# --------------------------------------------------------------------- map #

def _utc(text: str) -> datetime:
    """NVD stamps are naive ISO in UTC ('2026-01-05T10:15:00.000'); KEV and
    EPSS give dates. Everything becomes aware UTC."""
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _stamp(dt: datetime) -> str:
    return dt.strftime("%Y%m%dT%H%M%S")


def normalize_key(text: str) -> str:
    """KEV's freehand vendor/product names -> something CPE-shaped:
    'Connect Secure' -> connect_secure. Deliberately NOT smarter than that."""
    return re.sub(r"[^a-z0-9.]+", "_", text.strip().lower()).strip("_")


def parse_cpe(criteria: str) -> tuple[str, str, str] | None:
    """cpe:2.3:part:vendor:product:... -> (part, vendor, product)."""
    parts = criteria.replace("\\:", "\x00").split(":")
    if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    part, vendor, product = (p.replace("\x00", ":") for p in parts[2:5])
    if not vendor or not product or vendor == "*" or product == "*":
        return None
    return part, vendor, product


_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def _best_metric_per_source(metrics: dict) -> dict[str, dict]:
    """Newest CVSS version each scorer published. One score per source keeps
    a v4.0 and a v3.1 rating from the SAME scorer from reading as a conflict."""
    best: dict[str, dict] = {}
    for key in _METRIC_KEYS:
        for metric in metrics.get(key, []) or []:
            best.setdefault(metric.get("source", "unknown"), metric)
    return best


def _severity(metric: dict) -> str | None:
    sev = metric.get("cvssData", {}).get("baseSeverity") or metric.get("baseSeverity")
    return sev.lower() if isinstance(sev, str) else None


def nvd_envelopes(item: dict, namespace: str) -> Iterator[ClaimIn]:
    cve = item["cve"]
    cid = cve["id"]
    published = _utc(cve["published"])
    modified = _utc(cve.get("lastModified") or cve["published"])
    ref = EntityRef(type="cve", key=cid)
    prefix = f"nvd:{cid}:{_stamp(modified)}"

    def claim(pred, obj, source=SOURCE_NVD, tag="", **kw):
        return ClaimIn(namespace=namespace, event_id=f"{prefix}:{pred}{tag}"[:128],
                       subject=ref, predicate=pred, object=obj, observed_at=modified,
                       valid_from=published, source=source, **kw)

    status = cve.get("vulnStatus")
    if status:
        yield claim("status", status)
    if status == "Rejected":
        return
    for desc in cve.get("descriptions", []) or []:
        if desc.get("lang") == "en" and desc.get("value"):
            text = " ".join(desc["value"].split())
            attrs = {"truncated": True, "chars": len(text)} if len(text) > SUMMARY_CHARS else {}
            yield claim("summary", text[:SUMMARY_CHARS], attrs=attrs)
            break
    for scorer, metric in _best_metric_per_source(cve.get("metrics", {}) or {}).items():
        data = metric.get("cvssData", {})
        score = data.get("baseScore")
        tag = f":{scorer}"
        attrs = {"version": data.get("version"), "type": metric.get("type"),
                 "vector": data.get("vectorString")}
        if isinstance(score, (int, float)):
            yield claim("cvss_score", float(score), source=f"{SOURCE_NVD}:{scorer}", tag=tag, attrs=attrs)
        if sev := _severity(metric):
            yield claim("has_severity", sev, source=f"{SOURCE_NVD}:{scorer}", tag=tag,
                        attrs={"version": data.get("version")})
    seen_cwe: set[str] = set()
    for weakness in cve.get("weaknesses", []) or []:
        for desc in weakness.get("description", []) or []:
            value = desc.get("value", "")
            if value.startswith("CWE-") and value not in seen_cwe:
                seen_cwe.add(value)
                yield claim("has_weakness", EntityRef(type="cwe", key=value), tag=f":{value}",
                            source=f"{SOURCE_NVD}:{weakness.get('source', 'unknown')}")
    seen_products: set[str] = set()
    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                if not match.get("vulnerable"):
                    continue
                parsed = parse_cpe(match.get("criteria", ""))
                if not parsed:
                    continue
                part, vendor, product = parsed
                key = f"{vendor}:{product}"
                if key in seen_products:
                    continue
                seen_products.add(key)
                yield claim("affects", EntityRef(type="product", key=key), tag=f":{key}",
                            attrs={"part": part})
                yield ClaimIn(namespace=namespace, event_id=f"product:{key}:made_by"[:128],
                              subject=EntityRef(type="product", key=key), predicate="made_by",
                              object=EntityRef(type="vendor", key=vendor),
                              observed_at=modified, source=SOURCE_NVD)


def kev_envelopes(entry: dict, namespace: str) -> Iterator[ClaimIn | DocumentIn]:
    cid = entry["cveID"]
    added = _utc(entry["dateAdded"])
    ref = EntityRef(type="cve", key=cid)
    prefix = f"kev:{cid}:{added.date().isoformat()}"
    doc_event = f"{prefix}:doc"[:128]
    # the advisory text first, then the claims citing it by that event id
    # (D-039) — so the KEV entry's own words rank as excerpts for its CVE
    text = "\n".join(filter(None, [
        f"{cid}: {entry.get('vulnerabilityName', '')}".strip(),
        f"Vendor/project: {entry.get('vendorProject', '')}  Product: {entry.get('product', '')}",
        "",
        entry.get("shortDescription", ""),
        "",
        f"Required action: {entry.get('requiredAction', '')}",
        f"Due date: {entry.get('dueDate', '')}",
        f"Known ransomware campaign use: {entry.get('knownRansomwareCampaignUse', '')}",
        f"Notes: {entry.get('notes', '')}" if entry.get("notes") else "",
    ]))
    yield DocumentIn(namespace=namespace, event_id=doc_event, filename=f"KEV-{cid}.txt",
                     text=text, source=SOURCE_KEV, observed_at=added, attrs={"cve": cid})
    cites = Provenance(artifact_event_id=doc_event)

    def claim(pred, obj, tag="", **kw):
        return ClaimIn(namespace=namespace, event_id=f"{prefix}:{pred}{tag}"[:128], subject=ref,
                       predicate=pred, object=obj, observed_at=added, valid_from=added,
                       source=SOURCE_KEV, provenance=cites, **kw)

    yield claim("exploited_in_wild", True,
                attrs={"due_date": entry.get("dueDate"),
                       "required_action": (entry.get("requiredAction") or "")[:200]})
    if ransomware := entry.get("knownRansomwareCampaignUse"):
        yield claim("ransomware_campaign_use", ransomware)
    vendor = normalize_key(entry.get("vendorProject", ""))
    product = normalize_key(entry.get("product", ""))
    if vendor and product:
        key = f"{vendor}:{product}"
        yield claim("affects", EntityRef(type="product", key=key), tag=f":{key}")
        yield ClaimIn(namespace=namespace, event_id=f"product:{key}:made_by"[:128],
                      subject=EntityRef(type="product", key=key), predicate="made_by",
                      object=EntityRef(type="vendor", key=vendor), observed_at=added,
                      source=SOURCE_KEV)
    for cwe in entry.get("cwes", []) or []:
        if isinstance(cwe, str) and cwe.startswith("CWE-"):
            yield claim("has_weakness", EntityRef(type="cwe", key=cwe), tag=f":{cwe}")


def epss_envelopes(lines: Iterable[str], namespace: str,
                   known: set[str] | None) -> Iterator[ClaimIn]:
    """`known` limits output to those CVE ids; None means every row."""
    score_date = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    rows: list[str] = []
    for line in lines:
        if line.startswith("#"):
            m = re.search(r"score_date:(\d{4}-\d{2}-\d{2})", line)
            if m:
                score_date = _utc(m.group(1))
            continue
        rows.append(line)
    stamp = score_date.date().isoformat()
    for row in csv.DictReader(rows):
        cid = row.get("cve", "")
        if not cid or (known is not None and cid not in known):
            continue
        ref = EntityRef(type="cve", key=cid)
        for pred, col in (("epss_score", "epss"), ("epss_percentile", "percentile")):
            try:
                value = float(row[col])
            except (KeyError, TypeError, ValueError):
                continue
            yield ClaimIn(namespace=namespace, event_id=f"epss:{cid}:{stamp}:{pred}", subject=ref,
                          predicate=pred, object=value, observed_at=score_date, source=SOURCE_EPSS,
                          attrs={"model": "FIRST EPSS"})


def bridge_envelopes(namespace: str) -> Iterator[ClaimIn]:
    """Seed hosts -> products, stamped like the seed's own inventory facts."""
    observed = datetime(2026, 7, 3, 9, tzinfo=timezone.utc)
    for host, products in SEED_SOFTWARE.items():
        for key in products:
            yield ClaimIn(namespace=namespace, event_id=f"seed-bridge:{host}:{key}",
                          subject=EntityRef(type="host", key=host), predicate="runs_software",
                          object=EntityRef(type="product", key=key), observed_at=observed,
                          valid_from=observed, source=SOURCE_BRIDGE)


# ------------------------------------------------------------------ stream #

def iter_nvd(path: Path) -> Iterator[dict]:
    """Stream `vulnerabilities[]` from a gzipped NVD 2.0 feed without loading
    it (ijson; floats as float, not Decimal)."""
    import ijson
    with gzip.open(path, "rb") as fh:
        yield from ijson.items(fh, "vulnerabilities.item", use_float=True)


def iter_kev(path: Path) -> Iterator[dict]:
    with open(path, encoding="utf-8") as fh:
        yield from json.load(fh).get("vulnerabilities", [])


def iter_epss_lines(path: Path) -> Iterator[str]:
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            yield line.rstrip("\n")


def envelopes(cache: Path, namespace: str, years: list[int], sources: set[str],
              epss: str = "known", bridge: bool = False,
              stats: dict[str, int] | None = None) -> Iterator[ClaimIn | DocumentIn]:
    """Everything the cache holds, as envelopes, KEV first (small), then NVD,
    then EPSS for the CVEs seen, then the seed bridge."""
    stats = stats if stats is not None else {}
    paths = cache_paths(cache, years)
    known: set[str] = set()

    def count(kind: str, env):
        stats[kind] = stats.get(kind, 0) + 1
        return env

    if "kev" in sources and paths["kev"].exists():
        for entry in iter_kev(paths["kev"]):
            known.add(entry["cveID"])
            for env in kev_envelopes(entry, namespace):
                yield count("kev", env)
    if "nvd" in sources:
        for year in years:
            path = paths[f"nvd:{year}"]
            if not path.exists():
                continue
            for item in iter_nvd(path):
                known.add(item["cve"]["id"])
                for env in nvd_envelopes(item, namespace):
                    yield count("nvd", env)
    if "epss" in sources and epss != "none" and paths["epss"].exists():
        for env in epss_envelopes(iter_epss_lines(paths["epss"]), namespace,
                                  None if epss == "all" else known):
            yield count("epss", env)
    if bridge:
        for env in bridge_envelopes(namespace):
            yield count("bridge", env)


def to_lines(envs: Iterable[ClaimIn | DocumentIn]) -> Iterator[str]:
    for env in envs:
        yield env.model_dump_json(exclude_none=True) + "\n"


# --------------------------------------------------------------------- CLI #

def register(reg: SchemaRegistration, url: str | None, db: str | None, key: str | None) -> None:
    if db:
        from ..store.factory import store_from_url
        store = store_from_url(db)
        try:
            store.put_schema(reg)
        finally:
            store.close()
        return
    headers = {"content-type": "application/json"}
    if key:
        headers["X-Loom-Key"] = key
    req = urllib.request.Request(url.rstrip("/") + "/v1/schemas", data=reg.model_dump_json().encode(),
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30):
            pass
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"schema registration: HTTP {exc.code}: {exc.read()[:300].decode(errors='replace')}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loom.connectors.vulns", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--cache", default=DEFAULT_CACHE, help="feed cache dir (or $LOOM_FEED_CACHE)")
    common.add_argument("--namespace", default="netsec")
    common.add_argument("--years", default=str(date.today().year),
                        help="comma-separated NVD feed years (default: this year)")
    common.add_argument("--sources", default="kev,nvd,epss", help="subset of kev,nvd,epss")
    common.add_argument("--epss", choices=["known", "all", "none"], default="known",
                        help="EPSS rows for the CVEs loaded (default), every CVE, or none")
    common.add_argument("--bridge-seed-hosts", action="store_true",
                        help="add runs_software claims from the seed hosts to common products")
    common.add_argument("--offline", action="store_true", help="never download; use the cache as is")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("pull", parents=[common], help="download / refresh the feeds into the cache")
    sub.add_parser("emit", parents=[common], help="write NDJSON envelopes to stdout")
    sub.add_parser("schema", parents=[common], help="print the schema registration")
    load = sub.add_parser("load", parents=[common], help="pull, register the schema, and ingest")
    load.add_argument("--url", help="engine or gateway base URL")
    load.add_argument("--db", help="write straight into this store")
    load.add_argument("--key", default=os.environ.get("LOOM_API_KEY"))
    load.add_argument("--batch", type=int, default=500)
    args = parser.parse_args(argv)

    cache = Path(args.cache)
    years = [int(y) for y in args.years.split(",") if y.strip()]
    sources = {s.strip() for s in args.sources.split(",") if s.strip()} & set(FEEDS)
    if args.command == "schema":
        print(schema(args.namespace).model_dump_json(indent=2))
        return
    if args.command in ("pull", "load") and not args.offline:
        pull(cache, years, sources)
    if args.command == "pull":
        return
    stats: dict[str, int] = {}
    envs = envelopes(cache, args.namespace, years, sources, args.epss, args.bridge_seed_hosts, stats)
    if args.command == "emit":
        for line in to_lines(envs):
            sys.stdout.write(line)
        print(json.dumps({"envelopes": stats}), file=sys.stderr)
        return
    if bool(args.url) == bool(args.db):
        parser.error("load: give exactly one of --url or --db")
    from ..ingest import load_direct, post_batches
    register(schema(args.namespace), args.url, args.db, args.key)
    t0 = time.monotonic()
    lines = to_lines(envs)
    totals = load_direct(args.db, lines, args.batch) if args.db else post_batches(args.url, lines, args.batch, args.key)
    elapsed = time.monotonic() - t0
    total = sum(stats.values())
    print(json.dumps({**totals, "envelopes": stats, "seconds": round(elapsed, 1),
                      "per_second": round(total / elapsed, 1) if elapsed else None}))


if __name__ == "__main__":
    main()
