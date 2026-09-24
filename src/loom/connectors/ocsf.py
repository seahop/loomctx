"""OCSF interop (hardening R-8): Vulnerability Finding (class_uid 2002) in and out.

    python -m loom.connectors.ocsf import findings.ndjson --namespace netsec               # into the LOOM_DB store
    python -m loom.connectors.ocsf import findings.ndjson --namespace netsec --url http://loom:8000 --key ...
    python -m loom.connectors.ocsf export --namespace netsec --out findings.ndjson         # cve facts as findings
    python -m loom.connectors.ocsf emit findings.ndjson --namespace netsec > envelopes.jsonl
    python -m loom.connectors.ocsf schema --namespace netsec

Import — one `vulnerability_finding` event (a scanner's, a cloud
provider's, a SIEM's) becomes claims on the affected host and the CVE
(`docs/interop.md` has the table):

  * the host is `device.hostname` / `resources[].hostname|name|uid`
    (`host:<name>`); each `vulnerabilities[].cve.uid` is `cve:<id>` — the
    entity the KEV/NVD connector and the STIX importer also write to;
  * `host affected_by cve` with valid_from = first_seen_time, valid_to =
    last_seen_time when the finding is resolved (status_id 4) or closed
    (activity_id 3) — NOT when it is suppressed (3: muted, still present)
    — and the finding's uid, title, status and severity in attrs. `import`
    chains the versions of one finding (connectors/chain.py): each new
    event's `affected_by` supersedes the previous one (D-050), so a
    resolution closes the exposure instead of sitting next to the stale
    open row, and a re-scan does not pile up open rows;
  * on the CVE: `cvss_score` + `has_severity` per CVSS entry (source
    `<product>:cvss<version>`), `epss_score` / `epss_percentile`,
    `summary` (cve.desc), `exploit_available` / `fix_available`, and
    `affects` -> `product:<vendor:name>` from affected_packages;
  * `observed_at` is the event `time` (epoch ms), `source` the reporting
    product (`metadata.product.name`, normalized), and every event_id
    embeds the finding uid + time, so replays dedupe and a re-scan records
    new observations.

Export — `observations_to_findings` turns Loom's cve-shaped observations
(the vulns connector's, the STIX importer's, a scanner's) back into
`vulnerability_finding` records, one per (host, cve) pair — or per CVE
with no host — with cvss/epss/severity/exploit flags gathered from the
CVE's scalar facts and every contributing observation id listed under
`unmapped.loom_observation_ids` for citation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

from ..contracts import (ClaimIn, DocumentIn, EntityRef, EntityTypeDef, Observation,
                         PredicateDef, SchemaRegistration)

CLASS_UID = 2002
CATEGORY_UID = 2
CLASS_NAME = "Vulnerability Finding"
CATEGORY_NAME = "Findings"
OCSF_VERSION = "1.3.0"
SOURCE_DEFAULT = "ocsf"
PRODUCT_NAME = "Loom"
PRED_AFFECTED = "affected_by"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

SEVERITY = {0: "unknown", 1: "informational", 2: "low", 3: "medium", 4: "high", 5: "critical",
            6: "fatal", 99: "other"}
SEVERITY_ID = {"informational": 1, "info": 1, "low": 2, "medium": 3, "moderate": 3, "high": 4,
               "critical": 5, "fatal": 6}
# Finding status_id (OCSF 1.x): Suppressed means an operator muted the
# finding (accepted risk, false positive, snoozed) — the host is still
# affected, so it never closes the exposure. Resolved does; so does a Close
# activity unless the status says suppressed. Archived/Deleted are record
# housekeeping, not remediation.
STATUS = {0: "unknown", 1: "new", 2: "in progress", 3: "suppressed", 4: "resolved",
          5: "archived", 6: "deleted", 99: "other"}
CLOSED_STATUS_IDS = {4}
SUPPRESSED = 3
ACTIVITY = {0: "unknown", 1: "create", 2: "update", 3: "close", 99: "other"}
ACTIVITY_CLOSE = 3


# ------------------------------------------------------------------ helpers #

def _epoch(value: Any) -> datetime | None:
    """OCSF times are epoch milliseconds (an ISO string is tolerated)."""
    if value is None:
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = float(value) / (1000.0 if value > 1e11 else 1.0)
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    if isinstance(value, str) and value:
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return None


def _ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def _stamp(dt: datetime) -> str:
    return dt.strftime("%Y%m%dT%H%M%S")


def normalize_key(text: str) -> str:
    return re.sub(r"[^a-z0-9.]+", "_", text.strip().lower()).strip("_")


def host_of(event: dict) -> str | None:
    device = event.get("device") or {}
    for value in (device.get("hostname"), device.get("name"), device.get("uid")):
        if value:
            return str(value)
    for res in event.get("resources") or []:
        if not isinstance(res, dict):
            continue
        for value in (res.get("hostname"), res.get("name"), res.get("uid")):
            if value:
                return str(value)
    ip = device.get("ip")
    return str(ip) if ip else None


def source_of(event: dict) -> str:
    product = (event.get("metadata") or {}).get("product") or {}
    name = product.get("name") or product.get("vendor_name")
    return normalize_key(str(name)) if name else SOURCE_DEFAULT


def finding_uid(event: dict) -> str:
    info = event.get("finding_info") or {}
    uid = info.get("uid") or (event.get("metadata") or {}).get("uid")
    if uid:
        return str(uid)
    digest = hashlib.sha256(json.dumps(event, sort_keys=True, default=str).encode()).hexdigest()[:16]
    return f"sha256:{digest}"


def _int(value: Any) -> int:
    """An OCSF enum id; real producers send "4" as often as 4, and an
    unreadable one is 0 (Unknown) rather than a crashed import."""
    if isinstance(value, bool):
        return 0
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def closes_exposure(event: dict) -> bool:
    status_id = _int(event.get("status_id"))
    if status_id == SUPPRESSED:
        return False
    return status_id in CLOSED_STATUS_IDS or _int(event.get("activity_id")) == ACTIVITY_CLOSE


def _float(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# ------------------------------------------------------------------- import #

def event_to_envelopes(event: dict, namespace: str, source: str | None = None) -> Iterator[ClaimIn]:
    """Claims for one vulnerability_finding event. Other classes yield nothing."""
    if _int(event.get("class_uid")) != CLASS_UID:
        return
    info = event.get("finding_info") or {}
    observed = (_epoch(event.get("time")) or _epoch(info.get("modified_time"))
                or _epoch(info.get("created_time")) or _epoch((event.get("metadata") or {}).get("logged_time"))
                or datetime.now(timezone.utc))
    src = source or source_of(event)
    uid = finding_uid(event)
    prefix = f"ocsf:{uid}:{_stamp(observed)}"
    host = host_of(event)
    status_id = _int(event.get("status_id"))
    severity_id = _int(event.get("severity_id"))
    first_seen = _epoch(info.get("first_seen_time")) or _epoch(info.get("created_time"))
    last_seen = _epoch(info.get("last_seen_time"))
    closed = closes_exposure(event)
    base_attrs = {"finding_uid": uid, "ocsf_class_uid": CLASS_UID}

    def claim(subject: EntityRef, pred: str, obj, tag: str = "", **kw) -> ClaimIn:
        attrs = {**base_attrs, **kw.pop("attrs", {})}
        return ClaimIn(namespace=namespace, event_id=f"{prefix}:{pred}{tag}"[:128], subject=subject,
                       predicate=pred, object=obj, observed_at=observed, source=src, attrs=attrs, **kw)

    for vuln in event.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        cve = vuln.get("cve") or {}
        cid = str(cve.get("uid") or "").upper()
        if not CVE_RE.match(cid):
            continue
        ref = EntityRef(type="cve", key=cid)
        tag = f":{cid}"
        v_first = _epoch(vuln.get("first_seen_time")) or first_seen
        v_last = _epoch(vuln.get("last_seen_time")) or last_seen
        if host:
            attrs = {"title": (info.get("title") or vuln.get("title") or "")[:200],
                     "status": event.get("status") or STATUS.get(status_id, "unknown"),
                     "status_id": status_id,
                     "severity": event.get("severity") or SEVERITY.get(severity_id, "unknown"),
                     "severity_id": severity_id}
            for flag in ("is_exploit_available", "is_fix_available"):
                if vuln.get(flag) is not None:
                    attrs[flag] = bool(vuln[flag])
            yield claim(EntityRef(type="host", key=host), PRED_AFFECTED, ref, tag, attrs=attrs,
                        valid_from=v_first, valid_to=(v_last or observed) if closed else None)
        for i, metric in enumerate(cve.get("cvss") or []):
            if not isinstance(metric, dict):
                continue
            version = str(metric.get("version") or "").strip()
            scorer = f"{src}:cvss{version}" if version else f"{src}:cvss"
            attrs = {"version": version or None, "vector": metric.get("vector_string")}
            score = _float(metric.get("base_score"))
            if score is not None:
                yield ClaimIn(namespace=namespace, event_id=f"{prefix}:cvss_score{tag}:{i}"[:128], subject=ref,
                              predicate="cvss_score", object=score, observed_at=observed, source=scorer,
                              attrs={**base_attrs, **attrs})
            sev = metric.get("severity")
            if isinstance(sev, str) and sev:
                yield ClaimIn(namespace=namespace, event_id=f"{prefix}:has_severity{tag}:{i}"[:128], subject=ref,
                              predicate="has_severity", object=sev.lower(), observed_at=observed, source=scorer,
                              attrs={**base_attrs, "version": version or None})
        epss = cve.get("epss") or {}
        for pred, col in (("epss_score", "score"), ("epss_percentile", "percentile")):
            value = _float(epss.get(col))
            if value is not None:
                yield claim(ref, pred, value, tag, attrs={"model": epss.get("version") or "EPSS"})
        desc = cve.get("desc") or vuln.get("desc")
        if isinstance(desc, str) and desc.strip():
            text = " ".join(desc.split())
            yield claim(ref, "summary", text[:400], tag, attrs={"truncated": len(text) > 400})
        for flag, pred in (("is_exploit_available", "exploit_available"), ("is_fix_available", "fix_available")):
            if vuln.get(flag) is not None:
                yield claim(ref, pred, bool(vuln[flag]), tag)
        for j, pkg in enumerate(vuln.get("affected_packages") or []):
            if not isinstance(pkg, dict) or not pkg.get("name"):
                continue
            vendor = normalize_key(str(pkg.get("vendor_name") or pkg.get("vendor") or "unknown"))
            key = f"{vendor}:{normalize_key(str(pkg['name']))}"
            yield claim(ref, "affects", EntityRef(type="product", key=key), f"{tag}:{j}",
                        attrs={"version": pkg.get("version"), "fixed_in": pkg.get("fixed_in_version")})


def events_to_envelopes(events: Iterable[dict], namespace: str, source: str | None = None,
                        stats: dict[str, int] | None = None) -> Iterator[ClaimIn]:
    stats = stats if stats is not None else {}
    for event in events:
        if not isinstance(event, dict):
            stats["skipped"] = stats.get("skipped", 0) + 1
            continue
        try:
            # materialized per event: a malformed one (a future `time`, a
            # field of the wrong shape) is counted, not the end of the import
            envs = list(event_to_envelopes(event, namespace, source))
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            stats["invalid"] = stats.get("invalid", 0) + 1
            print(f"ocsf event {finding_uid(event) if isinstance(event, dict) else '?'}: skipped: "
                  f"{str(exc).splitlines()[0][:200]}", file=sys.stderr)
            continue
        n = len(envs)
        yield from envs
        kind = "finding" if n else ("other_class" if _int(event.get("class_uid")) != CLASS_UID else "empty")
        stats[kind] = stats.get(kind, 0) + 1


def iter_events(path: str) -> Iterator[dict]:
    """NDJSON (one event per line), a JSON array, or a single object —
    pretty-printed or not (a pretty-printed object used to be read as
    NDJSON and fail on its first line)."""
    fh = sys.stdin if path == "-" else open(path, encoding="utf-8")
    with fh:
        text = fh.read()
    stripped = text.strip()
    if stripped.startswith(("[", "{")):
        try:
            whole = json.loads(stripped)
        except ValueError:
            whole = None          # several objects: NDJSON, read below
        if isinstance(whole, list):
            yield from whole
            return
        if isinstance(whole, dict):
            yield whole
            return
    for line in text.splitlines():
        if line.strip():
            yield json.loads(line)


# ------------------------------------------------------------------- export #

def observations_to_findings(observations: Iterable[Observation], namespace: str,
                             now: datetime | None = None) -> list[dict]:
    """vulnerability_finding records: one per (host, cve) `affected_by`
    edge, plus one per CVE that has facts but no host."""
    now = now or datetime.now(timezone.utc)
    facts: dict[str, list[Observation]] = {}        # cve id -> scalar/relational facts about it
    edges: dict[tuple[str, str], list[Observation]] = {}
    for obs in observations:
        if obs.attrs.get("redacted"):
            continue
        if obs.subject.type == "cve":
            facts.setdefault(obs.subject.key, []).append(obs)
        if isinstance(obs.object, EntityRef) and obs.object.type == "cve" and obs.subject.type != "cve":
            edges.setdefault((obs.subject.key, obs.object.key), []).append(obs)
            facts.setdefault(obs.object.key, [])

    def newest(cid: str, predicate: str) -> Observation | None:
        rows = [o for o in facts.get(cid, []) if o.predicate == predicate and not isinstance(o.object, EntityRef)]
        return max(rows, key=lambda o: o.observed_at) if rows else None

    def cve_block(cid: str) -> tuple[dict, int, list[str]]:
        cited: list[str] = []
        cve: dict[str, Any] = {"uid": cid}
        cvss = []
        per_source: dict[str, Observation] = {}
        for o in facts.get(cid, []):
            if o.predicate == "cvss_score" and isinstance(o.object, (int, float)):
                prev = per_source.get(o.source)
                if prev is None or o.observed_at >= prev.observed_at:
                    per_source[o.source] = o
        for o in per_source.values():
            entry = {"base_score": float(o.object)}
            if o.attrs.get("version"):
                entry["version"] = str(o.attrs["version"])
            if o.attrs.get("vector"):
                entry["vector_string"] = str(o.attrs["vector"])
            cvss.append(entry)
            cited.append(o.id)
        if cvss:
            cve["cvss"] = cvss
        sev = newest(cid, "has_severity")
        severity_id = 0
        if sev is not None:
            severity_id = SEVERITY_ID.get(str(sev.object).lower(), 0)
            cited.append(sev.id)
            for entry in cvss:
                entry.setdefault("severity", str(sev.object).capitalize())
        epss = {}
        for pred, col in (("epss_score", "score"), ("epss_percentile", "percentile")):
            o = newest(cid, pred)
            if o is not None and isinstance(o.object, (int, float)):
                epss[col] = float(o.object)
                cited.append(o.id)
        if epss:
            cve["epss"] = epss
        summary = newest(cid, "summary")
        if summary is not None:
            cve["desc"] = str(summary.object)
            cited.append(summary.id)
        vuln: dict[str, Any] = {"cve": cve, "title": cid}
        for pred, flag in (("exploited_in_wild", "is_exploit_available"), ("exploit_available", "is_exploit_available"),
                           ("fix_available", "is_fix_available")):
            o = newest(cid, pred)
            if o is not None and isinstance(o.object, bool) and flag not in vuln:
                vuln[flag] = o.object
                cited.append(o.id)
        packages = []
        for o in facts.get(cid, []):
            if o.predicate == "affects" and isinstance(o.object, EntityRef) and o.object.type == "product":
                vendor, _, name = o.object.key.partition(":")
                packages.append({"name": name or vendor, "vendor_name": vendor if name else None})
                cited.append(o.id)
        if packages:
            vuln["affected_packages"] = packages
        return vuln, severity_id, cited

    def finding(host: str | None, cid: str, edge: Observation | None) -> dict:
        vuln, severity_id, cited = cve_block(cid)
        at = edge.observed_at if edge else max((o.observed_at for o in facts.get(cid, [])), default=now)
        status_id = 1
        if edge is not None:
            cited.insert(0, edge.id)
            recorded = _int(edge.attrs.get("status_id"))
            if edge.valid_to is not None and recorded not in (4, 5, 6):
                status_id = 4                      # closed (a Close activity): resolved
            elif recorded in STATUS and recorded:
                status_id = recorded               # suppressed / in progress survive the round trip
            if edge.attrs.get("severity_id"):
                severity_id = severity_id or int(edge.attrs["severity_id"])
            for flag in ("is_exploit_available", "is_fix_available"):
                if edge.attrs.get(flag) is not None and flag not in vuln:
                    vuln[flag] = bool(edge.attrs[flag])
        info: dict[str, Any] = {"uid": edge.id if edge else f"loom:{namespace}:cve:{cid}",
                                "title": f"{cid} on {host}" if host else cid}
        if edge is not None:
            if edge.valid_from:
                info["first_seen_time"] = _ms(edge.valid_from)
            if edge.valid_to:
                info["last_seen_time"] = _ms(edge.valid_to)
        record = {
            "activity_id": 1, "activity_name": ACTIVITY[1],
            "category_uid": CATEGORY_UID, "category_name": CATEGORY_NAME,
            "class_uid": CLASS_UID, "class_name": CLASS_NAME,
            "type_uid": CLASS_UID * 100 + 1, "type_name": f"{CLASS_NAME}: Create",
            "severity_id": severity_id, "severity": SEVERITY[severity_id].capitalize(),
            "status_id": status_id, "status": STATUS[status_id].capitalize(),
            "time": _ms(at),
            "metadata": {"version": OCSF_VERSION, "product": {"name": PRODUCT_NAME, "vendor_name": PRODUCT_NAME},
                         "logged_time": _ms(now)},
            "finding_info": info,
            "vulnerabilities": [vuln],
            "unmapped": {"loom_namespace": namespace, "loom_observation_ids": cited,
                         "loom_sources": sorted({o.source for o in facts.get(cid, [])} | ({edge.source} if edge else set()))},
        }
        if host:
            record["resources"] = [{"name": host, "type": "host"}]
            record["device"] = {"hostname": host, "type_id": 0}
        return record

    findings = []
    hosted: set[str] = set()
    for (host, cid), rows in sorted(edges.items()):
        edge = max(rows, key=lambda o: o.observed_at)
        hosted.add(cid)
        findings.append(finding(host, cid, edge))
    for cid in sorted(facts):
        if cid not in hosted and facts[cid]:
            findings.append(finding(None, cid, None))
    return findings


# ------------------------------------------------------------------- schema #

def schema(namespace: str) -> SchemaRegistration:
    """Not strict; the predicate names coincide with the vulns connector's
    so OCSF, NVD/KEV and STIX facts about one CVE read as one record."""
    return SchemaRegistration(
        namespace=namespace,
        entity_types=[
            EntityTypeDef(name="host", description="an asset a finding names (device / resources)"),
            EntityTypeDef(name="cve", description="a CVE record (vulnerabilities[].cve.uid)"),
            EntityTypeDef(name="product", description="software, keyed vendor:product"),
        ],
        predicates=[
            PredicateDef(name=PRED_AFFECTED, object_types=["cve"],
                         description="OCSF vulnerability_finding: the host has this CVE; attrs carry the "
                                     "finding uid, status and severity"),
            PredicateDef(name="cvss_score", description="CVSS base score; source names the scorer"),
            PredicateDef(name="has_severity", description="CVSS base severity (lowercase)"),
            PredicateDef(name="epss_score"), PredicateDef(name="epss_percentile"),
            PredicateDef(name="summary", description="cve.desc, trimmed"),
            PredicateDef(name="exploit_available", description="vulnerabilities[].is_exploit_available"),
            PredicateDef(name="fix_available", description="vulnerabilities[].is_fix_available"),
            PredicateDef(name="affects", object_types=["product"], description="affected_packages"),
        ],
    )


# ---------------------------------------------------------------------- CLI #

def _to_lines(envs: Iterable[ClaimIn | DocumentIn]) -> Iterator[str]:
    for env in envs:
        yield env.model_dump_json(exclude_none=True) + "\n"


def _open_store(db: str | None):
    from ..store.factory import store_from_env, store_from_url
    return store_from_url(db) if db else store_from_env()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loom.connectors.ocsf", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--namespace", default="netsec")
    sub = parser.add_subparsers(dest="command", required=True)
    imp = sub.add_parser("import", parents=[common], help="map vulnerability_finding events and ingest them")
    imp.add_argument("events", help="NDJSON / JSON array of OCSF events, or - for stdin")
    imp.add_argument("--url", help="engine or gateway base URL (default: write straight into the store)")
    imp.add_argument("--db", help="write straight into this explicit store URL/path")
    imp.add_argument("--key", default=os.environ.get("LOOM_API_KEY"))
    imp.add_argument("--source", help="override the source (default: metadata.product.name)")
    imp.add_argument("--batch", type=int, default=500)
    imp.add_argument("--no-schema", action="store_true", help="skip the registry registration")
    emit = sub.add_parser("emit", parents=[common], help="write NDJSON envelopes to stdout")
    emit.add_argument("events")
    emit.add_argument("--source")
    exp = sub.add_parser("export", parents=[common], help="write the namespace's CVE facts as findings")
    exp.add_argument("--out", required=True, help="NDJSON path, or - for stdout")
    exp.add_argument("--db", help="read this explicit store URL/path (default: LOOM_DB / LOOM_SHARDS)")
    sub.add_parser("schema", parents=[common], help="print the schema registration")
    args = parser.parse_args(argv)

    if args.command == "schema":
        print(schema(args.namespace).model_dump_json(indent=2))
        return
    if args.command == "export":
        store = _open_store(args.db)
        try:
            findings = observations_to_findings(store.iter_observations(args.namespace), args.namespace)
        finally:
            store.close()
        text = "".join(json.dumps(record) + "\n" for record in findings)
        if args.out == "-":
            sys.stdout.write(text)
        else:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text)
        print(json.dumps({"findings": len(findings), "out": args.out}), file=sys.stderr)
        return
    stats: dict[str, int] = {}
    envs = events_to_envelopes(iter_events(args.events), args.namespace, args.source, stats)
    if args.command == "emit":
        for line in _to_lines(envs):
            sys.stdout.write(line)
        print(json.dumps({"events": stats}), file=sys.stderr)
        return
    if args.url and args.db:
        parser.error("import: give --url or --db, not both")
    from .chain import HttpSink, StoreSink, keyed_by, load_chained
    from .vulns import register
    if not args.no_schema:
        register(schema(args.namespace), args.url, args.db, args.key)
    # each finding's affected_by versions are chained by supersession, so
    # a resolved finding closes the exposure (connectors/chain.py)
    key = keyed_by("finding_uid", {PRED_AFFECTED})
    if args.url:
        totals = load_chained(envs, HttpSink(args.url, args.key), key, args.batch)
    else:
        store = _open_store(args.db)
        try:
            totals = load_chained(envs, StoreSink(store), key, args.batch)
        finally:
            store.close()
    print(json.dumps({**totals, "events": stats}))


if __name__ == "__main__":
    main()
