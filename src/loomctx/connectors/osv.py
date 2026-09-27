"""OSV / GHSA advisory interop (D-070): OSV JSON records in, cited claims out.

    python -m loomctx.connectors.osv import advisory.json --namespace netsec              # into the LOOMCTX_DB store
    python -m loomctx.connectors.osv import ./osv-dir --namespace netsec                   # every *.json under a dir
    python -m loomctx.connectors.osv import advisory.json --namespace netsec --url http://loomctx:8000 --key ...
    python -m loomctx.connectors.osv emit advisory.json --namespace netsec > envelopes.jsonl
    python -m loomctx.connectors.osv schema --namespace netsec                             # the registry it declares

What it is: a PARSER for the public OSV schema (https://ossf.github.io/osv-schema/)
that osv.dev, the GitHub Advisory Database (GHSA), the PyPI Advisory Database
(PYSEC), the Go vuln DB (GO-…), npm and others all publish. It reads a FILE
or a directory of files — it fetches nothing and talks to no service — and
turns each OSV record into cited, timestamped claims in `netsec` (by default),
extending the vuln picture beyond NVD/KEV/EPSS.

The clean fusion is by CVE id, not by product. An OSV record has its own `id`
(`GHSA-…`, `PYSEC-…`, `GO-…`, `MAL-…`) and an `aliases` list that usually
includes the `CVE-…` id. When a CVE alias is present the advisory is keyed to
the SAME `cve:<id>` node NVD/KEV/OCSF/STIX already write to (D-035: OSV then
corroborates or CONFLICTS with NVD on one entity, not a duplicate node); the
OSV id and every alias ride in `attrs`. With no CVE alias the record is keyed
by its own id on an `advisory:<OSV-id>` node.

Per record, on that subject:
  * `cvss_score` (a float) + `has_severity` (band) computed from the record's
    `severity[]` CVSS vector, source `ghsa` (a `GHSA-…` id) or `osv` — so it
    lines up next to NVD's `cvss_score` and can disagree (D-035). CVSS v3.0 /
    v3.1 and v2.0 vectors are scored; a v4.0-only vector keeps its string in
    attrs (no numeric base score) and `has_severity` falls back to the
    record's `database_specific.severity` band.
  * `summary` (trimmed) on the subject, and the advisory itself as a DOCUMENT
    (summary + details) that every claim cites (D-039), so its own words rank
    as excerpts for the entity.
  * `published` → `valid_from`, `modified` → `observed_at` (the assertion time
    of the version being imported).

Affected packages are keyed by ECOSYSTEM + name, NOT by CPE: OSV names
`{"ecosystem": "PyPI", "name": "django"}` / `Maven:org.apache…:log4j-core`,
which is a different namespace from NVD's CPE `vendor:product`. Each is an
`affects` edge from the CVE/advisory to a `package:<ecosystem>:<name>` entity
(a new, non-strict entity type) with the affected version ranges in attrs.
The connector does NOT try to fold a `package` onto a CPE `product`: that
vendor/name reconciliation is entity-resolution's job (D-042), and forcing it
would be wrong. So an OSV `affects → package:PyPI:django` and an NVD
`affects → product:djangoproject:django` sit on one CVE as two honest,
un-reconciled edges — the package-vs-CPE seam, surfaced, not hidden.

`observed_at` is the record's `modified` stamp and every event id embeds it,
so re-importing a file is a no-op and a REVISED record (a later `modified`)
records a new observation — history, not overwrite. Source label `ghsa` /
`osv` (`--source` overrides). The loader fails on refusals (D-063).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from ..contracts import (ClaimIn, DocumentIn, EntityRef, EntityTypeDef,
                         PredicateDef, Provenance, SchemaRegistration)

SOURCE_GHSA = "ghsa"
SOURCE_OSV = "osv"
NAMESPACE_DEFAULT = "netsec"
SUMMARY_CHARS = 400
DETAILS_CHARS = 200_000        # the document body; OSV `details` is usually small
MAX_VERSIONS = 50              # a very long `versions[]` (log4j lists dozens) is capped in attrs
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


# ------------------------------------------------------------------- CVSS #

# CVSS v3.0 / v3.1 base metric weights (identical base formula, FIRST spec).
_V3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
# CVSS v2.0 base metric weights.
_V2 = {
    "AV": {"L": 0.395, "A": 0.646, "N": 1.0},
    "AC": {"H": 0.35, "M": 0.61, "L": 0.71},
    "Au": {"M": 0.45, "S": 0.56, "N": 0.704},
    "CIA": {"N": 0.0, "P": 0.275, "C": 0.66},
}


def _parse_vector(vector: str) -> dict[str, str]:
    """The metric map from a CVSS vector string. A leading `CVSS:3.1` prefix
    (v3/v4) is dropped; v2 vectors carry none. Temporal / environmental
    metrics (E, RL, RC, …) ride along and are ignored by the base scorers."""
    metrics: dict[str, str] = {}
    for part in (vector or "").strip().split("/"):
        key, _, value = part.partition(":")
        if key and value and key != "CVSS":
            metrics[key.upper()] = value.upper()
    return metrics


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: the smallest 1-decimal number >= value (guarded
    against binary float noise so 4.0000001 does not become 4.1)."""
    return math.ceil(round(value, 5) * 10) / 10.0


def _cvss3_base(metrics: dict[str, str]) -> float | None:
    try:
        av, ac, ui = _V3["AV"][metrics["AV"]], _V3["AC"][metrics["AC"]], _V3["UI"][metrics["UI"]]
        scope = metrics["S"]
        pr = _V3["PR_C" if scope == "C" else "PR_U"][metrics["PR"]]
        c, i, a = (_V3["CIA"][metrics[k]] for k in ("C", "I", "A"))
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 6.42 * iss if scope != "C" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    if impact <= 0:
        return 0.0
    exploit = 8.22 * av * ac * pr * ui
    factor = 1.08 if scope == "C" else 1.0
    return _roundup(min(factor * (impact + exploit), 10.0))


def _cvss2_base(metrics: dict[str, str]) -> float | None:
    try:
        av, ac, au = _V2["AV"][metrics["AV"]], _V2["AC"][metrics["AC"]], _V2["Au"][metrics["AU"]]
        c, i, a = (_V2["CIA"][metrics[k]] for k in ("C", "I", "A"))
    except KeyError:
        return None
    impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a))
    exploit = 20.0 * av * ac * au
    factor = 0.0 if impact == 0 else 1.176
    return round(((0.6 * impact) + (0.4 * exploit) - 1.5) * factor, 1)


# CVSS v3 base-score severity bands (FIRST qualitative severity rating scale).
def severity_band(score: float) -> str:
    if score <= 0.0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def score_severity(entry: dict) -> tuple[float | None, str, str | None]:
    """(base score or None, cvss version label, vector) for one OSV
    `severity[]` entry. v3.0/v3.1 and v2.0 vectors are scored; a v4.0 (or
    unrecognized) vector yields no number, keeping its string for attrs."""
    stype = str(entry.get("type") or "").upper()
    vector = entry.get("score")
    if not isinstance(vector, str) or not vector:
        return None, stype.replace("CVSS_", "").replace("_", "."), None
    metrics = _parse_vector(vector)
    if stype in ("CVSS_V3", "CVSS_V30", "CVSS_V31") or vector.startswith(("CVSS:3.0", "CVSS:3.1")):
        version = "3.1" if vector.startswith("CVSS:3.1") else "3.0"
        return _cvss3_base(metrics), version, vector
    if stype in ("CVSS_V2", "CVSS_V20"):
        return _cvss2_base(metrics), "2.0", vector
    if stype == "CVSS_V4" or vector.startswith("CVSS:4.0"):
        return None, "4.0", vector            # v4 base scoring (lookup tables) not implemented
    return None, stype.replace("CVSS_", "").replace("_", "."), vector


def best_severity(record: dict) -> tuple[float | None, str | None, str | None, list[str]]:
    """The severity to score for the record — the highest scorable CVSS
    version, else a v4 vector's string — plus the score, its version, and
    every other vector seen (kept in attrs)."""
    chosen: tuple[float | None, str | None, str | None] = (None, None, None)
    order = {"3.1": 3, "3.0": 2, "2.0": 1}
    best_rank = -1
    others: list[str] = []
    for entry in record.get("severity") or []:
        if not isinstance(entry, dict):
            continue
        score, version, vector = score_severity(entry)
        rank = order.get(version or "", 0) if score is not None else 0
        if score is not None and rank > best_rank:
            if chosen[2]:
                others.append(chosen[2])
            best_rank, chosen = rank, (score, version, vector)
        elif vector and vector != chosen[2]:
            others.append(vector)
    return chosen[0], chosen[1], chosen[2], others


# ------------------------------------------------------------------ mapping #

def _utc(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _stamp(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S")


def cve_alias(record: dict) -> str | None:
    """The first `CVE-…` id among `aliases` (upper-cased), or None."""
    for alias in record.get("aliases") or []:
        if isinstance(alias, str) and CVE_RE.match(alias):
            return alias.upper()
    return None


def advisory_subject(record: dict) -> tuple[EntityRef, str | None]:
    """(the entity the advisory attaches to, the CVE id or None): the shared
    `cve:<id>` node when a CVE alias is present, else `advisory:<OSV-id>`."""
    cid = cve_alias(record)
    if cid:
        return EntityRef(type="cve", key=cid), cid
    return EntityRef(type="advisory", key=str(record["id"])), None


def source_for(osv_id: str) -> str:
    return SOURCE_GHSA if osv_id.upper().startswith("GHSA-") else SOURCE_OSV


def affected_packages(record: dict) -> dict[str, dict]:
    """`ecosystem:name` -> merged {ecosystem, name, purl, ranges, versions}
    across the record's `affected[]` (one CVE lists many version ranges of one
    package). An `affected` entry with no `package` (a bare commit range) is
    skipped — there is no ecosystem/name to key it by."""
    out: dict[str, dict] = {}
    for aff in record.get("affected") or []:
        if not isinstance(aff, dict):
            continue
        pkg = aff.get("package") or {}
        eco, name = pkg.get("ecosystem"), pkg.get("name")
        if not eco or not name:
            continue
        key = f"{eco}:{name}"
        slot = out.setdefault(key, {"ecosystem": eco, "name": name, "purl": pkg.get("purl"),
                                    "ranges": [], "versions": []})
        for rng in aff.get("ranges") or []:
            if isinstance(rng, dict) and rng not in slot["ranges"]:
                slot["ranges"].append(rng)
        for ver in aff.get("versions") or []:
            if ver not in slot["versions"]:
                slot["versions"].append(ver)
    return out


def record_to_envelopes(record: dict, namespace: str, source: str | None = None,
                        as_of: datetime | None = None,
                        mtime: datetime | None = None) -> Iterator[ClaimIn | DocumentIn]:
    """Every envelope one OSV record yields: the advisory document first, then
    the claims citing it (D-039). Raises on a record with no usable `id`."""
    osv_id = record.get("id")
    if not isinstance(osv_id, str) or not osv_id:
        raise ValueError("OSV record has no id")
    subject, _cid = advisory_subject(record)
    src = source or source_for(osv_id)
    modified = _utc(record.get("modified"))
    published = _utc(record.get("published"))
    observed = modified or published or as_of or mtime or datetime.now(timezone.utc)
    now = datetime.now(timezone.utc)
    observed = observed if observed <= now else now
    valid_from = published or observed
    stamp = _stamp(observed)
    prefix = f"osv:{osv_id}:{stamp}"
    doc_event = f"{prefix}:doc"[:128]
    cites = Provenance(artifact_event_id=doc_event)
    aliases = [a for a in (record.get("aliases") or []) if isinstance(a, str)]
    base_attrs: dict = {"osv_id": osv_id}
    if aliases:
        base_attrs["aliases"] = aliases

    # the advisory document first, so every claim can cite it by event id
    summary = record.get("summary") if isinstance(record.get("summary"), str) else ""
    details = record.get("details") if isinstance(record.get("details"), str) else ""
    title = f"{osv_id}: {summary}".strip() if summary.strip() else osv_id
    text = "\n\n".join(p for p in (title, details) if p).strip() or osv_id
    yield DocumentIn(namespace=namespace, event_id=doc_event, filename=f"{osv_id}.txt",
                     text=text[:DETAILS_CHARS], source=src, observed_at=observed, attrs=dict(base_attrs))

    def claim(pred: str, obj, tag: str = "", **kw) -> ClaimIn:
        attrs = {**base_attrs, **kw.pop("attrs", {})}
        return ClaimIn(namespace=namespace, event_id=f"{prefix}:{pred}{tag}"[:128], subject=subject,
                       predicate=pred, object=obj, observed_at=observed, valid_from=valid_from,
                       source=src, provenance=cites, attrs=attrs, **kw)

    # summary as a scalar claim on the subject
    if summary:
        flat = " ".join(summary.split())
        yield claim("summary", flat[:SUMMARY_CHARS],
                    attrs={"truncated": True, "chars": len(flat)} if len(flat) > SUMMARY_CHARS else {})

    # one CVSS score (highest scorable version) beside NVD's, and a band
    score, version, vector, others = best_severity(record)
    db_sev = (record.get("database_specific") or {}).get("severity") \
        if isinstance(record.get("database_specific"), dict) else None
    if score is not None:
        attrs = {"version": version, "vector": vector}
        if others:
            attrs["other_vectors"] = others
        yield claim("cvss_score", float(score), attrs=attrs)
        yield claim("has_severity", severity_band(score), attrs={"version": version})
    else:
        # no numeric base score (a v4.0-only vector): keep the band the source
        # states, and the vector(s) for the reader
        vectors = [v for v in (vector, *others) if v]
        if isinstance(db_sev, str) and db_sev.strip():
            yield claim("has_severity", db_sev.strip().lower(),
                        attrs={"cvss": vectors} if vectors else {})

    # affected packages -> package:<ecosystem>:<name> (NOT CPE; D-042)
    for key, pkg in affected_packages(record).items():
        attrs = {"ecosystem": pkg["ecosystem"], "name": pkg["name"]}
        if pkg["purl"]:
            attrs["purl"] = pkg["purl"]
        if pkg["ranges"]:
            attrs["ranges"] = pkg["ranges"]
        if pkg["versions"]:
            attrs["versions"] = pkg["versions"][:MAX_VERSIONS]
            if len(pkg["versions"]) > MAX_VERSIONS:
                attrs["versions_truncated"] = len(pkg["versions"])
        yield claim("affects", EntityRef(type="package", key=key), f":{key}", attrs=attrs)


def records_to_envelopes(records: Iterable[dict], namespace: str, source: str | None = None,
                         as_of: datetime | None = None, mtime: datetime | None = None,
                         stats: dict[str, int] | None = None) -> Iterator[ClaimIn | DocumentIn]:
    """Every record's envelopes; a malformed record is counted `invalid` and
    skipped, never the end of a directory of thousands."""
    stats = stats if stats is not None else {}
    for record in records:
        if not isinstance(record, dict) or not record.get("id"):
            stats["invalid"] = stats.get("invalid", 0) + 1
            continue
        try:
            envs = list(record_to_envelopes(record, namespace, source, as_of, mtime))
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            stats["invalid"] = stats.get("invalid", 0) + 1
            print(f"osv record {record.get('id')}: skipped: {str(exc).splitlines()[0][:200]}",
                  file=sys.stderr)
            continue
        stats["record"] = stats.get("record", 0) + 1
        for env in envs:
            stats["document" if isinstance(env, DocumentIn) else "claim"] = \
                stats.get("document" if isinstance(env, DocumentIn) else "claim", 0) + 1
            yield env


# --------------------------------------------------------------------- read #

def _unwrap(obj) -> Iterator[dict]:
    """OSV records out of one parsed JSON value: a single record ({"id": …}),
    a list, an osv.dev query response ({"vulns": […]}) or a batch response
    ({"results": [{"vulns": […]}]})."""
    if isinstance(obj, list):
        for item in obj:
            yield from _unwrap(item)
    elif isinstance(obj, dict):
        if isinstance(obj.get("vulns"), list):
            yield from (v for v in obj["vulns"] if isinstance(v, dict))
        elif isinstance(obj.get("results"), list):
            for res in obj["results"]:
                if isinstance(res, dict) and isinstance(res.get("vulns"), list):
                    yield from (v for v in res["vulns"] if isinstance(v, dict))
        elif obj.get("id"):
            yield obj


def _records_from_text(text: str) -> Iterator[dict]:
    text = text.strip()
    if not text:
        return
    try:
        yield from _unwrap(json.loads(text))
    except ValueError:                       # several concatenated objects: NDJSON
        for line in text.splitlines():
            if line.strip():
                yield from _unwrap(json.loads(line))


def iter_records(path: str) -> Iterator[dict]:
    """OSV records from a file, `-` (stdin), or every `*.json` under a
    directory (the shape the OSV / GHSA databases publish: one file per
    record, in nested dirs)."""
    if path == "-":
        yield from _records_from_text(sys.stdin.read())
        return
    p = Path(path)
    if p.is_dir():
        for f in sorted(p.rglob("*.json")):
            yield from _records_from_text(f.read_text(encoding="utf-8"))
    else:
        yield from _records_from_text(p.read_text(encoding="utf-8"))


# ------------------------------------------------------------------- schema #

def schema(namespace: str) -> SchemaRegistration:
    """The registry this connector declares. Not strict: the seed's own types
    and the vulns / OCSF / STIX connectors' `cve` share the namespace. `cvss_score`,
    `has_severity`, `summary` and `affects` deliberately reuse the vulns
    vocabulary so an OSV advisory reads as part of one CVE record; `affects`
    is registered for BOTH `product` (NVD/KEV) and `package` (OSV), since a
    later registration overrides the object types by name."""
    return SchemaRegistration(
        namespace=namespace,
        entity_types=[
            EntityTypeDef(name="cve", description="a CVE record (the node NVD/KEV/OCSF/STIX also write to)"),
            EntityTypeDef(name="advisory", description="an OSV advisory with no CVE alias, keyed by its OSV id"),
            EntityTypeDef(name="package", description="software keyed ecosystem:name as OSV keys it "
                          "(PyPI:django, Maven:group:artifact) — NOT a CPE product (D-042)"),
        ],
        predicates=[
            PredicateDef(name="cvss_score", description="CVSS base score computed from the OSV "
                         "severity[] vector; source names the feed (ghsa / osv)"),
            PredicateDef(name="has_severity", description="CVSS base severity band (lowercase)"),
            PredicateDef(name="summary", description="the advisory summary, trimmed"),
            PredicateDef(name="affects", object_types=["product", "package"],
                         description="the CVE/advisory affects this package (OSV ecosystem:name) or "
                         "product (NVD CPE); the two are un-reconciled by design (D-042)"),
        ],
    )


# ---------------------------------------------------------------------- CLI #

def _to_lines(envs: Iterable[ClaimIn | DocumentIn]) -> Iterator[str]:
    for env in envs:
        yield env.model_dump_json(exclude_none=True) + "\n"


def _mtime(path: str) -> datetime | None:
    if path == "-":
        return None
    p = Path(path)
    try:
        target = p if p.is_file() else None
        if target is None:                   # a directory: the newest file in it
            files = [f for f in p.rglob("*.json")]
            target = max(files, key=lambda f: f.stat().st_mtime) if files else None
        if target is None:
            return None
        return datetime.fromtimestamp(target.stat().st_mtime, tz=timezone.utc).replace(microsecond=0)
    except OSError:
        return None


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loomctx.connectors.osv", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--namespace", default=NAMESPACE_DEFAULT)
    common.add_argument("--source", help="source label (default: ghsa for a GHSA id, else osv)")
    common.add_argument("--as-of", dest="as_of",
                        help="ISO timestamp used when a record carries no modified/published stamp")
    sub = parser.add_subparsers(dest="command", required=True)
    imp = sub.add_parser("import", parents=[common], help="parse OSV JSON and ingest it")
    imp.add_argument("path", help="an OSV JSON file or a directory of them, or - for stdin")
    imp.add_argument("--url", help="engine or gateway base URL (default: write straight into the store)")
    imp.add_argument("--db", help="write straight into this explicit store URL/path")
    imp.add_argument("--key", default=os.environ.get("LOOMCTX_API_KEY"), type=str.strip)
    imp.add_argument("--batch", type=int, default=500)
    imp.add_argument("--no-schema", action="store_true", help="skip the registry registration")
    emit = sub.add_parser("emit", parents=[common], help="write NDJSON envelopes to stdout")
    emit.add_argument("path")
    sub.add_parser("schema", parents=[common], help="print the schema registration")
    args = parser.parse_args(argv)

    if args.command == "schema":
        print(schema(args.namespace).model_dump_json(indent=2))
        return

    as_of = None
    if args.as_of:
        as_of = datetime.fromisoformat(args.as_of.replace("Z", "+00:00"))
        as_of = as_of if as_of.tzinfo else as_of.replace(tzinfo=timezone.utc)
    stats: dict[str, int] = {}
    envs = records_to_envelopes(iter_records(args.path), args.namespace, args.source, as_of,
                                _mtime(args.path), stats)

    if args.command == "emit":
        for line in _to_lines(envs):
            sys.stdout.write(line)
        print(json.dumps({"envelopes": stats}), file=sys.stderr)
        return

    if args.url and args.db:
        parser.error("import: give --url or --db, not both")
    from ..ingest import fail_on_refusals, load_direct, post_batches
    from .vulns import register
    if not args.no_schema:
        register(schema(args.namespace), args.url, args.db, args.key)
    lines = _to_lines(envs)
    totals = (post_batches(args.url, lines, args.batch, args.key) if args.url
              else load_direct(args.db, lines, args.batch))
    print(json.dumps({**totals, "envelopes": stats}))
    fail_on_refusals(totals, remote=bool(args.url))   # a refusal fails the load (D-063, S-36)


if __name__ == "__main__":
    main()
