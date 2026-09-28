"""MITRE ATT&CK taxonomy interop (D-073): the published ATT&CK knowledge base
(STIX 2.1 JSON) in, cited catalog claims out.

    python -m loomctx.connectors.attack import enterprise-attack.json --namespace netsec   # into the LOOMCTX_DB store
    python -m loomctx.connectors.attack import bundle.json --namespace netsec --url http://loomctx:8000 --key ...
    python -m loomctx.connectors.attack emit bundle.json --namespace netsec > envelopes.jsonl
    python -m loomctx.connectors.attack schema --namespace netsec                           # the registry it declares

What it is: a PARSER for the public `mitre-attack` STIX 2.1 bundles MITRE
publishes (https://github.com/mitre-attack/attack-stix-data — enterprise,
mobile and ICS ATT&CK). It reads a FILE (or `-` for stdin), fetches nothing,
and turns the catalog into cited, timestamped claims in the `attack`
namespace (by default). This is DEFENSIVE REFERENCE DATA: a published catalog
of technique / tactic / group / software / mitigation NAMES, ids,
descriptions, and the RELATIONSHIPS MITRE publishes between them. It is kept
strictly at the catalog level — there is no operational how-to here. In
particular the per-relationship "procedure" descriptions ATT&CK attaches to a
`uses` edge (how a given group used a technique in the wild) are NOT imported;
only the catalog edge itself is (D-073).

Objects, keyed by their ATT&CK external id (the stable public id):
  * `attack-pattern`  -> `technique:<Txxxx>`   (sub-techniques included, e.g. T1560.001)
  * `x-mitre-tactic`  -> `tactic:<TAxxxx>`
  * `intrusion-set`   -> `group:<Gxxxx>`
  * `malware` / `tool`-> `software:<Sxxxx>`
  * `course-of-action`-> `mitigation:<Mxxxx>`
Each entity's `name`, `summary` (the catalog description) and `url` land as
scalar claims on it, and the ATT&CK id / stix id / object version ride in
`attrs`. Revoked and deprecated objects (and edges touching them) are skipped.

Relationships, exactly as MITRE publishes them (the catalog edges only):
  * `technique in_tactic tactic`   (from an attack-pattern's kill_chain_phases)
  * `group uses technique` / `group uses software` / `software uses technique`
  * `mitigation mitigates technique`
Other STIX relationship types (`detects`, `subtechnique-of`, `attributed-to`,
`revoked-by`, ...) are skipped as out of scope / detection guidance.

`observed_at` is each object's `modified` stamp (the assertion time of the
version being imported; `created` rides in attrs), `valid_from` its `created`,
and every event id embeds `modified`: re-importing a bundle is idempotent, and
a later ATT&CK release (a bumped `modified`) records a NEW observation —
history, not overwrite (D-035's rule). Source label `mitre-attack`
(`--source` overrides). The loader fails on refusals (D-063, S-36).

No fusion with the vuln corpus is required — `attack` is its own namespace —
but a technique that carries a CVE external reference optionally links to the
same `cve:<id>` node the NVD/KEV/OCSF/STIX/OSV connectors write to (D-035).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from ..contracts import (ClaimIn, EntityRef, EntityTypeDef, PredicateDef,
                         SchemaRegistration)
# STIX-bundle timestamp / CVE helpers, reused read-only (do not modify stix.py)
from .stix import _stamp, _utc, cve_id

SOURCE_DEFAULT = "mitre-attack"
NAMESPACE_DEFAULT = "netsec"   # one namespace per environment (D-083)
DESC_CHARS = 8000                     # a catalog description is prose; cap it, marking truncation
ATTACK_KILL_CHAINS = ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack")

# STIX object type -> the LoomCtx entity type of the node it becomes. malware and
# tool are both `software` (ATT&CK's S-id space covers both).
ENTITY_TYPES = {
    "attack-pattern": "technique",
    "x-mitre-tactic": "tactic",
    "intrusion-set": "group",
    "malware": "software",
    "tool": "software",
    "course-of-action": "mitigation",
}
# STIX relationship_type -> LoomCtx predicate. Only the catalog edges in scope.
REL_PREDICATES = {"uses": "uses", "mitigates": "mitigates"}


def attack_id(obj: dict) -> str | None:
    """The object's stable ATT&CK external id (Txxxx / TAxxxx / Gxxxx / Sxxxx /
    Mxxxx), or None if it carries no `mitre-attack` reference."""
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and str(ref.get("source_name", "")).lower() == "mitre-attack":
            ext = ref.get("external_id")
            if isinstance(ext, str) and ext:
                return ext
    return None


def attack_url(obj: dict) -> str | None:
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and str(ref.get("source_name", "")).lower() == "mitre-attack":
            url = ref.get("url")
            if isinstance(url, str) and url:
                return url
    return None


def _is_dropped(obj: dict) -> bool:
    """A revoked or deprecated object: kept out of the catalog (and any edge
    touching it is dropped too)."""
    return bool(obj.get("revoked")) or bool(obj.get("x_mitre_deprecated"))


def _entity_ref(obj: dict) -> EntityRef | None:
    """The LoomCtx node for an in-scope, non-dropped object, keyed by its ATT&CK
    id; None for anything this connector does not catalog."""
    etype = ENTITY_TYPES.get(obj.get("type", ""))
    if etype is None or _is_dropped(obj):
        return None
    aid = attack_id(obj)
    return EntityRef(type=etype, key=aid) if aid else None


def _tactic_index(objects: list[dict]) -> dict[str, str]:
    """kill_chain phase_name (x_mitre_shortname) -> tactic ATT&CK id, from the
    bundle's x-mitre-tactic objects, so a technique's kill_chain_phases resolve
    to the `tactic:<TAxxxx>` node."""
    out: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic" and not _is_dropped(obj):
            short, aid = obj.get("x_mitre_shortname"), attack_id(obj)
            if isinstance(short, str) and short and aid:
                out[short] = aid
    return out


def bundle_to_envelopes(bundle: dict, namespace: str, source: str = SOURCE_DEFAULT,
                        stats: dict[str, int] | None = None) -> Iterator[ClaimIn]:
    """Every catalog claim a `mitre-attack` STIX bundle yields. One object at a
    time: a malformed object (a bad timestamp, a missing id) is counted and
    skipped, never the end of the whole bundle."""
    stats = stats if stats is not None else {}
    objects = [o for o in bundle.get("objects", []) if isinstance(o, dict) and o.get("id")]
    index = {o["id"]: o for o in objects}
    refs = {sid: r for sid, o in index.items() if (r := _entity_ref(o)) is not None}
    tactics = _tactic_index(objects)
    now = datetime.now(timezone.utc)

    def count(kind: str) -> None:
        stats[kind] = stats.get(kind, 0) + 1

    def when(obj: dict) -> tuple[datetime, str, datetime | None]:
        observed = _utc(obj.get("modified")) or _utc(obj.get("created"))
        if observed is None:
            raise ValueError("object has no modified/created stamp")
        if observed > now:
            observed = now
        return observed, _stamp(observed), _utc(obj.get("created"))

    def base_attrs(obj: dict, aid: str) -> dict:
        attrs = {"attack_id": aid, "stix_id": obj["id"], "stix_type": obj["type"]}
        if obj.get("x_mitre_version"):
            attrs["attack_version"] = str(obj["x_mitre_version"])
        if obj.get("created"):
            attrs["created"] = obj["created"]
        return attrs

    # pass 1: the objects (name / description / url scalar claims + the CVE link)
    for obj in objects:
        try:
            ref = _entity_ref(obj)
            if ref is None:
                if obj.get("type") in ("relationship", "x-mitre-collection"):
                    continue                 # relationships handled in pass 2; collection is metadata
                if _is_dropped(obj) and obj.get("type") in ENTITY_TYPES:
                    count("dropped")
                else:
                    count("skipped")
                continue
            observed, stamp, created = when(obj)
            aid = ref.key
            base = base_attrs(obj, aid)
            prefix = f"attack:{obj['id']}:{stamp}"

            def claim(pred: str, value, tag: str = "", *, attrs=None, r=ref, ev=prefix,
                      ob=observed, vf=created, default_attrs=base) -> ClaimIn:
                return ClaimIn(namespace=namespace, event_id=f"{ev}:{pred}{tag}"[:128], subject=r,
                               predicate=pred, object=value, observed_at=ob, valid_from=vf,
                               source=source, attrs=default_attrs if attrs is None else attrs)

            emitted = 0
            name = obj.get("name")
            if isinstance(name, str) and name:
                yield claim("name", name)
                emitted += 1
            desc = obj.get("description")
            if isinstance(desc, str) and desc.strip():
                flat = desc.strip()
                extra = {"chars": len(flat), "truncated": True} if len(flat) > DESC_CHARS else {}
                yield claim("summary", flat[:DESC_CHARS], attrs={**base, **extra} if extra else None)
                emitted += 1
            url = attack_url(obj)
            if url:
                yield claim("url", url)
                emitted += 1

            # technique in_tactic tactic (from kill_chain_phases), catalog-level
            if obj.get("type") == "attack-pattern":
                for phase in obj.get("kill_chain_phases") or []:
                    if not isinstance(phase, dict):
                        continue
                    if str(phase.get("kill_chain_name", "")) not in ATTACK_KILL_CHAINS:
                        continue
                    ta = tactics.get(phase.get("phase_name"))
                    if ta:
                        yield claim("in_tactic", EntityRef(type="tactic", key=ta), f":{ta}")
                        emitted += 1
                    else:
                        count("unresolved_tactic")

            # optional cross-corpus link: a technique that names a CVE (D-035)
            cid = cve_id(obj)
            if cid:
                yield claim("references", EntityRef(type="cve", key=cid), f":{cid}")
                emitted += 1

            count("object" if emitted else "empty_object")
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            count("invalid")
            print(f"attack object {obj.get('id')}: skipped: {str(exc).splitlines()[0][:200]}",
                  file=sys.stderr)

    # pass 2: the catalog relationships (uses / mitigates); both endpoints must
    # be in-scope, non-dropped nodes. The per-edge procedure description is
    # deliberately NOT imported — the catalog edge only (D-073).
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        try:
            rtype = obj.get("relationship_type")
            pred = REL_PREDICATES.get(rtype)
            if pred is None:
                count("skipped_edge")
                continue
            src, tgt = refs.get(obj.get("source_ref")), refs.get(obj.get("target_ref"))
            if src is None or tgt is None:
                count("skipped_edge")           # dangling / out-of-scope / dropped endpoint
                continue
            observed, stamp, created = when(obj)
            aid = attack_id(obj)                # relationships have no ATT&CK id of their own
            attrs = {"stix_id": obj["id"], "stix_type": "relationship"}
            if obj.get("x_mitre_version"):
                attrs["attack_version"] = str(obj["x_mitre_version"])
            if obj.get("created"):
                attrs["created"] = obj["created"]
            tag = f":{tgt.type}:{tgt.key}"
            yield ClaimIn(namespace=namespace, event_id=f"attack:{obj['id']}:{stamp}:{pred}{tag}"[:128],
                          subject=src, predicate=pred, object=tgt, observed_at=observed,
                          valid_from=created, source=source, attrs=attrs)
            count("relationship")
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            count("invalid")
            print(f"attack relationship {obj.get('id')}: skipped: {str(exc).splitlines()[0][:200]}",
                  file=sys.stderr)


# ------------------------------------------------------------------- schema #

def schema(namespace: str) -> SchemaRegistration:
    """The registry this connector declares. NOT strict: `attack` is its own
    taxonomy namespace, but `summary` / `name` / `url` and the optional
    `references cve` edge deliberately reuse the shared vocabulary so a
    technique that names a CVE reads on the same node the vuln connectors
    write to (D-035). `in_tactic` is a containment relation, so a default
    scope over a technique follows it up to its tactic (D-024)."""
    return SchemaRegistration(
        namespace=namespace,
        entity_types=[
            EntityTypeDef(name="technique", description="an ATT&CK technique / sub-technique (Txxxx), "
                          "from a STIX attack-pattern"),
            EntityTypeDef(name="tactic", description="an ATT&CK tactic (TAxxxx), the adversary goal a "
                          "technique serves"),
            EntityTypeDef(name="group", description="an ATT&CK group / intrusion-set (Gxxxx)"),
            EntityTypeDef(name="software", description="ATT&CK software (Sxxxx): a malware or tool"),
            EntityTypeDef(name="mitigation", description="an ATT&CK mitigation / course-of-action (Mxxxx)"),
            EntityTypeDef(name="cve", description="a CVE node an ATT&CK technique optionally references "
                          "(shared with the vuln connectors, D-035)"),
        ],
        predicates=[
            PredicateDef(name="in_tactic", object_types=["tactic"], containment=True,
                         description="the technique belongs to this ATT&CK tactic (kill_chain_phases)"),
            PredicateDef(name="uses", object_types=["technique", "software"],
                         description="a group uses a technique or software, or software uses a "
                         "technique — the catalog edge only, no procedure detail (D-073)"),
            PredicateDef(name="mitigates", object_types=["technique"],
                         description="the mitigation addresses this technique"),
            PredicateDef(name="references", object_types=["cve"],
                         description="the technique names this CVE (optional cross-corpus link, D-035)"),
            PredicateDef(name="name", label=True, description="the object's ATT&CK name"),
            PredicateDef(name="summary", description="the object's catalog description (trimmed)"),
            PredicateDef(name="url", description="the object's page on attack.mitre.org"),
        ],
    )


# ---------------------------------------------------------------------- read #

def iter_bundles(path: str) -> Iterator[dict]:
    """The STIX bundle(s) from a file, `-` (stdin), or every `*.json` under a
    directory (the shape attack-stix-data publishes: one bundle per domain)."""
    if path == "-":
        yield json.loads(sys.stdin.read())
        return
    p = Path(path)
    if p.is_dir():
        for f in sorted(p.rglob("*.json")):
            yield json.loads(f.read_text(encoding="utf-8"))
    else:
        yield json.loads(p.read_text(encoding="utf-8"))


def envelopes(path: str, namespace: str, source: str = SOURCE_DEFAULT,
              stats: dict[str, int] | None = None) -> Iterator[ClaimIn]:
    stats = stats if stats is not None else {}
    for bundle in iter_bundles(path):
        yield from bundle_to_envelopes(bundle, namespace, source, stats)


# ---------------------------------------------------------------------- CLI #

def _to_lines(envs: Iterable[ClaimIn]) -> Iterator[str]:
    for env in envs:
        yield env.model_dump_json(exclude_none=True) + "\n"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loomctx.connectors.attack", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--namespace", default=NAMESPACE_DEFAULT)
    common.add_argument("--source", default=SOURCE_DEFAULT, help="source label (default: mitre-attack)")
    sub = parser.add_subparsers(dest="command", required=True)
    imp = sub.add_parser("import", parents=[common], help="parse a mitre-attack STIX bundle and ingest it")
    imp.add_argument("bundle", help="a mitre-attack STIX 2.1 bundle (JSON), a directory of them, or - for stdin")
    imp.add_argument("--url", help="engine or gateway base URL (default: write straight into the store)")
    imp.add_argument("--db", help="write straight into this explicit store URL/path")
    imp.add_argument("--key", default=os.environ.get("LOOMCTX_API_KEY"), type=str.strip)
    imp.add_argument("--batch", type=int, default=500)
    imp.add_argument("--no-schema", action="store_true", help="skip the registry registration")
    emit = sub.add_parser("emit", parents=[common], help="write NDJSON envelopes to stdout")
    emit.add_argument("bundle")
    sub.add_parser("schema", parents=[common], help="print the schema registration")
    args = parser.parse_args(argv)

    if args.command == "schema":
        print(schema(args.namespace).model_dump_json(indent=2))
        return

    stats: dict[str, int] = {}
    envs = envelopes(args.bundle, args.namespace, args.source, stats)

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
