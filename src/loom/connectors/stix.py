"""STIX 2.1 interop (hardening R-8): bundles in, bundles out.

    python -m loom.connectors.stix import bundle.json --namespace netsec            # into the LOOM_DB store
    python -m loom.connectors.stix import bundle.json --namespace netsec --url http://loom:8000 --key ...
    python -m loom.connectors.stix export --namespace netsec --out bundle.json      # every observation, as STIX
    python -m loom.connectors.stix emit bundle.json --namespace netsec > envelopes.jsonl
    python -m loom.connectors.stix schema --namespace netsec                        # the registry it declares

Import — STIX objects become Loom claims (`docs/interop.md` has the full
table):

  * `relationship`: source_ref/target_ref -> subject/object (typed by the
    STIX type, keyed by the object's name / value / CVE id),
    relationship_type -> predicate (hyphens -> underscores, or the
    `mapping`), start_time/stop_time -> valid_from/valid_to, confidence
    0-100 -> 0-1, created_by_ref -> the identity's name as `source`.
  * `sighting`: sighting_of_ref `sighted_by` each where_sighted_refs entry,
    first_seen/last_seen -> the validity window, count in attrs.
  * SDO / SCO properties -> scalar claims on the object's entity (name,
    description -> summary, pattern, aliases, *_types, ...). A
    `vulnerability` with a CVE external reference lands on `cve:CVE-...`,
    the same entity the KEV/NVD connector writes to.
  * `note` / `report` / `opinion` -> documents; claims about the objects a
    report lists cite it (D-039), so its text ranks as an excerpt for them.
  * `revoked` objects, markings, `observed-data`, `x_` custom properties
    and non-CVE external references are skipped (documented) — except a
    revoked relationship or sighting on `import`, see below.

`observed_at` is the object's `modified` stamp (the assertion time of the
version being imported; `created` rides in attrs), and every event_id
embeds it: re-importing a bundle is idempotent, a revised object records a
new observation — history, not overwrite (D-035's rule). On `import`,
the versions of one relationship or sighting are chained by recorded
supersession (D-050, connectors/chain.py): a revision (a `stop_time`
appearing, a new confidence) supersedes the version before it, and a
revocation of an imported edge lands as a final version closed at the
revocation (`valid_to` = its `modified`, attrs.revoked) superseding it —
so the stale open edge stops being current. A revocation of something
never imported is dropped; `emit` has no store to ask and skips revoked
objects as before.

Export — `observations_to_bundle` writes a valid STIX 2.1 bundle: one
object per entity (SCOs for ip/domain/url/email/user/file, SDOs otherwise,
`x-loom-<type>` for types STIX has no name for), a `relationship` per
relational observation (`sighting` for `sighted_by`) carrying start/stop
time, confidence and `x_loom_observation_id` for citation, an `identity`
per source. Scalar observations sit on their entity's object: the newest
of each mapped predicate as the STIX property, all of them in
`x_loom_observations`. Ids are deterministic (UUIDv5), so re-exports
diff cleanly.

A `mapping` dict (`--mapping map.json`) overrides the default tables:
{"entity_types": {"identity": "org"}, "predicates": {"targets": "attacks"},
 "properties": {"description": "description"}, "sighting": "seen_by"}.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

from ..contracts import (ClaimIn, DocumentIn, EntityRef, EntityTypeDef, Observation,
                         PredicateDef, Provenance, SchemaRegistration)

SOURCE_DEFAULT = "stix"
SPEC_VERSION = "2.1"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
ID_RE = re.compile(r"^[a-z][a-z0-9-]*[a-z0-9]--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

# STIX type -> Loom entity type. SDO types not listed map hyphen -> underscore
# (intrusion-set -> intrusion_set). `vulnerability` is `cve` when the object
# carries a CVE external reference, `vulnerability` otherwise.
DEFAULT_ENTITY_TYPES = {
    "ipv4-addr": "ip", "ipv6-addr": "ip", "domain-name": "domain", "url": "url",
    "email-addr": "email", "user-account": "user", "mac-addr": "mac", "file": "file",
    "identity": "identity", "vulnerability": "cve",
}
# SCO "value" properties: the key of the entity
SCO_VALUE = {"ipv4-addr", "ipv6-addr", "domain-name", "url", "email-addr", "mac-addr"}
# object property -> predicate (scalars); list-valued ones yield one claim per item
DEFAULT_PROPERTIES = {
    "name": "name", "description": "summary", "pattern": "pattern", "pattern_type": "pattern_type",
    "is_family": "is_family", "aliases": "alias", "labels": "label",
    "indicator_types": "indicator_type", "malware_types": "malware_type",
    "infrastructure_types": "infrastructure_type", "threat_actor_types": "threat_actor_type",
    "goals": "goal", "sectors": "sector", "roles": "role", "resource_level": "resource_level",
    "primary_motivation": "primary_motivation", "sophistication": "sophistication",
    "kill_chain_phases": "kill_chain_phase", "first_seen": "first_seen", "last_seen": "last_seen",
    "identity_class": "identity_class", "tool_types": "tool_type", "objective": "objective",
}
# STIX reference properties on SCOs that are relations in Loom
REF_PROPERTIES = {"resolves_to_refs": "resolves_to", "belongs_to_refs": "belongs_to"}
DEFAULT_SIGHTING = "sighted_by"
SIGHTED_COUNT = "sighted_count"
DOCUMENT_TYPES = {"note", "report", "opinion"}
SKIPPED_TYPES = {"marking-definition", "language-content", "extension-definition", "observed-data",
                 "bundle"}
COMMON_RELATIONSHIPS = [
    "uses", "targets", "indicates", "attributed-to", "mitigates", "variant-of", "impersonates",
    "delivers", "drops", "exploits", "communicates-with", "controls", "consists-of", "hosts", "owns",
    "authored-by", "compromises", "originates-from", "located-at", "based-on", "derived-from",
    "duplicate-of", "related-to", "has", "beacons-to", "exfiltrates-to", "downloads", "remediates",
    "characterizes", "analysis-of", "investigates", "resolves-to", "belongs-to",
]
SDO_TYPES = [
    "attack-pattern", "campaign", "course-of-action", "grouping", "identity", "indicator",
    "infrastructure", "intrusion-set", "location", "malware", "malware-analysis", "threat-actor",
    "tool", "vulnerability",
]
# Loom entity type -> STIX type (export). Anything else becomes x-loom-<type>.
DEFAULT_STIX_TYPES = {
    "ip": "ipv4-addr", "domain": "domain-name", "url": "url", "email": "email-addr",
    "user": "user-account", "mac": "mac-addr", "file": "file", "identity": "identity",
    "organization": "identity", "cve": "vulnerability", "vulnerability": "vulnerability",
    **{t.replace("-", "_"): t for t in SDO_TYPES},
}
LOOM_UUID_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/seahop/Loom")
SCO_UUID_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")   # STIX 2.1 §2.9 deterministic SCO ids


class Mapping:
    """The default tables plus a namespace's overrides, both directions."""

    def __init__(self, overrides: dict | None = None):
        overrides = overrides or {}
        self.entity_types = {**DEFAULT_ENTITY_TYPES, **overrides.get("entity_types", {})}
        self.predicates = dict(overrides.get("predicates", {}))
        self.properties = {**DEFAULT_PROPERTIES, **overrides.get("properties", {})}
        self.sighting = overrides.get("sighting", DEFAULT_SIGHTING)
        # only the caller's overrides are inverted: the default table maps
        # both ipv4-addr and ipv6-addr to `ip`, and export picks by shape
        self._stix_types = {**DEFAULT_STIX_TYPES,
                            **{loom: stix for stix, loom in overrides.get("entity_types", {}).items()}}
        self._rel_types = {pred: rt for rt, pred in self.predicates.items()}
        self._props = {pred: prop for prop, pred in self.properties.items()}

    def entity_type(self, stix_type: str, obj: dict | None = None) -> str:
        if stix_type == "vulnerability" and obj is not None and cve_id(obj) is None:
            return "vulnerability"
        return self.entity_types.get(stix_type) or stix_type.replace("-", "_")

    def predicate(self, relationship_type: str) -> str:
        return self.predicates.get(relationship_type) or relationship_type.replace("-", "_")

    def stix_type(self, loom_type: str) -> str:
        return self._stix_types.get(loom_type) or f"x-loom-{loom_type.replace('_', '-')}"

    def relationship_type(self, predicate: str) -> str:
        return self._rel_types.get(predicate) or predicate.replace("_", "-")

    def property(self, predicate: str) -> str | None:
        return self._props.get(predicate)


# ------------------------------------------------------------------ helpers #

def _utc(text: str | None) -> datetime | None:
    if not text:
        return None
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _stamp(dt: datetime) -> str:
    return dt.strftime("%Y%m%dT%H%M%S")


def stix_timestamp(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def cve_id(obj: dict) -> str | None:
    for ref in obj.get("external_references") or []:
        if isinstance(ref, dict) and str(ref.get("source_name", "")).lower() == "cve":
            ext = str(ref.get("external_id", ""))
            if CVE_RE.match(ext):
                return ext.upper()
    name = str(obj.get("name", ""))
    return name.upper() if CVE_RE.match(name) else None


def entity_key(obj: dict) -> str:
    """What names this object in Loom: a CVE id, an SCO's value, a name —
    the STIX id as a last resort."""
    stype = obj.get("type", "")
    if stype == "vulnerability" and (cid := cve_id(obj)):
        return cid
    if stype in SCO_VALUE and obj.get("value"):
        return str(obj["value"])
    if stype == "user-account":
        return str(obj.get("user_id") or obj.get("account_login") or obj.get("display_name") or obj["id"])
    if stype == "file":
        hashes = obj.get("hashes") or {}
        return str(hashes.get("SHA-256") or hashes.get("sha256") or obj.get("name") or obj["id"])
    if obj.get("name"):
        return str(obj["name"])
    return str(obj["id"])


def _scalar(value: Any) -> str | int | float | bool | None:
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict) and "kill_chain_name" in value:      # kill_chain_phases items
        return f"{value['kill_chain_name']}:{value.get('phase_name', '')}"
    return None


# ------------------------------------------------------------------- import #

def bundle_to_envelopes(bundle: dict, namespace: str, mapping: dict | Mapping | None = None,
                        source: str = SOURCE_DEFAULT, stats: dict[str, int] | None = None,
                        include_revoked: bool = False) -> list[ClaimIn | DocumentIn]:
    """Every claim and document a bundle yields, documents first so the
    claims that cite them land after their artifact (D-039).
    `include_revoked` yields a revoked relationship / sighting as its
    closing version (attrs.revoked, valid_to = the revocation) for the
    chained import to supersede the imported edge with."""
    m = mapping if isinstance(mapping, Mapping) else Mapping(mapping)
    stats = stats if stats is not None else {}
    objects: list[dict] = [o for o in bundle.get("objects", []) if isinstance(o, dict) and o.get("id")]
    index = {o["id"]: o for o in objects}
    identities = {o["id"]: str(o.get("name") or o["id"]) for o in objects if o.get("type") == "identity"}
    now = datetime.now(timezone.utc)

    def count(kind: str) -> None:
        stats[kind] = stats.get(kind, 0) + 1

    def ref(stix_id: str) -> EntityRef:
        obj = index.get(stix_id)
        if obj is None:                      # dangling reference: keep the edge, keyed by the id
            return EntityRef(type=m.entity_type(stix_id.split("--", 1)[0]), key=stix_id)
        return EntityRef(type=m.entity_type(obj["type"], obj), key=entity_key(obj))

    def when(obj: dict) -> tuple[datetime, str]:
        observed = _utc(obj.get("modified")) or _utc(obj.get("created")) or now
        return observed, _stamp(observed)

    def source_of(obj: dict) -> str:
        return identities.get(obj.get("created_by_ref", ""), source)

    def base_attrs(obj: dict) -> dict:
        attrs = {"stix_id": obj["id"], "stix_type": obj["type"]}
        if obj.get("created"):
            attrs["created"] = obj["created"]
        return attrs

    def confidence(obj: dict) -> float:
        value = obj.get("confidence")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return max(0.0, min(1.0, float(value) / 100.0))
        return 1.0

    documents: list[DocumentIn] = []
    cites: dict[str, str] = {}               # stix id -> event_id of the document that lists it
    claims: list[ClaimIn] = []

    # pass 1: the documents, so every claim can cite the report that lists
    # its object wherever the report sits in the bundle
    for obj in objects:
        try:
            stype = obj["type"]
            if stype in DOCUMENT_TYPES and not obj.get("revoked"):
                observed, stamp = when(obj)
                title = obj.get("name") or obj.get("abstract") or ""
                body = obj.get("content") or obj.get("description") or obj.get("explanation") or ""
                if stype == "opinion":
                    body = f"Opinion: {obj.get('opinion', '')}\n\n{body}".strip()
                text = "\n\n".join(part for part in (title, body) if part).strip()
                if not text:
                    count("skipped")
                    continue
                event = f"stix:{obj['id']}:{stamp}:doc"[:128]
                attrs = {**base_attrs(obj), "object_refs": list(obj.get("object_refs") or [])}
                for extra in ("report_types", "authors", "published", "labels"):
                    if obj.get(extra) is not None:
                        attrs[extra] = obj[extra]
                documents.append(DocumentIn(namespace=namespace, event_id=event, text=text,
                                            filename=f"{obj['id']}.txt", source=source_of(obj),
                                            observed_at=observed, attrs=attrs))
                for target in obj.get("object_refs") or []:
                    cites.setdefault(target, event)
                count("document")
        except (ValueError, TypeError, KeyError) as exc:
            count("invalid")
            print(f"stix object {obj.get('id')}: skipped: {str(exc).splitlines()[0][:200]}",
                  file=sys.stderr)

    # pass 2: everything else — one object at a time: a malformed one (a
    # bad timestamp, a future `modified`) is counted and skipped, never
    # the end of the whole bundle
    for obj in objects:
        mark = len(claims)
        try:
            stype = obj["type"]
            if stype in SKIPPED_TYPES:
                count("skipped")
                continue
            revoked = bool(obj.get("revoked"))
            if revoked and not (include_revoked and stype in ("relationship", "sighting")):
                count("revoked")
                continue
            if stype in DOCUMENT_TYPES:
                continue
            observed, stamp = when(obj)
            # a revocation closes the edge at the revocation's own stamp
            closing = {"revoked": True} if revoked else {}

            def claim(subject: EntityRef, pred: str, obj_value, tag: str = "", *,
                      o=obj, observed=observed, stamp=stamp, **kw) -> ClaimIn:
                prov = Provenance(artifact_event_id=cites[o["id"]]) if o["id"] in cites else None
                return ClaimIn(namespace=namespace, event_id=f"stix:{o['id']}:{stamp}:{pred}{tag}"[:128],
                               subject=subject, predicate=pred, object=obj_value, observed_at=observed,
                               source=source_of(o), confidence=confidence(o), provenance=prov,
                               attrs={**base_attrs(o), **kw.pop("attrs", {})}, **kw)

            if stype == "relationship":
                if not obj.get("source_ref") or not obj.get("target_ref") or not obj.get("relationship_type"):
                    count("skipped")
                    continue
                attrs = dict(closing)
                if obj.get("description"):
                    attrs["description"] = obj["description"]
                claims.append(claim(ref(obj["source_ref"]), m.predicate(obj["relationship_type"]),
                                    ref(obj["target_ref"]), valid_from=_utc(obj.get("start_time")),
                                    valid_to=observed if revoked else _utc(obj.get("stop_time")), attrs=attrs))
                count("revoked_edge" if revoked else "relationship")
                continue
            if stype == "sighting":
                if not obj.get("sighting_of_ref"):
                    count("skipped")
                    continue
                subject = ref(obj["sighting_of_ref"])
                attrs = {"count": obj.get("count", 1), **closing}
                if obj.get("summary"):
                    attrs["summary"] = True
                window = {"valid_from": _utc(obj.get("first_seen")),
                          "valid_to": observed if revoked else _utc(obj.get("last_seen"))}
                wheres = obj.get("where_sighted_refs") or []
                for where in wheres:
                    claims.append(claim(subject, m.sighting, ref(where), f":{where}", attrs=attrs, **window))
                if not wheres:
                    claims.append(claim(subject, SIGHTED_COUNT, int(obj.get("count") or 1), attrs=attrs, **window))
                count("revoked_edge" if revoked else "sighting")
                continue

            # an SDO or SCO: its properties become scalar claims on its entity
            subject = ref(obj["id"])
            emitted = 0
            for prop, pred in m.properties.items():
                value = obj.get(prop)
                if value is None:
                    continue
                values = value if isinstance(value, list) else [value]
                for i, item in enumerate(values):
                    scalar = _scalar(item)
                    if scalar is None or scalar == "":
                        continue
                    tag = f":{i}" if isinstance(value, list) else ""
                    window = {}
                    if prop == "pattern":                      # an indicator's validity is the pattern's
                        window = {"valid_from": _utc(obj.get("valid_from")),
                                  "valid_to": _utc(obj.get("valid_until"))}
                    claims.append(claim(subject, pred, scalar, tag, **window))
                    emitted += 1
            for prop, pred in REF_PROPERTIES.items():
                for i, target in enumerate(obj.get(prop) or []):
                    claims.append(claim(subject, pred, ref(target), f":{i}"))
                    emitted += 1
            count("object" if emitted else "empty_object")
        except (ValueError, TypeError, KeyError) as exc:
            del claims[mark:]
            count("invalid")
            print(f"stix object {obj.get('id')}: skipped: {str(exc).splitlines()[0][:200]}",
                  file=sys.stderr)

    return [*documents, *claims]


# ------------------------------------------------------------------- export #

def _sco_id(stix_type: str, value: str) -> str:
    contributing = json.dumps({"value": value}, separators=(",", ":"), ensure_ascii=False)
    return f"{stix_type}--{uuid.uuid5(SCO_UUID_NS, contributing)}"


def stix_id_for(namespace: str, ref: EntityRef, m: Mapping) -> tuple[str, str]:
    """(stix type, deterministic id) for a Loom entity."""
    stype = m.stix_type(ref.type)
    if stype == "ipv4-addr" and ":" in ref.key:
        stype = "ipv6-addr"
    if stype in SCO_VALUE:
        return stype, _sco_id(stype, ref.key)
    return stype, f"{stype}--{uuid.uuid5(LOOM_UUID_NS, f'{namespace}|{ref.type}|{ref.key}')}"


def observations_to_bundle(observations: Iterable[Observation], namespace: str,
                           mapping: dict | Mapping | None = None) -> dict:
    """A STIX 2.1 bundle of everything in `observations` (all one namespace)."""
    m = mapping if isinstance(mapping, Mapping) else Mapping(mapping)
    entities: dict[str, dict] = {}            # stix id -> object
    identities: dict[str, dict] = {}          # source -> identity object
    relations: list[dict] = []

    def identity_for(source: str) -> str:
        ident = identities.get(source)
        if ident is None:
            ident = {"type": "identity", "spec_version": SPEC_VERSION,
                     "id": f"identity--{uuid.uuid5(LOOM_UUID_NS, f'source|{source}')}",
                     "created": None, "modified": None, "name": source,
                     "identity_class": "unknown", "x_loom_source": source}
            identities[source] = ident
        return ident["id"]

    def touch(obj: dict, at: datetime) -> None:
        stamp = stix_timestamp(at)
        if obj.get("created") is None or stamp < obj["created"]:
            obj["created"] = stamp
        if obj.get("modified") is None or stamp > obj["modified"]:
            obj["modified"] = stamp

    def entity(ref: EntityRef, at: datetime) -> dict:
        stype, sid = stix_id_for(namespace, ref, m)
        obj = entities.get(sid)
        if obj is None:
            obj = {"type": stype, "spec_version": SPEC_VERSION, "id": sid}
            if stype in SCO_VALUE:
                obj["value"] = ref.key
            elif stype == "user-account":
                obj["user_id"] = ref.key
            elif stype == "file":
                obj["hashes" if len(ref.key) == 64 else "name"] = (
                    {"SHA-256": ref.key} if len(ref.key) == 64 else ref.key)
            else:
                obj["name"] = ref.key
                if stype == "vulnerability" and CVE_RE.match(ref.key):
                    obj["external_references"] = [{"source_name": "cve", "external_id": ref.key.upper()}]
                if stype == "identity":
                    obj["identity_class"] = "unknown"
            obj["x_loom_entity_type"] = ref.type
            obj["x_loom_entity_key"] = ref.key
            obj["x_loom_namespace"] = namespace
            entities[sid] = obj
        if obj["type"] not in SCO_VALUE and obj["type"] not in ("user-account", "file", "mac-addr"):
            touch(obj, at)
        return obj

    newest_scalar: dict[tuple[str, str], datetime] = {}
    for obs in observations:
        if obs.attrs.get("redacted"):
            continue
        created_by = identity_for(obs.source)
        touch(identities[obs.source], obs.observed_at)
        subject = entity(obs.subject, obs.observed_at)
        citation = {"x_loom_observation_id": obs.id, "x_loom_predicate": obs.predicate,
                    "x_loom_source": obs.source}
        if isinstance(obs.object, EntityRef):
            target = entity(obs.object, obs.observed_at)
            common = {"spec_version": SPEC_VERSION, "created": stix_timestamp(obs.observed_at),
                      "modified": stix_timestamp(obs.observed_at), "created_by_ref": created_by,
                      "confidence": int(round(obs.confidence * 100)), **citation}
            if obs.predicate == m.sighting:
                rel = {"type": "sighting", "id": f"sighting--{uuid.uuid5(LOOM_UUID_NS, obs.id)}", **common,
                       "sighting_of_ref": subject["id"], "where_sighted_refs": [target["id"]],
                       "count": int(obs.attrs.get("count", 1) or 1)}
                if obs.valid_from:
                    rel["first_seen"] = stix_timestamp(obs.valid_from)
                if obs.valid_to:
                    rel["last_seen"] = stix_timestamp(obs.valid_to)
            else:
                rel = {"type": "relationship", "id": f"relationship--{uuid.uuid5(LOOM_UUID_NS, obs.id)}",
                       **common, "relationship_type": m.relationship_type(obs.predicate),
                       "source_ref": subject["id"], "target_ref": target["id"]}
                if obs.valid_from:
                    rel["start_time"] = stix_timestamp(obs.valid_from)
                if obs.valid_to:
                    rel["stop_time"] = stix_timestamp(obs.valid_to)
                if obs.attrs.get("description"):
                    rel["description"] = str(obs.attrs["description"])
            relations.append(rel)
            continue
        record = {"id": obs.id, "predicate": obs.predicate, "value": obs.object,
                  "observed_at": stix_timestamp(obs.observed_at), "source": obs.source,
                  "confidence": obs.confidence}
        if obs.valid_from:
            record["valid_from"] = stix_timestamp(obs.valid_from)
        if obs.valid_to:
            record["valid_to"] = stix_timestamp(obs.valid_to)
        subject.setdefault("x_loom_observations", []).append(record)
        prop = m.property(obs.predicate)
        if prop is None or prop == "name":
            continue
        key = (subject["id"], obs.predicate)
        list_valued = prop in ("aliases", "labels") or prop.endswith("_types") or prop in ("goals", "sectors", "roles")
        if list_valued:
            values = subject.setdefault(prop, [])
            if obs.object not in values:
                values.append(obs.object)
        elif prop == "kill_chain_phases":
            name, _, phase = str(obs.object).partition(":")
            phases = subject.setdefault(prop, [])
            item = {"kill_chain_name": name, "phase_name": phase}
            if item not in phases:
                phases.append(item)
        elif key not in newest_scalar or obs.observed_at >= newest_scalar[key]:
            newest_scalar[key] = obs.observed_at
            subject[prop] = obs.object
            if prop == "pattern":
                subject.setdefault("pattern_type", "stix")
                if obs.valid_from:
                    subject["valid_from"] = stix_timestamp(obs.valid_from)
                if obs.valid_to:
                    subject["valid_until"] = stix_timestamp(obs.valid_to)

    for ident in identities.values():
        if ident["created"] is None:
            touch(ident, datetime.now(timezone.utc))
    objects = [*identities.values(), *entities.values(), *relations]
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


# ------------------------------------------------------------------- schema #

def schema(namespace: str, mapping: dict | Mapping | None = None) -> SchemaRegistration:
    """The registry the import declares. Not strict; object_types are left
    open because STIX relationship types join many object kinds."""
    m = mapping if isinstance(mapping, Mapping) else Mapping(mapping)
    types = sorted({m.entity_type(t) for t in SDO_TYPES} | set(m.entity_types.values()) | {"vulnerability"})
    preds = sorted({m.predicate(rt) for rt in COMMON_RELATIONSHIPS} | set(m.properties.values())
                   | set(REF_PROPERTIES.values()) | {m.sighting, SIGHTED_COUNT})
    return SchemaRegistration(
        namespace=namespace,
        entity_types=[EntityTypeDef(name=t, description="STIX 2.1 object (loom.connectors.stix)") for t in types],
        predicates=[PredicateDef(name=p, description="STIX 2.1 relationship type or object property "
                                                     "(loom.connectors.stix)") for p in preds],
    )


# ---------------------------------------------------------------------- CLI #

def _load_mapping(path: str | None) -> Mapping:
    if not path:
        return Mapping()
    with open(path, encoding="utf-8") as fh:
        return Mapping(json.load(fh))


def _to_lines(envs: Iterable[ClaimIn | DocumentIn]) -> Iterator[str]:
    for env in envs:
        yield env.model_dump_json(exclude_none=True) + "\n"


def _open_store(db: str | None):
    from ..store.factory import store_from_env, store_from_url
    return store_from_url(db) if db else store_from_env()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loom.connectors.stix", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--namespace", default="netsec")
    common.add_argument("--mapping", help="JSON file overriding the default type/predicate tables")
    sub = parser.add_subparsers(dest="command", required=True)
    imp = sub.add_parser("import", parents=[common], help="map a bundle to envelopes and ingest them")
    imp.add_argument("bundle", help="STIX 2.1 bundle (JSON)")
    imp.add_argument("--url", help="engine or gateway base URL (default: write straight into the store)")
    imp.add_argument("--db", help="write straight into this explicit store URL/path")
    imp.add_argument("--key", default=os.environ.get("LOOM_API_KEY"))
    imp.add_argument("--source", default=SOURCE_DEFAULT,
                     help="source for objects with no created_by_ref identity")
    imp.add_argument("--batch", type=int, default=500)
    imp.add_argument("--no-schema", action="store_true", help="skip the registry registration")
    emit = sub.add_parser("emit", parents=[common], help="write NDJSON envelopes to stdout")
    emit.add_argument("bundle")
    emit.add_argument("--source", default=SOURCE_DEFAULT)
    exp = sub.add_parser("export", parents=[common], help="write the namespace as a STIX bundle")
    exp.add_argument("--out", required=True, help="bundle path, or - for stdout")
    exp.add_argument("--db", help="read this explicit store URL/path (default: LOOM_DB / LOOM_SHARDS)")
    sub.add_parser("schema", parents=[common], help="print the schema registration")
    args = parser.parse_args(argv)

    mapping = _load_mapping(args.mapping)
    if args.command == "schema":
        print(schema(args.namespace, mapping).model_dump_json(indent=2))
        return
    if args.command == "export":
        store = _open_store(args.db)
        try:
            bundle = observations_to_bundle(store.iter_observations(args.namespace), args.namespace, mapping)
        finally:
            store.close()
        text = json.dumps(bundle, indent=2)
        if args.out == "-":
            sys.stdout.write(text + "\n")
        else:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
        print(json.dumps({"objects": len(bundle["objects"]), "out": args.out}), file=sys.stderr)
        return
    with open(args.bundle, encoding="utf-8") as fh:
        bundle = json.load(fh)
    stats: dict[str, int] = {}
    envs = bundle_to_envelopes(bundle, args.namespace, mapping, source=args.source, stats=stats,
                               include_revoked=args.command == "import")
    if args.command == "emit":
        for line in _to_lines(envs):
            sys.stdout.write(line)
        print(json.dumps({"envelopes": stats}), file=sys.stderr)
        return
    if args.url and args.db:
        parser.error("import: give --url or --db, not both")
    from .chain import HttpSink, StoreSink, keyed_by, load_chained
    from .vulns import register
    if not args.no_schema:
        register(schema(args.namespace, mapping), args.url, args.db, args.key)
    # relationship / sighting versions chain by supersession; a revocation
    # of an edge never imported has nothing to close and is dropped
    key = keyed_by("stix_id", where=lambda row: (row.attrs or {}).get("stix_type") in ("relationship", "sighting"))
    revoked = lambda claim: bool(claim.attrs.get("revoked"))      # noqa: E731
    if args.url:
        totals = load_chained(envs, HttpSink(args.url, args.key), key, args.batch, revoked, stats)
    else:
        store = _open_store(args.db)
        try:
            totals = load_chained(envs, StoreSink(store), key, args.batch, revoked, stats)
        finally:
            store.close()
    print(json.dumps({**totals, "envelopes": stats, **({"dropped_no_prior": stats.pop("dropped_no_prior")}
                                                        if "dropped_no_prior" in stats else {})}))


if __name__ == "__main__":
    main()
