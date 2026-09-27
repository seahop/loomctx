"""Cloud inventory / config interop: a cloud resource export in, cited
timestamped inventory claims out.

    python -m loomctx.connectors.cloud import state.tfstate.json --format terraform --namespace netsec
    python -m loomctx.connectors.cloud import snapshot.json --format awsconfig --namespace netsec --url http://loomctx:8000 --key ...
    python -m loomctx.connectors.cloud emit state.json --format terraform --namespace netsec > envelopes.jsonl
    python -m loomctx.connectors.cloud schema --namespace netsec

What it is (and is NOT):

  This connector PARSES a resource inventory an operator already exported.
  It reads a FILE and calls NO cloud API — it is a parser, exactly like the
  STIX / OCSF / nmap / OSV connectors. It is strictly inventory / config-as-
  facts: which resources exist, their key attributes, and how they relate
  (an instance in a subnet in a VPC, a security group attached to an
  instance), as facts over time. No exploitation logic, no attack-path
  scoring, no exposure ranking — LoomCtx carries the evidence (this resource
  exists, this security group allows tcp/3389, this instance is in that
  subnet) and reachability stays the ordinary scope walk / `find_path`
  (D-067). Re-importing a later snapshot records drift (a port that opened,
  a resource that appeared or disappeared) as HISTORY, never an overwrite.

Two real, file-based inputs (`--format`):

  * `terraform` — a `terraform show -json` / `.tfstate` JSON export. Each
    managed resource in the root module and every child module becomes an
    entity keyed by its Terraform address (`aws_instance.web`,
    `module.net.aws_subnet.a`); `depends_on` becomes `depends_on` edges, and
    an attribute whose value is another resource's `id` / `arn` becomes a
    reference edge (`in_subnet` / `in_vpc` / `attached_to`, else
    `references`). Top-level scalar attributes become scalar claims.
  * `awsconfig` — an AWS Config configuration snapshot (`configurationItems`)
    or a single configuration item. Each item becomes an entity keyed by its
    resource id; `relationships[]` become edges (`in_subnet`, `in_vpc`,
    `attached_to`, `member_of`, else a slug of the relationship name); the
    `configuration` scalars become scalar claims, and a security group's
    `ipPermissions[]` become `allows_ingress` claims (so an opened port shows
    as drift). An `in_account` edge ties every resource to its
    `cloud_account`.

Entity types are kept small and generic: `vpc`, `subnet`, `security_group`,
`cloud_account`, and `resource` for everything else (the mapping is in
`_TF_ENTITY` / `_AWS_ENTITY`; `docs/interop.md` has the table).

Provenance & time — one synthetic snapshot DOCUMENT is emitted first (the
format, the resource counts, the snapshot id) with a content-addressed event
id, and every claim cites it (`provenance.artifact_event_id`, D-039). The
`observed_at` of every claim is the snapshot time — AWS Config's
`configurationItemCaptureTime`, else `--as-of`, else the file mtime — so
re-imports over time are history and `valid_at` / `as_of` work. Event ids are
content-addressed on the export (a re-import of the same file is a no-op; a
changed export is new history). Source label `cloud`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

from .. import identity as ident
from ..contracts import (ClaimIn, DocumentIn, EntityRef, EntityTypeDef,
                         PredicateDef, Provenance, SchemaRegistration)

SOURCE_DEFAULT = "cloud"
NAMESPACE_DEFAULT = "netsec"   # one namespace per environment (D-083)
FORMATS = ("terraform", "awsconfig")

# Resource-type -> entity-type maps, kept deliberately small and generic. The
# last "::" segment (AWS Config) or the terraform type is matched; anything
# unmatched is the generic `resource`.
_TF_ENTITY = {
    "aws_vpc": "vpc", "google_compute_network": "vpc", "azurerm_virtual_network": "vpc",
    "aws_subnet": "subnet", "google_compute_subnetwork": "subnet", "azurerm_subnet": "subnet",
    "aws_security_group": "security_group", "google_compute_firewall": "security_group",
    "azurerm_network_security_group": "security_group",
}
_AWS_ENTITY = {"vpc": "vpc", "subnet": "subnet", "securitygroup": "security_group"}

# A resolved reference edge's predicate follows the TARGET entity type (so the
# type-constrained in_subnet/in_vpc only ever point at a subnet/vpc); anything
# else lands as a generic `references` edge.
_REF_BY_TYPE = {"subnet": "in_subnet", "vpc": "in_vpc", "security_group": "attached_to"}
_MAX_ATTR_STR = 1024        # a scalar attribute longer than this rides only in the doc
_MAX_ATTRS = 64             # scalar attribute claims per resource (bound the fan-out)


# ------------------------------------------------------------------- helpers #

def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def _tag(predicate: str, obj: Any) -> str:
    """A short, stable event-id suffix for one (predicate, object) pair."""
    if isinstance(obj, EntityRef):
        raw = f"{predicate}:{obj.type}:{obj.key}"
    else:
        raw = f"{predicate}:{obj}"
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]


def _clamp(when: datetime) -> datetime:
    now = datetime.now(timezone.utc)
    return when if when <= now else now


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _scalar_attrs(config: dict) -> dict[str, Any]:
    """Top-level scalar entries of a config/values block, dropping None,
    empty strings and over-long strings (those stay in the snapshot doc)."""
    out: dict[str, Any] = {}
    for key, value in config.items():
        if isinstance(value, bool) or isinstance(value, (int, float)):
            out[key] = value
        elif isinstance(value, str) and value and len(value) <= _MAX_ATTR_STR:
            out[key] = value
    return out


# --------------------------------------------------------------- terraform #

_INSTANCE_TYPES = ("aws_instance", "AWS::EC2::Instance")


def _instance_identity(namespace: str, ref: EntityRef, values: dict, observed: datetime,
                       source: str) -> list[ClaimIn]:
    """What other tools call a compute instance (D-083): its instance id, DNS
    names and interface MACs, so a scan or an EDR event naming the machine
    folds into it; its addresses as time-stamped `has_ip` links."""
    get = values.get
    pairs = [("cloud_id", get("id") or get("instanceId"))]
    for key in ("private_dns", "public_dns", "privateDnsName", "publicDnsName"):
        pairs.append(("fqdn", get(key)))
    for nic in (get("networkInterfaces") or get("network_interface") or []):
        if isinstance(nic, dict):
            pairs.append(("mac", nic.get("macAddress") or nic.get("mac_address")))
    ips = [get(k) for k in ("private_ip", "public_ip", "privateIpAddress", "publicIpAddress")]
    return ident.claims(namespace, ref, pairs, observed, source) + ident.ip_claims(
        namespace, ref, ips, observed, source)


def _tf_entity(rtype: str, address: str) -> EntityRef:
    return EntityRef(type=_TF_ENTITY.get(rtype, "resource"), key=address)


def _tf_resources(module: dict, path: str = "") -> Iterator[tuple[dict, str]]:
    """Every managed resource in a terraform state module tree, with the
    module address it lives under ('' for the root)."""
    for res in module.get("resources", []) or []:
        if res.get("mode", "managed") == "managed":
            yield res, path
    for child in module.get("child_modules", []) or []:
        yield from _tf_resources(child, child.get("address", path))


def _iter_ref_values(values: dict) -> Iterator[tuple[str, str]]:
    """(attribute key, string value) pairs, one level into nested dicts (a
    terraform `triggers` / `keepers` map), for reference detection."""
    for key, value in values.items():
        if isinstance(value, str):
            yield key, value
        elif isinstance(value, dict):
            for sub, subval in value.items():
                if isinstance(subval, str):
                    yield sub, subval


def terraform_to_envelopes(text: str, namespace: str, source: str,
                           as_of: datetime | None, mtime: datetime | None,
                           stats: dict[str, int] | None = None) -> Iterator[ClaimIn | DocumentIn]:
    """Every envelope one terraform state export yields: the snapshot document
    first, then each resource's claims (a `resource_type` anchor, its scalar
    attributes, and its `depends_on` / reference edges) citing it (D-039)."""
    stats = stats if stats is not None else {}
    data = json.loads(text)
    root = (data.get("values") or {}).get("root_module")
    if root is None:
        raise ValueError("not a terraform state export (no values.root_module)")
    observed = _clamp(as_of or mtime or datetime.now(timezone.utc))
    snap = _digest(text)
    cites = Provenance(artifact_event_id=f"cloud:{snap}:snapshot"[:128])

    resources = list(_tf_resources(root))
    # id/arn index for value-based reference edges (an instance referencing a
    # subnet's id -> in_subnet), so referenced ids become edges (spec).
    id_index: dict[str, EntityRef] = {}
    for res, path in resources:
        ref = _tf_entity(res.get("type", ""), res.get("address", ""))
        for idkey in ("id", "arn"):
            val = (res.get("values") or {}).get(idkey)
            if isinstance(val, str) and val:
                id_index.setdefault(val, ref)

    yield _snapshot_document(namespace, snap, observed, source, "terraform",
                             {"resources": len(resources)})
    stats["document"] = stats.get("document", 0) + 1

    for res, _path in resources:
        rtype = res.get("type", "")
        address = res.get("address", "")
        if not rtype or not address:
            stats["resource_invalid"] = stats.get("resource_invalid", 0) + 1
            continue
        ref = _tf_entity(rtype, address)
        base_attrs = {"snapshot": snap, "resource_type": rtype, "address": address,
                      "provider": res.get("provider_name", "")}

        def claim(pred: str, obj: Any, **kw) -> ClaimIn:
            attrs = {**base_attrs, **kw.pop("attrs", {})}
            return ClaimIn(namespace=namespace, event_id=f"cloud:{snap}:{address}:{_tag(pred, obj)}"[:128],
                           subject=ref, predicate=pred, object=obj, observed_at=observed,
                           valid_from=observed, source=source, provenance=cites, attrs=attrs, **kw)

        yield claim("resource_type", rtype)
        stats["claim"] = stats.get("claim", 0) + 1
        if rtype in _INSTANCE_TYPES:
            yield from _instance_identity(namespace, ref, res.get("values") or {}, observed, source)
        # scalar attributes as scalar claims
        for n, (key, value) in enumerate(_scalar_attrs(res.get("values") or {}).items()):
            if n >= _MAX_ATTRS:
                break
            if key in ("id", "arn"):        # identity, already the entity key
                continue
            yield claim(f"attr:{key}", value)
            stats["claim"] = stats.get("claim", 0) + 1
        # depends_on edges
        for dep in res.get("depends_on", []) or []:
            target = id_index.get(dep)      # rarely an id; usually an address
            obj = target or EntityRef(type="resource", key=dep)
            yield claim("depends_on", obj)
            stats["claim"] = stats.get("claim", 0) + 1
        # value-based reference edges (an attribute equal to another resource's id)
        seen_refs: set[tuple[str, str]] = set()
        for attr_key, value in _iter_ref_values(res.get("values") or {}):
            target = id_index.get(value)
            if target is None or target == ref:
                continue
            # the predicate follows the target's entity type, so in_subnet /
            # in_vpc only ever point at a subnet / vpc (their object_types are
            # enforced even in a non-strict namespace); everything else is a
            # generic `references` edge.
            pred = _REF_BY_TYPE.get(target.type, "references")
            marker = (pred, target.key)
            if marker in seen_refs:
                continue
            seen_refs.add(marker)
            yield claim(pred, target, attrs={"via": attr_key})
            stats["claim"] = stats.get("claim", 0) + 1


# --------------------------------------------------------------- aws config #

def _aws_entity(rtype: str, rid: str) -> EntityRef:
    last = (rtype or "").split("::")[-1].lower()
    return EntityRef(type=_AWS_ENTITY.get(last, "resource"), key=rid)


def _rel_predicate(name: str) -> str | None:
    """An AWS Config relationship name -> an edge predicate. 'Contains X'
    relations are dropped (their inverse 'Is contained in X' rides the other
    resource, so the edge is not duplicated)."""
    low = (name or "").lower()
    if low.startswith("contains"):
        return None
    if "subnet" in low and "contained in" in low:
        return "in_subnet"
    if "vpc" in low and "contained in" in low:
        return "in_vpc"
    if "securitygroup" in low or "security group" in low:
        return "attached_to"
    if "contained in" in low:
        return "member_of"
    if "attached to" in low or "associated with" in low:
        return "attached_to"
    slug = "".join(c if c.isalnum() else "_" for c in low).strip("_")
    return slug or None


def _config_items(data: Any) -> list[dict]:
    if isinstance(data, dict) and isinstance(data.get("configurationItems"), list):
        return data["configurationItems"]
    if isinstance(data, dict) and data.get("resourceType"):
        return [data]
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    raise ValueError("not an AWS Config export (no configurationItems / resourceType)")


def _ingress_rules(config: dict) -> Iterator[str]:
    """A security group's ipPermissions[] as compact `proto/from-to` tokens,
    so an opened port shows up as a new `allows_ingress` claim over time."""
    for perm in config.get("ipPermissions", []) or []:
        proto = perm.get("ipProtocol", "-")
        proto = "any" if proto in ("-1", -1) else proto
        frm, to = perm.get("fromPort"), perm.get("toPort")
        if frm is None and to is None:
            yield f"{proto}/all"
        elif frm == to:
            yield f"{proto}/{frm}"
        else:
            yield f"{proto}/{frm}-{to}"


def awsconfig_to_envelopes(text: str, namespace: str, source: str,
                           as_of: datetime | None, mtime: datetime | None,
                           stats: dict[str, int] | None = None) -> Iterator[ClaimIn | DocumentIn]:
    """Every envelope one AWS Config export yields: the snapshot document
    first, then each configuration item's claims (a `resource_type` anchor,
    its config scalars, its `relationships[]` edges, its `in_account` edge,
    and a security group's `allows_ingress` rules) citing it (D-039)."""
    stats = stats if stats is not None else {}
    items = _config_items(json.loads(text))
    snap = _digest(text)
    cites = Provenance(artifact_event_id=f"cloud:{snap}:snapshot"[:128])

    yield _snapshot_document(namespace, snap, _clamp(as_of or mtime or datetime.now(timezone.utc)),
                             source, "awsconfig", {"resources": len(items)})
    stats["document"] = stats.get("document", 0) + 1

    for item in items:
        rid = item.get("resourceId") or item.get("arn")
        rtype = item.get("resourceType", "")
        if not rid or not rtype:
            stats["resource_invalid"] = stats.get("resource_invalid", 0) + 1
            continue
        # each item carries its own capture time -> observed_at (drift over time)
        observed = _clamp(_parse_time(item.get("configurationItemCaptureTime"))
                          or as_of or mtime or datetime.now(timezone.utc))
        ref = _aws_entity(rtype, rid)
        account = item.get("accountId") or item.get("awsAccountId")
        base_attrs = {"snapshot": snap, "resource_type": rtype, "arn": item.get("arn", ""),
                      "region": item.get("awsRegion", "")}
        if item.get("availabilityZone"):
            base_attrs["az"] = item["availabilityZone"]
        if isinstance(item.get("tags"), dict) and item["tags"]:
            base_attrs["tags"] = item["tags"]

        def claim(pred: str, obj: Any, **kw) -> ClaimIn:
            attrs = {**base_attrs, **kw.pop("attrs", {})}
            return ClaimIn(namespace=namespace, event_id=f"cloud:{snap}:{rid}:{_tag(pred, obj)}"[:128],
                           subject=ref, predicate=pred, object=obj, observed_at=observed,
                           valid_from=observed, source=source, provenance=cites, attrs=attrs, **kw)

        yield claim("resource_type", rtype)
        stats["claim"] = stats.get("claim", 0) + 1
        if account:
            yield claim("in_account", EntityRef(type="cloud_account", key=account))
            stats["claim"] = stats.get("claim", 0) + 1
        config = item.get("configuration") if isinstance(item.get("configuration"), dict) else {}
        if rtype in _INSTANCE_TYPES:
            yield from _instance_identity(namespace, ref, {"instanceId": rid, **config}, observed, source)
        for n, (key, value) in enumerate(_scalar_attrs(config).items()):
            if n >= _MAX_ATTRS:
                break
            yield claim(f"attr:{key}", value)
            stats["claim"] = stats.get("claim", 0) + 1
        for rule in _ingress_rules(config):
            yield claim("allows_ingress", rule)
            stats["claim"] = stats.get("claim", 0) + 1
        seen_edges: set[tuple[str, str]] = set()
        for rel in item.get("relationships", []) or []:
            pred = _rel_predicate(rel.get("name") or rel.get("relationshipName") or "")
            target_id = rel.get("resourceId")
            if not pred or not target_id:
                continue
            target = _aws_entity(rel.get("resourceType", ""), target_id)
            marker = (pred, target.key)
            if marker in seen_edges:
                continue
            seen_edges.add(marker)
            yield claim(pred, target)
            stats["claim"] = stats.get("claim", 0) + 1


# ------------------------------------------------------------------ shared #

def _snapshot_document(namespace: str, snap: str, observed: datetime, source: str,
                       fmt: str, counts: dict[str, int]) -> DocumentIn:
    """A compact record of the export every claim cites (D-039)."""
    text = "\n".join([
        f"cloud {fmt} snapshot {snap}",
        f"format: {fmt}",
        f"resources: {counts.get('resources', 0)}",
        f"observed: {observed.isoformat()}",
    ])
    return DocumentIn(namespace=namespace, event_id=f"cloud:{snap}:snapshot"[:128],
                      filename=f"cloud-{fmt}-{snap}.txt", text=text, source=source,
                      observed_at=observed, attrs={"snapshot": snap, "format": fmt})


def to_envelopes(text: str, fmt: str, namespace: str, source: str = SOURCE_DEFAULT,
                 as_of: datetime | None = None, mtime: datetime | None = None,
                 stats: dict[str, int] | None = None) -> Iterator[ClaimIn | DocumentIn]:
    if fmt == "terraform":
        return terraform_to_envelopes(text, namespace, source, as_of, mtime, stats)
    if fmt == "awsconfig":
        return awsconfig_to_envelopes(text, namespace, source, as_of, mtime, stats)
    raise ValueError(f"unknown --format {fmt!r} (use one of {', '.join(FORMATS)})")


# ------------------------------------------------------------------- schema #

def schema(namespace: str) -> SchemaRegistration:
    """The registry this connector declares. Not strict: cloud inventory joins
    whatever else lives in the namespace, and the containment edges
    (`in_subnet` / `in_vpc` / `in_account` / `member_of`) are marked so a
    scope with no explicit `expand` walks them (D-012/D-024)."""
    return SchemaRegistration(
        namespace=namespace,
        entity_types=[
            *ident.SCHEMA_TYPES,
            EntityTypeDef(name="resource", description="a cloud resource, keyed by its terraform "
                          "address or its cloud resource id / ARN"),
            EntityTypeDef(name="vpc", description="a virtual network (aws_vpc, google_compute_network, ...)"),
            EntityTypeDef(name="subnet", description="a subnet of a vpc"),
            EntityTypeDef(name="security_group", description="a security group / firewall / NSG"),
            EntityTypeDef(name="cloud_account", description="the account/project a resource belongs to"),
        ],
        predicates=[
            *ident.SCHEMA_PREDICATES,
            PredicateDef(name="resource_type", description="the cloud/terraform resource type "
                         "(anchors the entity; attrs carry region, arn, tags)"),
            PredicateDef(name="in_subnet", object_types=["subnet"], containment=True,
                         description="the resource is in this subnet"),
            PredicateDef(name="in_vpc", object_types=["vpc"], containment=True,
                         description="the resource is in this vpc"),
            PredicateDef(name="in_account", object_types=["cloud_account"], containment=True,
                         description="the resource belongs to this cloud account/project"),
            PredicateDef(name="member_of", containment=True,
                         description="a generic containment edge from a config relationship"),
            PredicateDef(name="attached_to", description="attached / associated with another resource "
                         "(e.g. a security group on an instance)"),
            PredicateDef(name="depends_on", description="a terraform depends_on edge"),
            PredicateDef(name="references", description="an attribute value equal to another resource's "
                         "id / arn (a resolved reference)"),
            PredicateDef(name="allows_ingress", description="a security-group ingress rule as proto/port "
                         "(a new one over time is an opened port, recorded as history)"),
        ],
    )


# ---------------------------------------------------------------------- CLI #

def _to_lines(envs: Iterable[ClaimIn | DocumentIn]) -> Iterator[str]:
    for env in envs:
        yield env.model_dump_json(exclude_none=True) + "\n"


def _read(path: str) -> tuple[str, datetime | None]:
    if path == "-":
        return sys.stdin.read(), None
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    mtime = datetime.fromtimestamp(os.stat(path).st_mtime, tz=timezone.utc).replace(microsecond=0)
    return text, mtime


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loomctx.connectors.cloud", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--namespace", default=NAMESPACE_DEFAULT)
    common.add_argument("--source", default=SOURCE_DEFAULT, help="source / snapshot label")
    common.add_argument("--format", dest="fmt", choices=FORMATS, required=True,
                        help="the export format to parse")
    common.add_argument("--as-of", dest="as_of",
                        help="ISO snapshot timestamp when the export carries no time")
    sub = parser.add_subparsers(dest="command", required=True)
    imp = sub.add_parser("import", parents=[common], help="parse a cloud export and ingest it")
    imp.add_argument("path", help="the export file, or - for stdin")
    imp.add_argument("--url", help="engine or gateway base URL (default: write straight into the store)")
    imp.add_argument("--db", help="write straight into this explicit store URL/path")
    imp.add_argument("--key", default=os.environ.get("LOOMCTX_API_KEY"), type=str.strip)
    imp.add_argument("--batch", type=int, default=500)
    imp.add_argument("--no-schema", action="store_true", help="skip the registry registration")
    emit = sub.add_parser("emit", parents=[common], help="write NDJSON envelopes to stdout")
    emit.add_argument("path")
    sch = sub.add_parser("schema", help="print the schema registration")
    sch.add_argument("--namespace", default=NAMESPACE_DEFAULT)
    args = parser.parse_args(argv)

    if args.command == "schema":
        print(schema(args.namespace).model_dump_json(indent=2))
        return

    as_of = None
    if args.as_of:
        as_of = datetime.fromisoformat(args.as_of.replace("Z", "+00:00"))
        as_of = as_of if as_of.tzinfo else as_of.replace(tzinfo=timezone.utc)
    text, mtime = _read(args.path)
    stats: dict[str, int] = {}
    envs = to_envelopes(text, args.fmt, args.namespace, args.source, as_of, mtime, stats)

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
