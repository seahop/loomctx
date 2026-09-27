"""Nmap scan-inventory interop: an nmap XML report in, cited timestamped claims out.

    python -m loomctx.connectors.nmap import report.xml --namespace netsec             # into the LOOMCTX_DB store
    python -m loomctx.connectors.nmap import report.xml --namespace netsec --url http://loomctx:8000 --key ...
    python -m loomctx.connectors.nmap emit report.xml --namespace netsec > envelopes.jsonl
    python -m loomctx.connectors.nmap schema --namespace netsec                        # the registry it declares

What it is (and is NOT):

  This connector PARSES the XML report an operator already produced with
  `nmap -oX` on authorized scope (`docs/interop.md` has the table). It reads
  a FILE: it performs NO scanning and issues NO network probing — it is a
  parser, exactly like the STIX / OCSF / vulns connectors. It is strictly
  inventory / asset parsing: what hosts, ports, services and product /
  versions a scan report lists, as facts over time. No exploitation logic,
  no attack-path scoring, no exposure ranking — LoomCtx carries the evidence
  (the host runs this software, this port is open, this OS was guessed) and
  the reachability graph is the ordinary scope walk / `find_path` (D-067).

Decode (all into ONE namespace, `netsec` by default, so the facts join the
seed hosts and the vulns corpus), per `<host>` in the report:

  * the host entity `host:<key>` keyed by the best stable id available — the
    scan's target hostname if present, else its IPv4 / IPv6 address (the
    seed's `host:web-01` convention). Both IP and hostname ride in attrs.
  * `listens_on_port <port>` (a scalar int, the seed's own nmap port fact)
    and the richer `runs_service tcp/<port>` (attrs port / protocol / state /
    service) per OPEN port (`state=open`, and `open|filtered` with the state
    attr'd — never a closed or filtered-only port).
  * `runs_software -> product:<vendor>:<product>` from each application
    (`cpe:/a:`) CPE the service carries, keyed the SAME way the vulns
    connector keys products (vendor:product from the CPE, via the SHARED
    `vulns.parse_cpe`), so a scanned host ties into the `product <-affects-
    cve` chain NVD / KEV already build — the scan data fuses with the vuln
    data through the shared `product` node. The CPE and the raw version
    banner ride in attrs. nmap's service-DB vendor is sometimes not the CPE
    vendor NVD uses (nginx is `igor_sysoev:nginx` here, `nginx:nginx` /
    `f5:nginx_open_source` in NVD) — a real entity-resolution seam, surfaced
    honestly, resolved by D-042 like KEV's freehand names, not hidden.
  * `runs_os <osmatch name>` from the best `<osmatch>` guess, as a
    LOWER-confidence claim (below an authoritative asset-inventory source's
    1.0) so it conflicts honestly with an authoritative OS record (D-035);
    the accuracy, the osclass CPE / vendor / family ride in attrs.

Provenance & time — one synthetic scan-report DOCUMENT is emitted first
(scanner, args, start, host/service summary) with a content-addressed event
id, and every claim cites it (`provenance.artifact_event_id`, D-039); the
`observed_at` of every claim is the scan's `@start` / `@startstr` time (then
`--as-of`, then the file mtime), so re-scans over time are history and
`valid_at` / `as_of` work. Source label `nmap`. Event ids are
content-addressed (the report id embeds the scan's args + start): a
re-import of the same file is a no-op, and a later scan of the same host
records new observations (a closed port, a changed version) as history, not
duplicates.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Iterable, Iterator

from .. import coverage
from .. import identity as ident
from ..contracts import (ClaimIn, DocumentIn, EntityRef, EntityTypeDef,
                         PredicateDef, Provenance, SchemaRegistration)
from .vulns import parse_cpe as _parse_cpe_23

SOURCE_DEFAULT = "nmap"
NAMESPACE_DEFAULT = "netsec"
# An OS fingerprint is a guess; it must never read as authoritative as an
# asset-inventory record (confidence 1.0), so it can conflict honestly with
# one (D-035). Capped here and scaled from nmap's own accuracy.
OS_CONFIDENCE_CAP = 0.9
OPEN_STATES = {"open", "open|filtered"}


# ---------------------------------------------------------------- CPE / keys #

def product_key_from_cpe(cpe: str) -> tuple[str, str, str] | None:
    """(part, vendor, product) from an nmap CPE, whether the 2.2 URI form
    nmap usually emits (`cpe:/a:openbsd:openssh:10.3`) or a 2.3 string. The
    vulns connector keys products `vendor:product` from CPE 2.3 with
    `vulns.parse_cpe`; nmap's URI form is normalized to 2.3 and handed to
    that SAME parser, so a scanned `runs_software` edge lands on the identical
    `product` node NVD / KEV populate. None when there is no usable
    vendor:product."""
    cpe = (cpe or "").strip()
    if cpe.startswith("cpe:2.3:"):
        return _parse_cpe_23(cpe)
    if cpe.startswith("cpe:/"):
        fields = cpe[len("cpe:/"):].split(":")
        part = fields[0] if len(fields) > 0 else ""
        vendor = fields[1] if len(fields) > 1 else ""
        product = fields[2] if len(fields) > 2 else ""
        version = fields[3] if len(fields) > 3 else "*"
        # reuse the 2.3 parser (its vendor/product '*' and empty guards too)
        return _parse_cpe_23(f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*")
    return None


# ------------------------------------------------------------------- parsing #

def _scan_time(root: ET.Element, as_of: datetime | None, mtime: datetime | None) -> datetime:
    """The scan's start time (`@start` epoch, else `@startstr`), then
    `--as-of`, then the file mtime, then now; never in the future."""
    start = root.get("start")
    when: datetime | None = None
    if start and start.strip().isdigit():
        when = datetime.fromtimestamp(int(start), tz=timezone.utc)
    if when is None and root.get("startstr"):
        try:
            when = datetime.strptime(root.get("startstr", ""), "%a %b %d %H:%M:%S %Y").replace(
                tzinfo=timezone.utc)
        except ValueError:
            when = None
    when = when or as_of or mtime or datetime.now(timezone.utc)
    now = datetime.now(timezone.utc)
    return when if when <= now else now


def _stamp(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S")


def report_id(root: ET.Element) -> str:
    """A stable id for one scan: a digest of the command and its start, so
    re-importing the same file dedupes and a later scan is new history."""
    material = f"{root.get('args', '')}|{root.get('start', '')}|{root.get('startstr', '')}"
    return hashlib.sha256(material.encode()).hexdigest()[:16]


def _host_identity(host: ET.Element) -> tuple[str, dict] | None:
    """(entity key, attrs) for a `<host>`: the target hostname if present,
    else the IPv4 / IPv6 address (the seed's host convention). None for a
    host with no address at all. Both IP and hostname ride in attrs."""
    ipv4 = ipv6 = mac = None
    for addr in host.findall("address"):
        kind, value = addr.get("addrtype"), addr.get("addr")
        if kind == "ipv4":
            ipv4 = value
        elif kind == "ipv6":
            ipv6 = value
        elif kind == "mac":
            mac = value
    names = [hn.get("name") for hn in host.findall("hostnames/hostname") if hn.get("name")]
    user_names = [hn.get("name") for hn in host.findall("hostnames/hostname")
                  if hn.get("name") and hn.get("type") == "user"]
    hostname = (user_names or names or [None])[0]
    key = hostname or ipv4 or ipv6
    if not key:
        return None
    attrs: dict = {}
    if hostname:
        attrs["hostname"] = hostname
    if ipv4:
        attrs["ip"] = ipv4
    if ipv6:
        attrs["ip6"] = ipv6
    if mac:
        attrs["mac"] = mac
    if len(names) > 1:
        attrs["hostnames"] = names
    return key, attrs


def host_envelopes(host: ET.Element, namespace: str, observed: datetime, stamp: str,
                   rid: str, source: str, cites: Provenance) -> Iterator[ClaimIn]:
    """Every inventory claim one `<host>` yields (ports, software, OS). A host
    that is down, or has no address, yields nothing."""
    if (host.find("status") is not None and host.find("status").get("state") == "down"):
        return
    identity = _host_identity(host)
    if identity is None:
        return
    key, host_attrs = identity
    ref = EntityRef(type="host", key=key)
    yield from _inventory(host, namespace, observed, stamp, rid, source, cites, ref, host_attrs)


def _inventory(host, namespace, observed, stamp, rid, source, cites, ref, host_attrs):
    """The host's claims, then — only when it has any (an up host with no
    open port yields nothing, as before) — what the scan calls it, for
    resolution across tools (D-083); the address is a time-stamped link,
    never an identifier. Every claim cites the scan report."""
    claims = list(_host_facts(host, namespace, observed, stamp, rid, source, cites, ref, host_attrs))
    if not claims:
        return
    yield from claims
    names = [host_attrs.get("hostname"), *host_attrs.get("hostnames", [])]
    yield from ident.claims(namespace, ref, [("fqdn" if "." in n else "hostname", n)
                                             for n in names if n]
                            + [("mac", host_attrs.get("mac"))], observed, source, {"scan": rid},
                            provenance=cites)
    yield from ident.ip_claims(namespace, ref, [host_attrs.get("ip"), host_attrs.get("ip6")],
                               observed, source, {"scan": rid}, provenance=cites)


def _host_facts(host, namespace, observed, stamp, rid, source, cites, ref, host_attrs):
    key = ref.key
    prefix = f"nmap:{rid}:{key}"

    def claim(pred: str, obj, tag: str = "", **kw) -> ClaimIn:
        attrs = {"scan": rid, **host_attrs, **kw.pop("attrs", {})}
        return ClaimIn(namespace=namespace, event_id=f"{prefix}:{pred}{tag}"[:128], subject=ref,
                       predicate=pred, object=obj, observed_at=observed, valid_from=observed,
                       source=source, provenance=cites, attrs=attrs, **kw)

    seen_software: set[str] = set()
    for port in host.findall("ports/port"):
        state_el = port.find("state")
        state = state_el.get("state") if state_el is not None else None
        if state not in OPEN_STATES:
            continue                        # closed / filtered / no state: not an open service
        proto = port.get("protocol") or "tcp"
        portid = port.get("portid") or ""
        if not portid.isdigit():
            continue
        svc = port.find("service")
        svc_name = svc.get("name") if svc is not None else None
        product = svc.get("product") if svc is not None else None
        version = svc.get("version") if svc is not None else None
        port_attrs = {"port": int(portid), "protocol": proto, "state": state}
        if svc_name:
            port_attrs["service"] = svc_name
        if product:
            port_attrs["product"] = product
        # the seed's own nmap fact (scalar port int) so scan data lines up
        # with the seed's `listens_on_port` observations, and the richer one
        yield claim("listens_on_port", int(portid), f":{proto}:{portid}", attrs=port_attrs)
        yield claim("runs_service", f"{proto}/{portid}", f":{proto}:{portid}", attrs=port_attrs)
        # runs_software from each application CPE the service carries — the
        # fusion edge into the vuln graph's product node
        if svc is None:
            continue
        for cpe_el in svc.findall("cpe"):
            parsed = product_key_from_cpe(cpe_el.text or "")
            if parsed is None or parsed[0] != "a":     # applications only; OS cpe -> runs_os
                continue
            _part, vendor, prod = parsed
            pkey = f"{vendor}:{prod}"
            if pkey in seen_software:
                continue
            seen_software.add(pkey)
            attrs = {"cpe": (cpe_el.text or "").strip(), "port": int(portid)}
            if version:
                attrs["version"] = version
            if product:
                attrs["product"] = product
            yield claim("runs_software", EntityRef(type="product", key=pkey), f":{pkey}", attrs=attrs)

    # the OS guess: the best (first, highest-accuracy) osmatch, lower
    # confidence so it conflicts honestly with an authoritative inventory
    osmatch = host.find("os/osmatch")
    if osmatch is not None and osmatch.get("name"):
        accuracy = osmatch.get("accuracy")
        conf = OS_CONFIDENCE_CAP
        if accuracy and accuracy.isdigit():
            conf = min(OS_CONFIDENCE_CAP, int(accuracy) / 100.0)
        attrs: dict = {}
        if accuracy:
            attrs["accuracy"] = int(accuracy) if accuracy.isdigit() else accuracy
        osclass = osmatch.find("osclass")
        if osclass is not None:
            for src, dst in (("vendor", "os_vendor"), ("osfamily", "osfamily"), ("osgen", "osgen")):
                if osclass.get(src):
                    attrs[dst] = osclass.get(src)
            cpe_el = osclass.find("cpe")
            if cpe_el is not None and cpe_el.text:
                attrs["cpe"] = cpe_el.text.strip()
        yield claim("runs_os", osmatch.get("name"), confidence=conf, attrs=attrs)


def report_document(root: ET.Element, namespace: str, observed: datetime, rid: str,
                    source: str, hosts_up: int, services: int) -> DocumentIn:
    """A compact record of the scan every claim cites (D-039): the scanner,
    its arguments and start, and what it found. The claims' anchor, and
    something real for excerpt retrieval to quote."""
    text = "\n".join([
        f"nmap scan report {rid}",
        f"scanner: {root.get('scanner', 'nmap')} {root.get('version', '')}".strip(),
        f"arguments: {root.get('args', '')}",
        f"started: {root.get('startstr') or observed.isoformat()}",
        f"hosts up: {hosts_up}; open services: {services}",
    ])
    return DocumentIn(namespace=namespace, event_id=f"nmap:{rid}:report"[:128],
                      filename=f"nmap-{rid}.txt", text=text, source=source,
                      observed_at=observed, attrs={"scan": rid, "scanner": root.get("scanner", "nmap")})


def report_to_envelopes(text: str, namespace: str, source: str = SOURCE_DEFAULT,
                        as_of: datetime | None = None, mtime: datetime | None = None,
                        stats: dict[str, int] | None = None) -> Iterator[ClaimIn | DocumentIn]:
    """Every envelope one nmap XML report yields: the scan document first,
    then each host's claims citing it (D-039). A host that cannot be parsed
    is counted (`host_invalid`) and skipped, not the whole report."""
    stats = stats if stats is not None else {}
    root = ET.fromstring(text)
    if root.tag != "nmaprun":
        raise ValueError(f"not an nmap XML report (root is <{root.tag}>)")
    observed = _scan_time(root, as_of, mtime)
    stamp = _stamp(observed)
    rid = report_id(root)
    cites = Provenance(artifact_event_id=f"nmap:{rid}:report"[:128])

    # materialize per host so one malformed host does not end the report; the
    # document is emitted first so the claims can cite it (D-039)
    per_host: list[list[ClaimIn]] = []
    services = 0
    hosts_up = 0
    shapes = coverage.Shapes()
    for host in root.findall("host"):
        shapes.add("nmap:host", [c.tag for c in host]
                   + [f"service.{a}" for svc in host.findall("ports/port/service") for a in svc.attrib])
        try:
            envs = list(host_envelopes(host, namespace, observed, stamp, rid, source, cites))
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            stats["host_invalid"] = stats.get("host_invalid", 0) + 1
            print(f"nmap host: skipped: {str(exc).splitlines()[0][:200]}", file=sys.stderr)
            continue
        if not envs:
            stats["host_empty"] = stats.get("host_empty", 0) + 1
            continue
        hosts_up += 1
        services += sum(1 for e in envs if e.predicate == "runs_service")
        per_host.append(envs)

    yield report_document(root, namespace, observed, rid, source, hosts_up, services)
    stats["document"] = stats.get("document", 0) + 1
    for envs in per_host:
        for env in envs:
            stats["claim"] = stats.get("claim", 0) + 1
            yield env
    yield from shapes.claims(namespace, source, observed)


# ------------------------------------------------------------------- schema #

def schema(namespace: str) -> SchemaRegistration:
    """The registry this connector declares. Not strict: the seed's own host
    facts and the vulns connector's `product` / `affects` share the
    namespace, and `runs_software` deliberately reuses the vulns vocabulary
    (object `product`, containment) so a scanned edge and NVD's `affects`
    meet at one product node."""
    return SchemaRegistration(
        namespace=namespace,
        entity_types=[
            EntityTypeDef(name="host", description="a scanned host (target hostname, else IP)"),
            *ident.SCHEMA_TYPES, coverage.ENTITY_TYPE,
            EntityTypeDef(name="product", description="software, keyed vendor:product as in CPE 2.3 "
                          "(the same node loomctx.connectors.vulns / OCSF / STIX write to)"),
        ],
        predicates=[
            *ident.SCHEMA_PREDICATES, *coverage.SCHEMA_PREDICATES,
            PredicateDef(name="listens_on_port", description="an open port (scalar int; the seed's "
                         "own nmap port fact)"),
            PredicateDef(name="runs_service", description="an open service as proto/port; attrs carry "
                         "port, protocol, state (open / open|filtered), service name and product"),
            PredicateDef(name="runs_software", object_types=["product"], containment=True,
                         description="a host runs this product, keyed vendor:product from the service "
                         "CPE (fuses with the vuln graph's product node); attrs carry cpe and version"),
            PredicateDef(name="runs_os", description="the nmap OS-match guess (lower confidence than an "
                         "authoritative asset inventory, so it conflicts honestly, D-035)"),
        ],
    )


# ---------------------------------------------------------------------- CLI #

def _to_lines(envs: Iterable[ClaimIn | DocumentIn]) -> Iterator[str]:
    for env in envs:
        yield env.model_dump_json(exclude_none=True) + "\n"


def _read_report(path: str) -> tuple[str, datetime | None]:
    if path == "-":
        return sys.stdin.read(), None
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    mtime = datetime.fromtimestamp(os.stat(path).st_mtime, tz=timezone.utc).replace(microsecond=0)
    return text, mtime


def main(argv: list[str] | None = None) -> None:
    import json

    parser = argparse.ArgumentParser(prog="loomctx.connectors.nmap", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--namespace", default=NAMESPACE_DEFAULT)
    common.add_argument("--source", default=SOURCE_DEFAULT, help="source / scan label")
    common.add_argument("--as-of", dest="as_of",
                        help="ISO scan timestamp when the report carries no start time")
    sub = parser.add_subparsers(dest="command", required=True)
    imp = sub.add_parser("import", parents=[common], help="parse an nmap XML report and ingest it")
    imp.add_argument("report", help="an nmap -oX XML report, or - for stdin")
    imp.add_argument("--url", help="engine or gateway base URL (default: write straight into the store)")
    imp.add_argument("--db", help="write straight into this explicit store URL/path")
    imp.add_argument("--key", default=os.environ.get("LOOMCTX_API_KEY"), type=str.strip)
    imp.add_argument("--batch", type=int, default=500)
    imp.add_argument("--no-schema", action="store_true", help="skip the registry registration")
    emit = sub.add_parser("emit", parents=[common], help="write NDJSON envelopes to stdout")
    emit.add_argument("report")
    sub.add_parser("schema", parents=[common], help="print the schema registration")
    args = parser.parse_args(argv)

    if args.command == "schema":
        print(schema(args.namespace).model_dump_json(indent=2))
        return

    as_of = None
    if args.as_of:
        as_of = datetime.fromisoformat(args.as_of.replace("Z", "+00:00"))
        as_of = as_of if as_of.tzinfo else as_of.replace(tzinfo=timezone.utc)
    text, mtime = _read_report(args.report)
    stats: dict[str, int] = {}
    envs = report_to_envelopes(text, args.namespace, args.source, as_of, mtime, stats)

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
    watch = coverage.Watch()
    lines = _to_lines(watch.wrap(envs))
    totals = (post_batches(args.url, lines, args.batch, args.key) if args.url
              else load_direct(args.db, lines, args.batch))
    drift = watch.report(args.url, args.db, args.key)
    print(json.dumps({**totals, "envelopes": stats, "drift": [d.text() for d in drift]}))
    coverage.print_drift(drift)
    fail_on_refusals(totals, remote=bool(args.url))   # a refusal fails the load (D-063, S-36)


if __name__ == "__main__":
    main()
