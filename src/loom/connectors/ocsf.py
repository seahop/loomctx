"""OCSF interop (hardening R-8): Vulnerability Finding (class_uid 2002) in and out.

    python -m loom.connectors.ocsf import findings.ndjson --namespace netsec               # into the LOOM_DB store
    python -m loom.connectors.ocsf import findings.ndjson --namespace netsec --url http://loom:8000 --key ...
    python -m loom.connectors.ocsf export --namespace netsec --out findings.ndjson         # cve facts as findings
    python -m loom.connectors.ocsf emit findings.ndjson --namespace netsec > envelopes.jsonl
    python -m loom.connectors.ocsf schema --namespace netsec

Import handles two shapes of OCSF finding (`docs/interop.md` has both tables):

Detections (D-071) — a `detection_finding` (class 2004), `security_finding`
(2001) or `incident_finding` (2005), the finding classes a SIEM / EDR / XDR
emits, becomes a `finding:<uid>` entity that:
  * carries its `title` (a scalar claim on the finding);
  * relates to the host it concerns via `detected_on -> host:<key>`, the host
    resolved from the OCSF device / endpoint / resource by the SAME hostname-
    else-IP convention the seed and nmap connector use — so a detection on
    `web-01` attaches to the same `host:web-01` the vuln / scan data uses;
  * relates to each CVE it references via `references -> cve:<id>`, fusing on
    the same `cve:` node NVD/KEV/OCSF-vuln/STIX/OSV write to;
  * the edges carry status/severity in attrs and chain by `finding_uid`
    (D-050/chain.py): a New->In Progress->Resolved transition supersedes the
    prior state (not a conflict), and Resolved/Close sets `valid_to` while
    Suppressed does NOT (a muted finding is still active).

Import — one `vulnerability_finding` event (a scanner's, a cloud
provider's, a SIEM's) becomes claims on the affected host and the CVE:

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
`vulnerability_finding` records, one per finding on a (host, cve) pair —
or per CVE with no host — with cvss/epss/severity/exploit flags gathered
from the CVE's scalar facts and every contributing observation id listed
under `unmapped.loom_observation_ids` for citation. A finding's versions
(chained by `supersedes`, or sharing an imported `finding_uid`) share
`finding_info.uid`; only the newest is written — its state and status —
unless `export --history` (Create, Update..., Close), so re-importing an
export into the store it came from adds no finding versions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Iterator

from .. import coverage
from .. import identity as ident
from ..contracts import (ClaimIn, DocumentIn, EntityRef, EntityTypeDef, Observation,
                         PredicateDef, SchemaRegistration)
from .chain import aware, supersession, version_key

CLASS_UID = 2002
CATEGORY_UID = 2
CLASS_NAME = "Vulnerability Finding"
CATEGORY_NAME = "Findings"
OCSF_VERSION = "1.3.0"
SOURCE_DEFAULT = "ocsf"
PRODUCT_NAME = "Loom"
PRED_AFFECTED = "affected_by"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# The detection/finding classes a SIEM / EDR / XDR emits alongside vuln
# findings (D-071). They share the base Finding fields (device, resources,
# finding_info, status/status_id, activity_id, time) and detection_finding
# carries an optional vulnerabilities[] block, so a detection lands as a
# `finding:<uid>` entity related to the host it concerns and to any CVE it
# references — in the SAME graph the vuln / scan data uses.
DETECTION_CLASS = {2001: "Security Finding", 2004: "Detection Finding", 2005: "Incident Finding"}
DETECTION_CLASS_UIDS = frozenset(DETECTION_CLASS)
PRED_DETECTED_ON = "detected_on"     # finding -> the host it concerns (lifecycle carrier)
PRED_REFERENCES = "references"       # finding -> a CVE it references (fuses on the cve node)
PRED_TITLE = "title"                 # the finding's own title (scalar, on the finding entity)
PRED_INDICATES = "indicates"         # finding -> the ATT&CK technique it maps to (D-086)
_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")


def technique_refs(event: dict) -> list[str]:
    """ATT&CK technique ids a detection maps to (`finding_info.attacks[]`,
    or the older top-level `attacks[]`): the sub-technique when given, else
    the technique — keyed as the ATT&CK connector keys them."""
    info = event.get("finding_info") if isinstance(event.get("finding_info"), dict) else {}
    out: list[str] = []
    for attack in (info.get("attacks") or event.get("attacks") or []):
        if not isinstance(attack, dict):
            continue
        for part in ("sub_technique", "technique"):
            uid = str((attack.get(part) or {}).get("uid") or "").strip().upper()
            if _TECHNIQUE.match(uid):
                if uid not in out:
                    out.append(uid)
                break
    return out

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
STATUS_BY_NAME = {name: sid for sid, name in STATUS.items()}
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


def device_identity(event: dict, namespace: str, host: str, observed: datetime,
                    source: str) -> list[ClaimIn]:
    """What the event's device / endpoint calls the host (D-083): hostname
    or FQDN, MAC, cloud instance uid as identifiers; its IPs as
    time-stamped `has_ip` links, never identifiers."""
    ref = EntityRef(type="host", key=host)
    pairs, ips = [], []
    for obj in (event.get("device"), event.get("endpoint")):
        if not isinstance(obj, dict):
            continue
        short = obj.get("hostname")
        joined = (f"{short}.{obj['domain']}" if short and obj.get("domain") and "." not in str(short)
                  else None)
        for name in (short, obj.get("name"), joined):
            if name:
                pairs.append(("fqdn" if "." in str(name) else "hostname", str(name)))
        pairs += [("mac", obj.get("mac")), ("cloud_id", obj.get("instance_uid"))]
        ips.append(obj.get("ip"))
    return (ident.claims(namespace, ref, pairs, observed, source, {"ocsf": True})
            + ident.ip_claims(namespace, ref, ips, observed, source))


def host_of(event: dict) -> str | None:
    """The host a finding concerns, keyed the SAME way the seed and the nmap
    connector key hosts (hostname, else IP), so a detection on `web-01`
    attaches to the same `host:web-01` the vuln / scan data uses. Resolves
    the OCSF device / endpoint / resource objects in order — top-level
    `device` then `endpoint`, the affected `resources[]`, an `evidences[]`
    device/endpoint, and finally an IP — the first that names something."""
    device = event.get("device") or {}
    for value in (device.get("hostname"), device.get("name"), device.get("uid")):
        if value:
            return str(value)
    endpoint = event.get("endpoint") or {}
    for value in (endpoint.get("hostname"), endpoint.get("name"), endpoint.get("uid")):
        if value:
            return str(value)
    for res in event.get("resources") or []:
        if not isinstance(res, dict):
            continue
        for value in (res.get("hostname"), res.get("name"), res.get("uid")):
            if value:
                return str(value)
    for ev in event.get("evidences") or []:
        if not isinstance(ev, dict):
            continue
        for obj in (ev.get("device"), ev.get("endpoint")):
            if isinstance(obj, dict):
                for value in (obj.get("hostname"), obj.get("name")):
                    if value:
                        return str(value)
    for obj in (device, endpoint):
        if obj.get("ip"):
            return str(obj["ip"])
    return None


def _info_time(info: dict, base: str) -> datetime | None:
    """A finding_info time by either its epoch (`first_seen_time`) or its
    OCSF datetime-profile ISO twin (`first_seen_time_dt`)."""
    return _epoch(info.get(base)) or _epoch(info.get(f"{base}_dt"))


def status_id_of(event: dict) -> int:
    """The finding's status id — from `status_id`, else resolved from the
    `status` string (real SIEM/EDR events often send only the name)."""
    sid = _int(event.get("status_id"))
    if sid:
        return sid
    name = event.get("status")
    return STATUS_BY_NAME.get(name.strip().lower(), 0) if isinstance(name, str) else 0


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
    """Whether this finding version CLOSES its edge (sets `valid_to`).
    Resolved (status 4) or a Close activity does; Suppressed (status 3,
    muted/accepted risk) NEVER does — the finding is still active, just
    silenced (D-071 keeps Suppressed distinct from Resolved). Uses the
    resolved status id, so an event that carries only `status: "Resolved"`
    closes exactly like one with `status_id: 4`."""
    status_id = status_id_of(event)
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
    """Claims for one OCSF finding event: a `vulnerability_finding` (class
    2002) maps host<-affected_by->cve + CVE facts as before; a detection /
    security / incident finding (classes 2004 / 2001 / 2005) maps to a
    `finding:<uid>` entity related to the host it concerns and to any CVE it
    references (D-071). Any other class yields nothing."""
    cls = _int(event.get("class_uid"))
    if cls == CLASS_UID:
        yield from _vuln_finding_envelopes(event, namespace, source)
    elif cls in DETECTION_CLASS_UIDS:
        yield from _detection_envelopes(event, namespace, source)


def _cve_refs(event: dict) -> list[str]:
    """The CVE ids a finding references (upper-cased, de-duplicated), from
    the OCSF `vulnerabilities[].cve.uid` block detection_finding carries."""
    out: list[str] = []
    seen: set[str] = set()
    for vuln in event.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        cid = str((vuln.get("cve") or {}).get("uid") or "").upper()
        if CVE_RE.match(cid) and cid not in seen:
            seen.add(cid)
            out.append(cid)
    return out


def _detection_envelopes(event: dict, namespace: str, source: str | None = None) -> Iterator[ClaimIn]:
    """Claims for one detection / security / incident finding (D-071): the
    `finding:<uid>` entity's title, a `detected_on` edge to the host it
    concerns (the lifecycle carrier — status/severity in attrs, `valid_to`
    set when it Resolves/Closes but not when Suppressed), and a `references`
    edge to each CVE it names (fusing on the shared `cve:` node like OSV).
    Versions of one finding chain by `finding_uid` (D-050/chain.py), so a
    New->In Progress->Resolved transition supersedes the prior state."""
    cls = _int(event.get("class_uid"))
    info = event.get("finding_info") or {}
    observed = (_epoch(event.get("time")) or _info_time(info, "modified_time")
                or _info_time(info, "created_time")
                or _epoch((event.get("metadata") or {}).get("logged_time"))
                or datetime.now(timezone.utc))
    src = source or source_of(event)
    uid = finding_uid(event)
    prefix = f"ocsf:{uid}:{_stamp(observed)}"
    finding = EntityRef(type="finding", key=uid)
    host = host_of(event)
    if host:
        yield from device_identity(event, namespace, host, observed, src)
    status_id = status_id_of(event)
    severity_id = _int(event.get("severity_id"))
    title = str(info.get("title") or info.get("desc") or DETECTION_CLASS.get(cls, "finding"))[:200]
    first_seen = _info_time(info, "first_seen_time") or _info_time(info, "created_time")
    last_seen = _info_time(info, "last_seen_time")
    closed = closes_exposure(event)
    valid_to = (last_seen or observed) if closed else None
    base_attrs = {"finding_uid": uid, "ocsf_class_uid": cls}
    # the transitional state rides on the edges (as vuln findings carry it on
    # affected_by), so a status change supersedes the prior version's edge
    state = {"title": title, "status": event.get("status") or STATUS.get(status_id, "unknown"),
             "status_id": status_id, "severity": event.get("severity") or SEVERITY.get(severity_id, "unknown"),
             "severity_id": severity_id}

    def claim(subject: EntityRef, pred: str, obj, tag: str = "", **kw) -> ClaimIn:
        attrs = {**base_attrs, **kw.pop("attrs", {})}
        return ClaimIn(namespace=namespace, event_id=f"{prefix}:{pred}{tag}"[:128], subject=subject,
                       predicate=pred, object=obj, observed_at=observed, source=src, attrs=attrs, **kw)

    yield claim(finding, PRED_TITLE, title,
                attrs={"class_uid": cls, "class_name": DETECTION_CLASS.get(cls, str(cls))})
    if host:
        yield claim(finding, PRED_DETECTED_ON, EntityRef(type="host", key=host),
                    attrs=state, valid_from=first_seen, valid_to=valid_to)
    for tid in technique_refs(event):
        yield claim(finding, PRED_INDICATES, EntityRef(type="technique", key=tid), tag=f":{tid}",
                    attrs={"first_seen": first_seen.isoformat() if first_seen else None})
    for cid in _cve_refs(event):
        yield claim(finding, PRED_REFERENCES, EntityRef(type="cve", key=cid), tag=f":{cid}",
                    attrs=state, valid_from=first_seen, valid_to=valid_to)


def _vuln_finding_envelopes(event: dict, namespace: str, source: str | None = None) -> Iterator[ClaimIn]:
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
    if host:
        yield from device_identity(event, namespace, host, observed, src)
    status_id = _int(event.get("status_id"))
    severity_id = _int(event.get("severity_id"))
    first_seen = _epoch(info.get("first_seen_time")) or _epoch(info.get("created_time"))
    last_seen = _epoch(info.get("last_seen_time"))
    closed = closes_exposure(event)
    base_attrs = {"finding_uid": uid, "ocsf_class_uid": CLASS_UID}
    # a record Loom exported restates the observations it cites (their
    # event ids, sources, times): those are imported as recorded — a replay
    # in the store they came from — instead of re-asserted under "loom"
    unmapped = event.get("unmapped") if isinstance(event.get("unmapped"), dict) else {}
    restated = unmapped.get("loom_observations") if isinstance(unmapped.get("loom_observations"), list) else None
    edge_event = unmapped.get("loom_event_id") if isinstance(unmapped.get("loom_event_id"), str) else None
    edge_source = source or (unmapped.get("loom_source") if isinstance(unmapped.get("loom_source"), str) else None)

    def claim(subject: EntityRef, pred: str, obj, tag: str = "", event_id: str | None = None,
              **kw) -> ClaimIn:
        attrs = {**base_attrs, **kw.pop("attrs", {})}
        return ClaimIn(namespace=namespace, event_id=(event_id or f"{prefix}:{pred}{tag}")[:128], subject=subject,
                       predicate=pred, object=obj, observed_at=observed, source=kw.pop("source", src),
                       attrs=attrs, **kw)

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
                        valid_from=v_first, valid_to=(v_last or observed) if closed else None,
                        event_id=edge_event, source=edge_source or src)
        if restated is not None:
            continue
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
    for rec in restated or []:
        if isinstance(rec, dict) and (env := _restated_claim(rec, namespace)) is not None:
            yield env


def _restated_claim(rec: dict, namespace: str) -> ClaimIn | None:
    """One `unmapped.loom_observations` entry of a Loom export, as recorded."""
    subject, value = rec.get("subject"), rec.get("value")
    observed = _epoch(rec.get("observed_at"))
    if not isinstance(subject, dict) or not rec.get("predicate") or observed is None:
        return None
    if isinstance(value, dict):
        value = EntityRef(type=str(value.get("type")), key=str(value.get("key")))
    elif not isinstance(value, (str, int, float, bool)):
        return None
    return ClaimIn(namespace=namespace, event_id=str(rec.get("event_id") or f"loom:{rec.get('id')}")[:128],
                   subject=EntityRef(type=str(subject.get("type")), key=str(subject.get("key"))),
                   predicate=str(rec["predicate"]), object=value, observed_at=observed,
                   valid_from=_epoch(rec.get("valid_from")), valid_to=_epoch(rec.get("valid_to")),
                   source=str(rec.get("source") or SOURCE_DEFAULT), confidence=float(rec.get("confidence", 1.0)),
                   attrs=rec["attrs"] if isinstance(rec.get("attrs"), dict) else {})


def events_to_envelopes(events: Iterable[dict], namespace: str, source: str | None = None,
                        stats: dict[str, int] | None = None) -> Iterator[ClaimIn]:
    stats = stats if stats is not None else {}
    shapes = coverage.Shapes()
    newest: datetime | None = None
    for event in events:
        if not isinstance(event, dict):
            stats["skipped"] = stats.get("skipped", 0) + 1
            continue
        info = event.get("finding_info") if isinstance(event.get("finding_info"), dict) else {}
        shapes.add(f"ocsf:{event.get('class_uid', '?')}",
                   [*event, *(f"finding_info.{k}" for k in info),
                    *(f"device.{k}" for k in (event.get("device") or {}) if isinstance(event.get("device"), dict))])
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
        for env in envs:
            if isinstance(env, ClaimIn) and (newest is None or env.observed_at > newest):
                newest = env.observed_at
        kind = "finding" if n else ("other_class" if _int(event.get("class_uid")) != CLASS_UID else "empty")
        stats[kind] = stats.get(kind, 0) + 1
    if shapes.objects:
        yield from shapes.claims(namespace, source or "ocsf", newest or datetime.now(timezone.utc))


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

def _restate(o: Observation) -> dict:
    """An observation an exported finding cites, as recorded — what
    `import` records instead of re-asserting the finding's CVE block."""
    value = {"type": o.object.type, "key": o.object.key} if isinstance(o.object, EntityRef) else o.object
    rec: dict[str, Any] = {"id": o.id, "subject": {"type": o.subject.type, "key": o.subject.key},
                           "predicate": o.predicate, "value": value, "observed_at": _ms(o.observed_at),
                           "source": o.source, "confidence": o.confidence}
    if o.event_id:
        rec["event_id"] = o.event_id
    if o.valid_from:
        rec["valid_from"] = _ms(o.valid_from)
    if o.valid_to:
        rec["valid_to"] = _ms(o.valid_to)
    if o.attrs:
        rec["attrs"] = o.attrs
    return rec


def observations_to_findings(observations: Iterable[Observation], namespace: str,
                             now: datetime | None = None, history: bool = False) -> list[dict]:
    """vulnerability_finding records: one per finding — the versions of a
    (host, cve) edge chained by recorded supersession (D-050) or sharing an
    imported `finding_uid` — plus one per CVE that has facts but no host.

    A finding's versions share `finding_info.uid` (the imported finding
    uid, else the chain's first observation id). By default only the
    newest version is written, carrying the newest state and status, so a
    superseded version never reads as a second open finding; `history=True`
    writes every version, oldest first (activity Create, then Update; Close
    when it closed the exposure). A finding whose newest version was
    superseded by something that is not a version of it ends in a Close
    with status Other / "Superseded"."""
    now = now or datetime.now(timezone.utc)
    rows = [o for o in observations if not o.attrs.get("redacted")]
    by_id = {o.id: o for o in rows}
    superseded_by = supersession(rows)
    facts: dict[str, list[Observation]] = {}        # cve id -> scalar/relational facts about it
    edges: dict[tuple[str, str], list[Observation]] = {}     # (finding uid, cve) -> its versions

    def is_edge(o: Observation) -> bool:
        # a vulnerability_finding edge only: host <-affected_by-> cve. A
        # detection's `finding <-references-> cve` (D-071) is NOT a vuln
        # finding and must not export as one.
        return (o.predicate == PRED_AFFECTED and isinstance(o.object, EntityRef)
                and o.object.type == "cve" and o.subject.type != "cve")

    def finding_id(o: Observation) -> str:
        """What every version of o's finding shares: the imported finding
        uid, else the first observation of its chain (a supersession that
        moves the finding to another host is a version; one that names
        another CVE is not)."""
        root, seen = o, {o.id}
        while root.supersedes in by_id and root.supersedes not in seen:
            prev = by_id[root.supersedes]
            if not is_edge(prev) or prev.object != o.object:
                break
            root = prev
            seen.add(root.id)
        for row in (root, o):
            uid = (row.attrs or {}).get("finding_uid")
            if isinstance(uid, str) and uid:
                return uid
        return root.id

    for obs in rows:
        if obs.subject.type == "cve":
            facts.setdefault(obs.subject.key, []).append(obs)
        if is_edge(obs):
            edges.setdefault((finding_id(obs), obs.object.key), []).append(obs)
            facts.setdefault(obs.object.key, [])

    def current_facts(cid: str) -> list[Observation]:
        return [o for o in facts.get(cid, []) if o.id not in superseded_by]      # superseded: history

    def newest(cid: str, predicate: str) -> Observation | None:
        rows = [o for o in current_facts(cid) if o.predicate == predicate and not isinstance(o.object, EntityRef)]
        return max(rows, key=lambda o: o.observed_at) if rows else None

    def cve_block(cid: str) -> tuple[dict, int, list[str]]:
        cited: list[str] = []
        cve: dict[str, Any] = {"uid": cid}
        cvss = []
        per_source: dict[str, Observation] = {}
        for o in current_facts(cid):
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
        for o in current_facts(cid):
            if o.predicate == "affects" and isinstance(o.object, EntityRef) and o.object.type == "product":
                vendor, _, name = o.object.key.partition(":")
                packages.append({"name": name or vendor, "vendor_name": vendor if name else None})
                cited.append(o.id)
        if packages:
            vuln["affected_packages"] = packages
        return vuln, severity_id, cited

    def finding(host: str | None, cid: str, edge: Observation | None, uid: str | None = None,
                first: bool = True, superseded_at: datetime | None = None) -> dict:
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
        info: dict[str, Any] = {"uid": uid or (edge.id if edge else f"loom:{namespace}:cve:{cid}"),
                                "title": f"{cid} on {host}" if host else cid}
        if edge is not None:
            if edge.valid_from:
                info["first_seen_time"] = _ms(edge.valid_from)
            if edge.valid_to:
                info["last_seen_time"] = _ms(edge.valid_to)
        status = STATUS[status_id].capitalize()
        if superseded_at is not None:          # replaced by something that is not a version of it
            status_id, status, at = 99, "Superseded", superseded_at
        activity_id = (ACTIVITY_CLOSE if superseded_at is not None or status_id == 4
                       else 1 if first else 2)
        record = {
            "activity_id": activity_id, "activity_name": ACTIVITY[activity_id].capitalize(),
            "category_uid": CATEGORY_UID, "category_name": CATEGORY_NAME,
            "class_uid": CLASS_UID, "class_name": CLASS_NAME,
            "type_uid": CLASS_UID * 100 + activity_id,
            "type_name": f"{CLASS_NAME}: {ACTIVITY[activity_id].capitalize()}",
            "severity_id": severity_id, "severity": SEVERITY[severity_id].capitalize(),
            "status_id": status_id, "status": status,
            "time": _ms(at),
            "metadata": {"version": OCSF_VERSION, "product": {"name": PRODUCT_NAME, "vendor_name": PRODUCT_NAME},
                         "logged_time": _ms(now)},
            "finding_info": info,
            "vulnerabilities": [vuln],
            "unmapped": {"loom_namespace": namespace, "loom_observation_ids": cited,
                         "loom_sources": sorted({o.source for o in facts.get(cid, [])} | ({edge.source} if edge else set()))},
        }
        record["unmapped"]["loom_observations"] = [_restate(by_id[i]) for i in cited
                                                   if i in by_id and (edge is None or i != edge.id)]
        if edge is not None:
            record["unmapped"]["loom_source"] = edge.source
            if edge.event_id:
                record["unmapped"]["loom_event_id"] = edge.event_id
        if host:
            record["resources"] = [{"name": host, "type": "host"}]
            record["device"] = {"hostname": host, "type_id": 0}
        return record

    findings = []
    hosted: set[str] = set()
    chains = [(sorted(group, key=version_key), uid, cid) for (uid, cid), group in edges.items()]
    for versions, uid, cid in sorted(chains, key=lambda c: (c[0][-1].subject.key, c[2], c[1])):
        hosted.add(cid)
        members = {o.id for o in versions}

        def replaced_outside(o: Observation, members=members) -> bool:
            later = superseded_by.get(o.id)
            return later is not None and later.id not in members

        # the current version: the newest one not superseded by a version of itself
        current = max((i for i, o in enumerate(versions)
                       if o.id not in superseded_by or replaced_outside(o)), default=len(versions) - 1)
        records = [finding(o.subject.key, cid, o, uid, first=i == 0) for i, o in enumerate(versions)]
        if replaced_outside(versions[current]):
            last = versions[current]
            later = superseded_by[last.id]
            at = max(aware(later.observed_at), aware(last.observed_at) + timedelta(milliseconds=1))
            records.append(finding(last.subject.key, cid, last, uid, first=False, superseded_at=at))
            records[-1]["unmapped"]["loom_superseded_by"] = later.id
            current = len(records) - 1
        findings.extend(records if history else [records[current]])
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
            EntityTypeDef(name="host", description="an asset a finding names (device / endpoint / resources)"),
            *ident.SCHEMA_TYPES, coverage.ENTITY_TYPE,
            EntityTypeDef(name="cve", description="a CVE record (vulnerabilities[].cve.uid)"),
            EntityTypeDef(name="technique", description="an ATT&CK technique, keyed by its id (T1003.001)"),
            EntityTypeDef(name="product", description="software, keyed vendor:product"),
            EntityTypeDef(name="finding", description="a SIEM/EDR/XDR detection, security or incident "
                          "finding (OCSF classes 2004 / 2001 / 2005), keyed by its finding uid"),
        ],
        predicates=[
            *ident.SCHEMA_PREDICATES, *coverage.SCHEMA_PREDICATES,
            PredicateDef(name=PRED_AFFECTED, object_types=["cve"],
                         description="OCSF vulnerability_finding: the host has this CVE; attrs carry the "
                                     "finding uid, status and severity"),
            PredicateDef(name=PRED_DETECTED_ON, object_types=["host"],
                         description="a detection finding concerns this host (the lifecycle carrier; attrs "
                                     "carry the finding title, status and severity, valid_to set on "
                                     "Resolved/Close but not Suppressed)"),
            PredicateDef(name=PRED_INDICATES, object_types=["technique"],
                         description="the ATT&CK technique a detection maps to (finding_info.attacks)"),
            PredicateDef(name=PRED_REFERENCES, object_types=["cve"],
                         description="a detection finding references this CVE (fuses on the shared cve node)"),
            PredicateDef(name=PRED_TITLE, description="a detection finding's title"),
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
    imp = sub.add_parser("import", parents=[common],
                         help="map vulnerability_finding and detection/security/incident findings, and ingest them")
    imp.add_argument("events", help="NDJSON / JSON array of OCSF events, or - for stdin")
    imp.add_argument("--url", help="engine or gateway base URL (default: write straight into the store)")
    imp.add_argument("--db", help="write straight into this explicit store URL/path")
    imp.add_argument("--key", default=os.environ.get("LOOM_API_KEY"), type=str.strip)
    imp.add_argument("--source", help="override the source (default: metadata.product.name)")
    imp.add_argument("--batch", type=int, default=500)
    imp.add_argument("--no-schema", action="store_true", help="skip the registry registration")
    emit = sub.add_parser("emit", parents=[common], help="write NDJSON envelopes to stdout")
    emit.add_argument("events")
    emit.add_argument("--source")
    exp = sub.add_parser("export", parents=[common], help="write the namespace's CVE facts as findings")
    exp.add_argument("--out", required=True, help="NDJSON path, or - for stdout")
    exp.add_argument("--db", help="read this explicit store URL/path (default: LOOM_DB / LOOM_SHARDS)")
    exp.add_argument("--history", action="store_true",
                     help="write every version of each finding (same finding_info.uid), not just the newest")
    sub.add_parser("schema", parents=[common], help="print the schema registration")
    args = parser.parse_args(argv)

    if args.command == "schema":
        print(schema(args.namespace).model_dump_json(indent=2))
        return
    if args.command == "export":
        store = _open_store(args.db)
        try:
            findings = observations_to_findings(store.iter_observations(args.namespace), args.namespace,
                                                history=args.history)
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
    watch = coverage.Watch()
    envs = watch.wrap(events_to_envelopes(iter_events(args.events), args.namespace, args.source, stats))
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
    # each finding's edge versions are chained by supersession, so a resolved
    # finding closes its exposure / detection (connectors/chain.py): vuln
    # findings on affected_by, detections on detected_on / references / title
    key = keyed_by("finding_uid", {PRED_AFFECTED, PRED_DETECTED_ON, PRED_REFERENCES, PRED_TITLE})
    if args.url:
        totals = load_chained(envs, HttpSink(args.url, args.key), key, args.batch)
    else:
        store = _open_store(args.db)
        try:
            totals = load_chained(envs, StoreSink(store), key, args.batch)
        finally:
            store.close()
    drift = watch.report(args.url, args.db, args.key)
    print(json.dumps({**totals, "events": stats, "drift": [d.text() for d in drift]}))
    coverage.print_drift(drift)
    from ..ingest import fail_on_refusals
    fail_on_refusals(totals, remote=bool(args.url))   # a refusal fails the load (D-063, S-36)


if __name__ == "__main__":
    main()
