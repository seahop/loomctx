"""One host, one person — however each tool names them (D-083).

A scan calls a machine `web-01`, the directory `WEB01$` and
`web-01.corp.local`, EDR `WEB-01`, the cloud `i-0abc…`; a user is `CORP\\jdoe`
to Windows, `jdoe@corp.com` to the IdP and `S-1-5-21-…-1106` to AD. Every
connector keys entities its own way; what they share is identifiers. A
connector states them as edges to identifier entities,

    host:web-01            -identified_by-> identifier:fqdn:web-01.corp.local
    computer:S-1-5-…-1104  -identified_by-> identifier:fqdn:web-01.corp.local

and the resolution tier (`enrich.resolve_identities`) folds entities of a
compatible kind that share a STRONG identifier; a WEAK one (a short
hostname, which recurs across domains) goes to the adjudicator. An IP is
not an identifier: addresses are reassigned, so a scan's address is a
time-stamped `has_ip` link, never grounds to merge. Merges are reversible
and declines are honored, as for every tier.

Values are normalized here, once, so every connector spells an identifier
the same way: case folded, a trailing root dot dropped, MACs as
colon-separated lowercase, `DOMAIN\\user` split on the backslash.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime

from .contracts import ClaimIn, EntityRef, EntityTypeDef, PredicateDef

ENTITY_TYPE = "identifier"
PREDICATE = "identified_by"
IP_PREDICATE = "has_ip"

# kind -> strong? A strong identifier names one thing within an environment;
# a weak one recurs (the short hostname `web-01` in two domains).
KINDS: dict[str, bool] = {
    "fqdn": True, "mac": True, "cloud_id": True,           # hosts
    "sid": True, "upn": True, "mail": True, "account": True,  # principals
    "hostname": False,
}

# which entity types may be one thing (a strong identifier shared across
# families — a user and a host — is a data error, not a merge)
FAMILIES: dict[str, frozenset[str]] = {
    "host": frozenset({"host", "computer", "device", "instance", "resource"}),
    "principal": frozenset({"user", "account", "service_principal"}),
}

SCHEMA_TYPES = [
    EntityTypeDef(name=ENTITY_TYPE,
                  description="a name a tool uses for a host or principal (fqdn, mac, sid, upn, "
                              "account, cloud id, hostname); shared identifiers fold entities (D-083)"),
    EntityTypeDef(name="ip", description="an IP address"),
]
SCHEMA_PREDICATES = [
    PredicateDef(name=PREDICATE, object_types=[ENTITY_TYPE],
                 description="the entity is known by this identifier (D-083)"),
    PredicateDef(name=IP_PREDICATE, object_types=["ip"],
                 description="the host had this address when observed; addresses are "
                             "reassigned, so this never merges hosts (D-083)"),
]

_MAC = re.compile(r"^[0-9a-f]{12}$")


def family(entity_type: str) -> str | None:
    for name, members in FAMILIES.items():
        if entity_type in members:
            return name
    return None


def normalize(kind: str, value: str) -> str | None:
    """The canonical spelling of an identifier, or None when the value is
    not one (empty, a placeholder)."""
    v = str(value or "").strip()
    if not v or v.lower() in ("-", "n/a", "none", "null", "unknown", "localhost"):
        return None
    if kind == "fqdn":
        v = v.lower().rstrip(".")
        return v if "." in v else None
    if kind == "hostname":
        v = v.lower().rstrip(".").rstrip("$")
        return v.split(".", 1)[0] or None
    if kind == "mac":
        hexes = re.sub(r"[^0-9a-f]", "", v.lower())
        if not _MAC.match(hexes) or hexes in ("000000000000", "ffffffffffff"):
            return None
        return ":".join(hexes[i:i + 2] for i in range(0, 12, 2))
    if kind == "sid":
        return v.upper() if v.upper().startswith("S-1-") else None
    if kind in ("upn", "mail"):
        v = v.lower()
        return v if "@" in v else None
    if kind == "account":
        # DOMAIN\\user; the NetBIOS domain is what Windows prints (a DNS
        # domain is reduced to its first label, which is the usual NetBIOS
        # name)
        if "\\" not in v:
            return None
        domain, _, user = v.partition("\\")
        domain = domain.strip().lower().split(".", 1)[0]
        user = user.strip().lower()
        if not domain or not user or domain in (".", "nt authority", "nt service", "window manager"):
            return None
        return f"{domain}\\{user}"
    if kind == "cloud_id":
        return v.lower()
    return None


def identifier_ref(kind: str, value: str) -> EntityRef | None:
    norm = normalize(kind, value)
    return EntityRef(type=ENTITY_TYPE, key=f"{kind}:{norm}") if norm else None


def split(identifier_key: str) -> tuple[str, str]:
    kind, _, value = identifier_key.partition(":")
    return kind, value


def _eid(parts: str) -> str:
    if len(parts) <= 128:
        return parts
    return f"{parts[:96]}:{hashlib.sha256(parts.encode('utf-8', 'replace')).hexdigest()[:31]}"


def claims(namespace: str, subject: EntityRef, pairs, observed_at: datetime, source: str,
           attrs: dict | None = None, provenance=None) -> list[ClaimIn]:
    """`identified_by` edges for each (kind, value) in `pairs` that
    normalizes — plus the short hostname an FQDN implies. Idempotent per
    subject, identifier and export time."""
    stamp = observed_at.strftime("%Y%m%dT%H%M%S")
    seen: set[str] = set()
    out: list[ClaimIn] = []
    expanded = []
    for kind, value in pairs:
        expanded.append((kind, value))
        if kind == "fqdn" and normalize("fqdn", value):
            expanded.append(("hostname", value))
    for kind, value in expanded:
        ref = identifier_ref(kind, value)
        if ref is None or ref.key in seen:
            continue
        seen.add(ref.key)
        out.append(ClaimIn(
            namespace=namespace,
            event_id=_eid(f"ident:{subject.type}:{subject.key}:{ref.key}:{stamp}"),
            subject=subject, predicate=PREDICATE, object=ref, observed_at=observed_at,
            source=source, provenance=provenance,
            attrs={**(attrs or {}), "kind": kind, "strong": KINDS[kind]}))
    return out


def ip_claims(namespace: str, subject: EntityRef, addresses, observed_at: datetime, source: str,
              attrs: dict | None = None, provenance=None) -> list[ClaimIn]:
    """`has_ip` links, stamped with the observation time: which host had an
    address WHEN is `as_of` / `valid_at` territory, never a merge."""
    stamp = observed_at.strftime("%Y%m%dT%H%M%S")
    out = []
    for addr in dict.fromkeys(str(a).strip() for a in addresses if a):
        if not addr or addr in ("0.0.0.0", "::", "127.0.0.1", "::1"):
            continue
        out.append(ClaimIn(
            namespace=namespace,
            event_id=_eid(f"ip:{subject.type}:{subject.key}:{addr}:{stamp}"),
            subject=subject, predicate=IP_PREDICATE, object=EntityRef(type="ip", key=addr),
            observed_at=observed_at, source=source, provenance=provenance, attrs=dict(attrs or {})))
    return out
