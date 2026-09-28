"""Raw-LDAP / LDIF interop: an Active Directory export in, typed cited claims out.

    python -m loomctx.connectors.ldap import export.ldif --namespace netsec                 # into the LOOMCTX_DB store
    python -m loomctx.connectors.ldap import export.ldif --namespace netsec --url http://loomctx:8000 --key ...
    python -m loomctx.connectors.ldap emit export.ldif --namespace netsec > envelopes.jsonl
    python -m loomctx.connectors.ldap schema --namespace netsec                             # the registry it declares

What it is (and is NOT):

  This connector DECODES a raw directory export — object by object,
  deterministically — into LoomCtx claims so an agent can ask object-level
  reachability questions ("what rights / trust / membership path connects
  user:X to domain:B?") over the ordinary scope walk. Every claim is cited
  to the directory fact it came from (its source object's DN) and dated
  from the export, so `as_of` / `valid_at` and multi-source corroboration
  work — the differentiators over a static graph tool.

  It is NOT BloodHound. It performs NO graph reasoning: no transitive or
  *effective* admin, no shortest / cheapest attack-path scoring, no edge
  exploitability weighting. LoomCtx carries the evidence (the direct edges and
  the decoded rights); the agent (or a later analysis layer) assembles and
  ranks the path. Nesting of groups is the scope walk's job at depth N, not
  this connector's.

  It reads a FILE. It is not a collector and issues no directory operations.
  And LDAP is object-level only: sessions and local-admin-on-member-servers
  are NOT in the directory — they need host collection (what SharpHound does
  at the host). So an LDAP-only LoomCtx answers control-of-account, delegation,
  trust and GPO-control questions, but not session-based lateral movement.
  Load host/session data as its own claims later and the same walk extends
  over it; this connector does not invent it.

Input — canonical LDIF (RFC 2849): base64 values (`attr:: <b64>`), line
folding (a continuation line begins with a single space), multi-valued
attributes and plain `changetype`-free entries. A small synthetic fixture
drives the tests; real AD data is never required.

Decode (all into ONE namespace, `ad` by default), keyed by **objectSid**
decoded to the standard `S-1-5-...` string (stable across rename);
`distinguishedName` and `domain\\sam` ride as attributes so entity
resolution (D-042/D-060) can fold them onto the SID-keyed entity. Within
one export, `member` / `memberOf` DNs are resolved to the SID of the object
they name, so the edges connect the SID-keyed entities directly.

  * entity types from objectClass: domain, computer, user, group, ou, gpo,
    container.
  * `member_of` from `member` / `memberOf` (DIRECT only; nesting is the
    walk's job).
  * `contains` from DN parentage (parent object -> child), containment.
  * `trusts` from `trustedDomain` objects: `subject trusts object` means
    "subject accepts credentials from object's principals." For inbound
    trusts (trustDirection 1) the local domain is the subject; for outbound
    (2) the partner is; bidirectional (3) emits both edges. Attrs:
    `direction`, `transitive`, `sid_filtering`, `partner`.
  * `has_ace` from `nTSecurityDescriptor` (a base64 SD blob): the DACL is
    parsed into (trustee SID -> this object) claims, `attrs.right` decoded
    from the access mask and, for object ACEs, `attrs.object_type` the GUID.
    Covered: GenericAll, GenericWrite (including the AD-mapped form 0x20028),
    WriteDacl, WriteOwner, ForceChangePassword (extended right
    00299570-246d-11d0-a768-00aa006e0529), AddMember (write-property to the
    member attribute bf9679c0-0de6-11d0-a285-00aa003049e2), AllExtendedRights.
    Inherit-only ACEs (flag 0x08) are skipped — they apply to children, not
    the object itself. ACEs granting none of these are skipped. The SD/ACE
    parser is hand-rolled (see `parse_security_descriptor`); no heavy
    dependency (no impacket).
  * attrs from `userAccountControl` (bitmask): `enabled` (not 0x2),
    `unconstrained_delegation` (0x80000), `no_preauth` (0x400000, AS-REP
    roastable), `is_dc` (0x2000 SERVER_TRUST_ACCOUNT, or objectClass);
    `kerberoastable` when a user has a non-empty `servicePrincipalName`;
    `can_delegate_to` edges from `msDS-AllowedToDelegateTo` (constrained
    delegation, object = the target SPN); `rbcd_from` from
    `msDS-AllowedToActOnBehalfOfOtherIdentity` (its SD is decoded too:
    object = each trustee allowed to act on behalf of this object).

Provenance & idempotency — each claim carries `attrs.dn` (its source
object) and `attrs.export` (the export label), and `observed_at` is the
export timestamp (an LDIF `# ...` date comment, then `--as-of`, then the
file mtime). Event ids are content-addressed and embed that stamp, so
re-importing the same export is a no-op and a later export records history.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import os
import struct
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Iterable, Iterator

from .. import coverage
from .. import identity as ident
from ..contracts import (ClaimIn, EntityRef, EntityTypeDef, PredicateDef,
                         SchemaRegistration)

SOURCE_DEFAULT = "ad-export"
NAMESPACE_DEFAULT = "netsec"   # one namespace per environment (D-083)

# objectClass -> LoomCtx entity type, most specific first (objectClass is
# multi-valued; a computer also carries `user`, a domain also `top`).
CLASS_TYPES = [
    ("groupPolicyContainer", "gpo"),
    ("computer", "computer"),
    ("group", "group"),
    ("organizationalUnit", "ou"),
    ("domainDNS", "domain"),
    ("domain", "domain"),
    ("user", "user"),
    ("container", "container"),
]
ENTITY_TYPES = ["domain", "computer", "user", "group", "ou", "gpo", "container", "spn"]

# userAccountControl bits
UAC_ACCOUNTDISABLE = 0x0002
UAC_SERVER_TRUST_ACCOUNT = 0x2000          # a domain controller's machine account
UAC_TRUSTED_FOR_DELEGATION = 0x80000       # unconstrained delegation
UAC_DONT_REQ_PREAUTH = 0x400000            # AS-REP roastable

# trustDirection
TRUST_DIRECTION = {0: "disabled", 1: "inbound", 2: "outbound", 3: "bidirectional"}
# trustAttributes bits
TRUST_NON_TRANSITIVE = 0x01
TRUST_QUARANTINED_DOMAIN = 0x04            # SID filtering enabled
TRUST_FOREST_TRANSITIVE = 0x08

# Access-mask bits (ADS rights / standard rights)
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100   # an extended right (or all, with no ObjectType)
ADS_RIGHT_DS_WRITE_PROP = 0x00000020       # write a property (or all, with no ObjectType)
WRITE_DAC = 0x00040000
WRITE_OWNER = 0x00080000
GENERIC_WRITE = 0x40000000
GENERIC_ALL = 0x10000000
FULL_CONTROL = 0x000F01FF                   # the expanded GenericAll bitset AD writes
GENERIC_WRITE_MAPPED = 0x00020028           # READ_CONTROL | DS_SELF | DS_WRITE_PROP

# extended-right / attribute GUIDs (lower-case string form)
GUID_FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
GUID_MEMBER_ATTR = "bf9679c0-0de6-11d0-a285-00aa003049e2"

# ACE flags
ACE_INHERIT_ONLY = 0x08                     # applies only to child objects, not this one

# ACE types we read
ACE_ACCESS_ALLOWED = 0x00
ACE_ACCESS_ALLOWED_OBJECT = 0x05
ACE_OBJECT_TYPE_PRESENT = 0x01
ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x02


# --------------------------------------------------------------- LDIF parsing #

class LdifEntry:
    """One LDIF record: its DN and a case-insensitive multimap of attributes
    (each value already base64-decoded to bytes when it needs to be, kept as
    str otherwise)."""

    def __init__(self, dn: str):
        self.dn = dn
        self.attrs: dict[str, list] = {}

    def add(self, name: str, value) -> None:
        self.attrs.setdefault(name.lower(), []).append(value)

    def first(self, name: str):
        vals = self.attrs.get(name.lower())
        return vals[0] if vals else None

    def text(self, name: str) -> str | None:
        v = self.first(name)
        if v is None:
            return None
        return v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v)

    def texts(self, name: str) -> list[str]:
        out = []
        for v in self.attrs.get(name.lower(), []):
            out.append(v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else str(v))
        return out

    def raw(self, name: str) -> bytes | None:
        """The value as bytes: a base64 (`::`) value is already bytes, a plain
        one is utf-8 encoded."""
        v = self.first(name)
        if v is None:
            return None
        return bytes(v) if isinstance(v, (bytes, bytearray)) else str(v).encode("utf-8")


def _unfold(text: str) -> Iterator[str]:
    """RFC 2849 line folding: a line beginning with a single space continues
    the previous one."""
    pending: str | None = None
    for line in text.splitlines():
        if line.startswith(" ") and pending is not None:
            pending += line[1:]
            continue
        if pending is not None:
            yield pending
        pending = line
    if pending is not None:
        yield pending


def parse_ldif(text: str) -> tuple[list[LdifEntry], datetime | None]:
    """Every entry in an LDIF document, plus an export timestamp read from a
    `# ...` comment if one carries an ISO date (else None). Handles base64
    (`attr:: b64`), folding, multi-valued attributes and `changetype`-free
    plain entries; `attr:< url` (an external reference) is skipped."""
    entries: list[LdifEntry] = []
    export_at: datetime | None = None
    current: LdifEntry | None = None
    for line in _unfold(text):
        if not line.strip():
            if current is not None:
                entries.append(current)
                current = None
            continue
        if line.startswith("#"):
            if export_at is None:
                export_at = _comment_date(line)
            continue
        if line.startswith("version:"):
            continue
        if ":" not in line:
            continue
        name, sep, rest = line.partition(":")
        if rest.startswith("<"):                      # attr:< url  — external, not inlined
            continue
        if rest.startswith(":"):                      # attr:: base64
            b64 = rest[1:].strip()
            try:
                value: object = base64.b64decode(b64, validate=False)
            except (binascii.Error, ValueError):
                value = b""
        else:
            value = rest.strip()
        if name.lower() == "dn":
            dn = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
            current = LdifEntry(dn)
            continue
        if current is None:
            continue
        if name.lower() == "changetype":
            continue
        current.add(name, value)
    if current is not None:
        entries.append(current)
    return entries, export_at


def _comment_date(line: str) -> datetime | None:
    for token in line[1:].replace(",", " ").split():
        text = token.strip()
        for candidate in (text, text[:19], text[:10]):
            try:
                dt = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
            except ValueError:
                continue
            dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            if dt <= datetime.now(timezone.utc):
                return dt
    return None


# ------------------------------------------------------------- binary decode #

def decode_sid(blob: bytes | None) -> str | None:
    """A binary objectSid -> the standard string `S-1-5-21-...-<rid>`.
    Revision, sub-authority count, a 6-byte big-endian identifier authority,
    then N little-endian sub-authorities (MS-DTYP 2.4.2)."""
    if not blob or len(blob) < 8:
        return None
    revision = blob[0]
    count = blob[1]
    authority = int.from_bytes(blob[2:8], "big")
    subs = []
    off = 8
    for _ in range(count):
        if off + 4 > len(blob):
            break
        subs.append(int.from_bytes(blob[off:off + 4], "little"))
        off += 4
    auth = str(authority) if authority < (1 << 32) else f"0x{authority:012x}"
    return "-".join(["S", str(revision), auth, *(str(s) for s in subs)])


def _sid_from_entry(entry: LdifEntry) -> str | None:
    """objectSid as string: base64/binary decoded, or already `S-...`."""
    v = entry.first("objectsid")
    if v is None:
        return None
    if isinstance(v, (bytes, bytearray)):
        text = bytes(v).decode("latin-1", "replace")
        if text.startswith("S-1-"):
            return text
        return decode_sid(bytes(v))
    text = str(v)
    if text.startswith("S-1-"):
        return text
    try:
        return decode_sid(base64.b64decode(text, validate=False))
    except (binascii.Error, ValueError):
        return None


def decode_guid(blob: bytes) -> str:
    """A 16-byte GUID (MS mixed-endian) -> lower-case string form."""
    d1 = int.from_bytes(blob[0:4], "little")
    d2 = int.from_bytes(blob[4:6], "little")
    d3 = int.from_bytes(blob[6:8], "little")
    d4 = blob[8:16]
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4[0:2].hex()}-{d4[2:8].hex()}"


class Ace:
    __slots__ = ("type", "flags", "mask", "trustee", "object_type", "inherited_object_type")

    def __init__(self, ace_type, flags, mask, trustee, object_type, inherited):
        self.type = ace_type
        self.flags = flags
        self.mask = mask
        self.trustee = trustee                        # SID string
        self.object_type = object_type                # GUID string or None
        self.inherited_object_type = inherited


def parse_security_descriptor(blob: bytes) -> list[Ace]:
    """The allowed ACEs of a self-relative Security Descriptor's DACL.

    Layout (MS-DTYP): a 20-byte header — Revision(1), Sbz1(1), Control(2 LE),
    OffsetOwner(4 LE), OffsetGroup(4 LE), OffsetSacl(4 LE), OffsetDacl(4 LE).
    At OffsetDacl an ACL header — AclRevision(1), Sbz1(1), AclSize(2 LE),
    AceCount(2 LE), Sbz2(2 LE) — then AceCount ACEs, each an ACE header
    (AceType(1), AceFlags(1), AceSize(2 LE)) plus body. ACCESS_ALLOWED (0x00):
    Mask(4 LE) then the trustee SID. ACCESS_ALLOWED_OBJECT (0x05): Mask(4 LE),
    Flags(4 LE), then ObjectType(16) if flag 0x1, InheritedObjectType(16) if
    flag 0x2, then the SID. Only allowed ACEs are returned; a truncated or
    malformed ACE ends the parse rather than raising."""
    aces: list[Ace] = []
    if len(blob) < 20:
        return aces
    dacl_off = struct.unpack_from("<I", blob, 16)[0]
    if dacl_off == 0 or dacl_off + 8 > len(blob):
        return aces
    ace_count = struct.unpack_from("<H", blob, dacl_off + 4)[0]
    off = dacl_off + 8
    for _ in range(ace_count):
        if off + 4 > len(blob):
            break
        ace_type, ace_flags, ace_size = struct.unpack_from("<BBH", blob, off)
        if ace_size < 4 or off + ace_size > len(blob):
            break
        body = off + 4
        if ace_type in (ACE_ACCESS_ALLOWED, ACE_ACCESS_ALLOWED_OBJECT):
            try:
                mask = struct.unpack_from("<I", blob, body)[0]
                cur = body + 4
                object_type = inherited = None
                if ace_type == ACE_ACCESS_ALLOWED_OBJECT:
                    flags = struct.unpack_from("<I", blob, cur)[0]
                    cur += 4
                    if flags & ACE_OBJECT_TYPE_PRESENT:
                        object_type = decode_guid(blob[cur:cur + 16])
                        cur += 16
                    if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT:
                        inherited = decode_guid(blob[cur:cur + 16])
                        cur += 16
                sid = decode_sid(blob[cur:off + ace_size])
                if sid is not None:
                    aces.append(Ace(ace_type, ace_flags, mask, sid, object_type, inherited))
            except (struct.error, IndexError):
                break
        off += ace_size
    return aces


def decode_rights(ace: Ace) -> list[str]:
    """The interesting rights an ACE's access mask grants (a decode table, not
    reasoning). Empty when it grants none — that ACE is skipped.
    Inherit-only ACEs (flag 0x08) apply to children, not this object."""
    if ace.flags & ACE_INHERIT_ONLY:
        return []
    rights: list[str] = []
    mask = ace.mask
    if mask & GENERIC_ALL or (mask & FULL_CONTROL) == FULL_CONTROL:
        rights.append("GenericAll")
    if mask & GENERIC_WRITE or (mask & GENERIC_WRITE_MAPPED) == GENERIC_WRITE_MAPPED:
        rights.append("GenericWrite")
    if mask & WRITE_DAC:
        rights.append("WriteDacl")
    if mask & WRITE_OWNER:
        rights.append("WriteOwner")
    if mask & ADS_RIGHT_DS_CONTROL_ACCESS:
        if ace.object_type is None:
            rights.append("AllExtendedRights")
        elif ace.object_type == GUID_FORCE_CHANGE_PASSWORD:
            rights.append("ForceChangePassword")
    if mask & ADS_RIGHT_DS_WRITE_PROP and ace.object_type == GUID_MEMBER_ATTR:
        rights.append("AddMember")
    return rights


# --------------------------------------------------------------------- index #

def _parent_dn(dn: str) -> str | None:
    """The DN of the object one level up (drop the first RDN), respecting
    escaped commas."""
    depth = 0
    for i, ch in enumerate(dn):
        if ch == "\\":
            depth += 1
            continue
        if ch == "," and depth % 2 == 0:
            return dn[i + 1:].strip()
        depth = 0
    return None


def entity_type_of(entry: LdifEntry) -> str:
    classes = {c.lower() for c in entry.texts("objectclass")}
    for name, loomctx in CLASS_TYPES:
        if name.lower() in classes:
            return loomctx
    return "container"


class Directory:
    """One export, indexed for resolution: DN (lower-cased) -> (sid, type),
    SID -> (sid, type), and the export's observation time."""

    def __init__(self, entries: list[LdifEntry], observed_at: datetime,
                 export: str = SOURCE_DEFAULT):
        self.entries = entries
        self.observed_at = observed_at
        self.export = export
        self.by_dn: dict[str, tuple[str, str]] = {}
        self.by_sid: dict[str, str] = {}
        for e in entries:
            sid = _sid_from_entry(e)
            if sid and e.dn:
                etype = entity_type_of(e)
                self.by_dn[e.dn.lower()] = (sid, etype)
                self.by_sid[sid] = etype

    def ref_for_dn(self, dn: str | None) -> EntityRef | None:
        if not dn:
            return None
        hit = self.by_dn.get(dn.lower())
        if hit is not None:
            return EntityRef(type=hit[1], key=hit[0])
        return None

    def ref_for_sid(self, sid: str | None, default_type: str = "group") -> EntityRef | None:
        if not sid:
            return None
        etype = self.by_sid.get(sid)
        if etype is not None:
            return EntityRef(type=etype, key=sid)
        return EntityRef(type=default_type, key=sid)


# -------------------------------------------------------------------- decode #

def _stamp(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S")


def _eid(parts: str) -> str:
    """Content-addressed event id: stable, unique, and always ≤128 chars."""
    if len(parts) <= 128:
        return parts
    prefix = parts[:96]
    suffix = hashlib.sha256(parts.encode("utf-8", "replace")).hexdigest()[:31]
    return f"{prefix}:{suffix}"


def entry_envelopes(entry: LdifEntry, directory: Directory, namespace: str,
                    source: str) -> Iterator[ClaimIn]:
    """Every claim one directory object yields. A trustedDomain object yields
    a `trusts` edge; anything with an objectSid yields its entity's scalar
    attrs and relational edges."""
    observed = directory.observed_at
    stamp = _stamp(observed)
    dn = entry.dn
    classes = {c.lower() for c in entry.texts("objectclass")}

    # a cross-domain trust object: no objectSid keying, key by the partner
    if "trusteddomain" in classes:
        yield from _trust_envelopes(entry, directory, namespace, source, observed, stamp)
        return

    sid = _sid_from_entry(entry)
    if sid is None:
        return
    etype = entity_type_of(entry)
    ref = EntityRef(type=etype, key=sid)
    base_attrs = {"dn": dn, "export": directory.export}

    def claim(pred: str, obj, tag: str = "", **kw) -> ClaimIn:
        attrs = {**base_attrs, **kw.pop("attrs", {})}
        return ClaimIn(namespace=namespace, event_id=_eid(f"ldap:{sid}:{stamp}:{pred}{tag}"),
                       subject=ref, predicate=pred, object=obj, observed_at=observed,
                       source=source, attrs=attrs, **kw)

    # identity / alias attributes so entity resolution can fold DN + sam
    yield claim("dn_name", dn)
    sam = entry.text("samaccountname")
    at = dn.lower().find("dc=")
    dns_domain = _dn_to_domain(dn[at:]) if at != -1 else None
    if sam:
        yield claim("sam", sam)
        if dns_domain:
            # the name with its domain (D-097): `dlee` reads the same in every
            # domain of a forest; `dlee@dev.local` says which one
            yield claim("principal", f"{sam}@{dns_domain}")
    friendly = entry.text("name") or entry.text("cn")
    if friendly:
        yield claim("name", friendly)
    os_name = entry.text("operatingsystem")
    if os_name:
        yield claim("os", os_name)

    # what other tools call this account or machine (D-083): the SID, the
    # UPN and DOMAIN\sam a Windows host prints, the DNS name a scanner sees
    if etype in ("user", "computer"):
        pairs = [("sid", sid), ("upn", entry.text("userprincipalname")), ("mail", entry.text("mail"))]
        if sam and dns_domain:
            pairs.append(("account", f"{dns_domain}\\{sam}"))
        if etype == "computer":
            pairs += [("fqdn", entry.text("dnshostname")), ("hostname", sam)]
        yield from ident.claims(namespace, ref, pairs, observed, source, base_attrs)

    # userAccountControl bitmask -> attrs
    uac = _int(entry.text("useraccountcontrol"))
    is_dc = False
    if uac is not None:
        yield claim("enabled", not bool(uac & UAC_ACCOUNTDISABLE))
        if uac & UAC_TRUSTED_FOR_DELEGATION:
            yield claim("unconstrained_delegation", True)
        if uac & UAC_DONT_REQ_PREAUTH:
            yield claim("no_preauth", True)
        if uac & UAC_SERVER_TRUST_ACCOUNT:
            is_dc = True
    if is_dc:
        yield claim("is_dc", True)

    # a user with an SPN is kerberoastable
    spns = entry.texts("serviceprincipalname")
    if spns and etype in ("user", "computer"):
        if etype == "user":
            yield claim("kerberoastable", True)
        for i, spn in enumerate(spns):
            yield claim("spn", spn, f":{i}")

    # direct group membership (member on the group, memberOf on the principal)
    seen_edges: set[tuple[str, str]] = set()
    for member_dn in entry.texts("member"):
        m = directory.ref_for_dn(member_dn)
        if m is not None and (m.type, m.key) not in seen_edges:
            seen_edges.add((m.type, m.key))
            yield ClaimIn(namespace=namespace, event_id=_eid(f"ldap:{m.key}:{stamp}:member_of:{sid}"),
                          subject=m, predicate="member_of", object=ref, observed_at=observed,
                          source=source, attrs={"dn": member_dn, "via": dn, "export": directory.export})
    for group_dn in entry.texts("memberof"):
        g = directory.ref_for_dn(group_dn)
        if g is not None and (g.type, g.key) not in seen_edges:
            seen_edges.add((g.type, g.key))
            yield claim("member_of", g, f":{g.key}", attrs={"to_dn": group_dn})

    # DN parentage -> contains (parent object -> this)
    parent = directory.ref_for_dn(_parent_dn(dn))
    if parent is not None and (parent.type, parent.key) != (ref.type, ref.key):
        yield ClaimIn(namespace=namespace, event_id=_eid(f"ldap:{parent.key}:{stamp}:contains:{sid}"),
                      subject=parent, predicate="contains", object=ref, observed_at=observed,
                      source=source, attrs={"dn": parent.key, "child_dn": dn, "export": directory.export})

    # constrained delegation: msDS-AllowedToDelegateTo -> can_delegate_to (target SPN)
    for i, target in enumerate(entry.texts("msds-allowedtodelegateto")):
        yield claim("can_delegate_to", EntityRef(type="spn", key=target), f":{i}")

    # RBCD: the SD in msDS-AllowedToActOnBehalfOfOtherIdentity names the
    # principals allowed to act on behalf of THIS object
    rbcd = entry.raw("msds-allowedtoactonbehalfofotheridentity")
    if rbcd:
        for j, ace in enumerate(parse_security_descriptor(rbcd)):
            if not decode_rights(ace):
                continue
            trustee = directory.ref_for_sid(ace.trustee)
            if trustee is not None:
                yield claim("rbcd_from", trustee, f":{ace.trustee}:{j}",
                            attrs={"trustee_sid": ace.trustee})

    # nTSecurityDescriptor DACL -> has_ace (trustee -> this object), per right
    sd = entry.raw("ntsecuritydescriptor")
    if sd:
        emitted: set[tuple[str, str]] = set()
        for ace in parse_security_descriptor(sd):
            rights = decode_rights(ace)
            if not rights:
                continue
            trustee = directory.ref_for_sid(ace.trustee)
            if trustee is None:
                continue
            for right in rights:
                key = (ace.trustee, right)
                if key in emitted:
                    continue
                emitted.add(key)
                attrs = {"right": right, "trustee_sid": ace.trustee, "target_dn": dn,
                         "export": directory.export}
                if ace.object_type:
                    attrs["object_type"] = ace.object_type
                yield ClaimIn(namespace=namespace,
                              event_id=_eid(f"ldap:{ace.trustee}:{stamp}:has_ace:{sid}:{right}"),
                              subject=trustee, predicate="has_ace", object=ref, observed_at=observed,
                              source=source, attrs=attrs)


def _trust_envelopes(entry: LdifEntry, directory: Directory, namespace: str, source: str,
                     observed: datetime, stamp: str) -> Iterator[ClaimIn]:
    partner_name = (entry.text("trustpartner") or entry.text("name")
                    or entry.text("cn") or entry.text("flatname"))
    if not partner_name:
        return
    partner_name = partner_name.lower()
    low = entry.dn.lower()
    idx = low.find("dc=")
    dc_suffix = entry.dn[idx:] if idx != -1 else None
    local = directory.ref_for_dn(dc_suffix) or EntityRef(
        type="domain", key=_dn_to_domain(dc_suffix) or "this-domain")
    partner = EntityRef(type="domain", key=partner_name)
    direction = _int(entry.text("trustdirection"))
    attributes = _int(entry.text("trustattributes")) or 0
    base_attrs = {
        "partner": partner_name,
        "transitive": not bool(attributes & TRUST_NON_TRANSITIVE),
        "sid_filtering": bool(attributes & TRUST_QUARANTINED_DOMAIN),
        "forest_transitive": bool(attributes & TRUST_FOREST_TRANSITIVE),
        "dn": entry.dn, "export": source,
    }
    raw_dir = TRUST_DIRECTION.get(direction, "unknown") if direction is not None else "unknown"

    def _trust_edge(subj: EntityRef, obj: EntityRef, dir_label: str) -> ClaimIn:
        return ClaimIn(
            namespace=namespace,
            event_id=_eid(f"ldap:trust:{subj.key}:{obj.key}:{stamp}"),
            subject=subj, predicate="trusts", object=obj, observed_at=observed,
            source=source, attrs={**base_attrs, "direction": dir_label})

    if direction == 1:
        yield _trust_edge(local, partner, "inbound")
    elif direction == 2:
        yield _trust_edge(partner, local, "outbound")
    elif direction == 3:
        yield _trust_edge(local, partner, "bidirectional")
        yield _trust_edge(partner, local, "bidirectional")
    else:
        yield _trust_edge(local, partner, raw_dir)


def _dn_to_domain(dn: str | None) -> str | None:
    """`DC=corp,DC=local` -> `corp.local`."""
    if not dn:
        return None
    parts = [p.split("=", 1)[1] for p in dn.split(",") if p.strip().lower().startswith("dc=")]
    return ".".join(parts).lower() if parts else None


def _int(text: str | None) -> int | None:
    if text is None:
        return None
    try:
        return int(str(text).strip())
    except (TypeError, ValueError):
        return None


def ldif_to_envelopes(text: str, namespace: str, source: str = SOURCE_DEFAULT,
                      as_of: datetime | None = None, mtime: datetime | None = None,
                      stats: dict[str, int] | None = None) -> Iterator[ClaimIn]:
    """Every claim an LDIF export yields. The export timestamp is the LDIF
    date comment, then `as_of`, then `mtime`, then now — so `valid_at` works.
    One bad object is counted (`invalid`) and skipped, not the whole export."""
    stats = stats if stats is not None else {}
    entries, comment_at = parse_ldif(text)
    observed = comment_at or as_of or mtime or datetime.now(timezone.utc)
    if observed > datetime.now(timezone.utc):
        observed = datetime.now(timezone.utc)
    directory = Directory(entries, observed, export=source)
    counts: dict[str, Counter] = {}
    shapes = coverage.Shapes()
    for entry in entries:
        _count_coverage(entry, counts)
        shapes.add(f"ldap:{entity_type_of(entry)}", entry.attrs)
        try:
            n = 0
            for env in entry_envelopes(entry, directory, namespace, source):
                n += 1
                yield env
            stats["object" if n else "empty"] = stats.get("object" if n else "empty", 0) + 1
        except (ValueError, TypeError, KeyError, struct.error) as exc:
            stats["invalid"] = stats.get("invalid", 0) + 1
            print(f"ldap object {entry.dn}: skipped: {str(exc).splitlines()[0][:200]}", file=sys.stderr)
    yield from _coverage_envelopes(counts, namespace, source, observed)
    yield from shapes.claims(namespace, source, observed)


def _count_coverage(entry: LdifEntry, counts: dict[str, Counter]) -> None:
    """Tally, per domain, the attributes every object of a kind carries in a
    full dump — so their absence means "not collected" (D-082): every object
    has an nTSecurityDescriptor (absent when the dump skipped it or the
    reading account lacked READ_CONTROL), every account a
    userAccountControl. Optional attributes (memberOf, SPNs) are not counted:
    their absence may just mean none."""
    if "trusteddomain" in {c.lower() for c in entry.texts("objectclass")}:
        return
    if _sid_from_entry(entry) is None:
        return
    at = entry.dn.lower().find("dc=")
    domain = (_dn_to_domain(entry.dn[at:]) if at != -1 else None) or "unknown"
    c = counts.setdefault(domain, Counter())
    c["objects"] += 1
    c["sd"] += bool(entry.raw("ntsecuritydescriptor"))
    etype = entity_type_of(entry)
    if etype in ("user", "computer"):
        c["accounts"] += 1
        c["uac"] += entry.text("useraccountcontrol") is not None
    if etype in ("user", "computer", "group"):
        c["principals"] += 1
        c["membership"] += bool(entry.texts("member") or entry.texts("memberof"))


def _coverage_envelopes(counts: dict[str, Counter], namespace: str, source: str,
                        observed: datetime) -> Iterator[ClaimIn]:
    for domain, c in sorted(counts.items()):
        scope = f"domain:{domain}"
        yield coverage.claim(namespace, source, scope, "has_ace", c["sd"], c["objects"], observed)
        for pred in ("enabled", "unconstrained_delegation", "no_preauth", "is_dc"):
            yield coverage.claim(namespace, source, scope, pred, c["uac"], c["accounts"], observed,
                                 types=["computer", "user"] if pred == "enabled" else None)
        if c["principals"] and not c["membership"]:
            # no member / memberOf anywhere in the domain: not dumped
            yield coverage.claim(namespace, source, scope, "member_of", 0, c["principals"], observed)


# ------------------------------------------------------------------- schema #

def schema(namespace: str) -> SchemaRegistration:
    """The registry this connector declares. Not strict: object-level AD
    reachability, no derived attack graph."""
    return SchemaRegistration(
        namespace=namespace,
        entity_types=[
            EntityTypeDef(name="domain", description="an AD domain / trustedDomain partner"),
            EntityTypeDef(name="computer", description="a computer / machine account"),
            EntityTypeDef(name="user", description="a user account"),
            EntityTypeDef(name="group", description="a security or distribution group"),
            EntityTypeDef(name="ou", description="an organizational unit"),
            EntityTypeDef(name="gpo", description="a group policy container"),
            EntityTypeDef(name="container", description="a directory container"),
            EntityTypeDef(name="spn", description="a service principal name (delegation target)"),
            coverage.ENTITY_TYPE,
            *ident.SCHEMA_TYPES,
        ],
        predicates=[
            *coverage.SCHEMA_PREDICATES,
            *ident.SCHEMA_PREDICATES,
            PredicateDef(name="member_of", object_types=["group"], containment=True,
                         description="direct group membership (member / memberOf); nesting is the walk's job"),
            PredicateDef(name="contains", containment=True,
                         description="DN parentage: this object contains the child"),
            PredicateDef(name="trusts", object_types=["domain"],
                         description="a domain trust; attrs direction, transitive, sid_filtering, partner"),
            PredicateDef(name="has_ace",
                         description="a DACL grant: the trustee holds attrs.right over this object "
                                     "(GenericAll/GenericWrite/WriteDacl/WriteOwner/ForceChangePassword/"
                                     "AddMember/AllExtendedRights)"),
            PredicateDef(name="can_delegate_to", object_types=["spn"],
                         description="constrained delegation target (msDS-AllowedToDelegateTo)"),
            PredicateDef(name="rbcd_from",
                         description="resource-based constrained delegation: the trustee may act on "
                                     "behalf of this object"),
            PredicateDef(name="enabled", node_status=True,
                         description="the account is enabled (userAccountControl)"),
            PredicateDef(name="is_dc", description="a domain controller machine account"),
            PredicateDef(name="unconstrained_delegation",
                         description="TRUSTED_FOR_DELEGATION (userAccountControl 0x80000)"),
            PredicateDef(name="no_preauth", description="AS-REP roastable (DONT_REQ_PREAUTH 0x400000)"),
            PredicateDef(name="kerberoastable", description="a user with a servicePrincipalName"),
            PredicateDef(name="spn", description="a servicePrincipalName registered on the account"),
            PredicateDef(name="sam", label=True, description="sAMAccountName"),
            PredicateDef(name="principal", label=True, display=True,
                         description="sAMAccountName@domain: the account or group with the domain it lives in"),
            PredicateDef(name="dn_name", label=True, description="distinguishedName (alias for entity resolution)"),
            PredicateDef(name="name", label=True, description="friendly name (cn / name)"),
            PredicateDef(name="os", description="operatingSystem"),
        ],
    )


# ---------------------------------------------------------------------- CLI #

def _to_lines(envs: Iterable[ClaimIn]) -> Iterator[str]:
    for env in envs:
        yield env.model_dump_json(exclude_none=True) + "\n"


def _open_store(db: str | None):
    from ..store.factory import store_from_env, store_from_url
    return store_from_url(db) if db else store_from_env()


def _read_ldif(path: str) -> tuple[str, datetime | None]:
    if path == "-":
        return sys.stdin.read(), None
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    mtime = datetime.fromtimestamp(os.stat(path).st_mtime, tz=timezone.utc).replace(microsecond=0)
    return text, mtime


def main(argv: list[str] | None = None) -> None:
    import json

    parser = argparse.ArgumentParser(prog="loomctx.connectors.ldap", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--namespace", default=NAMESPACE_DEFAULT)
    common.add_argument("--source", default=SOURCE_DEFAULT, help="source / export label")
    common.add_argument("--as-of", dest="as_of",
                        help="ISO export timestamp when the LDIF carries no date comment")
    sub = parser.add_subparsers(dest="command", required=True)
    imp = sub.add_parser("import", parents=[common], help="map an LDIF export to envelopes and ingest them")
    imp.add_argument("ldif", help="an LDIF export, or - for stdin")
    imp.add_argument("--url", help="engine or gateway base URL (default: write straight into the store)")
    imp.add_argument("--db", help="write straight into this explicit store URL/path")
    imp.add_argument("--key", default=os.environ.get("LOOMCTX_API_KEY"), type=str.strip)
    imp.add_argument("--batch", type=int, default=500)
    imp.add_argument("--no-schema", action="store_true", help="skip the registry registration")
    emit = sub.add_parser("emit", parents=[common], help="write NDJSON envelopes to stdout")
    emit.add_argument("ldif")
    sub.add_parser("schema", parents=[common], help="print the schema registration")
    args = parser.parse_args(argv)

    if args.command == "schema":
        print(schema(args.namespace).model_dump_json(indent=2))
        return

    as_of = None
    if args.as_of:
        as_of = datetime.fromisoformat(args.as_of.replace("Z", "+00:00"))
        as_of = as_of if as_of.tzinfo else as_of.replace(tzinfo=timezone.utc)
    text, mtime = _read_ldif(args.ldif)
    stats: dict[str, int] = {}
    envs = ldif_to_envelopes(text, args.namespace, args.source, as_of, mtime, stats)

    if args.command == "emit":
        for line in _to_lines(envs):
            sys.stdout.write(line)
        print(json.dumps({"envelopes": stats}), file=sys.stderr)
        return

    if args.url and args.db:
        parser.error("import: give --url or --db, not both")
    from ..ingest import load_direct, post_batches
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
    rejected = totals.get("rejected", 0)
    if rejected:
        # a scheduled import must fail visibly, not "succeed" with a hole in
        # it (D-063)
        raise SystemExit(f"{rejected} envelopes were refused by the engine (see the lines above)")


if __name__ == "__main__":
    main()
