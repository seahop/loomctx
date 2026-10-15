"""Synthetic Active Directory generator for the object-level reachability
benchmark (`loomctx.ad_eval`, the AD analogue of the KEV multi-hop retrieval
benchmark).

    python -m loomctx.connectors.ad_gen --seed 7 --scale medium --out corp.ldif --truth corp.truth.json

It emits a realistically-sized, **obviously fake** directory as canonical
LDIF that `loomctx.connectors.ldap` already parses (base64 objectSid, memberOf
nesting, nTSecurityDescriptor with real self-relative SD/ACE bytes for the
ACL edges, trustedDomain with direction/transitivity/SID-filtering,
userAccountControl, SPNs, msDS-AllowedTo*). Into that directory it plants a
known set of reachability chains — a low-privilege principal to a high-value
target, threading membership -> ACL -> (cross-domain) trust — and buries
them under dense benign membership, containment and ACL noise so the signal
paths are a small fraction of all edges.

Determinism: everything is drawn from one seeded RNG in a fixed order, so
`--seed S --scale X` always produces byte-identical LDIF and truth.

It plants nothing exploitable and computes no path *ranking*: the truth
sidecar records, per chain, the ordered (subject, predicate, object) edges
and the disqualifier of each **decoy** (a chain that looks like it connects
but dead-ends at a non-transitive trust, a SID-filtered trust or a disabled
account). `loomctx.ad_eval` measures only whether LoomCtx's scope walk surfaces
and cites the edges that already exist in the generated facts.

Styles: `plain` (the default; the published benchmarks) names objects
`u00001` / `grp00001` in flat OUs with evenly spread membership. `realistic`
builds the same planted structure into a directory shaped like a real
export: generated first.last names, site and department OUs, workstation,
server and DC naming, an OS mix, disabled and service accounts, admin
tiering, and heavy-tailed group sizes (an all-employees group, department-
and site-wide groups, a long tail of app / share / project groups). Plain
output is byte-identical whatever realistic does.

Domains: `corp.local` (root), `dev.local` (a bidirectional, transitive
child-domain trust used by the good cross-domain chains) and two external
partners used only by decoy trusts — `partner.local` (non-transitive) and
`fabrikam.local` (SID-filtered / quarantined). All names are generated;
there is no real organisation data.
"""

from __future__ import annotations

import argparse
import base64
import json
import random
import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from . import ldap

# Reuse the connector's right / GUID / ACE-type / UAC / trust constants so the
# bytes we emit are exactly what its parser decodes (never duplicated here).
GENERIC_ALL = ldap.GENERIC_ALL
WRITE_DAC = ldap.WRITE_DAC
WRITE_OWNER = ldap.WRITE_OWNER
GENERIC_WRITE = ldap.GENERIC_WRITE
DS_CONTROL_ACCESS = ldap.ADS_RIGHT_DS_CONTROL_ACCESS
DS_WRITE_PROP = ldap.ADS_RIGHT_DS_WRITE_PROP
GUID_FORCE_CHANGE_PASSWORD = ldap.GUID_FORCE_CHANGE_PASSWORD
GUID_MEMBER_ATTR = ldap.GUID_MEMBER_ATTR

# The right a planted has_ace edge grants, and the (mask, object_type) that
# make the connector decode exactly that right.
RIGHT_ENCODING: dict[str, tuple[int, str | None]] = {
    "GenericAll": (GENERIC_ALL, None),
    "WriteDacl": (WRITE_DAC, None),
    "WriteOwner": (WRITE_OWNER, None),
    "GenericWrite": (GENERIC_WRITE, None),
    "ForceChangePassword": (DS_CONTROL_ACCESS, GUID_FORCE_CHANGE_PASSWORD),
    "AddMember": (DS_WRITE_PROP, GUID_MEMBER_ATTR),
}

# userAccountControl values (bits from the connector)
UAC_NORMAL = 0x0200                                   # NORMAL_ACCOUNT, enabled
UAC_DISABLED = UAC_NORMAL | ldap.UAC_ACCOUNTDISABLE   # enabled == False
UAC_DC = 0x0200 | ldap.UAC_SERVER_TRUST_ACCOUNT | ldap.UAC_TRUSTED_FOR_DELEGATION
UAC_WORKSTATION = 0x1000                              # WORKSTATION_TRUST_ACCOUNT

CORP_DOMAIN = "corp.local"
DEV_DOMAIN = "dev.local"
PARTNER_NONTRANSITIVE = "partner.local"
PARTNER_SIDFILTERED = "fabrikam.local"

EXPORT_DATE = "2026-09-20T09:00:00Z"

SCALES: dict[str, dict[str, int]] = {
    # ~users / groups / computers, and the max group-nesting depth
    "tiny": {"users": 60, "groups": 20, "computers": 25, "nest": 3},
    "small": {"users": 500, "groups": 100, "computers": 150, "nest": 3},
    "medium": {"users": 3000, "groups": 600, "computers": 800, "nest": 5},
    "large": {"users": 10000, "groups": 1500, "computers": 2000, "nest": 5},
    # ~500,000 objects, same proportions as large: the scale measurement (docs/future-work.md item 0)
    "xl": {"users": 370000, "groups": 55000, "computers": 75000, "nest": 5},
}

# RIDs agent_eval_ext plants its fixed objects at (95001-95204); the generator
# hands out RIDs in sequence and skips this block, so a forest big enough to
# reach it never collides with them. Smaller scales stop short of it, so their
# output is unchanged.
RESERVED_RIDS = range(95000, 96000)

# how many chains to plant per hop bucket, and how many decoys of each kind
PLANT = {2: 4, 3: 4, 4: 3}
DECOYS = {"non_transitive_trust": 2, "sid_filtered_trust": 2, "disabled_principal": 2}


# ------------------------------------------------------------ binary encode #

def encode_sid(text: str) -> bytes:
    """The inverse of `ldap.decode_sid`: `S-1-5-21-..-<rid>` -> binary SID."""
    parts = text.split("-")
    revision = int(parts[1])
    authority = int(parts[2])
    subs = [int(p) for p in parts[3:]]
    out = bytes([revision, len(subs)]) + authority.to_bytes(6, "big")
    for sub in subs:
        out += sub.to_bytes(4, "little")
    return out


def guid_bytes(text: str) -> bytes:
    h = text.split("-")
    return (int(h[0], 16).to_bytes(4, "little") + int(h[1], 16).to_bytes(2, "little")
            + int(h[2], 16).to_bytes(2, "little") + bytes.fromhex(h[3]) + bytes.fromhex(h[4]))


def allowed_ace(sid: str, mask: int) -> bytes:
    body = struct.pack("<I", mask) + encode_sid(sid)
    return struct.pack("<BBH", ldap.ACE_ACCESS_ALLOWED, 0x00, 4 + len(body)) + body


def object_ace(sid: str, mask: int, object_type: str | None) -> bytes:
    flags = ldap.ACE_OBJECT_TYPE_PRESENT if object_type else 0
    body = struct.pack("<II", mask, flags)
    if object_type:
        body += guid_bytes(object_type)
    body += encode_sid(sid)
    return struct.pack("<BBH", ldap.ACE_ACCESS_ALLOWED_OBJECT, 0x00, 4 + len(body)) + body


def ace_for_right(trustee_sid: str, right: str) -> bytes:
    mask, object_type = RIGHT_ENCODING[right]
    return object_ace(trustee_sid, mask, object_type) if object_type else allowed_ace(trustee_sid, mask)


def build_sd(aces: list[bytes]) -> bytes:
    """A self-relative Security Descriptor whose DACL holds `aces` (owner /
    group / SACL empty), the layout `ldap.parse_security_descriptor` reads."""
    acl_body = b"".join(aces)
    acl = struct.pack("<BBHHH", 4, 0, 8 + len(acl_body), len(aces), 0) + acl_body
    header = struct.pack("<BBHIIII", 1, 0, 0x8004, 0, 0, 0, 20)   # DACL present + self-relative
    return header + acl


def b64(blob: bytes) -> str:
    return base64.b64encode(blob).decode("ascii")


# --------------------------------------------------------------- LDIF model #

@dataclass
class Obj:
    dn: str
    object_class: list[str]
    sid: str | None = None
    attrs: list[tuple[str, str]] = field(default_factory=list)   # (name, value), plain
    member_of: list[str] = field(default_factory=list)           # DNs
    aces: list[bytes] = field(default_factory=list)              # DACL ACEs on this object
    b64_attrs: list[tuple[str, bytes]] = field(default_factory=list)  # (name, raw) -> base64

    def add(self, name: str, value: str) -> None:
        self.attrs.append((name, value))

    def render(self) -> str:
        lines = [f"dn: {self.dn}"]
        for cls in self.object_class:
            lines.append(f"objectClass: {cls}")
        if self.sid is not None:
            lines.append(f"objectSid:: {b64(encode_sid(self.sid))}")
        for name, value in self.attrs:
            lines.append(f"{name}: {value}")
        for group_dn in self.member_of:
            lines.append(f"memberOf: {group_dn}")
        if self.sid is not None:
            # every object of a real dump carries a descriptor, most with no
            # grant the connector decodes; an empty DACL stands for those, so
            # the export reads as fully collected (D-082)
            lines.append(f"nTSecurityDescriptor:: {b64(build_sd(self.aces))}")
        for name, raw in self.b64_attrs:
            lines.append(f"{name}:: {b64(raw)}")
        return "\n".join(lines)


# ------------------------------------------------------------- edge / truth #

def _ref(etype: str, key: str) -> dict:
    return {"type": etype, "key": key}


def _edge(subject: dict, predicate: str, obj: dict, right: str | None = None) -> dict:
    e = {"subject": subject, "predicate": predicate, "object": obj}
    if right is not None:
        e["right"] = right
    return e


# --------------------------------------------------------------- generator #

class Generator:
    def __init__(self, seed: int, scale: str):
        if scale not in SCALES:
            raise SystemExit(f"unknown scale {scale!r}; choose from {', '.join(SCALES)}")
        self.seed = seed
        self.scale = scale
        self.dims = SCALES[scale]
        self.rng = random.Random(f"ad_gen:{seed}:{scale}")
        self.corp_sid = "S-1-5-21-1111111111-2222222222-3333333333"
        self.next_rid = 2000
        self.objects: list[Obj] = []
        self.by_sid: dict[str, Obj] = {}
        self._dn_index: dict[str, Obj] = {}
        self.users: list[Obj] = []
        self.groups: list[Obj] = []
        self.computers: list[Obj] = []
        self.dcs: list[Obj] = []
        self.domain_admins: Obj | None = None
        self.domain_obj: Obj | None = None
        self.chains: list[dict] = []
        self.decoys: list[dict] = []
        self._dev_trust_edge: dict | None = None
        self.style = "plain"

    def _plant_groups(self) -> list[Obj]:
        """Groups a planted chain or decoy may run through."""
        return self.groups

    # -- helpers ------------------------------------------------------------ #

    def _rid(self) -> int:
        self.next_rid += 1
        if self.next_rid in RESERVED_RIDS:
            self.next_rid = RESERVED_RIDS.stop
        return self.next_rid

    def _sid(self, rid: int | None = None) -> str:
        return f"{self.corp_sid}-{rid if rid is not None else self._rid()}"

    def _add(self, obj: Obj) -> Obj:
        self.objects.append(obj)
        self._dn_index[obj.dn] = obj
        if obj.sid is not None:
            self.by_sid[obj.sid] = obj
        return obj

    # -- structural objects ------------------------------------------------- #

    def _containers(self) -> None:
        self.domain_obj = self._add(Obj("DC=corp,DC=local", ["top", "domain", "domainDNS"],
                                        sid=self.corp_sid, attrs=[("name", "corp.local")]))
        for cn in ("Users", "Computers", "System"):
            self._add(Obj(f"CN={cn},DC=corp,DC=local", ["top", "container"],
                          sid=self._sid(), attrs=[("name", cn)]))
        for ou in ("Workstations", "Servers", "Domain Controllers", "Staff"):
            self._add(Obj(f"OU={ou},DC=corp,DC=local", ["top", "organizationalUnit"],
                          sid=self._sid(), attrs=[("name", ou)]))

    def _groups(self) -> None:
        self.domain_admins = self._add(Obj(
            "CN=Domain Admins,CN=Users,DC=corp,DC=local", ["top", "group"],
            sid=self._sid(512), attrs=[("name", "Domain Admins"), ("sAMAccountName", "Domain Admins")]))
        self.groups.append(self.domain_admins)
        for i in range(self.dims["groups"]):
            name = f"grp{i:05d}"
            g = self._add(Obj(f"CN={name},CN=Users,DC=corp,DC=local", ["top", "group"],
                              sid=self._sid(), attrs=[("name", name), ("sAMAccountName", name)]))
            self.groups.append(g)
        # benign nesting: a group may be a member of a higher-indexed group,
        # to a bounded depth, forming a DAG (no cycles)
        depth_cap = self.dims["nest"]
        order = list(range(len(self.groups)))
        for idx in order:
            g = self.groups[idx]
            if self.rng.random() < 0.45 and idx + 1 < len(self.groups):
                parents = self.rng.sample(range(idx + 1, len(self.groups)),
                                          k=min(self.rng.randint(1, 2), len(self.groups) - idx - 1))
                for p in parents:
                    if self._nest_depth(self.groups[p]) < depth_cap:
                        g.member_of.append(self.groups[p].dn)

    def _nest_depth(self, group: Obj, seen: set[str] | None = None) -> int:
        seen = seen or set()
        if group.dn in seen or not group.member_of:
            return 0
        seen.add(group.dn)
        return 1 + max((self._nest_depth(self.by_dn(p), seen) for p in group.member_of
                        if self.by_dn(p) is not None), default=0)

    def by_dn(self, dn: str) -> Obj | None:
        return self._dn_index.get(dn)

    def _computers(self) -> None:
        n_dc = max(1, self.dims["computers"] // 200)
        for i in range(n_dc):
            name = f"DC{i:02d}"
            c = self._add(Obj(f"CN={name},OU=Domain Controllers,DC=corp,DC=local",
                              ["top", "computer"], sid=self._sid(),
                              attrs=[("name", name), ("sAMAccountName", f"{name}$"),
                                     ("operatingSystem", "Windows Server 2022 Standard"),
                                     ("userAccountControl", str(UAC_DC))]))
            self.computers.append(c)
            self.dcs.append(c)
        for i in range(self.dims["computers"] - n_dc):
            server = i % 3 == 0
            name = f"{'SRV' if server else 'WS'}{i:05d}"
            ou = "Servers" if server else "Workstations"
            os_name = "Windows Server 2019 Standard" if server else "Windows 11 Enterprise"
            c = Obj(f"CN={name},OU={ou},DC=corp,DC=local", ["top", "computer"], sid=self._sid(),
                    attrs=[("name", name), ("sAMAccountName", f"{name}$"),
                           ("operatingSystem", os_name), ("userAccountControl", str(UAC_WORKSTATION))])
            if server and self.rng.random() < 0.3:
                c.add("servicePrincipalName", f"MSSQLSvc/{name.lower()}.corp.local:1433")
            self.computers.append(self._add(c))

    def _users(self) -> None:
        for i in range(self.dims["users"]):
            name = f"u{i:05d}"
            svc = self.rng.random() < 0.06
            u = Obj(f"CN={name},OU=Staff,DC=corp,DC=local", ["top", "person", "user"],
                    sid=self._sid(), attrs=[("name", name), ("sAMAccountName", name),
                                            ("userAccountControl", str(UAC_NORMAL))])
            if svc:
                u.add("servicePrincipalName", f"HTTP/{name}.corp.local")
            # dense benign membership: 1-4 random groups
            for g in self.rng.sample(self.groups, k=min(self.rng.randint(1, 4), len(self.groups))):
                u.member_of.append(g.dn)
            self.users.append(self._add(u))

    def _benign_acls(self) -> None:
        """Sprinkle benign has_ace edges so the signal ACEs are a small
        fraction: a random operations group gets a low-value right over a
        random slice of users / computers."""
        targets = self.users + self.computers
        n = max(20, len(targets) // 5)
        for _ in range(n):
            tgt = self.rng.choice(targets)
            if tgt in self.dcs or tgt is self.domain_admins:
                continue
            grp = self.rng.choice(self.groups)
            right = self.rng.choice(["GenericWrite", "WriteOwner", "ForceChangePassword", "AddMember"])
            tgt.aces.append(ace_for_right(grp.sid, right))

    # -- planting ----------------------------------------------------------- #

    def _low_priv_user(self, tag: str, disabled: bool = False) -> Obj:
        rid = self._rid()
        name = f"svc-low-{tag}-{rid}"
        uac = UAC_DISABLED if disabled else UAC_NORMAL
        u = Obj(f"CN={name},OU=Staff,DC=corp,DC=local", ["top", "person", "user"],
                sid=self._sid(rid), attrs=[("name", name), ("sAMAccountName", name),
                                           ("userAccountControl", str(uac))])
        # one benign group for camouflage
        u.member_of.append(self.rng.choice(self._plant_groups()).dn)
        self.users.append(self._add(u))
        return u

    def _nest(self, child: Obj, parent: Obj) -> dict:
        if parent.dn not in child.member_of:
            child.member_of.append(parent.dn)
        return _edge(_ref("group", child.sid), "member_of", _ref("group", parent.sid))

    def _member(self, user: Obj, group: Obj) -> dict:
        if group.dn not in user.member_of:
            user.member_of.append(group.dn)
        return _edge(_ref("user", user.sid), "member_of", _ref("group", group.sid))

    def _grant(self, group: Obj, target: Obj, target_type: str, right: str) -> dict:
        target.aces.append(ace_for_right(group.sid, right))
        # a domain is keyed by its DNS name (D-099), everything else by SID
        key = CORP_DOMAIN if target_type == "domain" else target.sid
        return _edge(_ref("group", group.sid), "has_ace", _ref(target_type, key), right)

    def _trust(self, partner: str, attributes: int, direction: int = 3) -> dict:
        self._add(Obj(f"CN={partner},CN=System,DC=corp,DC=local", ["top", "trustedDomain"],
                      attrs=[("name", partner), ("trustPartner", partner),
                             ("trustDirection", str(direction)), ("trustAttributes", str(attributes))]))
        return _edge(_ref("domain", CORP_DOMAIN), "trusts", _ref("domain", partner))

    def _target(self, kind: str) -> tuple[Obj, str]:
        if kind == "dc":
            return self.rng.choice(self.dcs), "computer"
        return self.domain_admins, "group"

    def _plant_chains(self) -> None:
        rights = ["GenericAll", "WriteDacl", "ForceChangePassword", "AddMember"]
        seq = 0
        for hops in (2, 3, 4):
            for _ in range(PLANT[hops]):
                seq += 1
                cid = f"chain-{hops}hop-{seq}"
                start = self._low_priv_user(f"{hops}h{seq}")
                if hops == 2:
                    g = self.rng.choice(self._plant_groups())
                    tgt, ttype = self._target(self.rng.choice(["dc", "da"]))
                    right = self.rng.choice(rights)
                    edges = [self._member(start, g), self._grant(g, tgt, ttype, right)]
                    target = _ref(ttype, tgt.sid)
                elif hops == 3:
                    g1, g2 = self.rng.sample(self._plant_groups(), 2)
                    tgt, ttype = self._target(self.rng.choice(["dc", "da"]))
                    right = self.rng.choice(rights)
                    edges = [self._member(start, g1), self._nest(g1, g2),
                             self._grant(g2, tgt, ttype, right)]
                    target = _ref(ttype, tgt.sid)
                else:  # 4-hop, cross-domain via the transitive dev.local trust
                    g1, g2 = self.rng.sample(self._plant_groups(), 2)
                    edges = [self._member(start, g1), self._nest(g1, g2),
                             self._grant(g2, self.domain_obj, "domain", "GenericAll"),
                             self._dev_trust()]
                    target = _ref("domain", DEV_DOMAIN)
                self.chains.append({"id": cid, "hops": hops, "kind": "chain",
                                    "start": _ref("user", start.sid), "target": target,
                                    "edges": edges})

    def _dev_trust(self) -> dict:
        if self._dev_trust_edge is None:
            self._dev_trust_edge = self._trust(DEV_DOMAIN, ldap.TRUST_FOREST_TRANSITIVE)
        return self._dev_trust_edge

    def _plant_decoys(self) -> None:
        seq = 0
        # non-transitive trust: looks like a cross-domain path, dead-ends at
        # the trust (transitive == False)
        nt_edge = self._trust(PARTNER_NONTRANSITIVE,
                              ldap.TRUST_NON_TRANSITIVE | ldap.TRUST_FOREST_TRANSITIVE)
        for _ in range(DECOYS["non_transitive_trust"]):
            seq += 1
            start = self._low_priv_user(f"dt{seq}")
            g = self.rng.choice(self._plant_groups())
            edges = [self._member(start, g), self._grant(g, self.domain_obj, "domain", "GenericAll"),
                     nt_edge]
            self.decoys.append({
                "id": f"decoy-nontransitive-{seq}", "kind": "decoy",
                "reason": "non_transitive_trust", "start": _ref("user", start.sid),
                "target": _ref("domain", PARTNER_NONTRANSITIVE), "edges": edges,
                "disqualifier": {"edge_index": 2, "predicate": "trusts", "attr": "transitive",
                                 "value": False}})
        # SID-filtered / quarantined trust: dead-ends at the trust
        sf_edge = self._trust(PARTNER_SIDFILTERED,
                             ldap.TRUST_QUARANTINED_DOMAIN | ldap.TRUST_FOREST_TRANSITIVE)
        for _ in range(DECOYS["sid_filtered_trust"]):
            seq += 1
            start = self._low_priv_user(f"sf{seq}")
            g = self.rng.choice(self._plant_groups())
            edges = [self._member(start, g), self._grant(g, self.domain_obj, "domain", "GenericAll"),
                     sf_edge]
            self.decoys.append({
                "id": f"decoy-sidfiltered-{seq}", "kind": "decoy",
                "reason": "sid_filtered_trust", "start": _ref("user", start.sid),
                "target": _ref("domain", PARTNER_SIDFILTERED), "edges": edges,
                "disqualifier": {"edge_index": 2, "predicate": "trusts", "attr": "sid_filtering",
                                 "value": True}})
        # disabled principal: the start account cannot authenticate, so the
        # membership -> ACL path is inert
        for _ in range(DECOYS["disabled_principal"]):
            seq += 1
            start = self._low_priv_user(f"dp{seq}", disabled=True)
            g = self.rng.choice(self._plant_groups())
            tgt, ttype = self._target("da")
            edges = [self._member(start, g), self._grant(g, tgt, ttype, "GenericAll")]
            self.decoys.append({
                "id": f"decoy-disabled-{seq}", "kind": "decoy",
                "reason": "disabled_principal", "start": _ref("user", start.sid),
                "target": _ref(ttype, tgt.sid), "edges": edges,
                "disqualifier": {"ref": _ref("user", start.sid), "predicate": "enabled",
                                 "value": False}})

    # -- drive -------------------------------------------------------------- #

    def build(self) -> tuple[str, dict]:
        self._containers()
        self._groups()
        self._computers()
        self._users()
        self._benign_acls()
        self._plant_chains()
        self._plant_decoys()
        return self._render(), self._truth()

    def _render(self) -> str:
        head = ["# Synthetic AD export for the LoomCtx reachability benchmark (loomctx.connectors.ad_gen).",
                f"# NOT real data. seed={self.seed} scale={self.scale}. Domains corp.local,",
                "# dev.local (trusted child), partner.local + fabrikam.local (decoy trusts).",
                f"# {EXPORT_DATE}", "version: 1", ""]
        blocks = [o.render() for o in self.objects]
        return "\n".join(head) + "\n\n".join(blocks) + "\n"

    def _truth(self) -> dict:
        edges = sum(len(o.member_of) for o in self.objects)
        edges += sum(len(o.aces) for o in self.objects)
        return {
            "seed": self.seed, "scale": self.scale, "style": self.style, "export_at": EXPORT_DATE,
            "namespace_hint": "ad", "corp_sid": self.corp_sid,
            "counts": {"objects": len(self.objects), "users": len(self.users),
                       "groups": len(self.groups), "computers": len(self.computers),
                       "dcs": len(self.dcs),
                       "planted_chains": len(self.chains), "decoys": len(self.decoys),
                       "raw_membership_and_ace_edges": edges},
            "chains": self.chains, "decoys": self.decoys}


# --------------------------------------------------------- realistic style #

STYLES = ("plain", "realistic")

FIRST = ["James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda", "David", "Elizabeth",
         "William", "Barbara", "Richard", "Susan", "Joseph", "Jessica", "Thomas", "Sarah", "Charles", "Karen",
         "Daniel", "Lisa", "Matthew", "Nancy", "Anthony", "Sandra", "Mark", "Ashley", "Steven", "Emily",
         "Paul", "Michelle", "Andrew", "Amanda", "Joshua", "Melissa", "Kevin", "Stephanie", "Brian", "Rebecca",
         "George", "Laura", "Timothy", "Helen", "Ryan", "Amy", "Jacob", "Anna", "Gary", "Olivia",
         "Wei", "Mei", "Hiroshi", "Yuki", "Raj", "Priya", "Arjun", "Ananya", "Mohammed", "Fatima",
         "Omar", "Aisha", "Carlos", "Sofia", "Diego", "Lucia", "Mateo", "Valentina", "Luca", "Giulia",
         "Lukas", "Hannah", "Jonas", "Lea", "Pierre", "Camille", "Hugo", "Chloe", "Sven", "Ingrid",
         "Kwame", "Amara", "Chinedu", "Zainab", "Dmitri", "Olga", "Ivan", "Natalia", "Min-jun", "Seo-yeon",
         "Thanh", "Linh", "Kenji", "Aiko", "Ahmed", "Leila", "Noah", "Emma", "Liam", "Ava"]
LAST = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez",
        "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
        "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson",
        "Walker", "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
        "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell", "Carter", "Roberts",
        "Chen", "Wang", "Li", "Zhang", "Liu", "Yang", "Huang", "Zhao", "Tanaka", "Suzuki",
        "Sato", "Watanabe", "Kim", "Park", "Choi", "Patel", "Shah", "Singh", "Kumar", "Gupta",
        "Sharma", "Iyer", "Khan", "Ali", "Hassan", "Rahman", "Mueller", "Schmidt", "Schneider", "Fischer",
        "Weber", "Meyer", "Dubois", "Moreau", "Laurent", "Rossi", "Russo", "Ferrari", "Esposito", "Bianchi",
        "Silva", "Santos", "Oliveira", "Costa", "Pereira", "Novak", "Kowalski", "Ivanov", "Petrov", "Larsen",
        "Andersen", "Nielsen", "Johansson", "Eriksson", "OBrien", "Murphy", "Kelly", "Okafor", "Mensah", "Abara"]
SITES = [("NYC", "New York", 30), ("LON", "London", 22), ("SFO", "San Francisco", 15), ("SIN", "Singapore", 10),
         ("FRA", "Frankfurt", 10), ("TOR", "Toronto", 8), ("SYD", "Sydney", 5)]
DEPTS = [("ENG", "Engineering", 30), ("SLS", "Sales", 15), ("OPS", "Operations", 12), ("SUP", "Customer Support", 12),
         ("FIN", "Finance", 7), ("MKT", "Marketing", 7), ("IT", "IT", 6), ("HR", "Human Resources", 4),
         ("SEC", "Security", 3), ("LGL", "Legal", 3), ("EXE", "Executive", 1)]
TITLES = {
    "ENG": ["Software Engineer", "Senior Software Engineer", "Staff Engineer", "Engineering Manager",
            "QA Engineer", "Site Reliability Engineer", "Data Engineer"],
    "SLS": ["Account Executive", "Sales Manager", "Sales Engineer", "Business Development Rep"],
    "OPS": ["Operations Analyst", "Operations Manager", "Logistics Coordinator", "Program Manager"],
    "SUP": ["Support Engineer", "Support Specialist", "Support Team Lead"],
    "FIN": ["Financial Analyst", "Accountant", "Controller", "Payroll Specialist"],
    "MKT": ["Marketing Manager", "Content Strategist", "Product Marketing Manager", "Designer"],
    "IT": ["Systems Administrator", "Helpdesk Technician", "Network Engineer", "IT Manager", "Desktop Support"],
    "HR": ["HR Business Partner", "Recruiter", "HR Coordinator"],
    "SEC": ["Security Analyst", "Security Engineer", "Incident Responder", "GRC Analyst"],
    "LGL": ["Counsel", "Paralegal", "Contracts Manager"],
    "EXE": ["Vice President", "Director", "Chief of Staff", "Executive Assistant"],
}
APPS = ["Salesforce", "Workday", "Jira", "Confluence", "GitLab", "ServiceNow", "SAP", "Tableau", "Zoom", "Slack",
        "Splunk", "Jenkins", "Grafana", "NetSuite", "Concur", "Coupa", "Snowflake", "Databricks", "PowerBI",
        "SharePoint", "Box", "DocuSign", "HubSpot", "Zendesk", "Citrix", "VMware", "Veeam", "SCCM", "Intune", "Oracle"]
SHARES = ["Finance", "HR", "Legal", "Engineering", "Marketing", "Sales", "Ops", "Exec", "Projects", "Public",
          "Scans", "Archive", "Builds", "Releases", "Contracts", "Payroll", "Audit", "Design", "Support", "Data"]
CODENAMES = ["Atlas", "Borealis", "Cobalt", "Dune", "Ember", "Falcon", "Granite", "Harbor", "Iris", "Juniper",
             "Kestrel", "Lumen", "Meridian", "Nimbus", "Onyx", "Pioneer", "Quartz", "Raven", "Summit", "Tundra"]
POLICIES = ["USB-Block", "BitLocker", "LAPS", "Firewall", "Browser", "Office-Macros", "PowerShell-CLM", "WSUS",
            "AppLocker", "Defender", "Proxy", "Printers", "DriveMaps", "Screensaver", "RDP"]
SERVER_ROLES = [("SQL", 18), ("APP", 30), ("WEB", 15), ("FS", 10), ("PRN", 5), ("INF", 12), ("CTX", 10)]
ENVS = [("PRD", 60), ("UAT", 20), ("DEV", 20)]
WS_OS = [("Windows 11 Enterprise", "10.0 (22631)", 50), ("Windows 11 Enterprise", "10.0 (26100)", 15),
         ("Windows 10 Enterprise", "10.0 (19045)", 33), ("Windows 7 Professional", "6.1 (7601)", 2)]
SRV_OS = [("Windows Server 2022 Standard", "10.0 (20348)", 40), ("Windows Server 2019 Standard", "10.0 (17763)", 38),
          ("Windows Server 2016 Standard", "10.0 (14393)", 16), ("Windows Server 2012 R2 Standard", "6.3 (9600)", 6)]
BUILTIN_GROUPS = [(513, "Domain Users"), (515, "Domain Computers"), (516, "Domain Controllers"),
                  (518, "Schema Admins"), (519, "Enterprise Admins"), (520, "Group Policy Creator Owners")]
UAC_DONT_EXPIRE = 0x10000
EXPORT_AT = datetime(2026, 9, 20, 9, 0, tzinfo=timezone.utc)


def _filetime(when: datetime) -> str:
    """Windows FILETIME (100 ns since 1601), as lastLogonTimestamp / pwdLastSet carry it."""
    return str(int((when.timestamp() + 11644473600) * 10_000_000))


def _gentime(when: datetime) -> str:
    return when.strftime("%Y%m%d%H%M%S.0Z")


class RealisticGenerator(Generator):
    """The `realistic` style: the same planted chains and decoys as `plain`,
    buried in a directory shaped like a real export. Planted chains run only
    through the long-tail groups, never the department- or company-wide
    ones, so a chain stays a chain rather than reaching half the company."""

    def __init__(self, seed: int, scale: str):
        super().__init__(seed, scale)
        self.rng = random.Random(f"ad_gen:{seed}:{scale}:realistic")
        self.style = "realistic"
        self.bulk_groups: list[Obj] = []
        self._sams: set[str] = set()
        self._site_w = [w for *_, w in SITES]
        self._dept_w = [w for *_, w in DEPTS]
        self.staff: list[tuple[Obj, str, str]] = []         # (user, site code, dept code)

    def _plant_groups(self) -> list[Obj]:
        return self._plant_pool

    def _pick(self, table: list[tuple]) -> tuple:
        return self.rng.choices(table, weights=[row[-1] for row in table])[0]

    def _ago(self, max_days: int, min_days: int = 0) -> datetime:
        return EXPORT_AT - timedelta(days=self.rng.uniform(min_days, max_days), seconds=self.rng.randrange(86400))

    def _unique_dn(self, dn: str) -> str:
        if dn not in self._dn_index:
            return dn
        cn, rest = dn.split(",", 1)
        n = 2
        while f"{cn} {n},{rest}" in self._dn_index:
            n += 1
        return f"{cn} {n},{rest}"

    def _sam(self, first: str, last: str) -> str:
        base = f"{first}.{last}".lower().replace("'", "")
        if base not in self._sams:
            self._sams.add(base)
            return base
        mid = f"{first}.{self.rng.choice('abcdefghjklmnprstw')}.{last}".lower()
        if mid not in self._sams:
            self._sams.add(mid)
            return mid
        n = 2
        while f"{base}{n}" in self._sams:
            n += 1
        self._sams.add(f"{base}{n}")
        return f"{base}{n}"

    # -- structure ------------------------------------------------------------ #

    def _containers(self) -> None:
        super()._containers()
        for ou in ("Service Accounts", "Admins"):
            self._add(Obj(f"OU={ou},DC=corp,DC=local", ["top", "organizationalUnit"],
                          sid=self._sid(), attrs=[("name", ou)]))
        for code, city, _ in SITES:
            for parent in ("Staff", "Workstations"):
                self._add(Obj(f"OU={code},OU={parent},DC=corp,DC=local", ["top", "organizationalUnit"],
                              sid=self._sid(), attrs=[("name", code), ("description", city)]))
        for role, _ in SERVER_ROLES:
            self._add(Obj(f"OU={role},OU=Servers,DC=corp,DC=local", ["top", "organizationalUnit"],
                          sid=self._sid(), attrs=[("name", role)]))

    def _group(self, name: str, description: str, sid: str | None = None) -> Obj:
        g = self._add(Obj(f"CN={name},CN=Users,DC=corp,DC=local", ["top", "group"], sid=sid or self._sid(),
                          attrs=[("name", name), ("sAMAccountName", name), ("description", description)]))
        self.groups.append(g)
        return g

    def _groups(self) -> None:
        self.domain_admins = self._group("Domain Admins", "Designated administrators of the domain",
                                         sid=self._sid(512))
        self.builtin = {name: self._group(name, f"Built-in {name}", sid=self._sid(rid))
                        for rid, name in BUILTIN_GROUPS}
        self.all_staff = self._group("DL-All-Employees", "All active employees")
        self.site_groups = {c: self._group(f"SG-{c}-All", f"All staff at {city}") for c, city, _ in SITES}
        self.dept_groups = {c: self._group(f"SG-{c}-All", f"All of {name}") for c, name, _ in DEPTS}
        self.dept_site = {}
        for d, dname, _ in DEPTS:
            for s, city, _ in SITES:
                g = self._group(f"SG-{d}-{s}", f"{dname}, {city}")
                g.member_of += [self.dept_groups[d].dn, self.site_groups[s].dn]
                self.dept_site[(d, s)] = g
        self.it = {k: self._group(f"SG-IT-{k}", desc) for k, desc in (
            ("Helpdesk", "Password resets and account unlocks"),
            ("WorkstationAdmins", "Local admin on workstations"),
            ("ServerAdmins", "Local admin on member servers"),
            ("SQLAdmins", "SQL Server administrators"))}
        made = len(self.groups)
        kinds = [("app", 34), ("share", 22), ("project", 16), ("dl", 14), ("gpo", 8), ("vpn", 6)]
        seen: set[str] = set()
        # at least a small long tail even where the fixed groups fill the scale's count
        for _ in range(max(40, self.dims["groups"] - made)):
            kind = self._pick(kinds)[0]
            if kind == "app":
                app = self.rng.choice(APPS)
                name, desc = f"APP-{app}-{self.rng.choice(['Users', 'Users', 'Users', 'Admins', 'ReadOnly'])}", f"{app} access"
            elif kind == "share":
                share = self.rng.choice(SHARES)
                name, desc = f"FS-{share}-{self.rng.choice(['RO', 'RW'])}", f"\\\\fs\\{share} file share"
            elif kind == "project":
                name, desc = f"PRJ-{self.rng.choice(CODENAMES)}", "Project team"
            elif kind == "dl":
                name, desc = f"DL-{self.rng.choice(['Newsletter', 'Social', 'Announcements', 'OnCall', 'Training', 'Events'])}-{self.rng.choice(SITES)[0]}", "Distribution list"
            elif kind == "gpo":
                name, desc = f"GPO-{self.rng.choice(POLICIES)}-Exempt", "Group Policy filtering"
            else:
                name, desc = f"VPN-{self.rng.choice(['Full', 'Split', 'Vendor', 'Contractor'])}-{self.rng.choice(SITES)[0]}", "Remote access profile"
            if name in seen:
                n = 2
                while f"{name}-{n:02d}" in seen:
                    n += 1
                name = f"{name}-{n:02d}"
            seen.add(name)
            self.bulk_groups.append(self._group(name, desc))
        # nesting among the long tail: a DAG to the scale's depth cap
        cap, n = self.dims["nest"], len(self.bulk_groups)
        for idx, g in enumerate(self.bulk_groups):
            if self.rng.random() < 0.3 and idx + 1 < n:
                for p in self.rng.sample(range(idx + 1, n), k=min(self.rng.randint(1, 2), n - idx - 1)):
                    if self._nest_depth(self.bulk_groups[p]) < cap:
                        g.member_of.append(self.bulk_groups[p].dn)
        # popularity: a few long-tail groups are big, most are small (Zipf-like)
        order = list(range(n))
        self.rng.shuffle(order)
        weights = [0.0] * n
        for rank, i in enumerate(order):
            weights[i] = 1.0 / (rank + 1) ** 1.1
        self._bulk_cum: list[float] = []
        total = 0.0
        for w in weights:
            total += w
            self._bulk_cum.append(total)
        # planted chains avoid the most popular 2%: a chain through a group
        # half the company is in would hand everyone the path
        self._plant_pool = [self.bulk_groups[i] for i in order[max(1, n // 50):]] or self.bulk_groups

    def _computers(self) -> None:
        n = self.dims["computers"]
        n_dc = max(4, min(40, n // 1800))
        n_srv = n * 20 // 100
        for i in range(n_dc):
            site = SITES[i % len(SITES)][0]
            name = f"{site}-DC{i // len(SITES) + 1:02d}"
            os_name, os_ver, _ = SRV_OS[i % 2]
            c = self._add(Obj(f"CN={name},OU=Domain Controllers,DC=corp,DC=local", ["top", "computer"],
                              sid=self._sid(), attrs=[
                                  ("name", name), ("sAMAccountName", f"{name}$"),
                                  ("dNSHostName", f"{name.lower()}.corp.local"),
                                  ("operatingSystem", os_name), ("operatingSystemVersion", os_ver),
                                  ("userAccountControl", str(UAC_DC)),
                                  ("lastLogonTimestamp", _filetime(self._ago(2)))]))
            self.computers.append(c)
            self.dcs.append(c)
        seq: dict[str, int] = {}
        for _ in range(n_srv):
            role, env = self._pick(SERVER_ROLES)[0], self._pick(ENVS)[0]
            seq[role + env] = seq.get(role + env, 0) + 1
            name = f"{role}-{env}-{seq[role + env]:03d}"
            os_name, os_ver, _ = self._pick(SRV_OS)
            fqdn = f"{name.lower()}.corp.local"
            stale = self.rng.random() < 0.03
            c = Obj(f"CN={name},OU={role},OU=Servers,DC=corp,DC=local", ["top", "computer"], sid=self._sid(),
                    attrs=[("name", name), ("sAMAccountName", f"{name}$"), ("dNSHostName", fqdn),
                           ("operatingSystem", os_name), ("operatingSystemVersion", os_ver),
                           ("userAccountControl", str(UAC_WORKSTATION | (ldap.UAC_ACCOUNTDISABLE if stale else 0))),
                           ("lastLogonTimestamp", _filetime(self._ago(400, 120) if stale else self._ago(14)))])
            if role == "SQL":
                c.add("servicePrincipalName", f"MSSQLSvc/{fqdn}:1433")
            elif role == "WEB":
                c.add("servicePrincipalName", f"HTTP/{fqdn}")
            self.computers.append(self._add(c))
        for _ in range(n - n_dc - n_srv):
            site = self._pick(SITES)[0]
            kind = "LT" if self.rng.random() < 0.55 else "WS"
            seq[site + kind] = seq.get(site + kind, 0) + 1
            name = f"{site}-{kind}-{seq[site + kind]:05d}"
            os_name, os_ver, _ = self._pick(WS_OS)
            stale = self.rng.random() < 0.06
            c = Obj(f"CN={name},OU={site},OU=Workstations,DC=corp,DC=local", ["top", "computer"], sid=self._sid(),
                    attrs=[("name", name), ("sAMAccountName", f"{name}$"),
                           ("dNSHostName", f"{name.lower()}.corp.local"),
                           ("operatingSystem", os_name), ("operatingSystemVersion", os_ver),
                           ("userAccountControl", str(UAC_WORKSTATION | (ldap.UAC_ACCOUNTDISABLE if stale else 0))),
                           ("lastLogonTimestamp", _filetime(self._ago(500, 90) if stale else self._ago(21)))])
            self.computers.append(self._add(c))

    def _person(self, ou_dn: str, first: str, last: str, sam: str, uac: int, extra: list[tuple[str, str]]) -> Obj:
        cn = f"{first} {last}"
        u = Obj(self._unique_dn(f"CN={cn},{ou_dn}"), ["top", "person", "organizationalPerson", "user"],
                sid=self._sid(), attrs=[
                    ("name", cn), ("displayName", cn), ("givenName", first), ("sn", last),
                    ("sAMAccountName", sam), ("userPrincipalName", f"{sam}@corp.local"),
                    ("mail", f"{sam}@corp.local"), ("userAccountControl", str(uac)), *extra])
        return u

    def _staff_user(self, disabled: bool | None = None) -> tuple[Obj, str, str]:
        site, city, _ = self._pick(SITES)
        dept, dname, _ = self._pick(DEPTS)
        first, last = self.rng.choice(FIRST), self.rng.choice(LAST)
        if disabled is None:
            disabled = self.rng.random() < 0.08
        uac = UAC_DISABLED if disabled else (UAC_NORMAL | UAC_DONT_EXPIRE if self.rng.random() < 0.03 else UAC_NORMAL)
        created = self._ago(3000, 30)
        u = self._person(f"OU={site},OU=Staff,DC=corp,DC=local", first, last, self._sam(first, last), uac, [
            ("department", dname), ("title", self.rng.choice(TITLES[dept])), ("company", "Corp"),
            ("physicalDeliveryOfficeName", city), ("whenCreated", _gentime(created)),
            ("pwdLastSet", _filetime(self._ago(365))),
            ("lastLogonTimestamp", _filetime(self._ago(400, 60) if disabled else self._ago(14)))])
        return u, site, dept

    def _extra_groups(self, user: Obj, k: int) -> None:
        if not self.bulk_groups:
            return
        picks = self.rng.choices(self.bulk_groups, cum_weights=self._bulk_cum, k=k)
        user.member_of.extend(dict.fromkeys(g.dn for g in picks))      # deduplicated, in order

    def _users(self) -> None:
        n = self.dims["users"]
        n_svc, n_adm = max(5, n * 4 // 100), max(3, n // 200)
        it_staff: list[Obj] = []
        for _ in range(n - n_svc - n_adm):
            u, site, dept = self._staff_user()
            u.member_of.append(self.dept_site[(dept, site)].dn)
            if "514" != dict(u.attrs)["userAccountControl"]:
                u.member_of.append(self.all_staff.dn)
            self._extra_groups(u, min(8, 1 + int(self.rng.expovariate(0.45))))
            if dept == "IT":
                it_staff.append(u)
                if self.rng.random() < 0.4:
                    u.member_of.append(self.it["Helpdesk"].dn)
            self.users.append(self._add(u))
            self.staff.append((u, site, dept))
        for i in range(n_svc):
            app = self.rng.choice(APPS)
            sam = f"svc-{app.lower()}-{i:03d}"
            self._sams.add(sam)
            u = Obj(f"CN={sam},OU=Service Accounts,DC=corp,DC=local", ["top", "person", "user"], sid=self._sid(),
                    attrs=[("name", sam), ("sAMAccountName", sam), ("userPrincipalName", f"{sam}@corp.local"),
                           ("description", f"{app} service account"),
                           ("userAccountControl", str(UAC_DISABLED if self.rng.random() < 0.05
                                                      else UAC_NORMAL | UAC_DONT_EXPIRE)),
                           ("pwdLastSet", _filetime(self._ago(2500, 200)))])
            u.add("servicePrincipalName", f"{self.rng.choice(['MSSQLSvc', 'HTTP'])}/{app.lower()}.corp.local")
            self._extra_groups(u, 1)
            self.users.append(self._add(u))
        admins = []
        for i in range(n_adm):
            src = it_staff[i % len(it_staff)] if it_staff else None
            sam = f"adm-{dict(src.attrs)['sAMAccountName']}" if src else f"adm-{i:03d}"
            if sam in self._sams:
                sam = f"{sam}{i}"
            self._sams.add(sam)
            u = Obj(f"CN={sam},OU=Admins,DC=corp,DC=local", ["top", "person", "user"], sid=self._sid(),
                    attrs=[("name", sam), ("sAMAccountName", sam), ("userPrincipalName", f"{sam}@corp.local"),
                           ("description", "Tier admin account"), ("userAccountControl", str(UAC_NORMAL)),
                           ("lastLogonTimestamp", _filetime(self._ago(30)))])
            u.member_of.append(self.it[self.rng.choice(["WorkstationAdmins", "ServerAdmins", "SQLAdmins"])].dn)
            admins.append(self._add(u))
            self.users.append(u)
        for u in admins[:max(3, min(8, len(admins) // 50))]:
            u.member_of.append(self.domain_admins.dn)
        for u in admins[:2]:
            u.member_of.append(self.builtin["Enterprise Admins"].dn)

    def _benign_acls(self) -> None:
        """Delegated administration, as a real domain has it: the helpdesk can
        reset staff passwords, workstation and server admins manage their
        machines, app admin groups manage their service accounts."""
        workstations = [c for c in self.computers if ",OU=Workstations," in c.dn]
        servers = [c for c in self.computers if ",OU=Servers," in c.dn]
        # staff only: admin accounts are protected (AdminSDHolder), so the
        # helpdesk can't reset a Domain Admin's password
        staff = [u for u, _, _ in self.staff]
        for u in self.rng.sample(staff, k=len(staff) // 10):
            u.aces.append(ace_for_right(self.it["Helpdesk"].sid, "ForceChangePassword"))
        for c in self.rng.sample(workstations, k=len(workstations) // 10):
            c.aces.append(ace_for_right(self.it["WorkstationAdmins"].sid, "GenericWrite"))
        for c in self.rng.sample(servers, k=len(servers) // 5):
            c.aces.append(ace_for_right(self.it["ServerAdmins"].sid, "GenericWrite"))

    def _low_priv_user(self, tag: str, disabled: bool = False) -> Obj:
        # a planted start looks like anyone else on the staff list
        u, _, _ = self._staff_user(disabled=disabled)
        u.member_of.append(self.rng.choice(self.bulk_groups).dn)
        self.users.append(self._add(u))
        return u


def generate(seed: int, scale: str, style: str = "plain") -> tuple[str, dict]:
    if style not in STYLES:
        raise SystemExit(f"unknown style {style!r}; choose from {', '.join(STYLES)}")
    gen = RealisticGenerator(seed, scale) if style == "realistic" else Generator(seed, scale)
    return gen.build()


# --------------------------------------------------------------------- CLI #

def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loomctx.connectors.ad_gen", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--scale", default="medium", choices=list(SCALES))
    parser.add_argument("--style", default="plain", choices=STYLES,
                        help="plain (the published benchmarks) or realistic (names, OUs, hubs)")
    parser.add_argument("--out", default="corp.ldif", help="LDIF output path (- for stdout)")
    parser.add_argument("--truth", help="sidecar JSON of planted chains + decoys "
                                        "(default: <out>.truth.json)")
    args = parser.parse_args(argv)

    ldif, truth = generate(args.seed, args.scale, args.style)
    if args.out == "-":
        import sys
        sys.stdout.write(ldif)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(ldif)
    truth_path = args.truth or (args.out + ".truth.json" if args.out != "-" else "corp.truth.json")
    with open(truth_path, "w", encoding="utf-8") as fh:
        json.dump(truth, fh, indent=2)
    c = truth["counts"]
    print(json.dumps({"ldif": args.out, "truth": truth_path, **c}))


if __name__ == "__main__":
    main()
