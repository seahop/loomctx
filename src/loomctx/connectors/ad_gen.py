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
}

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

    # -- helpers ------------------------------------------------------------ #

    def _rid(self) -> int:
        self.next_rid += 1
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
        u.member_of.append(self.rng.choice(self.groups).dn)
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
                    g = self.rng.choice(self.groups)
                    tgt, ttype = self._target(self.rng.choice(["dc", "da"]))
                    right = self.rng.choice(rights)
                    edges = [self._member(start, g), self._grant(g, tgt, ttype, right)]
                    target = _ref(ttype, tgt.sid)
                elif hops == 3:
                    g1, g2 = self.rng.sample(self.groups, 2)
                    tgt, ttype = self._target(self.rng.choice(["dc", "da"]))
                    right = self.rng.choice(rights)
                    edges = [self._member(start, g1), self._nest(g1, g2),
                             self._grant(g2, tgt, ttype, right)]
                    target = _ref(ttype, tgt.sid)
                else:  # 4-hop, cross-domain via the transitive dev.local trust
                    g1, g2 = self.rng.sample(self.groups, 2)
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
            g = self.rng.choice(self.groups)
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
            g = self.rng.choice(self.groups)
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
            g = self.rng.choice(self.groups)
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
            "seed": self.seed, "scale": self.scale, "export_at": EXPORT_DATE,
            "namespace_hint": "ad", "corp_sid": self.corp_sid,
            "counts": {"objects": len(self.objects), "users": len(self.users),
                       "groups": len(self.groups), "computers": len(self.computers),
                       "dcs": len(self.dcs),
                       "planted_chains": len(self.chains), "decoys": len(self.decoys),
                       "raw_membership_and_ace_edges": edges},
            "chains": self.chains, "decoys": self.decoys}


def generate(seed: int, scale: str) -> tuple[str, dict]:
    return Generator(seed, scale).build()


# --------------------------------------------------------------------- CLI #

def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loomctx.connectors.ad_gen", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--scale", default="medium", choices=list(SCALES))
    parser.add_argument("--out", default="corp.ldif", help="LDIF output path (- for stdout)")
    parser.add_argument("--truth", help="sidecar JSON of planted chains + decoys "
                                        "(default: <out>.truth.json)")
    args = parser.parse_args(argv)

    ldif, truth = generate(args.seed, args.scale)
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
