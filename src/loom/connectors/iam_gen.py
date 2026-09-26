"""Synthetic Entra ID + Okta exports for the IAM connector scale check
(`loom.iam_eval`).

    python -m loom.connectors.iam_gen --seed 7 --scale medium --out-dir /data/iam

It writes three files: `entra.json` (a combined Graph export), `okta.json`
(a combined Okta API export) and `truth.json` (every relational edge the
connectors should produce, plus a handful of planted multi-hop paths and the
cross-IdP person overlap).

The exports use the shapes the real APIs return, not shapes chosen to suit
the connectors: role assignments come from
`/roleManagement/directory/roleAssignments?$expand=principal` (the principal
may be a group or a service principal), per-user OAuth2 consent grants for
the same client/resource/scope repeat across users, Okta app users come from
`/apps/{id}/users` (the app id only in `_links.app.href`) and Okta role
assignments from `/users|groups/{id}/roles` (the assignee only in
`_links.assignee.href`). Each directory also has one hub group that holds
every user (Entra "All Staff", Okta "Everyone").

Determinism: one seeded RNG drawn in a fixed order, so `--seed S --scale X`
is byte-reproducible. All names are generated; `example` domains only.
"""

from __future__ import annotations

import argparse
import json
import random
import uuid
from pathlib import Path

EXPORT_DATE = "2026-09-20T09:00:00Z"
GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
OKTA_BASE = "https://example.okta.com/api/v1"

SCALES: dict[str, dict[str, int]] = {
    "tiny": {"users": 300, "groups": 30, "sps": 12, "okta_apps": 10},
    "small": {"users": 2_000, "groups": 200, "sps": 60, "okta_apps": 60},
    "medium": {"users": 20_000, "groups": 1_500, "sps": 400, "okta_apps": 300},
    "large": {"users": 60_000, "groups": 4_000, "sps": 1_000, "okta_apps": 800},
}

ENTRA_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "f2ef992c-3afb-46b9-b7cf-a126ee74c451": "Global Reader",
    "5d6b6bb7-de71-4623-b4af-96380a352509": "Security Reader",
}
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
PRIV_ROLE_ADMIN = "e8611ab8-c189-46e8-94e1-60213ab1f814"
SECURITY_ADMIN = "194ae4cb-b126-40b2-bd5b-6091b380977d"

OKTA_ROLES = {
    "SUPER_ADMIN": "Super Administrator",
    "ORG_ADMIN": "Organization Administrator",
    "APP_ADMIN": "Application Administrator",
    "HELP_DESK_ADMIN": "Help Desk Administrator",
    "READ_ONLY_ADMIN": "Read-only Administrator",
}

FIRST = ["Ada", "Ben", "Cho", "Dev", "Eli", "Fay", "Gus", "Hana", "Ivo", "Jun",
         "Kai", "Lea", "Mo", "Nia", "Omar", "Pia", "Quin", "Rae", "Sol", "Tove"]
LAST = ["Abe", "Brandt", "Costa", "Dahl", "Endo", "Fox", "Gray", "Holm", "Ito",
        "Juarez", "Kang", "Lund", "Mora", "Nash", "Ortiz", "Park", "Rossi", "Sato"]
DEPTS = ["Engineering", "Finance", "Sales", "Support", "Security", "IT", "Legal", "HR"]
SCOPES = ["User.Read", "Mail.Read", "Files.Read", "Calendars.Read", "offline_access"]
FACTORS = ["push", "token:software:totp", "webauthn", "sms"]


def _ref(etype: str, key: str) -> dict:
    return {"type": etype, "key": key}


def _edge(s: dict, pred: str, o: dict) -> dict:
    return {"subject": s, "predicate": pred, "object": o}


class Generator:
    def __init__(self, seed: int, scale: str):
        if scale not in SCALES:
            raise ValueError(f"unknown scale {scale!r} (choose {sorted(SCALES)})")
        self.rng = random.Random(seed)
        self.n = SCALES[scale]
        self.seed, self.scale = seed, scale
        self.edges: set[tuple] = set()
        self.paths: list[dict] = []

    def uid(self) -> str:
        return str(uuid.UUID(int=self.rng.getrandbits(128), version=4))

    def okta_id(self, prefix: str) -> str:
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return prefix + "".join(self.rng.choice(chars) for _ in range(17))

    def add(self, s: dict, pred: str, o: dict) -> dict:
        self.edges.add((s["type"], s["key"], pred, o["type"], o["key"]))
        return _edge(s, pred, o)

    # ------------------------------------------------------------ people #
    def people(self) -> list[dict]:
        out = []
        for i in range(self.n["users"]):
            first, last = self.rng.choice(FIRST), self.rng.choice(LAST)
            out.append({"first": first, "last": last,
                        "mail": f"{first.lower()}.{last.lower()}{i}@corp.example",
                        "dept": self.rng.choice(DEPTS),
                        "title": self.rng.choice(["Engineer", "Analyst", "Manager", "Lead"])})
        return out

    # ------------------------------------------------------------- entra #
    def entra(self, people: list[dict]) -> dict:
        rng = self.rng
        users = []
        for i, p in enumerate(people):
            guest = rng.random() < 0.04
            upn = (f"{p['mail'].replace('@', '_')}#EXT#@corp.onmicrosoft.example"
                   if guest else p["mail"])
            users.append({
                "@odata.type": "#microsoft.graph.user", "id": self.uid(),
                "userPrincipalName": upn, "displayName": f"{p['first']} {p['last']}",
                "mail": p["mail"], "accountEnabled": rng.random() > 0.03,
                "userType": "Guest" if guest else "Member",
                "jobTitle": p["title"], "department": p["dept"]})
        for u in users[1:]:
            if rng.random() < 0.6:
                mgr = users[rng.randrange(0, max(1, len(users) // 20))]
                if mgr["id"] != u["id"]:
                    u["manager"] = {"id": mgr["id"]}
                    self.add(_ref("user", u["id"]), "reports_to", _ref("user", mgr["id"]))

        def uref(u):
            return {"@odata.type": "#microsoft.graph.user", "id": u["id"]}

        groups = []
        for g in range(self.n["groups"]):
            groups.append({"@odata.type": "#microsoft.graph.group", "id": self.uid(),
                           "displayName": f"grp-{rng.choice(DEPTS).lower()}-{g}",
                           "mailNickname": f"grp{g}", "securityEnabled": True,
                           "groupTypes": [], "isAssignableToRole": False,
                           "members": [], "owners": []})
        hub = {"@odata.type": "#microsoft.graph.group", "id": self.uid(),
               "displayName": "All Staff", "mailNickname": "allstaff",
               "securityEnabled": True, "groupTypes": ["DynamicMembership"],
               "membershipRule": 'user.userType -eq "Member"',
               "isAssignableToRole": False, "members": [], "owners": []}
        for u in users:
            for g in rng.sample(groups, rng.randint(1, 4)):
                g["members"].append(uref(u))
            if u["userType"] == "Member":
                hub["members"].append(uref(u))
        # nesting: a slice of groups are members of other groups
        for g in rng.sample(groups, len(groups) // 5):
            parent = rng.choice(groups)
            if parent is not g:
                parent["members"].append({"@odata.type": "#microsoft.graph.group", "id": g["id"]})
        for g in groups:
            owner = rng.choice(users)
            g["owners"].append(uref(owner))
        groups.append(hub)
        for g in groups:
            for m in g["members"]:
                t = "group" if m["@odata.type"].endswith("group") else "user"
                self.add(_ref(t, m["id"]), "member_of", _ref("group", g["id"]))
            for o in g["owners"]:
                self.add(_ref("user", o["id"]), "owner_of", _ref("group", g["id"]))

        graph_sp = {"@odata.type": "#microsoft.graph.servicePrincipal", "id": self.uid(),
                    "appId": GRAPH_APP_ID, "displayName": "Microsoft Graph",
                    "servicePrincipalType": "Application", "accountEnabled": True,
                    "keyCredentials": [], "passwordCredentials": [], "owners": []}
        sps, apps = [graph_sp], []
        for s in range(self.n["sps"]):
            app_id = self.uid()
            sp = {"@odata.type": "#microsoft.graph.servicePrincipal", "id": self.uid(),
                  "appId": app_id, "displayName": f"svc-app-{s}",
                  "servicePrincipalType": rng.choice(["Application", "Application", "ManagedIdentity"]),
                  "accountEnabled": True, "keyCredentials": [], "passwordCredentials": [],
                  "owners": []}
            if rng.random() < 0.5:
                sp["passwordCredentials"].append({
                    "displayName": "ci-secret",
                    "endDateTime": f"202{rng.randint(5, 8)}-0{rng.randint(1, 9)}-15T00:00:00Z"})
            if rng.random() < 0.3:
                owner = rng.choice(users)
                sp["owners"].append(uref(owner))
                self.add(_ref("user", owner["id"]), "owner_of", _ref("service_principal", sp["id"]))
            sps.append(sp)
            app = {"@odata.type": "#microsoft.graph.application", "id": self.uid(),
                   "appId": app_id, "displayName": f"svc-app-{s}",
                   "requiredResourceAccess": [{"resourceAppId": GRAPH_APP_ID, "resourceAccess": [
                       {"id": self.uid(), "type": rng.choice(["Scope", "Role"])}
                       for _ in range(rng.randint(1, 3))]}]}
            for ra in app["requiredResourceAccess"][0]["resourceAccess"]:
                self.add(_ref("app_registration", app["id"]), "requires_permission",
                         _ref("api_permission", f"{GRAPH_APP_ID}:{ra['id']}"))
            apps.append(app)

        roles = []
        for tid, name in ENTRA_ROLES.items():
            roles.append({"@odata.type": "#microsoft.graph.directoryRole", "id": self.uid(),
                          "roleTemplateId": tid, "displayName": name, "members": []})
        assignments = []

        def assign(principal_type: str, pid: str, role_tid: str) -> None:
            assignments.append({
                "id": self.uid(), "principalId": pid, "roleDefinitionId": role_tid,
                "directoryScopeId": "/",
                "principal": {"@odata.type": f"#microsoft.graph.{principal_type}", "id": pid}})
            etype = {"user": "user", "group": "group",
                     "servicePrincipal": "service_principal"}[principal_type]
            self.add(_ref(etype, pid), "has_role", _ref("directory_role", role_tid))

        for tid in ENTRA_ROLES:
            for u in rng.sample(users, rng.randint(2, 6)):
                assign("user", u["id"], tid)

        # planted 1: user -> nested group -> role-assignable group -> Global Admin
        ra_group = {"@odata.type": "#microsoft.graph.group", "id": self.uid(),
                    "displayName": "Tier0 Operators", "mailNickname": "tier0",
                    "securityEnabled": True, "groupTypes": [], "isAssignableToRole": True,
                    "members": [], "owners": []}
        inner = rng.choice(groups[:-1])
        ra_group["members"].append({"@odata.type": "#microsoft.graph.group", "id": inner["id"]})
        self.add(_ref("group", inner["id"]), "member_of", _ref("group", ra_group["id"]))
        groups.append(ra_group)
        start = next(m for m in inner["members"] if m["@odata.type"].endswith("user"))
        assign("group", ra_group["id"], GLOBAL_ADMIN)
        self.paths.append({
            "name": "entra: user -> group -> role-assignable group -> Global Administrator",
            "start": _ref("user", start["id"]), "target": _ref("directory_role", GLOBAL_ADMIN),
            "via": ["member_of", "has_role"],
            "edges": [_edge(_ref("user", start["id"]), "member_of", _ref("group", inner["id"])),
                      _edge(_ref("group", inner["id"]), "member_of", _ref("group", ra_group["id"])),
                      _edge(_ref("group", ra_group["id"]), "has_role",
                            _ref("directory_role", GLOBAL_ADMIN))]})

        # planted 2: user -owner_of-> service principal -has_role-> Privileged Role Admin
        sp_t = rng.choice(sps[1:])
        owner = rng.choice(users)
        sp_t["owners"].append(uref(owner))
        self.add(_ref("user", owner["id"]), "owner_of", _ref("service_principal", sp_t["id"]))
        assign("servicePrincipal", sp_t["id"], PRIV_ROLE_ADMIN)
        self.paths.append({
            "name": "entra: user -owner_of-> service principal -has_role-> Privileged Role Admin",
            "start": _ref("user", owner["id"]), "target": _ref("directory_role", PRIV_ROLE_ADMIN),
            "via": ["owner_of", "has_role"],
            "edges": [_edge(_ref("user", owner["id"]), "owner_of",
                            _ref("service_principal", sp_t["id"])),
                      _edge(_ref("service_principal", sp_t["id"]), "has_role",
                            _ref("directory_role", PRIV_ROLE_ADMIN))]})

        # planted 3: directory-role members listing (the $expand=members shape)
        sec_admin = next(r for r in roles if r["roleTemplateId"] == SECURITY_ADMIN)
        direct = rng.choice(users)
        sec_admin["members"].append(uref(direct))
        self.add(_ref("user", direct["id"]), "has_role", _ref("directory_role", SECURITY_ADMIN))

        app_roles = []
        for sp in sps[1:]:
            for _ in range(rng.randint(0, 25)):
                if rng.random() < 0.8:
                    p, ptype, etype = rng.choice(users)["id"], "User", "user"
                else:
                    p, ptype, etype = rng.choice(groups)["id"], "Group", "group"
                rid = self.uid()
                app_roles.append({"id": self.uid(), "principalId": p, "principalType": ptype,
                                  "resourceId": sp["id"], "appRoleId": rid,
                                  "resourceDisplayName": sp["displayName"]})
                self.add(_ref(etype, p), "has_app_role", _ref("service_principal", sp["id"]))
            if rng.random() < 0.2:
                app_roles.append({"id": self.uid(), "principalId": sp["id"],
                                  "principalType": "ServicePrincipal",
                                  "resourceId": graph_sp["id"], "appRoleId": self.uid(),
                                  "resourceDisplayName": "Microsoft Graph"})
                self.add(_ref("service_principal", sp["id"]), "has_app_role",
                         _ref("service_principal", graph_sp["id"]))

        grants = []
        for sp in rng.sample(sps[1:], max(1, len(sps) // 4)):
            scope = " ".join(rng.sample(SCOPES, rng.randint(1, 3)))
            if rng.random() < 0.3:
                grants.append({"id": self.uid(), "clientId": sp["id"],
                               "consentType": "AllPrincipals", "principalId": None,
                               "resourceId": graph_sp["id"], "scope": scope})
                for sc in scope.split():
                    self.add(_ref("service_principal", sp["id"]), "has_permission",
                             _ref("api_permission", f"{graph_sp['id']}:{sc}"))
            else:
                # many users consent to the same client/resource/scope
                for u in rng.sample(users, rng.randint(2, 30)):
                    grants.append({"id": self.uid(), "clientId": sp["id"],
                                   "consentType": "Principal", "principalId": u["id"],
                                   "resourceId": graph_sp["id"], "scope": scope})
                    for sc in scope.split():
                        self.add(_ref("user", u["id"]), "has_permission",
                                 _ref("api_permission", f"{graph_sp['id']}:{sc}"))

        return {"users": users, "groups": groups, "servicePrincipals": sps,
                "appRegistrations": apps, "directoryRoles": roles,
                "roleAssignments": assignments, "appRoleAssignments": app_roles,
                "oauth2PermissionGrants": grants}

    # -------------------------------------------------------------- okta #
    def okta(self, people: list[dict]) -> tuple[dict, list[dict]]:
        rng = self.rng
        users, overlap = [], []
        for p in people:
            if rng.random() > 0.7:
                continue
            status = rng.choices(["ACTIVE", "SUSPENDED", "DEPROVISIONED", "PROVISIONED"],
                                 [90, 4, 3, 3])[0]
            u = {"id": self.okta_id("00u"), "status": status,
                 "created": "2024-03-01T12:00:00.000Z",
                 "lastLogin": "2026-09-18T08:30:00.000Z" if status == "ACTIVE" else None,
                 "profile": {"login": p["mail"], "email": p["mail"],
                             "firstName": p["first"], "lastName": p["last"],
                             "department": p["dept"], "title": p["title"]},
                 "credentials": {"provider": {"type": "OKTA", "name": "OKTA"}}}
            if rng.random() < 0.85:
                u["_embedded"] = {"factors": [
                    {"id": self.okta_id("mfa"), "factorType": f, "status": "ACTIVE"}
                    for f in rng.sample(FACTORS, rng.randint(1, 2))]}
            users.append(u)
            overlap.append(p["mail"])

        def member(u):
            return {"id": u["id"], "status": u["status"], "profile": {"login": u["profile"]["login"]}}

        groups = [{"id": self.okta_id("00g"), "type": "OKTA_GROUP",
                   "profile": {"name": f"okta-{rng.choice(DEPTS).lower()}-{g}",
                               "description": "synthetic"}, "_members": []}
                  for g in range(self.n["groups"] // 2)]
        everyone = {"id": self.okta_id("00g"), "type": "BUILT_IN",
                    "profile": {"name": "Everyone", "description": "All users"}, "_members": []}
        for u in users:
            for g in rng.sample(groups, rng.randint(1, 3)):
                g["_members"].append(member(u))
            everyone["_members"].append(member(u))
        groups.append(everyone)
        for g in groups:
            for m in g["_members"]:
                self.add(_ref("user", m["id"]), "member_of", _ref("group", g["id"]))

        apps = [{"id": self.okta_id("0oa"), "label": f"okta-app-{a}",
                 "status": "ACTIVE" if rng.random() > 0.05 else "INACTIVE",
                 "signOnMode": rng.choice(["SAML_2_0", "OPENID_CONNECT", "BOOKMARK"]),
                 "credentials": {"signing": {"kid": self.okta_id("kid")}}}
                for a in range(self.n["okta_apps"])]
        app_users = []
        for a in apps:
            for u in rng.sample(users, min(len(users), rng.randint(5, 80))):
                app_users.append({
                    "id": u["id"], "scope": rng.choice(["USER", "GROUP"]),
                    "status": "PROVISIONED" if rng.random() < 0.3 else "ACTIVE",
                    "credentials": {"userName": u["profile"]["login"]},
                    "_links": {"app": {"href": f"{OKTA_BASE}/apps/{a['id']}"},
                               "user": {"href": f"{OKTA_BASE}/users/{u['id']}"}}})
                self.add(_ref("user", u["id"]), "assigned_to", _ref("app", a["id"]))

        roles = []

        def grant(kind: str, pid: str, rtype: str) -> None:
            roles.append({"id": self.okta_id("ra1"), "label": OKTA_ROLES[rtype], "type": rtype,
                          "status": "ACTIVE", "assignmentType": kind.upper(),
                          "created": "2025-01-10T00:00:00.000Z",
                          "_links": {"assignee": {"href": f"{OKTA_BASE}/{kind}s/{pid}"}}})
            self.add(_ref(kind, pid), "has_role", _ref("admin_role", rtype))

        for rtype in OKTA_ROLES:
            for u in rng.sample(users, rng.randint(1, 5)):
                grant("user", u["id"], rtype)
        # planted 4: user -> group -has_role-> SUPER_ADMIN (group assignment)
        admins = rng.choice(groups[:-1])
        grant("group", admins["id"], "SUPER_ADMIN")
        start = admins["_members"][0]["id"]
        self.paths.append({
            "name": "okta: user -> group -has_role-> SUPER_ADMIN",
            "start": _ref("user", start), "target": _ref("admin_role", "SUPER_ADMIN"),
            "via": ["member_of", "has_role"],
            "edges": [_edge(_ref("user", start), "member_of", _ref("group", admins["id"])),
                      _edge(_ref("group", admins["id"]), "has_role",
                            _ref("admin_role", "SUPER_ADMIN"))]})
        # planted 5: user -has_role-> SUPER_ADMIN directly
        direct = rng.choice(users)
        grant("user", direct["id"], "SUPER_ADMIN")
        self.paths.append({
            "name": "okta: user -has_role-> SUPER_ADMIN (direct)",
            "start": _ref("user", direct["id"]), "target": _ref("admin_role", "SUPER_ADMIN"),
            "via": ["has_role"],
            "edges": [_edge(_ref("user", direct["id"]), "has_role",
                            _ref("admin_role", "SUPER_ADMIN"))]})
        return ({"users": users, "groups": groups, "apps": apps,
                 "appUsers": app_users, "roleAssignments": roles}, overlap)

    def run(self) -> tuple[dict, dict, dict]:
        people = self.people()
        entra = self.entra(people)
        n_entra_edges = len(self.edges)
        entra_edges = sorted(self.edges)
        self.edges = set()
        okta, overlap = self.okta(people)
        truth = {
            "seed": self.seed, "scale": self.scale, "export_date": EXPORT_DATE,
            "entra_edges": [list(e) for e in entra_edges],
            "okta_edges": [list(e) for e in sorted(self.edges)],
            "paths": self.paths,
            "shared_mail": len(overlap),
            "counts": {"entra_users": len(entra["users"]), "entra_groups": len(entra["groups"]),
                       "entra_edges": n_entra_edges, "okta_users": len(okta["users"]),
                       "okta_groups": len(okta["groups"]), "okta_edges": len(self.edges)},
        }
        return entra, okta, truth


def generate(seed: int, scale: str) -> tuple[dict, dict, dict]:
    return Generator(seed, scale).run()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loom.connectors.iam_gen", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--scale", default="medium", choices=sorted(SCALES))
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args(argv)
    entra, okta, truth = generate(args.seed, args.scale)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "entra.json").write_text(json.dumps(entra))
    (out / "okta.json").write_text(json.dumps(okta))
    (out / "truth.json").write_text(json.dumps(truth))
    print(json.dumps(truth["counts"]))


if __name__ == "__main__":
    main()
