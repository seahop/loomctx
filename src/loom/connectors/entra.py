"""Microsoft Entra ID (Azure AD) interop: a Graph API JSON export in,
cited identity/RBAC claims out.

    python -m loom.connectors.entra import users.json groups.json --namespace iam
    python -m loom.connectors.entra import directory_export.json --namespace iam --url http://loom:8000 --key ...
    python -m loom.connectors.entra emit users.json --namespace iam > envelopes.jsonl
    python -m loom.connectors.entra schema --namespace iam

What it is (and is NOT):

  This connector PARSES a JSON export of Microsoft Entra ID (Azure AD)
  objects — users, groups, service principals, app registrations, directory
  roles and role assignments — into Loom claims so an agent can ask
  identity/RBAC reachability questions ("who has Global Administrator?",
  "which service principals have Application.ReadWrite.All?", "what path
  connects user X to a privileged role?") over the ordinary scope walk.

  It reads a FILE: it does not call the Graph API. The operator exports
  the objects (az cli, Graph Explorer, PowerShell), and this connector
  decodes them deterministically, one object at a time, with no network
  calls. Every claim is cited to its source object and dated from the
  export, so `as_of` / `valid_at` and multi-source corroboration work.

  It is NOT an attack-path engine. It carries the evidence (the direct
  memberships, role assignments, API permission grants); the agent (or a
  later analysis layer) assembles the path.

Input — a JSON file whose top level is either:
  * An object with a `value` array (a Graph API collection response, the
    normal output of `GET /v1.0/users`, `GET /v1.0/groups`, etc.).
  * A plain array of objects.
  * A single object (one user, one group, etc.).
  * A combined export: an object with `users`, `groups`,
    `servicePrincipals`, `appRegistrations`, `directoryRoles`,
    `roleAssignments`, `appRoleAssignments`, `oauth2PermissionGrants`
    keys, each containing an array (or a `value`-wrapped response).

The connector detects the object type from the `@odata.type` field, the
`userPrincipalName` (user), `securityEnabled` (group), `appId` (sp or
app), `roleTemplateId` (directory role), or the assignment shape.

Entity keys are the Entra object id (a UUID), which is stable across
rename. `userPrincipalName`, `displayName`, `appId` and `mail` ride as
attributes for entity resolution (D-042/D-060).

Predicates:
  * `member_of` — direct group / role membership.
  * `owner_of` — an owner relationship (group owner, app owner).
  * `has_role` — a directory role assignment (subject has object role).
  * `has_app_role` — an app role assignment on a service principal.
  * `has_permission` — an OAuth2 / API permission grant.
  * Scalar attrs: `enabled`, `user_type`, `mfa_status`, `sign_in_risk`,
    `credential_count`, `key_expiry`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator

from ..contracts import (ClaimIn, EntityRef, EntityTypeDef, PredicateDef,
                         SchemaRegistration)

SOURCE_DEFAULT = "entra-export"
NAMESPACE_DEFAULT = "iam"

DANGEROUS_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "f28a1f94-e044-4c2d-b3d5-16bfe05a3e7c": "SharePoint Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
}


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def _eid(parts: str) -> str:
    if len(parts) <= 128:
        return parts
    prefix = parts[:96]
    suffix = hashlib.sha256(parts.encode("utf-8", "replace")).hexdigest()[:31]
    return f"{prefix}:{suffix}"


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


def _items(data: Any) -> list[dict]:
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        if "value" in data and isinstance(data["value"], list):
            return [d for d in data["value"] if isinstance(d, dict)]
        return [data]
    return []


def _detect_type(obj: dict) -> str | None:
    odata = obj.get("@odata.type", "")
    if "user" in odata.lower():
        return "user"
    if "group" in odata.lower():
        return "group"
    if "serviceprincipal" in odata.lower():
        return "service_principal"
    if "application" in odata.lower() and "role" not in odata.lower():
        return "app_registration"
    if "directoryrole" in odata.lower():
        return "directory_role"

    if "userPrincipalName" in obj:
        return "user"
    if "securityEnabled" in obj and "mailNickname" in obj:
        return "group"
    if "appId" in obj and "servicePrincipalType" in obj:
        return "service_principal"
    if "appId" in obj and "requiredResourceAccess" in obj:
        return "app_registration"
    if "roleTemplateId" in obj:
        return "directory_role"

    if "principalId" in obj and "roleDefinitionId" in obj:
        return "role_assignment"
    if "principalId" in obj and "appRoleId" in obj:
        return "app_role_assignment"
    if "clientId" in obj and "scope" in obj and "consentType" in obj:
        return "oauth2_grant"
    return None


def _ref(etype: str, key: str) -> EntityRef:
    return EntityRef(type=etype, key=key)


def _stamp(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S")


def _user_envelopes(obj: dict, ns: str, source: str, observed: datetime,
                    stamp: str) -> Iterator[ClaimIn]:
    oid = obj.get("id")
    if not oid:
        return
    ref = _ref("user", oid)
    base = {"export": source}

    def claim(pred: str, val: Any, tag: str = "", **kw) -> ClaimIn:
        attrs = {**base, **kw.pop("attrs", {})}
        return ClaimIn(namespace=ns, event_id=_eid(f"entra:{oid}:{stamp}:{pred}{tag}"),
                       subject=ref, predicate=pred, object=val,
                       observed_at=observed, source=source, attrs=attrs, **kw)

    upn = obj.get("userPrincipalName")
    if upn:
        yield claim("upn", upn)
    dn = obj.get("displayName")
    if dn:
        yield claim("name", dn)
    mail = obj.get("mail")
    if mail:
        yield claim("mail", mail)

    enabled = obj.get("accountEnabled")
    if enabled is not None:
        yield claim("enabled", enabled)

    user_type = obj.get("userType")
    if user_type:
        yield claim("user_type", user_type)

    job = obj.get("jobTitle")
    if job:
        yield claim("job_title", job)

    dept = obj.get("department")
    if dept:
        yield claim("department", dept)

    creds = obj.get("passwordProfile")
    if isinstance(creds, dict):
        if creds.get("forceChangePasswordNextSignIn"):
            yield claim("force_password_change", True)

    for i, method in enumerate(obj.get("authenticationMethods", []) or []):
        if isinstance(method, dict):
            mtype = method.get("@odata.type", "").rsplit(".", 1)[-1]
            if mtype:
                yield claim("auth_method", mtype, f":{i}")

    manager_id = (obj.get("manager", {}) or {}).get("id") if isinstance(obj.get("manager"), dict) else None
    if manager_id:
        yield claim("reports_to", _ref("user", manager_id))


def _group_envelopes(obj: dict, ns: str, source: str, observed: datetime,
                     stamp: str) -> Iterator[ClaimIn]:
    oid = obj.get("id")
    if not oid:
        return
    ref = _ref("group", oid)
    base = {"export": source}

    def claim(pred: str, val: Any, tag: str = "", **kw) -> ClaimIn:
        attrs = {**base, **kw.pop("attrs", {})}
        return ClaimIn(namespace=ns, event_id=_eid(f"entra:{oid}:{stamp}:{pred}{tag}"),
                       subject=ref, predicate=pred, object=val,
                       observed_at=observed, source=source, attrs=attrs, **kw)

    dn = obj.get("displayName")
    if dn:
        yield claim("name", dn)

    sec = obj.get("securityEnabled")
    if sec is not None:
        yield claim("security_enabled", sec)

    group_type = "dynamic" if obj.get("membershipRule") else "assigned"
    yield claim("group_type", group_type)

    if obj.get("membershipRule"):
        yield claim("membership_rule", obj["membershipRule"])

    for i, m in enumerate(obj.get("members", []) or []):
        if isinstance(m, dict) and m.get("id"):
            mtype = _detect_type(m) or "user"
            yield ClaimIn(namespace=ns,
                          event_id=_eid(f"entra:{m['id']}:{stamp}:member_of:{oid}"),
                          subject=_ref(mtype, m["id"]), predicate="member_of",
                          object=ref, observed_at=observed, source=source,
                          attrs=base)

    for i, o in enumerate(obj.get("owners", []) or []):
        if isinstance(o, dict) and o.get("id"):
            otype = _detect_type(o) or "user"
            yield ClaimIn(namespace=ns,
                          event_id=_eid(f"entra:{o['id']}:{stamp}:owner_of:{oid}"),
                          subject=_ref(otype, o["id"]), predicate="owner_of",
                          object=ref, observed_at=observed, source=source,
                          attrs=base)


def _sp_envelopes(obj: dict, ns: str, source: str, observed: datetime,
                  stamp: str) -> Iterator[ClaimIn]:
    oid = obj.get("id")
    if not oid:
        return
    ref = _ref("service_principal", oid)
    base = {"export": source}

    def claim(pred: str, val: Any, tag: str = "", **kw) -> ClaimIn:
        attrs = {**base, **kw.pop("attrs", {})}
        return ClaimIn(namespace=ns, event_id=_eid(f"entra:{oid}:{stamp}:{pred}{tag}"),
                       subject=ref, predicate=pred, object=val,
                       observed_at=observed, source=source, attrs=attrs, **kw)

    dn = obj.get("displayName")
    if dn:
        yield claim("name", dn)
    app_id = obj.get("appId")
    if app_id:
        yield claim("app_id", app_id)
    sp_type = obj.get("servicePrincipalType")
    if sp_type:
        yield claim("sp_type", sp_type)
    enabled = obj.get("accountEnabled")
    if enabled is not None:
        yield claim("enabled", enabled)

    for i, cred in enumerate(obj.get("keyCredentials", []) or []):
        if isinstance(cred, dict):
            end = cred.get("endDateTime")
            yield claim("key_credential", cred.get("displayName", "key"), f":{i}",
                        attrs={"key_expiry": end} if end else {})

    for i, cred in enumerate(obj.get("passwordCredentials", []) or []):
        if isinstance(cred, dict):
            end = cred.get("endDateTime")
            yield claim("password_credential", cred.get("displayName", "secret"), f":{i}",
                        attrs={"secret_expiry": end} if end else {})

    for i, o in enumerate(obj.get("owners", []) or []):
        if isinstance(o, dict) and o.get("id"):
            otype = _detect_type(o) or "user"
            yield ClaimIn(namespace=ns,
                          event_id=_eid(f"entra:{o['id']}:{stamp}:owner_of:{oid}"),
                          subject=_ref(otype, o["id"]), predicate="owner_of",
                          object=ref, observed_at=observed, source=source,
                          attrs=base)


def _app_envelopes(obj: dict, ns: str, source: str, observed: datetime,
                   stamp: str) -> Iterator[ClaimIn]:
    oid = obj.get("id")
    if not oid:
        return
    ref = _ref("app_registration", oid)
    base = {"export": source}

    def claim(pred: str, val: Any, tag: str = "", **kw) -> ClaimIn:
        attrs = {**base, **kw.pop("attrs", {})}
        return ClaimIn(namespace=ns, event_id=_eid(f"entra:{oid}:{stamp}:{pred}{tag}"),
                       subject=ref, predicate=pred, object=val,
                       observed_at=observed, source=source, attrs=attrs, **kw)

    dn = obj.get("displayName")
    if dn:
        yield claim("name", dn)
    app_id = obj.get("appId")
    if app_id:
        yield claim("app_id", app_id)

    for rra in obj.get("requiredResourceAccess", []) or []:
        if not isinstance(rra, dict):
            continue
        resource_app = rra.get("resourceAppId", "unknown")
        for i, ra in enumerate(rra.get("resourceAccess", []) or []):
            if not isinstance(ra, dict):
                continue
            perm_id = ra.get("id", "")
            perm_type = ra.get("type", "")
            yield claim("requires_permission",
                        _ref("api_permission", f"{resource_app}:{perm_id}"),
                        f":{resource_app}:{i}",
                        attrs={"permission_type": perm_type,
                               "resource_app_id": resource_app})


def _role_envelopes(obj: dict, ns: str, source: str, observed: datetime,
                    stamp: str) -> Iterator[ClaimIn]:
    oid = obj.get("id")
    if not oid:
        return
    template_id = obj.get("roleTemplateId", oid)
    ref = _ref("directory_role", template_id)
    base = {"export": source}

    dn = obj.get("displayName")
    if dn:
        yield ClaimIn(namespace=ns, event_id=_eid(f"entra:{template_id}:{stamp}:name"),
                       subject=ref, predicate="name", object=dn,
                       observed_at=observed, source=source, attrs=base)

    is_dangerous = template_id in DANGEROUS_ROLES
    if is_dangerous:
        yield ClaimIn(namespace=ns, event_id=_eid(f"entra:{template_id}:{stamp}:privileged"),
                       subject=ref, predicate="privileged", object=True,
                       observed_at=observed, source=source, attrs=base)

    for m in obj.get("members", []) or []:
        if isinstance(m, dict) and m.get("id"):
            mtype = _detect_type(m) or "user"
            yield ClaimIn(namespace=ns,
                          event_id=_eid(f"entra:{m['id']}:{stamp}:has_role:{template_id}"),
                          subject=_ref(mtype, m["id"]), predicate="has_role",
                          object=ref, observed_at=observed, source=source,
                          attrs={**base, "role_name": dn or template_id})


def _role_assignment_envelopes(obj: dict, ns: str, source: str, observed: datetime,
                               stamp: str) -> Iterator[ClaimIn]:
    principal = obj.get("principalId")
    role_def = obj.get("roleDefinitionId")
    if not principal or not role_def:
        return
    scope = obj.get("directoryScopeId", "/")
    yield ClaimIn(namespace=ns,
                  event_id=_eid(f"entra:{principal}:{stamp}:has_role:{role_def}"),
                  subject=_ref("user", principal), predicate="has_role",
                  object=_ref("directory_role", role_def),
                  observed_at=observed, source=source,
                  attrs={"export": source, "scope": scope,
                         "assignment_id": obj.get("id", "")})


def _app_role_assignment_envelopes(obj: dict, ns: str, source: str, observed: datetime,
                                   stamp: str) -> Iterator[ClaimIn]:
    principal = obj.get("principalId")
    resource = obj.get("resourceId")
    role_id = obj.get("appRoleId")
    if not principal or not resource:
        return
    ptype = obj.get("principalType", "User").lower()
    etype = "service_principal" if ptype == "serviceprincipal" else ptype if ptype in ("user", "group") else "user"
    yield ClaimIn(namespace=ns,
                  event_id=_eid(f"entra:{principal}:{stamp}:has_app_role:{resource}:{role_id}"),
                  subject=_ref(etype, principal), predicate="has_app_role",
                  object=_ref("service_principal", resource),
                  observed_at=observed, source=source,
                  attrs={"export": source, "app_role_id": role_id or "",
                         "principal_display": obj.get("principalDisplayName", ""),
                         "resource_display": obj.get("resourceDisplayName", "")})


def _oauth2_grant_envelopes(obj: dict, ns: str, source: str, observed: datetime,
                            stamp: str) -> Iterator[ClaimIn]:
    client = obj.get("clientId")
    scopes = obj.get("scope", "")
    if not client or not scopes:
        return
    resource = obj.get("resourceId", "unknown")
    consent = obj.get("consentType", "")
    principal = obj.get("principalId")
    for i, scope in enumerate(scopes.split()):
        subj = _ref("user", principal) if principal and consent == "Principal" else _ref("service_principal", client)
        yield ClaimIn(namespace=ns,
                      event_id=_eid(f"entra:{client}:{stamp}:has_permission:{resource}:{scope}"),
                      subject=subj, predicate="has_permission",
                      object=_ref("api_permission", f"{resource}:{scope}"),
                      observed_at=observed, source=source,
                      attrs={"export": source, "consent_type": consent,
                             "scope": scope, "resource_id": resource})


def entra_to_envelopes(text: str, namespace: str, source: str = SOURCE_DEFAULT,
                       as_of: datetime | None = None, mtime: datetime | None = None,
                       stats: dict[str, int] | None = None) -> Iterator[ClaimIn]:
    stats = stats if stats is not None else {}
    data = json.loads(text)
    observed = _clamp(as_of or mtime or datetime.now(timezone.utc))
    stamp = _stamp(observed)

    buckets: dict[str, list[dict]] = {}
    if isinstance(data, dict):
        for key in ("users", "groups", "servicePrincipals", "appRegistrations",
                     "directoryRoles", "roleAssignments", "appRoleAssignments",
                     "oauth2PermissionGrants"):
            val = data.get(key)
            if val is not None:
                buckets[key] = _items(val)
        if not buckets:
            buckets["auto"] = _items(data)
    else:
        buckets["auto"] = _items(data)

    dispatch = {
        "user": _user_envelopes,
        "group": _group_envelopes,
        "service_principal": _sp_envelopes,
        "app_registration": _app_envelopes,
        "directory_role": _role_envelopes,
        "role_assignment": _role_assignment_envelopes,
        "app_role_assignment": _app_role_assignment_envelopes,
        "oauth2_grant": _oauth2_grant_envelopes,
    }

    for key, items in buckets.items():
        forced = {"users": "user", "groups": "group",
                  "servicePrincipals": "service_principal",
                  "appRegistrations": "app_registration",
                  "directoryRoles": "directory_role",
                  "roleAssignments": "role_assignment",
                  "appRoleAssignments": "app_role_assignment",
                  "oauth2PermissionGrants": "oauth2_grant"}.get(key)
        for obj in items:
            otype = forced or _detect_type(obj)
            handler = dispatch.get(otype) if otype else None
            if handler is None:
                stats["skipped"] = stats.get("skipped", 0) + 1
                continue
            try:
                n = 0
                for env in handler(obj, namespace, source, observed, stamp):
                    n += 1
                    yield env
                stats["object"] = stats.get("object", 0) + 1
            except (ValueError, TypeError, KeyError) as exc:
                stats["invalid"] = stats.get("invalid", 0) + 1
                print(f"entra object {obj.get('id', '?')}: skipped: "
                      f"{str(exc).splitlines()[0][:200]}", file=sys.stderr)


def schema(namespace: str) -> SchemaRegistration:
    return SchemaRegistration(
        namespace=namespace,
        entity_types=[
            EntityTypeDef(name="user", description="an Entra ID / Azure AD user"),
            EntityTypeDef(name="group", description="a security or M365 group"),
            EntityTypeDef(name="service_principal",
                          description="a service principal (enterprise app)"),
            EntityTypeDef(name="app_registration",
                          description="an app registration"),
            EntityTypeDef(name="directory_role",
                          description="an Entra directory role (Global Admin, etc.)"),
            EntityTypeDef(name="api_permission",
                          description="an API permission scope or app role"),
        ],
        predicates=[
            PredicateDef(name="member_of", object_types=["group", "directory_role"],
                         containment=True,
                         description="direct group or role membership"),
            PredicateDef(name="owner_of",
                         description="owner relationship (group owner, app owner)"),
            PredicateDef(name="has_role", object_types=["directory_role"],
                         description="directory role assignment"),
            PredicateDef(name="has_app_role", object_types=["service_principal"],
                         description="app role assignment on a service principal"),
            PredicateDef(name="has_permission", object_types=["api_permission"],
                         description="OAuth2 / API permission grant"),
            PredicateDef(name="requires_permission", object_types=["api_permission"],
                         description="API permission the app registration requires"),
            PredicateDef(name="reports_to", object_types=["user"],
                         description="manager relationship"),
            PredicateDef(name="enabled", description="account is enabled"),
            PredicateDef(name="privileged",
                         description="a high-privilege directory role"),
            PredicateDef(name="upn", description="userPrincipalName"),
            PredicateDef(name="name", description="displayName"),
            PredicateDef(name="mail", description="mail address"),
            PredicateDef(name="app_id", description="application client id"),
            PredicateDef(name="user_type", description="Member / Guest"),
            PredicateDef(name="job_title", description="job title"),
            PredicateDef(name="department", description="department"),
            PredicateDef(name="sp_type",
                         description="servicePrincipalType (Application / ManagedIdentity)"),
            PredicateDef(name="security_enabled",
                         description="the group is security-enabled"),
            PredicateDef(name="group_type",
                         description="assigned or dynamic membership"),
            PredicateDef(name="membership_rule",
                         description="dynamic group membership rule"),
            PredicateDef(name="auth_method",
                         description="registered authentication method"),
            PredicateDef(name="force_password_change",
                         description="password change required at next sign-in"),
            PredicateDef(name="key_credential",
                         description="a key (certificate) credential"),
            PredicateDef(name="password_credential",
                         description="a client secret credential"),
        ],
    )


def _to_lines(envs: Iterable[ClaimIn]) -> Iterator[str]:
    for env in envs:
        yield env.model_dump_json(exclude_none=True) + "\n"


def _open_store(db: str | None):
    from ..store.factory import store_from_env, store_from_url
    return store_from_url(db) if db else store_from_env()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loom.connectors.entra",
                                     description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--namespace", default=NAMESPACE_DEFAULT)
    common.add_argument("--source", default=SOURCE_DEFAULT)
    common.add_argument("--as-of", dest="as_of",
                        help="ISO export timestamp override")
    sub = parser.add_subparsers(dest="command", required=True)
    imp = sub.add_parser("import", parents=[common],
                         help="parse Entra ID JSON and ingest")
    imp.add_argument("files", nargs="+", help="JSON export files")
    imp.add_argument("--url", help="engine/gateway URL")
    imp.add_argument("--db", help="direct store path")
    imp.add_argument("--key", default=os.environ.get("LOOM_API_KEY"), type=str.strip)
    imp.add_argument("--batch", type=int, default=500)
    imp.add_argument("--no-schema", action="store_true")
    emit = sub.add_parser("emit", parents=[common],
                          help="write NDJSON envelopes to stdout")
    emit.add_argument("files", nargs="+")
    sub.add_parser("schema", parents=[common], help="print the schema")
    args = parser.parse_args(argv)

    if args.command == "schema":
        print(schema(args.namespace).model_dump_json(indent=2))
        return

    as_of = None
    if args.as_of:
        as_of = datetime.fromisoformat(args.as_of.replace("Z", "+00:00"))
        as_of = as_of if as_of.tzinfo else as_of.replace(tzinfo=timezone.utc)

    def _all_envs() -> Iterator[ClaimIn]:
        for path in args.files:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            mt = datetime.fromtimestamp(os.stat(path).st_mtime,
                                       tz=timezone.utc).replace(microsecond=0)
            yield from entra_to_envelopes(text, args.namespace, args.source,
                                          as_of, mt, stats)

    stats: dict[str, int] = {}

    if args.command == "emit":
        for line in _to_lines(_all_envs()):
            sys.stdout.write(line)
        print(json.dumps({"envelopes": stats}), file=sys.stderr)
        return

    if args.url and args.db:
        parser.error("import: give --url or --db, not both")
    from ..ingest import load_direct, post_batches
    from .vulns import register
    if not args.no_schema:
        register(schema(args.namespace), args.url, args.db, args.key)
    lines = _to_lines(_all_envs())
    totals = (post_batches(args.url, lines, args.batch, args.key) if args.url
              else load_direct(args.db, lines, args.batch))
    print(json.dumps({**totals, "envelopes": stats}))
    rejected = totals.get("rejected", 0)
    if rejected:
        raise SystemExit(f"{rejected} envelopes were refused by the engine")


if __name__ == "__main__":
    main()
