"""Okta identity interop: an Okta API JSON export in, cited identity claims out.

    python -m loom.connectors.okta import users.json groups.json --namespace iam
    python -m loom.connectors.okta import directory.json --namespace iam --url http://loom:8000 --key ...
    python -m loom.connectors.okta emit users.json --namespace iam > envelopes.jsonl
    python -m loom.connectors.okta schema --namespace iam

What it is (and is NOT):

  This connector PARSES a JSON export of Okta directory objects — users,
  groups, applications and app-user assignments — into Loom claims so an
  agent can ask identity questions ("who has admin access to app X?", "what
  groups does user Y belong to?", "which users have MFA not enrolled?")
  over the ordinary scope walk.

  It reads a FILE: it does not call the Okta API. The operator exports
  the objects (Okta API, `okta-cli`, the admin console CSV → JSON), and
  this connector decodes them deterministically. Every claim is cited to
  its source object and dated from the export.

  It is NOT an access-path engine. It carries the evidence (direct group
  memberships, app assignments, role grants); the agent assembles paths.

Input — a JSON file whose top level is either:
  * An array of objects (the Okta list API response).
  * An object with a `value` or items key wrapping an array.
  * A combined export: an object with `users`, `groups`, `apps`,
    `appUsers` keys, each containing an array.
  * A single object (one user, one group, etc.).

The connector detects the object type from the `profile.login` (user),
`profile.name` + `type` == "OKTA_GROUP" (group), `signOnMode` (app),
or the `appUser` shape.

Entity keys are the Okta object id. `profile.login`, `profile.email`,
`profile.name` and `label` ride as attributes for entity resolution.

Predicates (shared namespace with the Entra connector so both can feed
the same `iam` namespace and entity resolution folds the overlap):
  * `member_of` — direct group membership.
  * `assigned_to` — an app-user assignment (user assigned to app).
  * `has_role` — an admin role grant.
  * Scalar attrs: `enabled`, `mfa_enrolled`, `user_type`, `login`,
    `name`, `sign_on_mode`.
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
from .iam_schema import SHARED_PREDICATES

SOURCE_DEFAULT = "okta-export"
NAMESPACE_DEFAULT = "iam"

ADMIN_ROLES = {
    "SUPER_ADMIN", "ORG_ADMIN", "APP_ADMIN", "USER_ADMIN",
    "HELP_DESK_ADMIN", "READ_ONLY_ADMIN", "MOBILE_ADMIN",
    "API_ACCESS_MANAGEMENT_ADMIN", "REPORT_ADMIN", "GROUP_MEMBERSHIP_ADMIN",
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
        for key in ("value", "items"):
            if key in data and isinstance(data[key], list):
                return [d for d in data[key] if isinstance(d, dict)]
        return [data]
    return []


def _detect_type(obj: dict) -> str | None:
    profile = obj.get("profile")
    if isinstance(profile, dict):
        if "login" in profile and "firstName" in profile:
            return "user"
        if "name" in profile and obj.get("type") in ("OKTA_GROUP", "APP_GROUP", "BUILT_IN"):
            return "group"
        if "name" in profile and "description" in profile and not obj.get("signOnMode"):
            return "group"

    if "signOnMode" in obj or "accessibility" in obj:
        return "app"

    if "scope" in obj and "appInstanceId" in obj:
        return "app_user"

    if "userId" in obj and "appId" in obj:
        return "app_user"

    if obj.get("type") in ADMIN_ROLES or (obj.get("type") == "CUSTOM" and "role" in obj):
        return "role_assignment"

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
    profile = obj.get("profile", {}) or {}

    def claim(pred: str, val: Any, tag: str = "", **kw) -> ClaimIn:
        attrs = {**base, **kw.pop("attrs", {})}
        return ClaimIn(namespace=ns, event_id=_eid(f"okta:{oid}:{stamp}:{pred}{tag}"),
                       subject=ref, predicate=pred, object=val,
                       observed_at=observed, source=source, attrs=attrs, **kw)

    login = profile.get("login")
    if login:
        yield claim("login", login)
    email = profile.get("email")
    if email:
        yield claim("mail", email)
    fn = profile.get("firstName", "")
    ln = profile.get("lastName", "")
    display = f"{fn} {ln}".strip()
    if display:
        yield claim("name", display)

    status = obj.get("status")
    if status:
        yield claim("enabled", status == "ACTIVE")
        yield claim("status", status)

    user_type = profile.get("userType")
    if user_type:
        yield claim("user_type", user_type)

    dept = profile.get("department")
    if dept:
        yield claim("department", dept)
    title = profile.get("title")
    if title:
        yield claim("job_title", title)

    created = _parse_time(obj.get("created"))
    if created:
        yield claim("created_at", obj["created"])

    last_login = _parse_time(obj.get("lastLogin"))
    if last_login:
        yield claim("last_login", obj["lastLogin"])

    creds = obj.get("credentials", {}) or {}
    provider = creds.get("provider", {}) or {}
    if provider.get("type"):
        yield claim("credential_provider", provider["type"])

    factors = obj.get("_embedded", {}).get("factors", []) if isinstance(obj.get("_embedded"), dict) else []
    mfa_enrolled = any(isinstance(f, dict) and f.get("status") == "ACTIVE"
                       for f in factors if isinstance(f, dict))
    if factors:
        yield claim("mfa_enrolled", mfa_enrolled)
        for i, f in enumerate(factors):
            if isinstance(f, dict) and f.get("factorType"):
                yield claim("mfa_factor", f["factorType"], f":{i}")

    for i, gid in enumerate(obj.get("_groupIds", []) or []):
        if isinstance(gid, str):
            yield ClaimIn(namespace=ns,
                          event_id=_eid(f"okta:{oid}:{stamp}:member_of:{gid}"),
                          subject=ref, predicate="member_of",
                          object=_ref("group", gid),
                          observed_at=observed, source=source, attrs=base)


def _group_envelopes(obj: dict, ns: str, source: str, observed: datetime,
                     stamp: str) -> Iterator[ClaimIn]:
    oid = obj.get("id")
    if not oid:
        return
    ref = _ref("group", oid)
    base = {"export": source}
    profile = obj.get("profile", {}) or {}

    def claim(pred: str, val: Any, tag: str = "", **kw) -> ClaimIn:
        attrs = {**base, **kw.pop("attrs", {})}
        return ClaimIn(namespace=ns, event_id=_eid(f"okta:{oid}:{stamp}:{pred}{tag}"),
                       subject=ref, predicate=pred, object=val,
                       observed_at=observed, source=source, attrs=attrs, **kw)

    name = profile.get("name")
    if name:
        yield claim("name", name)
    desc = profile.get("description")
    if desc:
        yield claim("description", desc)

    gtype = obj.get("type", "OKTA_GROUP")
    yield claim("group_type", gtype)

    for i, m in enumerate(obj.get("_members", []) or []):
        if isinstance(m, dict) and m.get("id"):
            yield ClaimIn(namespace=ns,
                          event_id=_eid(f"okta:{m['id']}:{stamp}:member_of:{oid}"),
                          subject=_ref("user", m["id"]),
                          predicate="member_of", object=ref,
                          observed_at=observed, source=source, attrs=base)
        elif isinstance(m, str):
            yield ClaimIn(namespace=ns,
                          event_id=_eid(f"okta:{m}:{stamp}:member_of:{oid}"),
                          subject=_ref("user", m),
                          predicate="member_of", object=ref,
                          observed_at=observed, source=source, attrs=base)


def _app_envelopes(obj: dict, ns: str, source: str, observed: datetime,
                   stamp: str) -> Iterator[ClaimIn]:
    oid = obj.get("id")
    if not oid:
        return
    ref = _ref("app", oid)
    base = {"export": source}

    def claim(pred: str, val: Any, tag: str = "", **kw) -> ClaimIn:
        attrs = {**base, **kw.pop("attrs", {})}
        return ClaimIn(namespace=ns, event_id=_eid(f"okta:{oid}:{stamp}:{pred}{tag}"),
                       subject=ref, predicate=pred, object=val,
                       observed_at=observed, source=source, attrs=attrs, **kw)

    label = obj.get("label")
    if label:
        yield claim("name", label)
    status = obj.get("status")
    if status:
        yield claim("enabled", status == "ACTIVE")
    sign_on = obj.get("signOnMode")
    if sign_on:
        yield claim("sign_on_mode", sign_on)

    creds = obj.get("credentials", {}) or {}
    signing = creds.get("signing", {}) or {}
    if signing.get("kid"):
        yield claim("signing_key", signing["kid"])


def _app_user_envelopes(obj: dict, ns: str, source: str, observed: datetime,
                        stamp: str) -> Iterator[ClaimIn]:
    uid = obj.get("id") or obj.get("userId")
    app_id = obj.get("appId") or obj.get("_links", {}).get("app", {}).get("href", "").rsplit("/", 1)[-1]
    if not uid or not app_id:
        return
    scope = obj.get("scope", "USER")
    yield ClaimIn(namespace=ns,
                  event_id=_eid(f"okta:{uid}:{stamp}:assigned_to:{app_id}"),
                  subject=_ref("user", uid), predicate="assigned_to",
                  object=_ref("app", app_id),
                  observed_at=observed, source=source,
                  attrs={"export": source, "scope": scope,
                         "status": obj.get("status", "")})


def _role_assignment_envelopes(obj: dict, ns: str, source: str, observed: datetime,
                               stamp: str) -> Iterator[ClaimIn]:
    # `/users/{id}/roles` and `/groups/{id}/roles` carry the holder only in
    # `_links.assignee.href` (.../users/<id> or .../groups/<id>)
    kind, uid = "user", None
    if isinstance(obj.get("assignee"), dict):
        uid = obj["assignee"].get("id")
    uid = uid or obj.get("userId")
    if not uid and obj.get("groupId"):
        kind, uid = "group", obj["groupId"]
    if not uid:
        href = ((obj.get("_links") or {}).get("assignee") or {}).get("href", "")
        parts = href.rstrip("/").rsplit("/", 2)
        if len(parts) == 3 and parts[1] in ("users", "groups"):
            kind, uid = parts[1][:-1], parts[2]
    if obj.get("assignmentType") == "GROUP":
        kind = "group"
    role_type = obj.get("type") or obj.get("role")
    if not uid or not role_type:
        return
    yield ClaimIn(namespace=ns,
                  event_id=_eid(f"okta:{uid}:{stamp}:has_role:{role_type}"),
                  subject=_ref(kind, uid), predicate="has_role",
                  object=_ref("admin_role", role_type),
                  observed_at=observed, source=source,
                  attrs={"export": source, "role_type": role_type,
                         "status": obj.get("status", "")})


def okta_to_envelopes(text: str, namespace: str, source: str = SOURCE_DEFAULT,
                      as_of: datetime | None = None, mtime: datetime | None = None,
                      stats: dict[str, int] | None = None) -> Iterator[ClaimIn]:
    stats = stats if stats is not None else {}
    data = json.loads(text)
    observed = _clamp(as_of or mtime or datetime.now(timezone.utc))
    stamp = _stamp(observed)

    buckets: dict[str, list[dict]] = {}
    if isinstance(data, dict):
        for key in ("users", "groups", "apps", "appUsers", "roleAssignments"):
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
        "app": _app_envelopes,
        "app_user": _app_user_envelopes,
        "role_assignment": _role_assignment_envelopes,
    }

    for key, items in buckets.items():
        forced = {"users": "user", "groups": "group", "apps": "app",
                  "appUsers": "app_user",
                  "roleAssignments": "role_assignment"}.get(key)
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
                if n == 0:
                    stats["empty"] = stats.get("empty", 0) + 1
            except (ValueError, TypeError, KeyError) as exc:
                stats["invalid"] = stats.get("invalid", 0) + 1
                print(f"okta object {obj.get('id', '?')}: skipped: "
                      f"{str(exc).splitlines()[0][:200]}", file=sys.stderr)


def schema(namespace: str) -> SchemaRegistration:
    return SchemaRegistration(
        namespace=namespace,
        entity_types=[
            EntityTypeDef(name="user", description="an Okta user"),
            EntityTypeDef(name="group", description="an Okta group"),
            EntityTypeDef(name="app", description="an Okta application integration"),
            EntityTypeDef(name="admin_role",
                          description="an Okta admin role (SUPER_ADMIN, etc.)"),
        ],
        predicates=[
            *SHARED_PREDICATES,
            PredicateDef(name="assigned_to", object_types=["app"],
                         description="app-user assignment"),
            PredicateDef(name="enabled", description="account is active"),
            PredicateDef(name="status", description="Okta user status"),
            PredicateDef(name="login", description="Okta login (email)"),
            PredicateDef(name="name", description="display name"),
            PredicateDef(name="mail", description="email address"),
            PredicateDef(name="user_type", description="user type"),
            PredicateDef(name="department", description="department"),
            PredicateDef(name="job_title", description="job title"),
            PredicateDef(name="group_type",
                         description="OKTA_GROUP / APP_GROUP / BUILT_IN"),
            PredicateDef(name="description", description="group description"),
            PredicateDef(name="sign_on_mode",
                         description="app sign-on mode (SAML_2_0, OPENID_CONNECT, etc.)"),
            PredicateDef(name="mfa_enrolled",
                         description="user has an active MFA factor"),
            PredicateDef(name="mfa_factor",
                         description="a registered MFA factor type"),
            PredicateDef(name="credential_provider",
                         description="credential provider type (OKTA, ACTIVE_DIRECTORY, etc.)"),
            PredicateDef(name="created_at", description="account creation time"),
            PredicateDef(name="last_login", description="last login time"),
            PredicateDef(name="signing_key", description="app signing key id"),
        ],
    )


def _to_lines(envs: Iterable[ClaimIn]) -> Iterator[str]:
    for env in envs:
        yield env.model_dump_json(exclude_none=True) + "\n"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loom.connectors.okta",
                                     description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--namespace", default=NAMESPACE_DEFAULT)
    common.add_argument("--source", default=SOURCE_DEFAULT)
    common.add_argument("--as-of", dest="as_of",
                        help="ISO export timestamp override")
    sub = parser.add_subparsers(dest="command", required=True)
    imp = sub.add_parser("import", parents=[common],
                         help="parse Okta JSON and ingest")
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
            yield from okta_to_envelopes(text, args.namespace, args.source,
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
