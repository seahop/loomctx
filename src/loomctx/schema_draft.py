"""Draft a schema registration from a sample export (D-106).

    python -m loomctx.registry draft envelopes.ndjson --namespace netsec > draft.json
    python -m loomctx.registry draft export.json  --out draft.json --notes draft.notes.txt
    python -m loomctx.registry draft export.ldif

Writing a new source's `SchemaRegistration` by hand is the slow part of
onboarding it. This reads a sample and proposes one: a DRAFT for a person to
review, edit and register. It never registers anything and never talks to an
engine. The JSON it prints is a valid `SchemaRegistration` (non-strict); what
it was unsure of goes to the review notes (stderr, and `--notes FILE`), never
into the JSON.

Inputs, most useful first:

  * envelope / claim NDJSON — what every connector's `emit` writes. The entity
    types and predicates are read straight off the claims, so this works for
    any connector, and drafting is mostly about the flags.
  * JSON records — an array, an object of named arrays (`{"users": [...],
    "groups": [...]}`, each array one kind), an OData `{"value": [...]}`, or
    NDJSON with one record per line.
  * LDIF (RFC 2849) — one record per entry, the kind from `objectClass`.

Inference (heuristics on field names and value shapes; no source-specific
branches):

  * entity types: claim subject and object types; else the array a record
    came from (`servicePrincipals` -> `service_principal`); else a kind field
    (`objectClass` — most specific, `@odata.type`, `kind`, `type`).
  * predicates: one per claim predicate, or per record field (camelCase ->
    snake_case; a few house-style names, `displayName` -> `name`, unless
    `--keep-names`).
  * `object_types`: the entity types a field's values point at. A record value
    points at another record when it equals that record's key (`id`, `dn`,
    `objectSid`, a unique `*Id` field), sits in a `{"id": ...}` object, or is a
    URL ending in one. Left open (any entity) when a predicate reaches four or
    more types, or most of them.
  * direction: a list of references named for a role (`members`, `owners`)
    is drafted from the member's side (`member_of`, `owner_of`), the way the
    connectors write it; a record with two or more references and no name of
    its own (an assignment / grant row) becomes one predicate between them.
  * `containment`: membership / parentage names (`member_of`, `contains`,
    `parent`, `children`, ...) and DN parentage (`contains`).
  * `node_status`: status-like scalars (`enabled`, `disabled`, `active`,
    `locked`, `suspended`, `status`, `state`).
  * `label`: name-like scalars (`name`, `displayName`, `sAMAccountName`,
    `userPrincipalName`, `login`, `mail`, ...) and DN-shaped values; `display`
    for the one label whose values say where the entity lives (`x@domain`).
"""

from __future__ import annotations

import base64
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

from .contracts import DEFAULT_NAMESPACE, EntityTypeDef, PredicateDef, SchemaRegistration

FORMATS = ("auto", "envelopes", "ndjson", "json", "ldif")

# name-like fields: their values name the subject (PredicateDef.label, D-091)
LABEL_NAMES = frozenset({
    "name", "display_name", "displayname", "common_name", "cn", "full_name", "label",
    "sam", "sam_account_name", "samaccountname", "upn", "user_principal_name",
    "login", "username", "user_name", "account_name", "principal", "principal_name",
    "mail", "email", "email_address", "hostname", "host_name", "fqdn", "dn_name",
})
# among qualified labels (`x@y`), which reads best beside an opaque key (D-097)
DISPLAY_PRIORITY = ("upn", "user_principal_name", "principal", "principal_name", "login",
                    "username", "user_name", "account_name", "mail", "email")
STATUS_NAMES = frozenset({"enabled", "disabled", "active", "inactive", "locked",
                          "locked_out", "suspended", "status", "state"})
CONTAINMENT_NAMES = frozenset({"member_of", "contains", "contained_in", "parent_of",
                               "child_of", "part_of", "belongs_to", "located_in"})
# key fields, by normalized name, in the order the first present one is the key
KEY_NAMES = ("id", "key", "uuid", "guid", "object_guid", "object_sid", "sid", "arn",
             "uid", "object_id", "dn", "distinguished_name")
KIND_FIELDS = ("objectclass", "@odata.type", "kind", "type", "_type", "entity_type",
               "object_type", "resource_type")
# nested objects that only group a record's own fields
WRAPPERS = frozenset({"profile", "properties", "attributes", "attrs", "fields", "data",
                      "spec", "details", "links", "embedded"})
# leaf names too generic to stand alone once nested (`provider.type` -> provider_type)
GENERIC_LEAVES = frozenset({"id", "href", "url", "uri", "key", "type", "name", "value",
                            "kid", "status", "dn"})
# house style: the names the shipped connectors use for the same thing
HOUSE_NAMES = {
    "display_name": "name", "displayname": "name", "common_name": "name", "cn": "name",
    "user_principal_name": "upn", "sam_account_name": "sam", "samaccountname": "sam",
    "email": "mail", "email_address": "mail", "mail_address": "mail",
    "account_enabled": "enabled", "is_enabled": "enabled",
    "operating_system": "os", "service_principal_name": "spn",
    "distinguished_name": "dn_name", "dn": "dn_name",
    "memberof": "member_of", "created": "created_at", "label": "name",
}
ACTOR_HINTS = ("principal", "assignee", "user", "member", "client", "subject", "actor",
               "source", "from", "owner", "grantee")
BITFIELD_HINTS = ("control", "flags", "flag", "mask", "bits", "attributes", "options")

_QUALIFIED = re.compile(r"^[^@]*[^@\s]@[^@\s]+\.[^@\s]+$")   # `Domain Admins@corp.local` too
_DN = re.compile(r"^[A-Za-z][\w-]*=[^,]+(?:(?<!\\),[A-Za-z][\w-]*=[^,]+)+$")
_DN_SPLIT = re.compile(r"(?<!\\),")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2})?")
_INT = re.compile(r"^-?\d+$")
_MAX_DISTINCT = 64
_REF_SHARE = 0.8          # a field is a reference when this share of its values resolve
_KEY_PRESENT = 0.9        # a key field is on at least this share of a kind's records
_OPEN_TYPES = 4           # a predicate reaching this many types stays open


class Binary(str):
    """A base64 value that did not decode to text (an LDIF `attr::`)."""


@dataclass
class Draft:
    registration: SchemaRegistration
    notes: list[str] = field(default_factory=list)

    def notes_text(self) -> str:
        head = (f"# draft schema for namespace {self.registration.namespace!r}: "
                f"{len(self.registration.entity_types)} entity types, "
                f"{len(self.registration.predicates)} predicates — review before "
                f"registering (nothing was registered)\n")
        return head + "".join(f"# - {n}\n" for n in self.notes)


# ------------------------------------------------------------------ naming #

def snake(name: str) -> str:
    """camelCase / kebab / dotted -> snake_case (`sAMAccountName` -> `sam_account_name`,
    `msDS-AllowedToDelegateTo` -> `ms_ds_allowed_to_delegate_to`)."""
    s = name.strip().lstrip("_@#")
    s = re.sub(r"^([a-z])([A-Z]+)(?=[A-Z][a-z]|$)", lambda m: m.group(1) + m.group(2).lower(), s)
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", s)
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    s = re.sub(r"[^A-Za-z0-9]+", "_", s).strip("_").lower()
    return s or "field"


def singular(name: str) -> str:
    if name.endswith("ies") and len(name) > 4:
        return name[:-3] + "y"
    if re.search(r"(ss|x|z|ch|sh)es$", name):
        return name[:-2]
    if name.endswith("s") and not re.search(r"(ss|us|is)$", name) and len(name) > 3:
        return name[:-1]
    return name


def _plural(name: str) -> bool:
    return singular(name) != name


def _humanize(name: str) -> str:
    return snake(name).replace("_", " ")


def _kind_from_value(value: Any) -> str | None:
    if isinstance(value, list):
        classes = [str(v) for v in value if str(v).lower() != "top"]
        if not classes:
            return None
        pick = classes[-1]
        for c in classes[:-1]:      # domain, domainDNS -> domain
            if pick.lower().startswith(c.lower()) and len(c) < len(pick):
                pick = c
                break
        return snake(pick)
    if isinstance(value, str) and value.strip():
        parts = [p for p in re.split(r"[#./:]", value) if p]
        return snake(parts[-1]) if parts else None
    return None


# ----------------------------------------------------------------- loading #

def parse_ldif(text: str) -> list[dict[str, list]]:
    """LDIF (RFC 2849) -> one {attribute: [values]} dict per entry. Folded
    lines are joined, `attr::` values base64-decoded (kept as `Binary` when
    they are not text), comments and `version:` skipped."""
    logical: list[str] = []
    for line in text.splitlines():
        if line.startswith(" ") and logical:
            logical[-1] += line[1:]
        else:
            logical.append(line)
    entries: list[dict[str, list]] = []
    cur: dict[str, list] | None = None
    for line in logical:
        if not line.strip():
            if cur:
                entries.append(cur)
            cur = None
            continue
        if line.startswith("#") or ":" not in line:
            continue
        attr, _, rest = line.partition(":")
        if cur is None and attr.lower() == "version":
            continue
        value: str
        if rest.startswith(":"):
            raw = rest[1:].strip()
            try:
                decoded = base64.b64decode(raw, validate=True)
                text_value = decoded.decode("utf-8")
                value = text_value if text_value.isprintable() else Binary(raw)
            except (ValueError, UnicodeDecodeError):
                value = Binary(raw)
        elif rest.startswith("<"):
            value = rest[1:].strip()
        else:
            value = rest[1:] if rest.startswith(" ") else rest
        if cur is None:
            cur = {}
        cur.setdefault(attr, []).append(value)
    if cur:
        entries.append(cur)
    return entries


def _is_envelope(obj: Any) -> bool:
    return (isinstance(obj, dict) and isinstance(obj.get("subject"), dict)
            and "predicate" in obj and "object" in obj)


def _sniff(text: str, path: str) -> str:
    low = path.lower()
    if low.endswith(".ldif"):
        return "ldif"
    head = text.lstrip()[:200]
    if re.match(r"^(dn|version):", head, re.IGNORECASE) or head.startswith("#") and "\ndn:" in text:
        return "ldif"
    if low.endswith((".ndjson", ".jsonl")):
        return "ndjson"
    if head.startswith(("[", "{")):
        try:
            json.loads(text)
            return "json"
        except ValueError:
            return "ndjson"
    return "ndjson"


def load(texts: Iterable[tuple[str, str]], fmt: str = "auto"
         ) -> tuple[str, list[Any], list[str]]:
    """(path, text) samples -> ("envelopes", [claim dicts]) or ("records",
    [(collection or None, record, path)]), plus loader notes."""
    envelopes: list[dict] = []
    records: list[tuple[str | None, dict, str]] = []
    notes: list[str] = []
    for path, text in texts:
        kind = _sniff(text, path) if fmt == "auto" else fmt
        if kind == "ldif":
            records.extend((None, e, path) for e in parse_ldif(text))
            continue
        if kind == "json":
            data = json.loads(text)
            items: list[tuple[str | None, Any]] = []
            if isinstance(data, list):
                items = [(None, x) for x in data]
            elif isinstance(data, dict) and isinstance(data.get("value"), list):
                items = [(None, x) for x in data["value"]]
            elif isinstance(data, dict) and any(
                    isinstance(v, list) and v and isinstance(v[0], dict) for v in data.values()):
                for key, val in data.items():
                    if isinstance(val, list) and val and isinstance(val[0], dict):
                        items.extend((key, x) for x in val)
                    else:
                        notes.append(f"{path}: top-level `{key}` is not an array of records; skipped")
            elif isinstance(data, dict):
                items = [(None, data)]
        else:   # ndjson / envelopes
            items = []
            for n, line in enumerate(text.splitlines(), 1):
                if not line.strip():
                    continue
                try:
                    items.append((None, json.loads(line)))
                except ValueError:
                    notes.append(f"{path}:{n}: not JSON; skipped")
        for coll, item in items:
            if not isinstance(item, dict):
                continue
            if fmt == "envelopes" or _is_envelope(item) or item.get("kind") == "document":
                envelopes.append(item)
            else:
                records.append((coll, item, path))
    if envelopes and records:
        notes.append(f"the sample mixes {len(envelopes)} claim envelopes with {len(records)} "
                     "plain records; drafted from the envelopes only")
    if envelopes:
        return "envelopes", envelopes, notes
    return "records", records, notes


# ------------------------------------------------------------- accumulation #

@dataclass
class _Acc:
    """What the sample says about one predicate."""
    subjects: Counter = field(default_factory=Counter)
    objects: Counter = field(default_factory=Counter)
    scalars: Counter = field(default_factory=Counter)   # scalar type -> count
    distinct: set = field(default_factory=set)
    strings: int = 0
    qualified: int = 0
    dn_shaped: int = 0
    sources: set = field(default_factory=set)
    inverted: set = field(default_factory=set)
    unresolved: int = 0
    is_key: bool = False      # a record's own unique identifier (an alias key)

    def ref(self, subject: str, obj: str) -> None:
        self.subjects[subject] += 1
        self.objects[obj] += 1

    def scalar(self, subject: str, value: Any) -> None:
        self.subjects[subject] += 1
        if isinstance(value, bool):
            kind = "boolean"
        elif isinstance(value, int):
            kind = "integer"
        elif isinstance(value, float):
            kind = "number"
        else:
            value = str(value)
            kind = "timestamp" if _DATE.match(value) else "string"
            self.strings += 1
            if _QUALIFIED.match(value):
                self.qualified += 1
            if _DN.match(value):
                self.dn_shaped += 1
        self.scalars[kind] += 1
        if len(self.distinct) < _MAX_DISTINCT:
            self.distinct.add(value if not isinstance(value, str) else value[:80])


def _typed(value: Any) -> Any:
    """LDIF and CSV-ish strings carry ints and booleans as text."""
    if isinstance(value, str) and not isinstance(value, Binary):
        if value.upper() in ("TRUE", "FALSE"):
            return value.upper() == "TRUE"
        if _INT.match(value) and len(value) < 19:
            return int(value)
    return value


# --------------------------------------------------------------- envelopes #

def draft_envelopes(envelopes: Iterable[dict], namespace: str | None = None,
                    notes: list[str] | None = None) -> Draft:
    notes = list(notes or [])
    keys: dict[str, set] = defaultdict(set)
    accs: dict[str, _Acc] = defaultdict(_Acc)
    namespaces: Counter = Counter()
    docs = bad = 0
    for env in envelopes:
        if env.get("kind") == "document":
            docs += 1
            continue
        subj, pred = env.get("subject"), env.get("predicate")
        if not (_is_envelope(env) and subj.get("type") and isinstance(pred, str) and pred):
            bad += 1
            continue
        namespaces[env.get("namespace") or DEFAULT_NAMESPACE] += 1
        stype = str(subj["type"])
        keys[stype].add(subj.get("key"))
        acc = accs[pred]
        acc.sources.add(pred)
        obj = env["object"]
        if isinstance(obj, dict) and obj.get("type"):
            keys[str(obj["type"])].add(obj.get("key"))
            acc.ref(stype, str(obj["type"]))
        elif isinstance(obj, (str, int, float, bool)):
            acc.scalar(stype, obj)
        else:
            bad += 1
    if docs:
        notes.append(f"{docs} document envelopes skipped (documents need no registration)")
    if bad:
        notes.append(f"{bad} lines were not claim envelopes; skipped")
    if namespace is None:
        namespace = namespaces.most_common(1)[0][0] if namespaces else DEFAULT_NAMESPACE
        if len(namespaces) > 1:
            notes.append(f"the sample spans namespaces {sorted(namespaces)}; drafted for "
                         f"{namespace!r} (pass --namespace to choose)")
    counts = {k: len(v) for k, v in keys.items()}
    descs = {k: f"{_humanize(k)} ({n} in the sample)" for k, n in counts.items()}
    return _build(namespace, counts, descs, accs, notes, from_records=False)


# ----------------------------------------------------------------- records #

class _Records:
    """Two passes over raw records: kinds and keys first, then fields with
    every reference resolved against the key index."""

    def __init__(self, records: list[tuple], keep_names: bool):
        self.keep_names = keep_names
        self.notes: list[str] = []
        # (kind, record, group, from a named array); a group is one kind of
        # record from one sample, so keys are judged per source
        self.rows: list[tuple[str, dict, tuple, bool]] = []
        self.coll_of: dict[str, set] = defaultdict(set)
        kind_src: Counter = Counter()
        for item in records:
            coll, rec, origin = item if len(item) == 3 else (*item, "")
            kind, how = self._kind(coll, rec)
            kind_src[how] += 1
            self.rows.append((kind, rec, (origin, coll or kind, kind), bool(coll)))
            if coll:
                self.coll_of[kind].add(coll)
        if kind_src.get("none"):
            self.notes.append(f"{kind_src['none']} records had no kind field and no named array; "
                              "drafted as entity type `record` — set the real type")
        self.key_fields: dict[tuple, list[str]] = {}
        self.index: dict[str, set] = defaultdict(set)
        self._index_keys()

    # kind -------------------------------------------------------------
    def _kind_field(self, rec: dict) -> str | None:
        lower = {k.lower(): k for k in rec}
        for name in KIND_FIELDS:
            if name in lower:
                return lower[name]
        return None

    def _kind(self, coll: str | None, rec: dict) -> tuple[str, str]:
        if coll:
            return singular(snake(coll)), "collection"
        kf = self._kind_field(rec)
        if kf is not None:
            kind = _kind_from_value(rec[kf])
            if kind:
                return kind, "field"
        return "record", "none"

    # keys -------------------------------------------------------------
    @staticmethod
    def _scalar_values(value: Any) -> list[str]:
        vals = value if isinstance(value, list) else [value]
        return [v for v in vals if isinstance(v, str) and v]

    def _index_keys(self) -> None:
        by_group: dict[tuple, list[dict]] = defaultdict(list)
        for _, rec, group, _ in self.rows:
            by_group[group].append(rec)
        candidates: dict[tuple, list[tuple[str, Counter]]] = {}
        for group, recs in by_group.items():
            kind = group[2]
            seen: dict[str, Counter] = defaultdict(Counter)
            present: Counter = Counter()
            for rec in recs:
                for k, v in rec.items():
                    n = snake(k)
                    if n in KEY_NAMES or n.endswith("_id"):
                        vals = self._scalar_values(v)
                        if len(vals) == 1:
                            present[k] += 1
                            seen[k][_norm_key(vals[0])] += 1
            keys = [k for k in present
                    if present[k] >= _KEY_PRESENT * len(recs)
                    and all(c == 1 for c in seen[k].values())]
            keys.sort(key=lambda k: (KEY_NAMES.index(snake(k)) if snake(k) in KEY_NAMES
                                     else len(KEY_NAMES), k))
            for k in present:
                if snake(k) in KEY_NAMES and k not in keys:
                    self.notes.append(f"`{k}` repeats across `{kind}` records, so it is not "
                                      f"their key (an assignment or link table?)")
            candidates[group] = [(k, seen[k]) for k in keys]
            # named keys first (`id`, `dn`, `objectSid`); a unique `*Id` comes second
            for k, values in candidates[group]:
                if snake(k) in KEY_NAMES:
                    for value in values:
                        self.index[value].add(kind)
        for group, recs in by_group.items():   # DNs always address a record
            kind = group[2]
            for rec in recs:
                for k, v in rec.items():
                    if snake(k) in ("dn", "distinguished_name"):
                        for dn in self._scalar_values(v):
                            self.index[_norm_key(dn)].add(kind)
        secondary: list[tuple[str, Counter]] = []
        for group, cands in candidates.items():
            kind = group[2]
            keys = []
            for k, values in cands:
                if snake(k) not in KEY_NAMES:
                    # a unique `managerId` that names other records is a pointer, not a key
                    if any(self.index.get(v, {kind}) - {kind} for v in values):
                        continue
                    secondary.append((kind, values))
                keys.append(k)
            self.key_fields[group] = keys
        for kind, values in secondary:
            for value in values:
                self.index[value].add(kind)

    def _resolve(self, value: Any) -> set | None:
        if isinstance(value, dict):
            for k, v in value.items():
                if snake(k) in KEY_NAMES and isinstance(v, str):
                    hit = self.index.get(_norm_key(v))
                    if hit:
                        return hit
            return None
        if not isinstance(value, str) or isinstance(value, Binary) or not value:
            return None
        hit = self.index.get(_norm_key(value))
        if hit:
            return hit
        if re.match(r"^https?://", value):
            last = value.rstrip("/").rsplit("/", 1)[-1]
            return self.index.get(_norm_key(last))
        return None

    # fields -----------------------------------------------------------
    def _name(self, path: tuple[str, ...], owner: str | None, ref: bool) -> str:
        parts = [p for p in path if snake(p) not in WRAPPERS] or list(path)
        leaf = snake(parts[-1])
        parents = [snake(p) for p in parts[:-1]]
        if ref:
            if leaf in GENERIC_LEAVES and parents:
                leaf = parents[-1]
            elif leaf.endswith("_id") and len(leaf) > 3:
                leaf = leaf[:-3]
        elif owner is not None and parts[-1] != owner:
            pre = singular(snake(owner))
            leaf = leaf if leaf.startswith(pre) else f"{pre}_{leaf}"
        elif leaf in GENERIC_LEAVES and parents:
            leaf = f"{parents[-1]}_{leaf}"
        return leaf

    def fields(self, kind: str, rec: dict, group: tuple, collection_mode: bool
               ) -> tuple[list[tuple[str, str, Any, set | None, bool]], set]:
        """(name, source path, value, referenced kinds or None, top level) per value,
        and the paths that were present but empty."""
        out: list[tuple[str, str, Any, set | None, bool]] = []
        empty: set = set()
        keys = self.key_fields.get(group, [])
        own_keys = set(keys)
        primary = keys[0] if keys else None
        kind_field = None if collection_mode else self._kind_field(rec)

        def emit(path: tuple[str, ...], owner: str | None, value: Any, hit: set | None) -> None:
            top = all(snake(p) in WRAPPERS for p in path[:-1])
            name = self._name(path, owner, hit is not None)
            if top and owner is None and hit is None and path[-1].lower() in KIND_FIELDS:
                name = f"{kind}_{snake(path[-1])}"   # a group's `type` -> group_type
            out.append((name, ".".join(path), value, hit, top and owner is None))

        def walk(value: Any, path: tuple[str, ...], owner: str | None, in_list: bool) -> None:
            if value is None or value == "":
                return
            if isinstance(value, list):
                if not value:
                    empty.add(".".join(path))
                for x in value:
                    walk(x, path, owner, True)
                return
            if isinstance(value, dict):
                hit = self._resolve(value)
                if hit:
                    emit(path, owner, next((v for k, v in value.items()
                                            if snake(k) in KEY_NAMES), None), hit)
                    return
                own = path[-1] if in_list else owner
                for k, x in value.items():
                    if k.startswith("@"):
                        continue
                    walk(x, path + (k,), own, False)
                return
            # a record's own secondary keys (a unique `appId`) are identifiers, not pointers
            hit = None if len(path) == 1 and path[0] in own_keys else self._resolve(value)
            emit(path, owner, value, hit)

        for k, v in rec.items():
            if k == kind_field or k == primary:
                continue
            if k.startswith("@") and isinstance(v, str):
                continue
            if snake(k) in KEY_NAMES and k not in own_keys:
                continue    # an `id` that repeats is the row's own, not a pointer
            walk(v, (k,), None, False)
        return out, empty


def _norm_key(value: str) -> str:
    """Index form of a key: DNs compare case-insensitively, everything else
    (base64 SIDs, mixed-case ids) exactly."""
    return value.lower() if _DN.match(value) else value


def _dn_parent(dn: str) -> str | None:
    parts = _DN_SPLIT.split(dn, 1)
    return parts[1] if len(parts) == 2 and "=" in parts[1] else None


def _house(name: str, keep: bool, taken: set) -> str:
    if keep:
        return name
    alias = HOUSE_NAMES.get(name)
    return alias if alias and alias not in taken else name


def draft_records(records: list[tuple], namespace: str | None = None,
                  keep_names: bool = False, notes: list[str] | None = None) -> Draft:
    notes = list(notes or [])
    rs = _Records(records, keep_names)
    notes.extend(rs.notes)
    collection_mode = any(c for c, *_ in records)
    namespace = namespace or DEFAULT_NAMESPACE

    # pass 2: every record's fields, resolved
    per_kind: dict[str, list[list]] = defaultdict(list)
    empties: dict[str, Counter] = defaultdict(Counter)
    referenced: set = set()
    own_keys: dict[str, set] = defaultdict(set)
    for kind, rec, group, in_array in rs.rows:
        own_keys[kind].update(rs.key_fields.get(group, ()))
        fl, empty = rs.fields(kind, rec, group, in_array)
        per_kind[kind].append(fl)
        for path in empty:
            empties[kind][path] += 1
        for _, _, _, hit, _ in fl:
            if hit:
                referenced.update(hit)

    # which kinds are assignment rows rather than entities
    assoc: dict[str, tuple[set, set]] = {}
    for kind, rows in per_kind.items():
        if kind in referenced:
            continue
        hits = 0
        for fl in rows:
            ref_names = {n for n, _, _, h, _ in fl if h}
            labelled = any(top and n in LABEL_NAMES for n, _, _, h, top in fl if not h)
            if len(ref_names) >= 2 and not labelled:
                hits += 1
        if rows and hits >= _REF_SHARE * len(rows):
            ref_names = {n for fl in rows for n, _, _, h, _ in fl if h}
            actors = {n for n in ref_names if set(n.split("_")) & set(ACTOR_HINTS)}
            if not actors:
                actors = {sorted(ref_names)[0]}
            targets = ref_names - actors
            if targets:
                assoc[kind] = (actors, targets)

    accs: dict[str, _Acc] = defaultdict(_Acc)
    counts: dict[str, int] = {}
    for kind, rows in per_kind.items():
        if kind in assoc:
            actors, targets = assoc[kind]
            pred = kind
            for fl in rows:
                subj = {k for n, _, _, h, _ in fl if h and n in actors for k in h}
                obj = {k for n, _, _, h, _ in fl if h and n in targets for k in h}
                for s in subj:
                    for o in obj:
                        accs[pred].ref(s, o)
            accs[pred].sources.add(f"{kind} records")
            scalars = sorted({n for fl in rows for n, _, _, h, _ in fl if not h})
            notes.append(
                f"`{kind}` records look like assignment rows (references {sorted(actors)} -> "
                f"{sorted(targets)}, no name of their own): drafted as one predicate `{pred}` "
                "between them — rename it to a verb (has_…, assigned_to)"
                + (f"; their other fields ({', '.join(scalars[:8])}) would ride as claim attrs"
                   if scalars else ""))
            continue
        counts[kind] = len(rows)
        # field names actually used on this kind (for house-name collisions)
        raw_names = {n for fl in rows for n, _, _, _, _ in fl}
        stats: dict[str, list] = defaultdict(lambda: [0, 0])   # name -> [refs, scalars]
        for fl in rows:
            for n, _, _, h, _ in fl:
                stats[n][0 if h else 1] += 1
        for fl in rows:
            for n, src, value, hit, _ in fl:
                refs, scal = stats[n]
                is_ref = refs >= _REF_SHARE * (refs + scal)
                if is_ref:
                    if not hit:
                        accs_name = _ref_pred(n, kind, per_kind, keep_names)[0]
                        accs[accs_name].unresolved += 1
                        continue
                    name, inverted = _ref_pred(n, kind, per_kind, keep_names)
                    acc = accs[name]
                    acc.sources.add(src)
                    for k in hit:
                        if inverted:
                            acc.ref(k, kind)
                        else:
                            acc.ref(kind, k)
                    if inverted:
                        acc.inverted.add(f"`{src}` on {kind}")
                    continue
                if isinstance(value, Binary):
                    accs.setdefault(f"\0binary:{src}", _Acc()).subjects[kind] += 1
                    continue
                name = _house(n, keep_names, raw_names - {n})
                acc = accs[name]
                acc.sources.add(src)
                acc.is_key |= src in own_keys[kind]
                acc.scalar(kind, _typed(value))
        # DN parentage -> contains
        for rec in (r for k, r, _, _ in rs.rows if k == kind):
            for k, v in rec.items():
                if snake(k) in ("dn", "distinguished_name"):
                    for dn in rs._scalar_values(v):
                        parent = _dn_parent(dn)
                        hit = rs.index.get(_norm_key(parent)) if parent else None
                        for pk in hit or ():
                            accs["contains"].ref(pk, kind)
                            accs["contains"].sources.add("DN parentage")
        for path, n in sorted(empties[kind].items()):
            if not any(src == path or src.startswith(path + ".")
                       for fl in rows for _, src, _, _, _ in fl):
                notes.append(f"`{path}` on {kind} is empty in every record ({n}); no predicate "
                             "drafted — add one if the source fills it")

    binaries = sorted(k.split(":", 1)[1] for k in accs if k.startswith("\0binary:"))
    for k in [k for k in accs if k.startswith("\0binary:")]:
        del accs[k]
    if binaries:
        notes.append(f"binary attributes skipped: {', '.join(binaries)} — a connector has to "
                     "decode them (e.g. a security descriptor into grant edges)")
    if collection_mode:
        notes.append("entity types come from the names of the arrays they were in")
    descs = {}
    for k, n in counts.items():
        colls = sorted(rs.coll_of.get(k, ()))
        descs[k] = (f"{_humanize(k)} ({n} records"
                    + (f" in `{'`, `'.join(colls)}`" if colls else "") + ")")
    return _build(namespace, counts, descs, accs, notes, from_records=True)


def _ref_pred(name: str, kind: str, per_kind: dict, keep_names: bool) -> tuple[str, bool]:
    """A reference field's predicate name and whether it is drafted from the
    referenced record's side (`members` on a group -> `member_of`)."""
    base = singular(name) if _plural(name) else name
    if name in ("member", "members"):
        return "member_of", True
    if name in ("children", "child", "contains"):
        return "contains", False
    if name in ("parent", "parents"):
        return "contains", True
    if name in ("memberof", "member_of"):
        return "member_of", False
    if _plural(name) and base not in per_kind and "_" not in name:
        return f"{base}_of", True       # owners -> owner_of
    return (name if keep_names else HOUSE_NAMES.get(name, name)), False


# ------------------------------------------------------------------- build #

def _is_status(name: str, acc: _Acc) -> bool:
    base = re.sub(r"^(is_|account_|user_)", "", name)
    if base not in STATUS_NAMES:
        return False
    kinds = set(acc.scalars)
    if kinds <= {"boolean"}:
        return True
    return kinds <= {"string", "boolean"} and len(acc.distinct) <= 20


def _describe(name: str, acc: _Acc, object_types: list[str]) -> str:
    sources = sorted(s for s in acc.sources if s != name)
    origin = f"from `{'`, `'.join(sources[:3])}`" if sources else ""
    subjects = ", ".join(sorted(acc.subjects)[:4]) + (", ..." if len(acc.subjects) > 4 else "")
    if acc.objects:
        what = (f"-> {', '.join(object_types)}" if object_types else "-> any entity")
        what += f" (from {subjects})"
    else:
        kinds = "/".join(sorted(acc.scalars))
        what = f"{kinds} on {subjects}"
    if acc.inverted:
        origin = f"inverted from {', '.join(sorted(acc.inverted)[:3])}"
    head = _humanize(name)
    return "; ".join(p for p in (f"{head}: {what}", origin) if p)


def _build(namespace: str, counts: dict[str, int], descs: dict[str, str],
           accs: dict[str, _Acc], notes: list[str], from_records: bool) -> Draft:
    kinds = set(counts)
    for acc in accs.values():
        kinds.update(acc.subjects)
        kinds.update(acc.objects)
    preds: list[PredicateDef] = []
    labels: list[tuple[str, _Acc]] = []
    for name in sorted(accs):
        acc = accs[name]
        refs, scal = sum(acc.objects.values()), sum(acc.scalars.values())
        if not refs and not scal:
            if acc.unresolved:
                notes.append(f"`{name}` values look like references but none matched a record "
                             "in the sample; add it with object_types by hand if it points at "
                             "another source")
            continue
        object_types: list[str] = []
        if refs and scal:
            notes.append(f"`{name}` mixes entity references ({refs}) and scalars ({scal}); "
                         "object_types left open — split it or pick one")
        elif refs:
            reach = sorted(acc.objects)
            if len(reach) >= _OPEN_TYPES or (len(kinds) >= _OPEN_TYPES
                                             and 2 * len(reach) > len(kinds)):
                notes.append(f"`{name}` points at {len(reach)} entity types "
                             f"({', '.join(reach)}); object_types left open (any entity)")
            else:
                object_types = reach
        if acc.unresolved and refs:
            notes.append(f"`{name}`: {acc.unresolved} values matched no record in the sample")
        containment = bool(refs) and not scal and (
            name in CONTAINMENT_NAMES or name.startswith("member_of"))
        if containment:
            notes.append(f"`{name}` marked containment (a scope with no `expand` follows it) "
                         "from its name — confirm")
        node_status = not refs and _is_status(name, acc)
        if node_status:
            notes.append(f"`{name}` marked node_status (reported on every path through its "
                         f"subject) — values seen: {_sample(acc)}")
        label = (not refs and scal > 0 and acc.strings == scal
                 and (name in LABEL_NAMES or acc.dn_shaped >= _REF_SHARE * scal))
        if label:
            labels.append((name, acc))
        if not refs and not node_status and set(acc.scalars) == {"integer"} and any(
                h in name for h in BITFIELD_HINTS):
            notes.append(f"`{name}` is an integer that looks like a bit field (values "
                         f"{_sample(acc)}); decode the bits that matter into boolean "
                         "predicates in the connector")
        if (not refs and set(acc.scalars) == {"string"} and name.endswith("_id")
                and from_records and not acc.is_key):
            notes.append(f"`{name}` looks like an id but matched no record in the sample; if it "
                         "points at another source, add object_types by hand")
        preds.append(PredicateDef(name=name, object_types=object_types,
                                  containment=containment, node_status=node_status,
                                  label=label, description=_describe(name, acc, object_types)))
    display = _pick_display(labels)
    if labels:
        notes.append("label (entity search matches its values): "
                     + ", ".join(n for n, _ in labels))
    if display:
        for p in preds:
            if p.name == display:
                p.display = True
        notes.append(f"display: `{display}` — its values are qualified (name@where), so a pack "
                     "reads them beside an opaque key; keep exactly one")
    elif labels:
        notes.append("no label has qualified values (name@domain); pick a display label by "
                     "hand if keys are opaque")
    if not any(p.containment for p in preds):
        notes.append("no containment predicate found: scopes will need an explicit `expand`")
    notes.append("strict is false: once the names are right, set \"strict\": true to reject "
                 "anything unregistered")
    entity_types = [EntityTypeDef(name=k, description=descs.get(k, f"{_humanize(k)} (referenced)"))
                    for k in sorted(kinds)]
    reg = SchemaRegistration(namespace=namespace, entity_types=entity_types, predicates=preds)
    return Draft(registration=reg, notes=notes)


def _sample(acc: _Acc) -> str:
    vals = sorted(acc.distinct, key=str)[:6]
    more = ", ..." if len(acc.distinct) > 6 else ""
    return ", ".join(json.dumps(v) for v in vals) + more


def _pick_display(labels: list[tuple[str, _Acc]]) -> str | None:
    qualified = [(n, a) for n, a in labels if a.qualified >= _REF_SHARE * a.strings]
    if not qualified:
        return None

    def rank(item: tuple[str, _Acc]) -> tuple:
        n, a = item
        pri = DISPLAY_PRIORITY.index(n) if n in DISPLAY_PRIORITY else len(DISPLAY_PRIORITY)
        return (pri, -sum(a.subjects.values()), n)
    return min(qualified, key=rank)[0]


# --------------------------------------------------------------------- API #

def draft(texts: Iterable[tuple[str, str]], fmt: str = "auto", namespace: str | None = None,
          keep_names: bool = False) -> Draft:
    """Draft from (path, text) samples. Pure: reads nothing, registers nothing."""
    mode, items, notes = load(texts, fmt)
    if mode == "envelopes":
        return draft_envelopes(items, namespace, notes)
    if not items:
        raise ValueError("the sample holds no records or claim envelopes")
    return draft_records(items, namespace, keep_names, notes)


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def draft_files(paths: list[str], fmt: str = "auto", namespace: str | None = None,
                keep_names: bool = False) -> Draft:
    return draft(((p, _read(p)) for p in paths), fmt, namespace, keep_names)
