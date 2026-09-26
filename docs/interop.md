# Interop: STIX 2.1, OCSF and raw LDAP / LDIF

Loom's own shapes are the contracts in `src/loom/contracts.py`; the world
speaks STIX (threat intelligence), OCSF (security events) and, for Active
Directory, raw LDAP. Connectors translate at the edges, so a TIP's bundle,
a scanner's findings or a directory export land as cited, time-windowed
claims, and Loom's facts leave as records other tools accept. The engine
learns nothing about any standard: the mapping is a connector plus a schema
registration (hard constraint: domain specifics stay in the registry).

Everything here is idempotent (event ids embed the record's own
modification stamp: a re-import is a no-op, a *revised* record is a new
observation — history, not overwrite) and runs through the same paths as
any other connector: `--db` writes straight into a store, `--url` posts
batches to an engine or gateway, `emit` writes NDJSON envelopes for
`python -m loom.ingest`.

```bash
# STIX 2.1
python -m loom.connectors.stix import bundle.json --namespace netsec                  # LOOM_DB store
python -m loom.connectors.stix import bundle.json --namespace netsec --url http://loom:8000 --key loomk_...
python -m loom.connectors.stix export --namespace netsec --out bundle.json            # or --db /data/loom.db; --history: every version
python -m loom.connectors.stix emit bundle.json --namespace netsec > envelopes.jsonl
python -m loom.connectors.stix schema --namespace netsec [--mapping map.json]

# OCSF vulnerability_finding (class_uid 2002)
python -m loom.connectors.ocsf import findings.ndjson --namespace netsec              # NDJSON or a JSON array
python -m loom.connectors.ocsf export --namespace netsec --out findings.ndjson       # --history: every version
python -m loom.connectors.ocsf emit findings.ndjson --namespace netsec
python -m loom.connectors.ocsf schema --namespace netsec

# raw LDAP / LDIF (Active Directory)
python -m loom.connectors.ldap import export.ldif --namespace ad                      # into the LOOM_DB store
python -m loom.connectors.ldap import export.ldif --namespace ad --url http://loom:8000 --key loomk_...
python -m loom.connectors.ldap emit export.ldif --namespace ad > envelopes.jsonl
python -m loom.connectors.ldap schema --namespace ad [--as-of 2026-09-20T09:00:00Z]
```

`examples/stix_import.py` is the same STIX import in ~100 lines of standard
library, for a pipeline that cannot depend on the Loom package.

## STIX 2.1 → Loom

### Entities

A STIX object becomes a Loom entity `type:key`. The STIX type maps by the
table; anything not listed keeps its name with hyphens as underscores
(`intrusion-set` → `intrusion_set`, `attack-pattern` → `attack_pattern`).

| STIX type | Loom type | key |
| --- | --- | --- |
| `ipv4-addr`, `ipv6-addr` | `ip` | `value` |
| `domain-name` | `domain` | `value` |
| `url` | `url` | `value` |
| `email-addr` | `email` | `value` |
| `mac-addr` | `mac` | `value` |
| `user-account` | `user` | `user_id`, else `account_login` / `display_name` |
| `file` | `file` | `hashes.SHA-256`, else `name` |
| `identity` | `identity` | `name` |
| `vulnerability` with a `cve` external reference | `cve` | the CVE id (`CVE-2014-0160`) — **the same entity `loom.connectors.vulns` (NVD/KEV/EPSS) and the OCSF importer write to** |
| `vulnerability` without one | `vulnerability` | `name` |
| any other SDO (`malware`, `indicator`, `intrusion-set`, `campaign`, `tool`, `infrastructure`, `attack-pattern`, `threat-actor`, `course-of-action`, `location`, `grouping`, `malware-analysis`) | the type, hyphens → underscores | `name` |

A reference to an object that is not in the bundle keeps the edge, keyed
by the STIX id (`ip:ipv4-addr--…`); the resolution worker (D-023) can
merge it when the object arrives later. An object that carries
`x_loom_entity_type` and `x_loom_entity_key` (Loom's own export) lands on
that entity — `x-loom-host` back on `host:<key>`, an `identity` exported
from `organization` back on `organization`.

### Relationships and sightings → relational claims

| STIX | Loom claim |
| --- | --- |
| `relationship.source_ref` / `target_ref` | `subject` / `object` (entity refs as above) |
| `relationship_type` | `predicate` — hyphens → underscores (`attributed-to` → `attributed_to`), or the mapping's `predicates` entry |
| `start_time` / `stop_time` | `valid_from` / `valid_to` |
| `created` / `modified` | `observed_at` = `modified` (the assertion time of the version being imported; `created` when absent), `attrs.created` keeps the original |
| `confidence` (0–100) | `confidence` (0–1); absent → the contract default 1.0 |
| `created_by_ref` | `source` = that identity's `name`; no identity → `--source` (default `stix`) |
| `description` | `attrs.description` |
| `revoked: true` | `import`: a final version closed at the revocation (`valid_to` = its `modified`, `attrs.revoked`) superseding the imported edge; dropped (`dropped_no_prior`) when that edge was never imported; `emit`: skipped (counted as `revoked`) |
| `sighting.sighting_of_ref` `where_sighted_refs[i]` | one claim per place: `subject sighted_by object` (the mapping's `sighting` name) |
| `sighting` with no `where_sighted_refs` | `subject sighted_count <count>` |
| `sighting.first_seen` / `last_seen` / `count` | `valid_from` / `valid_to` / `attrs.count` |

Every claim carries `attrs.stix_id` and `attrs.stix_type`; the event id is
`stix:<id>:<modified>:<predicate>[:tag]` (`unversioned` in place of the
stamp for an object with neither `modified` nor `created` — an SCO: STIX
does not version them, and an id that embedded the import's clock
recorded the SCO's facts again on every re-import).

**Versions chain (import).** A revised relationship or sighting (a new
`modified`: a `stop_time` appeared, the confidence changed) lands as a new
observation that names the previous version's in `supersedes` (D-050), so
the reader shows the old one as history instead of beside the new one.
The previous version is found in the target store (or earlier in the same
run) by subject, predicate, object and `attrs.stix_id`; an older version
arriving late supersedes nothing newer. `emit` has no store to ask and
does not chain. An object that cannot be read (a malformed timestamp, a
`modified` in the future) is counted as `invalid` and skipped; the rest of
the bundle imports.

### Object properties → scalar claims on the object's entity

| STIX property | predicate | notes |
| --- | --- | --- |
| `name` | `name` | always emitted for named objects, so the entity exists even with no relationships |
| `description` | `summary` | |
| `pattern`, `pattern_type` | `pattern`, `pattern_type` | the indicator's `valid_from` / `valid_until` become the pattern claim's validity window |
| `aliases`, `labels` | `alias`, `label` | one claim per item |
| `indicator_types`, `malware_types`, `infrastructure_types`, `threat_actor_types`, `tool_types` | `indicator_type`, `malware_type`, `infrastructure_type`, `threat_actor_type`, `tool_type` | one per item |
| `goals`, `sectors`, `roles` | `goal`, `sector`, `role` | one per item |
| `is_family`, `resource_level`, `primary_motivation`, `sophistication`, `identity_class`, `objective`, `first_seen`, `last_seen` | same name | |
| `kill_chain_phases[]` | `kill_chain_phase` | `"<kill_chain_name>:<phase_name>"` |
| `resolves_to_refs`, `belongs_to_refs` (SCOs) | `resolves_to`, `belongs_to` | relational |

### Notes, reports, opinions → documents

`note`, `report` and `opinion` become `DocumentIn` envelopes (title +
content/description, `attrs.object_refs`, `report_types`, `authors`,
`published`). They are emitted **first**, and every claim produced from an
object a report lists in `object_refs` cites that document
(`provenance.artifact_event_id`, D-039), so the report's text ranks as an
excerpt for those entities.

### Not mapped (by design)

- `marking-definition`, `language-content`, `extension-definition`,
  `observed-data` (its SCOs are imported when they are bundle objects).
- `x_` custom properties and non-CVE `external_references`: STIX-specific
  metadata, not facts about the entity. Add them to `mapping.properties`
  if a namespace wants them. (Loom's own `x_loom_*` properties are read
  back, see "Round trip" under Loom → STIX.)
- `object_marking_refs` / `granular_markings`: Loom scopes data by
  namespace and grant (D-013a), not per-object marking. Import TLP:RED
  into its own namespace.
- `revoked: true` on anything but a relationship or sighting (an SDO,
  an SCO, a report) is skipped; revocation of an edge is mapped (above).

### Overriding the tables

A `mapping` dict (`--mapping map.json`) merges over the defaults:

```json
{"entity_types": {"identity": "org"},
 "predicates": {"targets": "attacks", "attributed-to": "run_by"},
 "properties": {"description": "description", "x_acme_tier": "tier"},
 "sighting": "seen_at"}
```

`python -m loom.connectors.stix schema --namespace N --mapping map.json`
prints the resulting registration; `import` registers it (non-strict —
`object_types` are left open because STIX relationship types join many
object kinds). To make the names authoritative for the namespace, register
them with `strict: true` yourself (`POST /v1/schemas`, D-024) after the
first import; a strict namespace then rejects any unmapped predicate.

## Loom → STIX 2.1

`observations_to_bundle(observations, namespace)` / `export` writes a
valid 2.1 bundle:

| Loom | STIX |
| --- | --- |
| entity `ip` / `domain` / `url` / `email` / `mac` | SCO (`ipv4-addr` or `ipv6-addr` by shape, `domain-name`, …) with `value`; ids are the spec's deterministic UUIDv5 over the value |
| entity `user`, `file` | `user-account` (`user_id`), `file` (`hashes.SHA-256` for a 64-hex key, else `name`) |
| entity `cve` / `vulnerability` | `vulnerability` with `name` and `external_references: [{source_name: "cve", external_id}]` |
| entity `identity` / `organization` | `identity` |
| entity `malware`, `intrusion_set`, `threat_actor`, `attack_pattern`, `campaign`, `tool`, `infrastructure`, `indicator`, `course_of_action`, `location`, `grouping` | the SDO, `name` = key |
| any other entity type (`host`, `product`, `alert`, …) | `x-loom-<type>` custom object, `name` = key |
| every entity object | `x_loom_entity_type`, `x_loom_entity_key`, `x_loom_namespace`; `created` / `modified` from the earliest / latest observation touching it |
| relational observation | `relationship` (`relationship_type` = predicate, underscores → hyphens, or the inverse mapping), `start_time` / `stop_time` from `valid_from` / `valid_to`, `confidence` 0–100, `created_by_ref` = the source's identity, `description` from attrs |
| `sighted_by` observation | `sighting` (`sighting_of_ref`, `where_sighted_refs`, `first_seen` / `last_seen`, `count` from attrs) |
| scalar observation | on the subject's object: the **newest** of each mapped predicate as the STIX property (`summary` → `description`, `pattern`, `aliases`, `malware_types`, …; unmapped predicates are *not* invented as properties), and **all of them** in `x_loom_observations[]` (`id`, `predicate`, `value`, `observed_at`, `source`, `confidence`, validity) |
| every relationship / sighting | `x_loom_observation_id`, `x_loom_predicate`, `x_loom_source` — the citation |
| each `source` | one `identity` (`identity_class: unknown`, `x_loom_source`) |

Ids are deterministic (UUIDv5 over namespace, type and key; for
relationships the imported STIX id, else UUIDv5 over the first
observation of the edge's version chain), so two exports of the same store
diff cleanly and a consumer can upsert. Redacted observations (D-016) are
skipped.

**Versions are STIX versions (S-30).** STIX 2.1 (§3.6) versions an object
in place: every version keeps the object's `id` and `created` and carries
a later `modified`; a consumer keeps the newest. Loom's versions of one
edge — the versions the importer chained, and any recorded supersession
(D-050, `supersedes`) between relational observations of the same kind —
are written exactly that way:

| Loom | STIX |
| --- | --- |
| the versions of one relationship / sighting | one `id` (the imported `stix_id`, else derived from the chain's first observation), `created` = the first version's (its imported `created` when it has one), `modified` = each version's `observed_at` |
| `export` (default) | the **newest** version of each object only — a superseded version never appears as a second current edge |
| `export --history` | every version, oldest first, all under the same `id` (bundles may carry several versions of one object; the spec's consumers keep the newest) |
| a revoked version (imported `revoked: true`, `attrs.revoked`) | `revoked: true` |
| an edge whose newest version was superseded by something that is not a version of it (a correction into a scalar, a relationship turned sighting) | a final `revoked: true` version at the superseding row's time, `x_loom_superseded_by` |
| each version | `x_loom_observation_id` (the citation), `x_loom_event_id` (the observation's own event id; `x_loom_event_ids[]`, aligned with `where_sighted_refs`, on a sighting), `x_loom_supersedes` |
| a superseded scalar | still listed in `x_loom_observations` (with `superseded_by`), never the object's property |

A later version from a different `source` keeps the object's `id` with
its own `created_by_ref`; STIX expects only the creator to version an
object, Loom's supersession is recorded, not ownership-based — the
deviation is deliberate (one edge, one id).

**Round trip.** An export restates observations; importing it records
them as they were, not as new assertions: an entity object that carries
`x_loom_namespace` contributes the rows in its `x_loom_observations`
(their predicate, value, time, source, confidence and `event_id`; a
superseded one is skipped) instead of claims derived from its STIX
properties, an edge version reuses its `x_loom_event_id`, and the
per-source `identity` objects (`x_loom_source`) are not imported as
entities. So import → export → import is stable: re-importing an export
(either form) into the store it came from records nothing; importing it
into an empty store reproduces the current versions (all of them with
`--history`, chained by supersession) with their sources, times and
event ids, and exporting that store gives the same objects again. A
revocation exported without its earlier versions has nothing to close in
an empty store and is dropped, like any revocation of an edge never
imported.

## OCSF `vulnerability_finding` (class_uid 2002) → Loom

Other event classes are ignored (counted as `other_class`).

| OCSF | Loom |
| --- | --- |
| `device.hostname` / `name` / `uid`, else `resources[].hostname` / `name` / `uid`, else `device.ip` | the host entity `host:<name>` |
| `vulnerabilities[].cve.uid` | the CVE entity `cve:<CVE-…>` (upper-cased; non-CVE uids are dropped) |
| the pair | `host affected_by cve` — `valid_from` = `vulnerabilities[].first_seen_time` / `finding_info.first_seen_time` / `created_time`; `valid_to` = `last_seen_time` (or the event time) **only when the finding is closed**: `status_id` 4 (Resolved), or `activity_id` 3 (Close) unless the status is 3 (Suppressed — muted, still present, so the exposure stays open); `status_id` 5/6 (Archived/Deleted) are record housekeeping and close nothing; attrs: `finding_uid`, `title`, `status`, `status_id`, `severity`, `severity_id`, `is_exploit_available`, `is_fix_available` |
| `cve.cvss[]` (`base_score`, `version`, `vector_string`, `severity`) | `cvss_score` + `has_severity` on the CVE, one per entry, `source` = `<product>:cvss<version>` (so a scanner's score sits beside NVD's and the CNA's as a real cross-source conflict, D-035) |
| `cve.epss.score` / `.percentile` | `epss_score` / `epss_percentile` |
| `cve.desc` (or `vulnerabilities[].desc`) | `summary`, trimmed to 400 chars |
| `is_exploit_available` / `is_fix_available` | `exploit_available` / `fix_available` (bool) on the CVE |
| `affected_packages[]` | `cve affects product:<vendor:name>` with `version` / `fixed_in` attrs |
| `time` (epoch ms; else `finding_info.modified_time` / `created_time` / `metadata.logged_time`) | `observed_at` |
| `metadata.product.name` (normalized: `Acme Scanner` → `acme_scanner`) | `source` (`--source` overrides) |
| `finding_info.uid` (else `metadata.uid`, else a hash of the event) + `time` | the event-id prefix `ocsf:<uid>:<time>` |

**Versions chain (import).** Each event for a finding lands as a new
`affected_by` observation (the event id embeds its time) that names the
previous version's in `supersedes` (D-050) — found in the target store or
earlier in the same run by host, CVE and `finding_uid`. A re-scan of an
open finding therefore does not pile up open rows, and a resolution
supersedes the open row instead of sitting next to it, so the host stops
reading as affected. An older event arriving late supersedes nothing
newer. `emit` has no store to ask and does not chain; over `--url` the
prior versions are read through `GET /v1/entities/.../observations`, so the
key needs `r` on the namespace (a write-only key imports with in-run
chaining only, and says so). The input may be
NDJSON, a JSON array, or one (pretty-printed) object; an event that cannot
be mapped (a `time` in the future, a field of the wrong shape) is counted
as `invalid` and skipped. `status_id` / `severity_id` sent as strings
(`"4"`) are read as numbers.

Not mapped: `observables`, `evidences`, `remediation`, `enrichments`,
`actor`, cloud/`api` context, and anything under `unmapped`. Findings with
no CVE uid produce nothing (Loom's vulnerability entity is the CVE).

## Loom → OCSF

`observations_to_findings` / `export` writes one `vulnerability_finding`
per finding — the versions of a host→cve edge (`affected_by` or any
host→cve relation) — plus one per CVE that has facts but no host:

| Loom | OCSF |
| --- | --- |
| the edge | `resources[{name, type: host}]`, `device.hostname`, `finding_info.uid` = the imported `finding_uid` (else the first observation of the edge's version chain), `first_seen_time` / `last_seen_time` from the validity window, `status_id` 4 (Resolved) when the window is closed, else the recorded status (Suppressed and In Progress round-trip) |
| `cvss_score` (newest per source) with `attrs.version` / `vector` | `vulnerabilities[0].cve.cvss[]` |
| `has_severity` (newest) | `severity_id` / `severity`, and `cvss[].severity` |
| `epss_score` / `epss_percentile` | `cve.epss` |
| `summary` | `cve.desc` |
| `exploited_in_wild` (KEV) or `exploit_available`, `fix_available` | `is_exploit_available`, `is_fix_available` |
| `affects` → product | `affected_packages[]` |
| every contributing observation | `unmapped.loom_observation_ids[]` (the citation), `unmapped.loom_sources[]`, `unmapped.loom_namespace` |
| the CVE facts it restates | `unmapped.loom_observations[]`: each as recorded (`subject`, `predicate`, `value`, `observed_at`, `source`, `confidence`, validity, `attrs`, `event_id`) |
| the edge's own source and event id | `unmapped.loom_source`, `unmapped.loom_event_id` |

The CVE block is built from current facts only: a superseded score,
severity or package (D-050) is history and is not exported.

**Versions are one finding (S-30).** OCSF identifies a finding by
`finding_info.uid` and reports its lifecycle as successive events for
that uid. The versions of one finding — sharing an imported `finding_uid`,
or chained by `supersedes` (a supersession that moves the finding to
another host is a version; one that names another CVE is not) — share
the uid:

| Loom | OCSF |
| --- | --- |
| `export` (default) | the **newest** version only, with its state and status — a resolved finding is one Resolved record, not an open one per earlier scan |
| `export --history` | every version, oldest first: `activity_id` 1 (Create) for the first, 2 (Update) after, 3 (Close) for a version that closed the exposure |
| a finding whose newest version was superseded by something that is not a version of it | a final Close with `status_id` 99 (Other), `status` "Superseded", `unmapped.loom_superseded_by` |

`type_uid` follows the activity (`200201` / `200202` / `200203`).
Importing a record Loom exported (it carries `unmapped.loom_observations`)
records the edge under `unmapped.loom_event_id` / `loom_source` and the
restated CVE facts as they were, instead of re-asserting the CVE block
under the source `loom`: re-importing an export into the store it came
from records nothing, and importing it into an empty store gives the
same findings (and CVE facts, with their sources) on the next export.

Constants: `class_uid 2002`, `category_uid 2`, `metadata.version 1.3.0`,
`metadata.product.name Loom`.

## Raw LDAP / LDIF (Active Directory) → Loom

> **Experimental (2026-09-26).** A review found decoding gaps that must be
> fixed before this is used on real exports: mapped generic rights are not
> recognised (an export that stores GenericWrite as `0x20028` reads as no
> right); some ACL claim event ids collide and one is dropped; inherit-only
> (`INHERIT_ONLY`) ACEs are wrongly attributed to the object itself; an
> inbound `trustDirection` is emitted in the wrong direction; and large
> imports scan the DN index per ACE (slow). Treat output as illustrative
> until these land. The reachability benchmark's numbers are withdrawn
> ([ad-eval.md](ad-eval.md)).

`loom.connectors.ldap` decodes a raw directory export — object by object,
deterministically — into typed, cited claims in an `ad` namespace, so an
agent can ask **object-level reachability** questions over the ordinary
scope walk: *"what rights / trust / membership path connects user:X to
domain:B?"*. It reads a **file** (LDIF); it is not a collector and issues
no directory operations.

**It is NOT BloodHound.** It performs no graph reasoning: no transitive or
*effective* admin, no shortest / cheapest attack-path scoring, no edge
exploitability weighting. Loom carries the evidence (the direct edges and
the decoded rights); the agent (or a later analysis layer) assembles and
ranks the path. Group **nesting** is the scope walk's job at depth N, not
the connector's.

**The boundary — object-level only.** LDAP gives you ACL / membership /
delegation / trust reachability. It does **not** contain sessions or
local-admin-on-member-servers — those need host collection (what SharpHound
does at the host), not the directory. So an LDAP-only Loom answers
control-of-account, delegation, trust and GPO-control questions, but not
session-based lateral movement. Load host/session data as its own claims
later and the same walk extends over it; this connector does not invent it.

### Input — LDIF (RFC 2849)

Canonical input is LDIF: base64 values (`attr:: <b64>`), line folding (a
continuation line begins with a single space), multi-valued attributes and
plain `changetype`-free entries are all handled; `attr:< url` (an external
reference) is skipped. CSV/JSON from `Get-AD*` can be normalized to the same
claims by a thin adapter later. A small synthetic fixture
(`tests/fixtures/corp_ad.ldif`) drives the tests and demo; real AD data is
never required.

### Entities — keyed by objectSid

Every object is keyed by its **objectSid**, decoded from the binary/base64
LDIF value to the standard string `S-1-5-21-…-<rid>` (MS-DTYP 2.4.2) — it is
stable across rename. `distinguishedName` (`dn_name`) and `sAMAccountName`
(`sam`) ride as scalar claims so entity resolution (D-042/D-060) can fold
them onto the SID-keyed entity, and the friendly `name` is carried too.
Within one export, `member` / `memberOf` DNs are resolved to the SID of the
object they name, so the edges connect the SID-keyed entities directly. The
object's type comes from `objectClass` (most specific wins):

| objectClass | Loom type |
| --- | --- |
| `domainDNS` / `domain` | `domain` |
| `computer` | `computer` |
| `user` (not a computer) | `user` |
| `group` | `group` |
| `organizationalUnit` | `ou` |
| `groupPolicyContainer` | `gpo` |
| `container` (and the fallback) | `container` |

A `trustedDomain` object is not SID-keyed: its partner is an external
domain, keyed by DNS name (`domain:dev.local`).

### Decode (deterministic, per-object)

| Directory fact | Loom claim |
| --- | --- |
| `member` / `memberOf` | `member_of` (subject = principal, object = group) — **DIRECT only**; nesting is the walk's job |
| DN parentage | `contains` (parent object → child), containment |
| `trustedDomain` | `trusts` (trusting domain → partner), attrs `direction` (from `trustDirection`), `transitive` and `sid_filtering` (from `trustAttributes`), `forest_transitive`, `partner` |
| `nTSecurityDescriptor` (base64 SD blob) | `has_ace` (trustee SID → this object), `attrs.right` decoded from the access mask, `attrs.object_type` the ObjectType GUID for object ACEs |
| `userAccountControl` bitmask | `enabled` (not 0x2), `unconstrained_delegation` (0x80000), `no_preauth` (0x400000, AS-REP roastable), `is_dc` (0x2000 SERVER_TRUST_ACCOUNT) |
| a `user` with a non-empty `servicePrincipalName` | `kerberoastable`; each SPN as an `spn` claim |
| `msDS-AllowedToDelegateTo` | `can_delegate_to` (object = the target `spn`), constrained delegation |
| `msDS-AllowedToActOnBehalfOfOtherIdentity` (an SD) | `rbcd_from` (object = each trustee allowed to act on behalf of this object) |
| `operatingSystem` | `os` |

**The SD / ACE parser is hand-rolled** (`parse_security_descriptor`), no
heavy dependency (no impacket) — the self-relative Security Descriptor and
ACE binary layout is stable and documented (MS-DTYP): the DACL offset in the
20-byte SD header, the ACL header (revision, size, ACE count), each ACE
header (type, flags, size) and body — `ACCESS_ALLOWED` (0x00) is mask + SID;
`ACCESS_ALLOWED_OBJECT` (0x05) is mask + flags + the ObjectType /
InheritedObjectType GUIDs the flags say are present + SID. The access mask is
decoded to the interesting rights and **an ACE that grants none of them is
skipped**:

| Right | How it is recognized |
| --- | --- |
| `GenericAll` | `GENERIC_ALL` (0x10000000) or the expanded full-control bitset (0x000F01FF) |
| `GenericWrite` | `GENERIC_WRITE` (0x40000000) |
| `WriteDacl` | `WRITE_DAC` (0x00040000) |
| `WriteOwner` | `WRITE_OWNER` (0x00080000) |
| `ForceChangePassword` | control-access (0x100) on the extended-right GUID `00299570-246d-11d0-a768-00aa006e0529` |
| `AddMember` | write-property (0x20) on the `member` attribute GUID `bf9679c0-0de6-11d0-a285-00aa003049e2` |
| `AllExtendedRights` | control-access (0x100) with no ObjectType GUID |

A truncated or malformed SD / ACE ends the parse rather than raising; one
bad object is counted `invalid` and skipped, not the whole export.

### Provenance & time

Each claim carries `attrs.dn` (its source object) and `attrs.export` (the
export label), and `observed_at` is the **export timestamp** — an LDIF
`# … <ISO date>` comment, then `--as-of`, then the file mtime — so `valid_at`
and `as_of` work. Event ids are content-addressed and embed that stamp:
re-importing the same export is a no-op, and a later export records history
rather than overwriting. Two exports a month apart, or LDAP plus a later
host feed, reconcile as claims with conflicts surfaced (append-only), not
silently merged.

### The question it answers

```python
ask_scope(subjects=["user:S-1-5-21-…-1106"],           # svc-sql
          expand_predicates=["member_of", "has_ace", "trusts"],
          depth=3,
          question="what rights and trust path connects svc-sql to domain dev.local?")
```

The walk gathers the chain — e.g. `svc-sql -member_of-> Domain Admins
-has_ace(GenericAll)-> corp.local -trusts-> dev.local` — and every edge
ships **cited** (its source object's DN, observation id) and with its
**validity window**. Time and citations are the differentiators over a
static graph tool: `valid_at` answers "was this ACE / trust real as of X?",
supersession shows an ACL that was tightened between two exports, and each
step of the answer points at the directory fact it came from — auditable,
not a black-box path.

### Finding a path (D-067)

`ask_scope` hands back the *pack* the reader reassembles the chain from.
When the question is reachability itself — "what connects A to B?" — the
`path` type returns the connecting **edge sequence(s)** directly, so the
answer is explicit instead of reconstructed:

```python
find_path(from="user:S-1-5-21-…-1106",              # svc-sql
          to="domain:dev.local",
          via=["member_of", "has_ace", "trusts"], depth=3)
# POST /v1/path {"from": …, "to": …, "via": […], "depth": 3, "budget": 800}
```

It is a bounded, shortest-first BFS over the **same** gather/walk machinery
`ask_scope` uses, following `via` edges in both directions (an `affects`
edge is stored cve→product but walked product→cve), simple paths only (a
cycle never loops), capped by `depth` (≤ 3, the scope cap; a longer request
is clamped and noted), `max_paths`, the token `budget`, and the
`LOOM_MAX_SCOPE_*` caps. Each returned `PathEdge` is **cited** and carries
its `valid_from`/`valid_to`; `as_of`/`valid_at` filter every edge and a
superseded one (D-050) never appears; a path through an entity outside a
type-scoped grant is not returned. A cut — more paths than `max_paths` or
the budget allowed, the depth cap, the entity cap, a hub's gather limit — is
reported in `truncated` (never silently dropped), and `notes` carry the same
request advice a pack does (an unknown `via` predicate with close matches,
an unknown endpoint, "no path found within depth N").

It stays **honest and domain-agnostic**: it enumerates paths that EXIST in
the data along the named predicates (the KEV `host → product → cve` chain
and this AD `user → group → (ACE) → domain` chain alike) — it does **not**
rank, score, or weight edges by exploitability, and emits no such guidance.
Because `find_path` explores the gathered neighborhood, a "no path" that
comes with a `gather_limit` truncation means *no path within the newest
edges gathered at a hub*, not "none exists": a busy hub (a product with
thousands of `affects` edges, a group with thousands of members) can put a
specific far node beyond the per-entity window. `ask_scope` reaches those
via the attribute the question names (D-064 topic completion); `find_path`
does not, so widen there or read the truncation. The reachability benchmark below measures `ask_scope`; `find_path` walks the
identical edges.

### Measuring AD reachability

Whether the scope walk actually surfaces the **full cited chain** — and how
much of a realistically-sized directory it sorts through to do it — is a
benchmark of its own: [ad-eval.md](ad-eval.md). `loom.connectors.ad_gen`
generates a synthetic directory at scale, plants known 2/3/4-hop chains
(and decoys that dead-end at a non-transitive / SID-filtered trust or a
disabled account) and buries them in benign noise; `loom.ad_eval` loads it
through this connector and scores retrieval with a scripted reader (no LLM).
On a `medium` directory (4,429 objects, 31k observations) Loom recovers and
cites 100% of the planted chains while the walk pulls ~2.5% of the store's
entities. It is synthetic and object-level only, and measures retrieval, not
attack-path ranking.

## Registering the names in the schema registry

Every importer registers a non-strict schema for the namespace on
`import` (`--no-schema` skips it); `schema` prints it. The CVE predicate
names deliberately coincide across the vulns connector, the OCSF importer
and a STIX `vulnerability` (`cvss_score`, `has_severity`, `epss_score`,
`summary`, `affects`), so one CVE's record reads as one record whatever
produced it. The LDAP connector registers its own `ad` vocabulary
(`member_of`, `has_ace`, `trusts`, …) — a separate domain, typically its own
namespace. To pin a namespace to exactly these names:

```bash
python -m loom.connectors.stix schema --namespace netsec > stix.json
python -m loom.connectors.ocsf schema --namespace netsec > ocsf.json
# merge, set "strict": true, then
curl -X POST http://loom:8000/v1/schemas -H 'content-type: application/json' -H "X-Loom-Key: $KEY" -d @schema.json
```

Registration is additive by name (D-024); with `strict` the namespace
rejects unregistered predicates and entity types with a 422, which is how
a mis-mapped bundle is caught before it lands.
