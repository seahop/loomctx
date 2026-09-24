# Interop: STIX 2.1 and OCSF

Loom's own shapes are the contracts in `src/loom/contracts.py`; the world
speaks STIX (threat intelligence) and OCSF (security events). Two
connectors translate both ways, so a TIP's bundle or a scanner's findings
land as cited, time-windowed claims, and Loom's facts leave as records
other tools accept. The engine learns nothing about either standard: the
mapping is a connector plus a schema registration (hard constraint: domain
specifics stay in the registry).

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

## Registering the names in the schema registry

Both importers register a non-strict schema for the namespace on
`import` (`--no-schema` skips it); `schema` prints it. The predicate
names deliberately coincide across the vulns connector, the OCSF importer
and a STIX `vulnerability` (`cvss_score`, `has_severity`, `epss_score`,
`summary`, `affects`), so one CVE's record reads as one record whatever
produced it. To pin a namespace to exactly these names:

```bash
python -m loom.connectors.stix schema --namespace netsec > stix.json
python -m loom.connectors.ocsf schema --namespace netsec > ocsf.json
# merge, set "strict": true, then
curl -X POST http://loom:8000/v1/schemas -H 'content-type: application/json' -H "X-Loom-Key: $KEY" -d @schema.json
```

Registration is additive by name (D-024); with `strict` the namespace
rejects unregistered predicates and entity types with a 422, which is how
a mis-mapped bundle is caught before it lands.
