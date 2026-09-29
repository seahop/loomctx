# Changelog

LoomCtx is pre-1.0: contracts are stable within a minor version and every
change to them is recorded in `docs/decisions.md` (D-numbers below).

## Unreleased

Everything below is on `main` and not yet in a tagged release (the latest
tag is v0.1.0).

### Model scorecard 2026-09-28; Active Directory audits published

- `docs/models.md` re-measured on the current engine: 35 models, five runs of
  the four core tasks (686 scored task-runs); 15 models 20/20.
- A second scorecard, five Active Directory audits (`agent_eval_ext`:
  cross-domain admins, collection coverage, nested groups, unconstrained
  delegation, trusts) on a 10,000-account forest, five runs each; 19 of 35
  models 25/25. `glm-5.3-flash` is flagged as too slow for interactive use.

### Find entities by name; coverage gaps on entity asks (D-091, D-092)

- A predicate the registry marks `label` names its subject; entity search
  (`/v1/entities/search`, MCP `find_entity`) matches label values as well
  as keys, so a directory object keyed by a SID is found by its name
  (schema v9 adds the index). LDAP, Entra, Okta and ATT&CK mark theirs.
- A single-entity ask notes the collection gaps of the sources that
  supplied the entity; coverage notes carry the record's id to cite.
- Packs render opaque keys with their names (`user:S-… (dnguyen)`) in budget the facts
  leave over, reserving up to a fifth when a pack has names to show (D-093).
  A walked-to entity's name facts ride as that annotation instead of as items,
  so the budget goes to facts (D-094).
- A scope walk ships a reached entity's status when it differs from the rest
  (the one disabled member), asked or not, and ranks its own path edges first
  among equally dense facts; entity search resolves
  `name@realm` / `REALM\name` to the bare name when the whole query matches nothing (D-095).
- A scope walk whose last hop links onward says where it stopped and what depth
  reaches further (D-096).
- Packs name an account with its domain (`user:S-… (dlee@dev.local)`): new
  `PredicateDef.display`; LDAP records `principal` (sAMAccountName@domain), Entra's
  `upn` and Okta's `login` are marked display (D-097).
- LDAP records a trust's direction, transitivity and SID filtering as facts on the
  partner domain (`trust_direction`, `trust_transitive`, `trust_sid_filtering`);
  the extended AD tasks run on the large generated forest and add groups,
  delegation and trusts audits (D-098).
- LDAP keys a domain by its DNS name (the SID is an identifier), so an export's
  domain and the same domain from other sources are one entity; packs name the
  entities they only mention; a scope walk that reaches nothing along what it
  names also follows the containment, and says so (D-099).
- A scope topic naming several predicates filters on its rare ones: the walk admits,
  and the pack ships first, the entities carrying the filter, then their display
  fields (D-100).
- A `siblings` scope walks the no-turn-back chain first and ranks it first; the
  sibling walk fills what room the entity cap leaves (D-101).
- Faster: one walk per pack (memoized across the name-room rebuild), rare topic
  carriers counted before rows load, and describe_namespace's summary warmed at MCP
  start-up (D-102).
- Agent scorecard: the exposure scorer counts an exclusion one sentence before or
  after a CVE it rules out (D-103). Scorecard re-run 2026-09-28 (docs/models.md).
- MCP `ask_scope` walks an over-deep request to the depth cap and says so.
- `loomctx.agent_eval_ext`: two extended tasks (cross-domain admin audit,
  coverage honesty), run on demand and not part of the published
  scorecard.

### Agent scorecard fixed and re-run; GKE re-validation (D-089, D-090)

- The agent harness gives models 8,000 output tokens per turn on the
  OpenAI-compatible path too (it ran OpenRouter models at 1,500, which a
  reasoning model's hidden thinking spent before answering), records why
  each reply ended, and reports a second empty reply as an error instead
  of an empty answer.
- The scorers judge what an answer claims: a CVE named to rule it out, a
  former lease holder named to reject it ("not web-01"), a first sentence
  ending in a date, and typographic hyphens no longer fail a right answer.
- `docs/models.md`: 36 models × 5 runs on GKE, 19 pass every task every
  run; 0 unseen citations in 695 task-runs.
- `iam_eval` compares edges through cross-IdP identity merges (D-090); the
  large IAM run is 0 missing / 0 extra on every predicate.
- Re-validated on GKE after the rename (`deploy/README.md`): tests, 25/25
  security checks, load, failover (15 s, 0 of 233 writes lost), identity
  and estate at scale, retrieval scorecard. An A/B of the initial load on
  identical stacks: the current build 633/s against 361/s for the
  2026-09-25 build.

### Renamed to LoomCtx (D-088)

- The project is **LoomCtx**: repo `seahop/loomctx`, Python package
  `loomctx`, images `ghcr.io/seahop/loomctx{,-gateway}`, env vars
  `LOOMCTX_*`, compose service and k8s resources `loomctx*`, metrics
  `loomctx_*`, API keys `loomctxk_…`, MCP server `loomctx`. No migration
  path: rebuild stores and clusters from scratch. Website: loomctx.dev.

### Identity-pass throughput (D-087, closes S-63)

- Schema v8 indexes the entity foreign keys' child columns
  (`observations.object_entity_id`, `aliases.entity_id`): deleting a
  merged-away entity no longer scans the table
- `GraphStore.rank_facts` ranks merge candidates in one query; the identity
  pass resolves once and tracks its own merges (22 -> 74 merges/s)
- The strong identity pass is its own enrichment job, `identities`
  (enabled by `resolve` too), draining a backlog back to back and sharded
  across worker replicas; the LLM-backed weak pass stays paced with
  adjudication; `LOOMCTX_IDENTITY_BATCH` sets the groups per pass (500)
- `shared_identifier_groups` runs as indexed steps (a single join stalled
  87 min on a loading namespace)
- GKE, 6,000-machine estate through the gateway: the workers folded 8,480
  identities during ingest, 75 left after the drain (was ~5/s, ~45 min)

### Identity across tools, host artifacts, format drift, purple correlation (D-083…D-086)

- Identity (D-083): connectors state what each tool calls a host or person
  (`identified_by identifier:<kind>:<value>` — fqdn, mac, cloud id, sid,
  upn, mail, `DOMAIN\account`; short hostname as a weak one) and the
  enrichment worker folds entities of one family that share a strong
  identifier; IPs become time-stamped `has_ip` links, never merges. nmap,
  LDAP, Entra (incl. the on-premises SID of hybrid users), Okta, OCSF,
  cloud instances, endpoint and op logs emit them
- One namespace per environment: every connector defaults to `netsec`, and
  schema registration merges a shared predicate's definitions (union of
  object types) instead of replacing them
- Host artifacts (D-084): `loomctx.connectors.endpoint` parses process lists
  and file listings — osquery (rows and results logs), tasklist,
  PowerShell Win32_Process / Get-Process / Get-ChildItem / Get-FileHash,
  `ps`, `ls -laR`, `sha256sum`, CSV — into processes (host + pid + start),
  files, shared hashes and accounts that fold into directory users
- Format drift (D-085): imports record the fields they read per object
  kind and report a field that appeared or vanished since the last import
  from the same source (`"drift"` in the import output,
  `python -m loomctx.coverage drift`)
- Purple correlation (D-086): `loomctx.connectors.oplog` (Atomic Red Team,
  Attire, CSV/JSON) records red-team actions; OCSF detections link
  `indicates technique`; `python -m loomctx.purple` and the MCP tool
  `purple_report` classify each action detected / host only / missed with
  latency and citations
- `LOOMCTX_READ_URL`: an OCSF/STIX import or a drift check through a gateway
  (ingest only) reads prior versions / shapes from the engine (S-60)
- Tested on GKE: 803 tests on SQLite and 896 on the Postgres lane, and a
  6,000-machine synthetic estate through the gateway — 5,400/5,400 machines
  and 3,000/3,000 accounts folded, 0 false merges, purple 600/600
  (deploy/README.md); identity-pass throughput followed in D-087

### Coverage: what an import collected (D-082)

- Connectors record what their export carried (`loomctx.coverage`): LDAP per
  domain (security descriptors, userAccountControl, membership when wholly
  absent), Entra and Okta per tenant/org (expanded members / owners, account
  state, MFA factors; role and app assignments for combined exports)
- Scope asks and find_path add a `coverage:` note when a predicate they walk
  was absent or partial in some import, so "no path" from a partial dump is
  not read as "no access"; find_path notes path entities whose status is
  unknown rather than leaving it to read as enabled
- A later, fuller export supersedes the gap; the AD generator now gives
  every object a security descriptor, as a real dump does

### Postgres planner statistics after bulk loads (D-081)

- A new namespace loaded into a large Postgres store was queried with stale
  planner statistics (44 s per ask vs 0.5 s after ANALYZE) until autovacuum's
  10 % threshold was crossed. Schema v7 sets bounded analyze thresholds on
  `observations`/`entities` (migrates in place); direct bulk loads call the
  new `GraphStore.refresh_statistics()` when they finish

### Hub-safe walks, longer paths, flagged disabled accounts (D-080)

- Scope walks no longer turn back along the predicate that reached an
  entity: from a user, `member_of` climbs to its groups and their parents
  instead of fanning back down to every co-member of an every-user group
  (`ScopeSpec.siblings: true` restores it). Depth-2 identity asks went from
  seconds to ~0.2 s; blind AD walks gather less than half as much (S-57)
- `find_path` searches from both ends and joins in the middle, with the
  depth cap raised 3 → 6 (default 4) and the same no-turn-back rule
  (`PathRequest.siblings`): 4-hop AD chains are found, and a path past a hub
  group is met from the target's side (S-58)
- `PathPack.node_status`: every entity on a returned path carries its
  current value of the predicates the registry marks `node_status`
  (`PredicateDef.node_status`; `enabled` for LDAP/Entra/Okta, Okta
  `status`), cited and charged — a path through a disabled account is
  returned and flagged (S-58)
- MCP `find_path` / `ask_scope` take `siblings`; `find_path` shows
  `node_status`. Contracts, OpenAPI, TS and Go SDKs regenerated/updated

### Identity connectors at scale, blind AD benchmark, faster pack selection (D-077, D-078, D-079)

- `loomctx.connectors.iam_gen` + `loomctx.iam_eval`: seeded Entra + Okta exports
  in the real APIs' shapes (up to 60,000 users, every-user hub groups) and a
  check of every implied edge, idempotent re-import, planted role paths and
  hub-walk cost; run locally and on GKE through the gateway path up to
  1.38M observations (deploy/README.md)
- Fixed what it found (D-077): Entra per-user OAuth2 consents collided on
  one event id (323 of 357 lost); role holders that are groups or service
  principals were stored as users; Okta role assignments in the
  `_links.assignee` shape were dropped; Entra and Okta clobbered each
  other's `has_role` / `member_of` registration (now one shared definition,
  `connectors/iam_schema.py`). Objects that yield no claims are counted
  `empty` in import stats
- `ad_eval --blind` (D-078, closes S-51): the walk knows only the two named
  endpoints; decoys score evidenced / not surfaced / leaked; blind numbers
  replace the withdrawn ones in docs/ad-eval.md
- Pack fact selection is lazy-greedy (D-079): same picks, O(n log n) instead
  of rounds × pool — 3.1 s → 1.2 s on an identity-hub ask
- Open: scope walks through every-user groups cost 2–8 s (S-57); find_path
  cannot return 4-hop chains and omits account status (S-58)

### Identity/IAM connectors and LDAP deep fix (D-074, D-075, D-076)

- `python -m loomctx.connectors.entra import` parses Microsoft Graph API JSON
  exports (users, groups, service principals, app registrations, directory
  roles, role/app-role/OAuth2 assignments) into cited identity/RBAC claims
  in the `iam` namespace; privileged-role tagging, credential-expiry
  tracking, scope walk + find_path tested end to end (D-075)
- `python -m loomctx.connectors.okta import` parses Okta API JSON exports
  (users, groups, apps, app-user assignments) into the same `iam` namespace;
  MFA enrollment, credential provider, admin-role grants; both IdPs share
  overlapping predicates for cross-provider entity resolution (D-076)
- LDAP connector S-50 deep fix (D-074): mapped GenericWrite (0x20028)
  detection, content-addressed event ids (no collision on long SIDs),
  inherit-only ACE filtering, bidirectional trusts emit both edges, O(1)
  SID lookup via index; connector removed from experimental status

### Detections, cloud inventory, and the ATT&CK taxonomy (D-071, D-072, D-073)

- OCSF connector also ingests detection/security/incident findings (classes
  2004/2001/2005) as a cited `finding` graph — `detected_on` a host,
  `references` a CVE (shared node), status-transition supersession with
  Suppressed != Resolved (D-071)
- `python -m loomctx.connectors.cloud import` parses a `terraform show -json` /
  `.tfstate` or an AWS Config snapshot into cited inventory claims
  (resource/vpc/subnet/security_group/cloud_account) with containment and
  reference edges; drift over snapshots is history (D-072)
- `python -m loomctx.connectors.attack import` parses the published MITRE ATT&CK
  STIX bundle into a cited `attack` taxonomy (technique/tactic/group/
  software/mitigation; `in_tactic`/`uses`/`mitigates`), catalog-level only —
  no procedure detail (D-073)

### OSV / GHSA advisories + cross-vendor product resolution (D-069, D-070)

- `python -m loomctx.connectors.osv import` parses OSV-schema advisories
  (GHSA/PyPI/Go/npm) and fuses them to the shared `cve:` node by CVE alias,
  so an OSV CVSS shows as a corroboration/conflict next to NVD's; affected
  packages become `package:<ecosystem>:<name>` (not forced onto CPE)
- Entity resolution now proposes cross-vendor same-product aliases
  (nmap's `igor_sysoev:nginx` <-> NVD's `nginx:nginx` / `f5:nginx_open_source`)
  for adjudication, so a scanned host reaches its KEV CVEs even when sources
  disagree on the vendor; catch-all tokens (`multiple_products`, `multiple_*`)
  are excluded

### Scan inventory: nmap connector (D-068)

- `python -m loomctx.connectors.nmap import report.xml` parses an nmap `-oX`
  report (a file; no scanning) into `host` / `listens_on_port` /
  `runs_service` / `runs_software` / `runs_os` claims. `runs_software`
  keys products through the shared CPE parser, so a scanned host fuses
  with the NVD/KEV `product ← affects ← cve` graph and reaches its
  exploited-in-the-wild CVEs via `find_path`. Inventory only; genuine
  nmap fixtures; blind fusion test

### A `path` answer type (D-067)

- `POST /v1/path`, MCP `find_path`, SDK `path()` return cited, time-scoped reachability edge sequences between two entities along named predicates — the connecting chain directly, instead of an agent reassembling a scope pack. Contract `PathRequest`/`PathPack`/`PathEdge` (additive); a bounded shortest-first BFS reusing the scope walk, honest about hub limits via `truncated`

### AD reachability capability benchmark (D-066) — experimental; numbers withdrawn

- `python -m loomctx.connectors.ad_gen` — a deterministic synthetic directory
  generator (LDIF the connector parses; planted 2/3/4-hop reachability
  chains + decoy dead-ends under dense noise) — and `python -m loomctx.ad_eval`,
  a scripted path-recall / decoy-exclusion / entities-gathered scorer.
  `docs/ad-eval.md`. Medium run: 100% recall and decoy-exclusion, ~2.5% of
  the store walked per chain

### Raw LDAP / Active Directory connector (D-065) — experimental

- `python -m loomctx.connectors.ldap import export.ldif --namespace ad`:
  decodes an LDIF directory export into cited, time-stamped claims —
  `member_of`, `trusts`, `has_ace` (from a hand-rolled Security
  Descriptor / ACE parser), delegation edges and userAccountControl / SPN
  attributes — keyed by objectSid, for object-level reachability questions
  over `ask_scope`. Decodes facts only; no path computation or ranking.
  Sessions and local admin are out of scope (not in the directory)

### Agent ergonomics for scope asks (D-064)

- `ask_scope` defaults to budget 3,000 (cap 4,000), measured on the
  compact wire; an attribute in `expand_predicates` or a question in the
  registry's words selects the scope topic; `ContextPack.notes`
  (additive) reports unknown predicates with close matches, a scope a hop
  short, unknown subjects; `describe_namespace` lists each type's links
  and attributes; list arguments sent as JSON text are accepted

### GKE re-validation with auth on and real data (D-063)

`docs/hardening.md` S-35…S-45; `deploy/README.md` has the run.

- The nightly vulns refresh works with its documented, source-pinned key:
  connectors register only what the registry lacks; source grants take
  `:*` families (engine and gateway) — the key is
  `nvd,nvd:*,cisa-kev,first-epss,cisa-adp`; every loader (`loomctx.ingest`,
  `vulns`, `stix`, `ocsf`, `ldap`) prints its totals and exits non-zero on
  any refused envelope, direct or via the engine, and the EPSS ledger
  advances only after a load that landed whole
- Enrichment worker pools: `loomctx.enrich run --jobs` / `LOOMCTX_ENRICH_JOBS`
  (`vectors`, `llm`, named jobs); a vector backlog drains without the
  interval sleep — during a drain only the vector jobs run, while
  extraction, resolution, adjudication, aliases and dossiers keep the
  interval's pacing; a failing job backs off (one interval, doubling,
  10-minute cap)
- Keys mount at `/etc/loomctx-keys` in every shipped manifest (the old path
  hid the gateway's schema); keys are stripped of a `--from-file` newline
  (loaders and the Python, TypeScript and Go SDKs);
  `loomctx.loadgen --key`
- `retrieval_eval` redacts the store DSN's password; the MCP server closes
  its store on exit
- Teardown recipe deletes volumes before the cluster

### The 2026-09-24 review batch (D-057…D-062)

Full list with statuses: `docs/hardening.md` §S.

#### Evaluation validity (D-057)
- Baselines fill the same token budget as the pack (`vector@B`,
  `recency@B`); `full` gathers everything; questions record whether their
  truth is inside LoomCtx's gather
- Rows never answered (over `--full-cap`, past `--max-cost`, provider
  errors, empty or truncated replies) are excluded from denominators and
  shown per condition; a tripped cost cap marks the table INCOMPLETE and
  exits 3; rows stream to JSONL
- Stricter grading: conflicts need every value, numbers within half a unit
  of the recorded precision, whole-token entity matches, real citations
- agent_eval: exposure needs recall ≥ 50 % with precision 1 and the
  software named; every factual task needs a seen citation; provider
  outages are retried, then "not run" — never the model's failure
- Temperature 0 on live calls; seeded, whole-population question sampling

#### Read path (D-058)
- Scalar conflicts compare each source's newest value only
- Briefs: type-gate aware, withheld for `as_of` / `valid_at`, ≤ 25 % of
  the budget; `ContextPack.withheld_briefs` (additive)
- Merged-away names resolve to their canonical entity
- Scope walks capped (`LOOMCTX_MAX_SCOPE_ENTITIES`, `LOOMCTX_MAX_SCOPE_OBSERVATIONS`)
  and reported (`ScopeTruncation.reason`, additive); superseded edges skipped
- MCP wire within ~2 % of the charged budget (was up to 3.6×): compact
  JSON, string citations, `charged_tokens` in the agent view
- Excerpt KNN filters inside the index; SQLite `merge_candidates` no
  longer scans entities quadratically

#### Multihop over hubs (D-061)
- A scope question's topic (the predicates it names) completes a hub the
  gather limit cut: `GraphStore.edges_to_carriers` (additive) admits the
  far-end entities that carry the topic whatever their age — the KEV
  exposure question goes from 0/6 to 6/6 in one ask
- Sibling topic facts render grouped (four per item, each fact and edge
  cited); a reached entity's off-topic conflict becomes a handle
- `observations_for_many(predicates=)` (additive); `observations_by_ids`
  uses the primary key on SQLite

#### Small budgets (D-062)
- The attribute a question names ships first: it orders equal-standing
  conflicts, is picked before briefs and excerpts, and is exempt from the
  diversity term
- Handle ids are plain text (`ns~type~key~predicate…`, percent-escaped):
  ~55–65 tokens instead of ~128; old handles still decode, signing
  unchanged. Seed demo: web-01 `charged_tokens` 380 → 351

#### Security (D-059)
- Host / Origin allowlist and JSON-only `/v1` bodies on the engine, MCP
  http and gateway (`LOOMCTX_ALLOWED_HOSTS`, `LOOMCTX_ALLOWED_ORIGINS`); MCP
  binds 127.0.0.1 by default
- Type-gated keys cite only documents they uploaded or ones already in
  their world — HTTP, batch and the NATS writer; extraction stays inside
  the uploader's entity types
- Rate limits on MCP tools including the LLM bucket; a batch of n costs n
  on both engine and gateway; gateway rate dials parse as floats
- Auth before body parsing; scoped schema and counts for type-scoped keys

#### Enrichment and connectors (D-060)
- Unmerges stick; `python -m loomctx.enrich distinct`; adjudication calls all
  count against the cap, unreadable verdicts back off and give up
- EPSS emits changes only; OCSF / STIX imports chain versions via
  `supersedes`; Suppressed is not Resolved
- Consumer settles per message and redelivers claims awaiting their
  document; `loomctx.ingest` retries 429 / 5xx with `Retry-After`
- Fuzzy (tier-2) candidates skip settled groups; `python -m loomctx.enrich
  undistinct` / `GraphStore.forget_decline` take a decline back
- KEV ransomware / due-date / required-action changes are recorded as
  superseding versions (the refresh key needs `rw`); STIX and OCSF export
  express version chains (`--history` for every version); export → import
  is a replay

#### Measured (2026-09-24, real corpus, D-057 scoring)
- Retrieval, live: LoomCtx 81 / 84 / 86 / 96 % vs token-matched vector
  75 / 77 / 79 / 87 % at 400 / 800 / 1,600 / 3,200 tokens; the multi-hop
  KEV question only LoomCtx answers (15/18) — `docs/evaluation.md`
- Agents: eighteen models × three runs; `mistral-large` and
  `claude-sonnet-4.5` pass all twelve tasks — `docs/models.md`

#### Release
- Every engine-image compose service builds (a fresh clone's
  `docker compose run --rm test` works); Go SDK CI can fail; `go.sum` and
  the TS `package-lock.json` committed; CI lint runs pyflakes; pinned
  govulncheck / openapi-generator; CI concurrency group

### Design follow-ups to the 2026-09-23 review (D-050…D-056)

#### Read path (D-050, D-051)
- Recorded supersession: `ClaimIn.supersedes` / `Observation.supersedes`
  (additive) name the earlier observation a claim corrects — recorded,
  never inferred. A visibly superseded row leaves conflict detection, ranks
  ×0.5 and renders `[superseded by <cite>]`; for an `as_of` before the
  correction it is current again. Every ingest door validates the target
  (same namespace, same subject, visible)
- `GET /v1/observations/{id}/prov` exports one observation's provenance as
  PROV-O JSON-LD, gated like the raw observations route
- Honest budget: the budget charges the compact rendering an agent receives
  (text plus citations plus handle hints); `est_tokens` recalibrated to
  `len/3 + 4`; `ContextPack.charged_tokens` (additive); handles capped at
  15 % of the budget. Documented pack numbers moved accordingly
- Hybrid ranking: BM25 over the gathered candidates (predicate names split
  into words) fused with cosine by reciprocal rank fusion; value-per-token
  packing with a diversity penalty; entity-valued conflicts with normalized
  values and overlapping validity windows; a `more` handle pages past the
  gather cap

#### Store (D-054, schema v6)
- Schema v6: `observations.supersedes`, five indexes, `norm_key` recompute
  for colon-separated hex keys (IPv6, MAC, host:port); an older image warns
  and skips DDL
- Worker ticks are incremental (per-model/shard high-water marks with a
  periodic full rescan); the multi-entity gather pre-limits per entity
  (20k-edge hub: SQLite 101 → 21 ms, Postgres 170 → 13 ms)
- SQLite reads use a pool of WAL readers (`LOOMCTX_DB_READERS`, default 4);
  `iter_entities(since=)` makes the alias pass incremental

#### Evaluation (D-053)
- `python -m loomctx.retrieval_eval`: packs at graded budgets against `full`,
  vector top-k and recency top-k on store-derived questions, rule-scored,
  no LLM judge; see `docs/evaluation.md`

#### MCP, enrichment, connectors (D-055, D-056)
- MCP 2026-07-28 alignment: `outputSchema` + `structuredContent` on every
  tool, read-only/idempotent annotations, `format: concise|detailed`,
  `record_claim` takes `supersedes` and derives a content-addressed
  `event_id`
- CISA ADP lands as the third CVSS scorer (`cisa-adp`); SSVC decision points
  become `ssvc_*` claims when present
- Extraction retries only the windows that failed; a partial is `done` at
  the attempt bound; `agent_eval` uses adaptive thinking on Anthropic models
- STIX 2.1 and OCSF interop as connectors (`loomctx.connectors.stix`,
  `loomctx.connectors.ocsf`), import and export, with per-item LoomCtx citations;
  the engine core learns nothing about either (`docs/interop.md`,
  `examples/stix_import.py`)
- Seed: 592 claims, including a same-source `contract_owner` correction
  that supersedes its predecessor

#### Security and operations (D-052, D-056)
- Engine-side rate limiting (`RateLimitMiddleware`): one token bucket per
  grant, a stricter bucket for the LLM/embedder routes, 429 +
  `Retry-After`; dials `LOOMCTX_RATE_*` and per-key fields in the keys file;
  unset = unlimited
- Runtime image ships without a package manager (the first gated publish
  failed Trivy on pip's vendored `msgpack` and the base `setuptools`)
- GKE re-validation of the D-048 posture (NetworkPolicy enforcement, PDB
  drains, failover with zero failed writes) and an in-place v5 → v6
  migration on a populated HA Postgres (`deploy/README.md`)

### The 2026-09-23 review batch (D-046…D-049)

Six parallel review passes found ~60 verified issues; all landed except the
design follow-ups listed in `docs/hardening.md` §R.

#### Read path (D-046)
- `as_of` is the observation-time axis, applied in the store query (busy
  entities no longer yield empty time-travel packs; `truncated` counts as of T)
- Ingest rejects `observed_at` more than 24 h in the future; recency clamps to now
- Data gates apply to scope hops; extracted edges do not steer expansion
  unless `ScopeSpec.follow_extracted` (additive contract field); `subjects` ≤ 500
- Raw observations route gated and time-filtered like a pack
- Conflict handles expand at exactly `est_tokens`; forged handle fields are 400s
- Chunked-upload body cap, `nosniff`/`no-store`, ungated key required for
  `POST /v1/schemas`, answer prompt delimits items as data

#### Store (D-049)
- Reversible merges: `merge_log` + `unmerge` (schema v5); claims for a
  merged-away ref land on the canonical entity
- Blob-offload wrapper delegates the batch paths; shards no longer inherit
  `LOOMCTX_DB_READ`; CLIs open the env-configured store
- Export carries schema registrations and adjudication declines; vector index
  per model; purge cleans ANN rows; pgvector minority-namespace fallback;
  `norm_key` keeps IP/version separators

#### Enrichment, LLM, MCP (D-047)
- Anthropic client works with thinking-enabled models; no redirects with the
  key; Retry-After to 60 s with jitter; usage logged per job
- Extraction per window with lease renewal; random document delimiter;
  sanitized `doc:` labels; registry validation on every extracted claim
- Resolution: registered-vs-registered key collisions adjudicated, numeric
  keys never spelling-merged
- MCP: scoped keys see only their namespaces; `ToolError` everywhere; compact
  citations with `cite` tokens accepted by `expand`/`get_observations`
- Eval: store-derived lease truth, non-KEV CVEs penalized; connector
  validates downloads before caching

#### Supply chain, CI, deployment (D-048)
- `requirements.lock` consumed by the Dockerfile; every base image pinned by
  digest; Dependabot; SHA-pinned actions; `govulncheck`; Trivy gate; SBOM +
  provenance; build once, promote the tested image
- Registry validation on the NATS and Kafka paths; sanitized dead-letter
  headers; bounded dead-letter stream; Kafka SASL/TLS
- k8s: securityContext, NetworkPolicies, PDBs, bounded JetStream, no SA token
- Compose binds to 127.0.0.1 by default; documented env vars now pass through

#### Docs and demo
- Demo script made honest (night-before prep, pinned judge, frozen volume,
  rendered fallback transcripts); numbers reconciled; README gains
  "How it differs" and "Limitations"; talk date is mid-October

## v0.1.0 — 2026-09-09

First tagged release: the conference build.

### Core
- Append-only, cited observations about entities; claims and documents;
  two time axes (`as_of` knowledge time, `valid_at` fact time) (D-001…D-012, D-024)
- Context packs: token-budgeted, question-ranked, conflicts first,
  expansion handles, document excerpts, relation chains for multi-hop
  scopes, handle cap with `omitted_handles`, partial-coverage reporting
  via `truncated` (D-018, D-020, D-035, D-038)
- Per-namespace schema registry; the core stays domain-agnostic (D-024)
- Stores: SQLite (WAL, sqlite-vec) and Postgres (pgvector), behaviorally
  identical under one contract test suite; namespace sharding; artifact
  offload to filesystem or S3 (D-011, D-025, D-032, D-033)
- Async enrichment: embeddings, claim extraction with span provenance,
  dossiers, two-tier entity resolution, leased worker fleet (D-018, D-019, D-023, D-031)
- API keys with data scoping, signed handles, retention and redaction (D-013, D-013a, D-016, D-021)

### Surfaces
- HTTP API with `/v1/ingest/batch`; JSON Schema and OpenAPI, drift-checked in CI (D-034)
- MCP server for agents: find, ask, ask_scope, expand, record_claim,
  answer, plus `list_namespaces` / `describe_namespace`, an agent-shaped
  pack view, and coverage warnings (D-026, D-036, D-038)
- SDKs: Python, TypeScript (generated types), Go (schema-validated) (D-026, D-034)
- Pipeline adapters: Fluent Bit, Vector, Kafka/Redpanda consumer, bulk loader (D-034)

### Scale (all opt-in)
- Go ingest gateway, NATS JetStream buffer with dead-letter, writer
  consumers, Postgres pool/read replicas, CloudNativePG HA overlay,
  load generator and capacity table (D-010, D-027…D-030)

### Real data and evaluation
- Vulnerability-intelligence connector: CISA KEV + NVD + EPSS, streamed,
  idempotent, history-preserving, nightly CronJob (D-035)
- Agent end-to-end harness over the real MCP transport with store-derived
  ground truth and a citation-faithfulness check; eighteen-model scorecard
  with billed cost (D-036, D-037)

### Validation
- Validated on GKE: capacity on real nodes, 18 h soak, HA failover at 11 s
  end to end (D-043); worker quality fixes from the soak (D-044)
- Release gate: the scale shape (lb → gateways → JetStream → consumer →
  store) smoke-tested in CI on every push; store migrations proven on a
  populated database; the published image re-validated on GKE before the
  tag moves (D-045)

### Measured on this release (laptop, generator co-located)
- 511k envelopes loaded in 81 s to SQLite; single-entity ask 2–5 ms at
  465k observations; two-hop scope over 1,077 entities in 0.5 s
- Eighteen models, three runs each: nine pass all four agent tasks three
  times out of three (12/12); citation faithfulness 216/216 task-runs
  (`docs/models.md`)
