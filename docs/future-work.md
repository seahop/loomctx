# Future work: scale and the known weaknesses

Written 2026-09-29, after the AD audit scorecard (`docs/models.md`) and a
discussion of how LoomCtx compares with other graph-based retrieval. These
are **post-talk** items (the talk is 2026-10-21; keep `main` stable until
then). Each item states the problem, the evidence, a design that fits the
architecture, the files to touch, and how to know it worked. Take them in
order: item 0 decides whether items 1 and 2 are urgent.

House rules still apply to all of it (`CLAUDE.md`):
- Docker only; run test suites on GKE (`secrets/gke/run-tests.sh TAG`, local
  and gitignored).
- No SQL outside `src/loomctx/store/`; new storage goes behind `GraphStore`
  (`store/base.py`), implemented for **both** SQLite and Postgres.
- A contract change gets a `docs/decisions.md` entry and regenerated
  `contracts/` (`python -m loomctx.schemas`; `… schemas openapi`); CI
  drift-checks them. Regenerate the TS SDK types too.
- Every derived fact carries citations. Domain specifics go in the schema
  registry, never in core code.
- `ad_eval` must stay 11/11. Re-run the AD audits
  (`agent_eval_ext`, 5 tasks) and the retrieval scorecard
  (`retrieval_eval`) after any read-path change, and read every changed
  verdict by hand.

---

## 0. Measure first: a 500k-object directory

**Why.** Nothing above ~13.5k directory objects has been measured for query
latency. Two measured points (`docs/ad-eval.md`, 31k → 98k observations)
show scope-walk p50 growing ~2.2× for 3.1× the data, while find_path barely
moves and the entities a walk gathers stay flat (~920 → ~979). Extrapolating
37× gives scope walks of roughly 10–20 s p50 and 30–60 s p95. That is an
estimate, not a measurement.

**Do.**
- Add an `xl` preset to `SCALES` in `src/loomctx/connectors/ad_gen.py`, e.g.
  370k users, 55k groups, 75k computers (≈500k objects, ≈5M observations).
  Keep the planted objects' RIDs clear of the generated range (they sit at
  95000+ today; move them above the new range).
- Also generate **realistic answer sizes**. A second preset should plant
  ~200 effective Domain Admins and ~100 unconstrained-delegation hosts, so
  the list-sized-answer problem (item 2) shows up.
- Run `ad_eval` (blind, with latency p50/p95) and the five AD audits with one
  or two fast models (`gemini-2.5-flash`, `gpt-6-luna`) as GKE Jobs. Load
  directly into the store, not through HTTP: 1.59M identity observations
  took ~4,900 s through the gateway.
- Record the results in `docs/ad-eval.md` next to the medium and large rows.

**Decides.** If walk p95 is above ~10 s, do item 1. If the audits fail on
the step cap or on truncated sets, do item 2.

---

## 1. Precompute transitive membership (walk cost at scale)

**Problem.** "Effective members of Domain Admins" is answered by walking
`member_of` at read time (`resolve_scope_paths` → `_walk_scope` in
`src/loomctx/context.py`). Cost grows with the neighbourhood, and hubs (a
Domain Users with hundreds of thousands of members) are skipped by design
(`_hub_carriers`, `_HUB_EDGE_LIMIT`), so an answer that runs through one
comes back partial.

**Design.**
- Registry: add `transitive: bool` to `PredicateDef` (`contracts.py`, next to
  `containment` / `label` / `display`). LDAP, Entra and Okta mark
  `member_of`. This is a contract change, so it needs a decisions entry. Keep
  it domain-agnostic: the engine closes any predicate marked transitive.
- Storage: a derived table, **not** observations (observations are
  source-attested and append-only; a closure is computed). Model it on
  dossiers (`put_dossier`, `get_dossier` and `dossier_candidates` in
  `store/base.py`, `refresh_dossiers` in `enrich.py`). Each row holds
  namespace, subject, predicate, the reached object, hop count, the
  observation ids along the chain (its citations), and the chain's validity
  window (the intersection of the edges' `valid_from` / `valid_to`). This
  needs a schema version bump (currently 9, in both `sqlite.py` and
  `postgres.py`) and an index on (namespace, predicate, object) for
  "who reaches X".
- Maintenance: a new enrichment job in `tick()` (`enrich.py`, selected via
  `parse_jobs`). It recomputes closures for subjects whose transitive edges
  changed since a watermark (`recorded_at`), the same way dossiers find
  their candidates. Supersession and redaction of an edge must invalidate
  every closure row that cites it.
- Read path: when a scope asks for a transitive predicate and the request
  is *current* (`valid_at` and `as_of` unset), answer from the closure table
  with one indexed lookup, citing the chain's observations. Time-travel
  requests fall back to the walk. That keeps v1 correct without making the
  closure fully bitemporal.
- MCP and HTTP need no new tool: `ask_scope` and `find_path` use it
  transparently. The pack's items should still show the path
  ("dkim → CORP-Tier0-Admins → Domain Admins"), cited.

**Done when.** At the `xl` preset, "effective members of group X" is under
1 s at p95. `ad_eval` stays 11/11, the AD audits hold, and a membership
removal (superseding observation) drops the derived row on the next tick.
Add tests in `tests/test_store.py` (both lanes) and `tests/test_scope.py`.

**Risks.** Closure size (users × groups reached) can be large. Cap it per
subject and record the cap in the pack's `truncated`, the same way
`_record_scope_cap` does. Cycles in nesting are legal in AD, so compute
closures with a visited set.

---

## 2. List mode for large answer sets

**Status (2026-10-13): built, D-107** (`POST /v1/list`, MCP `list_entities`).
It is a separate read, not a pack item; paging is by offset over a key-sorted
set rather than a signed handle, and filters read current values set-wise
(index seeds, one-side edge reads, predicate range scans). The "done when"
measurement rides the next 10k/500k run.

**Problem.** Packs render facts as sentences, which is costly for "list all
X". In the AD audits most delegation failures were the 20-step cap: models
walking OUs one call at a time. With 200 correct answers, prose packs cannot
carry the set inside a budget.

**Design.**
- A compact paged listing. Either a new pack item kind (`ContextItem.kind`
  is a `Literal` in `contracts.py`) or, cleaner, a new read: MCP tool
  `list_members` / HTTP `POST /v1/list`. Given a scope (subjects plus a
  predicate, or a registered attribute filter such as
  `unconstrained_delegation = true`), it returns:
  `{total, rows: [{ref, name, citation}], next: handle}`.
  - Each row costs a few tokens: the display name (`display_predicates`)
    plus one citation id.
  - The budget still applies, and `total` is always exact, so the agent
    knows how much it has not seen.
  - Pages continue through a signed handle (`encode_handle`), like `expand`.
- Carriers of a rare attribute are already counted before they are loaded
  (`_rare_carriers`, `edges_to_carriers`), so the count is cheap.
- Contract change: decisions entry, regenerated contracts, a `TOOL_META`
  entry in `mcp_server.py` (read-only, idempotent), and a line in the MCP
  instructions telling agents to list, not walk, when they need a set.

**Done when.** The `xl` many-admins audit passes with a fast model inside
the 20-step cap, and the default-size AD audits don't regress.

---

## 3. Named queries in the schema registry (weaker models ask poorly)

**Status (2026-10-13): built, D-108** (`run_query`, `POST /v1/query`; the
LDAP connector registers seven). Queries compile to list mode only, so far.
The "done when" measurement rides the next run, reported with and without
them (`LOOMCTX_MCP_QUERIES=0`).

**Problem.** Scorecard spread is partly phrasing: D-064's phrasing fix took
the exposure task from 9 to 30 passes across the eighteen models tested.
Models that hit the step cap mostly didn't know which one call answers the
question.

**Design.**
- Let a `SchemaRegistration` declare named queries. For example,
  `effective_members(group)` = scope over `member_of`, transitive, reverse;
  `hosts_with(attribute, value)` = list mode over carriers.
  - This is configuration, not core code, so it obeys "domain specifics go
    in the registry".
  - `describe_namespace` lists them, with a one-line description each.
- The MCP server exposes one generic tool, `run_query(name, args)`, rather
  than a tool per query. That keeps the tool list stable across namespaces.
- Queries compile to the existing requests (`ask_scope`, find_path, list
  mode). No new retrieval logic.

**Done when.** A model that currently fails an AD audit on the step cap
(`gemini-3.5-flash`, `gemini-3.8-flash` on delegation) passes it with the
named query available.

This is the lightest item. It could land before the talk if a demo moment
is wanted, but it isn't needed.

---

## 4. Schema-drafting helper (a new source needs connector work)

**Status (2026-10-13): done, D-106.** `python -m loomctx.registry draft`
(`loomctx/schema_draft.py`) drafts from envelope NDJSON, JSON records or
LDIF. It has no LLM step. The overlap with the hand-written registrations
is measured in D-106.

**Problem.** Each new domain needs registered entity types and predicates.
That is what makes packs precise, but it costs a day of connector work.

**Design.**
- A CLI, `python -m loomctx.registry draft SAMPLE`, that reads a sample
  export (JSON, NDJSON or LDIF) and proposes a `SchemaRegistration`:
  - entity types from record kinds;
  - predicates from fields;
  - `object_types` where a field references another record;
  - `label` / `display` candidates from name-like fields.
- An LLM may help name things, but its output is a **draft file for human
  review**, never auto-registered.
- Point people at OCSF and STIX first: anything that already emits those
  loads through `connectors/ocsf.py` and `connectors/stix.py` without new
  work.

**Done when.** Drafting against the Entra and Okta generator output
(`connectors/iam_gen.py`) reproduces most of the hand-written registration
in `connectors/iam_schema.py`.

---

## 5. Entity resolution review queue (managed, never solved)

**Problem.** Deciding that `web-01`, `WEB-01.corp.local` and an IP are one
host is the stage where graph systems quietly fail. LoomCtx resolves by
natural key → alias → embedding → LLM adjudication (`resolve_entities`,
`resolve_identities`, `adjudicate_entities` and `adjudicate_aliases` in
`enrich.py`). Merges are recorded and reversible (`merge_entities` /
`unmerge` / `mark_distinct` in `store/base.py`).

**Improve.**
- Prefer hard identifiers first, everywhere: SIDs, objectGUIDs, cloud
  resource ids. `identity.py` does this for identities; extend the pattern
  to hosts (MAC, cloud instance id, cert fingerprint).
- A review queue: adjudications below a confidence threshold are held as
  *proposed* merges instead of applied, surfaced through an admin endpoint
  (`docs/administration.md`), and approved or declined by a person.
  Declines already exist (`_decline` / `remember_decline`).

**Done when.** A seeded set of near-duplicate hosts produces proposals, not
silent merges, below the threshold. Existing merge metrics
(`docs/evaluation.md`, alias merges) don't regress.

---

## 6. Theme summaries over documents (optional; off the core job)

**Problem.** "What are the recurring themes across our incident reports?"
is GraphRAG's home turf. LoomCtx answers about entities, not themes.

**Design.**
- An optional enrichment job clusters the document chunks LoomCtx already
  embeds (`nearest_chunks`, `doc_chunks_for_artifacts`).
- An LLM writes a short summary per cluster.
- Each summary is stored as a derived, cited artifact whose citations are
  the chunks.
- Serve it through `find_related` or a scope over a `theme` entity type.
- LLM cost is paid at enrichment, never at read time.

**Only if users ask.** It is useful, but it isn't what LoomCtx is for.

---

## 7. A harder benchmark tier (tougher questions)

**Problem.** The AD audits ask one thing each: a group's members, the
delegation hosts, the trusts. Nineteen models pass all five; the scorecard
no longer separates the strong ones, and real audits combine conditions
across sources.

**Design.** A second tier in `agent_eval_ext`, same forests and scorers'
style (truth from the generator, hand-read failures before publishing):
- **Multi-condition sets**: enabled members of a privileged group (nested)
  that are also Kerberoastable; delegation hosts whose owner group has a
  disabled-account member.
- **Cross-source joins**: an identity's AD groups against its Entra/Okta
  roles (D-099 resolution), or a vulnerable host (OSV/nmap) reachable by an
  account with an ACE path to it.
- **Time**: who was a Domain Admin on a past date (`as_of`), and who was
  removed since.
- **Negatives and coverage**: a question whose honest answer is "not
  collected" for one domain and a list for another.
Each task reports pass, steps, tokens and time, and runs with and without
named queries.

**Done when.** The tier separates the current 25/25 models, and the plain
tier's results are unchanged.

---

## Suggested order

1. Item 0 (measure).
2. Then items 1 and 2 if the numbers call for them; together they address
   everything the 500k-object discussion raised.
3. Item 3 whenever a model-facing improvement is wanted.
4. Items 4 and 5 when a new data source or a merge problem makes them
   concrete.
5. Item 6 only on demand.
