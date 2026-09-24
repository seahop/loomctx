# Hardening roadmap (reviews of 2026-09-08, 2026-09-23 and 2026-09-24)

Findings from a full-codebase review after phase 4 / D-020. Every item here
was verified against the code at commit `a2aa1a5`; nothing speculative.
Status legend: ✅ fixed · 🔨 in progress · ⬜ open · ➖ won't fix (with reason).

Keep this file current: flip markers as items land, and reference the
commit. **Progress 2026-09-08:** everything here has landed (D-021…D-024) except
H-F7, marked ➖ won't-fix with its reason. The roadmap's
deferred phase-1 registry and phase-4 resolution/excerpt items went in
alongside (commits 58300fa…HEAD). Items are grouped by area and ordered by severity within each group.
The "P" column is the pre-conference priority: **P1** must land before the
demo, **P2** should, **P3** after.

## A. Auth & data-scoping gates

| ID | P | Status | Item |
| --- | --- | --- | --- |
| H-A1 | P1 | ✅ | `/v1/expand` never checks the `entity_types` grant. Handles are unsigned base64 JSON (`context.py encode_handle`), so a type-scoped reader can mint a handle for any subject and read its observations. Fix: gate the decoded subject's type, and sign handles (HMAC with `LOOM_HANDLE_SECRET`; unsigned unless it is set — the engine warns at startup, and `.env.example` / `deploy/README.md` say to set it). |
| H-A2 | P1 | ✅ | Scope expansion and object-side entities ignore `entity_types`. `resolve_scope` BFSes to any type; facts whose *object* is an out-of-scope entity are returned. Fix: pass the grant's allowed types into `build_pack`/`expand_pack` and filter resolved subjects + observations there (scoped world, not an error — D-013a). |
| H-A3 | P1 | ✅ | `expand_pack` skips the `LOOM_MAX_BUDGET` clamp that `build_pack` applies. |
| H-A4 | P2 | ✅ | Go gateway rate-limits on the raw key string *before* authenticating (`server.go` `limiters.allow` precedes `grantFor`). Rotating a random header yields a fresh bucket each time and grows the bucket map without bound. Fix: authenticate first when auth is on, key buckets on the grant id, cap/evict the map. |
| H-A5 | P2 | ✅ | Naive-datetime `expires` in the keys file raises `TypeError` in Python (`auth.py` compares to aware now) → 500 on every request with that key; Go rejects the whole file. Fix: treat naive as UTC in both; validate `perms` in the file path. |
| H-A6 | P2 | ✅ | `/v1/artifacts/{id}` has no data gate beyond namespace: a type-scoped reader gets full document text. Fix: gate on whether any observation the key may see cites the artifact, or require an unrestricted grant. |
| H-A7 | P2 | ✅ | Consumer logs pydantic `errors()` which include `input` (claim values / document text). Use `include_input=False`. |
| H-A8 | P2 | ✅ | Provider error bodies and base URLs leak into 502 details (`llm.py` → `http.py`). Log the detail, return a generic message. |
| H-A9 | P3 | ✅ | MCP has no auth or scoping; `streamable-http` profile binds 0.0.0.0 with full rw over all namespaces. Documented open item (D-013) — at minimum honor `LOOM_API_KEYS`/`LOOM_AUTH_FILE` with a per-connection key, or document that the profile must sit behind cluster policy in bold. *Done: the http transports require the API key on every request and apply the key's data gates per tool call (D-024); compose binds the profile to 127.0.0.1 (`LOOM_BIND`) and passes the keys env through.* |
| H-A10 | P3 | ✅ | NATS shape has a single enforcement point (gateway); consumer applies no grants. Acceptable while the queue is cluster-internal; document it, and carry the grant id on the message for audit. |
| H-A11 | P3 | ✅ | `decode_handle` on a base64 JSON *list* raises `AttributeError` → 500 pre-auth. Catch it. |
| H-A12 | P3 | ✅ | Broken keys file → re-parse + `log.error` on every request (mtime never advances on failure) in both engines. |
| H-A13 | P3 | ✅ | Go vs Python keys-file tolerance differs (Go fails whole file on bad hex/expires; Python `KeyError`s on missing id/namespaces/perms). Align: skip + log the bad entry in both. |
| H-A14 | P3 | ✅ | No body-size limit on the default (no-gateway) shape; `DocumentIn.text` unbounded. Add a contract max (e.g. 2 MB) and a request-size guard. |

## B. Store correctness (both backends)

| ID | P | Status | Item |
| --- | --- | --- | --- |
| H-B1 | P1 | ✅ | **No rollback anywhere.** Postgres: a failed statement leaves the shared connection in aborted-transaction state; every later call fails until restart. SQLite: a failed `record_claims` leaves partial inserts that the next unrelated commit persists. Fix: a transaction context in each store that rolls back on exception. |
| H-B2 | P1 | ✅ | `event_id` dedupe is check-then-insert (`_record_claim`, `store_artifact`). Two writers (engine + consumer) hit the unique index → `IntegrityError` (and H-B1). Fix: `INSERT ... ON CONFLICT DO NOTHING` + re-read the winner. |
| H-B3 | P1 | ✅ | Redaction leaks: `_observation_by_id` (dedupe return path) has no tombstone filter, so re-sending a redacted event_id returns the full row. `dossier_candidates` counts tombstoned rows. |
| H-B4 | P1 | ✅ | Export omits tombstones and aliases while `iter_observations` includes tombstoned rows → a restore un-redacts data and breaks merged-away refs. Fix: `iter_tombstones`/`iter_aliases` + restore paths; export/import them. |
| H-B5 | P2 | ✅ | Timestamps are stored/ordered as raw ISO text with whatever offset the sender used. Mixed offsets sort wrong; naive strings sort before offset strings; `ORDER BY observed_at DESC LIMIT` and purge cutoffs are lexical. Fix: normalize to UTC `+00:00` in `common.iso` (contract: naive = UTC). |
| H-B6 | P2 | ✅ | `get_dossier` uses exact `_get_entity`, not alias-following `_resolve_entity` — no brief for a merged-away ref. `put_dossier` uses `_upsert_entity` and would re-create a deleted node. `merge_entities` leaves the source's dossier row orphaned and `object_json` still naming the old type/key. |
| H-B7 | P2 | ✅ | `purge_older_than` orphans `embeddings`, `doc_chunks`, `dossiers`; never removes now-empty entities. |
| H-B8 | P2 | ✅ | `search_entities` LIKE metacharacters (`_`, `%`) unescaped; SQLite LIKE is case-insensitive, Postgres is not (backend divergence visible via `/v1/entities/search` and auto-resolution). Escape and use `LOWER()` on both. |
| H-B9 | P3 | ✅ | Postgres upserts update a column subset where SQLite `INSERT OR REPLACE` rewrites the row: `redact` keeps old `recorded_at`, `put_doc_chunks` keeps old spans, `put_embeddings` keeps old namespace. |
| H-B10 | P3 | ✅ | SQLite never enables `PRAGMA foreign_keys`; Postgres enforces FKs. `merge_candidates` `LIMIT` without `ORDER BY` on both. `_upsert_entity` on SQLite has no `ON CONFLICT` re-read (cross-process race). *Done: ORDER BY + SQLite re-read. Open: FK pragma (needs a data audit of old files first).* |
| H-B11 | P3 | ✅ | `restore_observation` with an `event_id` collision on a different id crashes import. |
| H-B12 | P3 | ✅ | No schema-version table; the next migration needing a data rewrite (e.g. `embeddings` PK → `(ref_id, model)`) has no hook. Postgres DDL runs on every replica start with no advisory lock. *Done: advisory lock around DDL, and a `schema_meta` version table — v3→v4 was migrated in place and proven on a populated Postgres (D-044/D-045).* |

## C. Provenance & read-path semantics

| ID | P | Status | Item |
| --- | --- | --- | --- |
| H-C1 | P1 | ✅ | **`brief` and `doc_excerpt` items ship with empty `citations`**, violating hard constraint 3. Dossiers persist only text + count. Fix: store supporting observation ids with the dossier and cite them; extend `Citation` so an excerpt can cite `(artifact_id, span)` — contract change, needs a decisions entry. |
| H-C2 | P2 | ✅ | `as_of` is ignored by briefs and excerpts (post-`as_of` knowledge leaks into time-travel packs). |
| H-C3 | P2 | ✅ | `valid_to` is ignored everywhere (as-of filter and conflict detection). An expired lease from source A vs. a current one from source B reads as a conflict. *Done: expired-validity facts are excluded from conflict detection (relative to as_of or now), and `valid_at` is a separate read parameter on ask/scope/MCP (fact time) next to `as_of` (knowledge time) — D-024.* |
| H-C4 | P2 | ✅ | Conflicts dropped at small budgets vanish silently; the "conflicts ship first" invariant fails without signal. Add a `truncated`/overflow handle. |
| H-C5 | P2 | ✅ | Extracted (`doc:*`) claims count as an independent source in conflict detection and get no scoring discount → one injected document manufactures a score-1.0 conflict at the top of every pack (see H-D2). |
| H-C6 | P3 | ✅ | Excerpt threshold 0.15 is meaningless for both the hashing embedder (non-negative bag vectors) and real models (rarely < 0.7): excerpts always consume half the remaining budget. Make it relative (e.g. within X of the best) or per-embedder. |
| H-C7 | P3 | ✅ | Recency is ordinal (list rank), so 20 observations one second apart spread like 20 across a year; in multi-subject packs rank is global. Keyword and cosine formulas aren't calibrated against each other for mixed (embedded / not-yet-embedded) sets. No stopword removal in the keyword scorer. |
| H-C8 | P3 | ✅ | `search_entities` results are post-filtered after `LIMIT` for scoped keys → fewer than `limit` results. |

## D. Enrichment worker

| ID | P | Status | Item |
| --- | --- | --- | --- |
| H-D1 | P1 | ✅ | Worker loop has no top-level guard: an `LLMError` from `embed_pending`/`chunk_artifacts`, or a `sqlite3.OperationalError` (locked DB), exits the process. Compose `enrich` has no `restart:`. Fix: catch per job, log, continue; add restart policy. |
| H-D2 | P1 | ✅ | Prompt injection: document text goes into the extraction prompt raw and extracted claims choose their own subject/predicate, so a hostile document can assert facts about any entity. Fix: delimit + label untrusted text, tag extracted claims (`attrs.extracted=true`), discount them in `_score`, and don't let `doc:*` sources corroborate/contradict structured sources on their own (H-C5). |
| H-D3 | P2 | ✅ | Doc chunks aren't keyed by embedding model. A worker/engine model mismatch zips vectors of different dimensions silently → garbage excerpts. Add a `model` column, filter on it, and re-chunk when the model changes. |
| H-D4 | P2 | ✅ | Head-of-line starvation: a whitespace-only artifact (chunker yields nothing, never marked) or a persistently failing extraction stays in the 4-slot window forever with no backoff. Add `extraction_attempts`, mark empty artifacts `skipped`, exponential backoff, dead-letter after N. *Done: blank artifacts skipped at the query, per-artifact exponential backoff, ready set drawn from a wider window, and the hardened worker of D-023/D-044 keeps attempt state on the artifact so a restart does not reset a failing document's backoff.* |
| H-D5 | P2 | ✅ | `_parse_extraction`: `{"claims": "x"}` or a list of strings raises `AttributeError` out of the loop; prose before the JSON fence → permanent `failed`. Harden parsing (find the first `{`…`}` block; type-check items). |
| H-D6 | P2 | ✅ | Re-extraction event_ids are index-based (`extract:<artifact>:<n>`); a reordered LLM output silently drops new claims as "duplicates". Key on a content hash of (subject, predicate, object) instead. |
| H-D7 | P2 | ✅ | Extraction truncates at 8000 chars with no record. Windowed extraction over the full text (offset-aware), or at least an `attrs.truncated` flag on the artifact. *Done: a warning log names the truncation. Open: windowed extraction.* |
| H-D8 | P3 | ✅ | Redaction/merge don't touch derived data: briefs and chunks keep redacted text; merged entities keep orphan dossiers. Invalidate on redact; move/drop on merge. *Done: redact drops briefs citing the observation; merge drops the folded node's brief. Chunks are per artifact, which redaction doesn't target (purge does).* |
| H-D9 | P3 | ✅ | `_post_json`: one 120s attempt, no retry/backoff, no 429 handling; a non-JSON 200 body escapes as `JSONDecodeError` (→ 500 instead of 502). |
| H-D10 | P3 | ✅ | `embed_pending` returns the requested count, not the stored count; a short provider response makes `--once` loop forever re-billing. |

## E. Performance

| ID | P | Status | Item |
| --- | --- | --- | --- |
| H-E1 | P2 | ✅ | Every ask: one embedding HTTP round-trip + pure-Python cosine over ≤1000 vectors per subject + every chunk of every cited artifact (uncapped), each vector `json.loads`-decoded per call. Fix now: cap chunks per query, cache the query embedding (LRU by text+model), use numpy if present. Later: sqlite-vec / pgvector (D-002). *Done: query-embedding cache, excerpt candidates capped at 64 after ranking, numpy batched cosine (the `vector` extra), and the ANN index — sqlite-vec / pgvector — of D-025.* |
| H-E2 | P2 | ✅ | Worker tick queries do full scans: no index on `artifacts(extraction_status, recorded_at)`, `observations(recorded_at)`; chunk-backlog anti-join can't use `idx_chunk_artifact` (namespace leads). `dossier_candidates` is a full entities⋈observations GROUP BY every tick. *Done: indexes on `observations(recorded_at)`, `artifacts(extraction_status, recorded_at)`, `doc_chunks(artifact_id)`, `entities(namespace, key)`. Open: incremental dossier candidates.* |
| H-E3 | P3 | ✅ | Scoped asks read each node's observations twice (BFS + gather); `resolve_entities` loads ≤1000 full observations per candidate just to count. Add a count method / edge-only query. |
| H-E4 | P3 | ✅ | `iter_*` use `fetchall()` before yielding — export is O(table) memory. Stream with server-side cursors / `fetchmany`. |
| H-E5 | P3 | ✅ | Single connection + process lock per backend; Postgres never reconnects after a dropped connection. Pool (psycopg_pool) when replicas need it. |
| H-E6 | P3 | ✅ | MCP `answer` rebuilds the LLM client from env per call. |

## F. Demo & deployment risks

| ID | P | Status | Item |
| --- | --- | --- | --- |
| H-F1 | P1 | ✅ | `secrets/` (where the docs tell users to write `keys.json`) is not in `.gitignore` or `.dockerignore`. |
| H-F2 | P1 | ✅ | Seed has no `event_id`s: a second `seed load` on the same volume doubles the corpus (~1,180 claims) and changes every documented number. Generate deterministic ids. |
| H-F3 | P1 | ✅ | Scale profile can come up dead: gateway and consumer fatal on initial NATS connect; compose has bare `depends_on` and no `restart:`. Add healthcheck + `condition: service_healthy`, `restart: unless-stopped`, connect retry. |
| H-F4 | P2 | ✅ | k8s NATS has no persistence or probes — a pod restart drops the queue, contradicting "at-least-once". Add a PVC-backed JetStream store dir. |
| H-F5 | P2 | ✅ | `claude mcp add loom -- docker compose run ...` works only from the repo root. Add `--project-directory` / absolute `-f` in README, sdk.md, tutorial.md. |
| H-F6 | P2 | ✅ | k8s never wires auth: no manifest sets `LOOM_API_KEYS`/`LOOM_AUTH_FILE`, so every k8s shape runs in open dev mode while `deploy/README.md` says otherwise. Add a Secret mount example. *Done: commented `LOOM_AUTH_FILE` + Secret mount blocks in `base/deployment.yaml`, `scale/gateway.yaml` and `scale-pg/gateway.yaml` (2026-09-23); the README recipe creates the Secret they mount.* |
| H-F7 | P2 | ➖ | All k8s manifests pin `:latest`, which every main push overwrites. Pin the SHA tag in overlays (CI already publishes it). *Won't fix in-repo: a hardcoded SHA goes stale on every merge; the pin is a per-deployment choice — `kustomize edit set image ghcr.io/seahop/loom:<sha>` is documented in deploy/README.md.* |
| H-F8 | P3 | ✅ | Containers run as root (no `USER`, no `securityContext`); no `HEALTHCHECK`; engine image installs test extras; no lockfile; base image untagged by digest. *Done: non-root uid 10001 with container security contexts (no escalation, drop ALL, read-only root) and `HEALTHCHECK`s; `requirements.lock` consumed by the Dockerfile and every base image pinned by digest (2026-09-23). The `test` extra (pytest, httpx) stays in the image on purpose — one image serves loom/test/consumer/mcp so they cannot drift (D-011); it is ~2 MB and not a security surface.* |
| H-F9 | P3 | ✅ | Public-repo hygiene: no CONTRIBUTING / SECURITY / CHANGELOG; `pyproject.toml` lacks license/authors/urls. |

## G. SDK

| ID | P | Status | Item |
| --- | --- | --- | --- |
| H-G1 | P2 | ✅ | `search()` and `observations()` don't URL-encode (`web 01`, keys with `/`). |
| H-G2 | P2 | ✅ | Missing: `GET /v1/artifacts/{id}`, `event_id` on `document()`, `X-Loom-LLM-Key` on `answer()`. Server `detail` never surfaced on errors. |
| H-G3 | P3 | ✅ | No tests, no `pyproject.toml` under `sdk/python`, not in the image. |

## H. Docs drift

| ID | P | Status | Item |
| --- | --- | --- | --- |
| H-H1 | P2 | ✅ | `roadmap.md`: "23 tests" (90 + 24 PG-parametrized); "Remaining: per-namespace API keys" (done); milestone table shows phases 3–4 as future. |
| H-H2 | P2 | ✅ | `sdk.md` documents `POST /v1/schemas` and a `loom` CLI that don't exist. |
| H-H3 | P3 | ✅ | `docs/README.md` says D-001…D-019 (D-020 exists). `docker-compose.yml` passes `LOOM_MAX_BUDGET` to the gateway, which never reads it. `http.py` open-mode warning names only `LOOM_API_KEYS`. |

## I. Tests to add

| ID | P | Status | Item |
| --- | --- | --- | --- |
| H-I1 | P1 | ✅ | Type-scoped key: forged/real handle → 403 on expand; scope expansion pack contains no out-of-type subjects or object refs. |
| H-I2 | P1 | ✅ | Export→import keeps a redacted observation hidden and a merged alias resolving. |
| H-I3 | P1 | ✅ | Store: a failing statement doesn't poison later calls (both backends); concurrent same-event_id inserts return the same row. |
| H-I4 | P2 | ✅ | Worker survives an embedder `LLMError` and a locked DB; extraction parser on `{"claims":"x"}`, `["a"]`, prose+fence; reordered re-extraction doesn't drop claims. |
| H-I5 | P2 | ✅ | Chunker: empty, whitespace, 5000-char unbroken line, multibyte, offset round-trip. Excerpts with a chunk/query model mismatch. *Done: model mismatch, blank artifacts. Open: chunker edge cases.* |
| H-I6 | P2 | ✅ | Move D-014/D-016/D-018 store coverage into the backend-parametrized suite (D-011 rule). |
| H-I7 | P3 | ✅ | Consumer batch where the store raises: no crash loop, no duplicate documents. Gateway: random unauthenticated keys don't create buckets. SDK smoke tests. *Done: gateway bucket test, keys-file tolerance on both sides, engine body cap. Open: consumer failure-path test, SDK tests.* |


---

# Review of 2026-09-23

Second full review, six parallel passes (read path, store, enrichment/MCP,
security/deploy, docs/demo, and the field). Every item was verified
against the code at `293bd31` before it was listed; all landed on
2026-09-23 (D-046…D-049) except the design follow-ups in section R,
which change measured numbers and wait for the frozen-volume rehearsal.

## J. Demo-day

| ID | Status | Item |
| --- | --- | --- |
| J-1 | ✅ | `LOOM_MCP_NAMESPACE` (and `LOOM_ALIAS_TYPES`, the agent-eval and worker dials) documented but never passed through compose; `mcp` profile had no embedder. |
| J-2 | ✅ | Home-directory paths and the pre-rename project name in `demo/act3-claude-code-after-aliases.json`, `deploy/README.md`, `vector.yaml`, `fluent-bit.conf`. |
| J-3 | ✅ | The after-alias Act 3 rehearsal shows Claude Code grepping a spilled `ask_scope` result (7 of 26 calls); the demo prompt now asks for budget 1500 on scope asks — needs a rehearsal to confirm. |
| J-4 | ✅ | "Before the talk: 5 minutes" was ~35 min plus a judge-model dependency; script now says night-before, pinned judge, frozen volume, `--offline` reload; Act 2 numbers marked re-verify. |
| J-5 | ✅ | Native Anthropic client failed on every current model (thinking block first). |
| J-6 | ✅ | Seed 580/590/591 (592 since the D-050 supersession moment), handles 69/77 (both wrong: 67 at budget 400), models 14/18/20 and 168/216 runs, tests "~215": one value each. |
| J-7 | ✅ | Act 3 narration still described the pre-D-042 seam as unplanted; fallback transcripts unreadable projected → `demo/act3-*.md`. |

## K. Read path (D-046)

| ID | Status | Item |
| --- | --- | --- |
| K-1 | ✅ | `as_of` filtered on `observed_at` after a newest-first LIMIT 1000 gather (empty time-travel packs on busy entities; `truncated` as_of-blind); docs said `recorded_at`. Axis settled as observation time, bound pushed into SQL. |
| K-2 | ✅ | One forward-dated claim collapsed recency for the whole entity and never left the gather window. Reference clamped to now; ingest rejects `observed_at` > now + 24 h. |
| K-3 | ✅ | `GET /v1/entities/{t}/{k}/observations` skipped the object-side gate MCP applies. |
| K-4 | ✅ | Scope BFS ignored `as_of`/`valid_at`/`entity_types` on edges and followed extracted edges at full weight (a document could rewrite topology). `ScopeSpec.follow_extracted`, default off. |
| K-5 | ✅ | Expanding a conflict handle at `budget == est_tokens` silently dropped the conflict. |
| K-6 | ✅ | `/v1/answer` with both `subject` and `scope` → 500; forged handle field values → 500; `/v1/entities/semantic` → 500 on embedder failure. |
| K-7 | ✅ | Embedder serving with no stored vectors demoted every fact to cos 0 (worse than keyword-only, silently). |
| K-8 | ✅ | Keyword scorer read invisible `attrs` (rank stuffing); answer prompt had no delimiting (newline forged a cited line). |
| K-9 | ✅ | Chunked upload bypassed the body cap; any write key could flip a namespace to `strict`; no `nosniff`/`no-store`; query-vector cache eviction raced. |
| K-10 | ✅ | `ScopeSpec.subjects` unbounded (500 now); scorecard printout omitted `valid_at`; HTTP roundtrip test never expanded a real handle. |

## L. Store (D-049)

| ID | Status | Item |
| --- | --- | --- |
| L-1 | ✅ | `BlobOffloadStore` delegated only abstract methods: with `LOOM_BLOB_THRESHOLD` set, `record_claims` fell back to one tx per claim and `observations_for_many` to the D-043 per-ref regression. |
| L-2 | ✅ | `LOOM_DB_READ` applied to every Postgres shard — a tenant's reads went to the default cluster's replica. |
| L-3 | ✅ | `lifecycle` (and the other CLIs) built the store from `--db`, bypassing sharding and blob offload; the D-032 tenant-move recipe did not work as written. |
| L-4 | ✅ | A claim naming a merged-away ref resurrected the node (exact-key upsert); the worker then re-merged and dropped both dossiers each cycle. |
| L-5 | ✅ | Merges were not reversible despite D-019: no `unmerge`, repointed rows unlogged, `object_json` overwritten. `merge_log` + `unmerge`, schema v5. |
| L-6 | ✅ | `ensure_vector_index` matched every model's tables; purge left stale ANN rows; Postgres HNSW namespace post-filter returned short/empty results. |
| L-7 | ✅ | Export omitted schema registrations and adjudication declines (a restore turned `strict` namespaces permissive). |
| L-8 | ✅ | Older image could write the schema version *down* and re-run DDL under a rolling update; `wipe()` missed declines; `add_alias` no-op'd on a merged target; `search_entities` defeated its index; `subjects_citing` unbounded; vanished blob served as the body; lease release ignored ownership; `norm_key` stripped the dots out of IP addresses. |

## M. Enrichment, LLM, MCP, eval, connector (D-047)

| ID | Status | Item |
| --- | --- | --- |
| M-1 | ✅ | Anthropic client `content[0]["text"]`; OpenAI `content: null` escaped the retry path; `finish_reason` never checked; redirects followed with the key; Retry-After clamped to 8 s. |
| M-2 | ✅ | Tier-2 auto-merged distinct IPs/versions; tier-1 folded `user:admin` into `group:admin` without adjudication. |
| M-3 | ✅ | Extracted claims skipped registered `object_types` in non-strict namespaces. |
| M-4 | ✅ | `</document>` delimiter injection; sender-controlled filename as the `source` label. |
| M-5 | ✅ | Extraction lease never renewed (double extraction); all-or-nothing windows; one garbled window dead-lettered the artifact with zero claims. |
| M-6 | ✅ | `list_namespaces` and the unknown-namespace error leaked other tenants' namespaces to a scoped key; mixed `{"error"}` / `ToolError` conventions; 32-hex ids in every citation. |
| M-7 | ✅ | agent_eval: lease truth hard-coded, first-sentence regex split on the IP, exposure metric never penalized non-KEV CVEs. |
| M-8 | ✅ | Connector: truncated download cached forever via 304; no retry on 429/5xx. |
| M-9 | ✅ | Chunks ~800 chars not ~400, no overlap; `object_entity_type: null` → type `"None"`; alias pass aborted mid-tick; tick summed a FAILED job with merges to zero; per-call `namespace_summary` scan. |

## N. Security, CI, deployment (D-048)

| ID | Status | Item |
| --- | --- | --- |
| N-1 | ✅ | Consumer and Kafka paths never ran registry validation. |
| N-2 | ✅ | No lockfile (D-045's boto3 drift); base images unpinned; gateway on EOL Alpine 3.20; Go SDK on unsupported Go; `x/crypto` 0.18 indirect. |
| N-3 | ✅ | Published image rebuilt in a separate job from the tested one; default `GITHUB_TOKEN` permissions; mutable action tags; no Dependabot / Trivy / govulncheck / SBOM. |
| N-4 | ✅ | k8s: no NetworkPolicy, PDB, container securityContext or `automountServiceAccountToken: false`; JetStream unbounded on a 1 Gi PVC in `scale`; NATS monitor port on the client Service; readiness `failureThreshold` 1; vulns-refresh Secret optional. |
| N-5 | ✅ | Gateway `http.Server` without read/write/idle timeouts; Kafka consumer without SASL/TLS; dead-letter headers carrying row values; keys file written non-atomically at 0644 in CWD; engine on 0.0.0.0 in open mode by default. |
| N-6 | ✅ | Stale claims: compose said the MCP http transport had no auth; H-A1 fallback, H-F6 gateway mount, H-F8 lockfile marked ✅ but absent; SECURITY.md "until a tagged release"; deploy/README "while private". |

## R. Design follow-ups (deferred: each moves measured numbers; do after the frozen-volume rehearsal, measure with the harness)

| ID | Status | Item |
| --- | --- | --- |
| R-1 | ✅ | (D-051) Budget honesty: the budget charges item text only; citations (~25 tokens each) and up to 32 handles ride free, so an "800-token" pack is ~2,500 on the wire for an MCP agent. Charge the rendered form; one real-tokenizer test. |
| R-2 | ✅ | (D-051) Lexical leg: FTS5 / `tsvector` BM25 fused with cosine by reciprocal rank (every serious peer has it); tokenize predicate names so "operating system" matches `runs_os`. |
| R-3 | ✅ | (D-051) Packing: value-per-token with an MMR diversity term instead of greedy trim by score; cosine normalized within the gathered set (real embedders compress to ~0.27–0.40, so recency dominates). |
| R-4 | ✅ | (D-051) Entity-valued conflicts never surface (`isinstance(object, EntityRef): continue`); `str()` value normalization false-conflicts `True`/`"true"`. |
| R-5 | ✅ | (D-051) Pagination past the gather cap: a `before:` cursor in the handle payload so the 1,740 truncated kernel CVEs are reachable. |
| R-6 | ✅ | (D-053) Scorecard: `test_quality.py` is eight booleans with no baseline. A small labeled set over the vulns corpus, MRR/nDCG, a recency-only and a full-context baseline, abstention and as-of cases, an NLI/LLM-judge citation *support* check, cost columns. |
| R-7 | ✅ | (D-055) MCP 2026-07-28: `outputSchema` from the contracts, `readOnlyHint` annotations, handle TTL in the `expand` description, a `format: concise|detailed` knob, consider merging `ask`/`ask_scope`. |
| R-8 | ✅ | (all four landed: supersession + PROV-O in D-050; STIX/OCSF + Vulnrichment in D-055/D-056) Explicit, cited supersession edge (recorded, never inferred); PROV-O JSON-LD export; STIX 2.1 / OCSF predicate mapping in the registry; CISA Vulnrichment as a third vuln source. |
| R-9 | ✅ | (D-054) Worker tick scans (`observations_without_embeddings`, `dossier_candidates`) walk from the beginning each tick — high-water marks; `observations_for_many` has no per-entity pre-limit (a hub materializes every row). |
| R-10 | ✅ | (D-056) Engine-side per-grant rate limiting (a valid reader can burn LLM spend on `/v1/answer` without bound in the default shape). |

## S. Whole-project review (2026-09-24, D-057…D-060)

Four independent reviewers (security, store/read path, enrichment/eval,
release readiness) over `main` at `679bc83`; every item below was verified
against the code before it was fixed. Landed on branch `release-hardening`.

| ID | P | Status | Item |
| --- | --- | --- | --- |
| S-1 | P1 | ✅ | (D-057) agent_eval exposure passed on naming 1 of ~29 KEV CVEs; no task required a citation. |
| S-2 | P1 | ✅ | (D-057) retrieval conflict grading passed any reply containing the word "conflict" ("no conflict, 7.5"), favouring Loom's condition. |
| S-3 | P1 | ✅ | (D-057) An empty or length-truncated reply scored as a correct abstention. |
| S-4 | P1 | ✅ | `docker compose run --rm test` (README's first command) tried to pull `loom-engine:local` on a fresh clone — every engine-image service now has `build: .`; verified from a clean export. |
| S-5 | P1 | ✅ | The Go SDK CI step piped `go test` into `grep` and could never fail; `go.sum` uncommitted and `go mod tidy … \|\| true`. |
| S-6 | P2 | ✅ | (D-057) Baselines not token-matched (vector top-20 ≈ 320 tokens vs packs to 3,200); `full` capped at 1,000 observations per entity like Loom; never-sent rows scored as FAIL; EPSS tolerance 0.005 absolute; one embedder hiccup lost the whole paid run; question pool from the first 400 keys; EPSS-guessable orderings; conflict set drifting with the clock; dates read as citations; agent-eval lease check failing answers that mention history. |
| S-7 | P2 | ✅ | (D-057) agent scorecard counted provider outages as the model's failures. |
| S-8 | P2 | ✅ | (D-058) False scalar conflict when a source updates its own value and another source agrees with the new one. |
| S-9 | P2 | ✅ | (D-058) Briefs bypassed the entity-type gate, ignored `valid_at`, and could take ~85 % of a 1,600-token pack. |
| S-10 | P2 | ✅ | (D-058) A merged-away name lost its conflicts (and re-appeared as a second scope subject). |
| S-11 | P2 | ✅ | (D-058) Unbounded scope walk: 500 roots × depth 3 × 1,000 observations each could OOM a 512Mi pod on the vulns corpus. |
| S-12 | P2 | ✅ | (D-058) Budget honesty held only for the answer prompt; the MCP wire was 2.2–3.6× the budget. |
| S-13 | P2 | ✅ | (D-058) Excerpt KNN ran namespace-wide then filtered, so most asks decoded every chunk vector of every cited artifact. |
| S-14 | P2 | ✅ | (D-059) Open dev mode writable cross-site (`text/plain` batch POST) and reachable via DNS rebinding (engine had no Host check; MCP on 0.0.0.0 turned the SDK's protection off). |
| S-15 | P2 | ✅ | (D-059) A type-scoped rw key could cite any document into its world and then read it (H-A6 gate trusted writer-chosen citations); the NATS path had no citation check. |
| S-16 | P2 | ✅ | (D-059) LLM spend limits had holes: MCP `answer` unlimited; compose never passed `LOOM_RATE_*`; gateway parsed `0.5` as unlimited; engine charged a batch 1 token. |
| S-17 | P2 | ✅ | (D-060) An unmerge was re-merged within one worker tick; no way to mark two entities distinct. |
| S-18 | P2 | ✅ | (D-060) An unparseable adjudication verdict was re-asked and re-billed every tick without limit. |
| S-19 | P2 | ✅ | (D-060) Nightly EPSS refresh added ~109k unchanged observations (and embeddings) per night. |
| S-20 | P2 | ✅ | (D-060) OCSF: a resolved finding never closed the host's exposure; Suppressed treated as closed. |
| S-21 | P2 | ✅ | (D-060) Consumer: one bad envelope dead-lettered its whole batch; a claim whose document was in another replica's batch was dropped. `loom.ingest` died on the first 429. |
| S-22 | P2 | ✅ | (D-058) The decline-aware `merge_candidates` self-join compared 74k × 74k entities on SQLite each worker tick (found while embedding the vulns corpus; ~0.1 s now). |
| S-23 | P3 | ✅ | (D-058) Expand-path P3s: silent conflict drop in thread expansion, excerpt expansion charged 0, first-handle overrun unstated, supersession from unfiltered rows, import un-redaction window, trailing punctuation, `truncated` counting hidden rows, SQLite migration race. |
| S-24 | P3 | ✅ | (D-059) MCP `record_claim` skipped the subject check on `supersedes`; uploads bypassed the key's entity types for extraction; gateway HTTP-forward batch reported rejected items as recorded; bodies parsed before auth; scoped keys saw all-type counts. |
| S-25 | P3 | ✅ | Release hygiene: CHANGELOG stopped at D-049; `docs/interop.md` and `docs/evaluation.md` unlinked; GCP project id in docs; `AGENTS.md` an untracked copy of CLAUDE.md (now a symlink); `.env.*` not ignored; undocumented env vars; `govulncheck@latest` and openapi-generator by tag; no CI concurrency group or lint beyond hard errors (now the full pyflakes set); no TS lockfile; quickstart raced the engine's start-up and the keys recipe failed without `secrets/`. |
| S-26 | P3 | ✅ | (D-060) `fuzzy_merge_candidates` could still fill its limit with permanently declined groups (same shape as S-22's fix). |
| S-27 | P3 | ✅ | (D-060) Scope facts gathered as inbound edges on a reached subject did not carry their path (now they carry the reached entity's chain). |
| S-28 | P3 | ✅ | (D-060) No command to undo a decline: now `GraphStore.forget_decline` and `python -m loom.enrich undistinct`. |
| S-29 | P3 | ⬜ | A KEV `knownRansomwareCampaignUse` flip keeps its event id and is never recorded (fixing it changes KEV event ids). |
| S-30 | P3 | ⬜ | OCSF/STIX `emit` (export) does not chain versions — it has no store to look earlier versions up in. |
| S-31 | P3 | ➖ | A shared rate limiter across processes/replicas: buckets stay per process, the effective ceiling (rate × workers × replicas) is documented instead. |
| S-32 | P3 | ⬜ | The GCP project id remains in git history (not a secret; scrubbed from the tree). Rewriting history is not planned. |
