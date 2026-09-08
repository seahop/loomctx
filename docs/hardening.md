# Hardening roadmap (review of 2026-09-08)

Findings from a full-codebase review after phase 4 / D-020. Every item here
was verified against the code at commit `a2aa1a5`; nothing speculative.
Status legend: ✅ fixed · 🔨 in progress · ⬜ open · ➖ won't fix (with reason).

Keep this file current: flip markers as items land, and reference the
commit. **Progress 2026-09-08:** all P1 items and nearly all P2 items landed
in commits 58300fa…HEAD (D-021/D-022/D-023); what remains is listed with
⬜/🔨 below. Items are grouped by area and ordered by severity within each group.
The "P" column is the pre-conference priority: **P1** must land before the
demo, **P2** should, **P3** after.

## A. Auth & data-scoping gates

| ID | P | Status | Item |
| --- | --- | --- | --- |
| H-A1 | P1 | ✅ | `/v1/expand` never checks the `entity_types` grant. Handles are unsigned base64 JSON (`context.py encode_handle`), so a type-scoped reader can mint a handle for any subject and read its observations. Fix: gate the decoded subject's type, and sign handles (HMAC, `LOOM_HANDLE_SECRET`, random per-process fallback). |
| H-A2 | P1 | ✅ | Scope expansion and object-side entities ignore `entity_types`. `resolve_scope` BFSes to any type; facts whose *object* is an out-of-scope entity are returned. Fix: pass the grant's allowed types into `build_pack`/`expand_pack` and filter resolved subjects + observations there (scoped world, not an error — D-013a). |
| H-A3 | P1 | ✅ | `expand_pack` skips the `LOOM_MAX_BUDGET` clamp that `build_pack` applies. |
| H-A4 | P2 | ✅ | Go gateway rate-limits on the raw key string *before* authenticating (`server.go` `limiters.allow` precedes `grantFor`). Rotating a random header yields a fresh bucket each time and grows the bucket map without bound. Fix: authenticate first when auth is on, key buckets on the grant id, cap/evict the map. |
| H-A5 | P2 | ✅ | Naive-datetime `expires` in the keys file raises `TypeError` in Python (`auth.py` compares to aware now) → 500 on every request with that key; Go rejects the whole file. Fix: treat naive as UTC in both; validate `perms` in the file path. |
| H-A6 | P2 | ✅ | `/v1/artifacts/{id}` has no data gate beyond namespace: a type-scoped reader gets full document text. Fix: gate on whether any observation the key may see cites the artifact, or require an unrestricted grant. |
| H-A7 | P2 | ✅ | Consumer logs pydantic `errors()` which include `input` (claim values / document text). Use `include_input=False`. |
| H-A8 | P2 | ✅ | Provider error bodies and base URLs leak into 502 details (`llm.py` → `http.py`). Log the detail, return a generic message. |
| H-A9 | P3 | 🔨 | MCP has no auth or scoping; `streamable-http` profile binds 0.0.0.0 with full rw over all namespaces. Documented open item (D-013) — at minimum honor `LOOM_API_KEYS`/`LOOM_AUTH_FILE` with a per-connection key, or document that the profile must sit behind cluster policy in bold. *Done: compose binds the profile to 127.0.0.1 and the warning is in compose + SECURITY.md. Open: per-connection key on the http transport.* |
| H-A10 | P3 | ⬜ | NATS shape has a single enforcement point (gateway); consumer applies no grants. Acceptable while the queue is cluster-internal; document it, and carry the grant id on the message for audit. |
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
| H-B10 | P3 | 🔨 | SQLite never enables `PRAGMA foreign_keys`; Postgres enforces FKs. `merge_candidates` `LIMIT` without `ORDER BY` on both. `_upsert_entity` on SQLite has no `ON CONFLICT` re-read (cross-process race). *Done: ORDER BY + SQLite re-read. Open: FK pragma (needs a data audit of old files first).* |
| H-B11 | P3 | ✅ | `restore_observation` with an `event_id` collision on a different id crashes import. |
| H-B12 | P3 | 🔨 | No schema-version table; the next migration needing a data rewrite (e.g. `embeddings` PK → `(ref_id, model)`) has no hook. Postgres DDL runs on every replica start with no advisory lock. *Done: advisory lock around DDL. Open: schema-version table.* |

## C. Provenance & read-path semantics

| ID | P | Status | Item |
| --- | --- | --- | --- |
| H-C1 | P1 | ✅ | **`brief` and `doc_excerpt` items ship with empty `citations`**, violating hard constraint 3. Dossiers persist only text + count. Fix: store supporting observation ids with the dossier and cite them; extend `Citation` so an excerpt can cite `(artifact_id, span)` — contract change, needs a decisions entry. |
| H-C2 | P2 | ✅ | `as_of` is ignored by briefs and excerpts (post-`as_of` knowledge leaks into time-travel packs). |
| H-C3 | P2 | 🔨 | `valid_to` is ignored everywhere (as-of filter and conflict detection). An expired lease from source A vs. a current one from source B reads as a conflict. *Done: expired-validity facts are excluded from conflict detection (relative to as_of or now). Open: a separate `valid_at` read parameter so "what was true at T" and "what did we know at T" are distinct queries (architecture.md promises both).* |
| H-C4 | P2 | ✅ | Conflicts dropped at small budgets vanish silently; the "conflicts ship first" invariant fails without signal. Add a `truncated`/overflow handle. |
| H-C5 | P2 | ✅ | Extracted (`doc:*`) claims count as an independent source in conflict detection and get no scoring discount → one injected document manufactures a score-1.0 conflict at the top of every pack (see H-D2). |
| H-C6 | P3 | ✅ | Excerpt threshold 0.15 is meaningless for both the hashing embedder (non-negative bag vectors) and real models (rarely < 0.7): excerpts always consume half the remaining budget. Make it relative (e.g. within X of the best) or per-embedder. |
| H-C7 | P3 | ⬜ | Recency is ordinal (list rank), so 20 observations one second apart spread like 20 across a year; in multi-subject packs rank is global. Keyword and cosine formulas aren't calibrated against each other for mixed (embedded / not-yet-embedded) sets. No stopword removal in the keyword scorer. |
| H-C8 | P3 | ✅ | `search_entities` results are post-filtered after `LIMIT` for scoped keys → fewer than `limit` results. |

## D. Enrichment worker

| ID | P | Status | Item |
| --- | --- | --- | --- |
| H-D1 | P1 | ✅ | Worker loop has no top-level guard: an `LLMError` from `embed_pending`/`chunk_artifacts`, or a `sqlite3.OperationalError` (locked DB), exits the process. Compose `enrich` has no `restart:`. Fix: catch per job, log, continue; add restart policy. |
| H-D2 | P1 | ✅ | Prompt injection: document text goes into the extraction prompt raw and extracted claims choose their own subject/predicate, so a hostile document can assert facts about any entity. Fix: delimit + label untrusted text, tag extracted claims (`attrs.extracted=true`), discount them in `_score`, and don't let `doc:*` sources corroborate/contradict structured sources on their own (H-C5). |
| H-D3 | P2 | ✅ | Doc chunks aren't keyed by embedding model. A worker/engine model mismatch zips vectors of different dimensions silently → garbage excerpts. Add a `model` column, filter on it, and re-chunk when the model changes. |
| H-D4 | P2 | 🔨 | Head-of-line starvation: a whitespace-only artifact (chunker yields nothing, never marked) or a persistently failing extraction stays in the 4-slot window forever with no backoff. Add `extraction_attempts`, mark empty artifacts `skipped`, exponential backoff, dead-letter after N. *Done: blank artifacts skipped at the query, per-artifact exponential backoff (in worker memory), ready set drawn from a wider window. Open: persist attempts + dead-letter status across restarts.* |
| H-D5 | P2 | ✅ | `_parse_extraction`: `{"claims": "x"}` or a list of strings raises `AttributeError` out of the loop; prose before the JSON fence → permanent `failed`. Harden parsing (find the first `{`…`}` block; type-check items). |
| H-D6 | P2 | ✅ | Re-extraction event_ids are index-based (`extract:<artifact>:<n>`); a reordered LLM output silently drops new claims as "duplicates". Key on a content hash of (subject, predicate, object) instead. |
| H-D7 | P2 | 🔨 | Extraction truncates at 8000 chars with no record. Windowed extraction over the full text (offset-aware), or at least an `attrs.truncated` flag on the artifact. *Done: a warning log names the truncation. Open: windowed extraction.* |
| H-D8 | P3 | ✅ | Redaction/merge don't touch derived data: briefs and chunks keep redacted text; merged entities keep orphan dossiers. Invalidate on redact; move/drop on merge. *Done: redact drops briefs citing the observation; merge drops the folded node's brief. Chunks are per artifact, which redaction doesn't target (purge does).* |
| H-D9 | P3 | ✅ | `_post_json`: one 120s attempt, no retry/backoff, no 429 handling; a non-JSON 200 body escapes as `JSONDecodeError` (→ 500 instead of 502). |
| H-D10 | P3 | ✅ | `embed_pending` returns the requested count, not the stored count; a short provider response makes `--once` loop forever re-billing. |

## E. Performance

| ID | P | Status | Item |
| --- | --- | --- | --- |
| H-E1 | P2 | 🔨 | Every ask: one embedding HTTP round-trip + pure-Python cosine over ≤1000 vectors per subject + every chunk of every cited artifact (uncapped), each vector `json.loads`-decoded per call. Fix now: cap chunks per query, cache the query embedding (LRU by text+model), use numpy if present. Later: sqlite-vec / pgvector (D-002). *Done: query-embedding cache, excerpt candidates capped at 64 after ranking. Open: numpy/sqlite-vec.* |
| H-E2 | P2 | 🔨 | Worker tick queries do full scans: no index on `artifacts(extraction_status, recorded_at)`, `observations(recorded_at)`; chunk-backlog anti-join can't use `idx_chunk_artifact` (namespace leads). `dossier_candidates` is a full entities⋈observations GROUP BY every tick. *Done: indexes on `observations(recorded_at)`, `artifacts(extraction_status, recorded_at)`, `doc_chunks(artifact_id)`, `entities(namespace, key)`. Open: incremental dossier candidates.* |
| H-E3 | P3 | ✅ | Scoped asks read each node's observations twice (BFS + gather); `resolve_entities` loads ≤1000 full observations per candidate just to count. Add a count method / edge-only query. |
| H-E4 | P3 | ⬜ | `iter_*` use `fetchall()` before yielding — export is O(table) memory. Stream with server-side cursors / `fetchmany`. |
| H-E5 | P3 | ⬜ | Single connection + process lock per backend; Postgres never reconnects after a dropped connection. Pool (psycopg_pool) when replicas need it. |
| H-E6 | P3 | ⬜ | MCP `answer` rebuilds the LLM client from env per call. |

## F. Demo & deployment risks

| ID | P | Status | Item |
| --- | --- | --- | --- |
| H-F1 | P1 | ✅ | `secrets/` (where the docs tell users to write `keys.json`) is not in `.gitignore` or `.dockerignore`. |
| H-F2 | P1 | ✅ | Seed has no `event_id`s: a second `seed load` on the same volume doubles the corpus (~1,180 claims) and changes every documented number. Generate deterministic ids. |
| H-F3 | P1 | ✅ | Scale profile can come up dead: gateway and consumer fatal on initial NATS connect; compose has bare `depends_on` and no `restart:`. Add healthcheck + `condition: service_healthy`, `restart: unless-stopped`, connect retry. |
| H-F4 | P2 | ✅ | k8s NATS has no persistence or probes — a pod restart drops the queue, contradicting "at-least-once". Add a PVC-backed JetStream store dir. |
| H-F5 | P2 | ✅ | `claude mcp add loom -- docker compose run ...` works only from the repo root. Add `--project-directory` / absolute `-f` in README, sdk.md, tutorial.md. |
| H-F6 | P2 | ✅ | k8s never wires auth: no manifest sets `LOOM_API_KEYS`/`LOOM_AUTH_FILE`, so every k8s shape runs in open dev mode while `deploy/README.md` says otherwise. Add a Secret mount example. |
| H-F7 | P2 | ➖ | All k8s manifests pin `:latest`, which every main push overwrites. Pin the SHA tag in overlays (CI already publishes it). *Won't fix in-repo: a hardcoded SHA goes stale on every merge; the pin is a per-deployment choice — `kustomize edit set image ghcr.io/seahop/loom:<sha>` is documented in deploy/README.md.* |
| H-F8 | P3 | ⬜ | Containers run as root (no `USER`, no `securityContext`); no `HEALTHCHECK`; engine image installs test extras; no lockfile; base image untagged by digest. |
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
| H-I5 | P2 | 🔨 | Chunker: empty, whitespace, 5000-char unbroken line, multibyte, offset round-trip. Excerpts with a chunk/query model mismatch. *Done: model mismatch, blank artifacts. Open: chunker edge cases.* |
| H-I6 | P2 | ✅ | Move D-014/D-016/D-018 store coverage into the backend-parametrized suite (D-011 rule). |
| H-I7 | P3 | 🔨 | Consumer batch where the store raises: no crash loop, no duplicate documents. Gateway: random unauthenticated keys don't create buckets. SDK smoke tests. *Done: gateway bucket test, keys-file tolerance on both sides, engine body cap. Open: consumer failure-path test, SDK tests.* |
