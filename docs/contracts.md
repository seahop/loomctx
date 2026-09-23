# Contracts

**Source of truth: [`src/loom/contracts.py`](../src/loom/contracts.py).** This page is
the readable tour. Every surface (HTTP, MCP, SDK, CLI) serializes exactly these
shapes; JSON Schema for non-Python consumers is exported with:

```bash
docker compose run --rm loom python -m loom.schemas > schemas.json
```

## Ingestion envelope

One `POST /v1/ingest` body, discriminated by `kind`.

**Claim** — structured, entity-addressed, maps ~1:1 to an observation:

```json
{
  "kind": "claim",
  "namespace": "netsec",
  "subject": {"type": "host", "key": "web-01"},
  "predicate": "logged_in_by",
  "object": {"type": "user", "key": "jdoe"},
  "observed_at": "2026-09-01T14:03:00Z",
  "valid_from": null,
  "valid_to": null,
  "source": "auth-log",
  "confidence": 1.0,
  "attrs": {"session_id": "abc123"}
}
```

`object` may be another entity ref (creating a graph edge) **or** a scalar
(`"os": "fedora-44"` style facts). `valid_from`/`valid_to` are the world-time axis;
Loom stamps `recorded_at` itself (knowledge-time axis).

**Document** — unstructured; stored verbatim, mined asynchronously:

```json
{
  "kind": "document",
  "namespace": "netsec",
  "text": "…or use content_b64 for binary…",
  "content_type": "text/plain",
  "filename": "IR-4432.txt",
  "source": "ir-pipeline",
  "observed_at": "2026-09-02T09:00:00Z",
  "attrs": {}
}
```

Exactly one of `text` / `content_b64` is required.

**Batch** — `POST /v1/ingest/batch` takes a JSON array of envelopes, NDJSON
(one per line, `Content-Type: application/x-ndjson`), or `{"items": [...]}`,
up to `LOOM_MAX_BATCH` (1000), and answers with `IngestBatchResponse`:

```json
{"total": 3, "recorded": 1, "accepted": 1, "rejected": 1,
 "results": [
   {"index": 0, "status": "recorded", "observation_id": "…"},
   {"index": 1, "status": "accepted", "artifact_id": "…"},
   {"index": 2, "status": "rejected", "detail": "subject: Field required"}
 ]}
```

Every item passes the same gates as the single-envelope route and is
reported individually; a bad record never blocks the rest (D-034).

## Observation (stored form)

What both doors converge into. Same as a claim plus: server-assigned `id`,
`recorded_at`, and optional `provenance` (`artifact_id` + character span) when the
observation was extracted from a document.

## Entity

`{id, namespace, type, key, aliases, provisional, created_at}` — canonical node.
`provisional: true` marks an unresolved document mention awaiting merge.

## Artifact (stored document)

The 202 response to a document ingest carries an `artifact_id`; fetch the
verbatim content at `GET /v1/artifacts/{id}`. Artifacts carry an
`extraction_status` (`pending | done | failed | skipped`) that the enrichment
worker advances as it mines claims out of the text (blank artifacts are
`skipped`; a persistently failing one backs off and ends `failed`).

## Read side (live: /v1/ask and /v1/expand)

**AskRequest:** `{namespace, subject | scope, question, budget (tokens,
mandatory), as_of?, valid_at?}` — exactly one of `subject` (one entity) or
`scope` (`{subjects, expand?, depth?}`, several entities or an anchor plus
what it reaches over the named predicates); `as_of` is knowledge time
("what did we know at T"), `valid_at` is fact time ("what was true at T").

**ContextPack:**

```json
{
  "namespace": "netsec",
  "subject": {"type": "host", "key": "web-01"},
  "question": "who logged in this week?",
  "as_of": null,
  "budget": 800,
  "items": [
    {
      "kind": "fact",
      "text": "jdoe logged into web-01 on 2026-09-01 14:03 UTC.",
      "score": 0.92,
      "citations": [
        {"observation_id": "…", "source": "auth-log",
         "observed_at": "2026-09-01T14:03:00Z"}
      ]
    },
    {
      "kind": "doc_excerpt",
      "text": "\"…outbound traffic was observed from 10.0.4.7…\" [doc:3fa1b2c9 @118-203]",
      "score": 0.81,
      "citations": [
        {"artifact_id": "3fa1b2c9…", "span_start": 118, "span_end": 203,
         "source": "ir-pipeline", "observed_at": "2026-09-01T18:00:00Z"}
      ]
    }
  ],
  "handles": [
    {"id": "h1_…", "hint": "67 more 'logged_in_by' observations for host:web-01",
     "est_tokens": 1725, "kind": "more"},
    {"id": "h1_…", "hint": "CONFLICT on host:web-01 runs_os did not fit the budget",
     "est_tokens": 60, "kind": "conflict"}
  ],
  "omitted_handles": 0,
  "truncated": [
    {"entity": {"type": "product", "key": "linux:linux_kernel"}, "gathered": 1000, "total": 2740}
  ]
}
```

Item `kind` ∈ `brief | fact | relation | doc_excerpt | conflict`. A
`relation` is an edge a scope was expanded through, shipped right before
the first fact about the entity it reached, so a multi-hop pack reads as a
chain (D-035). **Every
item carries at least one citation** (D-023): facts and conflicts cite
observations, briefs cite the observations they were synthesized from,
excerpts cite an artifact span. A `Citation` therefore names either an
`observation_id` or an `artifact_id` (+ span). Conflicts are items, not
merged away — and one that doesn't fit the budget becomes a `conflict`
handle rather than disappearing. Handles feed `POST /v1/expand`; with
`LOOM_HANDLE_SECRET` set they are signed (`h2_` prefix, D-021). At most 32
handles ship, in priority order (conflicts, excerpts, then the most
skipped threads); `omitted_handles` counts the rest, so a scope over a hub
entity says "and 8,000 more threads" instead of shipping them (D-035).
`truncated` lists entities whose observations exceeded the gather limit:
only the newest `gathered` of `total` were examined, at that subject, at
a hop of a scope, or under an expanded handle. Partial coverage is a fact
the reader needs — an agent must not conclude absence there (D-038). The
MCP view renders it as a `coverage_warning`; the answering prompt as a
`coverage:` line.

## Provenance: a claim that cites a document

`ClaimIn.provenance` names the document a claim came from. An extracted
claim (the enrichment worker) carries the `artifact_id`. A sender that
ingests a document and structured claims about it in the same pipeline —
a scanner report and its findings, an advisory and its flags — does not
know the artifact id yet, so it may cite the document by its own
`event_id`:

```json
{"kind": "document", "event_id": "adv-2026-2441", "text": "...", "source": "cisa-kev", "observed_at": "..."}
{"kind": "claim", "subject": {"type": "cve", "key": "CVE-2026-2441"}, "predicate": "exploited_in_wild",
 "object": true, "source": "cisa-kev", "observed_at": "...",
 "provenance": {"artifact_event_id": "adv-2026-2441"}}
```

The reference is resolved to `artifact_id` at ingest. The document must
land first — the same batch is fine, documents are stored before the
batch's claims — and a reference to a document that was never ingested
rejects the claim (`422` on `/v1/ingest`, a `rejected` item in a batch, a
logged skip on the queue path). Once linked, the document's passages are
candidates for `doc_excerpt` items in packs about the claim's subject
(D-039). Provenance does not make a claim "extracted": ranking discounts
apply to claims whose `source` starts with `doc:` or that carry
`attrs.extracted`, never to a sender's structured claim that cites its
document.

## Schema registry

`SchemaRegistration`: per-namespace `entity_types` (name, description, facets) and
`predicates` (name, description, allowed object types, `containment`), plus
`strict`. Registered at runtime via `POST /v1/schemas` (additive by name;
`GET /v1/schemas` reads it back). A registered predicate's `object_types`
are enforced on ingest; a strict namespace rejects unregistered predicates
and entity types — on the HTTP path and for claims the enrichment worker
extracts from documents alike (D-044); containment predicates are what a
scope follows when the caller names none (D-024). An extracted entity
whose type is unregistered but whose key already exists under exactly one
registered type takes that type. This is what keeps the core domain-agnostic.

## Time axes on reads

`AskRequest`/`AnswerRequest` carry `as_of` (knowledge time: hide what was
recorded after T) and `valid_at` (fact time: keep only observations whose
validity window covers T; un-windowed facts are timeless and kept). Both
ride on expansion handles.

## Compatibility rules

- Additive changes (new optional fields) are free.
- Renames/removals/semantic changes require a version bump and a note in
  `docs/decisions.md`.
- SDKs contain no logic, so contract fidelity is the whole compatibility story.
