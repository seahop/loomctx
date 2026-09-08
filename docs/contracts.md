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
`extraction_status` (`pending | done | failed`) that the phase-4 workers will
advance as they mine claims out of the text.

## Read side (live: /v1/ask and /v1/expand)

**AskRequest:** `{subject, question, budget (tokens, mandatory), as_of?}`

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
    {"id": "h1_…", "hint": "69 more 'logged_in_by' observations for host:web-01",
     "est_tokens": 1725, "kind": "more"},
    {"id": "h1_…", "hint": "CONFLICT on host:web-01 runs_os did not fit the budget",
     "est_tokens": 60, "kind": "conflict"}
  ]
}
```

Item `kind` ∈ `brief | fact | relation | doc_excerpt | conflict`. **Every
item carries at least one citation** (D-023): facts and conflicts cite
observations, briefs cite the observations they were synthesized from,
excerpts cite an artifact span. A `Citation` therefore names either an
`observation_id` or an `artifact_id` (+ span). Conflicts are items, not
merged away — and one that doesn't fit the budget becomes a `conflict`
handle rather than disappearing. Handles feed `POST /v1/expand`; with
`LOOM_HANDLE_SECRET` set they are signed (`h2_` prefix, D-021).

## Schema registry

`SchemaRegistration`: per-namespace `entity_types` (name, description, facets) and
`predicates` (name, description, allowed object types, `containment`), plus
`strict`. Registered at runtime via `POST /v1/schemas` (additive by name;
`GET /v1/schemas` reads it back). A registered predicate's `object_types`
are enforced on ingest; a strict namespace rejects unregistered predicates
and entity types; containment predicates are what a scope follows when the
caller names none (D-024). This is what keeps the core domain-agnostic.

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
