# Contracts

**Source of truth: [`src/loomctx/contracts.py`](../src/loomctx/contracts.py).** This page is
the readable tour. Every surface (HTTP, MCP, SDK, CLI) serializes exactly these
shapes; JSON Schema for non-Python consumers is exported with:

```bash
docker compose run --rm loomctx python -m loomctx.schemas > schemas.json
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
LoomCtx stamps `recorded_at` itself (knowledge-time axis).

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
up to `LOOMCTX_MAX_BATCH` (1000), and answers with `IngestBatchResponse`:

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

## Read side (live: /v1/ask, /v1/path and /v1/expand)

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
    {"id": "h1_…", "hint": "74 more 'logged_in_by' observations for host:web-01",
     "est_tokens": 2664, "kind": "more"},
    {"id": "h1_…", "hint": "CONFLICT on host:web-01 runs_os did not fit the budget",
     "est_tokens": 71, "kind": "conflict"},
    {"id": "h1_…", "hint": "1,740 older observations about product:linux:linux_kernel were not examined (observed at or before 2026-03-02)",
     "est_tokens": 36000, "kind": "more"}
  ],
  "omitted_handles": 3,
  "truncated": [
    {"entity": {"type": "product", "key": "linux:linux_kernel"}, "gathered": 1000, "total": 2740}
  ],
  "charged_tokens": 781
}
```

**The budget is honest (D-051).** `budget` is the request (clamped to
`LOOMCTX_MAX_BUDGET`); `charged_tokens` is what the pack charged against it,
in the compact form an agent actually receives, sized to the costlier of
its two surfaces — the MCP concise view (compact JSON) over the answer
prompt's lines: every item's text *plus its citations* (one
`"<cite> <source> <date>"` string each) and its JSON framing, and every
handle's hint *plus its id* (charged at 1.5 characters a token, the rate
of the base64 ids before D-062; today's plain-text ids —
`h1_netsec~host~web-01~logged_in_by`, time bounds as `a20260924T0418Z` —
tokenize at 1.9–2.4, and 1.47 for a UUID key, as the base64 ones did) and
framing (D-058). The scorecard checks both the rendered prompt and the
MCP view's items and handles with `cl100k_base` against the request
(within 15 %; the view's envelope — namespace, question echo, subject
list — is ~70 tokens beside it). `charged_tokens ≤ budget`, with one
carve-out: the first handle always ships, so that what was cut is always
reachable — when the budget is under two handles, or conflicts, briefs
and excerpts filled it, the pack exceeds the budget by that handle's cost
at most. Handles take at most 15 % of the budget (`omitted_handles`
counts the rest); conflict items take at most half, briefs a quarter
(`withheld_briefs` counts one that did not fit, or that draws on
observations a type-scoped key may not see). `notes` (D-064) say what
the pack could not do as asked — an expand predicate the namespace does
not know (with up to three close ones), an attribute named in `expand`
taken as the question's topic, a link the question names that the scope
stops short of, a subject that names no entity; they are advice, not
evidence, and are not charged. A scope walk stops at
`LOOMCTX_MAX_SCOPE_ENTITIES` (2,000) entities and `LOOMCTX_MAX_SCOPE_OBSERVATIONS`
(100,000) gathered rows; the cut is a `truncated` entry with reason
`scope_cap`.

**Ranking (D-051).** A question is matched lexically by BM25 over the
gathered candidates — the document is what the pack renders: the
predicate name split on its separators (`runs_os` → *runs*, *os*), the
object and the subject key — so a rare term outweighs a common one and
"which port" finds `listens_on_port`. When the serving engine has an
embedder and vectors exist for the gathered rows, cosine is a second leg
and the two are fused by reciprocal rank (k = 60); a fact with no vector
yet earns nothing from that leg and nothing else. Recency (30-day
half-life, relative to the newest gathered fact) and source confidence
adjust the fused relevance multiplicatively; document-extracted claims
rank a notch below sender-asserted ones (D-023) and superseded
observations at half (D-050). Packing is value per charged token with a
diversity term: once a predicate holds three items, further items of it
compete at half their value, so twenty near-identical logins no longer
crowd out a relevant fact of another kind.

**Pages past the gather cap (D-051).** An entity in `truncated` also gets
a `more` handle whose payload carries the edge of the examined window;
expanding it returns the next window — the rows observed at or before
that instant, ranked for the same question — with its own next-page
handle, until the count says the window was the last. The boundary
instant is re-read rather than risk losing rows that share it. Thread
handles minted inside a page stay in that page's window.

Item `kind` ∈ `brief | fact | relation | doc_excerpt | conflict`. A
`relation` is an edge a scope was expanded through, shipped right before
the first fact about the entity it reached, so a multi-hop pack reads as a
chain (D-035). **Every
item carries at least one citation** (D-023): facts and conflicts cite
observations, briefs cite the observations they were synthesized from,
excerpts cite an artifact span. A `Citation` therefore names either an
`observation_id` or an `artifact_id` (+ span). Conflicts are items, not
merged away — and one that doesn't fit the budget becomes a `conflict`
handle rather than disappearing. A conflict is two or more sources
asserting different values for one predicate over a shared instant of
validity; values are compared normalized (`Ubuntu`/`ubuntu`, `true`/`"true"`,
`9.8`/`"9.8"` are one value), and entity-valued predicates count too when
every source asserts a single current object (D-051: `dhcp` says the ip
is web-01's, `arp-scan` says laptop-17's) — an edge one source itself
gives several objects (logins, the products a CVE affects) is a set, and
another source's different object is an addition. Handles feed
`POST /v1/expand`; with `LOOMCTX_HANDLE_SECRET` set they are signed (`h2_`
prefix, D-021). At most 32 handles ship, within their budget share, in
priority order (conflicts, pages past the gather cap, excerpts, then the
most skipped threads); `omitted_handles` counts the rest, so a scope over
a hub entity says "and 8,000 more threads" instead of shipping them
(D-035).
`truncated` lists entities whose observations exceeded the gather limit:
only the newest `gathered` of `total` were examined, at that subject, at
a hop of a scope, or under an expanded handle. Partial coverage is a fact
the reader needs — an agent must not conclude absence there (D-038). The
MCP view renders it as a `coverage_warning`; the answering prompt as a
`coverage:` line.

## Path: connecting two entities (D-067)

**PathRequest:** `{namespace, from (EntityRef, serialized as `from`), to
(EntityRef), via (list of predicates to traverse; empty = the namespace's
containment predicates), depth (max edges, clamped to the scope cap 3),
max_paths (default 8), budget (tokens), as_of?, valid_at?}`. **PathPack:**
`{namespace, from, to, paths: [[PathEdge]] (each an ordered edge sequence,
shortest first), charged_tokens, truncated, node_status, notes}`, where a **PathEdge** is
`{subject, predicate, object, cite, valid_from?, valid_to?, source}` — the
observation exactly as stored, never re-oriented.

`POST /v1/path` answers "what connects A to B?" — the KEV `host → product →
cve` chain, the AD `user → group → (ACE) → domain` chain — with the
connecting edge sequence(s) directly, instead of leaving an agent to
reassemble them from a scope pack. A bounded, shortest-first search over the
same gather/walk machinery `build_pack`/`resolve_scope` use, grown from **both
ends** and joined where they meet (D-080: each round extends the side with
fewer edges to follow, so a start whose groups include one holding every user
is met from the target's side): it follows `via` edges in **both** directions
(`affects` is stored cve→product but walked product→cve), simple paths only
(a cycle never loops), never turning back along the same predicate at an
entity (`user -member_of-> group <-member_of- admin` is a shared group, not
a route; `siblings: true` allows it), capped by `depth` (default 4, at most
6),
`max_paths`, `budget` (charged on the rendered path text + citations, like a
pack) and the `LOOMCTX_MAX_SCOPE_*` caps. Every edge is **cited** (hard
constraint 3) and time-scoped; `as_of`/`valid_at` filter each edge and a
superseded one (D-050) never appears; a path through a type-gated entity is
not returned. Cuts land in `truncated` (`max_paths`/`depth`/`scope_cap`/
`gather_limit`), request advice in `notes` (an unknown `via` with close
matches, an unknown endpoint, "no path found within depth N"). It is
domain-agnostic and honest: it enumerates paths that EXIST along the named
predicates — it does **not** rank, score, or weight edges by exploitability.
`node_status` carries, for every entity on a returned path, its newest
visible value of each predicate the registry marks `node_status` (an
account's `enabled`), cited and charged: a path through a disabled account
is returned — it may still matter — and says so.

Coverage (D-082) rides as ordinary claims — `coverage:collection
-collected-> "<predicate>"`, attrs `source`, `scope`, `with`, `of`, `state` —
written by connectors; a pack's or a path's `notes` start `coverage:` when a
predicate it walks (or a status it reports) was not fully collected. So do
import shapes (D-085, `coverage:shapes -shape-> "<source kind>"`, attrs
`fields`, `objects`) and identifiers (D-083: `<entity> -identified_by->
identifier:<kind>:<value>`, `<host> -has_ip-> ip:<address>`) — conventions
over the existing envelope, not new contract types.

A scope walk (`ScopeSpec`) follows the same no-turn-back rule unless
`siblings: true`: from a user, `member_of` climbs to its groups and their
parents, not back down to every co-member (through a group holding every
user that was the whole directory, D-080).

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

## Supersession: a claim that corrects an earlier observation

`ClaimIn.supersedes` names an earlier observation this one corrects or
replaces (D-050). It is recorded, never inferred: the old row stays for
audit and for `as_of` reads before the correction, but is no longer
current. Ingest validates it at the door — `/v1/ingest` answers `422`,
a batch rejects the item — unless it names a *visible* observation in
the same namespace about the same subject (a batch validates against the
store, so an item cannot supersede one recorded earlier in the same
batch). On the read side, an observation that a visible later observation
supersedes is excluded from conflict detection (a corrected value is not
a side), ranks as history (half score), and renders with a
`[superseded by <cite>]` suffix; for an `as_of` earlier than the
correction it is current again. The store column that persists the field
lands with the store work of the same decision.

## Provenance export: `GET /v1/observations/{id}/prov`

One observation's provenance as JSON-LD in the W3C PROV-O vocabulary
(D-050), for lineage tools that should not have to learn LoomCtx's
contracts. Namespace comes from `X-LoomCtx-Namespace` or `?namespace=`;
the route is gated like the raw observations route (a type-scoped reader
gets `404` for an observation touching an entity outside their world).
The body is a plain object, not a contract model:

```json
{"@context": {"prov": "http://www.w3.org/ns/prov#", "xsd": "…", "loomctx": "urn:loomctx:"},
 "@graph": [
   {"@id": "loomctx:netsec/observation/<id>", "@type": "prov:Entity",
    "prov:generatedAtTime": {"@value": "2026-09-01T14:03:00+00:00", "@type": "xsd:dateTime"},
    "prov:wasAttributedTo": {"@id": "loomctx:netsec/agent/auth-log"},
    "prov:wasDerivedFrom": {"@id": "loomctx:netsec/artifact/<artifact>#char=118,203"},
    "prov:wasGeneratedBy": {"@id": "loomctx:netsec/activity/extraction%2F<id>"},
    "prov:wasRevisionOf": {"@id": "loomctx:netsec/observation/<older id>"},
    "loomctx:subject": {"@id": "loomctx:netsec/entity/host%3Aweb-01"}, "loomctx:predicate": "runs_os",
    "loomctx:object": "fedora-44", "loomctx:confidence": 1.0, "loomctx:recordedAt": {"…": "…"}},
   {"@id": "loomctx:netsec/agent/auth-log", "@type": "prov:Agent", "loomctx:source": "auth-log"},
   {"@id": "loomctx:netsec/observation/<older id>", "@type": "prov:Entity",
    "prov:wasInvalidatedBy": {"@id": "loomctx:netsec/activity/supersession%2F<id>"}}
 ]}
```

`prov:wasDerivedFrom` (the artifact span) appears only when the
observation carries provenance; the `extraction` `prov:Activity` (with
the extractor model as a `prov:SoftwareAgent` when `attrs` name one) only
for document-extracted claims; the revision/invalidation pair only when
`supersedes` is set. Nothing is invented for a plain sender-asserted claim.

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
