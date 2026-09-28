/* eslint-disable */
/**
 * GENERATED from contracts/schemas.json by scripts/gen.mjs — do not edit.
 * Source of truth: src/loomctx/contracts.py (docs/contracts.md).
 */

export type IngestEnvelope = ClaimIn | DocumentIn;

/**
 * All LoomCtx contract roots (generated wrapper; use the named exports).
 */
export interface LoomCtxContracts {
  IngestEnvelope?: IngestEnvelope;
  Observation?: Observation;
  Entity?: Entity;
  Artifact?: Artifact;
  AskRequest?: AskRequest;
  ExpandRequest?: ExpandRequest;
  ContextPack?: ContextPack;
  PathRequest?: PathRequest;
  PathPack?: PathPack;
  AnswerRequest?: AnswerRequest;
  AnswerResponse?: AnswerResponse;
  SemanticSearchResponse?: SemanticSearchResponse;
  SchemaRegistration?: SchemaRegistration;
  IngestBatchResponse?: IngestBatchResponse;
}
/**
 * Structured, entity-addressed ingestion payload. Maps ~1:1 to an Observation.
 *
 * This interface was referenced by `LoomCtxContracts`'s JSON-Schema
 * via the `definition` "ClaimIn".
 */
export interface ClaimIn {
  kind?: "claim";
  namespace?: string;
  /**
   * sender-supplied idempotency key; redelivery of the same (namespace, event_id) is deduplicated instead of duplicated (D-014)
   */
  event_id?: string | null;
  subject: EntityRef;
  predicate: string;
  object: EntityRef | string | number | boolean;
  observed_at: string;
  valid_from?: string | null;
  valid_to?: string | null;
  source: string;
  confidence?: number;
  provenance?: Provenance | null;
  /**
   * id of an earlier observation this one corrects or replaces (same namespace). Recorded, never inferred: the old row stays for audit and for as_of reads before this one, but is no longer current — it drops out of conflict detection and ranks as history (D-050)
   */
  supersedes?: string | null;
  attrs?: {
    [k: string]: unknown;
  };
}
/**
 * Address of an entity by natural key, e.g. host:web-01.
 *
 * This interface was referenced by `LoomCtxContracts`'s JSON-Schema
 * via the `definition` "EntityRef".
 */
export interface EntityRef {
  type: string;
  key: string;
}
/**
 * Where an observation came from: an artifact and, optionally, a span.
 * Extracted claims carry the artifact's id; a sender that ingests a
 * document and structured claims about it in the same pipeline does not
 * know the id yet, so it may cite the document by its own `event_id`
 * instead — resolved to `artifact_id` at ingest (D-039). The document
 * must land first (same batch is fine: documents are stored before the
 * batch's claims); an unresolvable reference rejects the claim.
 *
 * This interface was referenced by `LoomCtxContracts`'s JSON-Schema
 * via the `definition` "Provenance".
 */
export interface Provenance {
  artifact_id?: string | null;
  artifact_event_id?: string | null;
  span_start?: number | null;
  span_end?: number | null;
}
/**
 * Unstructured ingestion payload. Stored verbatim as an artifact, mined async.
 *
 * This interface was referenced by `LoomCtxContracts`'s JSON-Schema
 * via the `definition` "DocumentIn".
 */
export interface DocumentIn {
  kind?: "document";
  namespace?: string;
  event_id?: string | null;
  text?: string | null;
  content_b64?: string | null;
  content_type?: string;
  filename?: string | null;
  source: string;
  observed_at: string;
  attrs?: {
    [k: string]: unknown;
  };
}
/**
 * Immutable stored fact. Never edited, only superseded.
 */
export interface Observation {
  id: string;
  namespace: string;
  event_id?: string | null;
  subject: EntityRef;
  predicate: string;
  object: EntityRef | string | number | boolean;
  observed_at: string;
  valid_from?: string | null;
  valid_to?: string | null;
  recorded_at: string;
  source: string;
  confidence: number;
  provenance?: Provenance | null;
  /**
   * id of an earlier observation this one corrects or replaces (same namespace). Recorded, never inferred: the old row stays for audit and for as_of reads before this one, but is no longer current — it drops out of conflict detection and ranks as history (D-050)
   */
  supersedes?: string | null;
  attrs?: {
    [k: string]: unknown;
  };
}
/**
 * Canonical graph node produced by entity resolution.
 */
export interface Entity {
  id: string;
  namespace: string;
  type: string;
  key: string;
  aliases?: string[];
  provisional?: boolean;
  created_at: string;
}
/**
 * A stored document: verbatim content plus extraction lifecycle status.
 * extraction_attempts counts failed extraction tries (the worker backs off
 * per attempt and dead-letters as `failed` after a bound, H-D4).
 */
export interface Artifact {
  id: string;
  namespace: string;
  event_id?: string | null;
  filename?: string | null;
  content_type: string;
  text?: string | null;
  content_b64?: string | null;
  source: string;
  observed_at: string;
  recorded_at: string;
  extraction_status?: "pending" | "done" | "failed" | "skipped";
  extraction_attempts?: number;
  attrs?: {
    [k: string]: unknown;
  };
}
/**
 * Two time axes (docs/architecture.md, D-024/D-046): `as_of` = what did
 * we KNOW at T, measured on observation time (`observed_at <= as_of`:
 * when the source asserted it), the closest proxy to knowledge time for
 * backfilled corpora, where `recorded_at` is load day; `recorded_at`
 * remains the audit column. `valid_at` = what was TRUE at T (fact time —
 * only observations whose validity window covers T survive, and facts
 * with no window at all are kept). A fact scheduled for after T but
 * asserted before it is part of the `as_of` view; hiding it is
 * `valid_at`'s job.
 */
export interface AskRequest {
  namespace?: string;
  subject?: EntityRef | null;
  scope?: ScopeSpec | null;
  question: string;
  /**
   * token budget; mandatory cap (LOOMCTX_MAX_BUDGET is the real ceiling)
   */
  budget?: number;
  as_of?: string | null;
  valid_at?: string | null;
}
/**
 * The set of entities a question is about — several computers, or an
 * anchor plus everything related to it ("domain X and its contents").
 *
 * `expand` names the containment/relational predicates to follow outward
 * from the subjects (e.g. ["member_of"]); `depth` bounds the traversal.
 *
 * This interface was referenced by `LoomCtxContracts`'s JSON-Schema
 * via the `definition` "ScopeSpec".
 */
export interface ScopeSpec {
  /**
   * anchors of the scope; bounded so one request cannot name a whole namespace (expansion is how a scope grows, D-046)
   *
   * @minItems 1
   * @maxItems 500
   */
  subjects: [EntityRef, ...EntityRef[]];
  expand?: string[];
  depth?: number;
  /**
   * also turn back along the same predicate at a reached entity — user -member_of-> group <-member_of- every other member. Off by default: through a group that holds every user it pulls the whole directory into the scope (D-080)
   */
  siblings?: boolean;
  /**
   * also traverse edges that were extracted from documents (D-023 second-class witnesses); off by default so a hostile document cannot rewrite the topology a scope walks (D-046)
   */
  follow_extracted?: boolean;
}
export interface ExpandRequest {
  handle: string;
  budget?: number;
}
/**
 * The unit of retrieval: budgeted, ranked, cited, expandable.
 *
 * This interface was referenced by `LoomCtxContracts`'s JSON-Schema
 * via the `definition` "ContextPack".
 */
export interface ContextPack {
  namespace: string;
  subject?: EntityRef | null;
  subjects?: EntityRef[];
  question?: string | null;
  as_of?: string | null;
  valid_at?: string | null;
  budget: number;
  items?: ContextItem[];
  handles?: ExpansionHandle[];
  /**
   * expansion threads that existed beyond the handle cap; narrow the scope or raise the budget to see them (D-035)
   */
  omitted_handles?: number;
  /**
   * entities whose observations exceeded the gather limit: coverage is partial there, so absence cannot be concluded (D-038)
   */
  truncated?: ScopeTruncation[];
  /**
   * what the pack charged against `budget`, in its compact rendered form: every item's text plus its citations, and every handle's hint plus id. At most `budget`, with one exception: the first handle always ships (a pack that cut something must say so): when facts cannot be trimmed to make room for it — the budget is under two handles, or conflicts, briefs and excerpts filled it — charged_tokens exceeds `budget` by at most that one handle's cost (D-051, D-058)
   */
  charged_tokens?: number;
  /**
   * entity briefs (dossiers) that exist but were left out: a brief is prose written from every observation it cites, so a type-scoped caller gets it only when it may see all of them, and a brief never takes more than a quarter of the budget (D-058)
   */
  withheld_briefs?: number;
  /**
   * what the pack could not do as asked, and what it did instead: an expand predicate the namespace does not know (with the closest ones it does), an attribute named in expand taken as the question's topic rather than walked, a subject that names no entity. Advice about the request, not evidence: not cited, not charged against the budget (D-064)
   */
  notes?: string[];
}
/**
 * Every item is cited (hard constraint 3): facts and conflicts cite
 * observations, briefs cite the observations they were synthesized from,
 * excerpts cite the artifact span they quote.
 *
 * This interface was referenced by `LoomCtxContracts`'s JSON-Schema
 * via the `definition` "ContextItem".
 */
export interface ContextItem {
  kind: "brief" | "fact" | "relation" | "doc_excerpt" | "conflict";
  text: string;
  score: number;
  /**
   * @minItems 1
   */
  citations: [Citation, ...Citation[]];
}
/**
 * What backs a context item: an observation (facts, conflicts, briefs)
 * or a span of a stored document (excerpts). At least one of
 * observation_id / artifact_id is set (D-023).
 *
 * This interface was referenced by `LoomCtxContracts`'s JSON-Schema
 * via the `definition` "Citation".
 */
export interface Citation {
  observation_id?: string | null;
  artifact_id?: string | null;
  span_start?: number | null;
  span_end?: number | null;
  source: string;
  observed_at: string;
}
/**
 * Opaque 'there is more here' pointer; feed back to expand().
 * kind says what was left out: more observations of one predicate, or a
 * whole conflict that didn't fit the budget (never silently dropped).
 *
 * This interface was referenced by `LoomCtxContracts`'s JSON-Schema
 * via the `definition` "ExpansionHandle".
 */
export interface ExpansionHandle {
  id: string;
  hint: string;
  est_tokens?: number | null;
  kind?: "more" | "conflict" | "excerpt";
}
/**
 * Partial coverage a reader must know about. An entity whose
 * observations exceeded the gather limit: only the newest `gathered` of
 * `total` were examined. A reader must not conclude absence about it —
 * "no KEV fact among the kernel's CVEs" means nothing when 1,740 of 2,740
 * were never looked at (D-038). A scope walk cut by the entity cap is
 * reported the same way, with reason `scope_cap` (D-058).
 *
 * This interface was referenced by `LoomCtxContracts`'s JSON-Schema
 * via the `definition` "ScopeTruncation".
 */
export interface ScopeTruncation {
  entity: EntityRef;
  gathered: number;
  total: number;
  /**
   * gather_limit: only the newest `gathered` of the `total` observations about `entity` that this caller may see were examined (D-038). scope_cap: the scope walk stopped at the entity cap (LOOMCTX_MAX_SCOPE_ENTITIES / LOOMCTX_MAX_SCOPE_OBSERVATIONS) while expanding `entity` — `gathered` entities are in the pack of at least `total` reached (D-058). max_paths: a path search found more connecting paths to `entity` (the `to` endpoint) than were returned — `gathered` of at least `total` (the cap, or the token budget, cut the rest, D-067). depth: the search reached the depth cap while the frontier still had unexplored entities, so a longer path may exist (D-067)
   */
  reason?: "gather_limit" | "scope_cap" | "max_paths" | "depth";
}
/**
 * "What connects A to B?" — enumerate the edge sequence(s) that already
 * exist in the data between two entities along the named predicates (D-067).
 * Domain-agnostic (the KEV host -> product -> cve chain, the AD user ->
 * group -> domain chain alike). It reports paths that EXIST; it does not
 * rank, score, or weight edges by exploitability, and emits no such advice.
 * `as_of` / `valid_at` carry the two time axes of AskRequest.
 */
export interface PathRequest {
  namespace?: string;
  from: EntityRef1;
  to: EntityRef;
  /**
   * predicates to traverse (both directions where the edge is naturally reversible, mirroring the scope walk); empty = the namespace's registered containment predicates, like a scope
   */
  via?: string[];
  /**
   * the most edges a path may hold; clamped to the path depth cap (6) and noted when a longer one is asked
   */
  depth?: number;
  /**
   * also allow a path to turn back along the same predicate at an entity — user -member_of-> group <-member_of- admin: a shared group, not a route. Off by default, as in a scope walk (D-080)
   */
  siblings?: boolean;
  /**
   * the most paths to return, shortest first; more found than this is reported in `truncated` (reason max_paths)
   */
  max_paths?: number;
  /**
   * token budget, charged on the rendered path text plus citations exactly as a pack is (LOOMCTX_MAX_BUDGET is the ceiling)
   */
  budget?: number;
  as_of?: string | null;
  valid_at?: string | null;
}
/**
 * Address of an entity by natural key, e.g. host:web-01.
 */
export interface EntityRef1 {
  type: string;
  key: string;
}
/**
 * The connecting edge sequences a PathRequest found, shortest first. Each
 * edge is cited (hard constraint 3) and time-scoped; a superseded edge
 * (D-050) never appears and `as_of` / `valid_at` filter every edge. `notes`
 * carry the same request advice a pack does (D-064): an unknown `via`
 * predicate with close matches, an unknown from/to entity, "no path found
 * within depth N", a `to` a longer depth might reach.
 */
export interface PathPack {
  namespace: string;
  from: EntityRef;
  to: EntityRef;
  paths?: PathEdge[][];
  /**
   * what the returned paths charged against `budget`: every edge's rendered text plus its citation, summed (D-067)
   */
  charged_tokens?: number;
  /**
   * what the search could not fully return: a hub whose edges the gather cap only partly examined (gather_limit), the walk cut at the entity/observation cap (scope_cap), more paths than max_paths or the budget allowed (max_paths), or the depth cap reached with the frontier still open (depth)
   */
  truncated?: ScopeTruncation[];
  /**
   * for every entity on a returned path, its current value of each predicate the registry marks `node_status` (an account's `enabled`, say), cited and charged against the budget: a path through a disabled account is returned, and says so (D-080)
   */
  node_status?: NodeStatus[];
  /**
   * what the search could not do as asked, and what it did instead — advice about the request, not evidence: not cited, not charged against the budget (D-064, D-067)
   */
  notes?: string[];
}
/**
 * One edge of a path, exactly as it is stored (never re-oriented): the
 * observation's `subject` `predicate` `object`, cited and time-scoped. The
 * traversal direction is implied by the edge's place in the sequence — an
 * `affects` edge (cve -> product) walked product -> cve still renders
 * cve affects product, so the reader sees the fact as recorded (D-067).
 *
 * This interface was referenced by `LoomCtxContracts`'s JSON-Schema
 * via the `definition` "PathEdge".
 */
export interface PathEdge {
  subject: EntityRef;
  predicate: string;
  object: EntityRef | string | number | boolean;
  cite: Citation;
  valid_from?: string | null;
  valid_to?: string | null;
  source: string;
}
/**
 * A status fact about an entity a path passes through (D-080): the
 * newest visible value of a `node_status` predicate, as stored and cited.
 *
 * This interface was referenced by `LoomCtxContracts`'s JSON-Schema
 * via the `definition` "NodeStatus".
 */
export interface NodeStatus {
  entity: EntityRef;
  predicate: string;
  value: EntityRef | string | number | boolean;
  cite: Citation;
}
/**
 * Ask + synthesize: retrieve a context pack, then have the configured
 * LLM produce a cited answer/decision. With neither subject nor scope,
 * subjects are auto-resolved from entity names mentioned in the question.
 */
export interface AnswerRequest {
  namespace?: string;
  question: string;
  subject?: EntityRef | null;
  scope?: ScopeSpec | null;
  budget?: number;
  as_of?: string | null;
  valid_at?: string | null;
  max_tokens?: number;
}
export interface AnswerResponse {
  answer: string;
  model: string;
  pack: ContextPack;
}
export interface SemanticSearchResponse {
  namespace: string;
  question: string;
  matches?: SemanticMatch[];
}
/**
 * An entity surfaced by meaning rather than by name (D-025): the best
 * matching fact is the evidence, cited like any pack item.
 *
 * This interface was referenced by `LoomCtxContracts`'s JSON-Schema
 * via the `definition` "SemanticMatch".
 */
export interface SemanticMatch {
  entity: EntityRef;
  score: number;
  evidence: ContextItem;
}
/**
 * Per-namespace registry (D-024). Registering is additive (a later POST
 * merges by name). Validation on ingest: a registered predicate's
 * object_types are always enforced; with `strict` the namespace also
 * rejects unregistered predicates and entity types.
 */
export interface SchemaRegistration {
  namespace?: string;
  entity_types?: EntityTypeDef[];
  predicates?: PredicateDef[];
  strict?: boolean;
}
/**
 * This interface was referenced by `LoomCtxContracts`'s JSON-Schema
 * via the `definition` "EntityTypeDef".
 */
export interface EntityTypeDef {
  name: string;
  description?: string;
  facets?: string[];
}
/**
 * This interface was referenced by `LoomCtxContracts`'s JSON-Schema
 * via the `definition` "PredicateDef".
 */
export interface PredicateDef {
  name: string;
  description?: string;
  /**
   * allowed object entity types; empty = any entity or scalar
   */
  object_types?: string[];
  /**
   * a 'contains / member of' relation: scopes with no explicit `expand` follow every containment predicate (D-012/D-024)
   */
  containment?: boolean;
  /**
   * a scalar that qualifies an entity as a step on a path (an account's `enabled`): find_path reports each path entity's current value of it, cited (D-080)
   */
  node_status?: boolean;
  /**
   * a scalar that names its subject (a sAMAccountName, displayName, UPN, login): entity search matches its values as well as keys, so an entity keyed by an opaque id (a SID, a GUID) can be found by name (D-091)
   */
  label?: boolean;
  /**
   * the label a pack shows beside its subject's opaque key, over the namespace's other labels: a name that says where the entity lives (`dlee@dev.local`, a UPN) rather than a bare login that reads the same in every domain (D-097)
   */
  display?: boolean;
}
export interface IngestBatchResponse {
  total: number;
  recorded: number;
  accepted: number;
  rejected: number;
  results?: IngestItemResult[];
}
/**
 * Outcome of one envelope in a batch (D-034). `rejected` items carry
 * the reason; the rest of the batch still lands — a shipper's bad record
 * never blocks its good ones.
 *
 * This interface was referenced by `LoomCtxContracts`'s JSON-Schema
 * via the `definition` "IngestItemResult".
 */
export interface IngestItemResult {
  index: number;
  status: "recorded" | "accepted" | "rejected";
  observation_id?: string | null;
  artifact_id?: string | null;
  detail?: string | null;
}
