/* eslint-disable */
/**
 * GENERATED from contracts/schemas.json by scripts/gen.mjs — do not edit.
 * Source of truth: src/loom/contracts.py (docs/contracts.md).
 */

export type IngestEnvelope = ClaimIn | DocumentIn;

/**
 * All Loom contract roots (generated wrapper; use the named exports).
 */
export interface LoomContracts {
  IngestEnvelope?: IngestEnvelope;
  Observation?: Observation;
  Entity?: Entity;
  Artifact?: Artifact;
  AskRequest?: AskRequest;
  ExpandRequest?: ExpandRequest;
  ContextPack?: ContextPack;
  AnswerRequest?: AnswerRequest;
  AnswerResponse?: AnswerResponse;
  SemanticSearchResponse?: SemanticSearchResponse;
  SchemaRegistration?: SchemaRegistration;
  IngestBatchResponse?: IngestBatchResponse;
}
/**
 * Structured, entity-addressed ingestion payload. Maps ~1:1 to an Observation.
 *
 * This interface was referenced by `LoomContracts`'s JSON-Schema
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
  attrs?: {
    [k: string]: unknown;
  };
}
/**
 * Address of an entity by natural key, e.g. host:web-01.
 *
 * This interface was referenced by `LoomContracts`'s JSON-Schema
 * via the `definition` "EntityRef".
 */
export interface EntityRef {
  type: string;
  key: string;
}
/**
 * Where an extracted observation came from: an artifact and a character span.
 *
 * This interface was referenced by `LoomContracts`'s JSON-Schema
 * via the `definition` "Provenance".
 */
export interface Provenance {
  artifact_id: string;
  span_start?: number | null;
  span_end?: number | null;
}
/**
 * Unstructured ingestion payload. Stored verbatim as an artifact, mined async.
 *
 * This interface was referenced by `LoomContracts`'s JSON-Schema
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
 * Two time axes (docs/architecture.md, D-024): `as_of` = what did we
 * KNOW at T (knowledge time — later-recorded observations are hidden);
 * `valid_at` = what was TRUE at T (fact time — only observations whose
 * validity window covers T survive, and facts with no window at all are
 * kept).
 */
export interface AskRequest {
  namespace?: string;
  subject?: EntityRef | null;
  scope?: ScopeSpec | null;
  question: string;
  /**
   * token budget; mandatory cap (LOOM_MAX_BUDGET is the real ceiling)
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
 * This interface was referenced by `LoomContracts`'s JSON-Schema
 * via the `definition` "ScopeSpec".
 */
export interface ScopeSpec {
  /**
   * @minItems 1
   */
  subjects: [EntityRef, ...EntityRef[]];
  expand?: string[];
  depth?: number;
}
export interface ExpandRequest {
  handle: string;
  budget?: number;
}
/**
 * The unit of retrieval: budgeted, ranked, cited, expandable.
 *
 * This interface was referenced by `LoomContracts`'s JSON-Schema
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
}
/**
 * Every item is cited (hard constraint 3): facts and conflicts cite
 * observations, briefs cite the observations they were synthesized from,
 * excerpts cite the artifact span they quote.
 *
 * This interface was referenced by `LoomContracts`'s JSON-Schema
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
 * This interface was referenced by `LoomContracts`'s JSON-Schema
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
 * This interface was referenced by `LoomContracts`'s JSON-Schema
 * via the `definition` "ExpansionHandle".
 */
export interface ExpansionHandle {
  id: string;
  hint: string;
  est_tokens?: number | null;
  kind?: "more" | "conflict" | "excerpt";
}
/**
 * An entity whose observations exceeded the gather limit: only the
 * newest `gathered` of `total` were examined. A reader must not conclude
 * absence about it — "no KEV fact among the kernel's CVEs" means nothing
 * when 1,740 of 2,740 were never looked at (D-038).
 *
 * This interface was referenced by `LoomContracts`'s JSON-Schema
 * via the `definition` "ScopeTruncation".
 */
export interface ScopeTruncation {
  entity: EntityRef;
  gathered: number;
  total: number;
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
 * This interface was referenced by `LoomContracts`'s JSON-Schema
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
 * This interface was referenced by `LoomContracts`'s JSON-Schema
 * via the `definition` "EntityTypeDef".
 */
export interface EntityTypeDef {
  name: string;
  description?: string;
  facets?: string[];
}
/**
 * This interface was referenced by `LoomContracts`'s JSON-Schema
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
 * This interface was referenced by `LoomContracts`'s JSON-Schema
 * via the `definition` "IngestItemResult".
 */
export interface IngestItemResult {
  index: number;
  status: "recorded" | "accepted" | "rejected";
  observation_id?: string | null;
  artifact_id?: string | null;
  detail?: string | null;
}
