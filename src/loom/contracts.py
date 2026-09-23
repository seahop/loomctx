"""The data contracts. These models ARE the framework's API (see docs/contracts.md).

Every surface (HTTP, MCP, SDK, CLI) serializes exactly these shapes. Breaking a
contract is a versioned event recorded in docs/decisions.md, not a refactor.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, Field, model_validator

DEFAULT_NAMESPACE = "default"
MAX_DOCUMENT_CHARS = 1_000_000          # ~1 MB of text per document envelope
MAX_DOCUMENT_B64 = 1_400_000            # base64 of ~1 MB of bytes
# Clock skew a sender may have; beyond it observed_at is a typo or a poison
# pill for recency ranking (D-046). valid_from/valid_to are never bounded:
# a lease or a maintenance window is legitimately scheduled ahead.
MAX_FUTURE_OBSERVED = timedelta(hours=24)


def _not_in_the_future(observed_at: datetime) -> None:
    when = observed_at if observed_at.tzinfo else observed_at.replace(tzinfo=timezone.utc)
    if when > datetime.now(timezone.utc) + MAX_FUTURE_OBSERVED:
        raise ValueError("observed_at is in the future")


class EntityRef(BaseModel):
    """Address of an entity by natural key, e.g. host:web-01."""

    type: str
    key: str


Scalar = Union[str, int, float, bool]
ObjectValue = Union[EntityRef, Scalar]


class Provenance(BaseModel):
    """Where an observation came from: an artifact and, optionally, a span.
    Extracted claims carry the artifact's id; a sender that ingests a
    document and structured claims about it in the same pipeline does not
    know the id yet, so it may cite the document by its own `event_id`
    instead — resolved to `artifact_id` at ingest (D-039). The document
    must land first (same batch is fine: documents are stored before the
    batch's claims); an unresolvable reference rejects the claim."""

    artifact_id: str | None = None
    artifact_event_id: str | None = Field(default=None, max_length=128)
    span_start: int | None = None
    span_end: int | None = None

    @model_validator(mode="after")
    def _one_reference(self) -> "Provenance":
        if not self.artifact_id and not self.artifact_event_id:
            raise ValueError("provenance needs artifact_id or artifact_event_id")
        return self


class ClaimIn(BaseModel):
    """Structured, entity-addressed ingestion payload. Maps ~1:1 to an Observation."""

    kind: Literal["claim"] = "claim"
    namespace: str = DEFAULT_NAMESPACE
    event_id: str | None = Field(
        default=None,
        max_length=128,
        description="sender-supplied idempotency key; redelivery of the same "
        "(namespace, event_id) is deduplicated instead of duplicated (D-014)",
    )
    subject: EntityRef
    predicate: str
    object: ObjectValue
    observed_at: datetime
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    source: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    provenance: Provenance | None = None
    attrs: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _observed_in_the_past(self) -> "ClaimIn":
        _not_in_the_future(self.observed_at)
        return self


class DocumentIn(BaseModel):
    """Unstructured ingestion payload. Stored verbatim as an artifact, mined async."""

    kind: Literal["document"] = "document"
    namespace: str = DEFAULT_NAMESPACE
    event_id: str | None = Field(default=None, max_length=128)
    # Bounded so one envelope can't be arbitrarily large (H-A14); the Go
    # gateway's LOOM_MAX_BODY_BYTES (1 MiB default) and the engine's
    # LOOM_MAX_BODY_BYTES guard the wire, this guards the contract.
    text: str | None = Field(default=None, max_length=MAX_DOCUMENT_CHARS)
    content_b64: str | None = Field(default=None, max_length=MAX_DOCUMENT_B64)
    content_type: str = "text/plain"
    filename: str | None = None
    source: str
    observed_at: datetime
    attrs: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _exactly_one_body(self) -> "DocumentIn":
        if (self.text is None) == (self.content_b64 is None):
            raise ValueError("provide exactly one of 'text' or 'content_b64'")
        _not_in_the_future(self.observed_at)
        return self


IngestEnvelope = Annotated[Union[ClaimIn, DocumentIn], Field(discriminator="kind")]

MAX_BATCH_ITEMS = 1000


class IngestItemResult(BaseModel):
    """Outcome of one envelope in a batch (D-034). `rejected` items carry
    the reason; the rest of the batch still lands — a shipper's bad record
    never blocks its good ones."""

    index: int
    status: Literal["recorded", "accepted", "rejected"]
    observation_id: str | None = None
    artifact_id: str | None = None
    detail: str | None = None


class IngestBatchResponse(BaseModel):
    total: int
    recorded: int
    accepted: int
    rejected: int
    results: list[IngestItemResult] = Field(default_factory=list)


class Observation(BaseModel):
    """Immutable stored fact. Never edited, only superseded."""

    id: str
    namespace: str
    event_id: str | None = None
    subject: EntityRef
    predicate: str
    object: ObjectValue
    observed_at: datetime
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    recorded_at: datetime
    source: str
    confidence: float
    provenance: Provenance | None = None
    attrs: dict[str, Any] = Field(default_factory=dict)


class Artifact(BaseModel):
    """A stored document: verbatim content plus extraction lifecycle status.
    extraction_attempts counts failed extraction tries (the worker backs off
    per attempt and dead-letters as `failed` after a bound, H-D4)."""

    id: str
    namespace: str
    event_id: str | None = None
    filename: str | None = None
    content_type: str
    text: str | None = None
    content_b64: str | None = None
    source: str
    observed_at: datetime
    recorded_at: datetime
    extraction_status: Literal["pending", "done", "failed", "skipped"] = "pending"
    extraction_attempts: int = 0
    attrs: dict[str, Any] = Field(default_factory=dict)


class Entity(BaseModel):
    """Canonical graph node produced by entity resolution."""

    id: str
    namespace: str
    type: str
    key: str
    aliases: list[str] = Field(default_factory=list)
    provisional: bool = False
    created_at: datetime


# --------------------------------------------------------------------------- #
# Read side (context packs) — shapes are contract now, behavior lands phase 2 #
# --------------------------------------------------------------------------- #

class Citation(BaseModel):
    """What backs a context item: an observation (facts, conflicts, briefs)
    or a span of a stored document (excerpts). At least one of
    observation_id / artifact_id is set (D-023)."""

    observation_id: str | None = None
    artifact_id: str | None = None
    span_start: int | None = None
    span_end: int | None = None
    source: str
    observed_at: datetime

    @model_validator(mode="after")
    def _cites_something(self) -> "Citation":
        if self.observation_id is None and self.artifact_id is None:
            raise ValueError("a citation names an observation or an artifact")
        return self


class ContextItem(BaseModel):
    """Every item is cited (hard constraint 3): facts and conflicts cite
    observations, briefs cite the observations they were synthesized from,
    excerpts cite the artifact span they quote."""

    kind: Literal["brief", "fact", "relation", "doc_excerpt", "conflict"]
    text: str
    score: float = Field(ge=0.0, le=1.0)
    citations: list[Citation] = Field(min_length=1)


class ExpansionHandle(BaseModel):
    """Opaque 'there is more here' pointer; feed back to expand().
    kind says what was left out: more observations of one predicate, or a
    whole conflict that didn't fit the budget (never silently dropped)."""

    id: str
    hint: str
    est_tokens: int | None = None
    kind: Literal["more", "conflict", "excerpt"] = "more"


class ScopeSpec(BaseModel):
    """The set of entities a question is about — several computers, or an
    anchor plus everything related to it ("domain X and its contents").

    `expand` names the containment/relational predicates to follow outward
    from the subjects (e.g. ["member_of"]); `depth` bounds the traversal.
    """

    subjects: list[EntityRef] = Field(min_length=1)
    expand: list[str] = Field(default_factory=list)
    depth: int = Field(default=1, ge=0, le=3)


class AskRequest(BaseModel):
    """Two time axes (docs/architecture.md, D-024/D-046): `as_of` = what did
    we KNOW at T, measured on observation time (`observed_at <= as_of`:
    when the source asserted it), the closest proxy to knowledge time for
    backfilled corpora, where `recorded_at` is load day; `recorded_at`
    remains the audit column. `valid_at` = what was TRUE at T (fact time —
    only observations whose validity window covers T survive, and facts
    with no window at all are kept). A fact scheduled for after T but
    asserted before it is part of the `as_of` view; hiding it is
    `valid_at`'s job."""

    namespace: str = DEFAULT_NAMESPACE
    subject: EntityRef | None = None
    scope: ScopeSpec | None = None
    question: str = Field(max_length=2000)
    budget: int = Field(
        default=800, gt=0, le=1_000_000,
        description="token budget; mandatory cap (LOOM_MAX_BUDGET is the real ceiling)"
    )
    as_of: datetime | None = None
    valid_at: datetime | None = None

    @model_validator(mode="after")
    def _subject_or_scope(self) -> "AskRequest":
        if (self.subject is None) == (self.scope is None):
            raise ValueError("provide exactly one of 'subject' or 'scope'")
        return self


class ExpandRequest(BaseModel):
    handle: str = Field(max_length=4096)
    budget: int = Field(default=800, gt=0, le=1_000_000)


class ScopeTruncation(BaseModel):
    """An entity whose observations exceeded the gather limit: only the
    newest `gathered` of `total` were examined. A reader must not conclude
    absence about it — "no KEV fact among the kernel's CVEs" means nothing
    when 1,740 of 2,740 were never looked at (D-038)."""

    entity: EntityRef
    gathered: int = Field(ge=0)
    total: int = Field(ge=0)


class ContextPack(BaseModel):
    """The unit of retrieval: budgeted, ranked, cited, expandable."""

    namespace: str
    subject: EntityRef | None = None  # set for single-subject packs
    subjects: list[EntityRef] = Field(default_factory=list)  # always populated
    question: str | None = None
    as_of: datetime | None = None
    valid_at: datetime | None = None
    budget: int
    items: list[ContextItem] = Field(default_factory=list)
    handles: list[ExpansionHandle] = Field(default_factory=list)
    omitted_handles: int = Field(
        default=0, ge=0,
        description="expansion threads that existed beyond the handle cap; "
        "narrow the scope or raise the budget to see them (D-035)",
    )
    truncated: list[ScopeTruncation] = Field(
        default_factory=list,
        description="entities whose observations exceeded the gather limit: "
        "coverage is partial there, so absence cannot be concluded (D-038)",
    )


class SemanticMatch(BaseModel):
    """An entity surfaced by meaning rather than by name (D-025): the best
    matching fact is the evidence, cited like any pack item."""

    entity: EntityRef
    score: float = Field(ge=0.0, le=1.0)
    evidence: ContextItem


class SemanticSearchResponse(BaseModel):
    namespace: str
    question: str
    matches: list[SemanticMatch] = Field(default_factory=list)


class AnswerRequest(BaseModel):
    """Ask + synthesize: retrieve a context pack, then have the configured
    LLM produce a cited answer/decision. With neither subject nor scope,
    subjects are auto-resolved from entity names mentioned in the question."""

    namespace: str = DEFAULT_NAMESPACE
    question: str = Field(max_length=2000)
    subject: EntityRef | None = None
    scope: ScopeSpec | None = None
    budget: int = Field(default=1200, gt=0, le=1_000_000)
    as_of: datetime | None = None
    valid_at: datetime | None = None
    max_tokens: int = Field(default=1024, gt=0, le=8192)


class AnswerResponse(BaseModel):
    answer: str
    model: str
    pack: ContextPack


# --------------------------------------------------------------------------- #
# Schema registry — what makes the core domain-agnostic                       #
# --------------------------------------------------------------------------- #

class EntityTypeDef(BaseModel):
    name: str
    description: str = ""
    facets: list[str] = Field(default_factory=list)


class PredicateDef(BaseModel):
    name: str
    description: str = ""
    object_types: list[str] = Field(
        default_factory=list,
        description="allowed object entity types; empty = any entity or scalar",
    )
    containment: bool = Field(
        default=False,
        description="a 'contains / member of' relation: scopes with no "
        "explicit `expand` follow every containment predicate (D-012/D-024)",
    )


class SchemaRegistration(BaseModel):
    """Per-namespace registry (D-024). Registering is additive (a later POST
    merges by name). Validation on ingest: a registered predicate's
    object_types are always enforced; with `strict` the namespace also
    rejects unregistered predicates and entity types."""

    namespace: str = DEFAULT_NAMESPACE
    entity_types: list[EntityTypeDef] = Field(default_factory=list)
    predicates: list[PredicateDef] = Field(default_factory=list)
    strict: bool = False
