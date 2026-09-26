"""The data contracts. These models ARE the framework's API (see docs/contracts.md).

Every surface (HTTP, MCP, SDK, CLI) serializes exactly these shapes. Breaking a
contract is a versioned event recorded in docs/decisions.md, not a refactor.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, model_validator

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
    supersedes: str | None = Field(
        default=None, max_length=64,
        description="id of an earlier observation this one corrects or replaces "
        "(same namespace). Recorded, never inferred: the old row stays for audit and "
        "for as_of reads before this one, but is no longer current — it drops out of "
        "conflict detection and ranks as history (D-050)",
    )
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
    supersedes: str | None = Field(
        default=None, max_length=64,
        description="id of an earlier observation this one corrects or replaces "
        "(same namespace). Recorded, never inferred: the old row stays for audit and "
        "for as_of reads before this one, but is no longer current — it drops out of "
        "conflict detection and ranks as history (D-050)",
    )
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

    subjects: list[EntityRef] = Field(
        min_length=1, max_length=500,
        description="anchors of the scope; bounded so one request cannot "
        "name a whole namespace (expansion is how a scope grows, D-046)",
    )
    expand: list[str] = Field(default_factory=list)
    depth: int = Field(default=1, ge=0, le=3)
    follow_extracted: bool = Field(
        default=False,
        description="also traverse edges that were extracted from documents "
        "(D-023 second-class witnesses); off by default so a hostile "
        "document cannot rewrite the topology a scope walks (D-046)",
    )


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
    """Partial coverage a reader must know about. An entity whose
    observations exceeded the gather limit: only the newest `gathered` of
    `total` were examined. A reader must not conclude absence about it —
    "no KEV fact among the kernel's CVEs" means nothing when 1,740 of 2,740
    were never looked at (D-038). A scope walk cut by the entity cap is
    reported the same way, with reason `scope_cap` (D-058)."""

    entity: EntityRef
    gathered: int = Field(ge=0)
    total: int = Field(ge=0)
    reason: Literal["gather_limit", "scope_cap", "max_paths", "depth"] = Field(
        default="gather_limit",
        description="gather_limit: only the newest `gathered` of the `total` "
        "observations about `entity` that this caller may see were examined "
        "(D-038). scope_cap: the scope walk stopped at the entity cap "
        "(LOOM_MAX_SCOPE_ENTITIES / LOOM_MAX_SCOPE_OBSERVATIONS) while "
        "expanding `entity` — `gathered` entities are in the pack of at "
        "least `total` reached (D-058). max_paths: a path search found more "
        "connecting paths to `entity` (the `to` endpoint) than were returned "
        "— `gathered` of at least `total` (the cap, or the token budget, cut "
        "the rest, D-067). depth: the search reached the depth cap while the "
        "frontier still had unexplored entities, so a longer path may exist "
        "(D-067)",
    )


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
    charged_tokens: int = Field(
        default=0, ge=0,
        description="what the pack charged against `budget`, in its compact "
        "rendered form: every item's text plus its citations, and every "
        "handle's hint plus id. At most `budget`, with one exception: the "
        "first handle always ships (a pack that cut something must say so): "
        "when facts cannot be trimmed to make room for it — the budget is "
        "under two handles, or conflicts, briefs and excerpts filled it — "
        "charged_tokens exceeds `budget` by at most that one handle's cost "
        "(D-051, D-058)",
    )
    withheld_briefs: int = Field(
        default=0, ge=0,
        description="entity briefs (dossiers) that exist but were left out: "
        "a brief is prose written from every observation it cites, so a "
        "type-scoped caller gets it only when it may see all of them, and a "
        "brief never takes more than a quarter of the budget (D-058)",
    )
    notes: list[str] = Field(
        default_factory=list,
        description="what the pack could not do as asked, and what it did "
        "instead: an expand predicate the namespace does not know (with the "
        "closest ones it does), an attribute named in expand taken as the "
        "question's topic rather than walked, a subject that names no "
        "entity. Advice about the request, not evidence: not cited, not "
        "charged against the budget (D-064)",
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

    @model_validator(mode="after")
    def _subject_or_scope(self) -> "AnswerRequest":
        # neither is fine (auto-resolution); both is ambiguous — and was a 500
        if self.subject is not None and self.scope is not None:
            raise ValueError("provide at most one of 'subject' or 'scope'")
        return self


class AnswerResponse(BaseModel):
    answer: str
    model: str
    pack: ContextPack


# --------------------------------------------------------------------------- #
# Reachability — connecting edge sequences between two entities (D-067)       #
# --------------------------------------------------------------------------- #
# Longest edge sequence a `path` search walks. The scope walk caps depth at 3
# (ScopeSpec.depth); a path request may ask for more but is clamped to this
# and told so in a note.
MAX_PATH_DEPTH = 3


class PathEdge(BaseModel):
    """One edge of a path, exactly as it is stored (never re-oriented): the
    observation's `subject` `predicate` `object`, cited and time-scoped. The
    traversal direction is implied by the edge's place in the sequence — an
    `affects` edge (cve -> product) walked product -> cve still renders
    cve affects product, so the reader sees the fact as recorded (D-067)."""

    subject: EntityRef
    predicate: str
    object: ObjectValue
    cite: Citation
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    source: str


# A path is an ordered edge sequence connecting `from` to `to`.
Path = list[PathEdge]


class PathRequest(BaseModel):
    """"What connects A to B?" — enumerate the edge sequence(s) that already
    exist in the data between two entities along the named predicates (D-067).
    Domain-agnostic (the KEV host -> product -> cve chain, the AD user ->
    group -> domain chain alike). It reports paths that EXIST; it does not
    rank, score, or weight edges by exploitability, and emits no such advice.
    `as_of` / `valid_at` carry the two time axes of AskRequest."""

    model_config = ConfigDict(populate_by_name=True)

    namespace: str = DEFAULT_NAMESPACE
    from_: EntityRef = Field(
        alias="from",
        description="the entity the path starts at (serialized as 'from')",
    )
    to: EntityRef
    via: list[str] = Field(
        default_factory=list,
        description="predicates to traverse (both directions where the edge "
        "is naturally reversible, mirroring the scope walk); empty = the "
        "namespace's registered containment predicates, like a scope",
    )
    depth: int = Field(
        default=MAX_PATH_DEPTH, ge=1, le=32,
        description="the most edges a path may hold; clamped to the scope "
        f"depth cap ({MAX_PATH_DEPTH}) and noted when a longer one is asked",
    )
    max_paths: int = Field(
        default=8, gt=0, le=100,
        description="the most paths to return, shortest first; more found "
        "than this is reported in `truncated` (reason max_paths)",
    )
    budget: int = Field(
        default=800, gt=0, le=1_000_000,
        description="token budget, charged on the rendered path text plus "
        "citations exactly as a pack is (LOOM_MAX_BUDGET is the ceiling)",
    )
    as_of: datetime | None = None
    valid_at: datetime | None = None


class PathPack(BaseModel):
    """The connecting edge sequences a PathRequest found, shortest first. Each
    edge is cited (hard constraint 3) and time-scoped; a superseded edge
    (D-050) never appears and `as_of` / `valid_at` filter every edge. `notes`
    carry the same request advice a pack does (D-064): an unknown `via`
    predicate with close matches, an unknown from/to entity, "no path found
    within depth N", a `to` a longer depth might reach."""

    namespace: str
    from_: EntityRef = Field(alias="from", serialization_alias="from")
    to: EntityRef
    paths: list[Path] = Field(default_factory=list)
    charged_tokens: int = Field(
        default=0, ge=0,
        description="what the returned paths charged against `budget`: every "
        "edge's rendered text plus its citation, summed (D-067)",
    )
    truncated: list[ScopeTruncation] = Field(
        default_factory=list,
        description="what the search could not fully return: a hub whose "
        "edges the gather cap only partly examined (gather_limit), the walk "
        "cut at the entity/observation cap (scope_cap), more paths than "
        "max_paths or the budget allowed (max_paths), or the depth cap "
        "reached with the frontier still open (depth)",
    )
    notes: list[str] = Field(
        default_factory=list,
        description="what the search could not do as asked, and what it did "
        "instead — advice about the request, not evidence: not cited, not "
        "charged against the budget (D-064, D-067)",
    )

    model_config = ConfigDict(populate_by_name=True)


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
