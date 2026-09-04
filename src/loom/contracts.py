"""The data contracts. These models ARE the framework's API (see docs/contracts.md).

Every surface (HTTP, MCP, SDK, CLI) serializes exactly these shapes. Breaking a
contract is a versioned event recorded in docs/decisions.md, not a refactor.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, Field, model_validator

DEFAULT_NAMESPACE = "default"


class EntityRef(BaseModel):
    """Address of an entity by natural key, e.g. host:web-01."""

    type: str
    key: str


Scalar = Union[str, int, float, bool]
ObjectValue = Union[EntityRef, Scalar]


class ClaimIn(BaseModel):
    """Structured, entity-addressed ingestion payload. Maps ~1:1 to an Observation."""

    kind: Literal["claim"] = "claim"
    namespace: str = DEFAULT_NAMESPACE
    subject: EntityRef
    predicate: str
    object: ObjectValue
    observed_at: datetime
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    source: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    attrs: dict[str, Any] = Field(default_factory=dict)


class DocumentIn(BaseModel):
    """Unstructured ingestion payload. Stored verbatim as an artifact, mined async."""

    kind: Literal["document"] = "document"
    namespace: str = DEFAULT_NAMESPACE
    text: str | None = None
    content_b64: str | None = None
    content_type: str = "text/plain"
    filename: str | None = None
    source: str
    observed_at: datetime
    attrs: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _exactly_one_body(self) -> "DocumentIn":
        if (self.text is None) == (self.content_b64 is None):
            raise ValueError("provide exactly one of 'text' or 'content_b64'")
        return self


IngestEnvelope = Annotated[Union[ClaimIn, DocumentIn], Field(discriminator="kind")]


class Provenance(BaseModel):
    """Where an extracted observation came from: an artifact and a character span."""

    artifact_id: str
    span_start: int | None = None
    span_end: int | None = None


class Observation(BaseModel):
    """Immutable stored fact. Never edited, only superseded."""

    id: str
    namespace: str
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
    """A stored document: verbatim content plus extraction lifecycle status."""

    id: str
    namespace: str
    filename: str | None = None
    content_type: str
    text: str | None = None
    content_b64: str | None = None
    source: str
    observed_at: datetime
    recorded_at: datetime
    extraction_status: Literal["pending", "done", "failed"] = "pending"
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
    observation_id: str
    source: str
    observed_at: datetime


class ContextItem(BaseModel):
    kind: Literal["brief", "fact", "relation", "doc_excerpt", "conflict"]
    text: str
    score: float = Field(ge=0.0, le=1.0)
    citations: list[Citation] = Field(default_factory=list)


class ExpansionHandle(BaseModel):
    """Opaque 'there is more here' pointer; feed back to expand()."""

    id: str
    hint: str
    est_tokens: int | None = None


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
    namespace: str = DEFAULT_NAMESPACE
    subject: EntityRef | None = None
    scope: ScopeSpec | None = None
    question: str
    budget: int = Field(default=800, gt=0, description="token budget; mandatory cap")
    as_of: datetime | None = None

    @model_validator(mode="after")
    def _subject_or_scope(self) -> "AskRequest":
        if (self.subject is None) == (self.scope is None):
            raise ValueError("provide exactly one of 'subject' or 'scope'")
        return self


class ExpandRequest(BaseModel):
    handle: str
    budget: int = Field(default=800, gt=0)


class ContextPack(BaseModel):
    """The unit of retrieval: budgeted, ranked, cited, expandable."""

    namespace: str
    subject: EntityRef | None = None  # set for single-subject packs
    subjects: list[EntityRef] = Field(default_factory=list)  # always populated
    question: str | None = None
    as_of: datetime | None = None
    budget: int
    items: list[ContextItem] = Field(default_factory=list)
    handles: list[ExpansionHandle] = Field(default_factory=list)


class AnswerRequest(BaseModel):
    """Ask + synthesize: retrieve a context pack, then have the configured
    LLM produce a cited answer/decision. With neither subject nor scope,
    subjects are auto-resolved from entity names mentioned in the question."""

    namespace: str = DEFAULT_NAMESPACE
    question: str
    subject: EntityRef | None = None
    scope: ScopeSpec | None = None
    budget: int = Field(default=1200, gt=0)
    as_of: datetime | None = None
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


class SchemaRegistration(BaseModel):
    namespace: str = DEFAULT_NAMESPACE
    entity_types: list[EntityTypeDef] = Field(default_factory=list)
    predicates: list[PredicateDef] = Field(default_factory=list)
