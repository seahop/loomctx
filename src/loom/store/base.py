"""The GraphStore interface. All persistence lives behind this (decision D-002).

No code outside src/loom/store/ may touch a database directly. New backends
(Neo4j, Kùzu, ...) implement this ABC and become drop-in via configuration.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Iterator

from ..contracts import (
    Artifact, ClaimIn, DocumentIn, Entity, EntityRef, Observation,
    SchemaRegistration,
)


class GraphStore(ABC):
    @abstractmethod
    def upsert_entity(self, namespace: str, ref: EntityRef) -> Entity:
        """Return the canonical entity for ref, creating it if new."""

    @abstractmethod
    def get_entity(self, namespace: str, ref: EntityRef) -> Entity | None:
        """Resolve by natural key, following alias records from prior merges;
        None if unknown."""

    # ------------------------------------------- entity resolution (D-019)

    @abstractmethod
    def add_alias(self, namespace: str, alias: EntityRef, into: EntityRef) -> None:
        """Record that `alias` (type:key) refers to the canonical `into`."""

    @abstractmethod
    def merge_entities(
        self, namespace: str, from_ref: EntityRef, into_ref: EntityRef
    ) -> bool:
        """Fold `from_ref` into `into_ref`: repoint its observations, record
        it as an alias, delete the now-empty node. Reversible via the alias
        record; no observation is ever lost. False if either side is unknown
        or they are the same entity."""

    @abstractmethod
    def unmerge(self, namespace: str, alias: EntityRef) -> bool:
        """Reverse the merge that folded `alias` (type:key) away — D-019's
        "reversible & lossless", backed by the merge log (schema v5):
        recreate the entity, repoint exactly the observations that merge
        moved, restore their rendered object refs, point the aliases that
        had named it back at it, remove its own alias record, drop both
        entities' dossiers and delete the log rows. False when no merge of
        that ref is on record."""

    @abstractmethod
    def iter_merges(self, namespace: str | None = None) -> Iterator[dict]:
        """One record per reversible merge, oldest first:
        {'id', 'namespace', 'from': {'type','key'}, 'into': {'type','key'},
        'from_id', 'from_provisional', 'from_created_at', 'prior_aliases',
        'recorded_at', 'observations': [{'observation_id',
        'prior_subject_id', 'prior_object_entity_id', 'prior_object_json'}]}
        — exported so a restore keeps merges reversible. The prior_* ids
        are the folded entity's id at the time; unmerge uses their presence
        as the side flag and repoints to the recreated entity's id."""

    @abstractmethod
    def restore_merge(self, record: dict) -> None:
        """Insert an exported merge record verbatim (idempotent by id)."""

    @abstractmethod
    def merge_candidates(
        self, namespace: str | None = None, limit: int = 50
    ) -> list[list[Entity]]:
        """Groups of entities that share a natural key across differing types
        (the drift LLM extraction produces, e.g. ip vs ip_address)."""

    @abstractmethod
    def fuzzy_merge_candidates(
        self, namespace: str | None = None, limit: int = 50
    ) -> list[list[Entity]]:
        """Groups of entities whose *normalized* keys collide but whose raw
        keys differ (web-01 / web01 / WEB_01) — resolution tier 2 (D-024).
        Same-type members are safe to auto-merge; cross-type ones need
        adjudication."""

    # ------------------------------------------------ schema registry (D-024)

    @abstractmethod
    def put_schema(self, registration: SchemaRegistration) -> SchemaRegistration:
        """Merge a registration into the namespace's registry (additive by
        name); returns the effective registry."""

    @abstractmethod
    def get_schema(self, namespace: str) -> SchemaRegistration | None: ...

    @abstractmethod
    def iter_schemas(self, namespace: str | None = None) -> Iterator[SchemaRegistration]:
        """Every namespace's effective registry — part of a faithful
        export (a restore without it would run unregistered)."""

    @abstractmethod
    def namespace_summary(self) -> dict[str, dict[str, int]]:
        """Every namespace that holds entities -> {entity type: count}. What
        an agent needs to orient itself before it can ask anything (D-036)."""

    def relation_summary(self, namespace: str) -> list[tuple[str, str, str | None, int]]:
        """How a namespace is connected (D-064): (subject type, predicate,
        object type — None for a value —, visible observations) for every
        combination that occurs, most frequent first. What describe_namespace
        shows an agent so a two-hop path (host -runs_software-> product
        <-affects- cve) is visible before it asks; the registry names a
        predicate's object types but never its subjects. Backends answer it
        with one GROUP BY; this default reads every observation."""
        from collections import Counter
        dead = {t["observation_id"] for t in self.iter_tombstones(namespace)}
        counts: Counter = Counter()
        for o in self.iter_observations(namespace):
            if o.id not in dead:
                counts[(o.subject.type, o.predicate,
                        o.object.type if isinstance(o.object, EntityRef) else None)] += 1
        return sorted(((s, p, t, n) for (s, p, t), n in counts.items()),
                      key=lambda r: (-r[3], r[0], r[1], r[2] or ""))

    @abstractmethod
    def record_claim(self, claim: ClaimIn) -> Observation:
        """Append one observation (auto-creating subject/object entities).

        With an event_id, a replay returns the original observation instead
        of appending (D-014) — race-safe across writer processes. If that
        original has since been redacted, the returned observation is a
        stand-in carrying the id but no content (object "[redacted]",
        attrs {"redacted": true}): replaying an event never resurrects data.
        """

    def record_claims(self, claims: list[ClaimIn]) -> list[Observation]:
        """Batch append. Backends override to commit once per batch — the
        difference between one fsync per claim and one per batch (D-011)."""
        return [self.record_claim(c) for c in claims]

    @abstractmethod
    def observations_for(
        self, namespace: str, ref: EntityRef, limit: int = 100,
        observed_before: datetime | None = None,
    ) -> list[Observation]:
        """Observations where ref is subject OR object, newest observed first.
        `observed_before` (the `as_of` axis, D-046) keeps only rows observed
        at or before that instant — applied in the query, so the newest
        `limit` rows are the newest *as of then*, not the newest overall."""

    def observations_for_many(
        self, namespace: str, refs: list[EntityRef], limit: int = 100,
        observed_before: datetime | None = None,
        predicates: list[str] | None = None,
    ) -> dict[tuple[str, str], list[Observation]]:
        """observations_for for many refs at once: (type, key) -> its newest
        `limit` observations. Backends override with one round trip per
        chunk; a 1,077-entity scope was 1,077 round trips, 5 s on Postgres
        over a network versus 0.5 s in-process (D-043). Refs that resolve
        to nothing are absent from the result. `predicates` keeps only rows
        on those predicates — the newest `limit` of *them* per entity, the
        filter applied in the query (D-061: a scope walk fetches a hub's
        edges past its gather window, and the attributes a question names
        on the entities at their far end)."""
        if predicates is None:
            return {(r.type, r.key): self.observations_for(namespace, r, limit, observed_before=observed_before)
                    for r in refs}
        wanted = set(predicates)
        out: dict[tuple[str, str], list[Observation]] = {}
        for r in refs:
            rows = [o for o in self.observations_for(namespace, r, 2 ** 31 - 1, observed_before=observed_before)
                    if o.predicate in wanted][:limit]
            if rows:
                out[(r.type, r.key)] = rows
        return out

    def edges_to_carriers(
        self, namespace: str, hubs: list[EntityRef], via: list[str], predicates: list[str],
        limit: int = 10_000, observed_before: datetime | None = None,
    ) -> list[tuple[tuple[str, str], str, str]]:
        """For each hub, its newest `limit` edges on `via` predicates (either
        direction) whose far end is the subject of a row on one of
        `predicates`: (hub (type, key), edge id, that row's id), newest edge
        first per hub, both rows visible (not tombstoned) and observed at or
        before `observed_before`. A far end with several such rows appears
        once per row. What a scope walk needs to complete a hub its gather
        window cut for the attribute a question names (D-061); backends
        answer it with one indexed join per hub side, so the hub's edges are
        never materialized. This default reads through
        `observations_for_many`."""
        if not hubs or not via or not predicates:
            return []
        edges = self.observations_for_many(namespace, hubs, limit=limit, observed_before=observed_before,
                                           predicates=list(via))
        out: list[tuple[tuple[str, str], str, str]] = []
        for hub in hubs:
            rows = [(o, o.object if o.subject == hub else o.subject)
                    for o in edges.get((hub.type, hub.key), [])]
            rows = [(o, end) for o, end in rows if isinstance(end, EntityRef) and end != hub]
            attrs = self.observations_for_many(namespace, list({(e.type, e.key): e for _, e in rows}.values()),
                                               limit=2 ** 31 - 1, observed_before=observed_before,
                                               predicates=list(predicates))
            for o, end in rows:
                out.extend(((hub.type, hub.key), o.id, a.id)
                           for a in attrs.get((end.type, end.key), []) if a.subject == end)
        return out

    @abstractmethod
    def search_entities(
        self, namespace: str, query: str, limit: int = 10,
        types: tuple[str, ...] | None = None,
    ) -> list[Entity]:
        """Entities whose key matches the query exactly or by prefix
        (case-insensitive; LIKE metacharacters in the query are literal).
        `types` restricts to those entity types *inside* the query so a
        scoped caller still gets `limit` results (H-C8). Used to resolve
        entity names mentioned inside a free-form question."""

    @abstractmethod
    def count_observations(
        self, namespace: str, ref: EntityRef, observed_before: datetime | None = None,
        allowed_types: tuple[str, ...] | None = None,
    ) -> int:
        """Visible observations touching ref (subject or object) — the
        connectivity signal entity resolution ranks by (H-E3), and the
        denominator of a pack's `truncated` report (D-038), which must use
        the same `observed_before` bound as the gather. `allowed_types`
        counts only rows whose subject and object entity both fall in those
        types — what a type-scoped caller could see (D-058)."""

    @abstractmethod
    def subjects_citing(
        self, namespace: str, artifact_ids: list[str],
        allowed_types: tuple[str, ...] | None = None, per_artifact: int = 5,
    ) -> dict[str, list[EntityRef]]:
        """artifact_id -> the subjects of visible observations that cite
        it, so a passage found by meaning maps back to the entities it is
        about (D-040). Scoped callers see only subjects (and objects) in
        their types."""

    @abstractmethod
    def artifact_cited_within(
        self, namespace: str, artifact_id: str, allowed_types: tuple[str, ...]
    ) -> bool:
        """True if some visible observation whose entities all fall inside
        `allowed_types` carries provenance from this artifact — i.e. the
        document is part of a type-scoped caller's world (H-A6)."""

    @abstractmethod
    def store_artifact(self, doc: DocumentIn) -> Artifact:
        """Persist a document verbatim; extraction happens asynchronously later."""

    @abstractmethod
    def artifact_by_event(self, namespace: str, event_id: str) -> Artifact | None:
        """The document a sender ingested under this event_id, so claims can
        cite it by that id before they know the artifact id (D-039)."""

    @abstractmethod
    def get_artifact(self, namespace: str, artifact_id: str) -> Artifact | None:
        """Fetch a stored document by id."""

    @abstractmethod
    def ping(self) -> bool:
        """Cheap liveness probe of the backing database (/readyz)."""

    # ------------------------------------------------- enrichment (D-018)

    @abstractmethod
    def put_embeddings(
        self, namespace: str, model: str,
        items: list[tuple[str, list[float]]],
    ) -> None:
        """Store (observation_id, vector) pairs for one embedding model."""

    @abstractmethod
    def embeddings_for(
        self, namespace: str, ref_ids: list[str], model: str
    ) -> dict[str, list[float]]:
        """ref_id -> its vector for `model`. A vector is a float sequence:
        a read-only float32 numpy view when numpy is installed — decoding
        1,000 gathered 1,536-dim vectors into Python floats cost ~120 ms
        of every semantic ask, the view ~35 ms with the cosine (D-058)."""

    @abstractmethod
    def observations_without_embeddings(
        self, model: str, limit: int = 128, shard: tuple[int, int] | None = None
    ) -> list[Observation]:
        """Backlog for the enrichment worker (tombstoned rows excluded).
        `shard=(i, n)` returns only the rows whose id hashes to partition
        i of n, so n workers split the backlog without coordination
        (D-031); n <= 16."""

    @abstractmethod
    def observations_by_ids(self, namespace: str, ids: list[str]) -> list[Observation]:
        """Visible observations for the given ids (tombstoned excluded),
        in no particular order."""

    @abstractmethod
    def superseded_ids(self, namespace: str, ids: list[str]) -> set[str]:
        """Of the given observation ids, those that a *visible* (not
        tombstoned) observation in the namespace names in its `supersedes`
        (D-050: recorded supersession, never inferred). The read path
        derives supersession from the rows it gathered; this serves a
        caller checking specific rows (PROV export, a single-row view).
        A `supersedes` that names an unknown id is dangling, not an error
        (claims may arrive out of order), and never appears here."""

    @abstractmethod
    def corrections_of(
        self, namespace: str, ids: list[str], observed_before: datetime | None = None,
    ) -> list[Observation]:
        """Visible observations whose `supersedes` names one of `ids`,
        observed at or before `observed_before` when given (the `as_of`
        axis: a correction made after T has not happened as of T). How an
        expansion over a window learns of a correction outside it (D-058);
        served by the supersedes index."""

    @abstractmethod
    def resolve_refs(
        self, namespace: str, refs: list[EntityRef],
    ) -> dict[tuple[str, str], EntityRef]:
        """(type, key) of each ref -> the canonical entity it names: itself,
        or — for a name a merge folded away — the entity it was merged into
        (D-019). Unknown refs are absent. The read path resolves its subjects
        once at entry so an alias asks about the same rows, conflicts and
        scope as the canonical name (D-058)."""

    @abstractmethod
    def observations_by_prefix(self, namespace: str, prefix: str) -> list[Observation]:
        """Visible observations whose id starts with `prefix` — how a
        12-hex cite token from a pack resolves back to its observation —
        ordered by id and capped at 20 rows (an ambiguous token is a
        caller problem, not an unbounded read). An empty prefix returns
        nothing. Served by the primary-key index on both backends."""

    # ------------------------------------------------ vector index (D-025)
    # The JSON `embeddings` / `doc_chunks` tables remain the portable source
    # of truth; each backend keeps an ANN index beside them (sqlite-vec /
    # pgvector) when the extension is available and falls back to an exact
    # scan otherwise. Scores are cosine similarity in [-1, 1].

    @abstractmethod
    def vector_backend(self) -> str:
        """'sqlite-vec', 'pgvector', or 'exact' (no extension available)."""

    @abstractmethod
    def nearest_observations(
        self, namespace: str, model: str, query: list[float], limit: int = 20
    ) -> list[tuple[str, float]]:
        """Namespace-wide k-NN over observation vectors: (observation_id,
        cosine) best first. Tombstoned observations are excluded."""

    @abstractmethod
    def nearest_chunks(
        self, namespace: str, model: str, query: list[float], limit: int = 20,
        artifact_ids: list[str] | None = None,
    ) -> list[tuple[dict, float]]:
        """k-NN over document passages, optionally restricted to the given
        artifacts: (chunk dict as in doc_chunks_for_artifacts, cosine)."""

    @abstractmethod
    def ensure_vector_index(self, model: str) -> dict:
        """Backfill the ANN index for `model` from the JSON tables (rows
        written before the extension was available, or imported). Returns
        {'backend', 'observations', 'chunks'} counts indexed."""

    @abstractmethod
    def pending_artifacts(
        self, limit: int = 4, now: datetime | None = None,
        lease: tuple[str, float] | None = None,
    ) -> list[Artifact]:
        """Artifacts still awaiting claim extraction whose backoff (if any)
        has elapsed as of `now` (default: the current time). With
        `lease=(worker_id, seconds)` the rows are *claimed* atomically for
        that long (D-031): other workers skip them until the lease expires
        or the artifact's status changes, so a fleet shares the backlog
        without double LLM spend."""

    @abstractmethod
    def defer_extraction(
        self, namespace: str, artifact_id: str, attempts: int, next_attempt_at: datetime,
        worker_id: str | None = None,
    ) -> bool:
        """Record a failed extraction attempt and when to try again (H-D4);
        survives worker restarts, unlike in-memory backoff. Releases the
        extraction lease. With `worker_id`, only if that worker still holds
        the lease (a worker whose lease expired and was re-claimed must not
        clobber the new holder's state); returns whether it applied."""

    @abstractmethod
    def extend_extraction_lease(
        self, namespace: str, artifact_id: str, worker_id: str, seconds: float
    ) -> bool:
        """Push the extraction lease `seconds` further out for the worker
        that holds it (a long extraction renews per window instead of
        guessing the whole job's length up front). False if the lease is
        held by someone else or the artifact is no longer pending."""

    @abstractmethod
    def doc_chunks_by_seq(
        self, namespace: str, artifact_id: str, model: str, seqs: list[int]
    ) -> list[dict]:
        """Specific passages of one artifact (excerpt expansion: the
        neighbours of a cited chunk), same dict shape as
        doc_chunks_for_artifacts, ordered by seq."""

    @abstractmethod
    def schema_version(self) -> int:
        """The store's applied migration level (loom_meta), for /readyz and
        upgrade audits (H-B12)."""

    @abstractmethod
    def artifacts_needing_chunks(
        self, model: str, limit: int = 4, lease: tuple[str, float] | None = None
    ) -> list[Artifact]:
        """Non-blank text artifacts not yet chunked+embedded under `model`
        (vectors from different models never mix — H-D3). `lease` as in
        pending_artifacts; released when chunks are stored."""

    @abstractmethod
    def put_doc_chunks(
        self, namespace: str, artifact_id: str, model: str,
        chunks: list[tuple[int, int, int, str, list[float]]],
        worker_id: str | None = None,
    ) -> None:
        """Store (seq, span_start, span_end, text, vector) passages embedded
        with `model`; the rows are idempotent by (artifact, model, seq) so
        they always land. Releases the chunking lease — with `worker_id`,
        only if that worker holds it."""

    @abstractmethod
    def doc_chunks_for_artifacts(
        self, namespace: str, artifact_ids: list[str], model: str
    ) -> list[dict]:
        """Chunks (with vectors) embedded under `model` for the given
        artifacts, for excerpt ranking. Each dict: artifact_id, seq,
        span_start, span_end, text, vector, plus the artifact's source and
        observed_at (datetime) so an excerpt can be cited."""

    @abstractmethod
    def set_extraction_status(
        self, namespace: str, artifact_id: str, status: str,
        worker_id: str | None = None,
    ) -> bool:
        """Set the extraction status and release the lease. With
        `worker_id`, only while that worker holds the lease; returns
        whether it applied (None = unconditional, for ops and tests)."""

    @abstractmethod
    def get_dossier(self, namespace: str, ref: EntityRef) -> dict | None:
        """{'brief', 'observation_count', 'observation_ids', 'updated_at'}
        or None. observation_ids are what the brief was synthesized from —
        its citations (D-023)."""

    @abstractmethod
    def put_dossier(
        self, namespace: str, ref: EntityRef, brief: str,
        observation_count: int, observation_ids: list[str],
        worker_id: str | None = None,
    ) -> bool:
        """Store the brief and release the dossier lease. With `worker_id`,
        only while that worker holds the lease (the re-claimer's brief is
        the one that should land); returns whether it was written."""

    @abstractmethod
    def dossier_candidates(
        self, min_new: int = 20, min_total: int = 5, limit: int = 4,
        lease: tuple[str, float] | None = None,
    ) -> list[tuple[str, EntityRef, int]]:
        """(namespace, entity, current observation count) for entities whose
        dossier is missing (>= min_total observations) or stale (>= min_new
        observations since the last build). `lease` claims the entities for
        one worker; released by put_dossier."""

    # ------------------------------------------------- lifecycle (D-016)

    @abstractmethod
    def redact(self, namespace: str, observation_id: str, reason: str) -> bool:
        """Tombstone one observation: it stops appearing in reads but the
        append-only record (and the tombstone itself) remains auditable.
        Returns False if the observation doesn't exist."""

    @abstractmethod
    def purge_older_than(self, namespace: str, before: datetime) -> int:
        """Retention sweep: hard-delete observations and artifacts observed
        before the cutoff, plus the derived rows that hung off them
        (embeddings, doc chunks, tombstones, dossiers of entities left with
        no observations). Entities themselves are kept. Returns
        observation + artifact rows removed."""

    @abstractmethod
    def iter_observations(self, namespace: str | None = None) -> Iterator[Observation]:
        """Every observation (tombstoned included — export is a backup, and
        the matching tombstones are exported alongside via iter_tombstones)."""

    @abstractmethod
    def iter_entities(
        self, namespace: str | None = None, since: datetime | None = None
    ) -> Iterator[Entity]:
        """Every entity, oldest created first. `since` keeps those created
        at or after that instant, so a periodic scan (the enrichment alias
        pass) can be incremental instead of re-reading the namespace every
        tick (R-9); served by the (namespace, created_at) index."""

    @abstractmethod
    def iter_artifacts(self, namespace: str | None = None) -> Iterator[Artifact]: ...

    @abstractmethod
    def iter_aliases(self, namespace: str | None = None) -> Iterator[dict]:
        """{'namespace', 'alias': 'type:key', 'canonical': {'type','key'}}
        for every merge alias (D-019) — part of a faithful export."""

    @abstractmethod
    def remember_decline(
        self, namespace: str, a: str, b: str, reason: str,
        decided_at: datetime | None = None,
    ) -> None:
        """Record that an adjudicator judged entity handles a and b (type:key)
        NOT the same thing, so no worker asks the model again (D-044). Order
        of a and b does not matter. `decided_at` defaults to now; an import
        passes the exported instant."""

    @abstractmethod
    def forget_decline(self, namespace: str, a: str, b: str) -> bool:
        """Drop the remembered decline of the pair a / b (type:key, either
        order) — an operator taking back a `distinct` or an adjudicator's
        no, so resolution may consider the pair again. True when a decline
        was on record."""

    @abstractmethod
    def declined_pairs(self, namespace: str) -> set[tuple[str, str]]:
        """Every (a, b) pair declined in this namespace, in canonical order
        (a < b)."""

    @abstractmethod
    def iter_declines(self, namespace: str | None = None) -> Iterator[dict]:
        """{'namespace', 'a', 'b', 'reason', 'decided_at'} for every
        adjudication decline — exported so a restored worker does not ask
        the model the same questions again."""

    @abstractmethod
    def iter_tombstones(self, namespace: str | None = None) -> Iterator[dict]:
        """{'namespace', 'observation_id', 'reason', 'recorded_at'} for every
        redaction (D-016) — exported so a restore never un-redacts."""

    @abstractmethod
    def restore_observation(self, obs: Observation) -> None:
        """Insert an exported observation verbatim (import/migration path).
        Idempotent: an existing id or (namespace, event_id) is left alone."""

    @abstractmethod
    def restore_artifact(self, artifact: Artifact) -> None: ...

    @abstractmethod
    def restore_entity(self, entity: Entity) -> None:
        """Ensure an exported entity exists (keeps `provisional`/`created_at`
        when creating; leaves an existing one alone)."""

    @abstractmethod
    def restore_alias(self, namespace: str, alias: str, canonical: EntityRef) -> None: ...

    @abstractmethod
    def restore_tombstone(
        self, namespace: str, observation_id: str, reason: str, recorded_at: datetime
    ) -> None:
        """Re-apply an exported redaction. Like `redact`, it drops any brief
        that cites the observation: a restore must not leave a dossier
        quoting what it redacts (D-058)."""

    @abstractmethod
    def wipe(self) -> None:
        """Delete all rows (test isolation and demo resets)."""

    @abstractmethod
    def close(self) -> None:
        """Release resources."""
