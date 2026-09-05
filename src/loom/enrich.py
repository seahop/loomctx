"""The async enrichment worker (phase 4, D-004/D-018).

Three jobs, all safe to run repeatedly (idempotent by construction):

1. **Embeddings** — vectorize observations that lack one for the configured
   model, so the pack builder can rank semantically instead of by keyword.
2. **Claim extraction** — mine pending document artifacts into ordinary
   observations with span provenance. Each extracted claim carries
   event_id "extract:<artifact>:<n>", so re-running extraction can never
   duplicate facts (D-014 doing double duty).
3. **Dossiers** — rolling per-entity briefs, rebuilt when enough new
   observations accumulate; the pack builder serves them as the cheap
   orientation layer.

Run once (cron/k8s Job) or as a loop (compose profile `enrich`):

    python -m loom.enrich run --once
    python -m loom.enrich run --interval 30

Embeddings need LOOM_EMBED_*; extraction and dossiers need LOOM_LLM_*.
Whatever isn't configured is skipped with a log line — never an error.
"""

from __future__ import annotations

import argparse
import json
import logging
import time

from .context import _render_fact
from .contracts import Artifact, ClaimIn, EntityRef, Provenance
from .llm import Embedder, LLMClient, LLMError, embedder_from_env, llm_from_env
from .store.base import GraphStore
from .store.factory import store_from_env

log = logging.getLogger("loom.enrich")

EXTRACT_SYSTEM = (
    "You extract factual claims from a document into STRICT JSON, nothing "
    "else. Schema: {\"claims\": [{\"subject_type\": str, \"subject_key\": str, "
    "\"predicate\": str, \"object_entity_type\": str|null, "
    "\"object_entity_key\": str|null, \"object_value\": str|null, "
    "\"quote\": str, \"confidence\": float}]}. Rules: predicates are "
    "snake_case verb phrases (logged_in_by, assigned_to, mentions); entity "
    "keys verbatim from the text; exactly one of object_entity_* or "
    "object_value per claim; quote is the exact sentence fragment the claim "
    "comes from; only state facts the document asserts — no inference. "
    "Return {\"claims\": []} if there are none."
)

DOSSIER_SYSTEM = (
    "Write a compact factual brief (3-5 sentences) of the entity from the "
    "observations provided. Plain prose, most load-bearing facts first, "
    "note open conflicts explicitly, no speculation, no preamble."
)


def embed_pending(store: GraphStore, embedder: Embedder, batch: int = 128) -> int:
    observations = store.observations_without_embeddings(embedder.model, batch)
    if not observations:
        return 0
    vectors = embedder.embed([_render_fact(o) for o in observations])
    by_namespace: dict[str, list[tuple[str, list[float]]]] = {}
    for obs, vec in zip(observations, vectors):
        by_namespace.setdefault(obs.namespace, []).append((obs.id, vec))
    for namespace, items in by_namespace.items():
        store.put_embeddings(namespace, embedder.model, items)
    return len(observations)


def _chunk_text(text: str, target: int = 400, hard: int = 800) -> list[tuple[int, int, str]]:
    """Split into (start, end, text) passages on paragraph/sentence
    boundaries, aiming for ~target chars and never exceeding hard. Offsets
    index the original text so excerpts cite an exact span."""
    import re

    chunks: list[tuple[int, int, str]] = []
    pos = 0
    n = len(text)
    while pos < n:
        end = min(pos + target, n)
        if end < n:
            window = text[pos:min(pos + hard, n)]
            # prefer a paragraph break, then sentence, then whitespace
            for pat in ("\n\n", ". ", "\n", " "):
                idx = window.rfind(pat, target // 2)
                if idx != -1:
                    end = pos + idx + len(pat)
                    break
        piece = text[pos:end].strip()
        if piece:
            real_start = pos + (len(text[pos:end]) - len(text[pos:end].lstrip()))
            chunks.append((real_start, real_start + len(piece), piece))
        pos = end
    return chunks


def chunk_artifacts(store: GraphStore, embedder: Embedder, limit: int = 4) -> int:
    """Chunk + embed pending document artifacts so their passages can rank
    into packs as doc_excerpt items (D-020)."""
    total = 0
    for artifact in store.artifacts_needing_chunks(limit):
        pieces = _chunk_text(artifact.text or "")
        if not pieces:
            continue
        vectors = embedder.embed([p[2] for p in pieces])
        rows = [(seq, start, end, txt, vec)
                for seq, ((start, end, txt), vec) in enumerate(zip(pieces, vectors))]
        store.put_doc_chunks(artifact.namespace, artifact.id, rows)
        total += len(rows)
    return total


def _parse_extraction(raw: str) -> list[dict]:
    text = raw.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
    return json.loads(text).get("claims", [])


def extract_from_artifact(
    store: GraphStore, llm: LLMClient, artifact: Artifact
) -> int:
    if not artifact.text:
        store.set_extraction_status(artifact.namespace, artifact.id, "skipped")
        return 0
    raw = llm.complete(EXTRACT_SYSTEM, artifact.text[:8000], max_tokens=2000)
    try:
        extracted = _parse_extraction(raw)
    except (json.JSONDecodeError, AttributeError) as exc:
        log.warning("extraction parse failed for %s: %s", artifact.id, exc)
        store.set_extraction_status(artifact.namespace, artifact.id, "failed")
        return 0

    claims: list[ClaimIn] = []
    for index, c in enumerate(extracted):
        try:
            if c.get("object_entity_key"):
                obj = EntityRef(type=c["object_entity_type"],
                                key=c["object_entity_key"])
            else:
                obj = str(c.get("object_value", ""))
            quote = c.get("quote") or ""
            start = artifact.text.find(quote) if quote else -1
            claims.append(ClaimIn(
                namespace=artifact.namespace,
                event_id=f"extract:{artifact.id}:{index}",
                subject=EntityRef(type=c["subject_type"], key=c["subject_key"]),
                predicate=c["predicate"],
                object=obj,
                observed_at=artifact.observed_at,
                source=f"doc:{artifact.filename or artifact.id[:8]}",
                confidence=min(float(c.get("confidence", 0.7)), 0.9),
                provenance=Provenance(
                    artifact_id=artifact.id,
                    span_start=start if start >= 0 else None,
                    span_end=start + len(quote) if start >= 0 else None,
                ),
            ))
        except (KeyError, ValueError, TypeError) as exc:
            log.warning("skipping malformed extracted claim %d of %s: %s",
                        index, artifact.id, exc)
    if claims:
        store.record_claims(claims)
    store.set_extraction_status(artifact.namespace, artifact.id, "done")
    return len(claims)


def extract_pending(store: GraphStore, llm: LLMClient, limit: int = 4) -> int:
    total = 0
    for artifact in store.pending_artifacts(limit):
        try:
            total += extract_from_artifact(store, llm, artifact)
        except LLMError as exc:  # provider hiccup: stay pending, retry later
            log.warning("extraction deferred for %s: %s", artifact.id, exc)
    return total


def refresh_dossiers(
    store: GraphStore, llm: LLMClient,
    min_new: int = 20, min_total: int = 5, limit: int = 4,
) -> int:
    built = 0
    for namespace, ref, count in store.dossier_candidates(min_new, min_total, limit):
        observations = store.observations_for(namespace, ref, limit=100)
        facts = "\n".join(_render_fact(o) for o in observations)
        try:
            brief = llm.complete(
                DOSSIER_SYSTEM,
                f"Entity: {ref.type}:{ref.key}\nObservations:\n{facts}",
                max_tokens=300,
            )
        except LLMError as exc:
            log.warning("dossier deferred for %s:%s: %s", ref.type, ref.key, exc)
            continue
        store.put_dossier(namespace, ref, brief.strip(), count)
        built += 1
    return built


def resolve_entities(store: GraphStore, limit: int = 50) -> int:
    """Fold same-key/cross-type duplicates (the drift extraction produces,
    e.g. ip_address:10.0.4.7 vs ip:10.0.4.7) into one canonical entity.

    Canonical = the most-connected member (most observations), ties broken by
    earliest creation — i.e. the established structured entity absorbs the
    stray extracted one. Every merge is reversible via its alias record.
    """
    merged = 0
    for group in store.merge_candidates(limit=limit):
        namespace = group[0].namespace
        ranked = sorted(
            group,
            key=lambda e: (
                -len(store.observations_for(
                    namespace, EntityRef(type=e.type, key=e.key), limit=1000)),
                e.created_at,
            ),
        )
        canonical, *rest = ranked
        into = EntityRef(type=canonical.type, key=canonical.key)
        for other in rest:
            if store.merge_entities(
                namespace, EntityRef(type=other.type, key=other.key), into
            ):
                log.info("merged %s:%s -> %s:%s", other.type, other.key,
                         into.type, into.key)
                merged += 1
    return merged


def run(once: bool, interval: float) -> None:
    store = store_from_env()
    embedder = embedder_from_env()
    llm = llm_from_env()
    if embedder is None:
        log.info("no embedder configured (LOOM_EMBED_*) — skipping embeddings")
    if llm is None:
        log.info("no LLM configured (LOOM_LLM_*) — skipping extraction/dossiers")
    try:
        while True:
            extracted = extract_pending(store, llm) if llm else 0
            # resolve BEFORE embedding/dossiers so merged entities are
            # embedded and summarized once, under their canonical identity
            resolved = resolve_entities(store)
            embedded = embed_pending(store, embedder) if embedder else 0
            chunked = chunk_artifacts(store, embedder) if embedder else 0
            dossiers = refresh_dossiers(store, llm) if llm else 0
            work = extracted or resolved or embedded or chunked or dossiers
            if work:
                log.info("extracted=%d resolved=%d embedded=%d chunked=%d "
                         "dossiers=%d", extracted, resolved, embedded, chunked,
                         dossiers)
            if once and not work:
                break
            if once:
                continue  # drain fully in --once mode
            time.sleep(interval)
    finally:
        store.close()


def main() -> None:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(message)s")
    parser = argparse.ArgumentParser(prog="loom.enrich", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p_run = sub.add_parser("run")
    p_run.add_argument("--once", action="store_true",
                       help="drain the backlog and exit (cron/k8s Job mode)")
    p_run.add_argument("--interval", type=float, default=30.0)
    args = parser.parse_args()
    run(once=args.once, interval=args.interval)


if __name__ == "__main__":
    main()
