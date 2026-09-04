"""Phase 4 enrichment: embeddings, claim extraction, dossiers (D-018)."""

from datetime import datetime, timezone

from loom.context import build_pack
from loom.contracts import AnswerRequest, AskRequest, ClaimIn, DocumentIn, EntityRef
from loom.enrich import (
    embed_pending,
    extract_from_artifact,
    refresh_dossiers,
    resolve_entities,
)
from loom.llm import HashingEmbedder, LLMClient
from loom.store.sqlite import SqliteStore

OBSERVED = datetime(2026, 9, 1, tzinfo=timezone.utc)


def _store(tmp_path):
    return SqliteStore(tmp_path / "enrich.db")


# ------------------------------------------------------------- embeddings #

def test_embed_pending_is_idempotent(tmp_path):
    store = _store(tmp_path)
    store.record_claim(ClaimIn(
        subject=EntityRef(type="host", key="web-01"), predicate="runs_os",
        object="fedora-44", observed_at=OBSERVED, source="inv"))
    embedder = HashingEmbedder()
    assert embed_pending(store, embedder) == 1
    assert embed_pending(store, embedder) == 0  # nothing left to embed
    vecs = store.embeddings_for(
        "default",
        [o.id for o in store.observations_for(
            "default", EntityRef(type="host", key="web-01"))],
        embedder.model)
    assert len(vecs) == 1


def test_semantic_ranking_changes_order(tmp_path):
    store = _store(tmp_path)
    host = EntityRef(type="host", key="web-01")
    store.record_claim(ClaimIn(subject=host, predicate="runs_os",
                               object="ubuntu operating system linux",
                               observed_at=OBSERVED, source="inv"))
    for i in range(5):
        store.record_claim(ClaimIn(
            subject=host, predicate="communicated_with",
            object=EntityRef(type="host", key=f"peer-{i}"),
            observed_at=OBSERVED, source="netflow"))
    embedder = HashingEmbedder()
    embed_pending(store, embedder)
    pack = build_pack(store, AskRequest(
        subject=host, question="what operating system does it run?",
        budget=2000), embedder=embedder)
    facts = [i for i in pack.items if i.kind == "fact"]
    assert "runs_os" in facts[0].text  # semantic match wins the top slot


# -------------------------------------------------------- claim extraction #

class ScriptedLLM(LLMClient):
    model = "scripted"

    def __init__(self, reply):
        self.reply = reply

    def complete(self, system, user, max_tokens=1024):
        return self.reply


def test_extraction_creates_cited_observations(tmp_path):
    store = _store(tmp_path)
    doc = DocumentIn(
        namespace="netsec",
        text="Alert AL-2291 fired on web-01 after jdoe logged in.",
        filename="ir.txt", source="ir-pipeline", observed_at=OBSERVED)
    artifact = store.store_artifact(doc)
    llm = ScriptedLLM(
        '{"claims":[{"subject_type":"host","subject_key":"web-01",'
        '"predicate":"logged_in_by","object_entity_type":"user",'
        '"object_entity_key":"jdoe","object_value":null,'
        '"quote":"jdoe logged in","confidence":0.8}]}')
    n = extract_from_artifact(store, llm, artifact)
    assert n == 1
    obs = store.observations_for("netsec", EntityRef(type="host", key="web-01"))
    assert len(obs) == 1
    o = obs[0]
    assert o.provenance is not None
    assert o.provenance.artifact_id == artifact.id
    assert o.provenance.span_start is not None  # quote located in the text
    assert store.get_artifact("netsec", artifact.id).extraction_status == "done"


def test_extraction_is_idempotent_via_event_id(tmp_path):
    store = _store(tmp_path)
    artifact = store.store_artifact(DocumentIn(
        text="web-01 runs fedora.", source="s", observed_at=OBSERVED))
    reply = ('{"claims":[{"subject_type":"host","subject_key":"web-01",'
             '"predicate":"runs_os","object_entity_type":null,'
             '"object_value":"fedora","quote":"runs fedora","confidence":0.7}]}')
    extract_from_artifact(store, ScriptedLLM(reply), artifact)
    store.set_extraction_status("default", artifact.id, "pending")
    extract_from_artifact(store, ScriptedLLM(reply), artifact)  # re-run
    obs = store.observations_for("default", EntityRef(type="host", key="web-01"))
    assert len(obs) == 1  # event_id dedupe prevented a duplicate


def test_extraction_handles_bad_json(tmp_path):
    store = _store(tmp_path)
    artifact = store.store_artifact(DocumentIn(
        text="whatever", source="s", observed_at=OBSERVED))
    assert extract_from_artifact(store, ScriptedLLM("not json"), artifact) == 0
    assert store.get_artifact("default", artifact.id).extraction_status == "failed"


def test_empty_document_is_skipped(tmp_path):
    store = _store(tmp_path)
    artifact = store.store_artifact(DocumentIn(
        content_b64="aGk=", content_type="application/octet-stream",
        source="s", observed_at=OBSERVED))
    assert extract_from_artifact(store, ScriptedLLM("{}"), artifact) == 0
    assert store.get_artifact("default", artifact.id).extraction_status == "skipped"


# ------------------------------------------------------- entity resolution #

def test_resolve_merges_extracted_into_structured(tmp_path):
    store = _store(tmp_path)
    # structured entity with several observations
    for i in range(4):
        store.record_claim(ClaimIn(
            subject=EntityRef(type="ip", key="10.0.4.7"),
            predicate="assigned_to",
            object=EntityRef(type="host", key=f"h{i}"),
            observed_at=OBSERVED, source="dhcp"))
    # a single stray extracted observation under a drifted type
    store.record_claim(ClaimIn(
        subject=EntityRef(type="ip_address", key="10.0.4.7"),
        predicate="mentioned_in", object="IR-4432",
        observed_at=OBSERVED, source="doc:ir"))

    assert resolve_entities(store) == 1
    # the well-connected 'ip' entity is canonical; the stray folded in
    obs = store.observations_for("default", EntityRef(type="ip", key="10.0.4.7"))
    assert len(obs) == 5
    assert any(o.predicate == "mentioned_in" for o in obs)
    # idempotent: nothing left to merge
    assert resolve_entities(store) == 0


# ---------------------------------------------------------------- dossiers #

def test_dossier_built_and_served_as_brief(tmp_path):
    store = _store(tmp_path)
    host = EntityRef(type="host", key="web-01")
    for i in range(6):
        store.record_claim(ClaimIn(
            subject=host, predicate="logged_in_by",
            object=EntityRef(type="user", key=f"u{i}"),
            observed_at=OBSERVED, source="auth"))
    llm = ScriptedLLM("web-01 is a busy host with many distinct logins.")
    assert refresh_dossiers(store, llm, min_new=20, min_total=5) == 1
    pack = build_pack(store, AskRequest(
        subject=host, question="tell me about this host", budget=2000))
    assert pack.items[0].kind == "brief"
    assert "busy host" in pack.items[0].text
    # not rebuilt until enough new observations arrive
    assert refresh_dossiers(store, llm, min_new=20, min_total=5) == 0
