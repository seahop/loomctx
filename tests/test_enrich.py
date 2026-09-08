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


# ------------------------------------------------- doc excerpts + budget cap #

def test_chunk_and_excerpt_retrieval(tmp_path):
    store = _store(tmp_path)
    # a claim ties the entity to the artifact via provenance
    from loom.contracts import Provenance
    art = store.store_artifact(DocumentIn(
        namespace="vuln",
        text=(
            "Section one covers routine patching notes across the estate, "
            "including scheduled maintenance windows, change tickets, and the "
            "usual reboot coordination that operations handles every month. "
            "\n\n"
            "Section two: web-01 remains exploitable via CVE-2026-1337 despite "
            "the August patch cycle, which addressed only lower-priority items; "
            "emergency remediation is strongly recommended before month end. "
            "\n\n"
            "Section three is an unrelated appendix about printer firmware "
            "revisions, toner supplier contacts, and office badge reader "
            "maintenance schedules that has nothing to do with the finding."),
        filename="pentest.txt", source="pentest", observed_at=OBSERVED))
    store.record_claim(ClaimIn(
        namespace="vuln", subject=EntityRef(type="asset", key="web-01"),
        predicate="mentioned_in", object="pentest.txt",
        observed_at=OBSERVED, source="doc:pentest",
        provenance=Provenance(artifact_id=art.id)))

    from loom.enrich import chunk_artifacts
    embedder = HashingEmbedder()
    assert chunk_artifacts(store, embedder) >= 2

    pack = build_pack(store, AskRequest(
        namespace="vuln", subject=EntityRef(type="asset", key="web-01"),
        question="is web-01 exploitable via CVE-2026-1337?", budget=1500),
        embedder=embedder)
    excerpts = [i for i in pack.items if i.kind == "doc_excerpt"]
    assert excerpts, "a relevant passage should surface as a doc_excerpt"
    top = excerpts[0]
    assert "CVE-2026-1337" in top.text and "@" in top.text  # passage + cited span
    cite = top.citations[0]
    assert cite.artifact_id == art.id and cite.source == "pentest"
    assert "CVE-2026-1337" in art.text[cite.span_start:cite.span_end]
    # excerpts are keyed by embedding model: a different serving embedder
    # sees no chunks rather than mixing vector spaces (H-D3)
    other = HashingEmbedder(dim=64)
    pack = build_pack(store, AskRequest(
        namespace="vuln", subject=EntityRef(type="asset", key="web-01"),
        question="is web-01 exploitable via CVE-2026-1337?", budget=1500),
        embedder=other)
    assert not [i for i in pack.items if i.kind == "doc_excerpt"]


def test_budget_cap_is_configurable(tmp_path, monkeypatch):
    store = _store(tmp_path)
    host = EntityRef(type="host", key="web-01")
    for i in range(30):
        store.record_claim(ClaimIn(
            subject=host, predicate="logged_in_by",
            object=EntityRef(type="user", key=f"u{i}"),
            observed_at=OBSERVED, source="auth"))

    monkeypatch.setenv("LOOM_MAX_BUDGET", "100")
    pack = build_pack(store, AskRequest(
        subject=host, question="who?", budget=5000))
    assert pack.budget == 100  # request clamped to the operator ceiling

    monkeypatch.setenv("LOOM_MAX_BUDGET", "5000")
    pack = build_pack(store, AskRequest(
        subject=host, question="who?", budget=5000))
    assert pack.budget == 5000  # raised ceiling honored


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
    assert len(pack.items[0].citations) == 6  # a brief cites what built it
    # a brief is present-tense: withheld from time-travel reads (H-C2)
    past = build_pack(store, AskRequest(
        subject=host, question="tell me about this host", budget=2000,
        as_of=datetime(2026, 9, 2, tzinfo=timezone.utc)))
    assert all(i.kind != "brief" for i in past.items)
    # not rebuilt until enough new observations arrive
    assert refresh_dossiers(store, llm, min_new=20, min_total=5) == 0


# ------------------------------------------------- worker hardening (H-D*) #

def test_extracted_claims_are_tagged_and_hash_keyed(tmp_path):
    """H-D2/H-D6: extracted claims carry attrs.extracted and a
    content-addressed event_id, so reordered replies never shadow facts."""
    store = _store(tmp_path)
    artifact = store.store_artifact(DocumentIn(
        text="web-01 runs fedora. jdoe logged in.", source="s", observed_at=OBSERVED))
    a = ('{"subject_type":"host","subject_key":"web-01","predicate":"runs_os",'
         '"object_entity_type":null,"object_value":"fedora","quote":"runs fedora","confidence":0.7}')
    b = ('{"subject_type":"host","subject_key":"web-01","predicate":"logged_in_by",'
         '"object_entity_type":"user","object_entity_key":"jdoe","object_value":null,'
         '"quote":"jdoe logged in","confidence":0.8}')
    extract_from_artifact(store, ScriptedLLM('{"claims":[%s]}' % a), artifact)
    store.set_extraction_status("default", artifact.id, "pending")
    # second pass: reordered AND one new claim
    extract_from_artifact(store, ScriptedLLM('{"claims":[%s,%s]}' % (b, a)), artifact)
    obs = store.observations_for("default", EntityRef(type="host", key="web-01"))
    assert {o.predicate for o in obs} == {"runs_os", "logged_in_by"}
    assert len(obs) == 2
    assert all(o.attrs.get("extracted") is True for o in obs)
    assert all(o.event_id.startswith("extract:") for o in obs)


def test_extraction_parser_tolerates_wrapping_and_rejects_junk():
    from loom.enrich import _parse_extraction
    import pytest
    good = '{"claims":[{"subject_type":"h","subject_key":"k","predicate":"p","object_value":"v","quote":"q"}]}'
    assert len(_parse_extraction(good)) == 1
    assert len(_parse_extraction("Here you go:\n```json\n" + good + "\n```")) == 1
    assert len(_parse_extraction("Sure! " + good + " hope that helps")) == 1
    assert _parse_extraction('{"claims": [1, "x", null]}') == []  # non-dicts dropped
    for junk in ('{"claims": "x"}', "[1,2]", "no json here"):
        with pytest.raises(ValueError):
            _parse_extraction(junk)


def test_worker_tick_survives_job_failures(tmp_path):
    """H-D1: a provider/database failure in one job is logged, not fatal,
    and the other jobs still run."""
    from loom.enrich import tick
    from loom.llm import Embedder, LLMError
    store = _store(tmp_path)
    for i in range(6):
        store.record_claim(ClaimIn(
            subject=EntityRef(type="host", key="web-01"), predicate="logged_in_by",
            object=EntityRef(type="user", key=f"u{i}"), observed_at=OBSERVED, source="auth"))

    class Broken(Embedder):
        model = "broken"

        def embed(self, texts):
            raise LLMError("provider down")

    counts = tick(store, Broken(), ScriptedLLM("brief text"))
    assert counts["embedded"] == 0 and counts["dossiers"] == 1  # dossiers still built


def test_extraction_backs_off_failing_artifacts(tmp_path, monkeypatch):
    """H-D4: a document whose extraction keeps failing stops hogging the
    per-tick slots; others behind it still get processed."""
    from loom import enrich
    from loom.llm import LLMError
    store = _store(tmp_path)
    monkeypatch.setattr(enrich, "_deferred", {})
    bad = store.store_artifact(DocumentIn(text="poison", source="s", observed_at=OBSERVED))
    good = store.store_artifact(DocumentIn(text="fine", source="s", observed_at=OBSERVED))

    class Flaky(LLMClient):
        model = "flaky"

        def complete(self, system, user, max_tokens=1024):
            if "poison" in user:
                raise LLMError("boom")
            return '{"claims": []}'

    # tick 1: poison fails (deferred), fine succeeds, both within one call
    enrich.extract_pending(store, Flaky(), limit=1)
    enrich.extract_pending(store, Flaky(), limit=1)
    assert store.get_artifact("default", bad.id).extraction_status == "pending"
    assert store.get_artifact("default", good.id).extraction_status == "done"
    assert enrich._deferred[bad.id][0] == 1


def test_embed_pending_counts_stored_vectors(tmp_path):
    """H-D10: a short embedder reply is an error, not a silent loop."""
    import pytest
    from loom.llm import Embedder, LLMError
    store = _store(tmp_path)
    for i in range(3):
        store.record_claim(ClaimIn(
            subject=EntityRef(type="host", key="web-01"), predicate="p",
            object=f"v{i}", observed_at=OBSERVED, source="s"))

    class Short(Embedder):
        model = "short"

        def embed(self, texts):
            return [[1.0]] * (len(texts) - 1)

    with pytest.raises(LLMError):
        embed_pending(store, Short())


def test_excerpt_handle_expands_to_neighbouring_passages(tmp_path):
    """Roadmap phase 4: 'doc_excerpt expansion handles to pull surrounding chunks'."""
    from loom.context import expand_pack
    from loom.contracts import Provenance
    from loom.enrich import chunk_artifacts
    store = _store(tmp_path)
    filler = ("It goes on at some length about maintenance windows, change "
              "tickets and the usual coordination that operations handles. ") * 3
    paras = [f"Paragraph {i} discusses topic number {i} in detail. {filler}"
             for i in range(6)]
    paras[3] = paras[3].replace("topic number 3", "the CVE-2026-1337 exploit on web-01")
    art = store.store_artifact(DocumentIn(text="\n\n".join(paras), source="pentest",
                                          observed_at=OBSERVED))
    store.record_claim(ClaimIn(
        subject=EntityRef(type="asset", key="web-01"), predicate="mentioned_in",
        object="report", observed_at=OBSERVED, source="doc:pentest",
        provenance=Provenance(artifact_id=art.id)))
    embedder = HashingEmbedder()
    assert chunk_artifacts(store, embedder) >= 4
    pack = build_pack(store, AskRequest(
        subject=EntityRef(type="asset", key="web-01"),
        question="CVE-2026-1337 exploit", budget=1500), embedder=embedder)
    handles = [h for h in pack.handles if h.kind == "excerpt"]
    assert handles
    around = expand_pack(store, handles[0].id, budget=3000)
    texts = [i.text for i in around.items]
    assert len(texts) >= 2 and all(i.kind == "doc_excerpt" for i in around.items)
    assert any("CVE-2026-1337" in t for t in texts)
    assert all(i.citations[0].artifact_id == art.id for i in around.items)
    # a reader scoped away from 'asset' gets nothing from the same handle
    assert expand_pack(store, handles[0].id, 3000, allowed_types=("host",)).items == []
