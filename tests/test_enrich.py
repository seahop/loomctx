"""Phase 4 enrichment: embeddings, claim extraction, dossiers (D-018)."""

import json
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
from loom.enrich import FAILED

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
    """A garbled reply is retried with backoff (models are nondeterministic)
    and dead-lettered as `failed` after the attempt bound (H-D4/H-D5)."""
    import pytest
    from loom import enrich
    store = _store(tmp_path)
    artifact = store.store_artifact(DocumentIn(
        text="whatever", source="s", observed_at=OBSERVED))
    with pytest.raises(enrich.ExtractionParseError):
        extract_from_artifact(store, ScriptedLLM("not json"), artifact)
    assert enrich.extract_pending(store, ScriptedLLM("not json")) == 0
    art = store.get_artifact("default", artifact.id)
    assert art.extraction_status == "pending" and art.extraction_attempts == 1
    assert store.pending_artifacts(10) == []  # backing off
    for _ in range(enrich.EXTRACTION_MAX_ATTEMPTS):
        store.defer_extraction("default", artifact.id,
                               store.get_artifact("default", artifact.id).extraction_attempts,
                               OBSERVED)  # backoff elapsed
        enrich.extract_pending(store, ScriptedLLM("still not json"))
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
    assert counts["embedded"] == FAILED and counts["dossiers"] == 1  # dossiers still built


def test_extraction_backs_off_failing_artifacts(tmp_path):
    """H-D4: a document whose extraction keeps failing stops hogging the
    per-tick slots (backoff persisted on the artifact); others behind it
    still get processed."""
    from loom import enrich
    from loom.llm import LLMError
    store = _store(tmp_path)
    bad = store.store_artifact(DocumentIn(text="poison", source="s", observed_at=OBSERVED))
    good = store.store_artifact(DocumentIn(text="fine", source="s", observed_at=OBSERVED))

    class Flaky(LLMClient):
        model = "flaky"

        def complete(self, system, user, max_tokens=1024):
            if "poison" in user:
                raise LLMError("boom")
            return '{"claims": []}'

    enrich.extract_pending(store, Flaky(), limit=1)  # poison fails, backs off
    enrich.extract_pending(store, Flaky(), limit=1)  # fine gets the slot
    assert store.get_artifact("default", bad.id).extraction_status == "pending"
    assert store.get_artifact("default", bad.id).extraction_attempts == 1
    assert store.get_artifact("default", good.id).extraction_status == "done"


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


# ------------------------------------------- windowed extraction (H-D7) #

def test_extraction_covers_the_whole_document_in_windows(tmp_path):
    from loom import enrich
    store = _store(tmp_path)
    filler = ("Routine paragraph about nothing in particular that pads the "
              "report out to a realistic length for testing purposes.\n\n")
    head = "web-01 runs fedora.\n\n"
    tail = "\n\nAppendix: db-02 was patched to rhel-9.4 last night."
    text = head + filler * 200 + tail            # well past two windows
    assert len(text) > 2 * enrich.EXTRACT_WINDOW_CHARS
    art = store.store_artifact(DocumentIn(text=text, source="s", observed_at=OBSERVED))
    seen_windows = []

    class PerWindow(LLMClient):
        model = "pw"

        def complete(self, system, user, max_tokens=1024):
            seen_windows.append(user)
            claims = []
            if "web-01 runs fedora" in user:
                claims.append('{"subject_type":"host","subject_key":"web-01","predicate":"runs_os",'
                              '"object_value":"fedora","quote":"web-01 runs fedora"}')
            if "db-02 was patched" in user:
                claims.append('{"subject_type":"host","subject_key":"db-02","predicate":"patched_to",'
                              '"object_value":"rhel-9.4","quote":"db-02 was patched to rhel-9.4"}')
            return '{"claims":[%s]}' % ",".join(claims)

    n = extract_from_artifact(store, PerWindow(), art)
    assert n == 2 and len(seen_windows) >= 3
    db = store.observations_for("default", EntityRef(type="host", key="db-02"))[0]
    assert text[db.provenance.span_start:db.provenance.span_end] == "db-02 was patched to rhel-9.4"
    assert db.provenance.span_start > enrich.EXTRACT_WINDOW_CHARS  # located past window 1
    assert enrich._windows("short", size=100) == [(0, "short")]
    ws = enrich._windows("a" * 250 + ". " + "b" * 250, size=300, overlap=20)
    assert ws[0][0] == 0 and ws[1][0] < ws[0][0] + len(ws[0][1])  # overlapping
    assert "".join(w for _, w in ws).count("b") >= 250


# ------------------------------------------- fuzzy resolution (D-024) #

def _claim(subject, predicate, obj, source="s"):
    return ClaimIn(subject=subject, predicate=predicate, object=obj,
                   observed_at=OBSERVED, source=source)


def test_same_type_spelling_drift_auto_merges(tmp_path):
    store = _store(tmp_path)
    canonical = EntityRef(type="host", key="web-01")
    for i in range(3):
        store.record_claim(_claim(canonical, "logged_in_by", EntityRef(type="user", key=f"u{i}")))
    store.record_claim(_claim(EntityRef(type="host", key="WEB_01"), "runs_os", "fedora"))
    store.record_claim(_claim(EntityRef(type="host", key="web01"), "runs_os", "fedora"))
    store.record_claim(_claim(EntityRef(type="host", key="web-02"), "runs_os", "ubuntu"))
    assert resolve_entities(store) == 2
    obs = store.observations_for("default", canonical, limit=50)
    assert len(obs) == 5
    assert store.get_entity("default", EntityRef(type="host", key="web01")).key == "web-01"
    assert store.get_entity("default", EntityRef(type="host", key="web-02")).key == "web-02"
    assert resolve_entities(store) == 0  # idempotent


def test_cross_type_collision_needs_adjudication(tmp_path):
    from loom.enrich import _declined, adjudicate_entities
    store = _store(tmp_path)
    _declined.clear()
    host = EntityRef(type="host", key="web-01")
    asset = EntityRef(type="asset", key="web01")
    user = EntityRef(type="user", key="web.01")   # a person with an unlucky handle
    for i in range(3):
        store.record_claim(_claim(host, "logged_in_by", EntityRef(type="user", key=f"u{i}")))
    store.record_claim(_claim(asset, "cve_finding", "CVE-2026-1337", source="doc:pentest"))
    store.record_claim(_claim(user, "department", "finance", source="hr"))
    # spelling alone never merges across types
    assert resolve_entities(store) == 0
    assert store.get_entity("default", asset).type == "asset"

    prompts = []

    class Judge(LLMClient):
        model = "judge"

        def complete(self, system, user_prompt, max_tokens=1024):
            prompts.append(user_prompt)
            if "asset:web01" in user_prompt:
                return '{"same": true, "confidence": 0.95, "reason": "same box"}'
            return '{"same": false, "confidence": 0.9, "reason": "a person"}'

    assert adjudicate_entities(store, Judge()) == 1
    assert store.get_entity("default", asset).type == "host"          # folded in
    assert store.get_entity("default", user).type == "user"           # left alone
    assert any("logged_in_by" in p for p in prompts)                  # evidence shown
    asked = len(prompts)
    assert adjudicate_entities(store, Judge()) == 0 and len(prompts) == asked  # declined pair not re-asked
    obs = store.observations_for("default", host, limit=50)
    assert any(o.predicate == "cve_finding" for o in obs)


# ------------------------------------------------ chunker edge cases (H-I5) #

def test_chunker_edge_cases():
    from loom.enrich import _chunk_text
    assert _chunk_text("") == []
    assert _chunk_text("   \n\t ") == []
    one = "x" * 5000                      # no whitespace at all: hard cuts
    pieces = _chunk_text(one)
    assert all(len(p[2]) <= 800 for p in pieces) and "".join(p[2] for p in pieces) == one
    multi = "Ünïcødé pärägraph 一二三四五. " * 60
    pieces = _chunk_text(multi)
    for start, end, text in pieces:       # offsets are code-point exact
        assert multi[start:end] == text
    assert sum(len(p[2]) for p in pieces) <= len(multi)
    paras = "\n\n".join(f"para {i} " + "word " * 60 for i in range(5))
    pieces = _chunk_text(paras)
    assert len(pieces) >= 3 and all(paras[s:e] == t for s, e, t in pieces)


def test_worker_shard_from_env_or_ordinal(monkeypatch):
    from loom import enrich
    monkeypatch.setenv("LOOM_WORKER_SHARD", "2/3")
    assert enrich.worker_shard() == (2, 3)
    monkeypatch.setenv("LOOM_WORKER_SHARD", "5/3")
    assert enrich.worker_shard() == (2, 3)          # wraps
    monkeypatch.delenv("LOOM_WORKER_SHARD")
    monkeypatch.setenv("LOOM_WORKER_COUNT", "4")
    monkeypatch.setattr(enrich, "WORKER_ID", "loom-enrich-3")
    assert enrich.worker_shard() == (3, 4)          # StatefulSet ordinal
    monkeypatch.setattr(enrich, "WORKER_ID", "somehost")
    assert enrich.worker_shard() == (0, 4)
    monkeypatch.delenv("LOOM_WORKER_COUNT")
    assert enrich.worker_shard() == (0, 1)          # a lone worker: everything


def test_embedder_passes_dimensions_when_configured(monkeypatch):
    from loom import llm
    seen = {}

    def fake_post(url, body, headers, timeout=120, attempts=3):
        seen.update(body)
        return {"data": [{"index": 0, "embedding": [0.0] * body.get("dimensions", 8)}]}

    monkeypatch.setattr(llm, "_post_json", fake_post)
    monkeypatch.setenv("LOOM_EMBED_PROVIDER", "openrouter")
    monkeypatch.setenv("LOOM_EMBED_MODEL", "openai/text-embedding-3-small")
    monkeypatch.setenv("LOOM_EMBED_DIM", "512")
    e = llm.embedder_from_env()
    assert len(e.embed(["x"])[0]) == 512 and seen["dimensions"] == 512
    monkeypatch.delenv("LOOM_EMBED_DIM")
    assert "dimensions" not in {**llm.embedder_from_env().__dict__} or llm.embedder_from_env().dimensions is None


def test_once_mode_does_not_mistake_a_failed_tick_for_a_drained_backlog():
    """D-039: a locked database on the first tick made a --once worker exit
    with 465k rows pending. A failure keeps the loop alive, bounded."""
    from loom.enrich import FAILED, once_should_stop
    stop, n = once_should_stop({"embedded": FAILED, "chunked": 0}, 0)
    assert not stop and n == 1
    stop, n = once_should_stop({"embedded": 512, "chunked": 0}, n)
    assert not stop and n == 0                          # success resets the streak
    stop, n = once_should_stop({"embedded": 0, "chunked": 0}, 0)
    assert stop and n == 0                              # genuinely drained
    n = 0
    for _ in range(19):
        stop, n = once_should_stop({"embedded": FAILED}, n)
        assert not stop
    stop, n = once_should_stop({"embedded": FAILED}, n)
    assert stop and n == 20                             # bounded, so a CronJob fails loudly


def test_query_embedding_is_single_attempt_with_a_short_timeout(monkeypatch):
    from loom import llm
    calls = []

    def fake_post(url, body, headers, timeout=120, attempts=3):
        calls.append((timeout, attempts, len(body["input"])))
        return {"data": [{"index": i, "embedding": [0.0] * 4} for i in range(len(body["input"]))]}

    monkeypatch.setattr(llm, "_post_json", fake_post)
    e = llm.OpenAICompatEmbedder("http://x/v1", "m")
    e.embed(["a", "b"]); e.embed_query("q")
    assert calls[0] == (120, 3, 2)
    assert calls[1] == (llm.QUERY_EMBED_TIMEOUT, 1, 1)


def test_excerpts_say_which_entity_they_are_about(tmp_path):
    """D-039: a small model attributed one CVE's KEV advisory to the kernel
    CVEs listed next to it. An excerpt now names the entities whose claims
    cite its document."""
    from loom.context import build_pack
    from loom.contracts import AskRequest, ClaimIn, DocumentIn, EntityRef, Provenance
    from loom.enrich import chunk_artifacts
    from loom.llm import HashingEmbedder
    from loom.store.sqlite import SqliteStore
    store = SqliteStore(tmp_path / "about.db")
    t = datetime(2026, 9, 1, tzinfo=timezone.utc)
    store.store_artifact(DocumentIn(namespace="ns", event_id="adv", text="Required action: apply the kernel patch now.",
                                    source="kev", observed_at=t))
    cve = EntityRef(type="cve", key="CVE-2026-1")
    store.record_claim(ClaimIn(namespace="ns", subject=cve, predicate="exploited_in_wild", object=True, source="kev",
                               observed_at=t, provenance=Provenance(artifact_event_id="adv")))
    e = HashingEmbedder()
    chunk_artifacts(store, e, limit=5)
    pack = build_pack(store, AskRequest(namespace="ns", subject=cve, question="required action patch", budget=800), embedder=e)
    ex = [i for i in pack.items if i.kind == "doc_excerpt"]
    assert ex and ex[0].text.startswith('[about cve:CVE-2026-1] "Required action')
    store.close()


def test_find_related_searches_passages_and_maps_them_to_entities(tmp_path):
    """D-040: 'ransomware campaign' finds the CVE whose advisory names one,
    with the passage as evidence — not the predicate ransomware_campaign_use."""
    from loom.context import semantic_search
    from loom.contracts import ClaimIn, DocumentIn, EntityRef, Provenance
    from loom.enrich import chunk_artifacts, embed_pending
    from loom.llm import HashingEmbedder
    from loom.store.sqlite import SqliteStore
    store = SqliteStore(tmp_path / "rel.db")
    t = datetime(2026, 9, 1, tzinfo=timezone.utc)
    store.store_artifact(DocumentIn(namespace="ns", event_id="adv", source="kev", observed_at=t,
                                    text="The Medusa ransomware campaign exploited this flaw in web servers during March."))
    target = EntityRef(type="cve", key="CVE-2026-77")
    store.record_claims([
        ClaimIn(namespace="ns", subject=target, predicate="exploited_in_wild", object=True, source="kev",
                observed_at=t, provenance=Provenance(artifact_event_id="adv")),
        ClaimIn(namespace="ns", subject=EntityRef(type="cve", key="CVE-2026-1"), predicate="ransomware_campaign_use",
                object="Unknown", source="kev", observed_at=t),
    ])
    e = HashingEmbedder()
    embed_pending(store, e); chunk_artifacts(store, e, limit=5)
    r = semantic_search(store, "ns", e, "medusa ransomware campaign web servers", limit=3)
    top = r.matches[0]
    assert top.entity == target and top.evidence.kind == "doc_excerpt"
    assert top.evidence.text.startswith('[about cve:CVE-2026-77] "The Medusa ransomware')
    assert top.evidence.citations[0].artifact_id
    # scoped callers do not see entities outside their types
    assert all(m.entity.type == "cve" for m in semantic_search(store, "ns", e, "medusa", limit=3, allowed_types=("cve",)).matches)
    store.close()


def _alias_store(tmp_path):
    from loom.store.sqlite import SqliteStore
    store = SqliteStore(tmp_path / "alias.db")
    t = datetime(2026, 9, 1, tzinfo=timezone.utc)
    def cve(n): return EntityRef(type="cve", key=f"CVE-2026-{n}")
    def prod(k): return EntityRef(type="product", key=k)
    claims = []
    # NVD side: many CVEs affect linux:linux_kernel; a few affect cisco:ios and cisco:ios_xe
    for n in range(6):
        claims.append(ClaimIn(namespace="ns", subject=cve(n), predicate="affects", object=prod("linux:linux_kernel"), source="nvd", observed_at=t))
    for k in ("cisco:ios", "cisco:ios_xe", "atlassian:confluence_server", "atlassian:confluence_data_center",
              "curl:curl", "microsoft:windows_10", "microsoft:windows_11"):
        claims.append(ClaimIn(namespace="ns", subject=cve(100 + len(claims)), predicate="affects", object=prod(k), source="nvd", observed_at=t))
    # KEV side: freehand keys
    for k, n in (("linux:kernel", 900), ("haxx:curl", 901), ("atlassian:confluence", 902), ("microsoft:windows", 903)):
        claims.append(ClaimIn(namespace="ns", subject=cve(n), predicate="affects", object=prod(k), source="cisa-kev", observed_at=t))
        claims.append(ClaimIn(namespace="ns", subject=cve(n), predicate="exploited_in_wild", object=True, source="cisa-kev", observed_at=t))
    store.record_claims(claims)
    return store


def test_alias_candidates_are_structural_and_unambiguous(tmp_path):
    """D-042: vendor repeated in the product, same product under another
    vendor, a bare family name with one longer key — and never a guess when
    several keys could match."""
    from loom.enrich import alias_candidates
    store = _alias_store(tmp_path)
    pairs = {tuple(sorted((a.key, b.key))) for a, b in alias_candidates(store, "ns", "product")}
    assert ("linux:kernel", "linux:linux_kernel") in pairs           # R1
    assert ("curl:curl", "haxx:curl") in pairs                       # R2
    assert not any("windows" in a for a, b in pairs)                  # windows -> windows_10 / _11: ambiguous
    assert not any("confluence" in a for a, b in pairs)               # two longer keys: ambiguous
    assert ("cisco:ios", "cisco:ios_xe") in pairs                     # a sibling IS offered; the adjudicator must decline it
    store.close()


def test_alias_adjudication_merges_on_yes_and_repoints_kev_edges(tmp_path, monkeypatch):
    from loom import enrich
    from loom.enrich import adjudicate_aliases
    store = _alias_store(tmp_path)
    asked = []

    class Judge:
        model = "fake"
        def complete(self, system, user, max_tokens=200):
            asked.append(user)
            same = "linux:kernel" in user and "linux:linux_kernel" in user
            return json.dumps({"same": same, "confidence": 0.95 if same else 0.9, "reason": "test"})

    monkeypatch.setattr(enrich, "_declined", set())
    counts = adjudicate_aliases(store, Judge(), "ns", ("product",), limit=10)
    assert counts["merged"] == 1 and counts["declined"] == counts["asked"] - 1 and counts["asked"] >= 2
    # the stray KEV key folded into the connected CPE key: its KEV CVE now hangs off linux:linux_kernel
    edges = store.observations_for("ns", EntityRef(type="product", key="linux:linux_kernel"), limit=100)
    assert any(o.subject.key == "CVE-2026-900" and o.source == "cisa-kev" for o in edges)
    # declined pairs are not re-asked
    before = len(asked)
    adjudicate_aliases(store, Judge(), "ns", ("product",), limit=10)
    assert len(asked) == before
    # dry run asks nothing
    assert adjudicate_aliases(store, Judge(), "ns", ("product",), limit=10, dry_run=True)["asked"] == 0
    store.close()


def test_structured_entity_absorbs_the_extracted_one_even_when_outnumbered(tmp_path):
    """D-043: extraction's ip_address:10.0.4.7 out-counted the DHCP log's
    ip:10.0.4.7 and the structured key became the alias. Never again."""
    from loom.enrich import resolve_entities
    from loom.store.sqlite import SqliteStore
    store = SqliteStore(tmp_path / "abs.db")
    t = datetime(2026, 9, 1, tzinfo=timezone.utc)
    ip = EntityRef(type="ip", key="10.0.4.7"); loose = EntityRef(type="ip_address", key="10.0.4.7")
    store.record_claims([ClaimIn(namespace="ns", subject=ip, predicate="assigned_to", object=EntityRef(type="host", key="h"),
                                 source="dhcp-log", observed_at=t)])
    store.record_claims([ClaimIn(namespace="ns", subject=loose, predicate=f"mentioned_{i}", object="x", source="doc:extract",
                                 observed_at=t, attrs={"extracted": True}) for i in range(12)])
    assert resolve_entities(store) == 1
    assert store.get_entity("ns", ip) is not None and store.get_entity("ns", ip).type == "ip"
    keys = {(o.subject.type, o.subject.key) for o in store.observations_for("ns", ip, limit=50)}
    assert keys == {("ip", "10.0.4.7")}          # every fact now reads under the structured key
    store.close()
