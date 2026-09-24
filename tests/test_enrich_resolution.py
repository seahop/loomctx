"""Entity-resolution hardening (2026-09-24 review): an unmerge sticks in
every tier, an operator can rule two entities distinct, and adjudication
spend is bounded — every model call counts against the per-tick cap, a
reply that cannot be read backs off and is given up on, and verdicts are
read the way models actually write them."""

import json
from datetime import datetime, timezone

import pytest

from loom import enrich
from loom.contracts import ClaimIn, EntityRef, EntityTypeDef, SchemaRegistration
from loom.llm import LLMClient, LLMError
from loom.store.sqlite import SqliteStore

T = datetime(2026, 9, 1, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _fresh_worker_state():
    enrich._declined_cache.clear()
    enrich._adjudication_failures.clear()
    enrich._alias_seen_until.clear()
    yield
    enrich._declined_cache.clear()
    enrich._adjudication_failures.clear()
    enrich._alias_seen_until.clear()


def _claim(subject, predicate, obj, source="s", ns="default"):
    return ClaimIn(namespace=ns, subject=subject, predicate=predicate, object=obj,
                   observed_at=T, source=source)


class Scripted(LLMClient):
    """Replies from a function of the prompt; records every call."""
    model = "scripted"

    def __init__(self, reply):
        self.reply = reply
        self.prompts = []
        self.last_usage = {"prompt_tokens": 1, "completion_tokens": 1}

    def complete(self, system, user, max_tokens=1024):
        self.prompts.append(user)
        out = self.reply(user)
        if isinstance(out, Exception):
            raise out
        return out


def _yes(_prompt):
    return json.dumps({"same": True, "confidence": 0.95, "reason": "same"})


# ------------------------------------------------------------- unmerge sticks #

def test_unmerge_sticks_in_the_automatic_tiers(tmp_path):
    """Tier 1 (extractor type drift) and tier 2 (spelling drift) used to
    re-merge an unmerged pair within one tick: unmerge recorded nothing
    and the automatic tiers never looked at declines."""
    store = SqliteStore(tmp_path / "u.db")
    ip, loose = EntityRef(type="ip", key="10.0.4.7"), EntityRef(type="ip_address", key="10.0.4.7")
    web, drift = EntityRef(type="host", key="web-01"), EntityRef(type="host", key="web01")
    for i in range(3):
        store.record_claim(_claim(ip, "assigned_to", EntityRef(type="host", key=f"h{i}")))
        store.record_claim(_claim(web, "runs_os", f"os{i}"))
    store.record_claim(_claim(loose, "mentioned_in", "IR-1", source="doc:ir"))
    store.record_claim(_claim(drift, "runs_os", "fedora"))
    assert enrich.resolve_entities(store) == 2
    assert store.get_entity("default", loose).type == "ip"

    # the worker has its decline cache loaded when the operator acts
    assert enrich._is_declined(store, "default", "ip:10.0.4.7", "ip_address:10.0.4.7") is False
    assert enrich.unmerge_and_decline(store, "default", loose)
    assert enrich.unmerge_and_decline(store, "default", drift)
    assert ("ip:10.0.4.7", "ip_address:10.0.4.7") in store.declined_pairs("default")

    for _ in range(2):                                    # the next ticks leave them apart
        assert enrich.resolve_entities(store) == 0
    assert store.get_entity("default", loose).type == "ip_address"
    assert store.get_entity("default", drift).key == "web01"
    # a stale per-process cache (the unmerge ran in another process) is refreshed per job
    enrich._declined_cache["default"] = set()
    assert enrich.resolve_entities(store) == 0
    store.close()


def test_unmerged_adjudicated_pair_is_not_re_asked(tmp_path):
    """An LLM-approved merge that an operator reverses must not be re-asked
    (and re-merged) on the next tick."""
    store = SqliteStore(tmp_path / "a.db")
    store.put_schema(SchemaRegistration(namespace="default", entity_types=[
        EntityTypeDef(name="user"), EntityTypeDef(name="group")]))
    user, group = EntityRef(type="user", key="admin"), EntityRef(type="group", key="admin")
    for i in range(3):
        store.record_claim(_claim(user, "logged_in_to", EntityRef(type="host", key=f"h{i}")))
    store.record_claim(_claim(group, "has_member", EntityRef(type="user", key="jdoe")))
    judge = Scripted(_yes)
    assert enrich.resolve_entities(store, llm=judge) == 1
    assert enrich.unmerge_and_decline(store, "default", group)
    assert enrich.resolve_entities(store, llm=judge) == 0
    assert len(judge.prompts) == 1
    assert store.get_entity("default", group).type == "group"
    store.close()


def test_unmerge_can_opt_out_of_the_decline(tmp_path):
    store = SqliteStore(tmp_path / "o.db")
    ip, loose = EntityRef(type="ip", key="10.0.4.7"), EntityRef(type="ip_address", key="10.0.4.7")
    store.record_claim(_claim(ip, "assigned_to", EntityRef(type="host", key="h")))
    store.record_claim(_claim(loose, "mentioned_in", "IR-1", source="doc:ir"))
    assert enrich.resolve_entities(store) == 1
    assert enrich.unmerge_and_decline(store, "default", loose, remember=False)
    assert store.declined_pairs("default") == set()
    assert enrich.resolve_entities(store) == 1            # the resolver may redo it
    assert enrich.unmerge_and_decline(store, "default", EntityRef(type="host", key="nope")) is False
    store.close()


def test_lifecycle_unmerge_records_the_decline(tmp_path, monkeypatch, capsys):
    from loom.lifecycle import main
    monkeypatch.setenv("LOOM_DB", str(tmp_path / "l.db"))
    monkeypatch.delenv("LOOM_SHARDS", raising=False)
    monkeypatch.delenv("LOOM_BLOB_THRESHOLD", raising=False)
    s = SqliteStore(tmp_path / "l.db")
    ip, loose = EntityRef(type="ip", key="10.0.4.7"), EntityRef(type="ip_address", key="10.0.4.7")
    s.record_claim(_claim(ip, "assigned_to", EntityRef(type="host", key="h")))
    s.record_claim(_claim(loose, "mentioned_in", "IR-1", source="doc:ir"))
    assert s.merge_entities("default", loose, ip)
    s.close()
    main(["unmerge", "--namespace", "default", "--alias", "ip_address:10.0.4.7"])
    assert capsys.readouterr().out.strip() == "unmerged"
    s = SqliteStore(tmp_path / "l.db")
    try:
        assert s.declined_pairs("default") == {("ip:10.0.4.7", "ip_address:10.0.4.7")}
        assert enrich.resolve_entities(s) == 0
    finally:
        s.close()


def test_distinct_cli_unmerges_and_declines(tmp_path, monkeypatch, capsys):
    """`python -m loom.enrich distinct a b`: the operator's ruling. A pair
    currently merged is split first; either way it is never merged or
    asked about again."""
    monkeypatch.setenv("LOOM_DB", str(tmp_path / "d.db"))
    monkeypatch.delenv("LOOM_SHARDS", raising=False)
    monkeypatch.delenv("LOOM_BLOB_THRESHOLD", raising=False)
    s = SqliteStore(tmp_path / "d.db")
    web, drift = EntityRef(type="host", key="web-01"), EntityRef(type="host", key="web01")
    for i in range(3):
        s.record_claim(_claim(web, "runs_os", f"os{i}"))
    s.record_claim(_claim(drift, "runs_os", "fedora"))
    s.record_claim(_claim(EntityRef(type="host", key="db-01"), "runs_os", "x"))
    s.record_claim(_claim(EntityRef(type="host", key="DB_01"), "runs_os", "y"))
    assert enrich.resolve_entities(s) == 2
    s.close()
    enrich.main(["distinct", "host:web01", "host:web-01", "--namespace", "default"])
    out = json.loads(capsys.readouterr().out)
    assert out["unmerged"] == "host:web01" and out["declined"] is True
    # a pair never merged can be ruled distinct too (the resolver then leaves it alone)
    enrich.main(["distinct", "host:db-01", "host:x-99", "--namespace", "default"])
    assert json.loads(capsys.readouterr().out)["unmerged"] is None
    s = SqliteStore(tmp_path / "d.db")
    try:
        assert ("host:web-01", "host:web01") in s.declined_pairs("default")
        assert enrich.resolve_entities(s) == 0
        assert s.get_entity("default", drift).key == "web01"
    finally:
        s.close()


# ----------------------------------------------------------- spend is capped #

def _cross_type_store(tmp_path, n):
    """n cross-type fuzzy collisions (host:srvN vs asset:SRV_N): each one an
    adjudication candidate."""
    store = SqliteStore(tmp_path / "x.db")
    for i in range(n):
        store.record_claim(_claim(EntityRef(type="host", key=f"srv-{i:02d}"), "runs_os", "linux"))
        store.record_claim(_claim(EntityRef(type="host", key=f"srv-{i:02d}"), "owner", "ops"))
        store.record_claim(_claim(EntityRef(type="asset", key=f"SRV_{i:02d}"), "tag", "x", source="doc:x"))
    return store


def test_unreadable_verdicts_count_against_the_cap_back_off_and_give_up(tmp_path, monkeypatch):
    """`"same": "maybe"` returned None and was not counted: the pair was
    re-asked and re-billed every tick forever, and every tick asked all
    of them. Now each call counts, the pair backs off, and after
    ADJUDICATION_MAX_FAILURES unreadable replies it is declined for good."""
    store = _cross_type_store(tmp_path, 12)
    judge = Scripted(lambda p: '{"same": "maybe", "confidence": 0.9}')
    assert enrich.adjudicate_entities(store, judge) == 0
    assert len(judge.prompts) == enrich.ADJUDICATIONS_PER_TICK          # capped, though none parsed
    # the failed pairs back off: the next tick spends its calls on the others
    enrich.adjudicate_entities(store, judge)
    assert len(judge.prompts) == 12
    assert len(set(judge.prompts)) == 12
    enrich.adjudicate_entities(store, judge)
    assert len(judge.prompts) == 12                                       # everything backing off: no calls

    monkeypatch.setattr(enrich, "ADJUDICATION_BACKOFF_BASE", 0.0)       # let the backoff lapse
    for key in list(enrich._adjudication_failures):
        enrich._adjudication_failures[key] = (enrich._adjudication_failures[key][0], 0.0)
    for _ in range(10):
        enrich.adjudicate_entities(store, judge)
    # every pair given up after exactly MAX_FAILURES calls, then never billed again
    assert len(judge.prompts) == 12 * enrich.ADJUDICATION_MAX_FAILURES
    assert len(store.declined_pairs("default")) == 12
    enrich.adjudicate_entities(store, judge)
    assert len(judge.prompts) == 12 * enrich.ADJUDICATION_MAX_FAILURES
    reasons = {d["reason"] for d in store.iter_declines("default")}
    assert all(r.startswith("gave up after 3 unreadable") for r in reasons)
    store.close()


def test_provider_outage_ends_the_pass_without_giving_up(tmp_path):
    store = _cross_type_store(tmp_path, 5)
    judge = Scripted(lambda p: LLMError("provider returned 503: overloaded"))
    enrich.adjudicate_entities(store, judge)
    assert len(judge.prompts) == 1                     # the first outage stops the pass
    assert store.declined_pairs("default") == set()    # an outage is not the pair's fault
    (count, _), = enrich._adjudication_failures.values()
    assert count == 0


def test_failing_alias_pairs_do_not_starve_the_rest(tmp_path):
    """Tier 3: the same failing pairs took every slot of every tick."""
    store = SqliteStore(tmp_path / "al.db")
    claims = []
    for n, k in enumerate(("linux:kernel", "linux:linux_kernel", "haxx:curl", "curl:curl",
                           "apache:struts", "apache:apache_struts")):
        claims.append(ClaimIn(namespace="ns", subject=EntityRef(type="cve", key=f"CVE-2026-{n}"),
                              predicate="affects", object=EntityRef(type="product", key=k),
                              source="nvd", observed_at=T))
    store.record_claims(claims)
    pairs = enrich.alias_candidates(store, "ns", "product")
    assert len(pairs) == 3

    def reply(prompt):
        if "curl" in prompt:
            return json.dumps({"same": True, "confidence": 0.9})
        return "I think these might be the same, hard to say."   # no JSON: unreadable

    judge = Scripted(reply)
    first = enrich.adjudicate_aliases(store, judge, "ns", ("product",), limit=2)
    assert first["asked"] == 2
    second = enrich.adjudicate_aliases(store, judge, "ns", ("product",), limit=2)
    # the pair that failed backs off; the untried one gets the slot
    tried = {p.split("\n")[0] for p in judge.prompts}
    assert len(judge.prompts) == 3 and second["asked"] == 1 and len(tried) == 3
    store.close()


@pytest.mark.parametrize("reply, same, confidence", [
    ('{"same": true, "confidence": 0.93, "reason": "r"}', True, 0.93),
    ('{"same": "yes", "confidence": "0.9"}', True, 0.9),
    ('{"same": "True", "confidence": "90%"}', True, 0.9),
    ('{"same": "no", "confidence": 85}', False, 0.85),
    ('{"same": 1, "confidence": "high"}', True, 0.9),
    ('{"same": false}', False, 0.0),
    ("```json\n{\"same\": \"No.\", \"confidence\": 0.7}\n```", False, 0.7),
    ("Sure! {'same': True, 'confidence': 0.95, 'reason': 'same product',}", True, 0.95),
])
def test_verdicts_parse_leniently(reply, same, confidence):
    verdict = enrich._parse_verdict(reply)
    assert verdict["same"] is same and verdict["confidence"] == pytest.approx(confidence)


@pytest.mark.parametrize("reply", [
    '{"same": "maybe", "confidence": 0.9}',
    '{"confidence": 0.9}',
    '{"same": true, "confidence": "certain"}',
    "no JSON here",
    None,
])
def test_unreadable_verdicts_raise(reply):
    with pytest.raises(ValueError):
        enrich._parse_verdict(reply)


def test_chunking_refuses_a_short_embedding_reply(tmp_path, monkeypatch):
    """zip() stored the head and marked the artifact chunked with its tail
    missing for good."""
    from loom.contracts import DocumentIn
    from loom.llm import HashingEmbedder

    class Short(HashingEmbedder):
        def embed(self, texts):
            return super().embed(texts)[:-1]

    monkeypatch.setattr(enrich, "LEASE_SECONDS", 0.0)      # the failed lease lapses at once
    store = SqliteStore(tmp_path / "c.db")
    store.store_artifact(DocumentIn(text="para one. " * 80 + "\n\n" + "para two. " * 80,
                                    source="ir", observed_at=T))
    with pytest.raises(LLMError):
        enrich.chunk_artifacts(store, Short())
    assert enrich.chunk_artifacts(store, HashingEmbedder()) > 0     # still pending, done properly
    store.close()


def test_dossier_skips_a_blank_reply(tmp_path, monkeypatch):
    store = SqliteStore(tmp_path / "b.db")
    ref = EntityRef(type="host", key="web-01")
    monkeypatch.setattr(store, "dossier_candidates", lambda *a, **k: [("default", ref, 30)])
    store.record_claim(_claim(ref, "runs_os", "fedora"))
    assert enrich.refresh_dossiers(store, Scripted(lambda p: None)) == 0
    assert enrich.refresh_dossiers(store, Scripted(lambda p: "   ")) == 0
    assert enrich.refresh_dossiers(store, Scripted(lambda p: "web-01 runs fedora.")) == 1
    store.close()
