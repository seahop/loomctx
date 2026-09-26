"""Retrieval evaluation harness (R-6). Question generation, ground truth,
rule-based scoring, every condition and the scorecard run here against the
seed corpus with the scripted reader and a canned model — no network."""

import json
from datetime import datetime, timezone

import pytest

from loom import retrieval_eval as re_
from loom.contracts import ClaimIn, EntityRef
from loom.llm import HashingEmbedder
from loom.seed import cmd_load
from loom.store.sqlite import SqliteStore


@pytest.fixture(scope="module")
def db(tmp_path_factory):
    path = tmp_path_factory.mktemp("reval") / "seed.db"
    cmd_load(str(path), seed=42)
    return str(path)


@pytest.fixture(scope="module")
def store(db):
    s = SqliteStore(db)
    yield s
    s.close()


@pytest.fixture(scope="module")
def questions(store):
    return re_.generate_questions(store, ["netsec", "procurement"], seed=7)


def _by(questions, prefix):
    return [q for q in questions if q.id.startswith(prefix)]


def test_questions_are_deterministic_store_derived_and_cover_every_family(store, questions):
    again = re_.generate_questions(store, ["netsec", "procurement"], seed=7)
    assert [q.id for q in again] == [q.id for q in questions]
    assert len(questions) >= 12
    assert {q.family for q in questions} == set(re_.FAMILIES)
    # a different seed samples differently but the planted moments stay
    other = re_.generate_questions(store, ["netsec", "procurement"], seed=8)
    assert any(q.id.startswith("lease:10.0.4.7@") for q in other)
    # the lease: valid_at picks the holder of the window covering T, as_of only
    # what was known — and the other holder is a rejected answer
    aug = next(q for q in questions if q.id == "lease:10.0.4.7@2026-08-20:valid_at")
    assert aug.truth == "laptop-17" and aug.reject == ["web-01"] and aug.valid_at and aug.as_of is None
    jul = next(q for q in questions if q.id == "lease:10.0.4.7@2026-07-21:as_of")
    assert jul.truth == "web-01" and jul.as_of and jul.valid_at is None
    known_both = next(q for q in questions if q.id == "lease:10.0.4.7@2026-08-20:as_of")
    assert known_both.truth == "laptop-17"
    # every truth id is a real observation and belongs to the question's namespace
    for q in questions:
        got = store.observations_by_ids(q.namespace, q.truth_ids)
        assert len(got) == len(q.truth_ids), q.id
    # the planted conflicts, in both namespaces
    os_q = next(q for q in questions if q.id == "conflict:host:web-01:runs_os")
    assert os_q.truth == ["fedora-44", "ubuntu-22.04"]
    assert any(q.id == "conflict:vendor:initech:contract_owner" for q in questions)
    # abstention: entities that do not exist, predicates nobody recorded
    fakes = _by(questions, "abstention:entity:")
    assert fakes and all(store.get_entity(q.namespace, q.subject) is None for q in fakes)
    preds = _by(questions, "abstention:predicate:")
    assert preds and all(q.truth is None for q in preds)
    # the seed's two-hop chains: alert -> host -> domain, alert -> host -> users that day
    dom = next(q for q in questions if q.id == "multihop:domain:AL-2291")
    assert dom.truth == "corp.local" and dom.scope.expand == ["triggered_on", "member_of"]
    logins = next(q for q in questions if q.id == "multihop:logins:AL-2291")
    assert "jdoe" in logins.truth and logins.probe["date"] == "2026-09-01"
    # numeric: a single-valued port and the largest invoice
    assert any(q.id == "numeric:host:db-01:listens_on_port" and q.truth == 5432.0 for q in questions)
    assert any(q.id.startswith("numeric:vendor:") and ":max-invoiced_amount" in q.id for q in questions)
    assert all(q.truth in ("A", "B") and len(q.truth_ids) == 2 for q in _by(questions, "order:"))


def test_truth_follows_the_store(tmp_path):
    path = tmp_path / "moved.db"
    cmd_load(str(path), seed=42)
    store = SqliteStore(path)
    t = datetime(2026, 8, 12, tzinfo=timezone.utc)
    store.record_claim(ClaimIn(namespace="netsec", subject=EntityRef(type="ip", key="10.0.4.7"),
                               predicate="assigned_to", object=EntityRef(type="host", key="db-02"),
                               observed_at=t, valid_from=t, valid_to=datetime(2026, 8, 30, tzinfo=timezone.utc),
                               source="dhcp-log"))
    qs = re_.generate_questions(store, ["netsec"], seed=7, families=["lease"])
    # Aug 20 now has two holders (db-02 overlaps the open-ended laptop-17
    # lease): no crisp answer, so that T is no longer asked; the July
    # question survives and db-02 joins its wrong answers
    assert not any(q.id.startswith("lease:10.0.4.7@2026-08-20") for q in qs)
    jul = next(q for q in qs if q.id == "lease:10.0.4.7@2026-07-21:valid_at")
    assert jul.truth == "web-01" and jul.reject == ["db-02", "laptop-17"]
    store.close()


def _ctx(ids=(), condition="loom@800"):
    return re_.Context(condition, "", set(ids), 10, 1.0, len(ids))


def test_scoring_rules_per_kind():
    ids = ["ab" * 16, "cd" * 16]
    q = re_.Question("lease:x", "lease", "?", "netsec", "entity", "laptop-17", ids, reject=["web-01"])
    assert re_.score(q, "answer: host:laptop-17\ncites: abababababab", _ctx(ids))["pass_"]
    s = re_.score(q, "answer: host:laptop-17\ncites: abababababab, cdcdcdcdcdcd", _ctx(ids))
    assert s["support_answer"] and s["cites_unseen"] == 0
    # the asserted answer is graded, not the history in an aside (D-057)
    assert re_.score(q, "answer: laptop-17 (previously web-01)\ncites: none", _ctx(ids))["pass_"]
    s = re_.score(q, "answer: host:web-01 (laptop-17 from Aug 10)\ncites: none", _ctx(ids))
    assert not s["pass_"] and s["rejected"] == ["web-01"]
    assert not re_.score(q, "answer: laptop-17, web-01\ncites: none", _ctx(ids))["pass_"]
    # whole tokens: laptop-170 does not name laptop-17
    assert not re_.score(q, "answer: host:laptop-170\ncites: none", _ctx(ids))["pass_"]
    assert not re_.score(q, "answer: unknown\ncites: none", _ctx(ids))["pass_"]
    s = re_.score(q, "answer: host:laptop-17\ncites: deadbeefdead", _ctx(ids))
    assert s["pass_"] and s["cites_unseen"] == 1 and not s["support_answer"]
    # a date or a count is not a citation (it used to count as an unseen one)
    s = re_.score(q, "answer: host:laptop-17\ncites: 20260820, 12345678", _ctx(ids))
    assert s["cites"] == 0 and s["cites_unseen"] == 0
    # abstention: anything but unknown is a hallucination
    q = re_.Question("abstention:x", "abstention", "?", "netsec", "unknown", None, [])
    assert re_.score(q, "answer: unknown\ncites: none", _ctx())["pass_"]
    s = re_.score(q, "answer: fedora-44\ncites: none", _ctx())
    assert not s["pass_"] and s["hallucinated"]
    # conflict: every value must be named; the word alone never suffices
    q = re_.Question("conflict:x", "conflict", "?", "netsec", "conflict", ["fedora-44", "ubuntu-22.04"], ids)
    assert re_.score(q, "answer: conflicting: fedora-44 | ubuntu-22.04\ncites: none", _ctx())["pass_"]
    assert re_.score(q, "answer: Fedora 44 and Ubuntu 22.04\ncites: none", _ctx())["pass_"]
    assert not re_.score(q, "answer: fedora-44\ncites: none", _ctx())["pass_"]
    assert not re_.score(q, "answer: conflicting: fedora-44\ncites: none", _ctx())["pass_"]
    q = re_.Question("conflict:c", "conflict", "?", "netsec", "conflict", ["7.5", "9.8"], ids)
    assert not re_.score(q, "answer: no conflict, 7.5\ncites: none", _ctx())["pass_"]
    assert not re_.score(q, "answer: sources conflict\ncites: none", _ctx())["pass_"]
    assert not re_.score(q, "answer: conflicting: 17.5 | 9.8\ncites: none", _ctx())["pass_"]
    assert re_.score(q, "answer: conflicting: 7.5 | 9.8\ncites: none", _ctx())["pass_"]
    # numbers: half a unit in the last recorded decimal place
    q = re_.Question("numeric:x", "numeric", "?", "netsec", "number", 41234.56, ids)
    assert re_.score(q, "answer: 41,234.56\ncites: none", _ctx())["pass_"]
    assert not re_.score(q, "answer: 41234.6\ncites: none", _ctx())["pass_"]
    # an EPSS-sized probability: `0` used to pass under the absolute 0.005
    q = re_.Question("numeric:e", "numeric", "?", "netsec", "number", 0.00043, ids,
                     tolerance=re_._tolerance(0.00043))
    assert re_.score(q, "answer: 0.00043\ncites: none", _ctx())["pass_"]
    assert not re_.score(q, "answer: 0\ncites: none", _ctx())["pass_"]
    assert not re_.score(q, "answer: 0.0004\ncites: none", _ctx())["pass_"]
    assert re_._tolerance(5432.0) == 0.5 == re_._tolerance(5400.0) and re_._tolerance(0.94321) == 0.000005
    assert abs(re_._tolerance(4.3e-05) - 5e-07) < 1e-15
    assert re_._tolerance(0.1 + 0.2) > 1e-11       # float noise does not demand 17 digits
    q = re_.Question("multihop:x", "multihop", "?", "netsec", "ids", ["CVE-2026-1", "CVE-2026-2"], ids,
                     probe={"id_regex": re_._CVE.pattern})
    assert re_.score(q, "answer: cve:CVE-2026-0002, cve:CVE-2026-0001\ncites: none", _ctx())["pass_"] is False
    q.truth = ["CVE-2026-0001", "CVE-2026-0002"]
    assert re_.score(q, "answer: cve:CVE-2026-0002, cve:CVE-2026-0001\ncites: none", _ctx())["pass_"]
    s = re_.score(q, "answer: CVE-2026-0001\ncites: none", _ctx())
    assert not s["pass_"] and s["recall"] == 0.5 and s["precision"] == 1.0
    q = re_.Question("multihop:u", "multihop", "?", "netsec", "ids", ["jdoe", "rlee"], ids)
    assert re_.score(q, "answer: user:rlee, user:jdoe\ncites: none", _ctx())["pass_"]
    q = re_.Question("order:x", "order", "?", "netsec", "order", "B", ids)
    assert re_.score(q, "answer: B\ncites: none", _ctx())["pass_"]
    assert re_.score(q, "answer: (B)\ncites: none", _ctx())["pass_"]
    assert not re_.score(q, "answer: A\ncites: none", _ctx())["pass_"]
    # "Both" used to pass for B on its first letter
    assert not re_.score(q, "answer: Both\ncites: none", _ctx())["pass_"]
    # a reply without the format still yields a value
    assert re_.parse_answer("B, because it was earlier [abababababab]") == ("B, because it was earlier [abababababab]", ["abababababab"])


def test_scripted_reader_answers_from_the_context_only(store, questions):
    reader = re_.ScriptedReader()
    aug = next(q for q in questions if q.id == "lease:10.0.4.7@2026-08-20:valid_at")
    # loom applies valid_at: one lease survives and the reader cites it
    ctx = re_.build_context(store, aug, "loom@800")
    reply, usage = reader.answer(aug, re_.SYSTEM, ctx.prompt)
    s = re_.score(aug, reply, ctx)
    assert s["pass_"] and s["support_pack"] and s["support_answer"] and s["cites_unseen"] == 0
    # the full baseline shows both leases with windows; the reader reads them
    full = re_.build_context(store, aug, "full")
    assert full.items >= 2 and full.tokens_est > 0
    reply, _ = reader.answer(aug, re_.SYSTEM, full.prompt)
    assert re_.score(aug, reply, full)["pass_"]
    # an empty context is answered `unknown`, never guessed
    fake = next(q for q in questions if q.id.startswith("abstention:entity:"))
    ctx = re_.build_context(store, fake, "loom@400")
    assert "(none found)" in ctx.prompt
    reply, _ = reader.answer(fake, re_.SYSTEM, ctx.prompt)
    assert re_.score(fake, reply, ctx)["pass_"]
    # the conflict item is read as a conflict
    os_q = next(q for q in questions if q.id == "conflict:host:web-01:runs_os")
    ctx = re_.build_context(store, os_q, "loom@400")
    reply, _ = reader.answer(os_q, re_.SYSTEM, ctx.prompt)
    assert reply.startswith("answer: conflicting: fedora-44 | ubuntu-22.04")
    # the two-hop chain is read through relation items
    dom = next(q for q in questions if q.id == "multihop:domain:AL-2291")
    ctx = re_.build_context(store, dom, "loom@1600")
    reply, _ = reader.answer(dom, re_.SYSTEM, ctx.prompt)
    assert re_.score(dom, reply, ctx)["pass_"], ctx.prompt


def _charged(ctx) -> int:
    from loom.context import item_tokens
    from loom.contracts import Citation, ContextItem
    total = 0
    for ln in re_.parse_context(ctx.prompt):
        # the rendered line carries the cite token, not the id; charge the item as the packer does
        total += item_tokens(ContextItem(kind="fact", text=ln.raw, score=1.0, citations=[
            Citation(observation_id="0" * 32, source=ln.source, observed_at=datetime(2026, 1, 1))]))
    return total


def test_reader_parses_corrected_facts(store, questions):
    """A superseded fact renders with `[superseded by ...]` in packs only;
    the reader missed it and loom@B lost an ordering it carried."""
    lines = re_.parse_context("- (fact) vendor:hooli contract_owner mchen (2026-07-06, per contract-db) "
                              "[superseded by 95236a39ee8c] [6a3205049db9]")
    assert lines[0].predicate == "contract_owner" and lines[0].object == "mchen"
    assert lines[0].observed == "2026-07-06" and lines[0].cites == ["6a3205049db9"]
    for q in (q for q in questions if q.family == "order"):
        ctx = re_.build_context(store, q, "loom@3200")
        if set(q.truth_ids) <= ctx.cite_ids:
            reply, _ = re_.ScriptedReader().answer(q, re_.SYSTEM, ctx.prompt)
            assert re_.score(q, reply, ctx)["pass_"], q.id


def test_vector_and_recency_fill_the_same_budget_as_loom(store, questions):
    q = next(q for q in questions if q.id == "conflict:host:web-01:runs_os")
    assert re_.build_context(store, q, "vector@400").note.startswith("skipped")
    small = re_.build_context(store, q, "vector@200", embedder=HashingEmbedder())
    big = re_.build_context(store, q, "vector@1600", embedder=HashingEmbedder())
    assert not small.note.startswith("skipped") and 0 < small.items < big.items
    # filled with the pack's own accounting: never past B, and close to it
    assert 120 <= _charged(small) <= 200
    # cosine on the rendered fact text ranks the runs_os facts first
    assert "runs_os" in small.prompt.split("\n")[4]
    rec = re_.build_context(store, q, "recency@200")
    assert 0 < rec.items and _charged(rec) <= 200
    assert rec.tokens_est < re_.build_context(store, q, "full").tokens_est
    # the budgeted names are budget-major; a bare baseline name is refused
    assert re_.condition_names((400, 800), ["loom", "vector", "recency", "full"]) == [
        "loom@400", "vector@400", "recency@400", "loom@800", "vector@800", "recency@800", "full"]
    with pytest.raises(ValueError):
        re_.build_context(store, q, "vector")
    with pytest.raises(ValueError):
        re_.condition_names((400,), ["bm25"])


def test_full_baseline_is_measured_not_sent_past_the_cap_and_not_scored(store, questions):
    q = next(q for q in questions if q.id == "multihop:logins:AL-2291")
    ctx = re_.build_context(store, q, "full", full_cap=200)
    assert ctx.note.startswith("not sent") and ctx.tokens_est > 200
    records = re_.evaluate(store, [q, questions[0]], re_.ScriptedReader(), ["full"], full_cap=200)
    assert records[0].status == "not_sent" and records[0].score["pass_"] is None
    # the row is counted, not failed: accuracy is over what was answered
    s = re_.summarize(records, ["full"])["full"]
    assert s["not_sent"] >= 1 and s["n"] == sum(r.status == "ok" for r in records)
    if s["n"]:
        assert s["accuracy"] == s["passed"] / s["n"]
    md = re_.markdown(re_.summarize(records, ["full"]), {"runs": 1})
    assert "| n | Not sent / errored |" in md and f"| `full` | {s['n']} | {s['not_sent']} / 0 |" in md


class _Replies:
    """A model with fixed (text, usage) replies, in order."""
    model = "fake"

    def __init__(self, *replies):
        self.replies = list(replies)

    def answer(self, q, system, prompt):
        return self.replies.pop(0)


def test_empty_and_truncated_replies_are_errors_not_abstentions(store, questions):
    fake = next(q for q in questions if q.id.startswith("abstention:entity:"))
    lease = next(q for q in questions if q.id == "lease:10.0.4.7@2026-08-20:valid_at")
    model = _Replies(("", {"out": 300, "cost": 0.0, "finish": "stop"}),
                     ("answer: unk", {"out": 300, "cost": 0.0, "finish": "length"}),
                     ("answer: host:laptop-17\ncites: none", {"out": 9, "cost": 0.0, "finish": "stop"}))
    records = re_.evaluate(store, [fake, fake, lease], model, ["loom@400"])
    assert [r.status for r in records] == ["error", "error", "ok"]
    assert "empty reply" in records[0].note and "max_tokens" in records[1].note
    # an empty reply to an abstention question used to score as a correct `unknown`
    assert records[0].score["pass_"] is None and records[0].score["abstained"] is None
    s = re_.summarize(records, ["loom@400"])["loom@400"]
    assert s["errored"] == 2 and s["n"] == 1 and s["accuracy"] == 1.0
    assert "abstention" not in s["families"]


def test_a_failing_context_build_is_one_error_row_and_rows_stream(store, questions):
    class Flaky(HashingEmbedder):
        calls = 0

        def embed_query(self, text):
            Flaky.calls += 1
            raise TimeoutError("stalled")

        def embed(self, texts):
            if len(texts) == 1 and texts[0].startswith("As of"):
                raise TimeoutError("stalled")
            return super().embed(texts)

    q = next(q for q in questions if q.id == "conflict:host:web-01:runs_os")
    seen = []
    records = re_.evaluate(store, [q], re_.ScriptedReader(), ["vector@400", "recency@400"],
                           embedder=Flaky(), sink=seen.append)
    # the query embedding was retried before giving up on that row only
    assert Flaky.calls == re_._QUERY_EMBED_ATTEMPTS - 1
    assert records[0].status == "error" and "context" in records[0].note
    assert records[1].status == "ok" and records[1].score["pass_"] is not None
    assert seen == records
    # a transient failure is retried away
    class Once(HashingEmbedder):
        failed = False

        def embed_query(self, text):
            if not Once.failed:
                Once.failed = True
                raise TimeoutError("stalled")
            return super().embed_query(text)
    ok = re_.evaluate(store, [q], re_.ScriptedReader(), ["vector@400"], embedder=Once())
    assert ok[0].status == "ok" and Once.failed


def test_live_model_sends_temperature_zero_and_reports_finish(monkeypatch):
    sent = []

    def fake_post(url, body, headers, timeout=0):
        sent.append(body)
        if "temperature" in body and body["model"] == "picky":
            raise re_.LLMError('provider returned 400: {"error": "temperature is not supported"}')
        return {"choices": [{"message": {"content": "answer: B\ncites: none"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 3, "cost": 0.001}}

    monkeypatch.setattr(re_, "_post_json", fake_post)
    q = re_.Question("order:x", "order", "?", "netsec", "order", "B", [])
    m = re_.LiveModel(re_.Provider("openai", "https://openrouter.ai/api/v1", "cheap", "k"), reasoning_effort="low")
    text, usage = m.answer(q, "sys", "prompt")
    assert sent[-1]["temperature"] == 0 and sent[-1]["max_tokens"] == re_.DEFAULT_MAX_TOKENS
    assert sent[-1]["reasoning"] == {"effort": "low", "exclude": True}
    assert usage["finish"] == "stop" and usage["cost"] == 0.001
    picky = re_.LiveModel(re_.Provider("openai", "https://x/v1", "picky", "k"))
    picky.answer(q, "sys", "prompt")
    assert "temperature" not in sent[-1] and picky.temperature is None
    picky.answer(q, "sys", "prompt")
    assert "temperature" not in sent[-1] and "reasoning" not in sent[-1]


def test_pool_samples_the_whole_population():
    import random
    pop = {"cve": [EntityRef(type="cve", key=f"CVE-2026-{i:05d}") for i in range(5000)]}
    got = re_._pool(pop, "cve", random.Random(7), 40)
    assert len(got) == 40 and got == sorted(got, key=lambda r: r.key)
    # the old pool was the 400 that sort first
    assert max(int(r.key[-5:]) for r in got) > 2500
    assert got == re_._pool(pop, "cve", random.Random(7), 40)


def test_snapshot_feeds_are_not_asked_in_order_questions(tmp_path):
    path = tmp_path / "snap.db"
    cmd_load(str(path), seed=42)
    store = SqliteStore(path)
    day = datetime(2026, 9, 20, tzinfo=timezone.utc)
    hosts = [e.key for e in store.iter_entities("netsec") if e.type == "host"]
    for i, host in enumerate(hosts):
        store.record_claim(ClaimIn(namespace="netsec", subject=EntityRef(type="host", key=host),
                                   predicate="epss_like_score", object=0.001 * (i + 1),
                                   observed_at=day, source="epss"))
    pop = re_.population(store, "netsec")
    import random
    cands = re_._candidates(pop, random.Random("7:netsec"))
    assert "epss_like_score" in re_.snapshot_predicates(store, "netsec", cands)
    qs = re_.generate_questions(store, ["netsec"], seed=7, per_family=40, families=["order"])
    assert qs and not any("epss_like_score" in q.id for q in qs)
    store.close()


def test_conflict_questions_are_pinned_to_a_store_derived_instant(store):
    qs = re_.generate_questions(store, ["netsec"], seed=7, families=["conflict"])
    os_q = next(q for q in qs if q.id == "conflict:host:web-01:runs_os")
    # not the wall clock: the newest observation about the sampled entities
    assert os_q.as_of is not None and os_q.as_of.year == 2026 and os_q.as_of.month <= 9
    assert os_q.as_of.date().isoformat() in os_q.text
    pinned = re_.generate_questions(store, ["netsec"], seed=7, families=["conflict"],
                                    reference=datetime(2026, 9, 1, tzinfo=timezone.utc))
    assert all(q.as_of == datetime(2026, 9, 1, tzinfo=timezone.utc) for q in pinned)


def test_full_is_uncapped_and_questions_outside_loom_gather_are_flagged(store, monkeypatch):
    from loom import context
    monkeypatch.setattr(context, "_GATHER_LIMIT", 3)
    qs = re_.generate_questions(store, ["netsec"], seed=7)
    outside = [q for q in qs if q.in_loom_gather is False]
    assert outside, "a gather cap of 3 must put some ground truth out of Loom's reach"
    for q in outside:
        full = re_.build_context(store, q, "full")
        # the baselines gather without a cap: the truth is in `full`
        assert set(q.truth_ids) <= full.cite_ids, q.id
        loom = re_.build_context(store, q, "loom@3200")
        assert not set(q.truth_ids) <= loom.cite_ids, q.id
    md = re_.markdown({}, {"runs": 1}, qs)
    assert f"Ground truth outside Loom's gather (the newest 3 observations per entity): {len(outside)} of" in md
    assert "OUTSIDE-LOOM-GATHER" in re_.describe(qs)


def test_end_to_end_scripted_scorecard_and_variance(store, questions, tmp_path):
    conditions = re_.condition_names((400, 3200), ["loom", "full", "recency", "vector"])
    records = re_.evaluate(store, questions, re_.ScriptedReader(), conditions, embedder=HashingEmbedder(),
                           runs=2)
    assert len(records) == 2 * len(questions) * len(conditions)
    summary = re_.summarize(records, conditions)
    assert summary["loom@3200"]["accuracy"] >= summary["loom@400"]["accuracy"]
    # a perfect reader over the pack: what it could not answer, the pack did not carry
    for r in records:
        if r.condition.startswith("loom@") and r.family != "abstention" and not r.score["pass_"]:
            assert r.score["abstained"] or not r.score["support_pack"], r
    # the reader never hallucinates and never cites what it did not see
    assert summary["full"]["hallucinated"][0] == 0 and summary["full"]["unseen"][0] == 0
    assert summary["full"]["accuracy"] == 1.0                      # everything, read perfectly
    assert summary["full"]["tokens_est"] > summary["loom@400"]["tokens_est"]
    assert summary["loom@3200"]["support_pack"][0] >= summary["loom@400"]["support_pack"][0]
    assert summary["loom@3200"]["accuracy_stdev"] == 0.0 and len(summary["loom@3200"]["accuracy_runs"]) == 2
    # at equal tokens, the pack's ranking is what differs
    for b in (400, 3200):
        assert summary[f"vector@{b}"]["tokens_est"] <= summary[f"loom@{b}"]["tokens_est"] * 1.6
    md = re_.markdown(summary, {"date": "2026-09-24", "store": "x", "namespaces": ["netsec"],
                                "model": "scripted-reader", "questions": len(questions), "runs": 2})
    assert "| `loom@400` |" in md and "| `vector@400` |" in md and "± " in md and "| lease |" in md
    assert "INCOMPLETE" not in md
    md = re_.markdown(summary, {"runs": 1, "cost_capped": 7, "max_cost": 1.0})
    assert "INCOMPLETE: 7 rows were not sent" in md


def test_cli_canned_run_writes_the_table(db, tmp_path, capsys):
    qs = re_.generate_questions(SqliteStore(db), ["netsec", "procurement"], seed=7)
    canned = {q.id: "answer: unknown\ncites: none" for q in qs}
    (tmp_path / "canned.json").write_text(json.dumps(canned))
    out = tmp_path / "eval" / "table.md"
    re_.main(["--db", db, "--canned", str(tmp_path / "canned.json"), "--conditions", "loom,recency",
              "--budgets", "800", "--out", str(out), "--json", str(tmp_path / "r.json"), "--quiet"])
    text = out.read_text()
    assert "| `loom@800` |" in text and "| `recency@800` |" in text
    data = json.loads((tmp_path / "r.json").read_text())
    assert data["meta"]["model"] == "canned" and len(data["records"]) == 2 * len(qs)
    # every row was streamed as it completed
    rows = [json.loads(line) for line in out.with_suffix(".jsonl").read_text().splitlines()]
    assert rows == json.loads(json.dumps(data["records"]))
    # always-unknown: every abstention passes, everything else is an abstention miss
    summary = re_.summarize([re_.Record(**r) for r in data["records"]], ["loom@800"])["loom@800"]
    assert summary["hallucinated"] == (0, summary["families"]["abstention"][1])
    assert summary["passed"] == summary["families"]["abstention"][0]
    re_.main(["--db", db, "--list-questions"])
    assert "lease:10.0.4.7@2026-08-20:valid_at" in capsys.readouterr().out
    # a run cut short by --max-cost says so, loudly, and exits non-zero
    with pytest.raises(SystemExit) as exc:
        re_.main(["--db", db, "--canned", str(tmp_path / "canned.json"), "--conditions", "loom",
                  "--budgets", "400", "--out", str(out), "--quiet", "--max-cost", "-1"])
    assert exc.value.code == 3 and "INCOMPLETE" in out.read_text()
    assert "INCOMPLETE" in capsys.readouterr().err


def test_the_scorecard_never_prints_a_dsn_password():
    """D-063: a GKE run's scorecard header carried the operator's Postgres
    password — and scorecards are meant to be published."""
    from loom.store.common import redact_dsn
    assert redact_dsn("postgresql://loom:s3cret@loom-pg-rw.loom:5432/loom") == \
        "postgresql://loom:***@loom-pg-rw.loom:5432/loom"
    assert redact_dsn("/data/loom.db") == "/data/loom.db"
    # review 2026-09-26: a query-param password, an empty user and a raw '@'
    # in the password all leaked
    for dsn, want in (
            ("postgresql://loom@host/db?password=x", "postgresql://loom@host/db?password=***"),
            ("postgresql://loom@host/db?sslmode=require&password=x&x=1",
             "postgresql://loom@host/db?sslmode=require&password=***&x=1"),
            ("postgresql://:pw@host:5432/db", "postgresql://:***@host:5432/db"),
            ("postgresql://loom:p@ss@w0rd@host/db", "postgresql://loom:***@host/db"),
            ("postgresql://loom:pa/ss?@host/db", "postgresql://loom:***@host/db"),
            ("host=pg user=loom password='s e@cret' dbname=loom", "host=pg user=loom password=*** dbname=loom"),
            ("postgresql://host/db", "postgresql://host/db"),
            ("postgresql://loom@host/db", "postgresql://loom@host/db"),
            ("sqlite:///data/loom.db", "sqlite:///data/loom.db")):
        assert redact_dsn(dsn) == want, dsn
        assert not any(s in redact_dsn(dsn) for s in ("pw", "p@ss", "w0rd", "e@cret", "=x", "pa/ss"))
    import inspect
    import loom.retrieval_eval as re_
    assert "redact_dsn(args.db" in inspect.getsource(re_.main)
