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
    assert not re_.score(q, "answer: laptop-17 (previously web-01)\ncites: none", _ctx(ids))["pass_"]
    assert not re_.score(q, "answer: unknown\ncites: none", _ctx(ids))["pass_"]
    s = re_.score(q, "answer: host:laptop-17\ncites: deadbeefdead", _ctx(ids))
    assert s["pass_"] and s["cites_unseen"] == 1 and not s["support_answer"]
    # abstention: anything but unknown is a hallucination
    q = re_.Question("abstention:x", "abstention", "?", "netsec", "unknown", None, [])
    assert re_.score(q, "answer: unknown\ncites: none", _ctx())["pass_"]
    s = re_.score(q, "answer: fedora-44\ncites: none", _ctx())
    assert not s["pass_"] and s["hallucinated"]
    # conflict: both values, or saying so
    q = re_.Question("conflict:x", "conflict", "?", "netsec", "conflict", ["fedora-44", "ubuntu-22.04"], ids)
    assert re_.score(q, "answer: conflicting: fedora-44 | ubuntu-22.04\ncites: none", _ctx())["pass_"]
    assert re_.score(q, "answer: Fedora 44 and Ubuntu 22.04\ncites: none", _ctx())["pass_"]
    assert not re_.score(q, "answer: fedora-44\ncites: none", _ctx())["pass_"]
    # numbers, id sets, ordering
    q = re_.Question("numeric:x", "numeric", "?", "netsec", "number", 41234.56, ids)
    assert re_.score(q, "answer: 41,234.56\ncites: none", _ctx())["pass_"]
    assert not re_.score(q, "answer: 41234.6\ncites: none", _ctx())["pass_"]
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
    assert not re_.score(q, "answer: A\ncites: none", _ctx())["pass_"]
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


def test_vector_condition_uses_the_embedder_and_is_skipped_without_one(store, questions):
    q = next(q for q in questions if q.id == "conflict:host:web-01:runs_os")
    assert re_.build_context(store, q, "vector").note.startswith("skipped")
    ctx = re_.build_context(store, q, "vector", embedder=HashingEmbedder(), k=5)
    assert ctx.items == 5 and not ctx.note.startswith("skipped")
    # cosine on the rendered fact text ranks the runs_os facts first
    assert "runs_os" in ctx.prompt.split("\n")[4]
    rec = re_.build_context(store, q, "recency", k=3)
    assert rec.items == 3 and rec.tokens_est < re_.build_context(store, q, "full").tokens_est


def test_full_baseline_is_measured_not_sent_past_the_cap(store, questions):
    q = next(q for q in questions if q.id == "multihop:logins:AL-2291")
    ctx = re_.build_context(store, q, "full", full_cap=200)
    assert ctx.note.startswith("not sent") and ctx.tokens_est > 200
    records = re_.evaluate(store, [q], re_.ScriptedReader(), ["full"], full_cap=200)
    assert records[0].note.startswith("not sent") and not records[0].score["pass_"]


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
    md = re_.markdown(summary, {"date": "2026-09-24", "store": "x", "namespaces": ["netsec"],
                                "model": "scripted-reader", "questions": len(questions), "runs": 2})
    assert "| `loom@400` |" in md and "| `vector` |" in md and "± " in md and "| lease |" in md


def test_cli_canned_run_writes_the_table(db, tmp_path, capsys):
    qs = re_.generate_questions(SqliteStore(db), ["netsec", "procurement"], seed=7)
    canned = {q.id: "answer: unknown\ncites: none" for q in qs}
    (tmp_path / "canned.json").write_text(json.dumps(canned))
    out = tmp_path / "eval" / "table.md"
    re_.main(["--db", db, "--canned", str(tmp_path / "canned.json"), "--conditions", "loom,recency",
              "--budgets", "800", "--out", str(out), "--json", str(tmp_path / "r.json"), "--quiet"])
    text = out.read_text()
    assert "| `loom@800` |" in text and "| `recency` |" in text
    data = json.loads((tmp_path / "r.json").read_text())
    assert data["meta"]["model"] == "canned" and len(data["records"]) == 2 * len(qs)
    # always-unknown: every abstention passes, everything else is an abstention miss
    summary = re_.summarize([re_.Record(**r) for r in data["records"]], ["loom@800"])["loom@800"]
    assert summary["hallucinated"] == (0, summary["families"]["abstention"][1])
    assert summary["passed"] == summary["families"]["abstention"][0]
    re_.main(["--db", db, "--list-questions"])
    assert "lease:10.0.4.7@2026-08-20:valid_at" in capsys.readouterr().out
