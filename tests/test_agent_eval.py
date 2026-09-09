"""Agent end-to-end harness (D-036). The loop, provider dialects, ground
truth and scoring run here against a scripted fake model (no network); the
live run against a real model is opt-in: LOOM_LIVE_AGENT=1 plus LOOM_LLM_*."""

import asyncio
import json
import os

import pytest

from loom import agent_eval as ae
from loom.seed import cmd_load
from loom.store.sqlite import SqliteStore


@pytest.fixture(scope="module")
def seeded_db(tmp_path_factory):
    db = tmp_path_factory.mktemp("agent") / "seed.db"
    cmd_load(str(db), seed=42)
    return str(db)


class Scripted:
    """A fake model: a list of turns; each turn is tool calls or a final text
    that may reference observation ids it 'saw' via a callback."""

    def __init__(self, turns):
        self.turns = list(turns)
        self.seen_messages = []

    def __call__(self, provider, system, messages, tools):
        self.seen_messages.append(list(messages))
        names = {t.name for t in tools}
        assert {"find_entity", "ask", "ask_scope", "expand"} <= names
        step = self.turns.pop(0)
        if callable(step):
            step = step(messages)
        if isinstance(step, str):
            return ae.Turn(step, [], {"role": "assistant", "content": step}, {"in": 10, "out": 5})
        calls = [(f"c{i}", name, args) for i, (name, args) in enumerate(step)]
        raw = {"role": "assistant", "content": None,
               "tool_calls": [{"id": cid, "type": "function",
                               "function": {"name": n, "arguments": json.dumps(a)}} for cid, n, a in calls]}
        return ae.Turn("", calls, raw, {"in": 10, "out": 5})


def _last_tool_output(messages) -> str:
    return next(m["content"] for m in reversed(messages) if m.get("role") == "tool")


def test_lease_task_scores_a_faithful_cited_answer(seeded_db):
    def final(messages):
        pack = json.loads(_last_tool_output(messages))
        item = next(i for i in pack["items"] if "laptop-17" in i["text"])
        oid = item["citations"][0]["observation_id"]
        return f"laptop-17 held 10.0.4.7 on that date [{oid[:12]}]."
    model = Scripted([
        [("find_entity", {"query": "10.0.4.7", "namespace": "netsec"})],
        [("ask", {"subject": "ip:10.0.4.7", "question": "which host?", "namespace": "netsec",
                  "valid_at": "2026-08-20T00:00:00Z", "budget": 600})],
        final,
    ])
    results = ae.evaluate(seeded_db, ["lease"], model="fake", caller=model)
    r = results[0]
    assert r.error is None and r.steps == 3 and [c["tool"] for c in r.tool_calls] == ["find_entity", "ask"]
    assert r.score["pass"] and r.score["citations"] == 1 and r.score["citations_unseen"] == 0
    # the provider dialect: tool results went back as role=tool messages
    assert any(m.get("role") == "tool" for m in model.seen_messages[-1])


def test_unseen_citations_and_wrong_answers_fail(seeded_db):
    model = Scripted([
        [("ask", {"subject": "ip:10.0.4.7", "question": "which host?", "namespace": "netsec"})],
        "web-01 holds it [deadbeefdeadbeef].",
    ])
    r = ae.evaluate(seeded_db, ["lease"], model="fake", caller=model)[0]
    assert not r.score["pass"] and r.score["citations_unseen"] == 1


def test_loop_survives_a_bad_tool_call_and_bounds_steps(seeded_db):
    model = Scripted([[("ask", {"subject": "no-colon", "question": "?"})]] * ae.MAX_STEPS)
    r = ae.evaluate(seeded_db, ["os"], model="fake", caller=model)[0]
    assert r.error and "steps" in r.error and all(c["error"] for c in r.tool_calls)
    assert not r.score["pass"]


def test_exposure_truth_is_computed_from_the_store(tmp_path):
    from loom.connectors import vulns
    from loom.ingest import load_direct
    db = tmp_path / "x.db"
    cmd_load(str(db), seed=42)
    envs = list(vulns.bridge_envelopes("netsec")) + list(vulns.kev_envelopes({
        "cveID": "CVE-2026-10001", "vendorProject": "OpenSSL", "product": "OpenSSL",
        "vulnerabilityName": "x", "dateAdded": "2026-03-02", "shortDescription": "d",
        "requiredAction": "a", "dueDate": "2026-03-23", "knownRansomwareCampaignUse": "Unknown",
    }, "netsec"))
    load_direct(str(db), vulns.to_lines(envs), size=100)
    store = SqliteStore(db)
    truth = ae._truth_exposure(store)
    assert "openssl:openssl" in truth["products"] and truth["kev"] == {"CVE-2026-10001": "openssl:openssl"}
    score = ae._score_cves("CVE-2026-10001 via openssl [abc]; also CVE-2026-9999", truth, {"abcdef" * 5 + "ab"}, store)
    assert score["kev_named"] == 1 and score["invented_cves"] == ["CVE-2026-9999"] and not score["pass"]
    store.close()


def test_anthropic_dialect_round_trip():
    turn = ae.Turn("", [("t1", "ask", {"subject": "host:web-01"})],
                   {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "ask", "input": {}}]},
                   {"in": 1, "out": 1})
    p = ae.Provider("anthropic", "https://api.anthropic.com", "m", None)
    msgs = ae.tool_result_messages(p, turn, [("t1", "{}")])
    assert msgs[1]["content"][0] == {"type": "tool_result", "tool_use_id": "t1", "content": "{}"}


@pytest.mark.skipif(not os.environ.get("LOOM_LIVE_AGENT"), reason="set LOOM_LIVE_AGENT=1 (and LOOM_LLM_*) for a live agent run")
def test_live_agent_answers_the_lease_question(seeded_db):
    r = ae.evaluate(seeded_db, ["lease"])[0]
    print(ae.summarize([r], ae.Provider.from_env().model))
    assert r.error is None and r.score["pass"], r.answer


def test_scorecard_ranks_passes_then_cost():
    def rr(task, ok, cost, err=None):
        r = ae.RunResult(task=task, answer="", steps=3, error=err)
        r.usage = {"in": 100, "out": 10, "cost": cost}
        r.score = {"pass": ok, "citations_unseen": 0}
        return r
    rows = ae.scorecard({
        "pricey/good": [rr("exposure", True, 0.5), rr("lease", True, 0.2)],
        "cheap/good": [rr("exposure", True, 0.05), rr("lease", True, 0.01)],
        "cheap/bad": [rr("exposure", False, 0.01), rr("lease", True, 0.01)],
        "broken/x": [rr("exposure", False, 0.0, err="LLMError: 404"), rr("lease", False, 0.0, err="LLMError: 404")],
    })
    assert [r["model"] for r in rows] == ["cheap/good", "pricey/good", "cheap/bad", "broken/x"]
    assert rows[0]["cost"] == 0.06 and rows[3]["exposure"] == "error"
    md = ae.scorecard_markdown(rows)
    assert md.count("\n") == 5 and "| `cheap/good` | 2/2 | pass | pass |" in md
    # repeats: pass counts per task, per-run averages, sorted by pass RATE
    rows = ae.scorecard({
        "flaky/x": [rr("exposure", True, 0.4), rr("lease", True, 0.1), rr("exposure", False, 0.4), rr("lease", True, 0.1)],
        "solid/y": [rr("exposure", True, 0.3), rr("lease", True, 0.1), rr("exposure", True, 0.3), rr("lease", True, 0.1)],
    }, repeat=2)
    assert [r["model"] for r in rows] == ["solid/y", "flaky/x"]
    assert rows[1]["exposure"] == "1/2" and rows[1]["passed"] == 3 and rows[1]["tasks"] == 4
    assert rows[0]["cost"] == 0.4 and rows[0]["cost_total"] == 0.8 and rows[0]["steps"] == 6
    assert "Cost/run" in ae.scorecard_markdown(rows) and "| `flaky/x` | 3/4 | 1/2 | 2/2 |" in ae.scorecard_markdown(rows)


def test_excerpt_and_artifact_citations_count_as_seen_and_empty_completion_retries(seeded_db):
    seen = set()
    ae._collect_ids('{"citations":[{"artifact_id":"0123456789abcdef0123456789abcdef","span_start":1}]} "[doc:deadbeef @0-10]"', seen)
    assert {"0123456789abcdef0123456789abcdef", "deadbeef"} <= seen
    model = Scripted([
        [("ask", {"subject": "ip:10.0.4.7", "question": "which host?", "namespace": "netsec"})],
        "",                                                     # transient empty completion
        lambda messages: "laptop-17 [" + json.loads(_last_tool_output(messages))["items"][0]["citations"][0]["observation_id"][:12] + "]",
    ])
    r = ae.evaluate(seeded_db, ["lease"], model="fake", caller=model)[0]
    assert r.error is None and r.score["pass"] and r.steps == 3
