"""Agent end-to-end harness (D-036). The loop, provider dialects, ground
truth and scoring run here against a scripted fake model (no network); the
live run against a real model is opt-in: LOOMCTX_LIVE_AGENT=1 plus LOOMCTX_LLM_*."""

import json
import os

import pytest

from loomctx import agent_eval as ae
from loomctx.seed import cmd_load
from loomctx.store.sqlite import SqliteStore


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
        cite = item["cites"][0].split()[0]            # concise cites: "<cite> <source> <date>" (D-058)
        return f"laptop-17 held 10.0.4.7 on that date [{cite}]."
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
    from loomctx.connectors import vulns
    from loomctx.ingest import load_direct
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
    assert truth["via"] == {"CVE-2026-10001": ["openssl:openssl"]}
    seen = {"abcdef" * 5 + "ab"}
    score = ae._score_cves("CVE-2026-10001 via openssl [abcdefab]; also CVE-2026-9999", truth, seen, store)
    assert score["kev_named"] == 1 and score["invented_cves"] == ["CVE-2026-9999"] and not score["pass"]
    # a real CVE that is not KEV-for-web-01 named as the exposure is a
    # precision failure (the score used to measure recall only)
    from loomctx.contracts import ClaimIn, EntityRef
    from datetime import datetime, timezone
    store.record_claim(ClaimIn(namespace="netsec", subject=EntityRef(type="cve", key="CVE-2026-10002"),
                               predicate="status", object="Analyzed", source="nvd",
                               observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc)))
    score = ae._score_cves("CVE-2026-10001 in OpenSSL and CVE-2026-10002 [abcdefab]", truth, seen, store)
    assert score["false_kev"] == 1 and score["false_kev_examples"] == ["CVE-2026-10002"] and not score["pass"]
    assert score["invented_cves"] == [] and score["precision"] == 0.5
    score = ae._score_cves("CVE-2026-10001 in OpenSSL [abcdefab]", truth, seen, store)
    assert score["pass"] and score["false_kev"] == 0 and score["recall"] == 1.0
    assert score["software_named"] == ["openssl:openssl"]
    # the software must be named, and the answer must cite something it saw
    assert not ae._score_cves("CVE-2026-10001 [abcdefab]", truth, seen, store)["pass"]
    s = ae._score_cves("CVE-2026-10001 in OpenSSL", truth, seen, store)
    assert not s["pass"] and s["citations"] == 0
    store.close()


def test_exposure_passes_on_recall_not_on_one_name():
    """D-057: naming one of 29 KEV CVEs used to pass. Now at least half
    (every one of a set of four or fewer) must be named."""
    kev = {f"CVE-2026-{i:04d}": "linux:linux_kernel" for i in range(1, 30)}
    truth = {"kev": kev, "via": {c: [p] for c, p in kev.items()}, "products": ["linux:linux_kernel"]}

    class Store:
        def get_entity(self, ns, ref):
            return object()        # every CVE named exists
    seen = {"abcdef" * 5 + "ab"}
    names = sorted(kev)
    assert ae.exposure_required(29) == 15 and ae.exposure_required(4) == 4 and ae.exposure_required(1) == 1
    one = ae._score_cves(f"{names[0]} in the Linux kernel [abcdefab]", truth, seen, Store())
    assert not one["pass"] and one["recall"] == round(1 / 29, 3)
    half = ae._score_cves(", ".join(names[:15]) + " in the Linux kernel [abcdefab]", truth, seen, Store())
    assert half["pass"] and half["kev_required"] == 15
    few = {"kev": dict(list(kev.items())[:3]), "via": {c: ["linux:linux_kernel"] for c in names[:3]}}
    assert not ae._score_cves(f"{names[0]}, {names[1]} (Linux kernel) [abcdefab]", few, seen, Store())["pass"]
    # no KEV exposure: the right answer names no CVE
    none = {"kev": {}, "via": {}}
    assert ae._score_cves("No KEV-listed CVE affects its software [abcdefab].", none, seen, Store())["pass"]
    assert not ae._score_cves(f"{names[0]} [abcdefab]", none, seen, Store())["pass"]


def test_a_cve_the_answer_rules_out_is_not_a_false_kev_claim():
    """D-089: careful answers named non-KEV CVEs only to exclude them ("OpenSSL
    does carry non-KEV CVEs, e.g. X, but none are KEV-listed") and failed on
    precision. A CVE counts against the answer only when some sentence
    naming it does not rule it out."""
    kev = {f"CVE-2026-{i:04d}": "linux:linux_kernel" for i in range(1, 5)}
    truth = {"kev": kev, "via": {c: [p] for c, p in kev.items()}}

    class Store:
        def get_entity(self, ns, ref):
            return object()
    seen = {"abcdef" * 5 + "ab"}
    listed = ", ".join(sorted(kev)) + " affect the Linux kernel [abcdefab]."
    for aside in ("OpenSSL does carry non-KEV CVEs (e.g. CVE-2026-9001, CVE-2026-9002) but none are KEV-listed.",
                  "The data shows NVD edges for openssh (e.g. CVE-2026-9001) but **no** `exploited_in_wild` observations.",
                  "CVE-2026-9001 affects openssh; it is not on the KEV list.",
                  "The CVEs I saw for openssh had no such listing, for example CVE-2026-9001 [abcdefab].",
                  "**openssh: none found.** Its CVEs came back fully checked, and none is marked as exploited "
                  "in the wild. Examples include CVE-2026-9001 [abcdefab].",
                  "I checked KEV CVEs search surfaced and ruled them out: CVE-2026-9001 affects adobe:acrobat.",
                  "One near-miss: CVE-2026-9001 is KEV-listed but affects android:kernel, which web-01 does not run.",
                  "Two other OpenSSL CVEs were found — CVE-2026-9001 and CVE-2026-9002 — but neither has a CISA KEV listing.",
                  "I verified each points at other products — none touches web-01's software (e.g. CVE-2026-9001 → debian).",
                  "A scan of openssh CVEs (e.g., CVE-2026-9001, CVE-2026-9002, etc. — [abcdefab]) found **no** "
                  "entries flagged `exploited_in_wild = True`.",
                  # the exclusion one sentence back (Claude Opus 5.5, 2026-09-28)
                  "**OpenSSH, nginx:** I saw no KEV entries for them. Their CVEs appear only with NVD or EPSS data, "
                  "such as CVE-2026-9001 [abcdefab] and CVE-2026-9002.",
                  # ruled out in the next sentence, or as "not in the catalogue"
                  "A separate search found one extra KEV CVE, CVE-2026-9001 [abcdefab]. The data ties it to the "
                  "Android kernel only, with no route to web-01, so it is not counted.",
                  "There was a fact: cve:CVE-2026-9001 affects openssl [abcdefab]. But that is not marked exploited_in_wild.",
                  "OpenSSL also has newer CVEs that are not in the catalogue, such as CVE-2026-9001 [abcdefab]."):
        r = ae._score_cves(f"{listed}\n{aside}", truth, seen, Store())
        assert r["pass"] and r["false_kev"] == 0 and r["ruled_out"] >= 1 and r["precision"] == 1.0, aside
    # a claim is still a claim — even next to an unrelated "not"
    for claim in ("CVE-2026-9001 is exploited in the wild and not yet patched.",
                  "CVE-2026-9001 is KEV-listed. Elsewhere, CVE-2026-9001 is not exploited.",
                  "OpenSSL has no patch listed. CVE-2026-9001 is exploited in the wild.",
                  "No KEV entry was missed. Critical CVEs such as CVE-2026-9001 are exploited in the wild.",
                  "CVE-2026-9001 is exploited in the wild. It is not patched yet."):
        r = ae._score_cves(f"{listed}\n{claim}", truth, seen, Store())
        assert not r["pass"] and r["false_kev"] == 1, claim


def test_every_factual_task_needs_a_seen_citation_and_dates_are_not_cites():
    seen = {"abcdef" * 5 + "ab"}
    assert ae.cite_tokens_in("on 20260820, id 12345678 [abcdefab] [0123456789abcdef0123456789abcdef]") == [
        "abcdefab", "0123456789abcdef0123456789abcdef"]
    c = ae._cited("held on 20260820 [abcdefab]", seen)
    assert c == {"citations": 1, "citations_seen": 1, "citations_unseen": 0, "unseen_examples": []}
    os_truth = {"values": ["fedora-44", "ubuntu-22.04"]}
    assert ae._score_os("Sources disagree: Fedora 44 and Ubuntu 22.04 [abcdefab].", os_truth, seen, None)["pass"]
    assert not ae._score_os("Sources disagree: Fedora 44 and Ubuntu 22.04.", os_truth, seen, None)["pass"]
    conflict = {"values": ["7.5", "9.8"], "sources": ["a", "b"]}
    assert ae._score_conflict("a says 7.5, b says 9.8 [abcdefab]", conflict, seen, None)["pass"]
    assert not ae._score_conflict("a says 7.5, b says 9.8", conflict, seen, None)["pass"]
    # 17.5 does not name 7.5
    assert not ae._score_conflict("a says 17.5, b says 9.8 [abcdefab]", conflict, seen, None)["pass"]


def test_hex_quoted_from_a_source_name_is_not_a_citation():
    # the 2026-09-28 false positive: an answer quoting the NVD source label
    # "nvd:134c704f-9b21-4f2e-91b3-4a467353bcc0" (CISA's org id), whole or cut
    # short, was failed for citing ids the model had "never seen"
    seen: set[str] = set()
    ae._collect_ids('{"cite": "068b382cfb88", "source": "nvd:134c704f-9b21-4f2e-91b3-4a467353bcc0"}', seen)
    ae._collect_ids('"0ca994117d4e nvd:0b0ca135-0b70-47e7-9f44-1890c2a1c46c 2026-08-01"', seen)
    for answer in ("`nvd:134c704f-9b21-4f2e-91b3-4a467353bcc0` says CWE-669 [068b382cfb88], while "
                   "`nvd:0b0ca135-0b70-47e7-9f44-1890c2a1c46c` says CWE-1288 [0ca994117d4e]",
                   "nvd:134c704f says CWE-122 [068b382cfb88]"):
        c = ae._cited(answer, seen)
        assert c["citations_unseen"] == 0 and c["citations_seen"] >= 1, (answer, c)
    # an invented id is still caught, and a name alone is no citation
    assert ae._cited("CWE-122 [deadbeefcafe]", seen)["citations_unseen"] == 1
    assert ae._cited("nvd:134c704f says CWE-122", seen)["citations"] == 0


def test_lease_truth_comes_from_validity_windows_and_dotted_ips_do_not_end_sentences(seeded_db, tmp_path):
    import shutil
    shutil.copy(seeded_db, tmp_path / "copy.db")          # this test adds a lease; keep the shared seed pristine
    store = SqliteStore(tmp_path / "copy.db")
    truth = ae._truth_lease(store)
    assert truth == {"expect": ["laptop-17"], "reject": ["web-01"]}
    seen = {"abcdef" * 5 + "ab"}
    # the old splitter cut the first sentence at the IP's first dot, so
    # "web-01" after "10.0.4.7" was never in the judged sentence
    s = ae._score_lease("On 2026-08-20 the address 10.0.4.7 was held by web-01, not laptop-17 [abcdefab].", truth, seen, store)
    assert "web-01" in s["first_sentence"] and s["rejected_in_answer"] == ["web-01"] and not s["pass"]
    s = ae._score_lease("10.0.4.7 was held by laptop-17 [abcdefab]. Before Aug 10 it was web-01.", truth, seen, store)
    assert s["pass"] and s["names_expected"] == ["laptop-17"] and s["rejected_in_answer"] == []
    # history in an aside is not the asserted answer (it used to fail this)
    s = ae._score_lease("laptop-17 (moved from web-01 on Aug. 10) [abcdefab].", truth, seen, store)
    assert s["pass"] and s["rejected_in_answer"] == []
    s = ae._score_lease("web-01 (laptop-17 took it later) [abcdefab].", truth, seen, store)
    assert not s["pass"] and s["rejected_in_answer"] == ["web-01"]
    # a correct but uncited answer does not pass
    assert not ae._score_lease("10.0.4.7 was held by laptop-17.", truth, seen, store)["pass"]
    # the truth follows the store: move the lease and the answer moves with it
    from loomctx.contracts import ClaimIn, EntityRef
    from datetime import datetime, timezone
    t = datetime(2026, 8, 15, tzinfo=timezone.utc)
    store.record_claim(ClaimIn(namespace="netsec", subject=EntityRef(type="ip", key="10.0.4.7"), predicate="assigned_to",
                               object=EntityRef(type="host", key="db-02"), observed_at=t, valid_from=t,
                               valid_to=datetime(2026, 8, 25, tzinfo=timezone.utc), source="dhcp-log"))
    assert ae._truth_lease(store)["expect"] == ["db-02", "laptop-17"]
    store.close()


def test_anthropic_dialect_round_trip():
    turn = ae.Turn("", [("t1", "ask", {"subject": "host:web-01"})],
                   {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "ask", "input": {}}]},
                   {"in": 1, "out": 1})
    p = ae.Provider("anthropic", "https://api.anthropic.com", "m", None)
    msgs = ae.tool_result_messages(p, turn, [("t1", "{}")])
    assert msgs[1]["content"][0] == {"type": "tool_result", "tool_use_id": "t1", "content": "{}"}


class _Tool:
    def __init__(self, name):
        self.name, self.description, self.input_schema = name, "d", {"type": "object"}


def test_anthropic_call_leaves_room_for_thinking_and_keeps_the_blocks(monkeypatch):
    """D-047 follow-up: with thinking on by default, max_tokens=1500 was
    spent before a tool_use block. The request now carries 8000 and
    adaptive thinking (omitted for the models that take budget_tokens or
    when LOOMCTX_AGENT_THINKING=off); the reply's blocks — thinking included —
    go back on the next turn unchanged; a refusal is an error, not an answer."""
    sent = []

    def fake_post(url, body, headers, timeout=0):
        sent.append((url, body, headers))
        return {"stop_reason": "tool_use", "usage": {"input_tokens": 7, "output_tokens": 3},
                "content": [{"type": "thinking", "thinking": "", "signature": "sig"},
                            {"type": "text", "text": "looking"},
                            {"type": "tool_use", "id": "t1", "name": "ask", "input": {"subject": "host:web-01"}}]}

    monkeypatch.setattr(ae, "_post_json", fake_post)
    monkeypatch.setattr(ae, "THINKING", "adaptive")
    p = ae.Provider("anthropic", "https://api.anthropic.com", "claude-opus-5", "k")
    turn = ae.call_model(p, "sys", [{"role": "user", "content": "q"}], [_Tool("ask")])
    url, body, headers = sent[-1]
    assert url.endswith("/v1/messages") and headers["x-api-key"] == "k"
    assert body["max_tokens"] == ae.ANTHROPIC_MAX_TOKENS == 8000 and body["thinking"] == {"type": "adaptive"}
    assert body["tools"][0]["input_schema"] == {"type": "object"} and body["system"] == "sys"
    assert turn.calls == [("t1", "ask", {"subject": "host:web-01"})] and turn.text == "looking"
    assert turn.raw_message["content"][0]["type"] == "thinking"           # replayed as-is
    assert turn.usage == {"in": 7, "out": 3}
    # models on the budget_tokens form run without the parameter, as on the scorecard
    ae.call_model(ae.Provider("anthropic", "https://api.anthropic.com", "claude-haiku-4-5", "k"),
                  "sys", [], [_Tool("ask")])
    assert "thinking" not in sent[-1][1]
    monkeypatch.setattr(ae, "THINKING", "off")
    ae.call_model(p, "sys", [], [_Tool("ask")])
    assert "thinking" not in sent[-1][1] and sent[-1][1]["max_tokens"] == 8000
    # a refusal is reported, never scored as an empty answer
    monkeypatch.setattr(ae, "_post_json", lambda *a, **k: {"stop_reason": "refusal", "content": [],
                                                           "stop_details": {"category": "cyber"}})
    with pytest.raises(RuntimeError, match="refused.*cyber"):
        ae.call_model(p, "sys", [], [_Tool("ask")])


def test_calls_run_at_temperature_zero_unless_the_model_refuses_it(monkeypatch):
    sent = []

    def fake_post(url, body, headers, timeout=0):
        sent.append(body)
        if "temperature" in body and body["model"].startswith("picky"):
            raise ae.LLMError('provider returned 400: {"error":"Unsupported parameter: temperature"}')
        if url.endswith("/v1/messages"):
            return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "ok"}], "usage": {}}
        return {"choices": [{"message": {"content": "ok"}}], "usage": {}}

    monkeypatch.setattr(ae, "_post_json", fake_post)
    monkeypatch.setattr(ae, "_NO_TEMPERATURE", set())
    ae.call_model(ae.Provider("openai", "https://x/v1", "cheap", "k"), "sys", [], [_Tool("ask")])
    assert sent[-1]["temperature"] == 0
    ae.call_model(ae.Provider("openai", "https://x/v1", "picky-r1", "k"), "sys", [], [_Tool("ask")])
    assert "temperature" not in sent[-1] and len(sent) == 3
    ae.call_model(ae.Provider("openai", "https://x/v1", "picky-r1", "k"), "sys", [], [_Tool("ask")])
    assert "temperature" not in sent[-1] and len(sent) == 4          # remembered: no second refusal
    # thinking takes the default temperature; without it, 0
    monkeypatch.setattr(ae, "THINKING", "adaptive")
    ae.call_model(ae.Provider("anthropic", "https://a", "claude-opus-5", "k"), "sys", [], [_Tool("ask")])
    assert "thinking" in sent[-1] and "temperature" not in sent[-1]
    ae.call_model(ae.Provider("anthropic", "https://a", "claude-haiku-4-5", "k"), "sys", [], [_Tool("ask")])
    assert sent[-1]["temperature"] == 0


def test_results_are_handed_over_as_each_task_finishes(seeded_db, tmp_path):
    def cite(messages):
        return "laptop-17 [" + json.loads(_last_tool_output(messages))["items"][0]["cites"][0].split()[0] + "]"
    model = Scripted([
        [("ask", {"subject": "ip:10.0.4.7", "question": "which host?", "namespace": "netsec",
                  "valid_at": "2026-08-20T00:00:00Z"})], cite,
        [("ask", {"subject": "host:web-01", "question": "os?", "namespace": "netsec"})], "no idea",
    ])
    out = tmp_path / "not-yet" / "t.json"          # the directory is created, not a crash mid-run
    got = []

    def keep(r):
        got.append(r)
        ae.write_json(str(out), [x.__dict__ for x in got])
        # written before the next task ran
        assert len(json.loads(out.read_text())) == len(got)
    results = ae.evaluate(seeded_db, ["lease", "os"], model="fake", caller=model, on_result=keep)
    assert [r.task for r in got] == ["lease", "os"] and got == results
    assert results[0].score["pass"] and not results[1].score["pass"]


@pytest.mark.skipif(not os.environ.get("LOOMCTX_LIVE_AGENT"), reason="set LOOMCTX_LIVE_AGENT=1 (and LOOMCTX_LLM_*) for a live agent run")
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
    assert md.count("\n| `") == 4 and "| `cheap/good` | 2/2 | pass | pass |" in md
    # repeats: pass counts per task, per-run averages, sorted by pass RATE
    rows = ae.scorecard({
        "flaky/x": [rr("exposure", True, 0.4), rr("lease", True, 0.1), rr("exposure", False, 0.4), rr("lease", True, 0.1)],
        "solid/y": [rr("exposure", True, 0.3), rr("lease", True, 0.1), rr("exposure", True, 0.3), rr("lease", True, 0.1)],
    }, repeat=2)
    assert [r["model"] for r in rows] == ["solid/y", "flaky/x"]
    assert rows[1]["exposure"] == "1/2" and rows[1]["passed"] == 3 and rows[1]["tasks"] == 4
    assert rows[0]["cost"] == 0.4 and rows[0]["cost_total"] == 0.8 and rows[0]["steps"] == 6
    assert "Cost/run" in ae.scorecard_markdown(rows) and "| `flaky/x` | 3/4 | 1/2 | 2/2 |" in ae.scorecard_markdown(rows)


def test_provider_outages_are_retried_then_not_scored(seeded_db):
    """A 5xx / rate limit / error body is the provider's failure, not the
    model's answer: the task runs once more, and if it fails again it is
    'not run' — out of the pass rate, cost still counted."""
    from loomctx.llm import LLMError

    class Flaky(Scripted):
        def __init__(self, turns, outages):
            super().__init__(turns)
            self.outages = outages

        def __call__(self, provider, system, messages, tools):
            if self.outages:
                self.outages -= 1
                raise LLMError("provider returned 503: upstream", transient=True)
            return super().__call__(provider, system, messages, tools)

    def cite(messages):
        return "laptop-17 [" + json.loads(_last_tool_output(messages))["items"][0]["cites"][0].split()[0] + "]"
    lease = [("ask", {"subject": "ip:10.0.4.7", "question": "which host?", "namespace": "netsec",
                      "valid_at": "2026-08-20T00:00:00Z"})]
    # one outage: retried, and the retry is scored normally
    [r] = ae.evaluate(seeded_db, ["lease"], model="fake", caller=Flaky([lease, cite], 1))
    assert not r.infra and r.score["pass"]
    # two outages: not run, excluded from the pass rate, shown in its own column
    [r] = ae.evaluate(seeded_db, ["lease"], model="fake", caller=Flaky([], 2))
    assert r.infra and not r.score["pass"]
    ok = ae.RunResult(task="os", answer="", steps=1, score={"pass": True})
    [row] = ae.scorecard({"m": [r, ok]})
    assert row["passed"] == 1 and row["tasks"] == 1 and row["not_run"] == 1 and row["lease"] == "not run"
    assert ae.scorecard_markdown([row]).split("\n")[2].endswith("| 1 |")
    assert "| 1/1 (incomplete) |" in ae.scorecard_markdown([row])
    # an incomplete row never outranks a complete one, whatever its rate
    full = [ae.RunResult(task=t, answer="", steps=1, score={"pass": t != "os"})
            for t in ("exposure", "lease", "conflict", "os")]
    rows = ae.scorecard({"partial": [r, ok], "complete": full})
    assert [x["model"] for x in rows] == ["complete", "partial"]
    # a request the provider rejects outright (400) is the model's problem: scored
    assert not LLMError("provider returned 400: bad tool schema").transient
    # out of credit (402) is the account's problem: transient, never retried
    import io
    import urllib.error
    from unittest import mock
    from loomctx import llm as _llm
    err = urllib.error.HTTPError("https://x/v1", 402, "Payment Required", {}, io.BytesIO(b"{}"))
    with mock.patch.object(_llm, "_urlopen", side_effect=err) as call:
        try:
            _llm._post_json("https://x/v1", {}, {})
        except LLMError as exc:
            assert exc.transient and call.call_count == 1
        else:
            raise AssertionError("402 must raise")
    # a spent key (OpenRouter: 403 "Key limit exceeded") is the account's problem too
    spent = urllib.error.HTTPError("https://x/v1", 403, "Forbidden", {},
                                   io.BytesIO(b'{"error":{"message":"Key limit exceeded (total limit)","code":403}}'))
    with mock.patch.object(_llm, "_urlopen", side_effect=spent):
        try:
            _llm._post_json("https://x/v1", {}, {})
        except LLMError as exc:
            assert exc.transient
    # an expired or revoked key (OpenRouter: 401 "API key expired") is the account's problem too
    expired = urllib.error.HTTPError("https://x/v1", 401, "Unauthorized", {},
                                     io.BytesIO(b'{"error":{"message":"API key expired.","code":401}}'))
    with mock.patch.object(_llm, "_urlopen", side_effect=expired) as call:
        try:
            _llm._post_json("https://x/v1", {}, {})
        except LLMError as exc:
            assert exc.transient and call.call_count == 1
        else:
            raise AssertionError("401 must raise")
    denied = urllib.error.HTTPError("https://x/v1", 403, "Forbidden", {}, io.BytesIO(b'{"error":"model not allowed"}'))
    with mock.patch.object(_llm, "_urlopen", side_effect=denied):
        try:
            _llm._post_json("https://x/v1", {}, {})
        except LLMError as exc:
            assert not exc.transient


def test_excerpt_and_artifact_citations_count_as_seen_and_empty_completion_retries(seeded_db):
    seen = set()
    ae._collect_ids('{"citations":[{"artifact_id":"0123456789abcdef0123456789abcdef","span_start":1}]} "[doc:deadbeef @0-10]"'
                    ' {"cite":"fedcba987654","source":"s"}', seen)
    assert {"0123456789abcdef0123456789abcdef", "deadbeef", "fedcba987654"} <= seen
    ae._collect_ids('"coverage: \'member_of\' was not collected by lab-export (domain:lab.local) [bc94e86d8f1b] — x"', seen)
    assert "bc94e86d8f1b" in seen          # a coverage note's record is shown, so citable (D-092)
    ae._collect_ids('{"cites":["a1b2c3d4e5f6 nmap-scan 2026-08-07",'
                    '"00112233445566778899aabbccddeeff @0-10 ir 2026-09-01"]}', seen)
    assert {"a1b2c3d4e5f6", "00112233445566778899aabbccddeeff"} <= seen
    assert ae._cited("[fedcba98] and [fedcba987654] and [fedcba9876543210]", seen)["citations_unseen"] == 0
    model = Scripted([
        [("ask", {"subject": "ip:10.0.4.7", "question": "which host?", "namespace": "netsec"})],
        "",                                                     # transient empty completion
        lambda messages: "laptop-17 [" + json.loads(_last_tool_output(messages))["items"][0]["cites"][0].split()[0] + "]",
    ])
    r = ae.evaluate(seeded_db, ["lease"], model="fake", caller=model)[0]
    assert r.error is None and r.score["pass"] and r.steps == 3


def test_an_empty_reply_twice_is_an_error_not_an_empty_answer(seeded_db):
    """D-089: the retry marker was overwritten by the second empty reply, so
    the run ended with answer '' and no error — scored as the model's
    wrong answer. Now the second empty reply is an error that says why."""
    r = ae.evaluate(seeded_db, ["lease"], model="fake", caller=Scripted(["", ""]))[0]
    assert r.answer == "" and r.error == "empty completion twice" and not r.infra
    assert not r.score["pass"] and r.steps == 2

    def capped(provider, system, messages, tools):
        return ae.Turn("", [], {"role": "assistant", "content": ""}, {"in": 10, "out": 8000}, "length")
    r = ae.evaluate(seeded_db, ["lease"], model="fake", caller=capped)[0]
    assert r.error == f"output cap ({ae.AGENT_MAX_TOKENS} tokens) reached before an answer"


def test_openai_path_leaves_room_for_reasoning_and_reads_why_the_reply_ended(monkeypatch):
    """D-089: on OpenRouter a reasoning model's thinking counts against
    max_tokens; at 1500 it ran out before a tool call or an answer."""
    sent = []

    def fake_post(url, body, headers, timeout=0):
        sent.append(body)
        return {"choices": [{"message": {"role": "assistant", "content": None}, "finish_reason": "length"}],
                "usage": {"prompt_tokens": 9, "completion_tokens": 8000, "cost": 0.01}}

    monkeypatch.setattr(ae, "_post_json", fake_post)
    monkeypatch.setattr(ae, "_NO_TEMPERATURE", set())
    p = ae.Provider("openai", "https://openrouter.ai/api/v1", "some/reasoning-model", "k")
    turn = ae.call_model(p, "sys", [{"role": "user", "content": "q"}], [_Tool("ask")])
    assert sent[-1]["max_tokens"] == ae.AGENT_MAX_TOKENS == 8000
    assert turn.stop == "length" and turn.text == "" and not turn.calls


def test_lease_first_sentence_ends_after_a_date_and_a_rejection_is_not_an_assertion(seeded_db):
    """D-089, found reading the 2026-09-27 failures: "laptop-17 held it on
    2026-08-20. The prior assignment to web-01 ended…" glued the second
    sentence on (no split after a digit), "held by laptop-17, not web-01"
    counted as naming web-01, and "laptop‑17" (U+2011) did not match."""
    truth = {"expect": ["laptop-17"], "reject": ["web-01"]}
    for ok in ("**laptop-17** held 10.0.4.7 on 2026-08-20. The DHCP assignment began on 2026-08-10; "
               "the prior assignment to web-01 ended that day.",
               "On 2026-08-20, ip 10.0.4.7 was held by **host:laptop-17**, not web-01.",
               "**answer: `host:laptop-17` held 10.0.4.7 during the incident — not `host:web-01`, which held it before.",
               "It was laptop-17 rather than web-01 on 2026-08-20."):
        r = ae._score_lease(ok, truth, set(), None)
        assert r["rejected_in_answer"] == [] and r["names_expected"] == ["laptop-17"], ok
    # the dotted IP still does not end a sentence, and an assertion still fails
    assert ae._score_lease("web-01 held 10.0.4.7 on 2026-08-20, not laptop-17.", truth, set(), None)["rejected_in_answer"] == ["web-01"]

    def final(messages):
        pack = json.loads(_last_tool_output(messages))
        cite = next(i for i in pack["items"] if "laptop-17" in i["text"])["cites"][0].split()[0]
        return f"The address was assigned to host laptop\u201117 on 2026\u201108\u201120 [{cite}]."
    model = Scripted([[("ask", {"subject": "ip:10.0.4.7", "question": "which host?", "namespace": "netsec",
                                "valid_at": "2026-08-20T00:00:00Z", "budget": 600})], final])
    assert ae.evaluate(seeded_db, ["lease"], model="fake", caller=model)[0].score["pass"]


def test_lease_history_in_the_first_sentence_is_not_an_assertion():
    """S-43: 'reassigned on 2026-08-10 from host:web-01 to host:laptop-17'
    narrates the past; asserting web-01 still fails."""
    truth = {"expect": ["laptop-17"], "reject": ["web-01"]}
    ok = ("Based on the results, 10.0.4.7 was reassigned on 2026-08-10 from host:web-01 to "
          "host:laptop-17, so on 2026-08-20 it was held by host:laptop-17.")
    assert ae._score_lease(ok, truth, set(), None)["rejected_in_answer"] == []
    for bad in ("On 2026-08-20 the address was held by web-01 and laptop-17.",
                "host:web-01 held 10.0.4.7 on that day, not laptop-17.",
                "It moved from web-01 to laptop-17, but web-01 still held it on 2026-08-20.",
                # a bare "before"/"from" is not a history marker: these assert
                # web-01 (review 2026-09-26)
                "On 2026-08-20 it was held by laptop-17 before web-01 took it back.",
                "10.0.4.7 was never reassigned from web-01 to laptop-17.",
                "It was not moved from host:web-01, so laptop-17 never held it.",
                "The lease came from web-01 on 2026-08-20, not laptop-17."):
        assert ae._score_lease(bad, truth, set(), None)["rejected_in_answer"] == ["web-01"], bad
    assert ae._score_lease("Previously web-01; now host:laptop-17.", truth, set(), None)["rejected_in_answer"] == []
    for fine in ("It was transferred from web-01 to laptop-17 on 2026-08-10; laptop-17 held it on 2026-08-20.",
                 "Formerly held by host:web-01, the address belonged to host:laptop-17 on 2026-08-20.",
                 "host:web-01 until 2026-08-10, then host:laptop-17, which held it on 2026-08-20."):
        assert ae._score_lease(fine, truth, set(), None)["rejected_in_answer"] == [], fine
