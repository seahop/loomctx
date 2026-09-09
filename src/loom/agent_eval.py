"""Agent end-to-end evaluation (D-036): a real LLM agent, the real MCP
transport, the real corpus, no pre-built scope.

`/v1/answer` tests the model as a *reader* of a pack Loom built. This runs
the model as an *agent*: it gets the MCP tools over stdio (the transport
`claude mcp add` uses), a task in plain language, and has to discover the
data itself — resolve names, pick ask vs ask_scope, work out which
predicates to expand, pull handles, and answer with citations. Ground
truth is computed from the store, never hard-coded, and the score checks
what matters: did it name the right entities, did it invent any, and do
its citations point at observations it actually saw.

    python -m loom.agent_eval --db /data/loom.db                # every task
    python -m loom.agent_eval --db /data/loom.db --tasks lease  # one task
    LOOM_AGENT_MODEL=anthropic/claude-haiku-4.5 python -m loom.agent_eval ...
    python -m loom.agent_eval --db ... --models a/x,b/y --markdown models.md   # a scorecard

Provider/key come from LOOM_LLM_* (any OpenAI-compatible endpoint with tool
calling, or provider=anthropic); LOOM_AGENT_MODEL overrides the model.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .contracts import EntityRef
from .llm import OPENAI_COMPAT_BASES, _env, _post_json

MAX_STEPS = int(os.environ.get("LOOM_AGENT_MAX_STEPS", "20"))   # model turns per task (D-037: 14 cut off thorough models)
MAX_TOOL_CHARS = 24_000       # a tool result larger than this is cut, with a marker
NAMESPACE = "netsec"
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_HEX = re.compile(r"\b[0-9a-f]{8,32}\b")

SYSTEM = (
    "You are a security analyst agent. You have tools that query Loom, a "
    "provenance-tracked context engine, over the namespace '{ns}'. Entities are "
    "'type:key' handles (find_entity resolves names). `ask` gives cited context "
    "about one entity; `ask_scope` covers several, and with expand_predicates "
    "follows relations outward for multi-hop questions; `expand` pulls a handle "
    "deeper. Fact texts show predicate names you can expand. Conflict items mean "
    "sources disagree: report both sides, never pick one silently. Every claim in "
    "your final answer must cite observation ids you saw, in square brackets. "
    "When you have enough, reply with the answer in plain text and stop calling tools."
)


# ------------------------------------------------------------------ tasks #

@dataclass
class Task:
    name: str
    prompt: str
    truth: Callable[[Any], dict]                       # store -> ground truth
    score: Callable[[str, dict, set[str], Any], dict]  # (answer, truth, seen ids, store) -> score


def _obs(store, ref: EntityRef, limit: int = 100_000):
    return store.observations_for(NAMESPACE, ref, limit=limit)


def _truth_exposure(store) -> dict:
    """KEV-listed CVEs that affect a product web-01 runs — computed without
    the pack builder's gather cap, so it is the real answer."""
    host = EntityRef(type="host", key="web-01")
    products = sorted({o.object.key for o in _obs(store, host)
                       if o.predicate == "runs_software" and isinstance(o.object, EntityRef)})
    candidates: dict[str, str] = {}
    for key in products:
        for o in _obs(store, EntityRef(type="product", key=key)):
            if o.predicate == "affects":
                candidates.setdefault(o.subject.key, key)
    kev = {}
    for cve, product in candidates.items():
        if any(o.predicate == "exploited_in_wild" and o.object is True
               for o in _obs(store, EntityRef(type="cve", key=cve), limit=200)):
            kev[cve] = product
    return {"products": products, "kev": kev, "candidates": len(candidates)}


def _score_cves(answer: str, truth: dict, seen: set[str], store) -> dict:
    mentioned = set(_CVE.findall(answer))
    hits = sorted(mentioned & set(truth["kev"]))
    invented = sorted(c for c in mentioned
                      if store.get_entity(NAMESPACE, EntityRef(type="cve", key=c)) is None)
    cites = _cited(answer, seen)
    return {
        "kev_total": len(truth["kev"]), "kev_named": len(hits), "hits": hits,
        "cves_mentioned": len(mentioned), "invented_cves": invented, **cites,
        "pass": bool(hits) and not invented and cites["citations_unseen"] == 0,
    }


def _truth_lease(store) -> dict:
    return {"expect": "laptop-17", "reject": "web-01"}


def _score_lease(answer: str, truth: dict, seen: set[str], store) -> dict:
    cites = _cited(answer, seen)
    low = answer.lower()
    # the sentence that answers must name laptop-17; web-01 may appear only as
    # history ("until Aug 10"), so the reject is: answering web-01 outright
    first = re.split(r"[.\n]", low)[0]
    ok = truth["expect"] in low and truth["reject"] not in first
    return {"names_laptop_17": truth["expect"] in low, "first_sentence": first[:120], **cites,
            "pass": ok and cites["citations_unseen"] == 0}


def _truth_conflict(store) -> dict:
    values, sources = set(), set()
    for o in _obs(store, EntityRef(type="cve", key="CVE-2026-0544"), limit=200):
        if o.predicate == "cvss_score":
            values.add(str(o.object)); sources.add(o.source)
    return {"values": sorted(values), "sources": sorted(sources)}


def _score_conflict(answer: str, truth: dict, seen: set[str], store) -> dict:
    cites = _cited(answer, seen)
    values_named = [v for v in truth["values"] if v in answer]
    return {"values_expected": truth["values"], "values_named": values_named, **cites,
            "pass": len(values_named) == len(truth["values"]) >= 2 and cites["citations_unseen"] == 0}


def _truth_os(store) -> dict:
    return {"values": sorted({str(o.object) for o in _obs(store, EntityRef(type="host", key="web-01"))
                              if o.predicate == "runs_os"})}


def _loose(text: str) -> str:
    """'Ubuntu 22.04' and 'ubuntu-22.04' are the same answer."""
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _score_os(answer: str, truth: dict, seen: set[str], store) -> dict:
    cites = _cited(answer, seen)
    named = [v for v in truth["values"] if _loose(v) in _loose(answer)]
    return {**cites, "values_expected": truth["values"], "values_named": named,
            "pass": len(named) == len(truth["values"]) and cites["citations_unseen"] == 0}


def _cited(answer: str, seen: set[str]) -> dict:
    """Every hex id the answer cites must be (a prefix of) an observation id
    that appeared in a tool result during THIS run — the faithfulness check."""
    cited = set(_HEX.findall(answer))
    unseen = sorted(c for c in cited if not any(s.startswith(c) for s in seen))
    return {"citations": len(cited), "citations_unseen": len(unseen), "unseen_examples": unseen[:3]}


TASKS = [
    Task("exposure",
         "Is host web-01 exposed to any vulnerability that CISA lists as exploited in the wild? "
         "Work out what software it runs and which of those products have such CVEs. Name the "
         "CVEs and the software, and cite observation ids.",
         _truth_exposure, _score_cves),
    Task("lease",
         "Which host held the IP address 10.0.4.7 on 2026-08-20? Cite observation ids.",
         _truth_lease, _score_lease),
    Task("conflict",
         "What do sources disagree about regarding CVE-2026-0544's CVSS score? Give each value "
         "and who reported it, with citations.",
         _truth_conflict, _score_conflict),
    Task("os",
         "What operating system does web-01 run? If sources disagree, say so and give every value, with citations.",
         _truth_os, _score_os),
]


# --------------------------------------------------------------- provider #

@dataclass
class Provider:
    kind: str                 # "openai" | "anthropic"
    base_url: str
    model: str
    api_key: str | None

    @classmethod
    def from_env(cls, model: str | None = None) -> "Provider":
        model = model or _env("LOOM_AGENT_MODEL") or _env("LOOM_LLM_MODEL")
        provider = (_env("LOOM_LLM_PROVIDER") or "").lower() or None
        base_url = _env("LOOM_LLM_BASE_URL")
        key = _env("LOOM_LLM_API_KEY")
        if not model:
            raise SystemExit("set LOOM_LLM_MODEL (or LOOM_AGENT_MODEL) and LOOM_LLM_PROVIDER/BASE_URL")
        if provider == "anthropic":
            return cls("anthropic", base_url or "https://api.anthropic.com", model, key)
        base_url = base_url or OPENAI_COMPAT_BASES.get(provider or "")
        if not base_url:
            raise SystemExit(f"unknown provider {provider!r} and no LOOM_LLM_BASE_URL")
        return cls("openai", base_url.rstrip("/"), model, key)


@dataclass
class Turn:
    """One model call: either tool calls to run, or a final text."""
    text: str
    calls: list[tuple[str, str, dict]]     # (call id, tool name, args)
    raw_message: Any
    usage: dict                            # in, out, and cost (USD) when the provider reports it


def _openai_tools(tools) -> list[dict]:
    return [{"type": "function", "function": {
        "name": t.name, "description": t.description or "", "parameters": t.input_schema}}
        for t in tools]


def _anthropic_tools(tools) -> list[dict]:
    return [{"name": t.name, "description": t.description or "", "input_schema": t.input_schema}
            for t in tools]


def call_model(p: Provider, system: str, messages: list, tools, max_tokens: int = 1500) -> Turn:
    if p.kind == "openai":
        headers = {"authorization": f"Bearer {p.api_key}"} if p.api_key else {}
        body = {
            "model": p.model, "max_tokens": max_tokens, "tools": _openai_tools(tools),
            "tool_choice": "auto",
            "messages": [{"role": "system", "content": system}, *messages],
        }
        if "openrouter.ai" in p.base_url:
            body["usage"] = {"include": True}   # billed cost per call, cache discounts included
        data = _post_json(p.base_url + "/chat/completions", body, headers, timeout=180)
        msg = data["choices"][0]["message"]
        calls = []
        for tc in msg.get("tool_calls") or []:
            fn = tc["function"]
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except ValueError:
                args = {}
            calls.append((tc["id"], fn["name"], args))
        u = data.get("usage") or {}
        return Turn(msg.get("content") or "", calls, msg,
                    {"in": u.get("prompt_tokens", 0), "out": u.get("completion_tokens", 0),
                     "cost": float(u.get("cost") or 0.0)})
    data = _post_json(p.base_url + "/v1/messages", {
        "model": p.model, "max_tokens": max_tokens, "system": system,
        "tools": _anthropic_tools(tools), "messages": messages,
    }, {"x-api-key": p.api_key or "", "anthropic-version": "2023-06-01"}, timeout=180)
    text, calls = "", []
    for block in data.get("content", []):
        if block.get("type") == "text":
            text += block.get("text", "")
        elif block.get("type") == "tool_use":
            calls.append((block["id"], block["name"], block.get("input") or {}))
    u = data.get("usage") or {}
    return Turn(text, calls, {"role": "assistant", "content": data.get("content", [])},
                {"in": u.get("input_tokens", 0), "out": u.get("output_tokens", 0)})


def tool_result_messages(p: Provider, turn: Turn, results: list[tuple[str, str]]) -> list:
    """The assistant turn plus its tool results, in the provider's dialect."""
    if p.kind == "openai":
        return [turn.raw_message, *[{"role": "tool", "tool_call_id": cid, "content": out}
                                    for cid, out in results]]
    return [turn.raw_message, {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": cid, "content": out} for cid, out in results]}]


# ------------------------------------------------------------------- loop #

def _payload_text(result) -> str:
    structured = getattr(result, "structured_content", None)
    if structured:
        return json.dumps(structured.get("result", structured))
    return "".join(c.text for c in result.content if getattr(c, "text", None))


def _collect_ids(text: str, seen: set[str]) -> None:
    for m in re.finditer(r'"observation_id":\s*"([0-9a-f]{32})"', text):
        seen.add(m.group(1))
    for m in re.finditer(r'"id":\s*"([0-9a-f]{32})"', text):
        seen.add(m.group(1))


@dataclass
class RunResult:
    task: str
    answer: str
    steps: int
    tool_calls: list[dict] = field(default_factory=list)
    usage: dict = field(default_factory=lambda: {"in": 0, "out": 0, "cost": 0.0})
    seconds: float = 0.0
    truth: dict = field(default_factory=dict)
    score: dict = field(default_factory=dict)
    error: str | None = None


async def run_task(session, provider: Provider, task: Task, store,
                   caller: Callable = call_model, instructions: str = "") -> RunResult:
    tools = (await session.list_tools()).tools
    seen: set[str] = set()
    messages: list = [{"role": "user", "content": task.prompt}]
    result = RunResult(task=task.name, answer="", steps=0)
    t0 = time.monotonic()
    # the server's own instructions, exactly as a real MCP client passes them on
    system = SYSTEM.format(ns=NAMESPACE) + (f"\n\nServer instructions: {instructions}" if instructions else "")
    try:
        for step in range(MAX_STEPS):
            result.steps = step + 1
            turn = await asyncio.to_thread(caller, provider, system, messages, tools)
            result.usage["in"] += turn.usage.get("in", 0)
            result.usage["out"] += turn.usage.get("out", 0)
            result.usage["cost"] = round(result.usage.get("cost", 0.0) + turn.usage.get("cost", 0.0), 5)
            if not turn.calls:
                result.answer = turn.text
                break
            outputs = []
            for cid, name, args in turn.calls:
                t1 = time.monotonic()
                try:
                    res = await session.call_tool(name, args)
                    out = _payload_text(res)
                    is_error = bool(getattr(res, "is_error", False))
                except Exception as exc:  # the loop must survive a bad call
                    out, is_error = f"error: {exc}", True
                _collect_ids(out, seen)
                if len(out) > MAX_TOOL_CHARS:
                    out = out[:MAX_TOOL_CHARS] + '... [truncated: use a smaller budget or expand a handle]'
                result.tool_calls.append({"step": step + 1, "tool": name, "args": args,
                                          "chars": len(out), "error": is_error,
                                          "ms": round((time.monotonic() - t1) * 1000)})
                outputs.append((cid, out))
            messages.extend(tool_result_messages(provider, turn, outputs))
        else:
            result.answer = turn.text or ""
            result.error = f"no final answer within {MAX_STEPS} steps"
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
    result.seconds = round(time.monotonic() - t0, 1)
    result.truth = task.truth(store)
    result.score = task.score(result.answer, result.truth, seen, store)
    if result.error:
        result.score["pass"] = False
    return result


async def _session(db: str, fn):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    env = {**os.environ, "LOOM_DB": db}
    for var in ("LOOM_API_KEYS", "LOOM_AUTH_FILE"):
        env.pop(var, None)
    params = StdioServerParameters(command=sys.executable, args=["-m", "loom.mcp_server"], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            return await fn(session, getattr(init, "instructions", None) or "")


def evaluate(db: str, task_names: list[str] | None, model: str | None = None,
             caller: Callable = call_model) -> list[RunResult]:
    from .store.factory import store_from_url
    provider = Provider.from_env(model)
    tasks = [t for t in TASKS if not task_names or t.name in task_names]
    store = store_from_url(db)
    try:
        async def run_all(session, instructions):
            return [await run_task(session, provider, t, store, caller, instructions) for t in tasks]
        return asyncio.run(_session(db, run_all))
    finally:
        store.close()


def summarize(results: list[RunResult], model: str) -> str:
    lines = [f"agent eval — model {model}", "task       pass  steps  calls  tokens(in/out)  secs   cost  detail"]
    for r in results:
        detail = {k: v for k, v in r.score.items() if k != "pass"}
        lines.append(f"{r.task:<10} {'PASS' if r.score.get('pass') else 'FAIL':<5} {r.steps:>5}  "
                     f"{len(r.tool_calls):>5}  {r.usage['in']:>6}/{r.usage['out']:<6}  {r.seconds:>5}  "
                     f"${r.usage.get('cost', 0):.3f}  {json.dumps(detail, default=str)[:150]}")
        if r.error:
            lines.append(f"           error: {r.error}")
    return "\n".join(lines)


# ------------------------------------------------------------- scorecard #

def scorecard(runs: dict[str, list[RunResult]]) -> list[dict]:
    """One row per model: passes, per-task outcome, totals. Sorted by passes
    desc, then cost asc — the cheapest model that gets it right wins."""
    rows = []
    for model, results in runs.items():
        by = {r.task: r for r in results}
        rows.append({
            "model": model,
            "passed": sum(1 for r in results if r.score.get("pass")),
            "tasks": len(results),
            "exposure": _outcome(by.get("exposure")), "lease": _outcome(by.get("lease")),
            "conflict": _outcome(by.get("conflict")), "os": _outcome(by.get("os")),
            "steps": sum(r.steps for r in results),
            "tool_calls": sum(len(r.tool_calls) for r in results),
            "tokens_in": sum(r.usage["in"] for r in results),
            "tokens_out": sum(r.usage["out"] for r in results),
            "seconds": round(sum(r.seconds for r in results), 1),
            "cost": round(sum(r.usage.get("cost", 0.0) for r in results), 4),
            "unseen_citations": sum(r.score.get("citations_unseen", 0) for r in results),
            "invented": sum(len(r.score.get("invented_cves", [])) for r in results),
            "errors": [f"{r.task}: {r.error}" for r in results if r.error],
        })
    rows.sort(key=lambda r: (-r["passed"], r["cost"]))
    return rows


def _outcome(r: RunResult | None) -> str:
    if r is None:
        return "-"
    if r.error and "steps" not in r.error:
        return "error"
    return "pass" if r.score.get("pass") else "fail"


def scorecard_markdown(rows: list[dict]) -> str:
    head = ("| Model | Passed | 2-hop exposure | lease | conflict | os | Steps | Tokens in/out | Time | Cost | Faithful |\n"
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    body = []
    for r in rows:
        faithful = "yes" if r["unseen_citations"] == 0 and r["invented"] == 0 else \
            f"no ({r['unseen_citations']} unseen cites, {r['invented']} invented)"
        body.append(f"| `{r['model']}` | {r['passed']}/{r['tasks']} | {r['exposure']} | {r['lease']} | "
                    f"{r['conflict']} | {r['os']} | {r['steps']} | {r['tokens_in']:,}/{r['tokens_out']:,} | "
                    f"{r['seconds']:.0f} s | ${r['cost']:.2f} | {faithful} |")
    return head + "\n" + "\n".join(body)


def main() -> None:
    parser = argparse.ArgumentParser(prog="loom.agent_eval", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", default=os.environ.get("LOOM_DB", "loom.db"))
    parser.add_argument("--tasks", help="comma-separated subset of: " + ",".join(t.name for t in TASKS))
    parser.add_argument("--model", help="override LOOM_AGENT_MODEL / LOOM_LLM_MODEL")
    parser.add_argument("--models", help="comma-separated models to compare (a scorecard run)")
    parser.add_argument("--out", help="write the full transcript (JSON) here")
    parser.add_argument("--markdown", help="scorecard runs: also write a Markdown table here")
    args = parser.parse_args()
    names = [n.strip() for n in args.tasks.split(",")] if args.tasks else None
    if args.models:
        runs: dict[str, list[RunResult]] = {}
        for model in [m.strip() for m in args.models.split(",") if m.strip()]:
            try:
                runs[model] = evaluate(args.db, names, model)
            except Exception as exc:  # a model that cannot even start still gets a row
                runs[model] = [RunResult(task=t.name, answer="", steps=0, error=f"{type(exc).__name__}: {exc}",
                                         score={"pass": False}) for t in TASKS if not names or t.name in names]
            print(summarize(runs[model], model), flush=True)
            print(flush=True)
        rows = scorecard(runs)
        print(scorecard_markdown(rows))
        if args.markdown:
            with open(args.markdown, "w") as fh:
                fh.write(scorecard_markdown(rows) + "\n")
        if args.out:
            with open(args.out, "w") as fh:
                json.dump({m: [r.__dict__ for r in rs] for m, rs in runs.items()}, fh, indent=2, default=str)
            print(f"transcripts: {args.out}")
        return
    results = evaluate(args.db, names, args.model)
    model = Provider.from_env(args.model).model
    print(summarize(results, model))
    if args.out:
        with open(args.out, "w") as fh:
            json.dump([r.__dict__ for r in results], fh, indent=2, default=str)
        print(f"transcript: {args.out}")
    sys.exit(0 if all(r.score.get("pass") for r in results) else 1)


if __name__ == "__main__":
    main()
