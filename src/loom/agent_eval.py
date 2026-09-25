"""Agent end-to-end evaluation (D-036): a real LLM agent, the real MCP
transport, the real corpus, no pre-built scope.

`/v1/answer` tests the model as a *reader* of a pack Loom built. This runs
the model as an *agent*: it gets the MCP tools over stdio (the transport
`claude mcp add` uses), a task in plain language, and has to discover the
data itself — resolve names, pick ask vs ask_scope, work out which
predicates to expand, pull handles, and answer with citations. Ground
truth is computed from the store, never hard-coded, and the score checks
what matters: did it name the right entities, did it invent any, and do
its citations point at observations it actually saw. Every task whose
answer is a fact must cite at least one observation the agent saw, and no
id it did not (D-057).

    python -m loom.agent_eval                                   # every task, the LOOM_DB store
    python -m loom.agent_eval --db /data/loom.db --tasks lease  # one task, an explicit store
    LOOM_LLM_PROVIDER=anthropic LOOM_AGENT_MODEL=claude-opus-5 python -m loom.agent_eval ...
    python -m loom.agent_eval --db ... --models a/x,b/y --markdown models.md   # a scorecard

Provider/key come from LOOM_LLM_* (any OpenAI-compatible endpoint with tool
calling, or provider=anthropic); LOOM_AGENT_MODEL overrides the model.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import math
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from .contracts import EntityRef
from .llm import OPENAI_COMPAT_BASES, LLMError, _env, _post_json

MAX_STEPS = int(os.environ.get("LOOM_AGENT_MAX_STEPS", "20"))   # model turns per task (D-037: 14 cut off thorough models)
MAX_TOOL_CHARS = 24_000       # a tool result larger than this is cut, with a marker
# Anthropic models think before they act, by default: at max_tokens=1500
# the thinking alone hit the cap before a tool_use block, and the turn
# read as a final answer. Current models take adaptive thinking
# (`thinking: {"type": "adaptive"}`); Haiku 4.5 still takes a
# budget_tokens form and runs without thinking here, as it did on the
# scorecard. LOOM_AGENT_THINKING=off omits the parameter for every model.
ANTHROPIC_MAX_TOKENS = 8000
THINKING = (os.environ.get("LOOM_AGENT_THINKING") or "adaptive").strip().lower()
_NO_ADAPTIVE = re.compile(r"haiku-4-5|sonnet-4-5|opus-4-5|claude-3")
NAMESPACE = "netsec"
LEASE_IP = "10.0.4.7"
LEASE_AT = datetime(2026, 8, 20, tzinfo=timezone.utc)    # the moment the lease task asks about
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_HEX = re.compile(r"\b[0-9a-f]{8,32}\b")
_HEX_LETTER = re.compile(r"[a-f]")
# the exposure task passes on recall of the KEV set, not on one name: at
# least this share of it (every one when the set has at most
# _EXPOSURE_ALL_UNDER members), with no invented or non-KEV CVE (D-057)
EXPOSURE_RECALL = 0.5
_EXPOSURE_ALL_UNDER = 4
# asides — "(moved from web-01 on Aug 10)", "[a1b2c3d4e5f6]" — are history
# and citations, not the asserted answer
_ASIDE = re.compile(r"\([^()]*\)|\[[^\[\]]*\]")
_NUMBER = re.compile(r"-?\d+(?:\.\d+)?")
# sentence boundary: a period not inside a dotted token (10.0.4.7, 22.04)
_SENTENCE = re.compile(r"(?<!\d)\.(?!\d)|\n")

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
    via: dict[str, set[str]] = {}
    for key in products:
        for o in _obs(store, EntityRef(type="product", key=key)):
            if o.predicate == "affects":
                via.setdefault(o.subject.key, set()).add(key)
    kev = {}
    for cve, product in candidates.items():
        if any(o.predicate == "exploited_in_wild" and o.object is True
               for o in _obs(store, EntityRef(type="cve", key=cve), limit=200)):
            kev[cve] = product
    return {"products": products, "kev": kev, "candidates": len(candidates),
            "via": {c: sorted(via.get(c, {kev[c]})) for c in sorted(kev)}}


def exposure_required(total: int) -> int:
    """How many of the KEV set an exposure answer must name to pass."""
    return total if total <= _EXPOSURE_ALL_UNDER else math.ceil(EXPOSURE_RECALL * total)


def _product_named(answer: str, key: str) -> bool:
    """A product key `vendor:product` is named when its product part is
    (`linux:linux_kernel` by "Linux kernel", `openssl:openssl` by "OpenSSL")."""
    part = _loose(key.split(":", 1)[-1])
    return bool(part) and part in _loose(answer)


def _score_cves(answer: str, truth: dict, seen: set[str], store) -> dict:
    """Pass: at least `exposure_required` of the KEV set named, none
    invented, none real-but-not-KEV-for-this-host, the software each named
    CVE reaches the host through named too, and a faithful citation. It
    used to pass on any one of 29 CVEs, software unchecked, uncited (D-057)."""
    mentioned = set(_CVE.findall(answer))
    kev = set(truth["kev"])
    hits = sorted(mentioned & kev)
    invented = sorted(c for c in mentioned
                      if store.get_entity(NAMESPACE, EntityRef(type="cve", key=c)) is None)
    # real CVEs that are NOT in the KEV set for web-01: naming them as the
    # exposure is a precision failure, not just a recall shortfall
    false_kev = sorted((mentioned - kev) - set(invented))
    via = truth.get("via") or {c: [p] for c, p in truth["kev"].items()}
    software = sorted({p for c in hits for p in via.get(c, []) if _product_named(answer, p)})
    unexplained = [c for c in hits if not any(p in software for p in via.get(c, []))]
    required = exposure_required(len(kev))
    cites = _cited(answer, seen)
    # with no KEV exposure at all, the right answer names no CVE
    ok = (len(hits) >= required and not invented and not false_kev and not unexplained
          and (bool(kev) or not mentioned))
    return {
        "kev_total": len(kev), "kev_named": len(hits), "kev_required": required, "hits": hits,
        "recall": round(len(hits) / len(kev), 3) if kev else None,
        "precision": round(len(hits) / len(mentioned), 3) if mentioned else None,
        "cves_mentioned": len(mentioned), "invented_cves": invented,
        "false_kev": len(false_kev), "false_kev_examples": false_kev[:3],
        "software_named": software, "software_missing_for": unexplained[:3], **cites,
        "pass": ok and _faithful(cites),
    }


def _truth_lease(store) -> dict:
    """Which hosts held LEASE_IP at LEASE_AT, from the observations whose
    validity window covers that moment; every other host the IP was ever
    assigned to is a wrong answer (history, not the answer)."""
    holders, others = set(), set()
    for o in _obs(store, EntityRef(type="ip", key=LEASE_IP), limit=1000):
        if o.predicate != "assigned_to" or not isinstance(o.object, EntityRef):
            continue
        covers = ((o.valid_from is None or o.valid_from <= LEASE_AT)
                  and (o.valid_to is None or LEASE_AT < o.valid_to))
        (holders if covers else others).add(o.object.key.lower())
    return {"expect": sorted(holders), "reject": sorted(others - holders)}


def _asserted(text: str) -> str:
    """The text without its asides (parentheses, brackets), nested ones too."""
    prev = None
    while prev != text:
        prev, text = text, _ASIDE.sub(" ", text)
    return text


def _mentions(text: str, key: str) -> bool:
    """`key` as a whole token, case-insensitive: web-01 is not web-010."""
    return re.search(r"(?<![a-z0-9])" + re.escape(key.lower()) + r"(?![a-z0-9])", text.lower()) is not None


# words that mark a host as the lease's past, not its answer: "reassigned
# from host:web-01 to host:laptop-17", "previously web-01"
_HISTORY_MARK = re.compile(r"\b(?:from|previously|formerly|until|replacing|replaced|before)\W+(?:\w+:)?$")


def _history_only(sentence: str, key: str) -> bool:
    """Every mention of `key` in `sentence` is marked as history (S-43: a
    correct answer that narrates the reassignment in its first sentence
    was failed as naming the former holder)."""
    text = sentence.lower()
    spots = list(re.finditer(r"(?<![a-z0-9])" + re.escape(key.lower()) + r"(?![a-z0-9])", text))
    return bool(spots) and all(_HISTORY_MARK.search(text[max(0, m.start() - 40):m.start()]) for m in spots)


def _score_lease(answer: str, truth: dict, seen: set[str], store) -> dict:
    cites = _cited(answer, seen)
    # the sentence that answers must name the holder; a former holder may
    # appear only as history — a later sentence ("Before Aug 10 it was
    # web-01") or an aside ("laptop-17 (moved from web-01 on Aug 10)") —
    # so the reject is: asserting it outright in the first sentence
    asserted = _asserted(answer).strip().lower()
    first = _SENTENCE.split(asserted)[0]
    named = [h for h in truth["expect"] if _mentions(asserted, h)]
    rejected = [h for h in truth["reject"] if _mentions(first, h) and not _history_only(first, h)]
    ok = bool(truth["expect"]) and len(named) == len(truth["expect"]) and not rejected
    return {"names_expected": named, "rejected_in_answer": rejected,
            "first_sentence": first[:120], **cites,
            "pass": ok and _faithful(cites)}


def _truth_conflict(store) -> dict:
    values, sources = set(), set()
    for o in _obs(store, EntityRef(type="cve", key="CVE-2026-0544"), limit=200):
        if o.predicate == "cvss_score":
            values.add(str(o.object)); sources.add(o.source)
    return {"values": sorted(values), "sources": sorted(sources)}


def _value_named(answer: str, value: str) -> bool:
    """A reported value: numbers by value (7.5 is not named by 17.5 or
    7.55), anything else as a whole token."""
    if _NUMBER.fullmatch(value):
        return any(float(n) == float(value) for n in _NUMBER.findall(answer))
    return _mentions(answer, value)


def _score_conflict(answer: str, truth: dict, seen: set[str], store) -> dict:
    cites = _cited(answer, seen)
    values_named = [v for v in truth["values"] if _value_named(answer, v)]
    return {"values_expected": truth["values"], "values_named": values_named, **cites,
            "pass": len(values_named) == len(truth["values"]) >= 2 and _faithful(cites)}


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
            "pass": bool(truth["values"]) and len(named) == len(truth["values"]) and _faithful(cites)}


def cite_tokens_in(text: str) -> list[str]:
    """The hex runs in `text` that can be citations: 8 to 32 hex digits
    with at least one a-f letter, or a full 32-hex id. A date or a count
    (20260820, 12345678) is not a citation — it used to be taken for one,
    and then flagged as unseen."""
    return [t for t in _HEX.findall(text) if len(t) == 32 or _HEX_LETTER.search(t)]


def _cited(answer: str, seen: set[str]) -> dict:
    """Every hex id the answer cites must be (a prefix of) an observation id
    that appeared in a tool result during THIS run — the faithfulness check."""
    cited = set(cite_tokens_in(answer))
    # a cite is seen when it prefixes a seen id, or a seen cite token (12
    # hex) prefixes it — the agent may quote either form
    unseen = sorted(c for c in cited
                    if not any(s.startswith(c) or c.startswith(s) for s in seen))
    return {"citations": len(cited), "citations_seen": len(cited) - len(unseen),
            "citations_unseen": len(unseen), "unseen_examples": unseen[:3]}


def _faithful(cites: dict) -> bool:
    """A factual answer must stand on at least one observation the agent
    saw, and cite nothing it did not (D-057: an uncited answer used to pass)."""
    return cites["citations_seen"] >= 1 and cites["citations_unseen"] == 0


TASKS = [
    Task("exposure",
         "Is host web-01 exposed to any vulnerability that CISA lists as exploited in the wild? "
         "Work out what software it runs and which of those products have such CVEs. Name every "
         "such CVE and the software it affects, and cite observation ids.",
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


# Models that answered a temperature parameter with an error (some
# reasoning models take none): they run at their default for the rest of
# the process, and every other model at 0 so repeats differ by the model's
# own nondeterminism, not by sampling (D-057).
_NO_TEMPERATURE: set[str] = set()


def _post_at_zero(p: Provider, url: str, body: dict, headers: dict) -> dict:
    """POST with temperature 0, retried once without it when the model
    rejects the parameter."""
    if p.model not in _NO_TEMPERATURE:
        try:
            return _post_json(url, {**body, "temperature": 0}, headers, timeout=180)
        except LLMError as exc:
            if "temperature" not in str(exc).lower():
                raise
            _NO_TEMPERATURE.add(p.model)
    return _post_json(url, body, headers, timeout=180)


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
        data = _post_at_zero(p, p.base_url + "/chat/completions", body, headers)
        if not data.get("choices"):
            # OpenRouter reports an upstream failure as a 200 with an error
            # body: the provider's outage, not the model's answer
            raise LLMError(f"provider returned no choices: {str(data.get('error') or data)[:300]}",
                           transient=True)
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
    body = anthropic_body(p, system, messages, tools, max_tokens)
    headers = {"x-api-key": p.api_key or "", "anthropic-version": "2023-06-01"}
    url = p.base_url + "/v1/messages"
    # extended thinking takes no temperature but the default
    data = (_post_json(url, body, headers, timeout=180) if "thinking" in body
            else _post_at_zero(p, url, body, headers))
    stop = data.get("stop_reason")
    if stop == "refusal":
        details = data.get("stop_details") or {}
        raise RuntimeError(f"provider refused the request (category={details.get('category')!r})")
    text, calls = "", []
    for block in data.get("content", []):
        if block.get("type") == "text":
            text += block.get("text", "")
        elif block.get("type") == "tool_use":
            calls.append((block["id"], block["name"], block.get("input") or {}))
    if stop == "max_tokens" and not calls:
        logging.getLogger("loom.agent_eval").warning(
            "%s hit max_tokens=%d before a tool call or an answer", p.model, ANTHROPIC_MAX_TOKENS)
    u = data.get("usage") or {}
    # the whole content list goes back on the next turn — thinking blocks
    # included, unchanged, as the same model expects them
    return Turn(text, calls, {"role": "assistant", "content": data.get("content", [])},
                {"in": u.get("input_tokens", 0), "out": u.get("output_tokens", 0)})


def anthropic_body(p: Provider, system: str, messages: list, tools, max_tokens: int) -> dict:
    """The Messages request: room for thinking plus a tool call, adaptive
    thinking on the models that take it."""
    body = {
        "model": p.model, "max_tokens": max(max_tokens, ANTHROPIC_MAX_TOKENS), "system": system,
        "tools": _anthropic_tools(tools), "messages": messages,
    }
    if THINKING != "off" and not _NO_ADAPTIVE.search(p.model):
        body["thinking"] = {"type": "adaptive"}
    return body


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
    for m in re.finditer(r'"(?:observation_id|artifact_id|id)":\s*"([0-9a-f]{32})"', text):
        seen.add(m.group(1))
    for m in re.finditer(r'"cite":\s*"([0-9a-f]{12})"', text):   # compact citations carry the token only
        seen.add(m.group(1))
    # concise MCP items cite as strings, token first (D-058): "<cite> <source> <date>",
    # or "<artifact_id> @<span> <source> <date>" for a passage
    for m in re.finditer(r'"([0-9a-f]{12}|[0-9a-f]{32}) (?:@\d+-\d+ )?[^"]*\d{4}-\d{2}-\d{2}"', text):
        seen.add(m.group(1))
    for m in re.finditer(r'\[doc:([0-9a-f]{8})', text):   # excerpt renderings cite a prefix
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
    # the provider failed (after its retries), not the model: excluded from
    # pass rates and shown as not run, never scored as a fail
    infra: bool = False


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
                if not turn.text.strip() and not result.answer:
                    # a provider returning neither text nor tool calls is a
                    # transient, not an answer: one retry (D-039)
                    result.answer = "\x00retry"
                    continue
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
        result.infra = isinstance(exc, LLMError) and exc.transient
    if result.answer == "\x00retry":
        result.answer = ""
        result.error = result.error or "empty completion twice"
    result.seconds = round(time.monotonic() - t0, 1)
    result.truth = task.truth(store)
    result.score = task.score(result.answer, result.truth, seen, store)
    if result.error:
        result.score["pass"] = False
    return result


async def _session(db: str | None, fn):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    # an explicit --db pins the server to one store; otherwise it opens the
    # same LOOM_DB / LOOM_SHARDS / LOOM_BLOB_* configuration this process has
    env = {**os.environ, **({"LOOM_DB": db} if db else {})}
    for var in ("LOOM_API_KEYS", "LOOM_AUTH_FILE"):
        env.pop(var, None)
    params = StdioServerParameters(command=sys.executable, args=["-m", "loom.mcp_server"], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            return await fn(session, getattr(init, "instructions", None) or "")


def evaluate(db: str | None, task_names: list[str] | None, model: str | None = None,
             caller: Callable = call_model,
             on_result: Callable[[RunResult], None] | None = None) -> list[RunResult]:
    """Every task, one after another; `on_result` sees each result as it
    finishes (the CLI writes --out then, so a crash keeps what was paid for)."""
    from .store.factory import store_from_env, store_from_url
    # a scripted caller (tests) needs no provider: CI has no LOOM_LLM_* and
    # must not need one to exercise the loop
    provider = (Provider.from_env(model) if caller is call_model
                else Provider("openai", "scripted://", model or "scripted", None))
    tasks = [t for t in TASKS if not task_names or t.name in task_names]
    store = store_from_url(db) if db else store_from_env()
    try:
        async def run_all(session, instructions):
            out = []
            for t in tasks:
                result = await run_task(session, provider, t, store, caller, instructions)
                if result.infra:
                    # one more try after a provider outage; what the failed
                    # attempt cost is still counted
                    spent = result.usage
                    result = await run_task(session, provider, t, store, caller, instructions)
                    for k in ("in", "out", "cost"):
                        result.usage[k] = result.usage.get(k, 0) + spent.get(k, 0)
                out.append(result)
                if on_result:
                    on_result(out[-1])
            return out
        return asyncio.run(_session(db, run_all))
    finally:
        store.close()


def write_json(path: str, payload: Any) -> None:
    """Replace `path` atomically: a reader (or a crash) never sees half a file."""
    tmp = f"{path}.tmp"
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(tmp, "w") as fh:
        json.dump(payload, fh, indent=2, default=str)
    os.replace(tmp, path)


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

def scorecard(runs: dict[str, list[RunResult]], repeat: int = 1) -> list[dict]:
    """One row per model over `repeat` full runs: pass rate, per-task
    passes, and per-run averages. Sorted by pass rate desc, then cost per
    run asc — the cheapest model that gets it right wins."""
    rows = []
    for model, results in runs.items():
        by: dict[str, list[RunResult]] = {}
        for r in results:
            by.setdefault(r.task, []).append(r)
        n = max(1, repeat)
        scored = [r for r in results if not r.infra]
        rows.append({
            "model": model, "repeat": n,
            "passed": sum(1 for r in scored if r.score.get("pass")),
            "tasks": len(scored),
            "not_run": len(results) - len(scored),
            "exposure": _outcome(by.get("exposure", [])), "lease": _outcome(by.get("lease", [])),
            "conflict": _outcome(by.get("conflict", [])), "os": _outcome(by.get("os", [])),
            "steps": round(sum(r.steps for r in results) / n, 1),
            "tool_calls": round(sum(len(r.tool_calls) for r in results) / n, 1),
            "tokens_in": round(sum(r.usage["in"] for r in results) / n),
            "tokens_out": round(sum(r.usage["out"] for r in results) / n),
            "seconds": round(sum(r.seconds for r in results) / n, 1),
            "cost": round(sum(r.usage.get("cost", 0.0) for r in results) / n, 4),
            "cost_total": round(sum(r.usage.get("cost", 0.0) for r in results), 4),
            "unseen_citations": sum(r.score.get("citations_unseen", 0) for r in results),
            "invented": sum(len(r.score.get("invented_cves", [])) for r in results),
            "errors": [f"{r.task}: {r.error}" for r in results if r.error],
        })
    # a row with tasks the provider never ran is incomplete: it ranks after
    # every complete row (7/7 of a partial run is not better than 12/12)
    rows.sort(key=lambda r: (r["not_run"] > 0, -(r["passed"] / max(1, r["tasks"])), r["cost"]))
    return rows


def _outcome(rs: list[RunResult]) -> str:
    """'pass'/'fail'/'error' for one run; 'k/n' across repeats."""
    if not rs:
        return "-"
    scored = [r for r in rs if not r.infra]
    if not scored:
        return "not run"
    if len(rs) == 1:
        r = rs[0]
        if r.error and "steps" not in r.error:
            return "error"
        return "pass" if r.score.get("pass") else "fail"
    return f"{sum(1 for r in scored if r.score.get('pass'))}/{len(scored)}"


def scorecard_markdown(rows: list[dict]) -> str:
    multi = any(r.get("repeat", 1) > 1 for r in rows)
    per = "/run" if multi else ""
    head = (f"| Model | Passed | 2-hop exposure | lease | conflict | os | Steps{per} | Tokens in/out{per} | "
            f"Time{per} | Cost{per} | Faithful | Not run |\n"
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    body = []
    for r in rows:
        faithful = "yes" if r["unseen_citations"] == 0 and r["invented"] == 0 else \
            f"no ({r['unseen_citations']} unseen cites, {r['invented']} invented)"
        partial = " (incomplete)" if r.get("not_run") else ""
        body.append(f"| `{r['model']}` | {r['passed']}/{r['tasks']}{partial} | {r['exposure']} | {r['lease']} | "
                    f"{r['conflict']} | {r['os']} | {r['steps']:g} | {r['tokens_in']:,}/{r['tokens_out']:,} | "
                    f"{r['seconds']:.0f} s | ${r['cost']:.2f} | {faithful} | {r.get('not_run', 0)} |")
    note = ("\n\nNot run: tasks the provider failed (rate limit, 5xx, unreachable, an error "
            "body) after its retries and one task-level retry — excluded from Passed, never "
            "scored as the model's failure.")
    return head + "\n" + "\n".join(body) + note


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loom.agent_eval", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", help="explicit store URL/path; bypasses LOOM_SHARDS / LOOM_BLOB_* "
                                     "(default: the store LOOM_DB and friends configure)")
    parser.add_argument("--tasks", help="comma-separated subset of: " + ",".join(t.name for t in TASKS))
    parser.add_argument("--model", help="override LOOM_AGENT_MODEL / LOOM_LLM_MODEL")
    parser.add_argument("--models", help="comma-separated models to compare (a scorecard run)")
    parser.add_argument("--repeat", type=int, default=1, help="scorecard runs: full runs per model (pass rates)")
    parser.add_argument("--out", help="write the full transcript (JSON) here, rewritten as each task finishes")
    parser.add_argument("--markdown", help="scorecard runs: also write a Markdown table here")
    args = parser.parse_args(argv)
    names = [n.strip() for n in args.tasks.split(",")] if args.tasks else None
    if args.models:
        runs: dict[str, list[RunResult]] = {}

        def save(_=None) -> None:
            if args.out:
                write_json(args.out, {m: [r.__dict__ for r in rs] for m, rs in runs.items()})
        for model in [m.strip() for m in args.models.split(",") if m.strip()]:
            runs[model] = []
            for rep in range(max(1, args.repeat)):
                done = len(runs[model])
                try:
                    batch = evaluate(args.db, names, model,
                                     on_result=lambda r, m=model: (runs[m].append(r), save()))
                except Exception as exc:  # a model that cannot even start still gets a row
                    batch = [RunResult(task=t.name, answer="", steps=0, error=f"{type(exc).__name__}: {exc}",
                                       score={"pass": False}, infra=True)
                             for t in TASKS if not names or t.name in names]
                # the callback appended what finished; a start-up failure appends the error rows
                del runs[model][done:]
                runs[model].extend(batch)
                save()
                print(summarize(batch, f"{model} (run {rep + 1}/{max(1, args.repeat)})"), flush=True)
                print(flush=True)
        rows = scorecard(runs, args.repeat)
        print(scorecard_markdown(rows))
        if args.markdown:
            with open(args.markdown, "w") as fh:
                fh.write(scorecard_markdown(rows) + "\n")
        if args.out:
            print(f"transcripts: {args.out}")
        return
    partial: list[RunResult] = []

    def keep(r: RunResult) -> None:
        partial.append(r)
        if args.out:
            write_json(args.out, [x.__dict__ for x in partial])
    results = evaluate(args.db, names, args.model, on_result=keep)
    model = Provider.from_env(args.model).model
    print(summarize(results, model))
    if args.out:
        write_json(args.out, [r.__dict__ for r in results])
        print(f"transcript: {args.out}")
    sys.exit(0 if all(r.score.get("pass") for r in results) else 1)


if __name__ == "__main__":
    main()
