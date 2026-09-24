"""Retrieval evaluation harness (hardening R-6): Loom's context packs
against the obvious alternatives, on the same store and the same questions.

`/v1/answer` and the agent harness (D-036) test whether a model can use
what Loom retrieves. This asks the prior question: is what Loom retrieves
better than *not* retrieving — than handing the model everything, or a
vector top-k, or the newest facts? Every condition renders its context the
way `answer.render_user_prompt` does, asks the same model the same
question, and is scored by the same rules:

  * ``loom@B``   a context pack at token budget B (400, 800, 1600, 3200)
  * ``full``     every observation about the question's entities — the
                 "just give it everything" baseline; its token count is
                 reported honestly and it is not sent past ``--full-cap``
  * ``vector``   the top-k observations by cosine similarity alone (needs an
                 embedder, LOOM_EMBED_*; skipped with a note otherwise)
  * ``recency``  the newest k observations (the trivial baseline)

Questions are *generated from the store* with a fixed seed, in six
families, each with ground truth computed from the observations (never
hard-coded, like `agent_eval`): a lease at time T (`valid_at` and `as_of`
variants — the knowledge-update case), conflict awareness, multi-hop
exposure (KEV CVEs reaching a host through runs_software -> affects when
the vulns corpus is loaded; alert -> host -> domain / users on the seed),
abstention (an entity or predicate that does not exist: the only right
answer is "unknown"), numeric lookup, and temporal ordering. The model
answers in a fixed two-line format so scoring is rule-based: there is no
LLM judge to disagree with.

    python -m loom.retrieval_eval --db /data/loom.db                    # live model from LOOM_LLM_*
    python -m loom.retrieval_eval --db /data/loom.db --scripted         # rule-based reader, no network
    python -m loom.retrieval_eval --db ... --runs 3 --budgets 400,1600 --families lease,abstention
    python -m loom.retrieval_eval --db ... --list-questions             # what would be asked, with truth

Output: a Markdown scorecard (conditions x metrics, then conditions x
families), printed and written to ``--out`` (default eval/retrieval-<date>.md).
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import statistics
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from .agent_eval import Provider, _cited
from .answer import SYSTEM_PROMPT, render_user_prompt
from .context import (_aware, _citation, _render_fact, build_pack, cosines,
                      covers_valid_at, resolve_scope)
from .contracts import AskRequest, ContextItem, ContextPack, EntityRef, Observation, ScopeSpec
from .llm import _post_json, embedder_from_env

BUDGETS = (400, 800, 1600, 3200)
FAMILIES = ("lease", "conflict", "multihop", "abstention", "numeric", "order")
CONDITIONS = ("loom", "full", "vector", "recency")
DEFAULT_K = 20                 # items for the vector / recency baselines
DEFAULT_FULL_CAP = 100_000     # a `full` context above this (est. tokens) is measured, not sent
DEFAULT_MAX_COST = 1.0         # USD; live calls stop past this when the provider reports cost
_POOL = 400                    # entities sampled per type when generating questions
_EMBED_ON_THE_FLY = 2_000      # unembedded candidates the vector baseline embeds itself, per question
_GATHER_ALL = 100_000
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_NUMBER = re.compile(r"-?\d+(?:\.\d+)?")
_MISSING_PREDICATES = ("serial_number", "rack_location", "purchase_price", "warranty_expiry")

FORMAT_RULES = (
    "\n\nReply with exactly two lines and nothing else:\n"
    "answer: <value>\n"
    "cites: <the bracketed cite tokens of the items you relied on, comma-separated, or none>\n"
    "Value rules: an entity as type:key; a number as plain digits; several values "
    "comma-separated; when the context shows sources disagreeing about the asked value, "
    "write `conflicting: value1 | value2`; when the context does not contain the answer, "
    "write exactly `unknown`. Never answer from memory."
)
SYSTEM = SYSTEM_PROMPT + FORMAT_RULES


# -------------------------------------------------------------- questions #

@dataclass
class Question:
    id: str
    family: str
    text: str
    namespace: str
    kind: str                                  # entity | ids | conflict | number | unknown | order
    truth: Any                                 # str | list[str] | float | None | "A"/"B"
    truth_ids: list[str]                       # observation ids that ground the answer
    subject: EntityRef | None = None
    scope: ScopeSpec | None = None
    as_of: datetime | None = None
    valid_at: datetime | None = None
    probe: dict = field(default_factory=dict)  # what the scripted reader looks for
    reject: list[str] = field(default_factory=list)   # entities that are a WRONG answer (lease history)

    def ask(self, budget: int) -> AskRequest:
        return AskRequest(namespace=self.namespace, subject=self.subject, scope=self.scope,
                          question=self.text, budget=budget, as_of=self.as_of, valid_at=self.valid_at)

    def roots(self) -> list[EntityRef]:
        return list(self.scope.subjects) if self.scope is not None else [self.subject]


def _ref(t: str, k: str) -> str:
    return f"{t}:{k}"


def _obs(store, ns: str, ref: EntityRef, before: datetime | None = None) -> list[Observation]:
    return store.observations_for(ns, ref, limit=_GATHER_ALL, observed_before=before)


def _scalar(o: Observation) -> bool:
    return not isinstance(o.object, EntityRef)


def _numeric(o: Observation) -> bool:
    return isinstance(o.object, (int, float)) and not isinstance(o.object, bool)


def _pool(store, ns: str, etype: str, rng: random.Random, n: int) -> list[EntityRef]:
    """A deterministic sample of entities of one type: the first _POOL by
    key, then `n` of them by the seeded rng (a spread over a 40k-CVE type
    rather than the lexically first forty)."""
    found = store.search_entities(ns, "", limit=_POOL, types=(etype,))
    refs = sorted((EntityRef(type=e.type, key=e.key) for e in found), key=lambda r: r.key)
    if len(refs) <= n:
        return refs
    return sorted(rng.sample(refs, n), key=lambda r: r.key)


def _fmt_date(dt: datetime) -> str:
    return _aware(dt).date().isoformat()


# ---- family 1: lease at T ---------------------------------------------- #

def _lease_questions(store, ns: str, rng: random.Random, cap: int) -> list[Question]:
    out: list[Question] = []
    ips = _pool(store, ns, "ip", rng, 40)
    # reassigned addresses first: the knowledge-update case is what matters
    scored = []
    for ip in ips:
        leases = [o for o in _obs(store, ns, ip)
                  if o.predicate == "assigned_to" and isinstance(o.object, EntityRef) and o.valid_from]
        if leases:
            scored.append((-len(leases), ip.key, ip, leases))
    for _, _, ip, leases in sorted(scored, key=lambda t: t[:2])[:max(1, cap // 4)]:
        holders = {o.object.key.lower() for o in leases}
        for lease in sorted(leases, key=lambda o: _aware(o.valid_from)):
            start = _aware(lease.valid_from)
            t = (start + (_aware(lease.valid_to) - start) / 2 if lease.valid_to
                 else start + timedelta(days=10)).replace(hour=0, minute=0, second=0, microsecond=0)
            covering = [o for o in leases if covers_valid_at(o, t)]
            if len({o.object.key for o in covering}) != 1:
                continue  # a T with two or no holders has no single crisp answer
            holder = covering[0].object.key
            known = [o for o in leases if _aware(o.observed_at) <= t]
            known_covering = [o for o in known if covers_valid_at(o, t)]
            as_of_truth = (known_covering or sorted(known, key=lambda o: _aware(o.observed_at))[-1:])
            date = t.date().isoformat()
            out.append(Question(
                id=f"lease:{ip.key}@{date}:valid_at", family="lease", namespace=ns,
                text=f"Which host held the address {_ref(ip.type, ip.key)} on {date}? "
                     "Answer with the host as host:<key>.",
                kind="entity", truth=holder, truth_ids=[o.id for o in covering],
                subject=ip, valid_at=t, reject=sorted(holders - {holder.lower()}),
                probe={"subject": _ref(ip.type, ip.key), "predicate": "assigned_to",
                       "at": t.isoformat(), "mode": "valid_at"}))
            if as_of_truth:
                truth = as_of_truth[0].object.key
                out.append(Question(
                    id=f"lease:{ip.key}@{date}:as_of", family="lease", namespace=ns,
                    text=f"Using only what was known by {date}: which host was the address "
                         f"{_ref(ip.type, ip.key)} assigned to on that day? Answer with the host as host:<key>.",
                    kind="entity", truth=truth, truth_ids=[o.id for o in as_of_truth],
                    subject=ip, as_of=t, reject=sorted(holders - {truth.lower()}),
                    probe={"subject": _ref(ip.type, ip.key), "predicate": "assigned_to",
                           "at": t.isoformat(), "mode": "as_of"}))
    return out[:cap]


# ---- family 2: conflict awareness -------------------------------------- #

def _conflicts_of(store, ns: str, ref: EntityRef) -> dict[str, dict[str, Observation]]:
    """predicate -> {value: newest observation}, for the scalar predicates of
    `ref` where two or more sources currently disagree (mirrors
    context._find_conflicts: closed validity windows are history)."""
    now = datetime.now(timezone.utc)
    by_pred: dict[str, dict[str, Observation]] = {}
    for o in _obs(store, ns, ref):
        if o.subject != ref or not _scalar(o):
            continue
        if o.valid_to is not None and _aware(o.valid_to) <= now:
            continue
        by_pred.setdefault(o.predicate, {}).setdefault(str(o.object), o)
    return {p: v for p, v in by_pred.items()
            if len(v) >= 2 and len({o.source for o in v.values()}) >= 2}


def _candidates(store, ns: str, rng: random.Random, per_type: int = 40) -> list[EntityRef]:
    summary = store.namespace_summary().get(ns, {})
    refs: list[EntityRef] = []
    for etype in sorted(summary):
        refs.extend(_pool(store, ns, etype, rng, per_type))
    return refs


def _conflict_questions(store, ns: str, rng: random.Random, cap: int,
                        candidates: list[EntityRef]) -> list[Question]:
    out: list[Question] = []
    for ref in candidates:
        for pred, by_value in sorted(_conflicts_of(store, ns, ref).items()):
            values = sorted(by_value)
            out.append(Question(
                id=f"conflict:{ref.type}:{ref.key}:{pred}", family="conflict", namespace=ns,
                text=f"What is the {pred} of {_ref(ref.type, ref.key)}? If sources disagree, "
                     "say so and give every value.",
                kind="conflict", truth=values, truth_ids=[by_value[v].id for v in values],
                subject=ref, probe={"subject": _ref(ref.type, ref.key), "predicate": pred}))
            if len(out) >= cap:
                return out
    return out


# ---- family 3: multi-hop ----------------------------------------------- #

def _has_vulns(store, ns: str) -> bool:
    summary = store.namespace_summary().get(ns, {})
    if "cve" not in summary or "product" not in summary:
        return False
    return any(o.predicate == "runs_software"
               for h in _pool(store, ns, "host", random.Random(0), 20)
               for o in _obs(store, ns, h))


def _kev_exposure(store, ns: str, host: EntityRef) -> tuple[list[str], dict[str, Observation]]:
    """KEV-listed CVEs affecting a product the host runs (agent_eval's
    truth, for any host): product keys, and cve -> its KEV observation."""
    products = sorted({o.object.key for o in _obs(store, ns, host)
                       if o.predicate == "runs_software" and isinstance(o.object, EntityRef)})
    cves: set[str] = set()
    for key in products:
        for o in _obs(store, ns, EntityRef(type="product", key=key)):
            if o.predicate == "affects":
                cves.add(o.subject.key)
    kev: dict[str, Observation] = {}
    for cve in sorted(cves):
        for o in _obs(store, ns, EntityRef(type="cve", key=cve)):
            if o.predicate == "exploited_in_wild" and o.object is True:
                kev[cve] = o
                break
    return products, kev


def _multihop_questions(store, ns: str, rng: random.Random, cap: int) -> list[Question]:
    out: list[Question] = []
    if _has_vulns(store, ns):
        for host in _pool(store, ns, "host", rng, 40):
            products, kev = _kev_exposure(store, ns, host)
            if not kev:
                continue
            out.append(Question(
                id=f"multihop:kev:{host.key}", family="multihop", namespace=ns,
                text=f"Which CVEs that CISA lists as exploited in the wild affect software that "
                     f"{_ref(host.type, host.key)} runs? List every CVE id.",
                kind="ids", truth=sorted(kev), truth_ids=[kev[c].id for c in sorted(kev)],
                scope=ScopeSpec(subjects=[host], expand=["runs_software", "affects"], depth=2),
                probe={"predicate": "exploited_in_wild", "object": "True", "collect": "subject",
                       "id_regex": _CVE.pattern}))
            if len(out) >= cap:
                break
        return out
    # the seed corpus: alert -> host -> domain, and alert -> host -> the users of that day
    for alert in _pool(store, ns, "alert", rng, 20):
        fired = [o for o in _obs(store, ns, alert)
                 if o.predicate == "triggered_on" and isinstance(o.object, EntityRef)]
        if not fired:
            continue
        hop = fired[0]
        host = hop.object
        host_obs = _obs(store, ns, host)
        domains = [o for o in host_obs if o.predicate == "member_of" and isinstance(o.object, EntityRef)]
        if domains:
            out.append(Question(
                id=f"multihop:domain:{alert.key}", family="multihop", namespace=ns,
                text=f"Which domain is the host that {_ref(alert.type, alert.key)} triggered on a member "
                     "of? Answer with the domain as domain:<key>.",
                kind="entity", truth=domains[0].object.key, truth_ids=[hop.id, domains[0].id],
                scope=ScopeSpec(subjects=[alert], expand=["triggered_on", "member_of"], depth=2),
                probe={"predicate": "member_of", "collect": "object"}))
        day = _fmt_date(hop.observed_at)
        logins = [o for o in host_obs if o.predicate == "logged_in_by"
                  and isinstance(o.object, EntityRef) and _fmt_date(o.observed_at) == day]
        if logins:
            users = sorted({o.object.key for o in logins})
            out.append(Question(
                id=f"multihop:logins:{alert.key}", family="multihop", namespace=ns,
                text=f"Which users logged in to the host that {_ref(alert.type, alert.key)} triggered on, "
                     f"on {day}? List every user as user:<key>.",
                kind="ids", truth=users, truth_ids=[o.id for o in logins],
                scope=ScopeSpec(subjects=[alert], expand=["triggered_on", "logged_in_by"], depth=2),
                probe={"subject": _ref(host.type, host.key), "predicate": "logged_in_by",
                       "date": day, "collect": "object"}))
        if len(out) >= cap:
            break
    return out[:cap]


# ---- family 4: abstention ---------------------------------------------- #

def _abstention_questions(store, ns: str, rng: random.Random, cap: int,
                          candidates: list[EntityRef]) -> list[Question]:
    out: list[Question] = []
    summary = store.namespace_summary().get(ns, {})
    # (a) entities that do not exist, shaped like ones that do
    for etype in sorted(summary):
        if len(out) >= cap // 2:
            break
        sample = _pool(store, ns, etype, rng, 1)
        if not sample:
            continue
        key = sample[0].key
        for suffix in ("-zz9", "-99x", "-000"):
            fake = re.sub(r"[-_.]?[0-9]+$", "", key) + suffix if re.search(r"[0-9]", key) else key + suffix
            if store.get_entity(ns, EntityRef(type=etype, key=fake)) is None:
                break
        else:
            continue
        preds = sorted({o.predicate for o in _obs(store, ns, sample[0]) if o.subject == sample[0]})
        pred = rng.choice(preds) if preds else "status"
        ref = EntityRef(type=etype, key=fake)
        out.append(Question(
            id=f"abstention:entity:{etype}:{fake}", family="abstention", namespace=ns,
            text=f"What is the {pred} of {_ref(etype, fake)}?", kind="unknown", truth=None, truth_ids=[],
            subject=ref, probe={"subject": _ref(etype, fake), "predicate": pred}))
    # (b) predicates nobody ever recorded, on entities that do exist
    known_preds = {o.predicate for ref in candidates[:60] for o in _obs(store, ns, ref)}
    reg = store.get_schema(ns)
    if reg is not None:
        known_preds |= {p.name for p in reg.predicates}
    missing = [p for p in _MISSING_PREDICATES if p not in known_preds]
    for ref in candidates:
        if len(out) >= cap or not missing:
            break
        if not any(o.subject == ref for o in _obs(store, ns, ref)):
            continue
        pred = missing[len(out) % len(missing)]
        out.append(Question(
            id=f"abstention:predicate:{ref.type}:{ref.key}:{pred}", family="abstention", namespace=ns,
            text=f"What is the {pred} of {_ref(ref.type, ref.key)}?", kind="unknown", truth=None,
            truth_ids=[], subject=ref, probe={"subject": _ref(ref.type, ref.key), "predicate": pred}))
    return out[:cap]


# ---- family 5: numeric lookup ------------------------------------------ #

def _numeric_questions(store, ns: str, rng: random.Random, cap: int,
                       candidates: list[EntityRef]) -> list[Question]:
    out: list[Question] = []
    for ref in candidates:
        mine = [o for o in _obs(store, ns, ref) if o.subject == ref and _numeric(o)]
        by_pred: dict[str, list[Observation]] = {}
        for o in mine:
            by_pred.setdefault(o.predicate, []).append(o)
        for pred, obs in sorted(by_pred.items()):
            values = {float(o.object) for o in obs}
            sources = {o.source for o in obs}
            label = _ref(ref.type, ref.key)
            if len(values) == 1 and len(sources) == 1:
                out.append(Question(
                    id=f"numeric:{ref.type}:{ref.key}:{pred}", family="numeric", namespace=ns,
                    text=f"What is the {pred} of {label}? Answer with the number.",
                    kind="number", truth=float(obs[0].object), truth_ids=[obs[0].id], subject=ref,
                    probe={"subject": label, "predicate": pred, "agg": "single"}))
            elif len(sources) >= 2 and len(values) >= 2:
                src = sorted(sources)[0]
                newest = sorted((o for o in obs if o.source == src), key=lambda o: _aware(o.observed_at))[-1]
                out.append(Question(
                    id=f"numeric:{ref.type}:{ref.key}:{pred}@{src}", family="numeric", namespace=ns,
                    text=f"What {pred} did the source '{src}' report for {label}? Answer with the number.",
                    kind="number", truth=float(newest.object), truth_ids=[newest.id], subject=ref,
                    probe={"subject": label, "predicate": pred, "source": src, "agg": "single"}))
            elif len(sources) == 1 and len(values) >= 3:
                top = max(obs, key=lambda o: float(o.object))
                out.append(Question(
                    id=f"numeric:{ref.type}:{ref.key}:max-{pred}", family="numeric", namespace=ns,
                    text=f"What is the largest {pred} ever recorded for {label}? Answer with the number.",
                    kind="number", truth=float(top.object), truth_ids=[top.id], subject=ref,
                    probe={"subject": label, "predicate": pred, "agg": "max"}))
            else:
                continue
            if len(out) >= cap:
                return out
    return out


# ---- family 6: temporal ordering --------------------------------------- #

def _order_questions(store, ns: str, rng: random.Random, cap: int,
                     candidates: list[EntityRef]) -> list[Question]:
    out: list[Question] = []
    for ref in candidates:
        obs = _obs(store, ns, ref)
        # facts that render uniquely (one observation per subject/predicate/object)
        rendered: dict[str, list[Observation]] = {}
        for o in obs:
            rendered.setdefault(_render_fact(o).split(" (")[0], []).append(o)
        unique = sorted((k, v[0]) for k, v in rendered.items() if len(v) == 1)
        if len(unique) < 2:
            continue
        pairs = [(a, b) for i, (_, a) in enumerate(unique) for _, b in unique[i + 1:]
                 if a.predicate != b.predicate
                 and abs((_aware(a.observed_at) - _aware(b.observed_at)).days) >= 2]
        if not pairs:
            continue
        a, b = rng.choice(pairs)
        if rng.random() < 0.5:
            a, b = b, a
        first = "A" if _aware(a.observed_at) < _aware(b.observed_at) else "B"
        la, lb = _render_fact(a).split(" (")[0], _render_fact(b).split(" (")[0]
        out.append(Question(
            id=f"order:{ref.type}:{ref.key}:{a.predicate}-vs-{b.predicate}", family="order", namespace=ns,
            text=f"About {_ref(ref.type, ref.key)}: which of these was observed first — "
                 f"(A) {la}, per {a.source}; or (B) {lb}, per {b.source}? Answer A or B.",
            kind="order", truth=first, truth_ids=[a.id, b.id], subject=ref,
            probe={"a": la, "b": lb}))
        if len(out) >= cap:
            break
    return out


def generate_questions(store, namespaces: list[str], seed: int = 7, per_family: int = 8,
                       families: list[str] | None = None) -> list[Question]:
    """Every family over every namespace, deterministic for (store, seed).
    `per_family` caps each family per namespace."""
    wanted = [f for f in FAMILIES if not families or f in families]
    out: list[Question] = []
    for ns in namespaces:
        rng = random.Random(f"{seed}:{ns}")
        candidates = _candidates(store, ns, rng)
        for fam in wanted:
            if fam == "lease":
                out.extend(_lease_questions(store, ns, rng, per_family))
            elif fam == "conflict":
                out.extend(_conflict_questions(store, ns, rng, per_family, candidates))
            elif fam == "multihop":
                out.extend(_multihop_questions(store, ns, rng, per_family))
            elif fam == "abstention":
                out.extend(_abstention_questions(store, ns, rng, max(2, per_family // 2), candidates))
            elif fam == "numeric":
                out.extend(_numeric_questions(store, ns, rng, per_family, candidates))
            elif fam == "order":
                out.extend(_order_questions(store, ns, rng, per_family, candidates))
    seen: set[str] = set()
    unique = []
    for q in out:
        if q.id not in seen:
            seen.add(q.id)
            unique.append(q)
    return unique


# ------------------------------------------------------------- conditions #

@dataclass
class Context:
    condition: str
    prompt: str
    cite_ids: set[str]           # every observation / artifact id the context carries
    tokens_est: int
    build_ms: float
    items: int
    note: str = ""               # why it was skipped, when it was


def est_prompt_tokens(text: str) -> int:
    """The same chars/4 estimate the pack builder budgets with, over the
    whole rendered prompt. The provider's own count sits beside it in the
    table when the model reports usage."""
    return max(1, len(text) // 4)


def _pack_ids(pack: ContextPack) -> set[str]:
    ids: set[str] = set()
    for item in pack.items:
        for c in item.citations:
            ids.add(c.observation_id or c.artifact_id)
    return ids


def _synthetic_pack(q: Question, observations: list[Observation]) -> ContextPack:
    items = [ContextItem(kind="fact", text=_render_fact(o), score=1.0, citations=[_citation(o)])
             for o in observations]
    return ContextPack(namespace=q.namespace, subjects=q.roots(), question=q.text,
                       budget=max(1, sum(est_prompt_tokens(i.text) for i in items) + 1), items=items)


def candidate_observations(store, q: Question) -> list[Observation]:
    """Everything about the question's entities: the subject, or every
    entity the scope reaches (no time axis applied — the baselines get the
    whole history and must read the dates themselves). Newest first."""
    if q.scope is not None:
        refs = resolve_scope(store, q.namespace, q.scope)
    else:
        refs = [q.subject]
    got = store.observations_for_many(q.namespace, refs, limit=_GATHER_ALL)
    seen: set[str] = set()
    out: list[Observation] = []
    for ref in refs:
        for o in got.get((ref.type, ref.key), []):
            if o.id not in seen:
                seen.add(o.id)
                out.append(o)
    out.sort(key=lambda o: _aware(o.observed_at), reverse=True)
    return out


def _vectors(store, q: Question, observations: list[Observation], embedder) -> dict[str, list[float]]:
    ids = [o.id for o in observations]
    have = store.embeddings_for(q.namespace, ids, embedder.model) if ids else {}
    missing = [o for o in observations if o.id not in have][:_EMBED_ON_THE_FLY]
    for start in range(0, len(missing), 128):
        chunk = missing[start:start + 128]
        for o, vec in zip(chunk, embedder.embed([_render_fact(o) for o in chunk])):
            have[o.id] = vec
    return have


def build_context(store, q: Question, condition: str, embedder=None, k: int = DEFAULT_K,
                  full_cap: int = DEFAULT_FULL_CAP) -> Context:
    t0 = time.monotonic()
    if condition.startswith("loom@"):
        budget = int(condition.split("@", 1)[1])
        pack = build_pack(store, q.ask(budget), embedder=embedder)
        prompt = render_user_prompt(q.text, pack)
        return Context(condition, prompt, _pack_ids(pack), est_prompt_tokens(prompt),
                       (time.monotonic() - t0) * 1000, len(pack.items))
    observations = candidate_observations(store, q)
    note = ""
    if condition == "full":
        chosen = observations
    elif condition == "recency":
        chosen = observations[:k]
    elif condition == "vector":
        if embedder is None:
            return Context(condition, "", set(), 0, 0.0, 0, note="skipped: no embedder (LOOM_EMBED_*)")
        vectors = _vectors(store, q, observations, embedder)
        query = embedder.embed_query(q.text) if hasattr(embedder, "embed_query") else embedder.embed([q.text])[0]
        sims = cosines(query, vectors)
        chosen = sorted((o for o in observations if o.id in sims), key=lambda o: -sims[o.id])[:k]
        if len(vectors) < len(observations):
            note = f"{len(observations) - len(vectors)} candidates had no vector"
    else:
        raise ValueError(f"unknown condition {condition!r}")
    pack = _synthetic_pack(q, chosen)
    prompt = render_user_prompt(q.text, pack)
    tokens = est_prompt_tokens(prompt)
    if condition == "full" and tokens > full_cap:
        note = f"not sent: {tokens:,} tokens exceeds --full-cap {full_cap:,}"
    return Context(condition, prompt, _pack_ids(pack), tokens, (time.monotonic() - t0) * 1000,
                   len(chosen), note)


def condition_names(budgets: tuple[int, ...] | list[int], conditions: list[str] | None = None) -> list[str]:
    wanted = conditions or list(CONDITIONS)
    names: list[str] = []
    for c in wanted:
        if c == "loom":
            names.extend(f"loom@{b}" for b in budgets)
        else:
            names.append(c)
    return names


# ----------------------------------------------------------------- models #

class LiveModel:
    """One system+user completion per question through the configured
    provider (LOOM_LLM_*, any OpenAI-compatible endpoint or Anthropic);
    OpenRouter is asked to report the billed cost per call (D-037)."""

    def __init__(self, provider: Provider, max_tokens: int = 300):
        self.provider = provider
        self.max_tokens = max_tokens
        self.model = provider.model

    def answer(self, q: Question, system: str, prompt: str) -> tuple[str, dict]:
        p = self.provider
        if p.kind == "openai":
            headers = {"authorization": f"Bearer {p.api_key}"} if p.api_key else {}
            body: dict = {"model": p.model, "max_tokens": self.max_tokens, "messages": [
                {"role": "system", "content": system}, {"role": "user", "content": prompt}]}
            if "openrouter.ai" in p.base_url:
                body["usage"] = {"include": True}
            data = _post_json(p.base_url + "/chat/completions", body, headers, timeout=180)
            msg = data["choices"][0]["message"]
            content = msg.get("content") or ""
            if isinstance(content, list):
                content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
            u = data.get("usage") or {}
            return str(content), {"in": int(u.get("prompt_tokens") or 0), "out": int(u.get("completion_tokens") or 0),
                                  "cost": float(u.get("cost") or 0.0)}
        data = _post_json(p.base_url + "/v1/messages", {
            "model": p.model, "max_tokens": self.max_tokens, "system": system,
            "messages": [{"role": "user", "content": prompt}]},
            {"x-api-key": p.api_key or "", "anthropic-version": "2023-06-01"}, timeout=180)
        text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        u = data.get("usage") or {}
        return text, {"in": int(u.get("input_tokens") or 0), "out": int(u.get("output_tokens") or 0), "cost": 0.0}


class CannedModel:
    """Answers from a map of question id -> reply text; anything unmapped
    is `unknown`. What CI feeds through the whole pipeline."""

    model = "canned"

    def __init__(self, answers: dict[str, str]):
        self.answers = dict(answers)

    def answer(self, q: Question, system: str, prompt: str) -> tuple[str, dict]:
        text = self.answers.get(q.id, "answer: unknown\ncites: none")
        return text, {"in": est_prompt_tokens(prompt), "out": est_prompt_tokens(text), "cost": 0.0}


_LINE = re.compile(r"^- \((\w+)\) (.*) \[([^\]]*)\]$")
_FACT = re.compile(r"^(\S+) (\S+) (.+?) \((\d{4}-\d{2}-\d{2}), per ([^)]+)\)(?: \[valid (\S+) to (\S+)\])?$")
_SAYS = re.compile(r"(\S+) says '([^']*)'")


@dataclass
class _Line:
    kind: str
    subject: str
    predicate: str
    object: str
    observed: str
    source: str
    valid_from: str | None
    valid_to: str | None
    cites: list[str]
    raw: str


def parse_context(prompt: str) -> list[_Line]:
    """The rendered items of a prompt, one parsed line each (conflict items
    keep their raw text; the reader mines the `says` clauses)."""
    out: list[_Line] = []
    for raw in prompt.splitlines():
        m = _LINE.match(raw)
        if not m:
            continue
        kind, text, cites = m.groups()
        cite_list = [c.strip() for c in cites.split(",") if c.strip() and not c.strip().startswith("+")]
        f = _FACT.match(text)
        if f:
            s, p, o, d, src, vf, vt = f.groups()
            out.append(_Line(kind, s, p, o, d, src, vf, vt, cite_list, text))
        else:
            out.append(_Line(kind, "", "", text, "", "", None, None, cite_list, text))
    return out


def _window_covers(line: _Line, at: datetime) -> bool:
    day = at.date().isoformat()
    lo = line.valid_from if line.valid_from and line.valid_from != "?" else None
    hi = line.valid_to if line.valid_to and line.valid_to != "present" else None
    return (lo is None or lo <= day) and (hi is None or day < hi)


class ScriptedReader:
    """A rule-based reader: answers from the rendered context exactly when
    the evidence is in it, `unknown` otherwise, and cites the lines it used.
    No network, no memory, no guessing — so its accuracy measures retrieval
    alone (did the context carry the answer?) and a live model's score
    minus this one is the reading cost."""

    model = "scripted-reader"

    def answer(self, q: Question, system: str, prompt: str) -> tuple[str, dict]:
        value, cites = self._read(q, parse_context(prompt))
        text = f"answer: {value}\ncites: {', '.join(cites) if cites else 'none'}"
        return text, {"in": est_prompt_tokens(prompt), "out": est_prompt_tokens(text), "cost": 0.0}

    def _read(self, q: Question, lines: list[_Line]) -> tuple[str, list[str]]:
        value, cites = self._answer(q, lines)
        if q.scope is not None and value != "unknown":
            # a multi-hop answer stands on the chain it was reached through:
            # cite the edges of the walk too (relation items, and the same
            # edges when they render as facts about a root), as an honest
            # reader would
            edges = set(q.scope.expand)
            chain = [c for ln in lines if ln.kind == "relation" or ln.predicate in edges for c in ln.cites]
            cites = sorted(set(cites) | set(chain))
        return value, cites

    def _answer(self, q: Question, lines: list[_Line]) -> tuple[str, list[str]]:
        probe = q.probe
        facts = [ln for ln in lines if ln.predicate]
        if q.kind == "entity" and probe.get("mode"):
            at = datetime.fromisoformat(probe["at"])
            mine = [ln for ln in facts if ln.subject == probe["subject"] and ln.predicate == probe["predicate"]]
            if probe["mode"] == "as_of":
                mine = [ln for ln in mine if ln.observed <= at.date().isoformat()]
                covering = [ln for ln in mine if _window_covers(ln, at)]
                mine = covering or sorted(mine, key=lambda ln: ln.observed)[-1:]
            else:
                mine = [ln for ln in mine if _window_covers(ln, at)]
            return (mine[0].object, mine[0].cites) if mine else ("unknown", [])
        if q.kind == "entity":
            mine = [ln for ln in facts if ln.predicate == probe["predicate"]]
            return (mine[0].object, mine[0].cites) if mine else ("unknown", [])
        if q.kind == "ids":
            mine = [ln for ln in facts if ln.predicate == probe["predicate"]
                    and (not probe.get("subject") or ln.subject == probe["subject"])
                    and (not probe.get("object") or ln.object == probe["object"])
                    and (not probe.get("date") or ln.observed == probe["date"])]
            got = sorted({ln.subject if probe["collect"] == "subject" else ln.object for ln in mine})
            cites = sorted({c for ln in mine for c in ln.cites})
            return (", ".join(got), cites) if got else ("unknown", [])
        if q.kind == "conflict":
            values: dict[str, list[str]] = {}
            for ln in lines:
                if ln.predicate == probe["predicate"] and ln.subject == probe["subject"]:
                    if ln.valid_to and ln.valid_to != "present":
                        continue  # history, not a competing claim
                    values.setdefault(ln.object, []).extend(ln.cites)
                elif ln.kind == "conflict" and ln.raw.startswith(f"CONFLICT on {probe['subject']} {probe['predicate']}:"):
                    for _, v in _SAYS.findall(ln.raw):
                        values.setdefault(v, []).extend(ln.cites)
            cites = sorted({c for cs in values.values() for c in cs})
            if len(values) >= 2:
                return "conflicting: " + " | ".join(sorted(values)), cites
            return (next(iter(values)), cites) if values else ("unknown", [])
        if q.kind == "number":
            mine = [ln for ln in facts if ln.subject == probe["subject"] and ln.predicate == probe["predicate"]
                    and (not probe.get("source") or ln.source == probe["source"])]
            nums = [(float(ln.object), ln) for ln in mine if _NUMBER.fullmatch(ln.object)]
            if not nums:
                return "unknown", []
            if probe.get("agg") == "max":
                best = max(nums, key=lambda t: t[0])
                return f"{best[0]:.10g}", sorted({c for _, ln in nums for c in ln.cites})
            newest = max(nums, key=lambda t: t[1].observed)
            return f"{newest[0]:.10g}", newest[1].cites
        if q.kind == "unknown":
            mine = [ln for ln in facts if ln.subject == probe["subject"] and ln.predicate == probe["predicate"]]
            return (mine[0].object, mine[0].cites) if mine else ("unknown", [])
        if q.kind == "order":
            a = next((ln for ln in facts if ln.raw.startswith(probe["a"] + " (")), None)
            b = next((ln for ln in facts if ln.raw.startswith(probe["b"] + " (")), None)
            if a is None or b is None:
                return "unknown", []
            return ("A" if a.observed <= b.observed else "B"), a.cites + b.cites
        return "unknown", []


# ---------------------------------------------------------------- scoring #

_UNKNOWN = ("unknown", "notknown", "insufficient", "cannot", "none", "notincontext", "nodata")


def _loose(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _strip_type(value: str) -> str:
    return value.split(":", 1)[1] if re.match(r"^[a-z_]+:", value) else value


def parse_answer(text: str) -> tuple[str, list[str]]:
    """The `answer:` value and the cite tokens (from the `cites:` line when
    there is one, else anywhere in the reply)."""
    value = ""
    cites_line = None
    for line in text.splitlines():
        low = line.strip().lower()
        if low.startswith("answer:") and not value:
            value = line.strip()[7:].strip()
        elif low.startswith("cites:"):
            cites_line = line.strip()[6:]
    if not value:
        value = text.strip().splitlines()[0].strip() if text.strip() else ""
    source = cites_line if cites_line is not None else text
    cites = sorted(set(re.findall(r"\b[0-9a-f]{8,32}\b", source)))
    return value, cites


def _is_unknown(value: str) -> bool:
    loose = _loose(value)
    return loose == "" or any(loose.startswith(u) for u in _UNKNOWN)


def score(q: Question, reply: str, ctx: Context) -> dict:
    value, cites = parse_answer(reply)
    unknown = _is_unknown(value)
    detail: dict[str, Any] = {"value": value[:120], "abstained": unknown, "hallucinated": False}
    if q.kind == "unknown":
        ok = unknown
        detail["hallucinated"] = not unknown
    elif unknown:
        ok = False
    elif q.kind == "entity":
        low = _loose(value)
        ok = _loose(_strip_type(str(q.truth))) in low
        wrong = [r for r in q.reject if _loose(r) in low]
        detail["rejected"] = wrong
        ok = ok and not wrong
    elif q.kind == "ids":
        if q.probe.get("id_regex"):
            found = re.findall(q.probe["id_regex"], value)
        else:
            found = [t for t in re.split(r"[,\s]+", value) if t]
        got = {_loose(_strip_type(m)) for m in found}
        truth = {_loose(_strip_type(t)) for t in q.truth}
        hits = got & truth
        detail.update(precision=round(len(hits) / len(got), 3) if got else 0.0,
                      recall=round(len(hits) / len(truth), 3) if truth else 0.0)
        ok = got == truth
    elif q.kind == "conflict":
        named = [v for v in q.truth if _loose(v) in _loose(value)]
        detail["values_named"] = named
        ok = len(named) == len(q.truth) or "conflict" in value.lower()
    elif q.kind == "number":
        nums = _NUMBER.findall(value.replace(",", ""))
        got = float(nums[0]) if nums else None
        ok = got is not None and abs(got - float(q.truth)) <= 0.005   # half a cent, half a hundredth of a score
    elif q.kind == "order":
        ok = _loose(value)[:1] == q.truth.lower()
    else:
        ok = False
    truth_ids = set(q.truth_ids)
    cited_support = all(any(cid.startswith(c) or c.startswith(cid) for c in cites) for cid in truth_ids)
    unseen = _cited(" ".join(f"[{c}]" for c in cites), ctx.cite_ids)["citations_unseen"]
    detail.update(
        pass_=bool(ok), cites=len(cites), cites_unseen=unseen,
        support_pack=truth_ids <= ctx.cite_ids if truth_ids else None,
        support_answer=(cited_support and bool(cites)) if truth_ids else None,
    )
    return detail


# -------------------------------------------------------------------- run #

@dataclass
class Record:
    run: int
    question: str
    family: str
    condition: str
    reply: str
    tokens_est: int
    tokens_provider: int | None
    build_ms: float
    cost: float
    score: dict
    note: str = ""


def evaluate(store, questions: list[Question], model, conditions: list[str], embedder=None,
             k: int = DEFAULT_K, full_cap: int = DEFAULT_FULL_CAP, runs: int = 1,
             max_cost: float = DEFAULT_MAX_COST, progress: Callable[[str], None] | None = None) -> list[Record]:
    records: list[Record] = []
    spent = 0.0
    for run in range(max(1, runs)):
        for q in questions:
            for cond in conditions:
                ctx = build_context(store, q, cond, embedder, k, full_cap)
                note = ctx.note
                reply, usage = "", {"in": None, "out": 0, "cost": 0.0}
                if note.startswith("skipped") or note.startswith("not sent"):
                    pass
                elif spent > max_cost:
                    note = f"not sent: spend ${spent:.2f} exceeded --max-cost ${max_cost:.2f}"
                else:
                    try:
                        reply, usage = model.answer(q, SYSTEM, ctx.prompt)
                    except Exception as exc:  # noqa: BLE001 — one bad call must not sink the table
                        note = f"error: {type(exc).__name__}: {str(exc)[:120]}"
                        usage = {"in": None, "out": 0, "cost": 0.0}
                spent += float(usage.get("cost") or 0.0)
                s = score(q, reply, ctx)
                if note and not reply:
                    s["pass_"] = False
                    s["abstained"] = False
                    s["hallucinated"] = False
                    s["support_answer"] = None
                records.append(Record(run, q.id, q.family, cond, reply, ctx.tokens_est,
                                      usage.get("in") if isinstance(model, LiveModel) else None,
                                      round(ctx.build_ms, 2), float(usage.get("cost") or 0.0), s, note))
                if progress:
                    progress(f"run {run + 1} {cond:<10} {q.id:<50} {'PASS' if s['pass_'] else 'FAIL'}"
                             f" {ctx.tokens_est:>7} tok  {note}")
    return records


# ---------------------------------------------------------------- summary #

def _pct(part: int, whole: int) -> str:
    return f"{100 * part / whole:.0f}% ({part}/{whole})" if whole else "-"


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, round(pct / 100 * (len(ordered) - 1))))
    return ordered[idx]


def summarize(records: list[Record], conditions: list[str]) -> dict[str, dict]:
    """Per condition: accuracy (overall, per family, per run), tokens,
    latency, citation support, hallucinations, cost."""
    out: dict[str, dict] = {}
    for cond in conditions:
        rs = [r for r in records if r.condition == cond]
        if not rs:
            continue
        if all(r.note.startswith("skipped") for r in rs):
            out[cond] = {"skipped": rs[0].note, "n": len(rs), "notes": [rs[0].note], "families": {}}
            continue
        runs = sorted({r.run for r in rs})
        per_run = [sum(r.score["pass_"] for r in rs if r.run == n) / max(1, sum(1 for r in rs if r.run == n))
                   for n in runs]
        families: dict[str, tuple[int, int]] = {}
        for fam in FAMILIES:
            fr = [r for r in rs if r.family == fam]
            if fr:
                families[fam] = (sum(r.score["pass_"] for r in fr), len(fr))
        sent = [r for r in rs if not r.note]
        provider = [r.tokens_provider for r in rs if r.tokens_provider]
        abst = [r for r in rs if r.family == "abstention"]
        others = [r for r in rs if r.family != "abstention" and not r.note]
        supp_p = [r for r in rs if r.score.get("support_pack") is not None]
        supp_a = [r for r in rs if r.score.get("support_answer") is not None]
        out[cond] = {
            "n": len(rs), "passed": sum(r.score["pass_"] for r in rs),
            "accuracy": sum(r.score["pass_"] for r in rs) / len(rs),
            "accuracy_runs": per_run,
            "accuracy_stdev": statistics.stdev(per_run) if len(per_run) > 1 else 0.0,
            "families": families,
            "tokens_est": statistics.mean(r.tokens_est for r in rs),
            "tokens_est_max": max(r.tokens_est for r in rs),
            "tokens_provider": statistics.mean(provider) if provider else None,
            "build_p50": _percentile([r.build_ms for r in rs], 50),
            "build_p95": _percentile([r.build_ms for r in rs], 95),
            "support_pack": (sum(r.score["support_pack"] for r in supp_p), len(supp_p)),
            "support_answer": (sum(r.score["support_answer"] for r in supp_a), len(supp_a)),
            "unseen": (sum(1 for r in sent if r.score["cites_unseen"]), len(sent)),
            "hallucinated": (sum(r.score["hallucinated"] for r in abst), len(abst)),
            "abstained": (sum(r.score["abstained"] for r in others), len(others)),
            "cost": sum(r.cost for r in rs),
            "not_sent": sum(1 for r in rs if r.note),
            "notes": sorted({r.note for r in rs if r.note}),
        }
    return out


def markdown(summary: dict[str, dict], meta: dict) -> str:
    runs = meta.get("runs", 1)
    lines = [f"# Retrieval evaluation — {meta.get('date', '')}", "",
             f"Store: `{meta.get('store', '?')}` · namespaces: {', '.join(meta.get('namespaces', []))} · "
             f"model: `{meta.get('model', '?')}` · embedder: {meta.get('embedder') or 'none'} · "
             f"questions: {meta.get('questions', 0)} ({meta.get('per_family', '')}) · runs: {runs} · "
             f"k: {meta.get('k', DEFAULT_K)} · seed: {meta.get('seed', '')}", ""]
    acc_head = "Accuracy" + (f" (mean ± sd over {runs} runs)" if runs > 1 else "")
    lines.append(f"| Condition | {acc_head} | Tokens est (mean / max) | Tokens provider | Build p50 / p95 ms | "
                 "Support@pack | Support@answer | Unseen cites | Hallucinated (abstention) | "
                 "Abstained (other) | Cost |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for cond, s in summary.items():
        if "skipped" in s:
            lines.append(f"| `{cond}` | {s['skipped']} |" + " - |" * 9)
            continue
        acc = f"{100 * s['accuracy']:.0f}% ({s['passed']}/{s['n']})"
        if runs > 1:
            acc = f"{100 * statistics.mean(s['accuracy_runs']):.0f}% ± {100 * s['accuracy_stdev']:.0f}"
        prov = f"{s['tokens_provider']:,.0f}" if s["tokens_provider"] else "-"
        cost = f"${s['cost']:.3f}" if s["cost"] else "-"
        lines.append(
            f"| `{cond}` | {acc} | {s['tokens_est']:,.0f} / {s['tokens_est_max']:,} | {prov} | "
            f"{s['build_p50']:.0f} / {s['build_p95']:.0f} | {_pct(*s['support_pack'])} | "
            f"{_pct(*s['support_answer'])} | {_pct(*s['unseen'])} | {_pct(*s['hallucinated'])} | "
            f"{_pct(*s['abstained'])} | {cost} |")
    fams = [f for f in FAMILIES if any(f in s["families"] for s in summary.values())]
    lines += ["", "| Condition | " + " | ".join(fams) + " |", "| --- |" + " --- |" * len(fams)]
    for cond, s in summary.items():
        cells = []
        for f in fams:
            p, n = s["families"].get(f, (0, 0))
            cells.append(_pct(p, n) if n else "-")
        lines.append(f"| `{cond}` | " + " | ".join(cells) + " |")
    notes = sorted({n for s in summary.values() for n in s["notes"]})
    if notes:
        lines += ["", "Notes:"] + [f"- {n}" for n in notes]
    lines += ["", "Support@pack: the ground-truth observation ids were among the context's citations. "
              "Support@answer: the model cited them. Unseen cites: replies citing an id the context "
              "did not carry. Hallucinated: an abstention question answered with anything but "
              "`unknown`. Abstained: a non-abstention question answered `unknown`. Tokens est is "
              "chars/4 over the rendered prompt; tokens provider is the model's own prompt count."]
    return "\n".join(lines) + "\n"


def describe(questions: list[Question]) -> str:
    lines = []
    for q in questions:
        axis = f" valid_at={q.valid_at.date()}" if q.valid_at else (f" as_of={q.as_of.date()}" if q.as_of else "")
        lines.append(f"{q.id}\n    {q.text}\n    truth={q.truth!r}{axis} ids={[i[:12] for i in q.truth_ids]}")
    return "\n".join(lines)


def _family_counts(questions: list[Question]) -> str:
    counts = {f: sum(1 for q in questions if q.family == f) for f in FAMILIES}
    return ", ".join(f"{f} {n}" for f, n in counts.items() if n)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loom.retrieval_eval", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", help="explicit store URL/path (default: LOOM_DB and friends)")
    parser.add_argument("--namespaces", help="comma-separated (default: every namespace with data)")
    parser.add_argument("--model", help="override LOOM_LLM_MODEL")
    parser.add_argument("--scripted", action="store_true", help="the rule-based reader instead of a model (no network)")
    parser.add_argument("--canned", help="JSON file of question id -> reply; unmapped questions answer unknown")
    parser.add_argument("--budgets", default=",".join(str(b) for b in BUDGETS))
    parser.add_argument("--conditions", default=",".join(CONDITIONS), help="subset of " + ",".join(CONDITIONS))
    parser.add_argument("--families", help="subset of " + ",".join(FAMILIES))
    parser.add_argument("--per-family", type=int, default=8, help="questions per family per namespace")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--k", type=int, default=DEFAULT_K, help="items for the vector / recency baselines")
    parser.add_argument("--full-cap", type=int, default=DEFAULT_FULL_CAP,
                        help="a full context above this many estimated tokens is measured but not sent")
    parser.add_argument("--max-cost", type=float, default=DEFAULT_MAX_COST, help="USD ceiling for live calls")
    parser.add_argument("--max-tokens", type=int, default=300, help="completion cap per answer")
    parser.add_argument("--runs", type=int, default=1, help="repeat everything N times; report variance")
    parser.add_argument("--out", help="Markdown scorecard path (default eval/retrieval-<date>.md)")
    parser.add_argument("--json", help="also write every record here")
    parser.add_argument("--list-questions", action="store_true", help="print the generated questions and exit")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    from .store.factory import store_from_env, store_from_url
    store = store_from_url(args.db) if args.db else store_from_env()
    try:
        namespaces = ([n.strip() for n in args.namespaces.split(",") if n.strip()] if args.namespaces
                      else sorted(store.namespace_summary()))
        families = [f.strip() for f in args.families.split(",")] if args.families else None
        questions = generate_questions(store, namespaces, args.seed, args.per_family, families)
        if args.list_questions:
            print(describe(questions))
            print(f"\n{len(questions)} questions ({_family_counts(questions)})")
            return
        if not questions:
            raise SystemExit("no questions could be generated from this store (is it seeded?)")
        budgets = tuple(int(b) for b in args.budgets.split(",") if b.strip())
        conditions = condition_names(budgets, [c.strip() for c in args.conditions.split(",") if c.strip()])
        if args.canned:
            with open(args.canned) as fh:
                model = CannedModel(json.load(fh))
        elif args.scripted:
            model = ScriptedReader()
        else:
            model = LiveModel(Provider.from_env(args.model), args.max_tokens)
        embedder = embedder_from_env()
        progress = None if args.quiet else (lambda line: print(line, flush=True))
        records = evaluate(store, questions, model, conditions, embedder, args.k, args.full_cap,
                           args.runs, args.max_cost, progress)
    finally:
        store.close()
    summary = summarize(records, conditions)
    meta = {"date": datetime.now(timezone.utc).date().isoformat(), "store": args.db or os.environ.get("LOOM_DB", "loom.db"),
            "namespaces": namespaces, "model": model.model, "embedder": getattr(embedder, "model", None),
            "questions": len(questions), "per_family": _family_counts(questions), "runs": args.runs,
            "k": args.k, "seed": args.seed}
    table = markdown(summary, meta)
    print("\n" + table)
    out = Path(args.out or f"eval/retrieval-{meta['date']}.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(table)
    print(f"scorecard: {out}")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"meta": meta, "questions": [q.__dict__ for q in questions],
                       "records": [r.__dict__ for r in records]}, fh, indent=2, default=str)
        print(f"records: {args.json}")


if __name__ == "__main__":
    main()
