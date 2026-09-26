"""Object-level AD reachability benchmark (the AD analogue of the KEV
multi-hop retrieval benchmark in `loom.retrieval_eval`).

`loom.connectors.ad_gen` plants known reachability chains in a synthetic
directory and buries them in benign noise; this harness loads that export
through the raw-LDAP connector and measures whether Loom's ordinary scope
walk **surfaces the full cited chain** and how much of the store it had to
sort through to do it. It computes no path *ranking* and emits no
exploitation guidance: for each chain the truth sidecar already names the
ordered edges, and the primary metric is simply "is every edge present in
the pack **with its citation**, and are the decoy dead-ends excludable".

    # generate -> import -> score, no LLM (the headline path)
    python -m loom.connectors.ad_gen --seed 7 --scale medium --out corp.ldif --truth corp.truth.json
    python -m loom.connectors.ldap import corp.ldif --namespace ad --db /data/ad.db
    python -m loom.ad_eval --db /data/ad.db --truth corp.truth.json --namespace ad

    # or do all three in one shot into a scratch store
    python -m loom.ad_eval --db /data/ad.db --generate --scale medium --seed 7

Scoring is done by a **scripted reader** (no network, no cost): it validates
each planted edge against the pack's cited observations, and for a decoy it
checks that the disqualifying fact (a non-transitive / SID-filtered trust,
or a disabled start account) is itself present and cited, so a reader has
the evidence to reject the dead-end. An optional `--live` smoke asks a cheap
model to assemble the chain on a few cases and confirms it cites it; the
headline stays scripted.

Metrics, per hop-length bucket and per budget: path-recall (chains fully
present + cited), edge-precision (edges in a "connects" verdict that belong
to a real chain), decoy-exclusion, whether the walk was truncated (D-058
scope cap / D-061 hub completion — a hub like a huge group), entities
gathered vs total in the store (the "sorted through this much" number),
build_pack latency p50/p95, and pack tokens.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .contracts import AskRequest, EntityRef, Observation, ScopeSpec
from .store.common import redact_dsn

BUDGETS = (1500, 3000, 4000)
CHAIN_PREDICATES = ("member_of", "has_ace", "trusts", "contains",
                    "can_delegate_to", "rbcd_from")
SCOPE_DEPTH_CAP = 3          # ScopeSpec.depth is capped at 3 (contract); a
                             # longer chain is walked in successive re-anchored
                             # asks, the way an agent follows a pack's reached
                             # entities
MAX_CALLS = 4
NODE_PROP_BUDGET = 800       # a per-principal node-properties ask: validating
                             # a candidate path means checking each account is
                             # enabled (a disabled account dead-ends it), which
                             # a subject-scoped ask surfaces where a broad
                             # path walk ranks it out


# --------------------------------------------------------------- ingest #

def load_ldif(store, ldif_text: str, namespace: str, source: str = "ad-export",
              batch: int = 1000) -> dict:
    """Import an LDIF export through the raw-LDAP connector into `store`,
    returning object stats and ingest timing/throughput."""
    from .connectors import ldap
    stats: dict[str, int] = {}
    t0 = time.monotonic()
    envs = ldap.ldif_to_envelopes(ldif_text, namespace, source, stats=stats)
    recorded = 0
    buf: list = []
    for env in envs:
        buf.append(env)
        if len(buf) >= batch:
            store.record_claims(buf)
            recorded += len(buf)
            buf = []
    if buf:
        store.record_claims(buf)
        recorded += len(buf)
    elapsed = time.monotonic() - t0
    return {"objects": stats.get("object", 0), "invalid": stats.get("invalid", 0),
            "observations": recorded, "seconds": round(elapsed, 3),
            "obs_per_sec": round(recorded / elapsed, 1) if elapsed else 0.0,
            "objects_per_sec": round(stats.get("object", 0) / elapsed, 1) if elapsed else 0.0}


# --------------------------------------------------------------- index #

def _obj_repr(obj) -> str:
    if isinstance(obj, EntityRef):
        return f"{obj.type}:{obj.key}"
    return str(obj)


def _obs_edge_key(obs: Observation) -> tuple:
    right = obs.attrs.get("right") if obs.predicate == "has_ace" else None
    return (obs.subject.type, obs.subject.key, obs.predicate, _obj_repr(obs.object), right)


def _truth_edge_key(edge: dict) -> tuple:
    s, o = edge["subject"], edge["object"]
    obj = f"{o['type']}:{o['key']}" if "type" in o else str(o["value"])
    return (s["type"], s["key"], edge["predicate"], obj, edge.get("right"))


@dataclass
class Index:
    """Everything the scripted reader needs about the loaded store: the
    observation id(s) backing each directed edge, the full observations by
    id (for a decoy's disqualifying attrs), and store-wide totals."""

    edge_ids: dict[tuple, list[str]]
    obs_by_id: dict[str, Observation]
    total_entities: int
    total_observations: int


def build_index(store, namespace: str) -> Index:
    edge_ids: dict[tuple, list[str]] = {}
    obs_by_id: dict[str, Observation] = {}
    n_obs = 0
    for obs in store.iter_observations(namespace):
        n_obs += 1
        obs_by_id[obs.id] = obs
        edge_ids.setdefault(_obs_edge_key(obs), []).append(obs.id)
    total_entities = sum(store.namespace_summary().get(namespace, {}).values())
    return Index(edge_ids, obs_by_id, total_entities, n_obs)


# --------------------------------------------------------------- packs #

def _ref(d: dict) -> EntityRef:
    return EntityRef(type=d["type"], key=d["key"])


def _cited_ids(pack) -> set[str]:
    out: set[str] = set()
    for item in pack.items:
        for c in item.citations:
            if c.observation_id:
                out.add(c.observation_id)
    return out


@dataclass
class WalkResult:
    cited: set[str]
    subjects: set[tuple[str, str]]
    build_ms: float
    tokens: int
    truncated: bool
    calls: int
    scope_calls: int = 0        # path-walk asks only (excludes node-property asks)


def build_chain_packs(store, namespace: str, record: dict, budget: int) -> WalkResult:
    """The scope pack(s) an agent would assemble for one planted item. A
    chain longer than the depth cap is walked in successive asks re-anchored
    at the deepest chain node the previous ask reached — what an agent does
    with the entities a pack surfaced. Everything is unioned and scored once."""
    from .context import build_pack
    edges = record["edges"]
    # ordered nodes: start, then each edge's object end
    nodes = [record["start"]] + [e["object"] for e in edges]
    expand = sorted({e["predicate"] for e in edges} | {"member_of"})
    start_lbl = f"{record['start']['type']}:{record['start']['key']}"
    tgt = record["target"]
    tgt_lbl = f"{tgt['type']}:{tgt['key']}"
    question = (f"what rights, trust and membership path connects {start_lbl} "
                f"to {tgt_lbl}?")
    cited: set[str] = set()
    subjects: set[tuple[str, str]] = set()
    total_ms = 0.0
    tokens = 0
    truncated = False
    calls = 0
    pos = 0
    while pos < len(edges) and calls < MAX_CALLS:
        depth = min(len(edges) - pos, SCOPE_DEPTH_CAP)
        anchor = _ref(nodes[pos])
        scope = ScopeSpec(subjects=[anchor], expand=expand, depth=depth)
        req = AskRequest(namespace=namespace, scope=scope, budget=budget, question=question)
        t0 = time.monotonic()
        pack = build_pack(store, req)
        total_ms += (time.monotonic() - t0) * 1000
        cited |= _cited_ids(pack)
        subjects |= {(s.type, s.key) for s in pack.subjects}
        tokens += pack.charged_tokens
        truncated = truncated or bool(pack.truncated)
        calls += 1
        pos += depth
    scope_calls = calls
    # node-viability: check the account status of each principal on the path,
    # the way a reader validates a lead (a disabled account dead-ends it). A
    # broad path walk ranks these scalars out; a subject-scoped ask surfaces
    # them. Groups / domains have no account status, so skip them.
    for node in nodes:
        if node["type"] not in ("user", "computer"):
            continue
        req = AskRequest(namespace=namespace, subject=_ref(node), budget=NODE_PROP_BUDGET,
                         question=f"account status of {node['type']}:{node['key']}: is it enabled? "
                                  "unconstrained delegation, no preauth, kerberoastable")
        t0 = time.monotonic()
        pack = build_pack(store, req)
        total_ms += (time.monotonic() - t0) * 1000
        cited |= _cited_ids(pack)
        subjects |= {(s.type, s.key) for s in pack.subjects}
        tokens += pack.charged_tokens
        truncated = truncated or bool(pack.truncated)
        calls += 1
    return WalkResult(cited, subjects, total_ms, tokens, truncated, calls, scope_calls)


# --------------------------------------------------------------- scoring #

def score_chain(record: dict, walk: WalkResult, index: Index) -> dict:
    """Per-edge present-and-cited, and the chain verdict: it connects only
    when every edge is present and cited (Loom carries the whole cited
    chain)."""
    edge_status = []
    for edge in record["edges"]:
        ids = index.edge_ids.get(_truth_edge_key(edge), [])
        present = any(oid in walk.cited for oid in ids)
        edge_status.append({"key": _truth_edge_key(edge), "present": present,
                            "cited_ids": [oid for oid in ids if oid in walk.cited]})
    full = all(e["present"] for e in edge_status) and bool(edge_status)
    return {"id": record["id"], "hops": record["hops"], "kind": "chain",
            "connects": full, "path_recovered": full, "edges": edge_status}


def _disqualifier_present(record: dict, walk: WalkResult, index: Index) -> bool:
    """Whether the decoy's dead-end fact is in the pack and cited: the trust
    attr (transitive False / sid_filtering True) on the cited trust edge, or
    the start account's `enabled == False`."""
    dq = record["disqualifier"]
    if "attr" in dq:
        edge = record["edges"][dq["edge_index"]]
        for oid in index.edge_ids.get(_truth_edge_key(edge), []):
            obs = index.obs_by_id.get(oid)
            if oid in walk.cited and obs is not None and obs.attrs.get(dq["attr"]) == dq["value"]:
                return True
        return False
    ref = dq["ref"]
    for oid in walk.cited:
        obs = index.obs_by_id.get(oid)
        if (obs is not None and obs.subject.type == ref["type"] and obs.subject.key == ref["key"]
                and obs.predicate == dq["predicate"] and obs.object == dq["value"]):
            return True
    return False


def score_decoy(record: dict, walk: WalkResult, index: Index) -> dict:
    """A correct answer must NOT report the decoy as connecting. The reader
    can only reject it if Loom surfaced the disqualifying fact, so that is
    what we measure; `apparent` says the rest of the path was present (it
    genuinely looked like a lead)."""
    present = []
    for edge in record["edges"]:
        ids = index.edge_ids.get(_truth_edge_key(edge), [])
        present.append(any(oid in walk.cited for oid in ids))
    apparent = all(present)
    disqualified = _disqualifier_present(record, walk, index)
    # the scripted reader connects a decoy only if the path is present AND it
    # never saw the disqualifier; excluded otherwise
    wrongly_connects = apparent and not disqualified
    return {"id": record["id"], "hops": len(record["edges"]), "kind": "decoy",
            "reason": record["reason"], "apparent": apparent,
            "disqualifier_cited": disqualified, "connects": wrongly_connects,
            "excluded": not wrongly_connects}


# --------------------------------------------------------------- run #

@dataclass
class Budgeted:
    budget: int
    chain_rows: list[dict] = field(default_factory=list)
    decoy_rows: list[dict] = field(default_factory=list)
    build_ms: list[float] = field(default_factory=list)
    tokens: list[int] = field(default_factory=list)
    gathered: list[int] = field(default_factory=list)
    truncated: int = 0
    calls: list[int] = field(default_factory=list)


def evaluate(store, namespace: str, truth: dict, budgets: tuple[int, ...],
             index: Index, progress=None) -> dict[int, Budgeted]:
    out: dict[int, Budgeted] = {}
    for budget in budgets:
        b = Budgeted(budget)
        for record in truth["chains"]:
            walk = build_chain_packs(store, namespace, record, budget)
            row = score_chain(record, walk, index)
            b.chain_rows.append(row)
            b.build_ms.append(walk.build_ms)
            b.tokens.append(walk.tokens)
            b.gathered.append(len(walk.subjects))
            b.calls.append(walk.calls)
            b.truncated += int(walk.truncated)
            if progress:
                progress(f"B={budget:<5} {record['id']:<22} "
                         f"{'RECOVERED' if row['connects'] else 'MISSING':<10} "
                         f"gathered {len(walk.subjects):>5}/{index.total_entities} "
                         f"{walk.tokens:>5}tok {walk.build_ms:.0f}ms")
        for record in truth["decoys"]:
            walk = build_chain_packs(store, namespace, record, budget)
            row = score_decoy(record, walk, index)
            b.decoy_rows.append(row)
            b.build_ms.append(walk.build_ms)
            b.tokens.append(walk.tokens)
            b.gathered.append(len(walk.subjects))
            b.calls.append(walk.calls)
            b.truncated += int(walk.truncated)
            if progress:
                progress(f"B={budget:<5} {record['id']:<22} "
                         f"{'EXCLUDED' if row['excluded'] else 'LEAKED':<10} "
                         f"disq_cited={row['disqualifier_cited']}")
        out[budget] = b
    return out


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, round(pct / 100 * (len(ordered) - 1))))
    return ordered[idx]


def _pct(part: int, whole: int) -> str:
    return f"{100 * part / whole:.0f}% ({part}/{whole})" if whole else "-"


def summarize(results: dict[int, Budgeted], index: Index) -> dict:
    buckets = sorted({r["hops"] for b in results.values() for r in b.chain_rows})
    per_budget = {}
    for budget, b in results.items():
        by_hop = {}
        for h in buckets:
            rows = [r for r in b.chain_rows if r["hops"] == h]
            recovered = sum(r["connects"] for r in rows)
            by_hop[h] = (recovered, len(rows))
        # edge-precision: of all edges in a "connects" verdict, the fraction
        # that belong to a genuine chain (decoys leaking in drop it)
        true_edges = sum(len(r["edges"]) for r in b.chain_rows if r["connects"])
        leaked = [r for r in b.decoy_rows if r["connects"]]
        # a leaked decoy contributes its edges as false positives
        leaked_edges = sum(r["hops"] for r in leaked)
        precision = true_edges / (true_edges + leaked_edges) if (true_edges + leaked_edges) else None
        by_reason: dict[str, tuple[int, int]] = {}
        for r in b.decoy_rows:
            ex, tot = by_reason.get(r["reason"], (0, 0))
            by_reason[r["reason"]] = (ex + int(r["excluded"]), tot + 1)
        per_budget[budget] = {
            "path_recall": {h: by_hop[h] for h in buckets},
            "path_recall_all": (sum(r["connects"] for r in b.chain_rows), len(b.chain_rows)),
            "edge_precision": precision,
            "decoy_excluded": (sum(r["excluded"] for r in b.decoy_rows), len(b.decoy_rows)),
            "decoy_by_reason": by_reason,
            "gathered_mean": statistics.mean(b.gathered) if b.gathered else 0.0,
            "gathered_max": max(b.gathered, default=0),
            "truncated": b.truncated,
            "calls_max": max(b.calls, default=0),
            "build_p50": _percentile(b.build_ms, 50),
            "build_p95": _percentile(b.build_ms, 95),
            "tokens_mean": statistics.mean(b.tokens) if b.tokens else 0.0,
        }
    return {"buckets": buckets, "per_budget": per_budget,
            "total_entities": index.total_entities, "total_observations": index.total_observations}


def markdown(summary: dict, meta: dict) -> str:
    buckets = summary["buckets"]
    lines = [f"# AD reachability benchmark — {meta.get('date', '')}", "",
             f"Synthetic, object-level only (no sessions / local-admin). Store: "
             f"`{meta.get('store', '?')}` · namespace: `{meta.get('namespace')}` · "
             f"scale: **{meta.get('scale', '?')}** · seed: {meta.get('seed', '?')}",
             ""]
    c = meta.get("counts", {})
    if c:
        lines += [f"Directory: {c.get('objects', '?')} objects "
                  f"({c.get('users', '?')} users / {c.get('groups', '?')} groups / "
                  f"{c.get('computers', '?')} computers, {c.get('dcs', '?')} DCs), "
                  f"{summary['total_observations']:,} observations, "
                  f"{summary['total_entities']:,} entities, "
                  f"{c.get('raw_membership_and_ace_edges', '?'):,} raw membership+ACL edges. "
                  f"Planted: {c.get('planted_chains')} chains + {c.get('decoys')} decoys "
                  f"(the signal is a small fraction of all edges).", ""]
    ing = meta.get("ingest")
    if ing:
        lines += [f"Ingest: {ing['observations']:,} observations from {ing['objects']:,} objects "
                  f"in {ing['seconds']}s = {ing['obs_per_sec']:,} obs/s "
                  f"({ing['objects_per_sec']:,} objects/s).", ""]
    hop_cols = " | ".join(f"{h}-hop recall" for h in buckets)
    lines += [f"| Budget | {hop_cols} | All recall | Edge precision | Decoy excluded | "
              "Entities gathered / total | Truncated | Build p50/p95 ms | Pack tokens |",
              "| --- |" + " --- |" * (len(buckets) + 7)]
    for budget in sorted(summary["per_budget"]):
        s = summary["per_budget"][budget]
        hop_cells = " | ".join(_pct(*s["path_recall"][h]) for h in buckets)
        prec = f"{100 * s['edge_precision']:.0f}%" if s["edge_precision"] is not None else "-"
        gathered = f"{s['gathered_mean']:.0f} / {summary['total_entities']:,}"
        lines.append(
            f"| {budget} | {hop_cells} | {_pct(*s['path_recall_all'])} | {prec} | "
            f"{_pct(*s['decoy_excluded'])} | {gathered} | {s['truncated']} | "
            f"{s['build_p50']:.0f} / {s['build_p95']:.0f} | {s['tokens_mean']:.0f} |")
    # decoy detail
    any_reason = next(iter(summary["per_budget"].values()))["decoy_by_reason"]
    if any_reason:
        lines += ["", "Decoy exclusion by dead-end kind (disqualifier surfaced + cited):", ""]
        lines.append("| Budget | " + " | ".join(sorted(any_reason)) + " |")
        lines.append("| --- |" + " --- |" * len(any_reason))
        for budget in sorted(summary["per_budget"]):
            reasons = summary["per_budget"][budget]["decoy_by_reason"]
            cells = " | ".join(_pct(*reasons[r]) for r in sorted(reasons))
            lines.append(f"| {budget} | {cells} |")
    if meta.get("live"):
        lines += ["", f"Live-reader smoke ({meta['live']['model']}): "
                  f"{meta['live']['passed']}/{meta['live']['n']} chains assembled + cited, "
                  f"spend ${meta['live']['cost']:.3f}."]
    lines += ["", "path-recall: planted chains whose every edge is present in the pack AND "
              "cited. edge-precision: of the edges in a 'connects' verdict, the fraction on a "
              "genuine chain (a decoy wrongly reported connecting drops it). decoy excluded: "
              "the dead-end's disqualifying fact (non-transitive / SID-filtered trust, or a "
              "disabled start account) was itself surfaced and cited, so a reader can reject "
              "it. entities gathered: the mean entities the scope walk pulled per chain, "
              "against the whole store. A 4-hop chain is walked in two re-anchored asks "
              "(ScopeSpec.depth caps at 3). Scripted reader: no LLM, so this measures "
              "retrieval alone."]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------- live smoke #

def live_smoke(store, namespace: str, truth: dict, index: Index, model_name: str | None,
               budget: int, max_cost: float, cases: int) -> dict:
    """A few chains through a cheap model: does it assemble + cite the chain?
    Reported, never the headline."""
    from .agent_eval import Provider, cite_tokens_in
    from .answer import SYSTEM_PROMPT
    from .context import build_pack
    from .retrieval_eval import LiveModel

    provider = Provider.from_env(model_name)
    model = LiveModel(provider)
    system = SYSTEM_PROMPT + ("\n\nReply in two lines:\nanswer: <does a path connect? name the "
                              "target>\ncites: <the bracketed cite tokens of the edges you relied "
                              "on>\nUse only the context; never answer from memory.")
    passed = 0
    spent = 0.0
    n = 0
    for record in truth["chains"][:cases]:
        walk = build_chain_packs(store, namespace, record, budget)
        # rebuild a single pack for the prompt (first ask); good enough for a smoke
        from .answer import render_user_prompt
        scope = ScopeSpec(subjects=[_ref(record["start"])],
                          expand=sorted({e["predicate"] for e in record["edges"]} | {"member_of"}),
                          depth=min(len(record["edges"]), SCOPE_DEPTH_CAP))
        pack = build_pack(store, AskRequest(namespace=namespace, scope=scope, budget=budget,
                                            question=f"path connecting {record['start']['key']} to "
                                                     f"{record['target']['key']}?"))
        prompt = render_user_prompt("Does a rights/trust/membership path connect the start to the "
                                    "target, and via which edges?", pack)
        try:
            reply, usage = model.answer(None, system, prompt)
        except Exception as exc:  # noqa: BLE001
            reply, usage = f"error: {exc}", {"cost": 0.0}
        spent += float(usage.get("cost") or 0.0)
        n += 1
        cites = set(cite_tokens_in(reply))
        chain_ids = {oid for e in record["edges"]
                     for oid in index.edge_ids.get(_truth_edge_key(e), []) if oid in walk.cited}
        cited_ok = any(any(oid.startswith(c) or c.startswith(oid) for c in cites) for oid in chain_ids)
        tgt = record["target"]["key"]
        if cited_ok and tgt.lower() in reply.lower():
            passed += 1
        if spent > max_cost:
            break
    return {"model": provider.model, "passed": passed, "n": n, "cost": spent}


# --------------------------------------------------------------------- CLI #

def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loom.ad_eval", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", help="explicit store URL/path (default: LOOM_DB)")
    parser.add_argument("--namespace", default="ad")
    parser.add_argument("--truth", help="the ad_gen truth sidecar JSON")
    parser.add_argument("--generate", action="store_true",
                        help="generate + import into the store first (uses --scale / --seed)")
    parser.add_argument("--scale", default="medium")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--budgets", default=",".join(str(b) for b in BUDGETS))
    parser.add_argument("--live", action="store_true", help="also run a cheap live-reader smoke")
    parser.add_argument("--model", help="override LOOM_LLM_MODEL for the live smoke")
    parser.add_argument("--live-cases", type=int, default=4)
    parser.add_argument("--max-cost", type=float, default=1.0)
    parser.add_argument("--out", help="Markdown report path (default eval/ad-<date>.md)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    from .store.factory import store_from_env, store_from_url
    store = store_from_url(args.db) if args.db else store_from_env()
    ingest = None
    try:
        if args.generate:
            from .connectors import ad_gen
            ldif, truth = ad_gen.generate(args.seed, args.scale)
            ingest = load_ldif(store, ldif, args.namespace)
        else:
            if not args.truth:
                raise SystemExit("give --truth (or --generate)")
            truth = json.loads(Path(args.truth).read_text())
        budgets = tuple(int(b) for b in args.budgets.split(",") if b.strip())
        index = build_index(store, args.namespace)
        if index.total_observations == 0:
            raise SystemExit(f"namespace {args.namespace!r} is empty — import the LDIF first "
                             "(or pass --generate)")
        progress = None if args.quiet else (lambda line: print(line, flush=True))
        results = evaluate(store, args.namespace, truth, budgets, index, progress)
        summary = summarize(results, index)
        meta = {"date": datetime.now(timezone.utc).date().isoformat(),
                "store": redact_dsn(args.db or os.environ.get("LOOM_DB", "loom.db")),
                "namespace": args.namespace, "scale": truth.get("scale", args.scale),
                "seed": truth.get("seed", args.seed), "counts": truth.get("counts", {}),
                "ingest": ingest}
        if args.live:
            meta["live"] = live_smoke(store, args.namespace, truth, index, args.model,
                                      max(budgets), args.max_cost, args.live_cases)
    finally:
        store.close()
    table = markdown(summary, meta)
    print("\n" + table)
    out = Path(args.out or f"eval/ad-{meta['date']}.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(table)
    print(f"report: {out}")


if __name__ == "__main__":
    main()
