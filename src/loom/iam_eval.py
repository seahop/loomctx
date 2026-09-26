"""Scale check for the identity connectors (Entra ID D-075, Okta D-076).

    python -m loom.iam_eval --db /data/iam.db --generate --scale medium --seed 7
    python -m loom.iam_eval --db postgresql://... --data-dir /data/iam --no-load \\
        --engine-url http://loom:8000 --key ...

Generates (or reads) `loom.connectors.iam_gen` exports, imports both into one
shared namespace, and checks against the generator's truth:

  * **edge fidelity** — every relational edge the export implies is stored
    once, with the right subject/object types (missing = a silent drop, e.g.
    an event-id collision; extra = a mistyped or invented edge);
  * **idempotent re-import** — importing the same export again adds nothing;
  * **planted paths** — find_path over the path's own predicates, and a blind
    scope walk from the start over the generic identity predicate set at the
    depth cap, each scored on every planted edge coming back cited;
  * **hub pressure** — scope walks from random users through groups that
    hold every user ("All Staff" / "Everyone"): latency and truncation;
  * **cross-IdP overlap** — mail values present from both exports (the
    resolution candidates; the merge itself is the adjudicator's job).

With `--no-load` it verifies a store something else loaded (e.g. the
connectors' `import --url` through a gateway). `--engine-url` also times
find_path / ask over HTTP against a running engine. Scripted; no LLM.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import resource
import statistics
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .contracts import AskRequest, EntityRef, PathRequest, ScopeSpec
from .store.common import redact_dsn

GENERIC_PREDICATES = ["member_of", "has_role", "owner_of", "has_app_role",
                      "assigned_to", "has_permission", "reports_to"]
SOURCES = {"entra": "entra-export", "okta": "okta-export"}
HUB_PROBES = 40


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, round(p / 100 * (len(ordered) - 1)))]


def _envelopes(kind: str, text: str, namespace: str, as_of: datetime, stats: dict):
    from .connectors import entra, okta
    fn = entra.entra_to_envelopes if kind == "entra" else okta.okta_to_envelopes
    return fn(text, namespace, SOURCES[kind], as_of=as_of, stats=stats)


def event_id_conflicts(envs: list) -> int:
    """Envelopes whose event_id another envelope in the same export already
    used with different content — the store keeps the first, drops the rest."""
    seen: dict[str, str] = {}
    conflicts = 0
    for e in envs:
        body = e.model_dump_json(exclude={"event_id"})
        prev = seen.setdefault(e.event_id, body)
        if prev != body:
            conflicts += 1
    return conflicts


def visible_observations(store, namespace: str) -> int:
    return sum(row[-1] for row in store.relation_summary(namespace))


def load(store, envs: list, batch: int = 1000) -> dict:
    """Through the consumer's batch path — the registry check a real import
    (engine, gateway queue or `import --db`) applies — not raw record_claims."""
    from .consumer import handle_batch
    from .registry import RegistryCache
    registry = RegistryCache(store)
    totals = {"accepted": 0, "skipped": 0, "rejected": 0}
    t0 = time.monotonic()
    for i in range(0, len(envs), batch):
        counts = handle_batch(store, [e.model_dump_json(exclude_none=True).encode()
                                      for e in envs[i:i + batch]], registry)
        for k in totals:
            totals[k] += counts.get(k, 0)
    elapsed = time.monotonic() - t0
    return {"envelopes": len(envs), "seconds": round(elapsed, 2),
            "obs_per_sec": round(len(envs) / elapsed, 1) if elapsed else 0.0, **totals}


def stored_edges(store, namespace: str) -> dict[str, set[tuple]]:
    out: dict[str, set[tuple]] = {src: set() for src in SOURCES.values()}
    for obs in store.iter_observations(namespace):
        if isinstance(obs.object, EntityRef) and obs.source in out:
            out[obs.source].add((obs.subject.type, obs.subject.key, obs.predicate,
                                 obs.object.type, obs.object.key))
    return out


def fidelity(truth_edges: list[list], got: set[tuple]) -> dict:
    want = {tuple(e) for e in truth_edges}
    preds = sorted({e[2] for e in want} | {e[2] for e in got})
    rows = {}
    for p in preds:
        w = {e for e in want if e[2] == p}
        g = {e for e in got if e[2] == p}
        rows[p] = {"expected": len(w), "stored": len(g), "missing": len(w - g),
                   "extra": len(g - w),
                   "missing_sample": [list(x) for x in sorted(w - g)[:3]],
                   "extra_sample": [list(x) for x in sorted(g - w)[:3]]}
    return rows


def _edge_ids(store, namespace: str, edge: dict) -> set[str]:
    s, o = edge["subject"], edge["object"]
    ref = EntityRef(type=s["type"], key=s["key"])
    return {obs.id for obs in store.observations_for(namespace, ref, limit=5000)
            if obs.subject == ref and obs.predicate == edge["predicate"]
            and isinstance(obs.object, EntityRef)
            and (obs.object.type, obs.object.key) == (o["type"], o["key"])}


def check_path(store, namespace: str, path: dict, budget: int) -> dict:
    from .context import build_pack, find_paths
    start = EntityRef(**path["start"])
    target = EntityRef(**path["target"])
    edge_ids = [_edge_ids(store, namespace, e) for e in path["edges"]]

    t0 = time.monotonic()
    fp = find_paths(store, PathRequest(namespace=namespace, to=target, via=path["via"],
                                       depth=len(path["edges"]), max_paths=8, budget=budget,
                                       **{"from": start}))
    fp_ms = (time.monotonic() - t0) * 1000
    fp_cited = {e.cite.observation_id for p in fp.paths for e in p}

    t0 = time.monotonic()
    pack = build_pack(store, AskRequest(
        namespace=namespace, budget=budget,
        question=f"what path connects {start.type}:{start.key} to {target.type}:{target.key}?",
        scope=ScopeSpec(subjects=[start], expand=GENERIC_PREDICATES,
                        depth=min(3, len(path["edges"])))))
    ask_ms = (time.monotonic() - t0) * 1000
    ask_cited = {c.observation_id for i in pack.items for c in i.citations if c.observation_id}

    return {"name": path["name"], "hops": len(path["edges"]),
            "edges_stored": all(edge_ids),
            "find_path": bool(edge_ids) and all(ids & fp_cited for ids in edge_ids),
            "find_path_ms": round(fp_ms, 1), "find_path_truncated": bool(fp.truncated),
            "blind_ask": bool(edge_ids) and all(ids & ask_cited for ids in edge_ids),
            "blind_ask_target_reached": (target.type, target.key)
            in {(s.type, s.key) for s in pack.subjects},
            "blind_ask_ms": round(ask_ms, 1), "blind_ask_tokens": pack.charged_tokens,
            "blind_ask_truncated": [t.reason for t in pack.truncated]}


def hub_probe(store, namespace: str, users: list[str], budget: int, depth: int) -> dict:
    from .context import build_pack
    from collections import Counter
    ms, truncated, gathered, reasons = [], 0, [], Counter()
    for key in users:
        t0 = time.monotonic()
        pack = build_pack(store, AskRequest(
            namespace=namespace, budget=budget, question="what groups, roles and apps?",
            scope=ScopeSpec(subjects=[EntityRef(type="user", key=key)],
                            expand=GENERIC_PREDICATES, depth=depth)))
        ms.append((time.monotonic() - t0) * 1000)
        truncated += bool(pack.truncated)
        reasons.update({t.reason for t in pack.truncated})
        gathered.append(len(pack.subjects))
    return {"depth": depth, "n": len(users), "p50_ms": round(_pct(ms, 50), 1),
            "p95_ms": round(_pct(ms, 95), 1), "max_ms": round(max(ms, default=0), 1),
            "truncated": truncated, "reasons": dict(reasons),
            "gathered_mean": round(statistics.mean(gathered), 1)}


def shared_mail(store, namespace: str) -> int:
    by_src: dict[str, set[str]] = {src: set() for src in SOURCES.values()}
    for obs in store.iter_observations(namespace):
        if obs.predicate == "mail" and obs.source in by_src and isinstance(obs.object, str):
            by_src[obs.source].add(obs.object.lower())
    a, b = by_src.values()
    return len(a & b)


def http_timings(url: str, key: str | None, namespace: str, paths: list[dict],
                 budget: int) -> list[dict]:
    def post(route: str, body: dict) -> tuple[dict, float]:
        req = urllib.request.Request(url.rstrip("/") + route, data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json",
                                              **({"X-Loom-Key": key} if key else {})})
        t0 = time.monotonic()
        with urllib.request.urlopen(req, timeout=60) as resp:
            out = json.loads(resp.read())
        return out, (time.monotonic() - t0) * 1000

    rows = []
    for p in paths:
        body, fp_ms = post("/v1/path", {"namespace": namespace, "from": p["start"],
                                        "to": p["target"], "via": p["via"],
                                        "depth": len(p["edges"]), "budget": budget})
        ask, ask_ms = post("/v1/ask", {"namespace": namespace, "budget": budget,
                                       "question": "what path connects these?",
                                       "scope": {"subjects": [p["start"]],
                                                 "expand": GENERIC_PREDICATES,
                                                 "depth": min(3, len(p["edges"]))}})
        rows.append({"name": p["name"], "path_found": bool(body.get("paths")),
                     "path_ms": round(fp_ms, 1), "ask_ms": round(ask_ms, 1),
                     "ask_items": len(ask.get("items", []))})
    return rows


def markdown(r: dict) -> str:
    L = [f"# IAM connector scale check — {r['date']}", "",
         f"Store `{r['store']}` · namespace `{r['namespace']}` · scale **{r['scale']}** · "
         f"seed {r['seed']}", ""]
    c = r["counts"]
    L += [f"Entra: {c['entra_users']:,} users, {c['entra_groups']:,} groups. "
          f"Okta: {c['okta_users']:,} users, {c['okta_groups']:,} groups. "
          f"Store after load: {r['observations']:,} observations.", ""]
    if r.get("ingest"):
        L += ["| Export | Envelopes | Rejected | Empty objects | Event-id conflicts | Seconds | "
              "obs/s | Re-import adds |", "| --- | --- | --- | --- | --- | --- | --- | --- |"]
        for k, v in r["ingest"].items():
            L.append(f"| {k} | {v['envelopes']:,} | {v['rejected']:,} | "
                     f"{v.get('empty_objects', '-')} | {v['conflicts']:,} | "
                     f"{v['seconds']} | {v['obs_per_sec']:,} | {v.get('reimport_added', '-')} |")
        L.append("")
    L += ["## Edge fidelity (stored vs implied by the export)", "",
          "| Export | Predicate | Expected | Stored | Missing | Extra |",
          "| --- | --- | --- | --- | --- | --- |"]
    for k, rows in r["fidelity"].items():
        for p, v in rows.items():
            L.append(f"| {k} | {p} | {v['expected']:,} | {v['stored']:,} | "
                     f"{v['missing']:,} | {v['extra']:,} |")
    L += ["", "## Planted paths", "",
          "| Path | Hops | Edges stored | find_path cited | ms | Blind ask cited | "
          "Target reached | ms | Tokens | Truncated |",
          "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for p in r["paths"]:
        L.append(f"| {p['name']} | {p['hops']} | {p['edges_stored']} | {p['find_path']} | "
                 f"{p['find_path_ms']} | {p['blind_ask']} | {p['blind_ask_target_reached']} | "
                 f"{p['blind_ask_ms']} | {p['blind_ask_tokens']} | "
                 f"{','.join(p['blind_ask_truncated']) or '-'} |")
    L += ["", "## Hub pressure (scope walks from random users, generic predicates)", "",
          "| Depth | Probes | p50 ms | p95 ms | max ms | Truncated (reasons) | Entities gathered |",
          "| --- | --- | --- | --- | --- | --- | --- |"]
    for h in r["hubs"]:
        L.append(f"| {h['depth']} | {h['n']} | {h['p50_ms']} | {h['p95_ms']} | {h['max_ms']} | "
                 f"{h['truncated']} ({', '.join(f'{k} {v}' for k, v in h['reasons'].items()) or '-'}) | "
                 f"{h['gathered_mean']} |")
    L += ["", f"Cross-IdP: {r['shared_mail']:,} mail values present from both exports "
          f"(generator planted {r['truth_shared_mail']:,}).",
          f"Peak RSS: {r['peak_rss_mb']} MB."]
    if r.get("http"):
        L += ["", "## Over HTTP", "", "| Path | find_path found | /v1/path ms | /v1/ask ms |",
              "| --- | --- | --- | --- |"]
        for h in r["http"]:
            L.append(f"| {h['name']} | {h['path_found']} | {h['path_ms']} | {h['ask_ms']} |")
    return "\n".join(L) + "\n"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loom.iam_eval", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", help="store URL/path (default: LOOM_DB)")
    parser.add_argument("--namespace", default="iam")
    parser.add_argument("--generate", action="store_true")
    parser.add_argument("--data-dir", help="read entra.json / okta.json / truth.json from here")
    parser.add_argument("--scale", default="medium")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--no-load", action="store_true",
                        help="verify a store something else already loaded")
    parser.add_argument("--budget", type=int, default=4000)
    parser.add_argument("--engine-url")
    parser.add_argument("--key", default=os.environ.get("LOOM_API_KEY"), type=str.strip)
    parser.add_argument("--out", help="Markdown report path")
    args = parser.parse_args(argv)

    if args.generate:
        from .connectors import iam_gen
        entra_doc, okta_doc, truth = iam_gen.generate(args.seed, args.scale)
        texts = {"entra": json.dumps(entra_doc), "okta": json.dumps(okta_doc)}
        del entra_doc, okta_doc
    elif args.data_dir:
        d = Path(args.data_dir)
        texts = {k: (d / f"{k}.json").read_text() for k in SOURCES}
        truth = json.loads((d / "truth.json").read_text())
    else:
        raise SystemExit("give --generate or --data-dir")
    as_of = datetime.fromisoformat(truth["export_date"].replace("Z", "+00:00"))

    from .connectors import entra, okta
    from .store.factory import store_from_env, store_from_url
    store = store_from_url(args.db) if args.db else store_from_env()
    report: dict = {"date": datetime.now(timezone.utc).date().isoformat(),
                    "store": redact_dsn(args.db or os.environ.get("LOOM_DB", "loom.db")),
                    "namespace": args.namespace, "scale": truth["scale"], "seed": truth["seed"],
                    "counts": truth["counts"], "truth_shared_mail": truth["shared_mail"]}
    try:
        if not args.no_load:
            report["ingest"] = {}
            for kind in SOURCES:
                store.put_schema((entra if kind == "entra" else okta).schema(args.namespace))
                stats: dict = {}
                envs = list(_envelopes(kind, texts[kind], args.namespace, as_of, stats))
                row = load(store, envs)
                row["conflicts"] = event_id_conflicts(envs)
                row["objects"] = stats.get("object", 0)
                row["skipped_objects"] = stats.get("skipped", 0)
                row["empty_objects"] = stats.get("empty", 0)
                before = visible_observations(store, args.namespace)
                load(store, envs)
                row["reimport_added"] = visible_observations(store, args.namespace) - before
                report["ingest"][kind] = row
                print(f"{kind}: {row}", flush=True)
                del envs
            # the nightly refresh with both jobs overlapping: both register,
            # then both import a next-day export (a predicate the two declare
            # differently would reject one side here)
            nxt = as_of + timedelta(days=1)
            store.put_schema(entra.schema(args.namespace))
            store.put_schema(okta.schema(args.namespace))
            for kind in SOURCES:
                envs = list(_envelopes(kind, texts[kind], args.namespace, nxt, {}))
                row = load(store, envs)
                report["ingest"][f"{kind} (next-day refresh)"] = {**row, "conflicts": 0}
                print(f"{kind} refresh: {row}", flush=True)
                del envs
        report["observations"] = visible_observations(store, args.namespace)
        got = stored_edges(store, args.namespace)
        report["fidelity"] = {k: fidelity(truth[f"{k}_edges"], got[SOURCES[k]])
                              for k in SOURCES}
        del got
        report["paths"] = [check_path(store, args.namespace, p, args.budget)
                           for p in truth["paths"]]
        rng = random.Random(args.seed)
        entra_users = sorted({e[1] for e in truth["entra_edges"] if e[0] == "user"})
        okta_users = sorted({e[1] for e in truth["okta_edges"] if e[0] == "user"})
        sample = (rng.sample(entra_users, HUB_PROBES // 2)
                  + rng.sample(okta_users, HUB_PROBES // 2))
        report["hubs"] = [hub_probe(store, args.namespace, sample, args.budget, d)
                          for d in (1, 2, 3)]
        report["shared_mail"] = shared_mail(store, args.namespace)
        if args.engine_url:
            report["http"] = http_timings(args.engine_url, args.key, args.namespace,
                                          truth["paths"], args.budget)
    finally:
        store.close()
    report["peak_rss_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024)
    md = markdown(report)
    print("\n" + md)
    out = Path(args.out or f"eval/iam-{truth['scale']}-{report['date']}.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md)
    out.with_suffix(".json").write_text(json.dumps(report, indent=2, default=str))
    print(f"report: {out}")


if __name__ == "__main__":
    main()
