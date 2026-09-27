"""Scale check for identity resolution, host artifacts, coverage, drift and
purple correlation together (D-082…D-086), on `loom.connectors.estate_gen`.

    python -m loom.estate_eval --db /data/estate.db --generate --scale medium
    python -m loom.estate_eval --db postgresql://... --data-dir /data/estate --no-load

Loads the estate (or verifies one loaded through the gateway), runs the
identity tier, and checks against the generator's truth:
  * every machine's directory object and scanned host fold into one
    entity; no second-domain twin folds into its first-domain namesake
    (a shared short hostname is weak) and no reassigned address merges
  * process-list accounts fold into the directory's users
  * the tasklist hosts' missing parents / command lines are reported as
    coverage gaps, in the store and in a scope ask's notes
  * the later export without userAccountControl is reported as drift
  * purple: each action's detected / host-only / missed matches the truth,
    latencies too
with timings for each step. Scripted; no LLM.
"""

from __future__ import annotations

import argparse
import json
import os
import resource
import time
from datetime import datetime, timezone
from pathlib import Path

from . import coverage, enrich, purple
from .contracts import AskRequest, EntityRef, PathRequest, ScopeSpec
from .store.common import redact_dsn


def _load(store, envs) -> dict:
    from .consumer import handle_batch
    from .registry import RegistryCache
    registry = RegistryCache(store)
    envs = list(envs)           # claims AND the documents they cite (a scan report)
    t0 = time.monotonic()
    counts = {"rejected": 0, "skipped": 0}
    for i in range(0, len(envs), 1000):
        got = handle_batch(store, [e.model_dump_json(exclude_none=True).encode()
                                   for e in envs[i:i + 1000]], registry)
        for k in counts:
            counts[k] += got.get(k, 0)
    store.refresh_statistics()
    secs = time.monotonic() - t0
    return {"envelopes": len(envs), **counts, "seconds": round(secs, 1),
            "per_sec": round(len(envs) / secs) if secs else 0}


def load_all(store, d: Path, ns: str) -> dict:
    from .connectors import endpoint, ldap, nmap, ocsf, oplog
    for mod in (ldap, nmap, endpoint, ocsf, oplog):
        store.put_schema(mod.schema(ns))
    out = {"ldap": _load(store, ldap.ldif_to_envelopes((d / "ad.ldif").read_text(), ns)),
           "nmap": _load(store, list(nmap.report_to_envelopes((d / "scan.xml").read_text(), ns))
                         + list(nmap.report_to_envelopes((d / "rescan.xml").read_text(), ns))),
           "osquery": _load(store, endpoint.to_envelopes((d / "osquery.log").read_text(), ns))}
    tl = []
    for f in sorted((d / "tasklist").glob("*.csv")):
        tl += list(endpoint.to_envelopes(f.read_text(), ns, host=f.stem, fmt="tasklist"))
    out["tasklist"] = _load(store, tl)
    out["detections"] = _load(store, ocsf.events_to_envelopes(
        (json.loads(line) for line in (d / "detections.ndjson").read_text().splitlines() if line), ns))
    out["oplog"] = _load(store, oplog.to_envelopes((d / "oplog.csv").read_text(), ns, "oplog"))
    return out


def _canon(store, ns, ref):
    return store.resolve_refs(ns, [ref]).get((ref.type, ref.key))


def evaluate(store, d: Path, ns: str, truth: dict) -> dict:
    from .connectors import ldap
    r: dict = {}
    t0 = time.monotonic()
    merged = enrich.resolve_identities(store, limit=1_000_000)
    r["resolve"] = {"merged": merged, "seconds": round(time.monotonic() - t0, 1)}

    # machines: directory object + scanned host -> one entity; twins stay apart
    folded = checked = false_merges = 0
    corp_fqdns = {}
    for sid, names in truth["host_names"].items():
        fqdn = names[0]
        if fqdn.endswith(".corp.example"):
            checked += 1
            a = _canon(store, ns, EntityRef(type="computer", key=sid))
            b = _canon(store, ns, EntityRef(type="host", key=fqdn))
            folded += a is not None and a == b
            corp_fqdns[fqdn.split(".")[0]] = b
    for short, _lab_fqdn in truth["twins"]:
        lab_sids = [s for s, n in truth["host_names"].items() if n[0] == f"{short}.lab.example"]
        corp = corp_fqdns.get(short)
        for s in lab_sids:
            false_merges += corp is not None and _canon(store, ns, EntityRef(type="computer", key=s)) == corp
    r["hosts"] = {"corp_hosts": checked, "folded": folded, "twins": len(truth["twins"]),
                  "false_merges": false_merges}

    # accounts from process lists -> directory users
    users_seen = users_folded = 0
    for u in range(truth["users"]):
        ref = EntityRef(type="user", key=f"corp\\user{u:05d}")
        c = _canon(store, ns, ref)
        if c is None:
            continue
        users_seen += 1
        sid = f"S-1-5-21-1000-2000-3000-{20000 + u}"
        users_folded += c == _canon(store, ns, EntityRef(type="user", key=sid))
    r["users"] = {"referenced": users_seen, "folded": users_folded}

    # coverage: tasklists carry no parent / cmdline
    tl_hosts = sorted(f.stem.lower() for f in (d / "tasklist").glob("*.csv"))
    gaps = coverage.gaps(store, ns, ["spawned_by", "cmdline"])
    tl_gap = next((g for g in gaps if g.predicate == "spawned_by" and g.scope.startswith("tasklist")), None)
    r["coverage"] = {"tasklist_hosts": len(tl_hosts),
                     "tasklist_parents": tl_gap.state if tl_gap else "not reported",
                     "tasklist_rows": tl_gap.of if tl_gap else 0}
    from .context import build_pack, find_paths
    t0 = time.monotonic()
    pack = build_pack(store, AskRequest(namespace=ns, budget=3000, question="what ran here?",
                                        scope=ScopeSpec(subjects=[EntityRef(type="host", key=tl_hosts[0])],
                                                        expand=["runs_on", "spawned_by"], depth=2)))
    r["coverage"]["ask_ms"] = round((time.monotonic() - t0) * 1000)
    r["coverage"]["ask_notes_gap"] = any(n.startswith("coverage:") and "spawned_by" in n
                                         for n in pack.notes)

    # drift: the later export has no userAccountControl
    watch = coverage.Watch()
    list(watch.wrap(ldap.ldif_to_envelopes((d / "ad-later.ldif").read_text(), ns,
                                           as_of=datetime.now(timezone.utc))))
    drift = watch.against(coverage.stored(store, ns))
    r["drift"] = {"kinds": sorted(x.kind for x in drift),
                  "uac_removed": all("useraccountcontrol" in x.removed for x in drift) and bool(drift)}

    # purple
    t0 = time.monotonic()
    rows, notes = purple.correlate(store, ns, "oplog")
    secs = time.monotonic() - t0
    want = {a["guid"]: a for a in truth["actions"]}
    right = latency_right = detected = 0
    for row in rows:
        exp = want.get(row.activity.split(":", 1)[1])
        if exp is None:
            continue
        right += row.status == exp["outcome"]
        if exp["outcome"] == "detected" and row.status == "detected":
            detected += 1
            latency_right += row.matches[0].latency_seconds == exp["latency"]
    r["purple"] = {"actions": len(truth["actions"]), "reported": len(rows), "status_right": right,
                   "latency_right": latency_right, "detected": detected, "seconds": round(secs, 2),
                   "summary": purple.summary(rows)}

    # a path through the folded identities: an account to the host it ran on
    user_sid, host_sid = truth["ran_as"]
    user_ref = EntityRef(type="user", key=user_sid)
    t0 = time.monotonic()
    path = find_paths(store, PathRequest(namespace=ns, **{"from": user_ref},
                                         to=EntityRef(type="computer", key=host_sid),
                                         via=["run_as", "runs_on"], depth=2))
    r["path"] = {"found": bool(path.paths), "ms": round((time.monotonic() - t0) * 1000)}
    return r


def markdown(res: dict) -> str:
    L = [f"# Estate check — {res['date']}", "",
         f"Store `{res['store']}` · scale **{res['scale']}** · {res['hosts_total']:,} machines"]
    if res.get("load"):
        L += ["", "| Source | Envelopes | Rejected | Skipped | Seconds | per s |",
              "| --- | --- | --- | --- | --- | --- |"]
        L += [f"| {k} | {v['envelopes']:,} | {v['rejected']} | {v['skipped']} | {v['seconds']} | {v['per_sec']:,} |"
              for k, v in res["load"].items()]
    h, u, c, dr, p = res["hosts"], res["users"], res["coverage"], res["drift"], res["purple"]
    L += ["", f"Identity pass: {res['resolve']['merged']:,} merges in {res['resolve']['seconds']} s.",
          f"Machines folded (directory object + scanned host): {h['folded']:,} / {h['corp_hosts']:,}; "
          f"second-domain twins: {h['twins']:,}, false merges: {h['false_merges']}.",
          f"Process-list accounts folded into directory users: {u['folded']:,} / {u['referenced']:,}.",
          f"Coverage: tasklist parents {c['tasklist_parents']} over {c['tasklist_rows']:,} processes on "
          f"{c['tasklist_hosts']} hosts; a scope ask names the gap: {c['ask_notes_gap']} "
          f"({c['ask_ms']} ms).",
          f"Drift on the later export: {', '.join(dr['kinds']) or 'none'}; userAccountControl reported "
          f"missing: {dr['uac_removed']}.",
          f"Purple: {p['status_right']} / {p['actions']} actions classified as planted "
          f"({p['summary']['by_status']}), latency exact on {p['latency_right']} / {p['detected']} "
          f"detected, in {p['seconds']} s.",
          f"find_path user -> host through run_as/runs_on: {res['path']['found']} "
          f"({res['path']['ms']} ms).", f"Peak RSS {res['peak_rss_mb']} MB."]
    return "\n".join(L) + "\n"


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="loom.estate_eval", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db")
    ap.add_argument("--namespace", default="estate")
    ap.add_argument("--generate", action="store_true")
    ap.add_argument("--data-dir")
    ap.add_argument("--scale", default="medium")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--no-load", action="store_true")
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    from .connectors import estate_gen
    d = Path(a.data_dir or f"/tmp/estate-{a.scale}")
    if a.generate:
        truth = estate_gen.generate(a.seed, a.scale, str(d))
    else:
        truth = json.loads((d / "truth.json").read_text())
    from .store.factory import store_from_env, store_from_url
    store = store_from_url(a.db) if a.db else store_from_env()
    res = {"date": datetime.now(timezone.utc).date().isoformat(),
           "store": redact_dsn(a.db or os.environ.get("LOOM_DB", "loom.db")),
           "scale": truth["scale"], "hosts_total": truth["hosts"]}
    try:
        if not a.no_load:
            res["load"] = load_all(store, d, a.namespace)
        res.update(evaluate(store, d, a.namespace, truth))
    finally:
        store.close()
    res["peak_rss_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024)
    md = markdown(res)
    print(md)
    out = Path(a.out or f"eval/estate-{truth['scale']}.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md)
    out.with_suffix(".json").write_text(json.dumps(res, indent=2, default=str))


if __name__ == "__main__":
    main()
