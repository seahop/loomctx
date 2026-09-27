#!/usr/bin/env python3
"""Example sender: push a STIX 2.1 bundle into LoomCtx, standard library only.

The shape a TIP export hook or a pipeline step would have — no dependency
on the LoomCtx package. `python -m loomctx.connectors.stix import` does the full
mapping (docs/interop.md); this covers the common core: relationships,
sightings, and the name/description/pattern of the objects they join,
with a STIX vulnerability landing on the `cve:` entity the KEV/NVD
connector writes to.

    python examples/stix_import.py bundle.json --base http://localhost:8000 --namespace netsec
    python examples/stix_import.py bundle.json --api-key loomctxk_...
"""

import argparse
import json
import re
import urllib.request

CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
ENTITY_TYPES = {"ipv4-addr": "ip", "ipv6-addr": "ip", "domain-name": "domain", "url": "url",
                "email-addr": "email", "user-account": "user", "identity": "identity"}
PROPERTIES = {"name": "name", "description": "summary", "pattern": "pattern"}


def entity(obj, stix_id):
    """type:key for a STIX object (or a dangling reference)."""
    if obj is None:
        stype = stix_id.split("--", 1)[0]
        return {"type": ENTITY_TYPES.get(stype, stype.replace("-", "_")), "key": stix_id}
    stype = obj["type"]
    if stype == "vulnerability":
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "cve" and CVE.match(ref.get("external_id", "")):
                return {"type": "cve", "key": ref["external_id"].upper()}
    key = obj.get("value") or obj.get("user_id") or obj.get("name") or stix_id
    return {"type": ENTITY_TYPES.get(stype, stype.replace("-", "_")), "key": str(key)}


def envelopes(bundle, namespace, default_source="stix"):
    objects = {o["id"]: o for o in bundle.get("objects", []) if isinstance(o, dict) and "id" in o}
    identities = {i: o.get("name", i) for i, o in objects.items() if o["type"] == "identity"}

    def claim(obj, subject, predicate, value, tag=""):
        stamp = (obj.get("modified") or obj.get("created") or "").replace("-", "").replace(":", "")[:15]
        env = {"kind": "claim", "namespace": namespace, "subject": subject, "predicate": predicate,
               "object": value, "observed_at": obj.get("modified") or obj.get("created"),
               "source": identities.get(obj.get("created_by_ref"), default_source),
               "event_id": f"stix:{obj['id']}:{stamp}:{predicate}{tag}"[:128],
               "attrs": {"stix_id": obj["id"], "stix_type": obj["type"]}}
        if isinstance(obj.get("confidence"), (int, float)):
            env["confidence"] = max(0.0, min(1.0, obj["confidence"] / 100))
        return env

    for obj in objects.values():
        if obj.get("revoked") or not (obj.get("modified") or obj.get("created")):
            continue
        if obj["type"] == "relationship" and obj.get("source_ref") and obj.get("target_ref"):
            env = claim(obj, entity(objects.get(obj["source_ref"]), obj["source_ref"]),
                        obj["relationship_type"].replace("-", "_"),
                        entity(objects.get(obj["target_ref"]), obj["target_ref"]))
            if obj.get("start_time"):
                env["valid_from"] = obj["start_time"]
            if obj.get("stop_time"):
                env["valid_to"] = obj["stop_time"]
            yield env
        elif obj["type"] == "sighting" and obj.get("sighting_of_ref"):
            subject = entity(objects.get(obj["sighting_of_ref"]), obj["sighting_of_ref"])
            for where in obj.get("where_sighted_refs", []):
                env = claim(obj, subject, "sighted_by", entity(objects.get(where), where), f":{where}")
                env["attrs"]["count"] = obj.get("count", 1)
                if obj.get("first_seen"):
                    env["valid_from"] = obj["first_seen"]
                if obj.get("last_seen"):
                    env["valid_to"] = obj["last_seen"]
                yield env
        elif obj["type"] not in ("bundle", "marking-definition", "note", "report", "opinion", "observed-data"):
            subject = entity(obj, obj["id"])
            for prop, predicate in PROPERTIES.items():
                if isinstance(obj.get(prop), str) and obj[prop].strip():
                    yield claim(obj, subject, predicate, obj[prop])


def post_batch(base, envs, api_key):
    headers = {"content-type": "application/x-ndjson"}
    if api_key:
        headers["X-LoomCtx-Key"] = api_key
    body = "".join(json.dumps(e) + "\n" for e in envs).encode()
    req = urllib.request.Request(base.rstrip("/") + "/v1/ingest/batch", data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req) as resp:
        return json.load(resp)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle")
    ap.add_argument("--base", default="http://localhost:8000")
    ap.add_argument("--namespace", default="netsec")
    ap.add_argument("--api-key", default=None)
    ap.add_argument("--batch", type=int, default=200)
    args = ap.parse_args()
    with open(args.bundle, encoding="utf-8") as fh:
        bundle = json.load(fh)
    envs = list(envelopes(bundle, args.namespace))
    totals = {"total": 0, "recorded": 0, "accepted": 0, "rejected": 0}
    for i in range(0, len(envs), args.batch):
        result = post_batch(args.base, envs[i:i + args.batch], args.api_key)
        for k in totals:
            totals[k] += result.get(k, 0)
        for r in result.get("results", []):
            if r.get("status") == "rejected":
                print(f"  rejected: {r.get('detail')}")
    print(json.dumps(totals))


if __name__ == "__main__":
    main()
