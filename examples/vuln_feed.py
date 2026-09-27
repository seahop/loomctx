#!/usr/bin/env python3
"""Example sender: push a small vulnerability-management dataset into LoomCtx.

Standard library only — the shape a real pipeline device or scanner would
have (no dependency on the LoomCtx package or SDK). Mirrors docs/tutorial.md.

    docker compose up -d loomctx
    docker compose exec -T loomctx python - < examples/vuln_feed.py
    # or, from the host with the engine on :8000:
    python examples/vuln_feed.py --base http://localhost:8000

Then query it (see docs/tutorial.md):
    curl -s -X POST localhost:8000/v1/ask -H 'content-type: application/json' \
      -d '{"namespace":"vuln","subject":{"type":"cve","key":"CVE-2026-1337"},
           "question":"how severe is this?","budget":500}'
"""

import argparse
import json
import urllib.request

NAMESPACE = "vuln"


def ingest(base: str, body: dict, api_key: str | None) -> str:
    headers = {"content-type": "application/json"}
    if api_key:
        headers["X-LoomCtx-Key"] = api_key
    req = urllib.request.Request(
        base.rstrip("/") + "/v1/ingest",
        data=json.dumps(body).encode(),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return json.load(resp).get("status", "?")


def claim(base, api_key, subject, predicate, obj, observed_at, source, **extra):
    body = {"kind": "claim", "namespace": NAMESPACE, "subject": subject,
            "predicate": predicate, "object": obj, "observed_at": observed_at,
            "source": source, **extra}
    print(f"  claim {subject['type']}:{subject['key']} {predicate} -> "
          f"{ingest(base, body, api_key)}")


def document(base, api_key, text, filename, source, observed_at):
    body = {"kind": "document", "namespace": NAMESPACE, "text": text,
            "filename": filename, "source": source, "observed_at": observed_at}
    print(f"  document {filename} -> {ingest(base, body, api_key)}")


def E(t, k):
    return {"type": t, "key": k}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8000")
    ap.add_argument("--api-key", default=None)
    args = ap.parse_args()
    b, k = args.base, args.api_key

    print("sending scanner findings...")
    claim(b, k, E("asset", "web-01"), "affected_by", E("cve", "CVE-2026-1337"),
          "2026-08-01T09:00:00Z", "nessus", confidence=0.9)
    claim(b, k, E("cve", "CVE-2026-1337"), "has_severity", "critical",
          "2026-08-01T09:00:00Z", "nvd")
    claim(b, k, E("cve", "CVE-2026-1337"), "has_severity", "high",
          "2026-08-20T09:00:00Z", "vendor-advisory", confidence=0.7)
    claim(b, k, E("asset", "web-01"), "affected_by", E("cve", "CVE-2026-9001"),
          "2026-08-02T09:00:00Z", "nessus")
    claim(b, k, E("asset", "web-01"), "scanned_by", E("scanner", "nessus"),
          "2026-08-02T09:00:00Z", "nessus")
    claim(b, k, E("asset", "web-01"), "patched_for", E("cve", "CVE-2026-9001"),
          "2026-08-25T12:00:00Z", "patch-mgmt")
    # reachability (from firewall/netflow) — the graph edge a red-team
    # traversal follows, and a blue-team blast-radius query reads
    claim(b, k, E("asset", "web-01"), "can_reach", E("asset", "db-01"),
          "2026-08-10T00:00:00Z", "firewall-rules")
    claim(b, k, E("asset", "db-01"), "affected_by", E("cve", "CVE-2026-5150"),
          "2026-08-11T09:00:00Z", "nessus")

    print("sending a pentest report...")
    document(
        b, k,
        text=("Engagement summary: web-01 remains exploitable via "
              "CVE-2026-1337 despite the August patch cycle, which only "
              "addressed CVE-2026-9001. Recommend emergency remediation. "
              "Lateral movement to db-01 was demonstrated."),
        filename="pentest-2026-08.txt", source="pentest-vendor",
        observed_at="2026-08-28T00:00:00Z")

    print("done. Try the /v1/ask calls in docs/tutorial.md.")


if __name__ == "__main__":
    main()
