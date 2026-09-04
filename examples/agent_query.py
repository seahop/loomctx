#!/usr/bin/env python3
"""Example reader: what an agent (without MCP) does — resolve, ask, expand.

Standard library only. Run after examples/vuln_feed.py has loaded data:

    python examples/agent_query.py --base http://localhost:8000

For a real agent, prefer the MCP server (docs/sdk.md) — this script just
shows the underlying HTTP calls an agent framework would make.
"""

import argparse
import json
import urllib.request

NAMESPACE = "vuln"


def post(base, path, body, api_key):
    headers = {"content-type": "application/json"}
    if api_key:
        headers["X-Loom-Key"] = api_key
    req = urllib.request.Request(base.rstrip("/") + path,
                                 data=json.dumps(body).encode(),
                                 headers=headers, method="POST")
    with urllib.request.urlopen(req) as resp:
        return json.load(resp)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8000")
    ap.add_argument("--api-key", default=None)
    args = ap.parse_args()

    pack = post(args.base, "/v1/ask", {
        "namespace": NAMESPACE,
        "subject": {"type": "cve", "key": "CVE-2026-1337"},
        "question": "how severe is this and what is affected?",
        "budget": 500,
    }, args.api_key)

    print(f"pack for CVE-2026-1337 ({len(pack['items'])} items, "
          f"budget {pack['budget']}):")
    for item in pack["items"]:
        cites = ", ".join(c["source"] for c in item.get("citations", []))
        print(f"  [{item['kind']}] {item['text']}"
              + (f"   ({cites})" if cites else ""))

    if pack["handles"]:
        print(f"\nexpanding: {pack['handles'][0]['hint']}")
        frag = post(args.base, "/v1/expand",
                    {"handle": pack["handles"][0]["id"], "budget": 600},
                    args.api_key)
        for item in frag["items"][:5]:
            print(f"  [{item['kind']}] {item['text']}")


if __name__ == "__main__":
    main()
