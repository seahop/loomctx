# Tutorial: your own security domain in 30 minutes

The quickstart used a bundled dataset. Here you build a *different* one from an
empty store — **vulnerability management** — to see how Loom adapts to whatever
security data your team actually has. Same engine, your entities, your
predicates, no netsec-specific code anywhere in Loom.

We'll model **assets**, **CVEs**, and **scanners**; feed both structured
scanner events and an unstructured pentest report; then query it the way an
agent would.

> **No schema to declare.** Loom creates entity types and predicates the first
> time you use them — "bring your own schema" is just "start sending claims."
> Registering a schema (`POST /v1/schemas`, D-024) is optional and additive:
> a registered predicate's `object_types` are enforced on ingest, and a
> `strict` namespace rejects anything unregistered — on the HTTP path, the
> MCP `record_claim` tool, the extraction worker and the queue consumers
> alike. Leave it off while you explore; turn it on when the domain settles.

Everything runs in Docker. We'll use a fresh namespace, `vuln`, so it sits
beside the demo data without colliding.

## 1. A clean engine

```bash
docker compose up -d --wait loom
```

## 2. Send structured claims (scanner findings)

A scanner emits entity-addressed events; these map straight to observations.
This script uses only the standard library (the shape a real pipeline device
would send). Save as `feed.py`, or use [`examples/vuln_feed.py`](../examples/vuln_feed.py)
instead — one or the other, not both (these claims carry no `event_id`, so a
second run records them twice), and note the example also sends the step-3
pentest report for you:

```python
import json, urllib.request

BASE = "http://localhost:8000"

def claim(subject, predicate, obj, observed_at, source, **extra):
    body = {"kind": "claim", "namespace": "vuln",
            "subject": subject, "predicate": predicate, "object": obj,
            "observed_at": observed_at, "source": source, **extra}
    req = urllib.request.Request(BASE + "/v1/ingest",
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json"}, method="POST")
    with urllib.request.urlopen(req) as r:
        print(predicate, "->", json.load(r).get("status"))

E = lambda t, k: {"type": t, "key": k}

# web-01 is affected by two CVEs; one scanner disagrees on severity later
claim(E("asset","web-01"), "affected_by", E("cve","CVE-2026-1337"),
      "2026-08-01T09:00:00Z", "nessus", confidence=0.9)
claim(E("cve","CVE-2026-1337"), "has_severity", "critical",
      "2026-08-01T09:00:00Z", "nvd")
claim(E("cve","CVE-2026-1337"), "has_severity", "high",       # <- conflict
      "2026-08-20T09:00:00Z", "vendor-advisory", confidence=0.7)
claim(E("asset","web-01"), "affected_by", E("cve","CVE-2026-9001"),
      "2026-08-02T09:00:00Z", "nessus")
claim(E("asset","web-01"), "scanned_by", E("scanner","nessus"),
      "2026-08-02T09:00:00Z", "nessus")
# a fix lands for one of them
claim(E("asset","web-01"), "patched_for", E("cve","CVE-2026-9001"),
      "2026-08-25T12:00:00Z", "patch-mgmt")
# reachability from firewall/netflow — the edge red-team traversal follows
claim(E("asset","web-01"), "can_reach", E("asset","db-01"),
      "2026-08-10T00:00:00Z", "firewall-rules")
claim(E("asset","db-01"), "affected_by", E("cve","CVE-2026-5150"),
      "2026-08-11T09:00:00Z", "nessus")
```

```bash
docker compose exec -T loom python - < feed.py
```

## 3. Send an unstructured document (a pentest report)

Documents are stored verbatim, then mined asynchronously into observations
with span-level provenance (step 5). Ingest one:

```bash
curl -s -X POST localhost:8000/v1/ingest -H 'content-type: application/json' -d '{
  "kind": "document", "namespace": "vuln",
  "filename": "pentest-2026-08.txt", "source": "pentest-vendor",
  "observed_at": "2026-08-28T00:00:00Z",
  "text": "Engagement summary: web-01 remains exploitable via CVE-2026-1337 despite the August patch cycle, which only addressed CVE-2026-9001. Recommend emergency remediation. Lateral movement to db-01 was demonstrated."
}'
```

You get `202 accepted` with an `artifact_id` — the write path never blocks on
extraction.

## 4. Query it

Raw facts about an asset:

```bash
curl -s 'localhost:8000/v1/entities/asset/web-01/observations' \
  -H 'X-Loom-Namespace: vuln' | python3 -m json.tool
```

A focused, budgeted pack — note the CVE-severity **conflict surfaces first**:

```bash
curl -s -X POST localhost:8000/v1/ask -H 'content-type: application/json' -d '{
  "namespace": "vuln",
  "subject": {"type": "cve", "key": "CVE-2026-1337"},
  "question": "how severe is this and what is affected?",
  "budget": 500
}' | python3 -m json.tool
```

## 5. Enrich: mine the document, embed, summarize

Run the enrichment worker once against your configured LLM (see
`.env.example` for `LOOM_LLM_*`; embeddings via `LOOM_EMBED_*`, or
`LOOM_EMBED_PROVIDER=hashing` for an offline pass):

```bash
docker compose exec -T -e LOOM_EMBED_PROVIDER=hashing loom \
  python -m loom.enrich run --once
```

Now the pentest report's assertions ("web-01 exploitable via CVE-2026-1337")
exist as cited observations, `web-01` has a dossier brief, its passages are
retrievable as `doc_excerpt` items, and ranking is semantic. (Configure
`LOOM_EMBED_*` on the **engine** too, not just the worker — the query is
embedded at read time; see `.env.example`.) Ask a question whose wording
doesn't match any predicate literally, and raise the budget if you want more
of the report's passages back — the ceiling is `LOOM_MAX_BUDGET`:

```bash
curl -s -X POST localhost:8000/v1/ask -H 'content-type: application/json' -d '{
  "namespace": "vuln", "subject": {"type": "asset", "key": "web-01"},
  "question": "is this box still exploitable after patching?", "budget": 700
}' | python3 -m json.tool
```

## 6. Ask across a set (scopes)

Everything affected by a CVE, or every asset a scanner touched, in one pack —
give a `scope` instead of a single subject:

```bash
curl -s -X POST localhost:8000/v1/ask -H 'content-type: application/json' -d '{
  "namespace": "vuln",
  "scope": {"subjects": [{"type": "scanner", "key": "nessus"}],
            "expand": ["scanned_by"], "depth": 1},
  "question": "what did this scanner find?", "budget": 800
}' | python3 -m json.tool
```

## 6b. Same data, both sides of the line

The store doesn't care whether you're attacking or defending — the *question*
does. Against the exact data you just loaded:

- **Blue:** *"is web-01 still exploitable after patching?"* (step 5) — answered
  from the patch record and the pentest finding, conflict-aware.
- **Red:** *"what's exploitable on web-01 and what can it reach?"* — the same
  asset pack surfaces the unpatched CVE-2026-1337 and the `can_reach` edge to
  db-01 (the next hop). A **scope** then pulls web-01 *and* what it reaches
  into one pack, so the attack path — db-01's own CVE included — assembles in
  a single question:

```bash
curl -s -X POST localhost:8000/v1/ask -H 'content-type: application/json' -d '{
  "namespace": "vuln",
  "scope": {"subjects": [{"type": "asset", "key": "web-01"}],
            "expand": ["can_reach"], "depth": 1},
  "question": "what is exploitable along this path?", "budget": 900
}' | python3 -m json.tool
```

Neither framing is baked into Loom; both are just questions over the graph.

## 7. Connect an agent (MCP)

Point any MCP-capable agent at Loom and it gets `list_namespaces`,
`describe_namespace`, `find_entity`, `find_related`, `ask`, `ask_scope`,
`find_path` (the connecting edge sequence(s) between two entities, D-067),
`expand`, `record_claim`, `get_observations`, `answer`, `purple_report` (a
red-team operation against the detections, D-086) — scoped to whatever
the agent's API key allows:

```bash
claude mcp add loom -- docker compose --project-directory "$PWD" run --rm -T loom python -m loom.mcp_server
```

Now "ask Loom which assets are still exploitable" is a tool call, and the
agent can `record_claim` its own conclusions back.

## 8. Lock it down (when you're past experimenting)

Mint a scoped key so a scanner can only *write* its findings and an analyst's
agent can only *read* the slice they're cleared for — see
**[administration.md](administration.md)**:

```bash
mkdir -p secrets   # yours, not root's: docker would create a missing mount source as root
docker compose run --rm --user "$(id -u):$(id -g)" -v $PWD/secrets:/secrets loom \
  python -m loom.keys --file /secrets/keys.json generate \
  --id nessus-feed --namespace vuln --perms w \
  --entity-types asset,cve,scanner --sources nessus
```

## What you just proved

You stood up a security domain Loom had never seen — different entities,
different predicates, a different document type — with no code changes and no
schema ceremony, and got budgeted, cited, conflict-aware answers plus an agent
integration. The same data answered a defender's question and an attacker's.
That's the framework: **your security data, whatever its shape, whichever side
you're asking from.**

Next: **[sdk.md](sdk.md)** for the typed SDKs and full surface,
**[../deploy/integrations/README.md](../deploy/integrations/README.md)** to
feed Loom from the shippers, queues, and files you already have,
**[architecture.md](architecture.md)** for how the write/read split works, and
**[administration.md](administration.md)** for running it for a team.
