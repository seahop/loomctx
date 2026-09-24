# Quickstart (5 minutes)

Loom running, seeded with a demo security dataset, answering a cited question —
in Docker, nothing on your host.

## 1. Start the engine

```bash
docker compose up -d loom
curl -s localhost:8000/healthz          # {"status":"ok"}
```

## 2. Load the demo corpus

592 claims and 5 documents across two namespaces (`netsec`, `procurement`),
with planted demo moments (an IP-lease reassignment, cross-source conflicts,
an incident report).

```bash
docker compose exec loom python -m loom.seed load
```

## 3. Ask a focused, budgeted, cited question

"Which host held `10.0.4.7`?" — the answer is a time-bounded lease history,
each fact cited to its source:

```bash
curl -s -X POST localhost:8000/v1/ask -H 'content-type: application/json' -d '{
  "namespace": "netsec",
  "subject": {"type": "ip", "key": "10.0.4.7"},
  "question": "which host was assigned this ip?",
  "budget": 600
}' | python3 -m json.tool
```

Ask about `host web-01`'s OS instead and the pack **leads with a conflict**
(two scanners disagree), followed by facts and **expansion handles** —
opaque ids you pass to `/v1/expand` to pull one thread deeper without
bloating the first response.

## 4. (Optional) Let an LLM answer over the pack

Point Loom at any provider (OpenRouter, Venice, Anthropic, or a self-hosted
endpoint) — copy `.env.example` to `.env`, fill in a key, and restart:

```bash
cp .env.example .env      # set LOOM_LLM_PROVIDER / MODEL / API_KEY
docker compose up -d loom
curl -s -X POST localhost:8000/v1/answer -H 'content-type: application/json' -d '{
  "namespace": "netsec",
  "question": "what happened around alert AL-2291, and is 10.0.4.7 relevant?"
}' | python3 -m json.tool
```

Loom auto-resolves the entities named in the question, builds one budgeted
pack across them, and the model answers with citations — and returns the
pack it saw, so you can audit exactly what grounded the answer.

## Where next

- **[real-data.md](real-data.md)** — one more command loads real
  vulnerability intelligence (CISA KEV, NVD, EPSS) next to these hosts.
- **[tutorial.md](tutorial.md)** — build your *own* security domain from an
  empty store (vulnerability management), end to end, in ~30 minutes.
- **[sdk.md](sdk.md)** — connect an agent over MCP, or use the HTTP/Python
  surfaces.
- **[architecture.md](architecture.md)** — how it works.
