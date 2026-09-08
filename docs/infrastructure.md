# Infrastructure views

Two deployment shapes of the same contract, plus the two request flows that
matter. Everything a small team runs is in the first diagram; everything a
platform team can turn on is in the second. Nothing in the second changes
the API, the SDKs, or the MCP tools. Dials referenced here are documented in
`../deploy/README.md`; decisions in `decisions.md` (D-008…D-033).

## 1. Simple shape — one container on a laptop or a small VPS

`docker compose up loom`. One engine process, one SQLite file on a volume,
no queue, no operator. The enrichment worker and the answering LLM are
optional; without them Loom still ingests, ranks by keyword, and serves
cited packs.

```mermaid
flowchart LR
    subgraph callers["Callers"]
        agent["AI agent<br/>(Claude Code, any MCP client)"]
        app["Apps / custom code<br/>Python · TypeScript · Go SDK · curl · OpenAPI clients"]
        ship["Existing pipelines<br/>Fluent Bit / Vector (batch HTTP) · files via loom.ingest"]
        admin["Operator<br/>python -m loom.keys / lifecycle / seed"]
    end

    subgraph engine["Engine container  ·  loom-engine:local  ·  uid 10001"]
        direction TB
        mcp["MCP server (stdio)<br/>find_entity · find_related · ask · ask_scope<br/>expand · record_claim · get_observations · answer"]
        http["HTTP  :8000  (uvicorn, 1 worker)<br/>POST /v1/ingest · /v1/ingest/batch · /v1/ask · /v1/expand · /v1/answer · /v1/schemas<br/>GET /v1/entities/search|semantic · /v1/artifacts/{id}<br/>GET /healthz · /readyz · /metrics"]
        gate["Auth + data gates (D-013a/D-021)<br/>keys file hot-reload · namespace/perms<br/>entity_types · sources · signed handles"]
        core["Core<br/>registry validation (D-024) · pack builder<br/>rank: cosine ∘ keyword · time-decayed recency · confidence<br/>conflicts first · budget trim · citations · handles<br/>as_of (knowledge) / valid_at (fact) time axes"]
        store["GraphStore → SqliteStore<br/>transactions · event_id dedupe · tombstones<br/>norm keys · schema registry · leases"]
        mcp --> gate --> core --> store
        http --> gate
    end

    subgraph disk["Volume  /data"]
        db[("loom.db  (SQLite, WAL)<br/>entities · observations · artifacts · embeddings<br/>doc_chunks · dossiers · aliases · tombstones · schemas<br/>vobs_*/vchk_* sqlite-vec ANN tables")]
        keys["keys.json  (hashed keys + grants)<br/>bind-mounted, hot-reloaded"]
    end

    subgraph optional["Optional (compose profiles / .env)"]
        worker["Enrichment worker  (profile: enrich)<br/>python -m loom.enrich run<br/>extract · resolve · adjudicate · embed<br/>chunk · dossiers · vector-index backfill"]
        llm["LLM + embedding provider<br/>OpenRouter · Venice · OpenAI · Anthropic<br/>Ollama / vLLM self-hosted<br/>LOOM_LLM_* · LOOM_EMBED_*"]
    end

    agent -- "stdio (spawned per session)" --> mcp
    app -- "HTTPS + X-Loom-Key" --> http
    ship -- "POST /v1/ingest/batch (NDJSON or array)" --> http
    admin -- "docker compose run --rm loom …" --> store
    store <--> db
    gate -. reads .-> keys
    worker <--> db
    worker -- "extraction · dossiers · adjudication · embeddings" --> llm
    core -- "answer(): synthesis · query embedding" --> llm
```

What each box guarantees: every pack item is cited (D-023); writes are
append-only and idempotent on `event_id` (D-014/D-022); redaction is a
tombstone (D-016); a scoped key sees a scoped world, never a wall of errors
(D-013a/D-021); the vector index is derived from the portable JSON vectors
and falls back to an exact scan (D-025).

## 2. Scaled shape — `deploy/k8s/scale-pg-ha` (every dial on)

Same image, same contract. Stateless tiers scale on CPU; the two stateful
tiers (queue, database) are replicated clusters run by boring, shipped
components. Dials are env vars or overlays; a team turns on only what a
measurement asks for.

```mermaid
flowchart TB
    subgraph senders["Senders"]
        shippers["Log shippers (Fluent Bit, Vector) · scanners<br/>SDKs (Python/TS/Go) · bulk loader · OpenAPI clients"]
        kafka[("Your Kafka / Redpanda topics")]
    end
    subgraph readers["Readers"]
        agents["Agents (MCP streamable-http, keyed)<br/>Apps (Python / TypeScript SDK, HTTP)"]
    end

    lb1["Ingress / Service"]
    lb2["Ingress / Service"]

    subgraph gws["Gateway pods (Go) · HPA 2–10 · stateless"]
        gw["authenticate → per-principal rate limit → size cap<br/>→ JSON-Schema validate → namespace/type/source gates<br/>→ publish (3 retries) · header Loom-Principal = grant id"]
    end

    subgraph nats["NATS JetStream · 3-node cluster · PVC per node"]
        direction LR
        s1[("LOOM_INGEST · R=3<br/>max_bytes 4 GiB · discard old")]
        s2[("LOOM_DEADLETTER · R=3<br/>poison + Loom-Error")]
    end

    subgraph cons["Writer consumers ×N · shared durable"]
        c1["pull ≤64 → one transaction<br/>ack after commit · nak on failure<br/>dead-letter after 5 deliveries"]
    end

    subgraph kcons["Kafka consumers ×N (optional, D-034)"]
        k1["read envelopes from your topics<br/>commit after write · retry · dead-letter topic"]
    end

    subgraph engs["Engine pods · HPA 2–8"]
        e1["uvicorn · LOOM_WORKERS × LOOM_DB_POOL<br/>gates · registry · pack builder · semantic search"]
    end

    subgraph wks["Enrichment StatefulSet ×N"]
        w1["leased extraction / chunking / dossiers<br/>embedding backlog sharded by ordinal"]
    end

    subgraph pg["Postgres · CloudNativePG · 3 instances · failover"]
        direction LR
        rw[("loom-pg-rw → primary<br/>pgvector HNSW")]
        ro[("loom-pg-ro → 2 replicas")]
        rw -- "WAL" --> ro
    end

    llm["LLM + embedding provider"]
    prom["Prometheus ← /metrics"]

    shippers -- "/v1/ingest · /v1/ingest/batch" --> lb1 --> gw
    kafka --> k1 --> rw
    gw -- "loom.ingest.{kind}" --> s1
    s1 -- "batches" --> c1
    c1 -- "max deliveries" --> s2
    c1 -- "INSERT … ON CONFLICT (event_id)" --> rw
    agents --> lb2 --> e1
    e1 -- "writes" --> rw
    e1 -- "reads (LOOM_DB_READ)" --> ro
    w1 --> rw
    e1 -.-> llm
    w1 -.-> llm
    prom -.-> e1
    prom -.-> gw
```

### 2b. Optional capacity dials on top of the scaled shape

Both are off unless configured; both sit behind the same `GraphStore`
interface, so engines, consumers and workers change nothing.

```mermaid
flowchart LR
    subgraph procs["Every store user (engine · consumer · worker)"]
        st["GraphStore as built by the factory<br/>BlobOffloadStore( ShardedStore( … ) )"]
    end

    subgraph shards["LOOM_SHARDS — tenant capacity isolation (D-032)"]
        direction TB
        d0[("LOOM_DB (default)<br/>every unmapped namespace")]
        d1[("acme → its own Postgres cluster")]
        d2[("globex → a SQLite file")]
    end

    subgraph blobs["LOOM_BLOB_* — artifact offload (D-033)"]
        b1[("S3 / MinIO / Ceph bucket<br/>or a shared volume<br/>bodies above LOOM_BLOB_THRESHOLD")]
    end

    st -- "namespace → shard<br/>admin calls fan out<br/>backlogs fill shard by shard" --> d0
    st --> d1
    st --> d2
    st -- "row keeps a stub + pointer<br/>every read reinflates" --> b1
```


Failure modes this shape was tested against on a k3s cluster (D-029/D-030):
a JetStream leader deleted mid-burst (3000/3000 acknowledged, nothing lost
or duplicated); the Postgres primary deleted under synchronous writes and
replica reads (319/319 and 319/319, failover completed). Engine and worker
pods wait up to 180 s for a booting database instead of crash-looping.

## 3. Read flow — `POST /v1/ask` (same code path in both shapes)

```mermaid
sequenceDiagram
    autonumber
    participant A as Agent / App
    participant H as HTTP route
    participant G as Auth + gates
    participant P as Pack builder
    participant S as GraphStore
    participant E as Embedder (optional)

    A->>H: POST /v1/ask {subject or scope, question, budget, as_of?, valid_at?}
    H->>G: X-Loom-Key → grant (namespace, perms, entity_types)
    G-->>H: 401 / 403, or grant
    H->>P: build_pack(req, allowed_types)
    P->>S: resolve_scope (BFS over containment predicates, registry default)
    P->>S: observations_for each subject (≤1000, tombstones excluded)
    Note over P: drop subjects / edges outside allowed_types (scoped world)
    opt embedder configured
        P->>E: embed(question)  (memoized per model+text)
        P->>S: embeddings_for(ids) → cosines (numpy)
        P->>S: nearest_chunks(cited artifacts)  (sqlite-vec / pgvector / exact)
    end
    P->>S: get_dossier per subject (skipped when as_of set)
    Note over P: as_of → hide later-recorded facts<br/>valid_at → keep facts whose window covers T
    Note over P: rank = cosine∘keyword + time-decayed recency + confidence<br/>extracted (doc:) claims discounted
    Note over P: conflicts first (cross-source scalar disagreement)<br/>→ brief → excerpts (≤ half remaining) → facts, until budget
    Note over P: every item cited, what didn't fit → handles<br/>(more / conflict / excerpt), HMAC-signed if LOOM_HANDLE_SECRET
    P-->>H: ContextPack
    H-->>A: 200 {items[], handles[], budget, subjects[]}
    A->>H: POST /v1/expand {handle}  (same gates re-applied)
```

## 4. Write flow — ingest through the scaled tier

```mermaid
sequenceDiagram
    autonumber
    participant D as Sender
    participant GW as Gateway (Go)
    participant JS as JetStream (R=3)
    participant C as Consumer
    participant DB as Postgres primary
    participant W as Enrichment worker
    participant L as LLM / Embedder

    D->>GW: POST /v1/ingest {envelope} — or /v1/ingest/batch [envelopes] (each item below, individually)
    GW->>GW: key → grant · rate bucket (per grant, n tokens for n items) · size cap<br/>schema validate · namespace/type/source gates
    GW-->>D: 401 / 403 / 413 / 422 / 429 on failure
    GW->>JS: publish loom.ingest.{kind} + Loom-Principal (3 retries)
    JS-->>GW: quorum ack
    GW-->>D: 202 {status: queued}
    JS->>C: batch (≤64) via durable loom-writer
    C->>DB: one transaction: INSERT … ON CONFLICT (namespace, event_id) DO NOTHING
    alt commit ok
        C->>JS: ack each message
    else store error (rolled back)
        C->>JS: nak (redeliver in 2 s)
        Note over C,JS: on the 5th delivery → publish to LOOM_DEADLETTER<br/>with Loom-Error, then ack
    end
    Note over DB: claim → observation (entities auto-created)<br/>document → artifact (status pending)
    W->>DB: lease pending artifacts / claim dossier candidates<br/>shard of embedding backlog
    W->>L: extract (windowed, untrusted-text framing) · embed · brief
    W->>DB: observations tagged extracted · vectors + ANN rows · dossier with citations
    Note over W,DB: resolve: same-key cross-type merge · normalized-key merge<br/>LLM adjudication for ambiguous pairs (aliases keep it reversible)
```

## Reading the two shapes together

| Concern | Simple | Scaled |
| --- | --- | --- |
| Ingest path | direct write to SQLite (single or batch) | gateways → replicated JetStream → N consumers → Postgres primary; or Kafka topics → Kafka consumers → primary |
| Read path | same process, same file | engine replicas, reads on Postgres replicas |
| Vector search | sqlite-vec tables beside the JSON vectors | pgvector HNSW; exact scan if the extension is absent |
| Enrichment | one optional worker | leased, sharded StatefulSet |
| Tenant isolation | namespaces (data) | namespaces + `LOOM_SHARDS` (capacity) |
| Documents | in the database | offloaded to object storage above a threshold |
| Auth | keys file, hot-reloaded | same file as a Secret, mounted on engines and gateways |
| What changes for callers | nothing | nothing |
