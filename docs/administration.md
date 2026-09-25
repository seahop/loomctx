# Administering Loom

The runbook for the person who runs a Loom for their team: adding users and
senders, scoping what each can see, rotating and revoking, and keeping the
data healthy. Everything here is CLI + one mounted file — deliberately: the
keys file is auditable, diffable, backed by whatever secret machinery you
already trust, and both the engine and the gateway hot-reload it, so **no
administrative action requires a restart**.

## The mental model

- **A key = an identity + a grant.** The grant (namespaces, read/write,
  entity types, sources, expiry) lives beside the key's hash in the keys
  file. The plaintext exists only in the moment of generation and in the
  holder's config.
- **Capabilities are never gated — data is.** Every valid reader keeps the
  full query surface (ask, expand, search, `/v1/answer`). Scope controls
  which slice of the world those queries operate over.
- **Two kinds of principals:**
  - *Senders* (pipeline devices, log shippers, agents writing back):
    write-only keys, usually source-pinned and type-scoped.
  - *Readers* (people via their agents, dashboards): read keys scoped to
    the namespaces/entity types that user is cleared for.

## Where the keys file lives

| Deployment | Location | How updates propagate |
| --- | --- | --- |
| Compose | a bind-mounted file, e.g. `-v ./secrets:/secrets` + `LOOM_AUTH_FILE=/secrets/keys.json` | instant (mtime hot reload) |
| Kubernetes | a Secret mounted at `/secrets`, `LOOM_AUTH_FILE=/secrets/keys.json` on the engine AND gateway pods | `kubectl create secret generic loom-keys --from-file=keys.json --dry-run=client -o yaml \| kubectl apply -f -` — kubelet refreshes mounted Secrets within ~a minute, hot reload does the rest |

Keep `keys.json` in your secret store (Vault, SOPS, sealed-secrets), never in
git. It contains only hashes, but grants are still access metadata.

## Recipes

Create the directory first (`mkdir -p secrets`): if it is missing, docker
creates it owned by root and the key file cannot be written. All commands
run in the container (`docker compose run --rm --user "$(id -u):$(id -g)" -v $PWD/secrets:/secrets loom python -m loom.keys --file /secrets/keys.json ...`).
The `--user` flag matters: the image runs as an unprivileged user (uid
10001), so a bind-mounted `secrets/` owned by you would otherwise be
read-only to it. On Kubernetes the mounted Secret is readable by that uid
because the manifests set `fsGroup: 10001`.

`--file` defaults to `secrets/keys.json` (the directory is gitignored and
dockerignored, and `keys.json` anywhere is gitignored too). The file is
written atomically — a temp file in the same directory, then `os.replace`
— with mode `0600`, so a hot-reloading engine never parses a half-written
file and the grants are not readable by other users on the host. The
recipes below omit `--file` and use that default; inside the compose
recipe above it is `/secrets/keys.json`.

**Onboard a sender** (a log shipper that may only write auth-log facts about
hosts/users/ips into netsec, expiring in 6 months):

```bash
python -m loom.keys generate --id netsec-authlog-shipper \
  --namespace netsec --perms w --entity-types host,user,ip \
  --sources auth-log --expires-days 180
# -> prints loomk_... ONCE; put it in the shipper's config (X-Loom-Key)
```

**A feed refresh job** (the nightly `vulns-refresh` CronJob: reads the
stored KEV rows, writes only the feed sources). A source grant is an exact
name or a family ending in `:*` — NVD records each scorer's CVSS under its
own source, `nvd:<scorer>`, so the key needs both `nvd` and `nvd:*`:

```bash
python -m loom.keys generate --id vulns-refresh \
  --namespace netsec --perms rw --sources 'nvd,nvd:*,cisa-kev,first-epss,cisa-adp'
```

A loader exits non-zero when the engine refuses any envelope, so a
mis-scoped key fails the Job instead of loading a partial feed (D-063).
The first load, which registers the namespace schema, needs a key with no
source gate.

**Onboard a user** (an analyst whose agent may query netsec, but only
host/ip/alert data — not, say, HR entities another team ingests):

```bash
python -m loom.keys generate --id analyst-jdoe \
  --namespace netsec --perms r --entity-types host,ip,alert,domain
# hand the key to them for their agent config; their MCP/HTTP/SDK calls
# carry it as X-Loom-Key or a Bearer token
```

Their agent now sees a coherent, smaller world: entity search and
`/v1/answer` auto-resolution return only in-scope entities; an explicit
request outside scope gets a 403 naming the gate.

**Change what someone can see** (grants are metadata — no re-minting, the
holder's key keeps working):

```bash
python -m loom.keys update --id analyst-jdoe \
  --entity-types host,ip,alert,domain,user       # widen
python -m loom.keys update --id analyst-jdoe --perms rw  # allow write-back
```

**Rotate a credential** (suspected leak, scheduled rotation):

```bash
python -m loom.keys generate --id analyst-jdoe-2 --namespace netsec --perms r --entity-types host,ip,alert,domain
# hand over the new key, then:
python -m loom.keys revoke --id analyst-jdoe
```

**Offboard:** `revoke --id ...` — takes effect on the next reload (seconds
locally, ≤ ~1 min on k8s). Their history remains attributed in the
observations they wrote (`source`, and their writes are in the append-only
record).

**Review who has access:** `python -m loom.keys list` —
one line per key: id, namespaces, perms, state, gates. The file itself
diffs cleanly in your secret store's history, which is your change audit.

## Why the bearer can't be tampered with

The key is an **opaque reference token**, not a self-describing one (not a
JWT). `loomk_...` is 32 random bytes with no structure — it carries no
scope, no namespaces, no expiry, no identity. On every request the server
hashes the presented string and looks the hash up in the keys file; the
grant found *server-side* is the only authority. Consequences:

- There is nothing inside the token to "open and edit" — scope tampering
  isn't a defended-against attack here, it's a non-existent one.
- Flipping any character yields a hash that matches nothing → 401.
- Widening a principal's access requires writing the keys file, i.e.
  control of the Secret — which is the real trust boundary. Protect the
  keys file with your secret store's RBAC; whoever can write it
  administers Loom.
- A leaked *file* doesn't leak credentials (hashes only, and lookups
  compare digests in constant time); a leaked *key* is revoked by id and
  dies at the next hot reload.
- The key travels in a header, so transport security is on you: terminate
  TLS at your ingress/LB in any deployment that leaves localhost (no
  plaintext HTTP across networks).

## Documents and type-scoped keys (D-059)

A document has no entity type of its own; a type-scoped reader may fetch
it (`GET /v1/artifacts/{id}`, excerpt handles) once it backs a fact about
an entity in their world. So *citing* a document is a privilege too: a
key with `entity_types` may put `provenance` on a claim only for

- a document **it ingested itself** — the engine records the uploading
  grant on the artifact as `attrs["loom.uploader"]` (`{"grant": id,
  "entity_types": [...]}`; senders may not set it, the key is reserved), or
- a document that **already backs a fact inside its entity types** — one
  its holder could read anyway.

Anything else is a 403 (a rejected item in a batch). Keys without
`entity_types` cite freely, as before. A type-scoped key may likewise
`supersedes` only an observation whose entities are all inside its types.
Type-scoped readers also see a scoped registry (`GET /v1/schemas`, MCP
`describe_namespace`) and scoped entity counts (MCP `list_namespaces`).

## Browser exposure: Host and Origin (D-059)

A Loom in open dev mode on your laptop or LAN is reachable from every web
page your browser opens. The engine, the MCP http transport and the
gateway therefore refuse:

- a `Host` header outside the allowlist (400) — the tell of a DNS-rebinding
  page. Always allowed: `localhost`, IP addresses (kubelet probes use the
  pod IP), single-label service names (`loom`, `mcp`, `loom-gateway`) and
  `*.svc`, `*.svc.cluster.local`, `*.cluster.local`, `*.internal`.
  **Serving Loom under a real DNS name (an ingress, a reverse proxy)?**
  Add it: `LOOM_ALLOWED_HOSTS=loom.example.com,*.corp.example.com`
  (engine, `mcp` and gateway read the same variable). A cross-namespace
  client in Kubernetes should use `loom.<ns>.svc`, not `loom.<ns>`. `*`
  turns the check off — only behind a proxy that validates Host itself.
- a foreign `Origin` (403). Loopback origins (local tools such as the MCP
  Inspector) and same-origin requests pass; list others in
  `LOOM_ALLOWED_ORIGINS`. Agents, SDKs and shippers send no Origin.
- a body-carrying `/v1` request whose `Content-Type` is not JSON (415):
  `application/json`, `application/*+json` or an NDJSON spelling
  (`application/x-ndjson`). `text/plain` and form encodings are exactly
  what a cross-site page can send without a CORS preflight.

With auth on, a request with no key (401) or an unknown key (403) is
refused before its body is read or validated.

## Rate limits (R-10)

A valid reader can otherwise burn LLM spend on `/v1/answer` without
bound, and one noisy sender can starve the others. Both the engine and
the Go gateway keep **one token bucket per key** (per grant id — never per
raw header value, so an unauthenticated caller rotating bogus keys gets
no bucket at all) and answer `429` with `Retry-After` when it is empty.
Unset = unlimited, so a dev checkout is unchanged.

| Dial | Where | Meaning |
| --- | --- | --- |
| `LOOM_RATE_PER_SEC` | engine, MCP http, gateway | requests per second per key: every `/v1` route on the engine, every tool call on the MCP http transport, every ingest request on the gateway. A batch of *n* envelopes costs *n* on both the engine and the gateway. Fractions are fine (`0.5` = one every 2 s); a value that does not parse stops the engine, the MCP server and the gateway at start-up — never a silent "unlimited" |
| `LOOM_RATE_BURST` | engine, MCP http, gateway | bucket size (default: the rate — rounded up on the engine, down on the gateway, at least 1) |
| `LOOM_RATE_LLM_PER_SEC` | engine, MCP http | a second, stricter bucket per key for what spends LLM/embedder budget: `/v1/answer`, `/v1/entities/semantic`, and the MCP `answer` / `find_related` tools |
| `LOOM_RATE_LLM_BURST` | engine, MCP http | its bucket size (default: the rate, rounded up) |

Compose passes all four through from `.env` to the engine, the `mcp`
service and the gateway. The stdio MCP server is local trust and is not
limited.

**Buckets live in each process.** The effective ceiling for one key is
the dial × `LOOM_WORKERS` × engine replicas (and, separately, × gateway
replicas; the MCP server is its own process). With `LOOM_WORKERS=4` and 3
engine pods, `LOOM_RATE_LLM_PER_SEC=0.2` lets one key make up to 2.4
answers/s. Divide the dials by that product when you size them, or enforce
an exact global bound at a shared ingress / API gateway in front of Loom.

**A batch larger than the key's burst is refused with 413** (it could
never pass, so a 429 would only make a shipper retry forever). Size
`LOOM_RATE_BURST` (or the shipper key's `rate_burst`) at or above your
shippers' batch size — Vector's `max_events`, Fluent Bit's flush volume,
`loom.ingest --batch`.

**Per-key overrides** live in the keys file beside the grant, so one file
serves every tier (`rate_llm_per_sec` is ignored by the gateway, which has
no LLM routes):

```bash
python -m loom.keys generate --id dashboard --namespace netsec --perms r \
  --rate-per-sec 20 --rate-burst 60 --rate-llm-per-sec 0.2   # one answer every 5 s
python -m loom.keys update --id dashboard --rate-llm-per-sec 1    # loosen; hot-reloaded, no restart
python -m loom.keys update --id dashboard --rate-per-sec 0        # 0 = drop the override, defaults apply
```

An override applies even when the global dials are unset ("unlimited by
default, this key is capped"), and a tightened key's live bucket is
retuned on reload — the old, larger balance is not honoured. A zero or
negative value *in the file* is a configuration error that disables that
key entry (logged), not "unlimited": remove the field to lift a cap.

With auth disabled (open dev mode) the engine dials, when set, apply per
client IP; `/healthz`, `/readyz` and `/metrics` are never limited.

## Watching for trouble

- `loom_requests_rejected_total{reason="auth"|"scope"}` (engine) and
  `loom_gateway_rejected_unauthorized_total` (gateway) climbing = someone
  is probing or a sender is misconfigured.
- `loom_requests_rejected_total{reason="rate"}` (engine) and
  `loom_gateway_rejected_ratelimited_total` (gateway) = a key is over its
  budget; its own bucket protects everyone else. A steady climb on one
  reader's `/v1/answer` calls is the LLM-spend guard doing its job — raise
  that key's `rate_llm_per_sec` deliberately, not the global dial.
- `loom_requests_rejected_total{reason="host"|"origin"|"content_type"}`
  (engine) = browser-shaped requests refused (D-059). A burst of `host`
  right after you put Loom behind a new DNS name means
  `LOOM_ALLOWED_HOSTS` is missing that name.
- Auth denials name the key **id** (never the key) in error details, so a
  400-level spike traces to a principal.

## Data maintenance (D-016)

```bash
python -m loom.lifecycle export --out backup.jsonl           # backup / migration
python -m loom.lifecycle purge --namespace netsec --older-than-days 365
python -m loom.lifecycle redact --namespace netsec --observation-id <id> --reason "PII spill"
```

Schedule `purge` as a cron/k8s CronJob per your retention policy; `export`
before destructive maintenance.

### Correcting entity resolution

The enrichment worker folds entities it judges to be one thing (type drift,
spelling drift, an LLM's confident yes). Every merge is reversible, and a
reversal **sticks**: it records the pair as declined, which every
resolution tier — automatic and adjudicated — honors, so the worker does
not fold it again on its next tick (each resolution job re-reads the
declines, so an unmerge from another process is seen at once).

```bash
python -m loom.lifecycle unmerge --namespace netsec --alias ip_address:10.0.4.7   # split + remember
python -m loom.lifecycle unmerge --namespace netsec --alias ... --allow-remerge   # split only
python -m loom.enrich distinct host:web-01 host:web01 --namespace netsec          # never merge these
python -m loom.enrich undistinct host:web-01 host:web01 --namespace netsec        # take that back
```

`distinct` is the operator's ruling that two entities are different
things: it splits them first if one is folded into the other, and neither
tier will merge or ask about them again. Declines travel in `export` /
`import`. A settled group — every pair in it declined — also stops
occupying the resolver's candidate lists (type drift and spelling drift
alike), so declined groups never crowd out new collisions.

`undistinct` forgets the decline of one pair, whoever recorded it: a
`distinct`, an `unmerge`, or an adjudicator's no (an `export` lists them
as `decline` records). It merges nothing itself: the pair is a candidate
again, and the next resolution tick folds it if a tier would (type or
spelling drift) or asks the adjudicator anew. The worker re-reads declines
at the start of each job, so a running worker sees the change on its next
tick. It prints `{"forgotten": true, ...}`, or exits non-zero when no
decline of that pair was on record (handles are `type:key`, in either
order). An unmerge that recorded declines against both the merge target
and its current canonical needs one `undistinct` per pair.

Adjudication spend is bounded: at most 8 model calls per resolution job
per tick, whatever the replies say. A reply that cannot be read (verdicts
are read leniently — `"yes"`, `"True"`, `"90%"`, `"high"`, single-quoted
near-JSON — but never guessed) backs the pair off (1 min doubling to 1 h)
and after 3 such replies the pair is recorded as declined — never merged,
never billed again — with the reason `gave up after 3 unreadable
adjudication replies`. A provider outage (unreachable, 429, 5xx) ends
that job's pass for the tick without counting against the pair.

### Queue consumer settlement

A batch the store rejects is re-written one message at a time: good
envelopes land and are acked, and only the one that fails on its own is
redelivered (and dead-lettered with `Loom-Error-Code: store_rejected` on
its `LOOM_MAX_DELIVER`-th delivery). A claim citing a document the store
does not have yet — with two consumer replicas the document can be in the
other one's batch — is nak'd with a growing delay (`LOOM_PROVENANCE_RETRY`
seconds × delivery count, default 5) and dead-lettered with
`provenance_unresolved` on its last delivery, never silently dropped.

## What's deliberately NOT here (yet)

- **Admin HTTP API / UI** for key management — the file+CLI flow is the
  audited path for now; an API needs its own authz story (admin perms) and
  a distribution mechanism to gateways. Post-conference (see D-013a).
- **Per-entity / attribute ACLs** ("jdoe may see host web-01 but not
  db-01") — planned via the schema registry; entity-type + namespace
  granularity is the current boundary.
- **SSO/OIDC identity** — keys identify *principals* Loom-side; mapping
  them onto your IdP is an integration, not a core concern, until demand
  says otherwise.

## Environment reference: dials not covered above

Most settings are documented where they are used: `.env.example` (the
compose pass-through list), `deploy/README.md` "Scaling dials", and the
rate-limit table above. These remaining ones are read by the code but were
not written down anywhere else. Unset means the default shown.

| Variable | Read by | Default | What it does |
| --- | --- | --- | --- |
| `LOOM_HTTP_HOST` | engine (`python -m loom.serve`) | `0.0.0.0` | listen address. Deliberately not `LOOM_HOST`/`LOOM_PORT`: Kubernetes injects `LOOM_PORT=tcp://…` into every pod when a Service is named `loom` |
| `LOOM_HTTP_PORT` | engine | `8000` | listen port (non-numeric values fall back to the default) |
| `LOOM_BLOB_S3_PREFIX` | engine, workers (artifact offload) | `loom` | key prefix inside `LOOM_BLOB_S3_BUCKET` |
| `LOOM_KAFKA_BATCH` | `loom.kafka_consumer` | `200` | records fetched and committed per batch |
| `LOOM_KAFKA_CONNECT_TIMEOUT` | `loom.kafka_consumer` | `120` | seconds to keep retrying the first broker connection before exiting |
| `LOOM_WORKER_ID` | `loom.enrich` | hostname | worker identity recorded on leases |
| `LOOM_WORKER_SHARD` | `loom.enrich` | unset | explicit embedding-backlog shard as `i/n`; overrides the StatefulSet-ordinal split driven by `LOOM_WORKER_COUNT` |
| `LOOM_ENRICH_JOBS` | `loom.enrich run` (`--jobs`) | all | which jobs this worker runs: any of `extract, resolve, adjudicate, aliases, embed, index, chunk, dossiers`, or the groups `vectors` (embed, index, chunk — no LLM calls) and `llm` (extract, adjudicate, aliases, dossiers). Split a fleet into a `vectors` pool and an `llm,resolve` pool so a large backfill embeds at the embedder's pace instead of behind each extraction pass (D-063). A one-off backfill is `enrich run --once --jobs vectors` |
| `LOOM_LEASE_SECONDS` | `loom.enrich` | `600` | how long an artifact or dossier lease lasts before another worker may take it over (renewed per extraction window) |
| `LOOM_AGENT_THINKING` | `loom.agent_eval` | `adaptive` | `off` omits the thinking parameter on the Anthropic path |
| `LOOM_GATEWAY_ADDR` | Go gateway | `:8080` | listen address |
| `LOOM_SCHEMAS_PATH` | Go gateway | `/etc/loom/schemas.json` | the contract schema it validates envelopes against (baked into the image) |
| `LOOM_FORWARD_URL` | Go gateway | `http://loom:8000` | where envelopes go when `LOOM_NATS_URL` is unset (no queue) |
| `LOOM_URL`, `LOOM_SCHEMAS` | SDK test containers (`sdk-ts`, `sdk-go`) | set by compose | the live engine and the schema file the SDK tests use; not engine settings |

Not settings, despite the name: `LOOM_UUID_NS` is a constant in
`loom.connectors.stix` (the UUIDv5 namespace for deterministic STIX ids)
and `LOOM_CONTEXT` is the delimiter of the answer prompt's data block.
