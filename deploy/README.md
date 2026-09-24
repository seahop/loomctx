# Deploying Loom

Same images, same `/v1/ingest` contract, pick a shape:

| Shape | For | How |
| --- | --- | --- |
| Local Compose, default | development, demos on one machine | `docker compose up loom` |
| Local Compose, **scale** | rehearsing/exercising the ingestion tier | `docker compose --profile scale up -d --build --scale gateway=3` |
| Kubernetes, default | shared/team deployments | `kubectl apply -k deploy/k8s` |
| Kubernetes, **scale** | high-volume ingestion, SQLite kept (D-010) | `kubectl apply -k deploy/k8s/scale` |
| Kubernetes, **scale-pg** | everything autoscales, Postgres-backed (D-011) | edit `scale-pg/postgres-secret.yaml`, then `kubectl apply -k deploy/k8s/scale-pg` |
| Kubernetes, **scale-pg-ha** | + highly available Postgres run by CloudNativePG, reads on replicas (D-030) | install the operator (one `kubectl apply`, see the overlay), then `kubectl apply -k deploy/k8s/scale-pg-ha` |

## Does it autoscale under load?

| Tier | default | scale | scale-pg |
| --- | --- | --- | --- |
| Ingest gateways | — (no gateway tier) | **HPA 2–10** on CPU | **HPA 2–10** on CPU |
| Burst absorption | none (direct writes) | NATS JetStream (1 node) | NATS JetStream **3-node cluster**, streams replicated 3× |
| Engine (ask/expand/answer) | fixed 1 (SQLite single writer) | fixed 1 (SQLite single writer) | **HPA 2–8** on CPU |
| Writer consumers | n/a | 1 (engine sidecar) | replicas (shared JetStream durable — raise freely) |
| Database | SQLite on PVC | SQLite on PVC | your Postgres (managed/operator — scale it there); `scale-pg-ha`: CloudNativePG 3 instances, failover, reads on replicas |

So: **yes for ingestion** from the `scale` overlay up (gateways autoscale and
the queue absorbs what the writer hasn't caught up on), and **yes for
everything** in `scale-pg`, where the Postgres-backed store makes engine pods
stateless. The default shape deliberately does not autoscale — that's the
SQLite trade documented in D-008.

## Operating it

- **Metrics:** scrape the engine and each gateway at `GET /metrics`
  (Prometheus text). Watch `loom_gateway_rejected_*` for abuse,
  `loom_ingest_deduped_total` for retry storms, `loom_pack_build_seconds`
  for read latency.
- **Probes:** liveness `GET /healthz`; readiness `GET /readyz` (probes the
  store — a pod with a dead database drops out of the Service).
- **Auth:** the shipped manifests run in **open dev mode** (no keys) so a
  first `kubectl apply` just works inside the cluster. Before exposing
  anything, mint keys (`docs/administration.md`), create a Secret from the
  keys file, and mount it on the engine and gateways — the commented
  `LOOM_AUTH_FILE` blocks in `base/deployment.yaml`, `scale/gateway.yaml`
  and `scale-pg/gateway.yaml` show exactly where:

  ```bash
  kubectl -n loom create secret generic loom-keys --from-file=keys.json=secrets/keys.json
  ```

  Both engine and gateway hot-reload the file, so rotating keys is
  `kubectl create secret ... --dry-run=client -o yaml | kubectl apply -f -`
  with no restarts. Set `LOOM_HANDLE_SECRET` (any long random string, the
  same on every engine replica) alongside it so expansion handles are signed
  (D-021).

- **Host allowlist (D-059):** engine, MCP server and gateway answer 400 to
  a `Host` they don't recognise (DNS-rebinding defence). Pod IPs (probes),
  `localhost` (port-forward), Service names (`loom`, `loom-gateway`) and
  `*.svc` / `*.svc.cluster.local` pass by default. Behind an Ingress or a
  load balancer with a DNS name, add that name as `LOOM_ALLOWED_HOSTS` on
  the engine and gateway Deployments (`loom.example.com,*.corp.example.com`).

- **Rate limits (R-10, D-059):** `LOOM_RATE_*` and the keys file's per-key
  fields are enforced **per process** — the ceiling for one key is the
  dial × `LOOM_WORKERS` × replicas (HPA scale-out raises it). Size the
  dials for your replica count, or enforce an exact bound at the ingress.

- **Pod posture:** every pod runs as uid 10001 with a read-only root
  filesystem, no capabilities, no privilege escalation, and no
  ServiceAccount token mounted (nothing here talks to the Kubernetes API);
  writable paths are the data volume and an `emptyDir` at `/tmp`. Each
  shape ships a **default-deny ingress** NetworkPolicy plus one allowance
  per tier (engine and gateway HTTP from anywhere the cluster routes,
  NATS only from gateways and consumers, Postgres only from Loom's pods
  and the CNPG operator). Egress is deliberately left open — engines and
  workers call LLM/embedding providers, the feeds, and possibly an external
  Postgres. Enforcement needs a CNI that implements NetworkPolicy (Calico,
  Cilium, GKE Dataplane V2); kind's default CNI silently ignores it. A
  scraper that wants NATS's monitor port labels itself
  `loom.dev/scrape: "true"`. Tiers with ≥ 2 replicas carry a
  PodDisruptionBudget (`minAvailable: 1`, NATS `maxUnavailable: 1`) so a
  node drain never takes a whole tier.

- **Upgrading:** the engine migrates its store in place on first open
  (schema version in `loom_meta`; a current schema takes a no-DDL fast
  path). Every schema bump is proven on a populated database before it is
  tagged, not just on a fresh one (D-045): seed Postgres with the image
  from the previous schema's last commit, open the same database with the
  new image, check counts, the new tables, an `ask`, and that the second
  open is fast. Roll the engine first; workers and gateways tolerate both
  versions during the roll. An *older* image opening a *newer* database
  warns (`schema version N is newer than this build's M`), runs no DDL,
  never writes the version down, and serves what it understands — so a
  rollback is safe, it just ignores what it does not know.

  - **v5 → v6** (D-050, R-9): one column, `observations.supersedes`
    (recorded supersession; an older image ignores it), and five indexes —
    `observations (namespace, supersedes)`, `observations (subject_id,
    recorded_at)`, `artifacts (recorded_at)`, `entities (namespace,
    created_at)` and a partial one on `entities (dossier_claimed_until)`.
    `norm_key` is recomputed for entity keys carrying `:` (IPv6 and MAC
    addresses keep their separators). On Postgres the `CREATE INDEX`
    statements take the usual lock on a populated `observations` table
    for the duration of the build — open the new image once during a
    quiet window, or accept that the first engine pod to start does it.
    The enrichment workers now scan their backlogs from persisted
    high-water marks (`loom_meta` rows named `hwm:*`, forgotten by
    `wipe()`); a worker's first tick after the upgrade — and every 16th
    tick — is the old full scan, so nothing is missed and the marks take
    over from there. On SQLite, reads now use a small pool of WAL read
    connections beside the single writer (`LOOM_DB_READERS`, default 4;
    `0` restores the single connection).

**HPA prerequisite:** the cluster must run metrics-server (managed clusters
usually do; on kind/minikube enable it). Resource *requests* are set on every
container — HPA percentage targets are meaningless without them.

## The scale shape (D-010)

```
devices/SDKs -> load balancer -> Go ingest gateways (stateless, validate
against contracts/schemas.json) -> NATS JetStream -> writer consumer ->
store  ... while the Python engine serves /v1/ask unchanged
```

Locally the balancer is nginx on **:8081** (host :8080 is left alone since it
is commonly occupied); ingestion goes to `:8081/v1/ingest`, reads stay on
`:8000`. `--scale gateway=N` adds replicas and nginx round-robins across them
via Docker DNS with no config change. Invalid envelopes are rejected *at the
gateway* with a schema-precise error and never reach the queue.

On Kubernetes, the `scale` overlay adds NATS, an autoscaled gateway tier
(Service round-robin + HPA 2–10 replicas on CPU), and runs the writer consumer
as a sidecar of the engine pod so it shares the SQLite volume. The `scale-pg`
overlay is the fully horizontal version: point `postgres-secret.yaml` at your
Postgres and gateways, engines, and consumers all scale independently (the
consumers share one JetStream durable, so NATS spreads messages across
replicas). CI publishes `ghcr.io/seahop/loom-gateway` alongside the engine
image.

Manifest layout: `deploy/k8s/base/` holds the default resources;
`deploy/k8s/` is a thin wrapper so `kubectl apply -k deploy/k8s` keeps
working; `scale/` and `scale-pg/` are overlays.

## Kubernetes

**Validated 2026-09-08 on a real cluster** (Rancher Desktop, k3s v1.36,
docker runtime, local-path storage, metrics-server): all three shapes
rolled out from the shipped manifests — pods run as uid 10001 with the
`fsGroup` PVCs writable, `/readyz` reported the vector index
(`sqlite-vec` / `pgvector`), the HPAs were live (`cpu: 2%/70%`), NATS
persisted its stream on its PVC, and claims posted to the gateway Service
arrived through the queue and consumers in the store served by the engine
replicas. The `scale-pg` run used an in-cluster `pgvector/pgvector:pg17`
Deployment behind the `loom-db` Secret.

CI publishes the image to `ghcr.io/seahop/loom` (`latest` + per-commit SHA tags)
on every push to `main`; a `vX.Y.Z` tag push re-tags that commit's
already-published image as `:vX.Y.Z` rather than rebuilding it (D-045).
The repository is meant to be public; **as of 2026-09-24 it is still
private on GitHub, and so are the packages** (anonymous `docker manifest
inspect ghcr.io/seahop/loom:latest` is refused). GHCR package visibility is
a **separate** setting from the repository's: after flipping the repo, an
owner must open each package on GitHub (Packages → loom → Package settings
→ Change visibility) once, or the first pull fails with `denied`. Until
then — and for any private fork — the nodes need a pull secret: a GitHub
token with `read:packages`, attached to the namespace's default
ServiceAccount so no manifest changes:

```bash
kubectl -n loom create secret docker-registry ghcr --docker-server=ghcr.io \
  --docker-username=GITHUB_USER --docker-password="$GHCR_TOKEN"
kubectl -n loom patch serviceaccount default -p '{"imagePullSecrets":[{"name":"ghcr"}]}'
```

Then:

```bash
kubectl apply -k deploy/k8s
kubectl -n loom rollout status deploy/loom

# try it without an ingress
kubectl -n loom port-forward svc/loom 8000:80
curl -s localhost:8000/healthz

# load the demo dataset into the running pod's volume
kubectl -n loom exec deploy/loom -- python -m loom.seed load
```

Pin a specific version by editing `images:` in `deploy/k8s/kustomization.yaml`
to a SHA tag instead of `latest`.

### Validated on GKE (2026-09-10, D-043)

One zonal Standard cluster, `3 × e2-standard-4` in `us-central1-a`, the
`scale-pg-ha` overlay with CloudNativePG 1.26 on `standard-rwo` disks,
images from Artifact Registry, the seed plus the full vulnerability corpus
(482k observations) loaded, enrichment workers embedding. What a real
cloud enforces that a laptop cluster does not, and the recipe for each:

| It | On GKE | Recipe |
| --- | --- | --- |
| Image pulls | a new project's default compute service account has no roles | `gcloud projects add-iam-policy-binding PROJECT --member=serviceAccount:NUM-compute@developer.gserviceaccount.com --role=roles/artifactregistry.reader` (or pull from GHCR) |
| Your own build | CI images lag local commits | `docker tag loom-engine:local REGION-docker.pkg.dev/PROJECT/loom/loom:tag && docker push …`, then an overlay `images:` entry with `newName`, and roll by **digest** so a re-pushed tag is not served from the node cache |
| JetStream storage | PVC sizes are real; a 4 GiB stream on a 1 Gi claim is refused | NATS PVC is 8 Gi in the shipped manifest; keep `LOOM_STREAM_MAX_BYTES × LOOM_STREAM_REPLICAS` under it |
| Postgres storage | 2 Gi filled up under the corpus with vectors | 20 Gi in the shipped manifest. To grow a running cluster: `kubectl patch cluster loom-pg --type merge -p '{"spec":{"storage":{"size":"40Gi"}}}'`. If the instances are already down on a full disk the operator waits for the volume and the volume waits for a mount: patch the PVCs, mount each from a throwaway pod (busybox with the claim) until `kubectl get pvc` shows the new capacity, delete the pods, and the operator restarts the cluster |
| Provider keys | the engine and workers need `LOOM_LLM_*` / `LOOM_EMBED_*` | `kubectl -n loom create secret generic loom-llm --from-env-file=.env` and an `envFrom: [secretRef: {name: loom-llm}]` patch on `loom` and `loom-enrich`. **Strip inline comments and quotes first**: compose tolerates `LOOM_LLM_PROVIDER=openrouter  # …`, kubectl keeps the comment in the value, and the LLM is then silently unconfigured (the worker logs "no LLM configured") |
| A primary deletion takes three minutes to fail over | the stopping primary waits `smartShutdownTimeout` (operator default 180 s) for pooled client connections to close, and the replicas stay attached to it until then | the shipped `postgres-cluster.yaml` sets `smartShutdownTimeout: 10`; measured 183 s → 13 s to promote, 17 s write gap end to end (D-045) |
| A worker starting while Postgres is failing over | pool initialization times out after 180 s and the pod restarts (CrashLoopBackOff) until the primary is back | expected; nothing to do — it recovers on its own, but a long back-off can add minutes after the database returns: `kubectl -n loom delete pod -l app=loom-enrich` resets it |

**Measured** (one run each; treat as floors for this machine class):

| Path | Result |
| --- | --- |
| Direct load into the HA primary, one loader (`loom.connectors.vulns load --db`) | 715 envelopes/s, 530k in 12.4 min |
| Gateway → JetStream (3 replicas) → 2 consumers → Postgres, single envelopes | 175/s at concurrency 32 (p50 126 ms, p99 771 ms); 189/s at 128 (p50 596 ms) — every pod's CPU idle: the replicated stream acknowledgement over persistent disks is the bound |
| Same path, `POST /v1/ingest/batch` of 500 (what shippers send) | 660 envelopes/s accepted |
| `/v1/ask`, 2 engine replicas × 2 workers, reads on replicas, 482k observations | 287/s, p50 54 ms, p99 86 ms, 0 errors at concurrency 16 |
| Single-entity ask, first / cached question | 430–860 ms / 30–130 ms (the first pays one embedding call) |
| Two-hop scope, 1,077 entities reached | 1.4–2.4 s (was 5–6 s before the batched gather) |
| Primary pod deleted under 20,000 in-flight ingests | 0 client errors, 55,000/55,000 rows present, nothing redelivered or dead-lettered — the queue absorbed it |
| Write availability during a primary deletion | **11 s**, measured two ways on a clean cluster: a `psql` probe with `connect_timeout=2` through `loom-pg-rw`, and HTTP `POST /v1/ingest` through the engine every 0.5 s (3 failed requests of 617). Operator defaults with idle pools; with the workers holding connections the same deletion took 183 s to promote until `smartShutdownTimeout: 10` was set (D-045, 13 s to promote, 17 s write gap). The first measurement said 190 s — that was the *client* hanging in a TCP connect to the vanished primary, not the operator. Loom's pool now sets `connect_timeout=5` and TCP keepalives so engines and workers fail over with the database instead of waiting on the kernel |

The consumers lost two deadlocks to each other on entity upserts during
the run and retried them; no row was lost.

**What the operator owns on the CNPG cluster.** `scale-pg-ha` ships the
`Cluster` with instances, storage, the vector extension and the failover
timeout — and nothing about *your* durability or sizing, because those
are yours to decide: there is **no backup** and `max_connections` is the
Postgres default (100) until you say otherwise. A worked example that
goes in `postgres-cluster.yaml` (or a kustomize patch):

```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: loom-pg
spec:
  # ... instances, storage, bootstrap as shipped ...
  postgresql:
    parameters:
      # engines × LOOM_WORKERS × LOOM_DB_POOL + consumers + workers + the
      # operator's own; 8 engine pods × 2 × 4 = 64 already
      max_connections: "200"
      shared_buffers: "256MB"
  backup:
    barmanObjectStore:
      destinationPath: s3://YOUR-BUCKET/loom-pg
      s3Credentials:
        accessKeyId: {name: loom-pg-backup, key: ACCESS_KEY_ID}
        secretAccessKey: {name: loom-pg-backup, key: SECRET_ACCESS_KEY}
      wal: {compression: gzip}
    retentionPolicy: "30d"
---
apiVersion: postgresql.cnpg.io/v1
kind: ScheduledBackup
metadata:
  name: loom-pg-nightly
spec:
  schedule: "0 0 3 * * *"     # six fields: seconds first
  backupOwnerReference: self
  cluster: {name: loom-pg}
```

Continuous WAL archiving to the object store is what makes point-in-time
recovery possible; the ScheduledBackup is the base backup it replays from.
Restore by bootstrapping a new `Cluster` with `recovery` from the same
store (CNPG docs). `python -m loom.lifecycle export` remains the
backend-independent backup (JSONL) and is what you use to move between
SQLite and Postgres.

**Overnight soak (18 h, full enrichment pipeline on the real corpus):**
every tier at zero restarts except the enrichment workers, which the
vector-index backfill OOM-killed every few minutes at 200k vectors —
fixed (D-043), and the workers now run at the shipped 512 MiB limit. Give
workers 512 MiB; give Postgres 20 GiB per instance for a corpus this size
(2.1 GB used after the soak).

**Release gate (2026-09-11, D-045):** the image CI published for the tagged
build was re-deployed from GHCR onto a fresh cluster with the shipped
overlay and, with both enrichment workers live, loaded the corpus at 421/s,
took single-envelope ingest at 202/s and asks at 186/s with no errors, ran
every worker stage at 49 MiB resident under the 512 MiB limit with no
restarts, and survived two primary deletions with 16 s write gaps. Numbers
and the failover finding are in `docs/decisions.md`.

### Re-validated on GKE after the 2026-09-23 batch (2026-09-24, D-052)

The posture changes of D-048 (container securityContext with a read-only
root filesystem, no service-account token, default-deny NetworkPolicies,
PodDisruptionBudgets, non-root NATS, the bounded JetStream) had only been
kustomize-validated. Same recipe as D-043 — project `<PROJECT_ID>`, a fresh
zonal cluster (`3 × e2-standard-4`, `us-central1-a`, **Dataplane V2** so
NetworkPolicy is enforced), CloudNativePG 1.26, images built from `dda1051`
and pushed to Artifact Registry, the `scale-pg-ha` overlay rendered with
the images pinned by digest. The project had no `default` VPC any more
(`gcloud compute networks create default --subnet-mode=auto` first) and
`kubectl` needed `gke-gcloud-auth-plugin`; both are now in the recipe.

| Check | Result |
| --- | --- |
| Rollout | every pod Running with the new securityContext; NATS unprivileged on its PVC; engines restarted twice while the primary was still initializing (the documented pool-timeout case), nothing else restarted |
| NetworkPolicy | an unlabeled pod: `nats:4222` blocked, `loom-pg-rw:5432` blocked, `loom-gateway:80` open, `loom:80` open; gateways publish, consumers pull, the operator reaches the instance manager (the failover below completed) |
| Ingest through lb → 2 gateways → JetStream ×3 → 2 consumers → Postgres | 5,000 single envelopes at concurrency 32: **174/s, p50 128 ms, p99 802 ms, 0 errors**, 5,000/5,000 rows present (D-043: 175/s) |
| Asks, 2 engine replicas, reads on replicas | 3,000 at concurrency 16: **284/s, p50 55 ms, p99 78 ms, 0 errors**; the engine HPA scaled 2 → 6 during the run (D-043: 287/s) |
| Primary deleted under a 2/s write probe through the engine | promoted in **13.3 s**; **0 of 240 writes failed** (D-045: 3 of 617 — the pool's `connect_timeout` and keepalives now ride the gap); 240/240 rows present |
| Node drain (a node without the primary) | 33 s; PDBs allowed one NATS pod and one Postgres replica at a time; `/readyz` stayed `ready` throughout; every pod rescheduled; `loom-pg-primary` shows 0 allowed disruptions — draining the primary's node needs a switchover first (`kubectl cnpg promote`), by design |
| Enrichment workers without provider keys | idle with two log lines ("no embedder", "no LLM"), 0 restarts |

### Local cluster (kind/minikube/Rancher Desktop) without GHCR

```bash
docker compose build loom && docker compose --profile scale build gateway
docker tag loom-engine:local ghcr.io/seahop/loom:dev
docker tag loom-gateway:local ghcr.io/seahop/loom-gateway:dev
kind load docker-image ghcr.io/seahop/loom:dev   # minikube image load ...; Rancher Desktop
                                                  # on the docker runtime sees local images directly
```

Kustomize forbids absolute resource paths, so pin the `:dev` tags from an
overlay that layers on a *rendered* copy of the shipped manifests:

```bash
mkdir -p /tmp/loom && kubectl kustomize deploy/k8s > /tmp/loom/rendered.yaml
printf '%s\n' 'resources: ["rendered.yaml"]' 'images:' \
  '  - {name: ghcr.io/seahop/loom, newTag: dev}' \
  '  - {name: ghcr.io/seahop/loom-gateway, newTag: dev}' > /tmp/loom/kustomization.yaml
kubectl apply -k /tmp/loom
```

## Tying in existing pipelines (D-034)

Log shippers post batches to `POST /v1/ingest/batch`; Kafka topics feed
the `kafka` profile / `deploy/k8s/integrations/kafka-consumer.yaml`; files
load with `python -m loom.ingest`. Configs and the full table are in
[`integrations/README.md`](integrations/README.md).

## Scaling dials (D-027 / D-028)

Every dial is off by default: the single-container shape stays exactly as
simple as it is. Turn them when a measurement says to.

| Dial | Env / manifest | Default | When |
| --- | --- | --- | --- |
| Engine workers per pod | `LOOM_WORKERS` | 1 | Postgres shapes: 2–4 multiplies a pod's concurrency before adding pods |
| DB connections per worker | `LOOM_DB_POOL` | 4 | raise with `LOOM_WORKERS`; keep `workers × pool × pods` under Postgres `max_connections` |
| Read replica for the read path | `LOOM_DB_READ` (replica DSN) | unset | packs/search/export go to replicas, ingest and worker backlog stay on the primary; reads may lag by replication delay |
| Engine pods | HPA in `scale-pg` | 2–8 | stateless once on Postgres |
| Gateway pods | HPA in `scale` / `scale-pg` | 2–10 | ingestion bursts |
| Writer consumers | replicas in `scale-pg` | 2 | queue depth grows |
| Stream replicas | `LOOM_STREAM_REPLICAS` (gateway + consumer) | 1 (`scale-pg`: 3) | must match the NATS cluster size |
| Ingest buffer cap | `LOOM_STREAM_MAX_BYTES`, `LOOM_STREAM_DISCARD` | 1 GiB / old (`scale-pg`: 4 GiB) | storms degrade predictably instead of filling disks |
| Redelivery | `LOOM_ACK_WAIT`, `LOOM_MAX_DELIVER` (consumer) | 30 s / 5 | after the bound a message is parked on `LOOM_DEADLETTER` with the error, never dropped |
| Enrichment workers | `loom-enrich` StatefulSet replicas + `LOOM_WORKER_COUNT` (raise together) | 2 in `scale-pg` | document/LLM backlog grows; leases + sharding prevent double spend |
| Embedding throughput | `LOOM_EMBED_BATCH` (observations per embedder call, default 128) and `LOOM_CHUNK_LIMIT` (documents chunked per tick, default 4) | 128 / 4 | a hosted embedder takes 512–2048 per call; a 465k-observation backlog went from ~4 h to ~1 h with four sharded workers at 512 (D-039) |
| Embedding storage | `LOOM_EMBED_DIM` (Matryoshka output size, e.g. 512) | model native (1536 for text-embedding-3-small) | vectors are packed float32 (schema v3): 6 KB per 1,536-dim row plus the ANN index's copy; 512 dims is a third of that at most of the quality (D-039) |
| Alias resolution | `LOOM_ALIAS_TYPES` (entity types whose `vendor:product` keys get structural alias candidates, LLM-adjudicated each tick; e.g. `product`) | off | each candidate is one model call (~283 on the vulnerability corpus, ~3 cents with a flash-class judge); `python -m loom.enrich resolve --dry-run` lists candidates without asking (D-042) |
| Tenant shards | `LOOM_SHARDS` (namespace → DSN map; engines, consumers, workers) | unset | a heavy tenant needs its own database; move with `lifecycle export`/`import`, then flip the map |
| Artifact offload | `LOOM_BLOB_THRESHOLD` + `LOOM_BLOB_DIR` or `LOOM_BLOB_S3_BUCKET`/`_ENDPOINT` | unset | documents bloat the database; bodies above the threshold live in object storage, reinflated on every read |

### Measured capacity (2026-09-08, one laptop — treat as relative floors)

| Shape | Ingest | Ask | Notes |
| --- | --- | --- | --- |
| compose, SQLite, 1 worker | 507/s | — | D-011 (2026-09-03) |
| compose, Postgres, 1 connection | 388/s | 181/s, p99 178 ms | before D-028 |
| compose, Postgres, pool 4 | 416/s | 251/s, p99 93 ms | D-028 |
| compose, Postgres, pool 4 × 2 workers | 515/s | 184/s (CPU-bound laptop) | D-028 |
| k3s scale-pg, 2 gateways → 3-node JetStream → 2 consumers | 284/s acknowledged, 0 errors **while the stream leader was deleted** | — | D-029 |
| k3s scale-pg-ha, primary deleted under load | 319/319 sync writes ok | 319/319 reads ok | D-030 |

The generator ran on the same machine as everything it measured; the
numbers are floors and the *relative* changes are the point. Re-measure on
real nodes with `deploy/k8s/jobs/loadgen.yaml` before quoting capacity.

Real data on a schedule: `deploy/k8s/jobs/vulns-refresh.yaml` is a nightly
CronJob that pulls CISA KEV + NVD + EPSS into a small PVC cache and loads
them through the engine's batch API (D-035, `docs/real-data.md`).

## Choosing a database (D-011)

`LOOM_DB` is the whole decision — a file path means SQLite, a
`postgresql://` URL means Postgres. Both backends pass the same contract
tests and behave identically.

- **Singular setup (SQLite, default):** tuned for real input volume — WAL,
  batched transactions. Measured at ~507 claims/s (~44M/day) on one small
  container with zero errors, and the measuring tool ships in the image:

  ```bash
  docker compose run --rm loom python -m loom.loadgen --url http://loom:8000
  ```

- **Scaling the database (Postgres):** use an image with the `vector`
  extension (compose ships `pgvector/pgvector:pg17`) to get the ANN index
  (D-025); a plain Postgres works too and `/readyz` reports
  `"vector_backend": "exact"`.

  ```bash
  LOOM_DB=postgresql://loom:loom@postgres:5432/loom \
    docker compose --profile pg up -d loom postgres
  ```

  On Kubernetes, point the engine's (and consumer's) `LOOM_DB` env at your
  Postgres — at which point engine replicas can scale horizontally and the
  single-replica constraint below no longer applies.

## Why one replica?

The default store is SQLite on a ReadWriteOnce volume: exactly one writer, so
`replicas: 1` with a `Recreate` strategy. That is the *correct* shape for this
store, not a limitation of the manifests — it comfortably handles the target
workload (large context, small resources).

The scaling path (docs/decisions.md D-008) is swapping the `GraphStore` for a
server-backed implementation — Postgres ships (`scale-pg`); a graph
database such as Neo4j is a possible backend, not a shipped one. At that
point replicas scale horizontally and only the `LOOM_DB`-style config
changes. The API surface, image, and manifests stay the same.

No ingress is shipped: it is environment-specific. Add your cluster's usual
Ingress/HTTPRoute pointing at service `loom:80`, with keys mounted
(`docs/administration.md`) before exposing beyond the cluster.
