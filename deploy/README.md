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
  keys file, and mount it on the engine and gateways — the commented block
  in `base/deployment.yaml` shows exactly where:

  ```bash
  kubectl -n loom create secret generic loom-keys --from-file=keys.json=secrets/keys.json
  ```

  Both engine and gateway hot-reload the file, so rotating keys is
  `kubectl create secret ... --dry-run=client -o yaml | kubectl apply -f -`
  with no restarts. Set `LOOM_HANDLE_SECRET` (any long random string, the
  same on every engine replica) alongside it so expansion handles are signed
  (D-021).

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
on every push to `main`. Then:

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

### Local cluster (kind/minikube/Rancher Desktop) without GHCR

```bash
docker compose build loom && docker compose --profile scale build gateway
docker tag loom-engine:local ghcr.io/seahop/loom:dev
docker tag project2026-gateway ghcr.io/seahop/loom-gateway:dev
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
server-backed implementation (Postgres/Neo4j); at that point replicas scale
horizontally and only the `LOOM_DB`-style config changes. The API surface,
image, and manifests stay the same.

No ingress is shipped: it is environment-specific. Add your cluster's usual
Ingress/HTTPRoute pointing at service `loom:80`, plus auth (phase 5, OQ-3)
before exposing beyond the cluster.
