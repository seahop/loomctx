# Deploying Loom

Same images, same `/v1/ingest` contract, pick a shape:

| Shape | For | How |
| --- | --- | --- |
| Local Compose, default | development, demos on one machine | `docker compose up loom` |
| Local Compose, **scale** | rehearsing/exercising the ingestion tier | `docker compose --profile scale up -d --build --scale gateway=3` |
| Kubernetes, default | shared/team deployments | `kubectl apply -k deploy/k8s` |
| Kubernetes, **scale** | high-volume ingestion, SQLite kept (D-010) | `kubectl apply -k deploy/k8s/scale` |
| Kubernetes, **scale-pg** | everything autoscales, Postgres-backed (D-011) | edit `scale-pg/postgres-secret.yaml`, then `kubectl apply -k deploy/k8s/scale-pg` |

## Does it autoscale under load?

| Tier | default | scale | scale-pg |
| --- | --- | --- | --- |
| Ingest gateways | — (no gateway tier) | **HPA 2–10** on CPU | **HPA 2–10** on CPU |
| Burst absorption | none (direct writes) | NATS JetStream buffer | NATS JetStream buffer |
| Engine (ask/expand/answer) | fixed 1 (SQLite single writer) | fixed 1 (SQLite single writer) | **HPA 2–8** on CPU |
| Writer consumers | n/a | 1 (engine sidecar) | replicas (shared JetStream durable — raise freely) |
| Database | SQLite on PVC | SQLite on PVC | your Postgres (managed/operator — scale it there) |

So: **yes for ingestion** from the `scale` overlay up (gateways autoscale and
the queue absorbs what the writer hasn't caught up on), and **yes for
everything** in `scale-pg`, where the Postgres-backed store makes engine pods
stateless. The default shape deliberately does not autoscale — that's the
SQLite trade documented in D-008.

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

### Local cluster (kind/minikube) without GHCR

```bash
docker build -t ghcr.io/seahop/loom:dev .
kind load docker-image ghcr.io/seahop/loom:dev   # or: minikube image load ...
cd deploy/k8s && kustomize edit set image ghcr.io/seahop/loom:dev
kubectl apply -k .
```

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

- **Scaling the database (Postgres):**

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
