# Deploying Loom

Two supported shapes, same image, same behavior:

| Shape | For | How |
| --- | --- | --- |
| Local Docker Compose | development, demos on one machine | `docker compose up loom` |
| Kubernetes | shared/team deployments | `kubectl apply -k deploy/k8s` |

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
