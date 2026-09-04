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

All commands run in the container (`docker compose run --rm -v $PWD/secrets:/secrets loom python -m loom.keys --file /secrets/keys.json ...`).

**Onboard a sender** (a log shipper that may only write auth-log facts about
hosts/users/ips into netsec, expiring in 6 months):

```bash
python -m loom.keys --file keys.json generate --id netsec-authlog-shipper \
  --namespace netsec --perms w --entity-types host,user,ip \
  --sources auth-log --expires-days 180
# -> prints loomk_... ONCE; put it in the shipper's config (X-Loom-Key)
```

**Onboard a user** (an analyst whose agent may query netsec, but only
host/ip/alert data — not, say, HR entities another team ingests):

```bash
python -m loom.keys --file keys.json generate --id analyst-jdoe \
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
python -m loom.keys --file keys.json update --id analyst-jdoe \
  --entity-types host,ip,alert,domain,user       # widen
python -m loom.keys --file keys.json update --id analyst-jdoe --perms rw  # allow write-back
```

**Rotate a credential** (suspected leak, scheduled rotation):

```bash
python -m loom.keys --file keys.json generate --id analyst-jdoe-2 --namespace netsec --perms r --entity-types host,ip,alert,domain
# hand over the new key, then:
python -m loom.keys --file keys.json revoke --id analyst-jdoe
```

**Offboard:** `revoke --id ...` — takes effect on the next reload (seconds
locally, ≤ ~1 min on k8s). Their history remains attributed in the
observations they wrote (`source`, and their writes are in the append-only
record).

**Review who has access:** `python -m loom.keys --file keys.json list` —
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

## Watching for trouble

- `loom_requests_rejected_total{reason="auth"|"scope"}` (engine) and
  `loom_gateway_rejected_unauthorized_total` (gateway) climbing = someone
  is probing or a sender is misconfigured.
- `loom_gateway_rejected_ratelimited_total` = a sender is misbehaving; its
  per-key bucket protects everyone else.
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
