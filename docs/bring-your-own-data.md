# Bring your own data

The quickstart runs on a corpus we wrote. This page is for a team that
wants LoomCtx on its own exports: pick the connector, load the file,
check what landed, ask the first questions, and what to do when no
connector fits. Documents (incident reports, advisories) are at the end.

Everything runs in Docker. Start the engine first:

```bash
docker compose up -d --wait loomctx
```

The examples use one namespace, `corp`, for one environment. Connectors
default to `netsec`; pass `--namespace` to choose. One namespace per
environment or engagement keeps identities from two estates apart (D-083).

## 1. Pick the connector

| What you export | Connector | Load it with |
| --- | --- | --- |
| Active Directory as LDIF (`ldifde`, `ldapsearch`) | `ldap` | `python -m loomctx.connectors.ldap import - --namespace corp --as-of <export time>` |
| nmap XML (`nmap -oX`) | `nmap` | `python -m loomctx.connectors.nmap import - --namespace corp` |
| CISA KEV, NVD, FIRST EPSS (public feeds, no file) | `vulns` | `python -m loomctx.connectors.vulns load --namespace corp` |
| OSV / GitHub advisories (OSV JSON, a file or a directory) | `osv` | `python -m loomctx.connectors.osv import <path> --namespace corp` |
| A TIP's STIX 2.1 bundle | `stix` | `python -m loomctx.connectors.stix import <bundle.json> --namespace corp` |
| OCSF findings or detections (Security Lake, scanners, GuardDuty) | `ocsf` | `python -m loomctx.connectors.ocsf import - --namespace corp` |
| Entra ID users / groups / roles (Microsoft Graph JSON) | `entra` | `python -m loomctx.connectors.entra import <files> --namespace corp` |
| Okta users / groups / apps (Okta API JSON) | `okta` | `python -m loomctx.connectors.okta import <files> --namespace corp` |
| `terraform show -json` or an AWS Config snapshot | `cloud` | `python -m loomctx.connectors.cloud import - --format terraform\|awsconfig --namespace corp` |
| The MITRE ATT&CK enterprise bundle | `attack` | `python -m loomctx.connectors.attack import - --namespace corp` |
| Process lists and file listings (tasklist CSV, osquery results, `ps`, `ls`) | `endpoint` | `python -m loomctx.connectors.endpoint import <files> --host <host> --namespace corp` |
| Red-team operation logs (Atomic Red Team, Attire, CSV, JSONL) | `oplog` | `python -m loomctx.connectors.oplog import <files> --operation <name> --namespace corp` |
| Anything else | none | [section 5](#5-when-no-connector-fits) |

Every file connector takes `import` (load), `emit` (write NDJSON envelopes
to stdout instead) and `schema` (print the registry it declares); `vulns`
has `load`, `pull`, `emit` and `schema`, and `stix` and `ocsf` also
`export`. Flags,
mapping tables and what each one does not map are in
[interop.md](interop.md) and, for the feeds, [real-data.md](real-data.md).
Before writing a connector, check whether the tool can export STIX or
OCSF: those load with no new code.

## 2. Load it

The connectors run inside the engine container. A file reaches them one of
two ways:

- **stdin**, for the connectors that read `-` (`ldap`, `nmap`, `ocsf`,
  `osv`, `cloud`, `attack`): `docker compose exec -T loomctx python -m … import - < file`.
- **`docker compose cp`**, for the ones that take paths (`entra`, `okta`,
  `stix`, `endpoint`, `oplog`):
  `docker compose cp users.json loomctx:/tmp/users.json`, then import `/tmp/users.json`.

Pass `--url http://localhost:8000` to send the envelopes through the
engine's batch API, so they pass the same gates as any other sender. With
API keys on, add `--key` with a write key (or set `LOOMCTX_API_KEY`). A
connector registers its schema before it sends claims, and registering
needs a write key with no entity-type or source gates; with a gated
sender key, register once with an ungated key and pass `--no-schema` to
the file connectors' `import`
([administration.md](administration.md)). Without `--url` the connector
writes straight into the store `LOOMCTX_DB` names (see real-data.md for
that form).

Every load prints one JSON line of totals; read `rejected`. The `ldap`,
`entra`, `okta` and `vulns` loads also exit non-zero when anything was
rejected, so a scheduled import fails visibly. Event ids
embed each record's own timestamp: loading the same export twice adds
nothing, and a later export records history instead of overwriting.

### Active Directory (LDIF)

Export the domain to LDIF on a machine that can read the directory. How
you export depends on your tooling (illustrative, not run here):
`ldifde -f export.ldif` on a domain controller, or `ldapsearch` with the
attributes the connector reads. The rights edges (`has_ace`) come from
`nTSecurityDescriptor`, which most exports leave out unless asked for it.
The full attribute list is in
[interop.md](interop.md#raw-ldap--ldif-active-directory--loomctx).

```bash
docker compose exec -T loomctx python -m loomctx.connectors.ldap import - \
    --namespace corp --as-of 2026-09-20T09:00:00Z --url http://localhost:8000 < export.ldif
# {"total": 76, "recorded": 76, "accepted": 0, "rejected": 0, "envelopes": {"object": 9}, "drift": []}
```

That output is from `tests/fixtures/corp_ad.ldif`, a nine-object synthetic
export you can try first. `--as-of` sets the export time when the LDIF has
no `# <ISO date>` comment. Read from stdin, the file has no modification
time to fall back on, so without either the import is stamped "now" and a
second run is a new export, not a replay. Pass it.

For a directory of realistic size without real data,
`python -m loomctx.connectors.ad_gen --scale small --style realistic --out /data/ad.ldif`
writes a synthetic forest (848 objects at `small`) with known paths to
Domain Admins planted in it ([ad-eval.md](ad-eval.md)).

### nmap

```bash
nmap -sV -O -oX scan.xml 10.0.0.0/24      # your authorised scope; illustrative, not run here
docker compose exec -T loomctx python -m loomctx.connectors.nmap import - \
    --namespace corp --url http://localhost:8000 < scan.xml
# {"total": 23, "recorded": 22, "accepted": 1, "rejected": 0, "envelopes": {"document": 1, "claim": 21}, "drift": []}
```

(Output from `tests/fixtures/nmap_inventory.xml`.) The connector parses the
report; it never scans. The one `accepted` envelope is the scan report
itself, stored as a document that every claim cites. Each host becomes
`host:<hostname or ip>` with `listens_on_port`, `runs_service`, a
lower-confidence `runs_os` guess, and `runs_software` edges to
`product:<vendor>:<product>`.

### Vulnerability feeds (KEV, NVD, EPSS)

```bash
docker compose exec -T loomctx python -m loomctx.connectors.vulns load \
    --namespace corp --url http://localhost:8000
```

This downloads this year's NVD feed (about 40 MB), the KEV catalogue and
EPSS into the container's cache, registers the schema and loads. For a
fast first pass, `--sources kev,epss` skips NVD: about 14,000 envelopes in
under ten seconds. A download that fails three times stops the load; run
it again and the feeds already cached are not fetched twice.

The feeds join your scans on the product key. nmap's `runs_software` and
NVD's `affects` both point at `product:<vendor>:<product>`, so a host
reaches its CVEs as `host -runs_software-> product <-affects- cve`. Where
nmap names the vendor differently (it keys nginx as `igor_sysoev:nginx`),
the two do not meet until entity resolution merges them
(`python -m loomctx.enrich resolve`, which needs an LLM; see
[real-data.md](real-data.md)) or you send a `runs_software` claim for the
NVD key yourself.

## 3. Check what landed

Over MCP (any client from [mcp-clients.md](mcp-clients.md)):

- `list_namespaces()`: every namespace with entity counts by type.
- `describe_namespace(namespace="corp")`: each type's `links`
  (`-runs_software-> product`, `<-affects- cve`) and `attributes`, the
  registered predicates with their `aliases`, the namespace's named
  `queries`, and what its sources declare `not_collected`.

Over HTTP:

```bash
curl -s 'localhost:8000/v1/schemas?namespace=corp' | python3 -m json.tool          # the registry
curl -s 'localhost:8000/v1/entities/search?q=svc-sql' -H 'X-LoomCtx-Namespace: corp' # name -> entity
curl -s 'localhost:8000/v1/entities/user/S-1-5-21-1111111111-2222222222-3333333333-1106/observations' \
     -H 'X-LoomCtx-Namespace: corp' | python3 -m json.tool                          # raw rows
```

AD objects are keyed by objectSid, so search by name first: `svc-sql`
resolves to `user:S-1-5-21-…-1106`.

Then ask what the imports did **not** carry:

```bash
docker compose exec -T loomctx python -m loomctx.coverage gaps --namespace corp --url http://localhost:8000
# [{"source": "ad-export", "scope": "domain:corp.local", "predicate": "has_ace",
#   "state": "absent", "with": 0, "of": 8}]
```

That fixture has no security descriptors, so none of its 8 objects carry
rights edges. An agent sees the same fact as a `coverage:` note on any
pack or path that walks `has_ace`, and reports "not collected" rather than
"nobody has rights". `coverage drift` lists fields that appeared or
vanished between two imports of the same source.

## 4. Ask the first questions

Over MCP, an agent's first calls on a new namespace look like this:

```text
describe_namespace(namespace="corp")
find_entity(query="svc-sql", namespace="corp")                  # -> user:S-1-5-21-…-1106
run_query(name="kerberoastable_users", namespace="corp")        # svc-sql, with its SPNs, cited
run_query(name="asrep_roastable_users", namespace="corp")       # jdoe
ask(subject="user:S-1-5-21-…-1106", question="what can this account reach?", namespace="corp")
# -> its facts (member_of Help Desk, kerberoastable, two SPNs), plus the note
#    "coverage: 'has_ace' was not collected by ad-export (domain:corp.local) …"
```

The same over HTTP:

```bash
curl -s -X POST localhost:8000/v1/query -H 'content-type: application/json' \
     -d '{"namespace": "corp", "name": "kerberoastable_users"}' | python3 -m json.tool
curl -s -X POST localhost:8000/v1/list -H 'content-type: application/json' -d '{
  "namespace": "corp", "type": "user",
  "where": [{"predicate": "no_preauth", "op": "eq", "value": true}],
  "fields": ["enabled"]
}' | python3 -m json.tool
```

Named queries come with the connector (the LDAP ones are listed by
`describe_namespace`); `list_entities` / `POST /v1/list` answers any other
"which entities…" question exactly. More questions, one per team, are in
[recipes.md](recipes.md).

## 5. When no connector fits

Say your EDR exports devices as JSON or CSV. There is no connector for
it, and you do not need one: send claims. LoomCtx creates types and
predicates on first use. Registering them is optional, and worth it once
the names settle, because the registry is where agents learn your domain.

### Draft the registration

```bash
docker compose exec -T loomctx python -m loomctx.registry draft - --namespace edr < edr_export.json
```

For `{"devices": [{"device_id": …, "hostname": …, "os": …}]}` the drafter
proposes a `device` type, one predicate per field and `hostname` as a
label, and writes its doubts as `#` lines on stderr. It never registers
anything. Details: [real-data.md](real-data.md#draft-the-registration-from-a-sample-d-106).

### Register and send with the Python SDK

The SDK is one stdlib-only module (`sdk/python/`, install notes in its
README). This script registers the domain, then turns two CSV rows into
claims:

```python
import csv, io, os
from loomctx_sdk import LoomCtx

loomctx = LoomCtx(os.environ.get("LOOMCTX_URL", "http://localhost:8000"), namespace="edr",
                  api_key=os.environ.get("LOOMCTX_API_KEY"))

loomctx.register_schema(
    entity_types=[
        {"name": "asset", "description": "an endpoint the EDR agent runs on",
         "aliases": ["host", "machine", "endpoint"]},
        {"name": "person", "description": "the asset's owner", "aliases": ["owner", "user"]},
    ],
    predicates=[
        {"name": "runs_os", "description": "operating system the agent reports",
         "aliases": ["operatingSystem", "os"]},
        {"name": "owned_by", "object_types": ["person"], "aliases": ["owner"]},
        {"name": "agent_version", "description": "EDR agent build, not the OS patch level"},
        {"name": "isolated", "description": "the agent has network-isolated the asset",
         "node_status": True},
        {"name": "hostname", "label": True},
    ],
    not_collected=[
        {"topic": "patch_level",
         "description": "OS patch level and missing updates; the EDR export does not carry them",
         "words": ["patched", "patch level", "missing updates"],
         "source": "edr-export",
         "mistaken_for": ["agent_version"]},
    ],
)

EXPORT = """device_id,hostname,os,owner,agent_version,isolated,last_seen
d-1001,web-01,Ubuntu 22.04,jdoe,7.14.2,false,2026-10-20T08:00:00Z
d-1002,db-01,Ubuntu 22.04,asmith,7.13.0,true,2026-10-20T08:05:00Z
"""

envelopes = []
for row in csv.DictReader(io.StringIO(EXPORT)):
    asset = {"type": "asset", "key": row["device_id"]}
    facts = [("hostname", row["hostname"]), ("runs_os", row["os"]),
             ("owned_by", {"type": "person", "key": row["owner"]}),
             ("agent_version", row["agent_version"]),
             ("isolated", row["isolated"] == "true")]
    for predicate, value in facts:
        envelopes.append({
            "kind": "claim", "namespace": "edr",
            "event_id": f"edr:{row['device_id']}:{predicate}:{row['last_seen']}",
            "subject": asset, "predicate": predicate, "object": value,
            "observed_at": row["last_seen"], "source": "edr-export"})

result = loomctx.ingest_batch(envelopes)
print(result["recorded"], "recorded,", result["rejected"], "rejected")
```

Run it in a throwaway container on the compose network, with the SDK
mounted, so nothing installs on the host:

```bash
docker compose run --rm -T -v "$PWD/sdk/python:/sdk:ro" -e PYTHONPATH=/sdk \
    -e LOOMCTX_URL=http://loomctx:8000 loomctx python - < send_edr.py
# 10 recorded, 0 rejected
```

The `event_id` is the device, the predicate and the export time, so a
second run of the same export records nothing new.

What the registration buys:

- **`aliases`** are the other names a question uses. `list_entities(type="machine",
  where="operatingSystem~=ubuntu")` lists both assets, with the notes
  `type 'machine' is entity type 'asset'` and `'operatingSystem' is
  predicate 'runs_os'`. A name two definitions both claim maps to neither.
- **`label`** makes `find_entity("web-01")` return `asset:d-1001`.
- **`node_status`** puts the value on every path that passes through the
  entity, cited, so a path through an isolated asset says so.
- **`not_collected`** says what the source cannot answer. Ask "is this
  machine patched?" and the pack carries `not collected by this
  namespace's sources: OS patch level …` instead of an empty answer.
  **`mistaken_for`** names facts that look like the answer and are not:
  any listing, pack or path that shows `agent_version` adds
  `agent_version is not patch level: … do not present these rows as it`.
  The LDAP connector ships the same pair for `has_ace` and local admin.
- **`queries`** (not used above) registers a named, parameterised listing
  an agent runs by name; see `QueryDef` in [contracts.md](contracts.md).

When the names stop changing, register again with `"strict": true` and the
namespace rejects predicates and types it does not know, on every write
path. Registration is additive: a later call merges by name.

The full build of a new domain, from an empty store to an agent, is
[tutorial.md](tutorial.md).

## 6. Documents

Incident reports, advisories and pentest write-ups go in as documents:

```bash
curl -s -X POST localhost:8000/v1/ingest -H 'content-type: application/json' -d '{
  "kind": "document", "namespace": "ir", "event_id": "ir-4432",
  "filename": "IR-4432.txt", "source": "ir-team",
  "observed_at": "2026-09-02T09:00:00Z",
  "text": "Incident IR-4432. On 1 September an attacker used a reused SSH key to log in to web-01 and moved laterally to db-01 over port 5432. web-01 was rebuilt on 3 September; db-01 credentials were rotated."
}'
# {"status":"accepted","artifact_id":"23f9beda…","extraction":"pending"}
```

The envelope is `DocumentIn`: exactly one of `text` (up to 1,000,000
characters) or `content_b64`, plus `source`, `observed_at`, and optional
`event_id`, `filename`, `content_type` and `attrs`. The engine stores it
verbatim and answers `202`; `GET /v1/artifacts/{id}` returns it. Only
`text` is ever mined or searched: a PDF sent as `content_b64` is kept but
never read, so convert it to text first.

A stored document connects to entities in three ways.

**You cite it from claims (no LLM, no embedder).** A claim's
`provenance.artifact_event_id` names the document by its `event_id`; the
engine resolves it to the artifact id at ingest. Send the document first
(the same batch is fine):

```bash
curl -s -X POST localhost:8000/v1/ingest/batch -H 'content-type: application/json' -d '[
  {"kind": "claim", "namespace": "ir", "event_id": "ir-4432:c1",
   "subject": {"type": "incident", "key": "IR-4432"}, "predicate": "affected",
   "object": {"type": "host", "key": "web-01"}, "observed_at": "2026-09-02T09:00:00Z",
   "source": "ir-team", "provenance": {"artifact_event_id": "ir-4432"}},
  {"kind": "claim", "namespace": "ir", "event_id": "ir-4432:c2",
   "subject": {"type": "incident", "key": "IR-4432"}, "predicate": "affected",
   "object": {"type": "host", "key": "db-01"}, "observed_at": "2026-09-02T09:00:00Z",
   "source": "ir-team", "provenance": {"artifact_event_id": "ir-4432"}}
]'
```

The raw observations now carry `provenance.artifact_id`, so an agent can
go from a cited fact to the report (`get_observations` on the cite, then
`GET /v1/artifacts/{id}`). This is how the nmap and KEV connectors link
their own reports.

**The worker mines it (needs `LOOMCTX_LLM_*`).** `python -m loomctx.enrich
run --once` (or the `enrich` compose profile) asks the configured model
for claims, each with the span it came from. Extracted claims carry
`attrs.extracted = true`: they rank below claims a sender asserted, cannot
corroborate or contradict a structured source on their own, and a scope walk does
not follow their edges unless asked (`follow_extracted`), so a hostile
document cannot rewrite the graph. Without an LLM the worker logs
`no LLM configured … skipping extraction/dossiers` and moves on.

**Its passages rank into packs (needs `LOOMCTX_EMBED_*` on the worker and
on the engine).** The worker splits the text into passages and embeds
them. A pack about an entity whose facts cite the document can then carry
`doc_excerpt` items, each naming who it is about and the span it quotes,
with an `excerpt` handle that reads the passages around it.
`find_related` searches passages too. After one worker pass, the same ask
about web-01 leads with:

```text
doc_excerpt  [about incident:IR-4432] "Incident IR-4432. On 1 September an attacker used a
             reused SSH key to log in to web-01 …" [doc:23f9beda @0-198]
fact         incident:IR-4432 affected host:web-01 (2026-09-02, per ir-team)
```

To try this offline, set `LOOMCTX_EMBED_PROVIDER=hashing` on both. It is a
word-hashing embedder: enough to see excerpts appear, not semantic
ranking. A real embedding model is configured in `.env` (`.env.example`
lists the variables).

| You want | Needs |
| --- | --- |
| The document stored and readable (`GET /v1/artifacts/{id}`) | nothing |
| Facts that cite it (`provenance.artifact_event_id`) | nothing |
| Claims mined from the text, with spans | `LOOMCTX_LLM_*` on the worker |
| `doc_excerpt` items in packs, `find_related` over passages | `LOOMCTX_EMBED_*` on the worker and the engine |
| A per-entity brief (dossier) in packs | `LOOMCTX_LLM_*` on the worker |
