# Recipes: one question per team

Each recipe is the tool calls an agent makes over MCP
([mcp-clients.md](mcp-clients.md)) and the same request over HTTP. MCP
handles are `"type:key"` strings; HTTP takes `{"type", "key"}` objects and
the request shapes in `src/loomctx/contracts.py`. Every result is cited,
and a set-valued answer carries an exact `total`.

## Data for the recipes

The outputs quoted below come from two reproducible corpora: the demo seed
plus the KEV and EPSS feeds in `netsec`, and a synthetic Active Directory
forest in `ad`.

```bash
docker compose up -d --wait loomctx
docker compose exec loomctx python -m loomctx.seed load
docker compose exec -T loomctx python -m loomctx.connectors.vulns load --namespace netsec \
    --sources kev,epss --bridge-seed-hosts --url http://localhost:8000
docker compose exec -T loomctx python -m loomctx.connectors.ad_gen --seed 7 --scale small \
    --style realistic --out /data/ad.ldif
docker compose exec -T loomctx python -m loomctx.connectors.ldap import /data/ad.ldif \
    --namespace ad --url http://localhost:8000
```

`--bridge-seed-hosts` gives the demo hosts `runs_software` edges; on your
own data they come from nmap or an inventory
([bring-your-own-data.md](bring-your-own-data.md)). Drop `--sources
kev,epss` to load NVD as well, which the CVSS recipe needs. In the forest
every object is keyed by its SID; the domain prefix is
`S-1-5-21-1111111111-2222222222-3333333333`, so Domain Admins is `…-512`.
On your own directory, `find_entity(query="Domain Admins")` gives the
handle.

The combined `within` filter and type aliases used below landed after
v0.2.0 (CHANGELOG, "Unreleased").

## Red team: from an account to Domain Admins

```text
find_path(namespace="ad",
          from="user:S-1-5-21-1111111111-2222222222-3333333333-2826",
          to="group:S-1-5-21-1111111111-2222222222-3333333333-512",
          via=["member_of", "has_ace"], depth=4)
# user:…-2826 -member_of-> group:…-2159 -member_of-> group:…-2168 -has_ace-> group:…-512
# three cites; node_status: user:…-2826 enabled True
```

```bash
curl -s -X POST localhost:8000/v1/path -H 'content-type: application/json' -d '{
  "namespace": "ad",
  "from": {"type": "user", "key": "S-1-5-21-1111111111-2222222222-3333333333-2826"},
  "to": {"type": "group", "key": "S-1-5-21-1111111111-2222222222-3333333333-512"},
  "via": ["member_of", "has_ace"], "depth": 4, "budget": 1500}'
```

The path is what exists in the export, shortest first; LoomCtx does not
score it. The `notes` say how many sideways steps through a shared group
it skipped (`siblings=true` follows them) and that `has_ace` is not local
admin. Depth is capped at 6.

## Red team: Kerberoastable admins

```text
list_entities(namespace="ad", type="user",
              where="kerberoastable=true; member_of within group:S-1-5-21-1111111111-2222222222-3333333333-512",
              fields=["enabled", "spn"])
run_query(namespace="ad", name="enabled_members", params={"group": "Domain Admins"},
          where="kerberoastable=true")
```

```bash
curl -s -X POST localhost:8000/v1/list -H 'content-type: application/json' -d '{
  "namespace": "ad", "type": "user", "fields": ["enabled", "spn"],
  "where": [{"predicate": "kerberoastable", "op": "eq", "value": true},
            {"predicate": "member_of", "op": "within",
             "value": "group:S-1-5-21-1111111111-2222222222-3333333333-512"}]}'
```

`within` follows nested membership (default depth 6). Both calls answer
`total: 0` on this forest, exactly: its 18 Kerberoastable accounts
(`run_query(name="kerberoastable_users")`) are service accounts outside
Domain Admins. A group name with a space works in the object form
(`"value": "group:Domain Admins"`) and in `run_query` params; the text
form needs the handle.

## Blue team / IR: who held the IP when the alert fired

```text
ask(namespace="netsec", subject="alert:AL-2291", question="where and when did this alert fire?")
# alert:AL-2291 triggered_on host:web-01 (2026-09-01, per ids)
ask(namespace="netsec", subject="ip:10.0.4.7", question="which host held this ip?",
    valid_at="2026-09-01T14:02:00Z")
# ip:10.0.4.7 assigned_to host:laptop-17 (2026-08-10, per dhcp-log) [valid 2026-08-10 to present]
ask(namespace="netsec", subject="ip:10.0.4.7", question="which host held this ip?",
    valid_at="2026-08-05T00:00:00Z")
# ip:10.0.4.7 assigned_to host:web-01 (2026-07-02, per dhcp-log) [valid 2026-07-02 to 2026-08-10]
```

```bash
curl -s -X POST localhost:8000/v1/ask -H 'content-type: application/json' -d '{
  "namespace": "netsec", "subject": {"type": "ip", "key": "10.0.4.7"},
  "question": "which host held this ip?", "valid_at": "2026-09-01T14:02:00Z", "budget": 400}'
```

`valid_at` is what was true at that moment; `as_of` is what was known
then. An alert that names an IP is about whoever held the lease at the
alert's time, not whoever holds it now.

## Blue team / IR: what the alert host runs that is exploited

```text
ask_scope(namespace="netsec", subjects=["host:web-01"],
          expand_predicates=["runs_software", "affects", "exploited_in_wild"], depth=2,
          question="is web-01 running anything exploited in the wild?")
# relation  host:web-01 runs_software product:openssl:openssl (per asset-inventory)
# fact      cve:CVE-2014-0160 (2022-05-04) exploited_in_wild True (per cisa-kev, valid from each date);
#           each affects product:openssl:openssl
```

```bash
curl -s -X POST localhost:8000/v1/ask -H 'content-type: application/json' -d '{
  "namespace": "netsec",
  "scope": {"subjects": [{"type": "host", "key": "web-01"}],
            "expand": ["runs_software", "affects", "exploited_in_wild"], "depth": 2},
  "question": "is web-01 running anything exploited in the wild?", "budget": 3000}'
```

`exploited_in_wild` holds a value, so the pack takes it as the topic rather
than an edge to walk, and says so in `notes`. The pack also leads with the
`runs_os` conflict on web-01 (two sources disagree); an agent must report
it, not pick a side.

## Vulnerability management: KEV exposure across hosts

```text
list_entities(namespace="netsec", type="host")                       # total 7
list_entities(namespace="netsec", of="host:web-01", via=["runs_software", "affects"],
              direction="any", depth=2, type="cve", where="exploited_in_wild=true", paths=true)
# cve:CVE-2014-0160  through product:openssl:openssl
# path "cve:CVE-2014-0160 -affects-> product:openssl:openssl <-runs_software- host:web-01", both edges cited
```

```bash
curl -s -X POST localhost:8000/v1/list -H 'content-type: application/json' -d '{
  "namespace": "netsec", "of": {"type": "host", "key": "web-01"},
  "via": ["runs_software", "affects"], "direction": "any", "depth": 2, "type": "cve",
  "where": [{"predicate": "exploited_in_wild", "op": "eq", "value": true}], "paths": true}'
```

Run the second call once per host for an exact list. `direction: "any"`
is needed because the chain points both ways (`host -runs_software->
product`, `cve -affects-> product`). For one ranked pack over many hosts,
pass them all to `ask_scope` as in the IR recipe.

## Vulnerability management: conflicting CVSS

```text
ask(namespace="netsec", subject="cve:<id>", question="how severe is this?")
# conflict  CONFLICT on cve:<id> cvss_score: <scorer A> says '…' as of …; <scorer B> says '…' as of …
ask_scope(namespace="netsec", subjects=["host:web-01"],
          expand_predicates=["runs_software", "affects", "cvss_score"], depth=2,
          question="where do scorers disagree on severity?")
```

```bash
curl -s -X POST localhost:8000/v1/ask -H 'content-type: application/json' -d '{
  "namespace": "netsec",
  "scope": {"subjects": [{"type": "host", "key": "web-01"}],
            "expand": ["runs_software", "affects", "cvss_score"], "depth": 2},
  "question": "where do scorers disagree on severity?", "budget": 3000}'
```

NVD records one `cvss_score` per scorer (NIST, the CNA, CISA's ADP, each
its own source), so needs the full feed load. Conflicts come first in a
pack and take at most half its budget; the rest are conflict handles to
`expand`. [real-data.md](real-data.md) has a real NIST-versus-CNA example.

## Identity governance: disabled accounts still in privileged groups

```text
list_entities(namespace="ad", type="user",
              where="enabled=false; member_of within group:S-1-5-21-1111111111-2222222222-3333333333-512")
```

```bash
curl -s -X POST localhost:8000/v1/list -H 'content-type: application/json' -d '{
  "namespace": "ad", "type": "user",
  "where": [{"predicate": "enabled", "op": "eq", "value": false},
            {"predicate": "member_of", "op": "within",
             "value": "group:S-1-5-21-1111111111-2222222222-3333333333-512"}]}'
```

Repeat per privileged group (`find_entity` resolves each name). On this
forest the answer is `total: 0` of 42 disabled accounts. `enabled=false`
lists accounts recorded as disabled; `enabled!=true` also counts accounts
whose status was never collected, and a note says how many.

## Identity governance: who has rights over a machine

```text
list_entities(namespace="ad", type="user",
              where="has_ace,member_of within computer:S-1-5-21-1111111111-2222222222-3333333333-2174")
# total 88: every account with an ACE on the computer, directly or through its groups
list_entities(namespace="ad", type="account",
              where="has_ace,member_of within computer:S-1-5-21-1111111111-2222222222-3333333333-2174 AND member_of within group:S-1-5-21-1111111111-2222222222-3333333333-512")
# which of them are Domain Admins (none on this forest); note: type 'account' is entity type 'user'
```

```bash
curl -s -X POST localhost:8000/v1/list -H 'content-type: application/json' -d '{
  "namespace": "ad", "type": "user",
  "where": [{"predicate": "has_ace,member_of", "op": "within",
             "value": "computer:S-1-5-21-1111111111-2222222222-3333333333-2174"},
            {"predicate": "member_of", "op": "within",
             "value": "group:S-1-5-21-1111111111-2222222222-3333333333-512"}]}'
```

A comma-separated predicate walks any mix of those edges. For each
account's cited route, list from the machine: `list_entities(of=…,
via=["has_ace", "member_of"], direction="in", depth=3, paths=true)`.
Every result carries the note `has_ace is not local groups …`: an ACE on
the computer object is a directory right, and LDAP does not collect local
administrators.
