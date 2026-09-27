"""Connectors (D-035): scripted pulls of real, public data into Loom.

A connector is a domain adapter, like `loom.seed`, not core: it fetches a
source, maps it to the ingestion envelopes in `loom.contracts`, and hands
them to `loom.ingest`. The engine never learns what a CVE is — the
connector registers a schema for the namespace and everything else is data.

    vulns   CISA KEV + NVD + EPSS feeds (D-035)
    stix    STIX 2.1 bundles, both directions (R-8; docs/interop.md)
    ocsf    OCSF vulnerability_finding events, both directions (R-8)
    ldap    raw LDAP / LDIF directory exports -> object-level AD reachability
            claims (D-065; docs/interop.md)
    entra / okta   identity-provider exports (D-075/D-076)
    nmap / osv / cloud / attack   scans, advisories, cloud inventory, ATT&CK
    endpoint   process lists and file listings (D-084)
    oplog      red-team operation logs, for the purple report (D-086)

Every connector writes into one namespace per environment (`netsec` by
default) and states identifiers (D-083), coverage (D-082) and the shape of
what it read (D-085).
"""
