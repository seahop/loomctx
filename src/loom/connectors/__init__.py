"""Connectors (D-035): scripted pulls of real, public data into Loom.

A connector is a domain adapter, like `loom.seed`, not core: it fetches a
source, maps it to the ingestion envelopes in `loom.contracts`, and hands
them to `loom.ingest`. The engine never learns what a CVE is — the
connector registers a schema for the namespace and everything else is data.

    vulns   CISA KEV + NVD + EPSS feeds (D-035)
    stix    STIX 2.1 bundles, both directions (R-8; docs/interop.md)
    ocsf    OCSF vulnerability_finding events, both directions (R-8)
"""
