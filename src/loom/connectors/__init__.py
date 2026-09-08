"""Connectors (D-035): scripted pulls of real, public data into Loom.

A connector is a domain adapter, like `loom.seed`, not core: it fetches a
source, maps it to the ingestion envelopes in `loom.contracts`, and hands
them to `loom.ingest`. The engine never learns what a CVE is — the
connector registers a schema for the namespace and everything else is data.
"""
