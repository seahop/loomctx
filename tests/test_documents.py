"""Documents tied to structured data (D-118): deterministic mention links at
ingest, and finding a document by its words with no embedder."""
import asyncio
import os
from datetime import datetime, timezone

import pytest

import loomctx.listing as listing
import loomctx.mcp_server as mcp_server
from loomctx.context import build_pack
from loomctx.contracts import (
    AskRequest, ClaimIn, DocumentIn, DocumentSearchRequest, EntityRef, EntityTypeDef, ListRequest, PredicateDef,
    SchemaRegistration,
)
from loomctx.docsearch import search_documents, terms_of
from loomctx.mentions import link_mentions
from loomctx.store.sqlite import SqliteStore

NS = "ad"
T1 = datetime(2026, 9, 1, tzinfo=timezone.utc)
T2 = datetime(2026, 9, 14, tzinfo=timezone.utc)
SVC = EntityRef(type="user", key="S-1-5-21-1-95320")
JDOE = EntityRef(type="user", key="S-1-5-21-1-95312")
WS = EntityRef(type="computer", key="S-1-5-21-1-95300")
IR_KERB = """IR-2026-031: suspected Kerberoasting

On 14 September the SOC saw a burst of TGS requests for MSSQLSvc/svc-sqladm.corp.local:1433 from
workstation WS-AUDIT01. The analyst suspects the svc-sqladm account was Kerberoasted; its password
was rotated the same day. CVE-2026-0544 was ruled out as the entry point."""
IR_PHISH = """IR-2026-029: phishing

A credential-harvesting email reached the operations team on 9 September. One user, jdoe-ops, entered
their password on the fake portal before the link was blocked."""


@pytest.fixture(params=["sqlite", "postgres", "sharded"])
def store(request, tmp_path):
    if request.param == "sqlite":
        s = SqliteStore(tmp_path / "docs.db")
    elif request.param == "sharded":
        from loomctx.store.sharded import ShardedStore
        s = ShardedStore(SqliteStore(tmp_path / "a.db"), {"other": SqliteStore(tmp_path / "b.db")})
    else:
        url = os.environ.get("LOOMCTX_TEST_POSTGRES_URL")
        if not url:
            pytest.skip("LOOMCTX_TEST_POSTGRES_URL not set")
        from loomctx.store.postgres import PostgresStore
        s = PostgresStore(url)
        s.wipe()
    s.put_schema(SchemaRegistration(namespace=NS, entity_types=[
        EntityTypeDef(name="user"), EntityTypeDef(name="computer"), EntityTypeDef(name="cve")],
        predicates=[PredicateDef(name="sam", label=True), PredicateDef(name="name", label=True),
                    PredicateDef(name="enabled")]))
    for ref, sam in ((SVC, "svc-sqladm"), (JDOE, "jdoe-ops")):
        s.record_claim(ClaimIn(namespace=NS, subject=ref, predicate="sam", object=sam, observed_at=T1, source="ldap"))
        s.record_claim(ClaimIn(namespace=NS, subject=ref, predicate="enabled", object=True, observed_at=T1,
                               source="ldap"))
    s.record_claim(ClaimIn(namespace=NS, subject=WS, predicate="name", object="WS-AUDIT01", observed_at=T1,
                           source="ldap"))
    s.record_claim(ClaimIn(namespace=NS, subject=EntityRef(type="cve", key="CVE-2026-0544"), predicate="cvss_score",
                           object=9.8, observed_at=T1, source="nvd"))
    yield s
    s.close()


def _ingest(store, text, event):
    art = store.store_artifact(DocumentIn(namespace=NS, event_id=event, text=text, source="ir-notes",
                                          observed_at=T2))
    return art, link_mentions(store, art)


def test_a_document_is_linked_to_the_entities_it_names(store):
    art, n = _ingest(store, IR_KERB, "ir-031")
    assert n == 3     # svc-sqladm (by its login), WS-AUDIT01 (by name), CVE-2026-0544 (by key)
    doc = EntityRef(type="document", key=art.id)
    rows = store.lite_rows(NS, [doc], ["mentioned_in"], side="object")
    assert {r.subject for r in rows} == {("user", SVC.key), ("computer", WS.key), ("cve", "CVE-2026-0544")}
    # each link is cited to where the document names the entity
    obs = store.observations_for_many(NS, [SVC], predicates=["mentioned_in"], limit=5)
    mention = next(o for rows in obs.values() for o in rows)
    assert mention.provenance.artifact_id == art.id
    assert IR_KERB[mention.provenance.span_start:mention.provenance.span_end] == "svc-sqladm"
    # idempotent: linking again records nothing new
    assert link_mentions(store, art) == 3
    assert len(store.lite_rows(NS, [doc], ["mentioned_in"], side="object")) == 3


def test_documents_are_found_by_their_words_and_lead_to_entities(store):
    kerb, _ = _ingest(store, IR_KERB, "ir-031")
    phish, _ = _ingest(store, IR_PHISH, "ir-029")
    page = search_documents(store, DocumentSearchRequest(namespace=NS, query="phishing incident report"))
    assert [h.artifact_id for h in page.hits][:1] == [phish.id]
    hit = page.hits[0]
    assert hit.title == "IR-2026-029: phishing" and JDOE in hit.mentions
    assert "phishing" in hit.snippet.lower() and hit.citation.artifact_id == phish.id
    page = search_documents(store, DocumentSearchRequest(namespace=NS, query='"TGS requests" kerberoast'))
    assert page.hits[0].artifact_id == kerb.id and SVC in page.hits[0].mentions
    empty = search_documents(store, DocumentSearchRequest(namespace=NS, query="ransomware"))
    assert empty.hits == [] and any("no stored document" in n for n in empty.notes)


def test_a_pack_and_a_listing_carry_the_mention(store):
    art, _ = _ingest(store, IR_KERB, "ir-031")
    pack = build_pack(store, AskRequest(namespace=NS, subject=SVC, question="which reports name it?", budget=800))
    assert any("mentioned_in" in i.text for i in pack.items)
    page = listing.list_entities(store, ListRequest(namespace=NS, of=EntityRef(type="document", key=art.id),
                                                    via=["mentioned_in"]))
    assert {r.entity.key for r in page.rows} == {SVC.key, WS.key, "CVE-2026-0544"}
    # the document is findable by its title (a label)
    found = store.search_entities(NS, "IR-2026-031", limit=3, labels=("title",))
    assert any(e.type == "document" and e.key == art.id for e in found)


def test_mcp_and_http_surfaces(store, tmp_path, monkeypatch):
    art, _ = _ingest(store, IR_PHISH, "ir-029")
    mcp_server.configure(store)
    try:
        res = asyncio.run(mcp_server.mcp._tool_manager.call_tool(
            "search_documents", {"query": "phishing", "namespace": NS}, context=None, convert_result=True))
        assert not res.is_error, res.content
        assert res.structured_content["hits"][0]["artifact_id"] == art.id
    finally:
        mcp_server.configure(None)


def test_query_terms():
    assert terms_of('the "TGS requests" for svc-sqladm in a report') == ["tgs requests", "svc-sqladm"]
    assert terms_of("an of to") == []


def test_http_ingest_links_and_searches(tmp_path, monkeypatch):
    monkeypatch.setenv("LOOMCTX_DB", str(tmp_path / "api.db"))
    from fastapi.testclient import TestClient

    from loomctx.api import http
    with TestClient(http.app) as client:
        store = http.app.state.store
        store.put_schema(SchemaRegistration(namespace=NS, predicates=[PredicateDef(name="sam", label=True)],
                                            entity_types=[EntityTypeDef(name="user")]))
        store.record_claim(ClaimIn(namespace=NS, subject=JDOE, predicate="sam", object="jdoe-ops", observed_at=T1,
                                   source="ldap"))
        r = client.post("/v1/ingest", json={"kind": "document", "namespace": NS, "text": IR_PHISH,
                                            "source": "ir-notes", "observed_at": T2.isoformat()})
        assert r.status_code == 202 and r.json()["mentions"] == 1
        r = client.post("/v1/documents/search", json={"namespace": NS, "query": "phishing portal"})
        assert r.status_code == 200
        hit = r.json()["hits"][0]
        assert hit["title"] == "IR-2026-029: phishing" and hit["mentions"] == [{"type": "user", "key": JDOE.key}]
