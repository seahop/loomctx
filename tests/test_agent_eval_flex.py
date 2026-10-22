"""Held-out and hybrid agent tasks (D-119): truths walked in the store, the
incident reports linked to the forest's entities (D-118), and each scorer's
pass and fail cases."""
import pytest

from loomctx import agent_eval as ae
from loomctx import agent_eval_ext as ext
from loomctx import agent_eval_flex as flex
from loomctx import ingest
from loomctx.connectors import ldap
from loomctx.contracts import DocumentSearchRequest
from loomctx.docsearch import search_documents
from loomctx.store.factory import store_from_url

CITE = "[abcdefab0123]"
SEEN = {"abcdefab0123" + "0" * 20}


@pytest.fixture(scope="module")
def store(tmp_path_factory):
    d = tmp_path_factory.mktemp("flex")
    ext.main(["prepare", str(d), "--scale", "small"])
    flex.main(["prepare", str(d)])
    db = str(d / "flex.db")
    ldap.main(["import", str(d / "forest.ldif"), "--db", db])
    ingest.main(["--db", db, str(d / "docs.ndjson")])
    s = store_from_url(db, read_url=None)
    yield s
    s.close()


def test_truths_are_walked_in_the_store(store):
    assert {"svc-backupadm", "dnguyen"} <= set(flex._truth_disabled(store)["disabled"])
    r = flex._truth_rights_nonadmin(store)
    assert r["nonadmins"] == ["jdoe-ops"] and {"adm-pchen", "adm-rlopez"} <= set(r["admins"])
    d = flex._truth_delegation_os(store)
    assert {"APP-LEGACY01", "PRINT-HQ02", "SQL-OLD03"} <= set(d["hosts"])
    assert d["os"]["PRINT-HQ02"] == "Windows Server 2016 Standard"
    assert flex._truth_chain(store)["via"] == ["CORP-Tier0-Admins"]
    assert flex._truth_sid_history(store)["sid_filtering"] is True
    assert flex._truth_hyb_kerberoast(store)["enabled"] and flex._truth_hyb_delegation(store)["unconstrained"]


def test_the_incident_reports_lead_to_the_forest(store):
    hits = search_documents(store, DocumentSearchRequest(namespace=ae.NAMESPACE, query="Kerberoasting")).hits
    assert hits and hits[0].title == "IR-2026-031: suspected Kerberoasting"
    assert any(m.type == "user" and m.key.endswith("-95320") for m in hits[0].mentions)      # svc-sqladm
    phish = search_documents(store, DocumentSearchRequest(namespace=ae.NAMESPACE, query="phished credentials")).hits
    assert any(m.key.endswith("-95312") for m in phish[0].mentions)                           # jdoe-ops
    coerced = search_documents(store, DocumentSearchRequest(namespace=ae.NAMESPACE,
                                                            query="captured Kerberos tickets server")).hits
    assert coerced[0].title == "IR-2026-033: coerced authentication"
    assert any(m.type == "computer" for m in coerced[0].mentions)                             # PRINT-HQ02


def test_flex_scorers():
    t = {"disabled": ["dnguyen", "svc-backupadm"], "enabled": ["adm-kwu"]}
    assert flex._score_disabled(f"Disabled: dnguyen (via DEV-Ops) and svc-backupadm {CITE}.", t, SEEN, None)["pass"]
    assert not flex._score_disabled(f"dnguyen, svc-backupadm and adm-kwu are disabled {CITE}.", t, SEEN, None)["pass"]
    t = {"nonadmins": ["jdoe-ops"], "admins": ["adm-pchen", "adm-rlopez"]}
    assert flex._score_rights_nonadmin(f"jdoe-ops — GenericAll through CORP-WS-Operators {CITE}.", t, SEEN, None)["pass"]
    assert not flex._score_rights_nonadmin(
        f"jdoe-ops and adm-rlopez (non-Domain Admin) via CORP-WS-Operators {CITE}.", t, SEEN, None)["pass"]
    t = {"hosts": ["APP-LEGACY01"], "os": {"APP-LEGACY01": "Windows Server 2016 Standard"}, "dcs": ["DC01"]}
    assert flex._score_delegation_os(f"- APP-LEGACY01 — Windows Server 2016 {CITE}", t, SEEN, None)["pass"]
    assert not flex._score_delegation_os(f"- APP-LEGACY01 {CITE}", t, SEEN, None)["pass"]
    t = {"host": "WS-AUDIT01", "collected": False}
    assert flex._score_sessions("Logon sessions are not collected in this AD export.", t, SEEN, None)["pass"]
    assert not flex._score_sessions(f"adm-rlopez logged on to WS-AUDIT01 yesterday {CITE}.", t, SEEN, None)["pass"]
    t = {"account": "dkim", "via": ["CORP-Tier0-Admins"]}
    assert flex._score_chain(f"dkim -> CORP-Tier0-Admins -> Domain Admins {CITE}", t, SEEN, None)["pass"]
    assert not flex._score_chain(f"dkim is a member of DEV-Ops, which is in CORP-Tier0-Admins {CITE}",
                                 t, SEEN, None)["pass"]
    t = {"account": "iwalsh", "group": "CORP-Finance-All", "member": True,
         "via": ["CORP-Finance-Interns", "CORP-Finance-Users"]}
    good = f"Yes. iwalsh -> CORP-Finance-Interns -> CORP-Finance-Users -> CORP-Finance-All {CITE}."
    assert flex._score_nested(good, t, SEEN, None)["pass"]
    assert not flex._score_nested(good.replace("Yes.", "No."), t, SEEN, None)["pass"]
    t = {"partner": "fabrikam.local", "sid_filtering": True}
    assert flex._score_sid_history(f"No. The fabrikam.local trust has SID filtering enabled {CITE}.", t, SEEN, None)["pass"]
    assert not flex._score_sid_history(f"Yes, fabrikam.local accounts could {CITE}.", t, SEEN, None)["pass"]


def test_hybrid_scorers():
    t = {"account": "svc-sqladm", "enabled": True, "via": "CORP-Tier0-Admins", "decoys": ["svc-backupadm", "svc-web"]}
    good = f"IR-2026-031 names svc-sqladm {CITE}. It is enabled and a Domain Admin through CORP-Tier0-Admins {CITE}."
    assert flex._score_hyb_kerberoast(good, t, SEEN, None)["pass"]
    assert not flex._score_hyb_kerberoast(good.replace("It is enabled", "It is disabled"), t, SEEN, None)["pass"]
    assert not flex._score_hyb_kerberoast(f"The target was svc-backupadm {CITE}.", t, SEEN, None)["pass"]
    t = {"account": "jdoe-ops", "machines": ["WS-AUDIT01"], "via": "CORP-WS-Operators"}
    good = f"The phished user jdoe-ops controls WS-AUDIT01 through CORP-WS-Operators (GenericAll) {CITE}."
    assert flex._score_hyb_phished(good, t, SEEN, None)["pass"]
    assert not flex._score_hyb_phished(good + f" jdoe-ops is a Domain Admin {CITE}.", t, SEEN, None)["pass"]
    t = {"host": "PRINT-HQ02", "unconstrained": True, "os": "Windows Server 2016 Standard"}
    good = f"PRINT-HQ02 is trusted for unconstrained delegation and runs Windows Server 2016 Standard {CITE}."
    assert flex._score_hyb_delegation(good, t, SEEN, None)["pass"]
    assert not flex._score_hyb_delegation(f"PRINT-HQ02 is not trusted for unconstrained delegation; 2016 {CITE}.",
                                          t, SEEN, None)["pass"]


def test_the_tasks_are_selectable_by_name():
    got = ae.select_tasks(["flex_disabled", "hyb_kerberoast", "kerberoast"])
    assert [t.name for t in got] == ["kerberoast", "flex_disabled", "hyb_kerberoast"]
