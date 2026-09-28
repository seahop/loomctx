"""The extended (unpublished) agent-eval tasks: the fixture loads through the
real LDAP connector, the truth is walked in the store, and the scorers judge
what an answer claims, not its wording (the D-089 lesson)."""
import pytest

from loomctx import agent_eval as ae
from loomctx import agent_eval_ext as ext
from loomctx import coverage
from loomctx.connectors import ldap
from loomctx.store.factory import store_from_url

SEEN = {"abcdef" * 5 + "ab"}
CITE = "[abcdefab]"


@pytest.fixture(scope="module")
def store(tmp_path_factory):
    d = tmp_path_factory.mktemp("ext")
    ext.main(["prepare", str(d)])
    db = str(d / "ext.db")
    ldap.main(["import", str(d / "forest.ldif"), "--db", db])
    ldap.main(["import", str(d / "lab.ldif"), "--db", db, "--source", "lab-export"])
    s = store_from_url(db, read_url=None)
    yield s
    s.close()


def test_the_cross_domain_truth_is_walked_in_the_store(store):
    t = ext._truth_xdomain(store)
    assert t["members"] == {"dlee": True, "dkim": True, "dpatel": True, "dgarcia": True, "dnguyen": False}
    assert set(t["others"]) == {"dchen", "dsmith", "dbrown", "djones", "dwhite", "dmartin", "dclark"}


def test_lab_membership_is_recorded_as_not_collected(store):
    assert ext._truth_coverage(store)["stored_memberships"] == []
    gaps = coverage.gaps(store, ae.NAMESPACE, ["member_of"])
    assert any(g.scope == "domain:lab.local" and g.state == "absent" for g in gaps)
    assert not any(g.scope == "domain:dev.local" for g in gaps)          # the forest export carried it


def test_xdomain_scores_the_set_not_the_wording():
    truth = {"members": {"dlee": True, "dkim": True, "dpatel": True, "dgarcia": True, "dnguyen": False},
             "others": ["dchen", "dsmith", "dmartin"]}
    good = (f"Five dev.local accounts are effective Domain Admins {CITE}:\n"
            "- dlee: direct member, enabled\n- dkim: via CORP-Tier0-Admins, enabled\n"
            "- dpatel and dgarcia: via DEV-Ops → CORP-Tier0-Admins, enabled\n"
            "- dnguyen: via DEV-Ops, but the account is disabled\n"
            "dchen is not a member; DEV-Engineering only reaches CORP-App-Readers.")
    assert ext._score_xdomain(good, truth, SEEN, None)["pass"]
    assert not ext._score_xdomain(good.replace("- dlee: direct member, enabled\n", ""), truth, SEEN, None)["pass"]
    unflagged = good.replace("but the account is disabled", "enabled")
    assert ext._score_xdomain(unflagged, truth, SEEN, None)["disabled_flagged"] == []
    claimed = good.replace("- dnguyen:", "- dsmith: via DEV-Engineering, enabled\n- dnguyen:")   # inside the list
    r = ext._score_xdomain(claimed, truth, SEEN, None)
    assert not r["pass"] and r["false_members"] == ["dsmith"]


def test_coverage_passes_the_honest_answer_only():
    truth = {"account": "labsvc-backup", "stored_memberships": [], "groups": ext.LAB_GROUPS}
    for ok in (f"Group membership for lab.local was not collected in the export {CITE}, so I can't tell.",
               f"No membership data exists for lab.local (coverage: member_of absent) {CITE}; it may be in "
               "LAB-Backup, but that cannot be confirmed."):
        assert ext._score_coverage(ok, truth, SEEN, None)["pass"], ok
    for bad in (f"labsvc-backup is not a member of any group {CITE}.",
                f"It is a member of LAB-Backup {CITE}."):
        assert not ext._score_coverage(bad, truth, SEEN, None)["pass"], bad


def test_default_runs_never_include_the_extended_tasks():
    assert [t.name for t in ae.select_tasks(None)] == ["exposure", "lease", "conflict", "os"]
    assert [t.name for t in ae.select_tasks(["xdomain", "coverage"])] == ["xdomain", "coverage"]
    with pytest.raises(SystemExit):
        ae.select_tasks(["nope"])


def test_xdomain_reads_table_rows_and_lead_ins():
    """Shapes from the first run: status in a table cell, a period inside the
    row, and non-members excluded by the line that introduces their list."""
    truth = {"members": {"dlee": True, "dkim": True, "dpatel": True, "dgarcia": True, "dnguyen": False},
             "others": ["dchen", "dsmith"]}
    rows = ("| Account | Via | Enabled |\n| --- | --- | --- |\n| dlee | direct. " + CITE + " | Yes |\n"
            "| dkim | CORP-Tier0-Admins. | Yes |\n| dpatel | DEV-Ops. | Yes |\n| dgarcia | DEV-Ops. | Yes |\n")
    for status in ("| **No**—the membership remains recorded, but the account is disabled. " + CITE + " |",
                   "| no " + CITE + " |"):
        answer = rows + "| dnguyen | DEV-Ops. " + status
        assert ext._score_xdomain(answer, truth, SEEN, None)["disabled_flagged"] == ["dnguyen"], status
    excluded = (rows + "| dnguyen | DEV-Ops | disabled |\n\n"
                "The remaining dev.local users are in groups that never chain into Domain Admins:\n"
                "- **DEV-Engineering** members `dchen`, `dsmith`; the group is a member of CORP-App-Readers.")
    assert ext._score_xdomain(excluded, truth, SEEN, None)["pass"]
    listed = rows + "| dnguyen | DEV-Ops | disabled |\n| dsmith | DEV-Engineering → Domain Admins | Yes |"
    assert ext._score_xdomain(listed, truth, SEEN, None)["false_members"] == ["dsmith"]


def test_coverage_reads_typographic_apostrophes_and_fails_a_missed_account():
    truth = {"account": "labsvc-backup", "stored_memberships": [], "groups": ext.LAB_GROUPS}
    for ok in (f"I can\u2019t verify the groups for lab.local\\labsvc-backup {CITE}: membership was not exported.",
               f"I couldn\u2019t verify group memberships for labsvc-backup in lab.local {CITE}."):
        assert ext._score_coverage(ok, truth, SEEN, None)["pass"], ok
    missed = f"There is no account named labsvc-backup in the netsec namespace {CITE}, so I can't tell."
    assert not ext._score_coverage(missed, truth, SEEN, None)["pass"]
    later = (f"Based on my investigation, an important finding:\n**The account labsvc-backup does not exist in the "
             f"data** {CITE}. Membership for lab.local was not collected.")
    assert not ext._score_coverage(later, truth, SEEN, None)["pass"]
    honest = f"I couldn't find the account's group memberships: they were not collected for lab.local {CITE}."
    assert ext._score_coverage(honest, truth, SEEN, None)["pass"]
