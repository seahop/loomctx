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
    ext.main(["prepare", str(d), "--scale", "small"])
    db = str(d / "ext.db")
    ldap.main(["import", str(d / "forest.ldif"), "--db", db])
    ldap.main(["import", str(d / "lab.ldif"), "--db", db, "--source", "lab-export"])
    s = store_from_url(db, read_url=None)
    yield s
    s.close()


@pytest.fixture(scope="module")
def realistic_store(tmp_path_factory):
    d = tmp_path_factory.mktemp("ext-real")
    ext.main(["prepare", str(d), "--scale", "small", "--style", "realistic"])
    db = str(d / "ext.db")
    ldap.main(["import", str(d / "forest.ldif"), "--db", db])
    ldap.main(["import", str(d / "lab.ldif"), "--db", db, "--source", "lab-export"])
    s = store_from_url(db, read_url=None)
    yield s
    s.close()


def test_every_audit_truth_holds_on_a_realistic_forest(realistic_store):
    # the realistic base adds hubs, admins and delegated rights; the planted answers must not move
    s = realistic_store
    t = ext._truth_xdomain(s)
    assert t["members"] == {"dlee": True, "dkim": True, "dpatel": True, "dgarcia": True, "dnguyen": False}
    assert ext._truth_coverage(s)["stored_memberships"] == []
    g = ext._truth_groups(s)
    assert g["groups"] == ["CORP-ERP-Access", "CORP-Finance-All", "CORP-Finance-Users", "CORP-Remote-Apps",
                           "CORP-VPN-Users"]
    d = ext._truth_delegation(s)
    assert d["hosts"] == ["APP-LEGACY01", "PRINT-HQ02", "SQL-OLD03"] and d["decoys"] == ["WEB-KCD04"]
    assert d["dcs"] and all("-DC" in n for n in d["dcs"])
    t = ext._truth_trusts(s)["trusts"]
    assert t["dev.local"] == {"direction": "bidirectional", "transitive": True, "sid_filtering": False}


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
    # a labelled field under the member's item (Haiku on the realistic forest, 2026-10-13)
    items = "".join(f"{i}. **{m}@dev.local** {CITE}\n   - **Group Added Through:** DEV-Ops@dev.local\n"
                    f"   - **Enabled Status:** {'No' if m == 'dnguyen' else 'Yes'} {CITE}\n"
                    for i, m in enumerate(["dlee", "dkim", "dnguyen", "dgarcia", "dpatel"], 1))
    assert ext._score_xdomain(items, truth, SEEN, None)["disabled_flagged"] == ["dnguyen"]
    excluded = (rows + "| dnguyen | DEV-Ops | disabled |\n\n"
                "The remaining dev.local users are in groups that never chain into Domain Admins:\n"
                "- **DEV-Engineering** members `dchen`, `dsmith`; the group is a member of CORP-App-Readers.")
    assert ext._score_xdomain(excluded, truth, SEEN, None)["pass"]
    items = ("Five accounts reach Domain Admins " + CITE + ":\n1) dev\\dlee — Enabled: True\n2) dkim\n3) dpatel\n"
             "4) dgarcia\n5) dev\\dnguyen (CN=dnguyen,CN=Users,DC=dev,DC=local)\n   - Added through: DEV-Ops\n"
             "   - Enabled: **False**\n")
    assert ext._score_xdomain(items, truth, SEEN, None)["disabled_flagged"] == ["dnguyen"]
    headed = ("Accounts " + CITE + ":\n**4. dgarcia (dev\\dgarcia)**\n- **Enabled**: Yes\n\n"
              "**5. dnguyen (dev\\dnguyen)**\n- **Membership Path**: DEV-Ops → CORP-Tier0-Admins → Domain Admins\n"
              "- **Enabled**: No [abcdefab]\n")
    assert ext._score_xdomain(headed, truth, SEEN, None)["disabled_flagged"] == ["dnguyen"]
    # an item stops at the next account: dgarcia's "Yes" is not read as dnguyen's
    wrong = ("**5. dnguyen**\n- **Enabled**: Yes\n**6. dgarcia**\n- disabled\n")
    assert ext._score_xdomain(wrong, truth, SEEN, None)["disabled_flagged"] == []
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
    # emphasis and "did not collect" (GPT-5.2's wording): honest, and passes
    bold = (f"No direct group memberships for labsvc-backup are recorded, so I can’t name its groups. "
            f"The import source explicitly did **not** collect `member_of` for domain:lab.local {CITE}.")
    assert ext._score_coverage(bold, truth, SEEN, None)["pass"]
    # GPT-4o's wording (2026-09-28 full run): honest, and passes
    gpt4o = (f"The account labsvc-backup in the lab.local domain does not have collected data regarding its "
             f"group memberships, which may indicate missing data rather than absence of group memberships {CITE}.")
    assert ext._score_coverage(gpt4o, truth, SEEN, None)["pass"]


def test_the_new_truths_are_read_from_the_store(store):
    g = ext._truth_groups(store)
    assert g["groups"] == ["CORP-ERP-Access", "CORP-Finance-All", "CORP-Finance-Users", "CORP-Remote-Apps",
                           "CORP-VPN-Users"]
    assert g["direct"] == ["CORP-Finance-Users", "CORP-VPN-Users"]
    assert g["distractors"] == ["CORP-Finance-Interns", "CORP-Finance-Managers"]
    d = ext._truth_delegation(store)
    assert d["hosts"] == ["APP-LEGACY01", "PRINT-HQ02", "SQL-OLD03"] and d["decoys"] == ["WEB-KCD04"]
    assert d["dcs"] and all(n.startswith("DC") for n in d["dcs"])
    t = ext._truth_trusts(store)["trusts"]
    assert t["partner.local"]["transitive"] is False and t["fabrikam.local"]["sid_filtering"] is True
    assert t["dev.local"] == {"direction": "bidirectional", "transitive": True, "sid_filtering": False}


def test_groups_scores_the_closure_and_the_distractors():
    truth = {"groups": ["CORP-ERP-Access", "CORP-Finance-All", "CORP-Finance-Users", "CORP-Remote-Apps",
                        "CORP-VPN-Users"], "direct": [], "distractors": ["CORP-Finance-Interns", "CORP-Finance-Managers"]}
    good = (f"mreyes belongs to {CITE}:\n- CORP-Finance-Users (direct)\n- CORP-VPN-Users (direct)\n"
            "- CORP-Finance-All (via CORP-Finance-Users)\n- CORP-ERP-Access (via CORP-Finance-All)\n"
            "- CORP-Remote-Apps (via CORP-ERP-Access)\n"
            "CORP-Finance-Interns is nested into CORP-Finance-Users, so it is not one of mreyes's groups.")
    assert ext._score_groups(good, truth, SEEN, None)["pass"]
    short = good.replace("- CORP-Remote-Apps (via CORP-ERP-Access)\n", "")
    assert not ext._score_groups(short, truth, SEEN, None)["pass"]
    padded = good.replace("- CORP-VPN-Users (direct)\n", "- CORP-VPN-Users (direct)\n- CORP-Finance-Managers (nested)\n")
    assert ext._score_groups(padded, truth, SEEN, None)["false_groups"] == ["CORP-Finance-Managers"]
    by_sid = short + "- group:S-1-5-21-9-95007 (via CORP-ERP-Access)\n"
    assert ext._score_groups(by_sid, {**truth, "keys": {"CORP-Remote-Apps": "S-1-5-21-9-95007"}}, SEEN, None)["pass"]
    # arrow notation states structure too (a realistic-forest answer's risk note, 2026-10-13)
    arrows = (good + "\n- Worth noting (other principals): CORP-Finance-Interns → CORP-Finance-Users [abcdefab] and "
              "CORP-Finance-Managers → CORP-Finance-All [abcdefab] feed the same chain.")
    assert ext._score_groups(arrows, truth, SEEN, None)["pass"]


def test_delegation_scores_the_servers_and_not_the_dcs():
    truth = {"hosts": ["APP-LEGACY01", "PRINT-HQ02", "SQL-OLD03"], "dcs": ["DC00", "DC01"], "decoys": ["WEB-KCD04"]}
    good = (f"Three non-DC computers are trusted for unconstrained delegation {CITE}:\n"
            "- APP-LEGACY01\n- PRINT-HQ02\n- SQL-OLD03\n"
            "DC00 and DC01 are domain controllers, which carry it by design. "
            "WEB-KCD04 has constrained delegation only (HTTP/intranet.corp.local).")
    assert ext._score_delegation(good, truth, SEEN, None)["pass"]
    listed = good.replace("- SQL-OLD03\n", "- SQL-OLD03\n- WEB-KCD04\n- DC00\n")
    assert ext._score_delegation(listed, truth, SEEN, None)["false_hosts"] == ["DC00", "WEB-KCD04"]
    assert not ext._score_delegation(good.replace("- PRINT-HQ02\n", ""), truth, SEEN, None)["pass"]


def test_trusts_scores_each_partner_property():
    truth = {"trusts": {"dev.local": {"direction": "bidirectional", "transitive": True, "sid_filtering": False},
                        "partner.local": {"direction": "bidirectional", "transitive": False, "sid_filtering": False},
                        "fabrikam.local": {"direction": "bidirectional", "transitive": True, "sid_filtering": True}}}
    good = (f"corp.local has three trusts {CITE}:\n"
            "| Partner | Direction | Transitive | SID filtering |\n|---|---|---|---|\n"
            "| dev.local | bidirectional | yes | no |\n| partner.local | bidirectional | **no** (non-transitive) | no |\n"
            "| fabrikam.local | bidirectional | yes | enabled (quarantined) |")
    r = ext._score_trusts(good, truth, SEEN, None)
    assert r["pass"], r
    wrong = good.replace("**no** (non-transitive)", "yes")
    assert "partner.local: non-transitive not stated" in ext._score_trusts(wrong, truth, SEEN, None)["wrong"]
    assert not ext._score_trusts(good.replace("enabled (quarantined)", "no"), truth, SEEN, None)["pass"]
    # a table that says it by column: "No" under "Transitive", "Yes" under "SID filtering"
    bare = (f"Trusts {CITE}:\n| Partner | Direction | Transitive | SID filtering |\n|---|---|---|---|\n"
            "| dev.local | Bidirectional | Yes | No |\n| partner.local | Bidirectional | No | No |\n"
            "| fabrikam.local | Bidirectional | Yes | Yes |")
    assert ext._score_trusts(bare, truth, SEEN, None)["pass"]
    assert not ext._score_trusts(bare.replace("| partner.local | Bidirectional | No |", "| partner.local | Bidirectional | Yes |"),
                                 truth, SEEN, None)["pass"]
    # "SID Filtering (Quarantine): Disabled" is off, whatever the label says
    labelled = (f"Trusts {CITE}:\n1. partner.local\n   - Transitive: No\n   - SID Filtering (Quarantine): Disabled\n"
                "2. dev.local\n   - Transitive: Yes\n   - SID Filtering (Quarantine): Disabled\n"
                "3. fabrikam.local\n   - Transitive: Yes\n   - SID Filtering (Quarantine): Enabled")
    assert ext._score_trusts(labelled, truth, SEEN, None)["pass"], ext._score_trusts(labelled, truth, SEEN, None)


def test_new_scorers_read_the_full_run_answers():
    """Patterns from the 2026-09-28 full run that the first scorers misread."""
    trusts = {"trusts": {"dev.local": {"direction": "bidirectional", "transitive": True, "sid_filtering": False},
                         "partner.local": {"direction": "bidirectional", "transitive": False, "sid_filtering": False},
                         "fabrikam.local": {"direction": "bidirectional", "transitive": True, "sid_filtering": True}}}
    # a table without outer pipes (GPT-5.2)
    bare = (f"Partner domain | Trust direction | Transitive? | SID filtering (quarantine) enabled?\n---|---|---|---\n"
            f"dev.local | bidirectional | True | False {CITE}\nfabrikam.local | bidirectional | True | True\n"
            "partner.local | bidirectional | False | False")
    assert ext._score_trusts(bare, trusts, SEEN, None)["pass"]
    deleg = {"hosts": ["APP-LEGACY01", "PRINT-HQ02", "SQL-OLD03"], "dcs": ["DC00", "DC01"], "decoys": ["WEB-KCD04"]}
    hosts = f"- SQL-OLD03$ {CITE}\n- PRINT-HQ02$\n- APP-LEGACY01$\n"
    for ok in (
        # DCs under a lead-in that calls them domain controllers (Gemini 2.5 Flash)
        hosts + "\nThe following domain controllers are also trusted for unconstrained delegation:\n\n- DC00$\n- DC01$",
        # the exclusion a sentence on (Claude Opus 5.5)
        hosts + "\nDC00$–DC01$ also have unconstrained delegation set. DCs normally have this setting, so I didn't count them.",
        # constrained, then unconstrained later on the line (Claude Opus 4.8)
        "The Servers OU holds WEB-KCD04$ (constrained delegation), but the queries returned three flagged for "
        "unconstrained delegation.\n" + hosts,
        # named only as present (Qwen3-coder)
        hosts + "Note that while other computers such as WEB-KCD04$ are also present, only the above three are "
                "confirmed to have unconstrained delegation."):
        assert ext._score_delegation(ok, deleg, SEEN, None)["pass"], ok
    listed = f"Trusted for unconstrained delegation:\n- SQL-OLD03 {CITE}\n- PRINT-HQ02\n- APP-LEGACY01\n- WEB-KCD04"
    assert ext._score_delegation(listed, deleg, SEEN, None)["false_hosts"] == ["WEB-KCD04"]
    groups = {"account": "mreyes", "groups": ["CORP-Finance-Users", "CORP-VPN-Users"], "direct": [],
              "distractors": ["CORP-Finance-Interns"]}
    base = f"mreyes is in {CITE}:\n- CORP-Finance-Users\n- CORP-VPN-Users\n"
    for ok in (
        # a nested bullet under a parent that says "not" (Claude Opus 5.5)
        base + "- Two other groups showed up but are **not** mreyes's groups:\n  - CORP-Finance-Interns is a member of CORP-Finance-Users.",
        # the directory's structure, not a claim (GPT-4o)
        base + "### Additional Group Relationships:\n- **CORP-Finance-Interns** (SID: S-1-5-21-9) is a member of **CORP-Finance-Users**"):
        assert ext._score_groups(ok, groups, SEEN, None)["pass"], ok
    inherited = base + "- CORP-Finance-Interns (inherited via CORP-Finance-Users)"
    assert ext._score_groups(inherited, groups, SEEN, None)["false_groups"] == ["CORP-Finance-Interns"]


def test_scorers_read_the_five_run_answers():
    """Patterns from the 2026-09-28 five-run pass the scorers first misread."""
    trusts = {"trusts": {"dev.local": {"direction": "bidirectional", "transitive": True, "sid_filtering": False},
                         "partner.local": {"direction": "bidirectional", "transitive": False, "sid_filtering": False},
                         "fabrikam.local": {"direction": "bidirectional", "transitive": True, "sid_filtering": True}}}
    # several fields on one line (GPT-5.2)
    inline = (f"corp.local trusts {CITE}:\n"
              "- partner.local — direction: **bidirectional**; transitive: **no (non-transitive)**; SID filtering (quarantine) enabled: **no**.\n"
              "- dev.local — direction: **bidirectional**; transitive: **yes**; SID filtering (quarantine) enabled: **no**.\n"
              "- fabrikam.local — direction: **bidirectional**; transitive: **yes**; SID filtering (quarantine) enabled: **yes**.")
    assert ext._score_trusts(inline, trusts, SEEN, None)["pass"]
    # a numbered header with "- field" bullets under it (Claude Sonnet 5)
    numbered = (f"Trusts {CITE}:\n\n**1. corp.local ↔ dev.local**\n- Transitive: Yes\n- SID filtering (quarantine): Off\n\n"
                "**2. corp.local ↔ fabrikam.local**\n- Transitive: Yes\n- SID filtering (quarantine): On/enabled\n\n"
                "**3. corp.local ↔ partner.local**\n- Transitive: No (non-transitive)\n- SID filtering (quarantine): Off")
    assert ext._score_trusts(numbered, trusts, SEEN, None)["pass"]
    # a later sentence about an attribute named *_transitive is not the field (Grok 4.7)
    later = (f"1. partner.local — trust is **not** transitive; SID filtering **off**. {CITE}\n"
             "2. dev.local — transitive; SID filtering off.\n3. fabrikam.local — transitive; SID filtering **on**.\n"
             "The same observations carry `forest_transitive: true` for all three (including partner.local).")
    assert ext._score_trusts(later, trusts, SEEN, None)["pass"]
    groups = {"account": "mreyes", "groups": ["CORP-Finance-Users"], "direct": [], "distractors": ["CORP-Finance-Interns"]}
    # a bold lead-in that says "Not" (Qwen 3.8 Flash)
    bold = (f"- CORP-Finance-Users {CITE}\n\n**Not mreyes memberships (do not count):**\n"
            "- CORP-Finance-Interns@corp.local is itself a member of CORP-Finance-Users; its member is iwalsh.")
    assert ext._score_groups(bold, groups, SEEN, None)["pass"]
    deleg = {"hosts": ["APP-LEGACY01", "PRINT-HQ02", "SQL-OLD03"], "dcs": ["DC00", "DC09"], "decoys": ["WEB-KCD04"]}
    hosts = f"## Non-DC computers trusted for unconstrained delegation\n- APP-LEGACY01$ {CITE}\n- PRINT-HQ02$\n- SQL-OLD03$\n"
    for ok in (hosts + "3. **Treat the hosts as Tier-0-adjacent:** monitor for TGTs from DC00$–DC09$ landing on them, and audit local admins.",
               hosts + "- Servers OU was examined; its other members — e.g., WEB-KCD04$, SRV01986 — carry no flag."):
        assert ext._score_delegation(ok, deleg, SEEN, None)["pass"], ok
    # a list of findings that includes the constrained server stays wrong (Qwen3-coder)
    listed = ("The following computer accounts, other than domain controllers, are trusted for unconstrained delegation:\n"
              f"- APP-LEGACY01$ {CITE}\n- PRINT-HQ02$\n- SQL-OLD03$\n- WEB-KCD04$@corp.local [4a33ed837fb0]\n- SRV01989$")
    assert ext._score_delegation(listed, deleg, SEEN, None)["false_hosts"] == ["WEB-KCD04"]


def test_coverage_hedge_reads_not_collected_phrasings_from_list_notes():
    """GPT-4o on the final A/B: the right answer, scored unhedged — "does not
    have its group memberships collected" and "may be missing data, not
    absent" (the list note's own words, with a comma) were not read."""
    from loomctx.agent_eval_ext import _NOT_COLLECTED
    for text in ("The account labsvc-backup does not have its group memberships collected by the lab-export.",
                 "Therefore, the groups it is a member of may be missing data, not absent [775390e1b4b4].",
                 "the data regarding its group memberships may be missing, not necessarily absent."):
        assert _NOT_COLLECTED.search(text), text
    assert not _NOT_COLLECTED.search("labsvc-backup is a member of LAB-Backup and LAB-Ops.")


def test_coverage_fails_a_membership_the_data_does_not_record():
    """Qwen3 Coder on the final A/B: "is a member of the following groups:
    Domain Users, Backup Operators" (each cited to an unrelated fact) plus a
    coverage note passed — only the lab's own groups counted as guesses.
    With no membership on record, any unhedged membership claim fails."""
    from loomctx.agent_eval_ext import _score_coverage
    truth = {"account": "labsvc-backup", "stored_memberships": [], "groups": ["LAB-Admins", "LAB-Backup", "LAB-Users"]}
    bad = ("The account `labsvc-backup` in the `lab.local` domain is a member of the following groups:\n\n"
           "- Domain Users [e51e8b03f5d0]\n- Backup Operators [a1c09e453656]\n\nNote: The data indicates that the "
           "`member_of` relationship was not collected by the `lab-export` [a3e306710498].")
    assert _score_coverage(bad, truth, set(), None)["claimed_membership"] is True
    good = [
        "The `labsvc-backup` account in the `lab.local` domain was not observed as a member of any groups in the "
        "data collected by `lab-export`. The collection did not gather `member_of` for lab.local, so this is a "
        "coverage gap [a3e306710498].",
        "The account labsvc-backup in the lab.local domain does not have its group memberships collected by the "
        "lab-export. Therefore, the groups it is a member of may be missing data, not absent [775390e1b4b4].",
        "No group memberships are recorded for labsvc-backup — a data-collection gap: lab-export did not collect "
        "member_of [775390e1b4b4]. It may belong to groups that were never exported.",
    ]
    for text in good:
        got = _score_coverage(text, truth, set(), None)
        assert not got["claimed_membership"] and got["hedged"], text
    # excerpts of real final-A/B answers the first version of this check failed wrongly
    excerpts = [
        "This cannot be answered from the data — group membership for lab.local was not collected [a3e306710498].\n"
        "Any groups it belongs to in lab.local are simply missing from this dataset.",
        "labsvc-backup has no group memberships recorded — a data-collection gap [a3e306710498].\n"
        "- A direct listing of groups this user is a member of   returned 0 rows",
        "The account `labsvc-backup@lab.local` is a member of the following groups:\n\n"
        "- No group membership data was collected for this account in the `lab-export` records [a3e306710498].",
    ]
    for text in excerpts:
        assert not _score_coverage(text, truth, set(), None)["claimed_membership"], text


# ------------------------------------------------------- harder tier (D-113) #

def test_harder_tier_truth_on_both_forests(store, realistic_store):
    for s in (store, realistic_store):
        a = ext._truth_access(s)
        assert a["admins"] == ["adm-pchen", "adm-rlopez"] and set(a["decoys"]) == {"jdoe-ops", "adm-kwu"}
        k = ext._truth_kerberoast(s)
        assert "svc-sqladm" in k["accounts"] and "svc-backupadm" in k["disabled"] and k["others"] == ["svc-web"]


def test_access_scorer():
    truth = {"admins": ["adm-pchen", "adm-rlopez"], "decoys": ["adm-kwu", "jdoe-ops"], "host": "WS-AUDIT01"}
    good = (f"Two Domain Admins hold rights over WS-AUDIT01:\n- adm-rlopez — GenericAll through CORP-WS-Operators {CITE}\n"
            f"- adm-pchen — a direct WriteDacl grant {CITE}\n\n"
            f"jdoe-ops is in CORP-WS-Operators but is not a Domain Admin; adm-kwu has no rights over it {CITE}.")
    assert ext._score_access(good, truth, SEEN, None)["pass"]
    bad = good.replace("jdoe-ops is in CORP-WS-Operators but is not a Domain Admin; adm-kwu has no rights over it",
                       "- jdoe-ops — GenericAll through CORP-WS-Operators")
    got = ext._score_access(bad, truth, SEEN, None)
    assert not got["pass"] and got["false_accounts"] == ["jdoe-ops"]
    assert not ext._score_access(f"adm-rlopez has GenericAll via CORP-WS-Operators {CITE}", truth, SEEN, None)["pass"]


def test_localadmin_scorer():
    truth = {"host": "WS-AUDIT01", "collected": False}
    good = (f"Local administrator membership on WS-AUDIT01 is not collected: an AD export does not carry machines' "
            f"local groups {CITE}. What the data does show is AD rights over the computer object: CORP-WS-Operators "
            f"holds GenericAll {CITE}.")
    assert ext._score_localadmin(good, truth, SEEN, None)["pass"]
    # nothing to cite for what was never collected: no citation is fine
    assert ext._score_localadmin("Local administrator membership is not collected in this AD export.",
                                 truth, SEEN, None)["pass"]
    bad = f"The local administrators on WS-AUDIT01 are adm-rlopez and adm-pchen {CITE}."
    got = ext._score_localadmin(bad, truth, SEEN, None)
    assert got["claimed_local_admins"] and not got["pass"]
    hedged_claim = (f"adm-rlopez is a local admin on WS-AUDIT01 {CITE}. Note: local group membership was not "
                    f"collected {CITE}.")
    assert not ext._score_localadmin(hedged_claim, truth, SEEN, None)["pass"]


def test_kerberoast_scorer():
    truth = {"accounts": ["svc-sqladm"], "disabled": ["svc-backupadm"], "others": ["svc-web"]}
    good = (f"One enabled Kerberoastable Domain Admin: svc-sqladm (SPN MSSQLSvc/…, via CORP-Tier0-Admins) {CITE}. "
            f"svc-backupadm also has an SPN but is disabled {CITE}.")
    assert ext._score_kerberoast(good, truth, SEEN, None)["pass"]
    bad = f"Kerberoastable Domain Admins:\n- svc-sqladm {CITE}\n- svc-backupadm {CITE}\n- svc-web {CITE}"
    got = ext._score_kerberoast(bad, truth, SEEN, None)
    assert not got["pass"] and got["false_accounts"] == ["svc-backupadm", "svc-web"]


def test_the_engine_answers_the_harder_tier_exactly(store):
    """What the new list mode gives an agent for each (D-110): one call each."""
    import loomctx.mcp_server as mcp
    from loomctx.connectors import ldap as conn
    store.put_schema(conn.schema("netsec"))
    mcp.configure(store)
    try:
        host = f"computer:{ext.CORP_SID}-{ext.ACCESS_HOST_RID}"
        v = mcp.list_entities(namespace="netsec", of=host, via=["has_ace", "member_of"], direction="in", depth=4,
                              type="user", paths=True, where=f"member_of within group:{ext.DOMAIN_ADMINS.key}")
        assert sorted(r["name"].split("@")[0] for r in v["rows"]) == ["adm-pchen", "adm-rlopez"]
        assert all(r["path"]["text"].endswith(host) for r in v["rows"])
        p = mcp.ask(namespace="netsec", subject=host, question=f"Who has local administrator rights on {ext.ACCESS_HOST}?")
        assert any("local group membership" in n for n in p.get("notes", []))
        v = mcp.list_entities(namespace="netsec", type="user",
                              where=f"kerberoastable=true, enabled=true, member_of within group:{ext.DOMAIN_ADMINS.key}")
        assert sorted(r["name"].split("@")[0] for r in v["rows"]) == ext._truth_kerberoast(store)["accounts"]
    finally:
        mcp.configure(None)


def test_harder_tier_scorers_on_real_smoke_answers():
    """Two correct answers the first scorers failed (small-forest smoke run):
    DeepSeek named exactly the two admins under a "## Access review" title
    and listed adm-kwu only in an inventory of members; Mistral said local
    admin "is impossible to determine … who has local administrator rights"."""
    truth = {"admins": ["adm-pchen", "adm-rlopez"], "decoys": ["adm-kwu", "jdoe-ops"], "host": "WS-AUDIT01"}
    ds = (f"## Access review — WS-AUDIT01 (corp.local) vs. Domain Admins\n\n"
          f"Domain Admins has 15 effective members: users adm-rlopez, adm-pchen, adm-kwu, svc-sqladm {CITE}.\n\n"
          f"Of those, exactly two hold rights over WS-AUDIT01:\n\n"
          f"1. adm-pchen — a direct WriteDacl grant {CITE}\n2. adm-rlopez — GenericAll via CORP-WS-Operators {CITE}\n")
    assert ext._score_access(ds, truth, SEEN, None)["pass"]
    nova = (f"#### Nested Rights Holders (via Domain Admins)\n\n1. adm-pchen {CITE}\n2. adm-rlopez {CITE}\n"
            f"3. adm-kwu — member of Domain Admins {CITE}\n")
    assert ext._score_access(nova, truth, SEEN, None)["false_accounts"] == ["adm-kwu"]
    lt = {"host": "WS-AUDIT01", "collected": False}
    mistral = (f"Local admin / RDP rights on a computer are not collected by its sources {CITE}. Therefore, it is "
               f"impossible to determine from this data who has local administrator rights on WS-AUDIT01.")
    assert ext._score_localadmin(mistral, lt, SEEN, None)["pass"]


def test_held_out_scorer_corrections():
    """Read by hand on the held-out run: Fable named exactly the two admins
    and said, truly, that jdoe-ops holds rights through the group — not a
    finding; Nemotron's "does not contain data on local group membership, so
    it is not possible to confirm" hedges; Opus's "Domain Admins are local
    administrators by default" is a stated default, not a claim from data."""
    truth = {"admins": ["adm-pchen", "adm-rlopez"], "decoys": ["adm-kwu", "jdoe-ops"], "operators": ["jdoe-ops"],
             "idle_admins": ["adm-kwu"], "host": "WS-AUDIT01"}
    fable = (f"Resolving the group grant through membership yields 4 principals: the group itself, adm-rlopez, "
             f"adm-pchen, and jdoe-ops {CITE}.\n\nDomain Admins with rights over WS-AUDIT01:\n"
             f"1. adm-pchen — WriteDacl {CITE}\n2. adm-rlopez — GenericAll via CORP-WS-Operators {CITE}\n")
    assert ext._score_access(fable, truth, SEEN, None)["pass"]
    glm = fable + (f"\nCORP-WS-Operators has exactly two members: adm-rlopez {CITE} and jdoe-ops {CITE} — only "
                   f"adm-rlopez is a Domain Admin.")
    assert ext._score_access(glm, truth, SEEN, None)["pass"]
    assert ext._score_access(fable + "\n- " + glm.split("\n")[-1], truth, SEEN, None)["pass"]   # as a bullet
    glm46 = (f"Here are the members of the Domain Admins group who hold rights over this workstation:\n\n"
             f"## Direct Domain Admin Access\n- adm-pchen — direct rights via has_ace {CITE}\n\n"
             f"## Indirect Access Through Nested Groups\n- jdoe-ops@corp.local\n  - Member of CORP-WS-Operators {CITE}\n"
             f"- adm-rlopez@corp.local\n  - Member of CORP-WS-Operators {CITE}\n")
    assert ext._score_access(glm46, truth, SEEN, None)["false_accounts"] == ["jdoe-ops"]
    table = fable + f"\n| CORP-WS-Operators (group) | GenericAll | members: adm-rlopez, jdoe-ops {CITE} |\n"
    assert ext._score_access(table, truth, SEEN, None)["pass"]
    listed = fable + f"3. jdoe-ops — GenericAll via CORP-WS-Operators {CITE}\n"
    assert ext._score_access(listed, truth, SEEN, None)["false_accounts"] == ["jdoe-ops"]
    lt = {"host": "WS-AUDIT01", "collected": False}
    nemo = (f"adm-pchen has an ACE on WS-AUDIT01 {CITE}. The namespace does not contain data on local group "
            f"membership, so it is not possible to confirm whether these ACEs confer local administrator rights.")
    assert ext._score_localadmin(nemo, lt, SEEN, None)["pass"]
    opus = (f"True local administrator rights cannot be answered from this data {CITE}. adm-pchen is a member of "
            f"Domain Admins — Domain Admins are local administrators on domain-joined machines by default {CITE}.")
    assert ext._score_localadmin(opus, lt, SEEN, None)["pass"]
