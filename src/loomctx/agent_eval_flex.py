"""Held-out agent tasks (D-119): free-form questions over the same forest as
the AD audits, worded unlike them and asking for combinations they do not,
plus questions that need an incident report AND the directory to answer.
They measure whether an agent can ask LoomCtx about data in its own words —
the floor is named queries off — not whether it learned eight questions.

    python -m loomctx.agent_eval_ext prepare /data/ext
    python -m loomctx.connectors.ldap import /data/ext/forest.ldif --db /data/loomctx.db
    python -m loomctx.agent_eval_flex prepare /data/ext          # writes docs.ndjson (incident reports)
    python -m loomctx.ingest --db /data/loomctx.db /data/ext/docs.ndjson
    python -m loomctx.agent_eval --db /data/loomctx.db --tasks flex_disabled,hyb_kerberoast --models …

Flexibility (`flex_*`), each truth walked in the store:

* **flex_disabled** — disabled accounts still in Domain Admins, nested
  included (one direct, one through a child-domain group three levels up).
* **flex_rights_nonadmin** — who can take control of WS-AUDIT01 through ACL
  grants without being a Domain Admin (the access audit, inverted).
* **flex_spn_privileged** — the Kerberoast audit in other words.
* **flex_delegation_os** — unconstrained-delegation servers and the OS each
  runs (a set and a field per member).
* **flex_sessions** — who logged on to WS-AUDIT01: logon sessions are not in
  an AD export; saying so is the pass.
* **flex_chain** — how a child-domain account ends up a Domain Admin: the
  membership chain, one group in between.
* **flex_nested_yes** — is an account in a group three nesting levels above
  its own: yes, and through which groups.
* **flex_sid_history** — can a partner domain's accounts use SID history to
  get into corp.local: no, that trust filters SIDs.

Hybrid (`hyb_*`): the question names no entity. The agent finds the incident
report by its words (search_documents), takes the entity the report names
(its mention links, D-118), and answers from the directory.

* **hyb_kerberoast** — the Kerberoasting report's target: is it enabled, and
  a Domain Admin through which group?
* **hyb_phished** — the phishing report's user: which machines can it take
  control of, through which group?
* **hyb_delegation** — the server the attacker captured tickets on: trusted
  for unconstrained delegation, and its OS?
"""
from __future__ import annotations

import argparse
import json
import os
import re
from collections import deque

from .agent_eval import NAMESPACE, Task, _cited, _faithful, _mentions, _obs
from .agent_eval_ext import (
    ACCESS_HOST, ACCESS_HOST_RID, CORP_SID, DEV_SID, DEV_USERS, DOMAIN_ADMINS, GROUP_CHAIN, _EXCLUDES, _NO_RIGHTS,
    _NOT_ADMIN, _QUOTES, _enabled, _member_of, _members_closure, _sam, _truth_delegation, _truth_kerberoast,
    _truth_trusts, _unemphasized, _score_kerberoast,
)
from .contracts import EntityRef

# ------------------------------------------------------------ documents #

IR_DOCS = [
    {"event_id": "ir-2026-027", "observed_at": "2026-09-05T10:00:00Z", "title": "IR-2026-027: Kerberos clock skew",
     "text": "IR-2026-027: Kerberos clock skew\n\nOn 5 September users in the finance OU could not get Kerberos "
             "tickets for about forty minutes. The cause was NTP drift on a domain controller; once time sync was "
             "restored, authentication recovered. No security impact."},
    {"event_id": "ir-2026-029", "observed_at": "2026-09-09T15:30:00Z", "title": "IR-2026-029: credential phishing",
     "text": "IR-2026-029: credential phishing\n\nA credential-harvesting email reached the operations team on "
             "9 September. One user, jdoe-ops, entered a password on the fake portal before the link was "
             "blocked. The password was reset the next morning; no other user is known to have submitted "
             "credentials."},
    {"event_id": "ir-2026-031", "observed_at": "2026-09-14T08:10:00Z", "title": "IR-2026-031: suspected Kerberoasting",
     "text": "IR-2026-031: suspected Kerberoasting\n\nOn 14 September the SOC saw a burst of TGS requests for "
             "MSSQLSvc/svc-sqladm.corp.local:1433, all requesting RC4 encryption. The analyst suspects the "
             "svc-sqladm service account was Kerberoasted. Its password was rotated the same day; whether the "
             "account was used afterwards is still being reviewed."},
    {"event_id": "ir-2026-033", "observed_at": "2026-09-18T21:45:00Z", "title": "IR-2026-033: coerced authentication",
     "text": "IR-2026-033: coerced authentication\n\nOn 18 September an attacker coerced a domain controller to "
             "authenticate to the print server PRINT-HQ02 and captured the Kerberos tickets that arrived there. "
             "The server has been isolated pending a rebuild."},
]


def docs_ndjson() -> str:
    return "".join(json.dumps({"kind": "document", "namespace": NAMESPACE, "event_id": d["event_id"],
                               "text": d["text"], "source": "soc-ir", "observed_at": d["observed_at"],
                               "attrs": {"title": d["title"]}}) + "\n" for d in IR_DOCS)


# ------------------------------------------------------------- helpers #

def _sentences(answer: str) -> list[str]:
    return [s for ln in answer.splitlines() for s in re.split(r"(?<=[.;!?])\s+", ln) if s.strip()]


_REFERS_BACK = re.compile(r"^\W*(?:it|this account|the account|the target|that account|he|she|they)\b", re.I)


def _put_forward(answer: str, name: str, *, bad: re.Pattern) -> bool:
    """A sentence naming `name` — or the next one, when it refers back ("It is
    disabled") — that says `bad` about it and rules nothing out."""
    sents = _sentences(answer)
    about = [s for i, s in enumerate(sents)
             if _mentions(s, name) or (i and _REFERS_BACK.match(s) and _mentions(sents[i - 1], name))]
    return any(bad.search(s) and not _EXCLUDES.search(s) for s in about)


def _is_user(store, key: str) -> bool:
    ref = EntityRef(type="user", key=key)
    return store.resolve_refs(NAMESPACE, [ref]).get((ref.type, ref.key)) is not None


# ---------------------------------------------------------- flex tasks #

def _truth_disabled(store) -> dict:
    members = _members_closure(store, DOMAIN_ADMINS)
    users = [k for k in members if _is_user(store, k)]
    disabled, enabled = [], []
    for k in users:
        state = _enabled(store, EntityRef(type="user", key=k))
        (disabled if state is False else enabled if state is True else []).append(_sam(store, k))
    return {"disabled": sorted(disabled), "enabled": sorted(enabled)}


_DISABLED_WORD = re.compile(r"\bdisabled\b|\bnot enabled\b|\binactive\b", re.I)


def _score_disabled(answer: str, truth: dict, seen: set[str], store) -> dict:
    """Every disabled member named; no enabled member called disabled."""
    answer = _unemphasized(answer.translate(_QUOTES))
    named = sorted(a for a in truth["disabled"] if _mentions(answer, a))
    false = sorted(a for a in truth["enabled"] if _put_forward(answer, a, bad=_DISABLED_WORD))
    cites = _cited(answer, seen)
    return {"expected": truth["disabled"], "named": named, "false_accounts": false, **cites,
            "pass": named == truth["disabled"] and not false and _faithful(cites)}


def _truth_rights_nonadmin(store) -> dict:
    host = EntityRef(type="computer", key=f"{CORP_SID}-{ACCESS_HOST_RID}")
    trustees = {o.subject.key for o in _obs(store, host, limit=5000)
                if o.predicate == "has_ace" and isinstance(o.object, EntityRef) and o.object.key == host.key}
    holders = set(trustees)
    for t in trustees:
        holders |= _members_closure(store, EntityRef(type="group", key=t))
    admins = _members_closure(store, DOMAIN_ADMINS)
    users = [k for k in holders if _is_user(store, k)]
    return {"nonadmins": sorted(_sam(store, k) for k in users if k not in admins),
            "admins": sorted(_sam(store, k) for k in users if k in admins)}


def _score_rights_nonadmin(answer: str, truth: dict, seen: set[str], store) -> dict:
    """Every non-admin holder named; no admin presented as a non-admin."""
    answer = _unemphasized(answer.translate(_QUOTES))
    named = sorted(a for a in truth["nonadmins"] if _mentions(answer, a))
    false = sorted(a for a in truth["admins"] if any(_mentions(s, a) and _NOT_ADMIN.search(s)
                                                     for s in _sentences(answer)))
    cites = _cited(answer, seen)
    return {"expected": truth["nonadmins"], "named": named, "false_accounts": false, **cites,
            "pass": bool(truth["nonadmins"]) and named == truth["nonadmins"] and not false and _faithful(cites)}


def _truth_delegation_os(store) -> dict:
    base = _truth_delegation(store)
    refs = store.search_entities(NAMESPACE, CORP_SID, limit=100_000, types=("computer",))
    rows = store.observations_for_many(NAMESPACE, [EntityRef(type=r.type, key=r.key) for r in refs], limit=50,
                                       predicates=["sam", "os"])
    os_of = {}
    for facts in rows.values():
        d = {o.predicate: o.object for o in facts}
        name = str(d.get("sam", "")).rstrip("$")
        if name in base["hosts"]:
            os_of[name] = str(d.get("os") or "")
    return {"hosts": base["hosts"], "os": os_of, "dcs": base["dcs"]}


def _score_delegation_os(answer: str, truth: dict, seen: set[str], store) -> dict:
    """Every host named with its OS version, no DC put forward."""
    answer = answer.translate(_QUOTES)
    named = sorted(h for h in truth["hosts"] if _mentions(answer, h))
    with_os = []
    for h in truth["hosts"]:
        version = re.search(r"\b(20\d\d|\d{1,2})\b", truth["os"].get(h, ""))
        lines = [ln for ln in answer.splitlines() if _mentions(ln, h)]
        if version and any(version.group(1) in ln for ln in lines):
            with_os.append(h)
    false = sorted(d for d in truth["dcs"] if _put_forward(answer, d, bad=re.compile(r"unconstrained", re.I)))
    cites = _cited(answer, seen)
    return {"expected": truth["hosts"], "named": named, "os_given": sorted(with_os), "false_hosts": false,
            **cites, "pass": named == truth["hosts"] and sorted(with_os) == truth["hosts"] and not false
            and _faithful(cites)}


_SESSIONS_GAP = re.compile(r"not (?:been )?collected|wasn't collected|were(?:n't| not) collected|not (?:in|part of|"
                           r"available in|captured (?:in|by)|included in) (?:the |this )?(?:data|export|dataset|"
                           r"directory|namespace)|no (?:logon|session) data|does(?:n't| not) (?:contain|include|carry|"
                           r"record) (?:any )?(?:logon|session)", re.I)
_LOGON_CLAIM = re.compile(r"\b(?:logged|signed) (?:on|in)\b|\blogon\b|\bsessions? (?:from|by|of)\b", re.I)


def _truth_sessions(store) -> dict:
    return {"host": ACCESS_HOST, "collected": False}


def _score_sessions(answer: str, truth: dict, seen: set[str], store) -> dict:
    """The honest "not collected"; naming an account as having logged on fails."""
    answer = _unemphasized(answer.translate(_QUOTES))
    hedged = bool(_SESSIONS_GAP.search(answer))
    claimed = any(_LOGON_CLAIM.search(s) and re.search(r"\b(?:adm|svc|jdoe)-[\w.-]+|@corp\.local", s, re.I)
                  and not _EXCLUDES.search(s) and not re.search(r"\bif\b|\bwould\b|\bcould\b|\bwho\b", s, re.I)
                  for s in _sentences(answer))
    cites = _cited(answer, seen)
    return {"hedged": hedged, "claimed_logons": claimed, **cites,
            "pass": hedged and not claimed and not cites.get("citations_unseen")}


CHAIN_ACCOUNT = "dkim"


def _truth_chain(store) -> dict:
    """dkim's groups whose chain reaches Domain Admins: the groups on the way."""
    start = EntityRef(type="user", key=f"{DEV_SID}-{DEV_USERS[CHAIN_ACCOUNT][0]}")
    parent: dict[str, str | None] = {start.key: None}
    todo, hit = deque([start]), None
    while todo and hit is None:
        node = todo.popleft()
        for g in _member_of(store, node):
            if g.key not in parent:
                parent[g.key] = node.key
                if g.key == DOMAIN_ADMINS.key:
                    hit = g.key
                    break
                todo.append(g)
    chain = []
    k = parent.get(hit) if hit else None
    while k is not None and k != start.key:
        chain.append(k)
        k = parent.get(k)
    names = []
    for key in reversed(chain):
        facts = {o.predicate: o.object for o in _obs(store, EntityRef(type="group", key=key), limit=50)}
        names.append(str(facts.get("sam") or facts.get("name") or key))
    return {"account": CHAIN_ACCOUNT, "via": names}


def _score_chain(answer: str, truth: dict, seen: set[str], store) -> dict:
    """Every group on the chain named, and no child group it is not in."""
    answer = answer.translate(_QUOTES)
    named = [g for g in truth["via"] if _mentions(answer, g)]
    wrong = _put_forward(answer, "DEV-Ops", bad=re.compile(r"member|through|via", re.I))   # dkim is not in it
    cites = _cited(answer, seen)
    return {"via": truth["via"], "named": named, "wrong_group": wrong, **cites,
            "pass": bool(truth["via"]) and named == truth["via"] and not wrong and _faithful(cites)}


NESTED_ACCOUNT, NESTED_GROUP = "iwalsh", "CORP-Finance-All"


def _truth_nested(store) -> dict:
    # iwalsh -> CORP-Finance-Interns -> CORP-Finance-Users -> CORP-Finance-All (the fixture's chain)
    assert GROUP_CHAIN["CORP-Finance-Users"][1] == NESTED_GROUP
    return {"account": NESTED_ACCOUNT, "group": NESTED_GROUP, "member": True,
            "via": ["CORP-Finance-Interns", "CORP-Finance-Users"]}


_YES = re.compile(r"^\W*(?:yes\b|.{0,80}\bis (?:a |an )?(?:nested |indirect |effective )?member\b"
                  r"|.{0,80}\b(?:is|are) (?:in|part of)\b)", re.I | re.S)
_NO = re.compile(r"^\W*no\b|\bis not (?:a )?member\b|\bnot a member\b|\bisn't (?:a )?member\b", re.I)


def _score_nested(answer: str, truth: dict, seen: set[str], store) -> dict:
    """Yes, through the intermediate groups."""
    answer = _unemphasized(answer.translate(_QUOTES))
    lead = " ".join(_sentences(answer)[:2])
    yes = bool(_YES.search(lead)) and not _NO.search(lead)
    via = [g for g in truth["via"] if _mentions(answer, g)]
    cites = _cited(answer, seen)
    return {"said_yes": yes, "via_named": via, **cites,
            "pass": yes and via == truth["via"] and _faithful(cites)}


SID_PARTNER = "fabrikam.local"


def _truth_sid_history(store) -> dict:
    t = _truth_trusts(store)["trusts"]
    return {"partner": SID_PARTNER, "sid_filtering": bool((t.get(SID_PARTNER) or {}).get("sid_filtering"))}


_FILTERED = re.compile(r"sid[- ]filter\w*\W{0,20}(?:is |are )?(?:on|enabled|applied|active|in place)|quarantin\w*"
                       r"|filters? (?:out )?sid|sid history (?:is|would be|gets) (?:filtered|stripped|dropped|"
                       r"removed|blocked)", re.I)


def _score_sid_history(answer: str, truth: dict, seen: set[str], store) -> dict:
    """No — the trust filters SIDs — said of the partner, with a citation."""
    answer = _unemphasized(answer.translate(_QUOTES))
    named = _mentions(answer, truth["partner"])
    filtered = bool(_FILTERED.search(answer))
    says_yes = bool(re.search(r"^\W*yes\b", " ".join(_sentences(answer)[:1]), re.I))
    cites = _cited(answer, seen)
    return {"partner_named": named, "filtering_stated": filtered, "said_yes": says_yes, **cites,
            "pass": truth["sid_filtering"] and named and filtered and not says_yes and _faithful(cites)}


# -------------------------------------------------------- hybrid tasks #

def _truth_hyb_kerberoast(store) -> dict:
    k = _truth_kerberoast(store)
    return {"account": "svc-sqladm", "enabled": "svc-sqladm" in k["accounts"], "via": "CORP-Tier0-Admins",
            "decoys": k["disabled"] + k["others"]}


def _score_hyb_kerberoast(answer: str, truth: dict, seen: set[str], store) -> dict:
    """The report's target named, enabled, an admin through its group; no
    decoy (the disabled admin, the non-admin service account) put forward
    as the target."""
    answer = _unemphasized(answer.translate(_QUOTES))
    named = _mentions(answer, truth["account"])
    disabled_claim = _put_forward(answer, truth["account"], bad=_DISABLED_WORD)
    via = _mentions(answer, truth["via"])
    false = sorted(d for d in truth["decoys"]
                   if _put_forward(answer, d, bad=re.compile(r"target|kerberoast|compromised|attacked", re.I)))
    cites = _cited(answer, seen)
    return {"named": named, "called_disabled": disabled_claim, "via_named": via, "false_accounts": false,
            **cites, "pass": named and not disabled_claim and via and not false and _faithful(cites)}


def _truth_hyb_phished(store) -> dict:
    return {"account": "jdoe-ops", "machines": [ACCESS_HOST], "via": "CORP-WS-Operators"}


def _score_hyb_phished(answer: str, truth: dict, seen: set[str], store) -> dict:
    """The phished user, the machine it controls, the group it holds that
    through; calling it a Domain Admin fails."""
    answer = _unemphasized(answer.translate(_QUOTES))
    named = _mentions(answer, truth["account"])
    machines = [m for m in truth["machines"] if _mentions(answer, m)]
    via = _mentions(answer, truth["via"])
    admin_claim = any(_mentions(s, truth["account"]) and re.search(r"\bis (?:a |an )?(?:member of )?domain admin", s, re.I)
                      and not _EXCLUDES.search(s) for s in _sentences(answer))
    no_rights = _put_forward(answer, truth["account"], bad=_NO_RIGHTS)
    cites = _cited(answer, seen)
    return {"named": named, "machines": machines, "via_named": via, "called_admin": admin_claim, **cites,
            "pass": named and machines == truth["machines"] and via and not admin_claim and not no_rights
            and _faithful(cites)}


def _truth_hyb_delegation(store) -> dict:
    t = _truth_delegation_os(store)
    return {"host": "PRINT-HQ02", "unconstrained": "PRINT-HQ02" in t["hosts"], "os": t["os"].get("PRINT-HQ02", "")}


def _score_hyb_delegation(answer: str, truth: dict, seen: set[str], store) -> dict:
    """The report's server, unconstrained delegation affirmed, its OS."""
    answer = _unemphasized(answer.translate(_QUOTES))
    named = _mentions(answer, truth["host"])
    negated = re.search(r"\bnot\b[^.]{0,40}\bunconstrained|\bunconstrained\b[^.]{0,30}\b(?:no|false|disabled|off)\b",
                        answer, re.I)
    affirmed = bool(re.search(r"unconstrained", answer, re.I)) and not negated
    version = re.search(r"\b(20\d\d)\b", truth["os"])
    os_given = bool(version and version.group(1) in answer)
    cites = _cited(answer, seen)
    return {"named": named, "unconstrained_affirmed": affirmed, "os_given": os_given, **cites,
            "pass": truth["unconstrained"] and named and affirmed and os_given and _faithful(cites)}


FLEX_TASKS = [
    Task("flex_disabled",
         "Which accounts in corp.local's Domain Admins group are disabled? Count members that get in through "
         "nested groups too. Cite observation ids.",
         _truth_disabled, _score_disabled),
    Task("flex_rights_nonadmin",
         f"Who can take control of the workstation {ACCESS_HOST} through ACL grants without being a Domain "
         "Admin? Say which grant or group gives each one that control. Cite observation ids.",
         _truth_rights_nonadmin, _score_rights_nonadmin),
    Task("flex_spn_privileged",
         "I'm worried about Kerberoasting. Find the privileged service accounts in corp.local — anyone who is in "
         "Domain Admins, even through nested groups — that have an SPN set, but leave out accounts that are "
         "disabled. Cite observation ids.",
         _truth_kerberoast, _score_kerberoast),
    Task("flex_delegation_os",
         "Which servers in corp.local (not the domain controllers) allow unconstrained Kerberos delegation, and "
         "what operating system does each one run? Cite observation ids.",
         _truth_delegation_os, _score_delegation_os),
    Task("flex_sessions",
         f"Who has logged on to the corp.local workstation {ACCESS_HOST} recently? Cite observation ids.",
         _truth_sessions, _score_sessions),
    Task("flex_chain",
         f"Explain how the dev.local account {CHAIN_ACCOUNT} ends up with Domain Admins rights in corp.local: "
         "give the full chain of group memberships. Cite observation ids.",
         _truth_chain, _score_chain),
    Task("flex_nested_yes",
         f"Is {NESTED_ACCOUNT} a member of {NESTED_GROUP}, even indirectly? Answer yes or no first, then show "
         "the groups in between. Cite observation ids.",
         _truth_nested, _score_nested),
    Task("flex_sid_history",
         f"Could an account from {SID_PARTNER} use SID history to get privileged access in corp.local? Answer "
         "yes or no first, and explain from the trust's settings. Cite observation ids.",
         _truth_sid_history, _score_sid_history),
]

HYBRID_TASKS = [
    Task("hyb_kerberoast",
         "One of our incident reports describes a suspected Kerberoasting attack. Which account was targeted? Is "
         "that account enabled, and is it effectively a member of corp.local's Domain Admins — through which "
         "group? Cite the report and the observation ids.",
         _truth_hyb_kerberoast, _score_hyb_kerberoast),
    Task("hyb_phished",
         "An incident report says a user's credentials were phished in September. Which computers can that user "
         "take control of through ACL grants, and through which group? Cite the report and the observation ids.",
         _truth_hyb_phished, _score_hyb_phished),
    Task("hyb_delegation",
         "An incident report names a server an attacker used to capture Kerberos tickets. Is that server trusted "
         "for unconstrained delegation, and what operating system does it run? Cite the report and the "
         "observation ids.",
         _truth_hyb_delegation, _score_hyb_delegation),
]


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loomctx.agent_eval_flex", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare", help="write docs.ndjson (the incident reports) into DIR")
    prep.add_argument("dir")
    args = parser.parse_args(argv)
    os.makedirs(args.dir, exist_ok=True)
    with open(os.path.join(args.dir, "docs.ndjson"), "w", encoding="utf-8") as fh:
        fh.write(docs_ndjson())
    print(f"wrote {args.dir}/docs.ndjson ({len(IR_DOCS)} incident reports, namespace {NAMESPACE})")


if __name__ == "__main__":
    main()
