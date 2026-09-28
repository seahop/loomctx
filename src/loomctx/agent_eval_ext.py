"""Extended agent-eval tasks — run on demand, NOT part of the published
scorecard (`docs/models.md`) until their scoring has been read against real
answers.

    python -m loomctx.agent_eval_ext prepare /data/ext         # write the two LDIF exports
    python -m loomctx.connectors.ldap import /data/ext/forest.ldif --db /data/loomctx.db
    python -m loomctx.connectors.ldap import /data/ext/lab.ldif --db /data/loomctx.db --source lab-export
    python -m loomctx.agent_eval --db /data/loomctx.db --tasks xdomain,coverage --models …

* **xdomain** — a cross-domain administrative-membership audit, the review
  run on every forest trust: which accounts of the child domain `dev.local`
  are effective members of `corp.local`'s Domain Admins, directly or
  through nested groups, and is each enabled? Five are (one direct, one via
  a parent group, three via a child group nested in it — one disabled);
  child groups nested into ordinary parent groups are distractors. Scored
  as a set: every member named, the disabled one called disabled, no
  non-member presented as one, faithful citations.
* **coverage** — the honest "not collected": `lab.local` was exported
  without group membership (no member / memberOf anywhere, which the LDAP
  connector records as a coverage gap, D-082). Asked which groups one of
  its accounts belongs to, the right answer says membership was not
  collected; a confident "none" or a guessed group fails.

The directory is the synthetic `ad_gen` forest (seed 7, small) exported
forest-wide — a global-catalog dump — so a parent group lists child members
by their own DNs, as within one AD forest. Membership only; no rights.
"""
from __future__ import annotations

import argparse
import os
import re
from collections import deque

from .agent_eval import (_CVE_SENTENCE, NAMESPACE, Task, _asserted, _cited, _faithful, _mentions,
                         _obs, _SENTENCE)
from .connectors import ad_gen
from .contracts import EntityRef

CORP_SID = "S-1-5-21-1111111111-2222222222-3333333333"
DEV_SID = "S-1-5-21-4444444444-5555555555-6666666666"
LAB_SID = "S-1-5-21-7777777777-8888888888-9999999999"
CORP = "DC=corp,DC=local"
DEV = "DC=dev,DC=local"
LAB = "DC=lab,DC=local"
DOMAIN_ADMINS = EntityRef(type="group", key=f"{CORP_SID}-512")
DA_DN = f"CN=Domain Admins,CN=Users,{CORP}"

# dev.local accounts: name -> (rid, enabled)
DEV_USERS = {
    "dlee": (1101, True), "dkim": (1102, True), "dpatel": (1103, True), "dgarcia": (1104, True),
    "dnguyen": (1105, False), "dchen": (1106, True), "dsmith": (1107, True), "dbrown": (1108, True),
    "djones": (1109, True), "dwhite": (1110, True), "dmartin": (1111, True), "dclark": (1112, True),
}
DEV_GROUPS = {"DEV-Ops": (1201, ["dpatel", "dgarcia", "dnguyen"]),
              "DEV-Engineering": (1202, ["dchen", "dsmith", "dbrown", "djones", "dwhite"]),
              "DEV-Helpdesk": (1203, ["dmartin", "dclark"])}
LAB_USERS = ["labadmin", "labsvc-backup", "labuser1", "labuser2", "labuser3", "labuser4"]
LAB_GROUPS = ["LAB-Admins", "LAB-Backup", "LAB-Users"]
LAB_ACCOUNT = "labsvc-backup"
EXPORT_AT = "2026-09-20T09:00:00Z"


def _sd() -> str:
    """An empty-DACL security descriptor: collected, grants nothing."""
    return ad_gen.b64(ad_gen.build_sd([]))


def _obj(dn: str, classes: list[str], sid: str, name: str, **attrs) -> str:
    lines = [f"dn: {dn}", *[f"objectClass: {c}" for c in ["top", *classes]], f"objectSid: {sid}",
             f"name: {name}", f"nTSecurityDescriptor:: {_sd()}"]
    for k, v in attrs.items():
        for item in (v if isinstance(v, list) else [v]):
            lines.append(f"{k}: {item}")
    return "\n".join(lines)


def _user(dn: str, sid: str, sam: str, enabled: bool, **attrs) -> str:
    return _obj(dn, ["person", "organizationalPerson", "user"], sid, sam, sAMAccountName=sam,
                userAccountControl=512 if enabled else 514, **attrs)


def forest_ldif(seed: int = 7) -> str:
    """The generated corp.local directory plus a dev.local child domain and
    the parent groups that nest it — one forest-wide export."""
    base, _ = ad_gen.generate(seed, "small")
    dev = lambda name: f"CN={name},CN=Users,{DEV}"   # noqa: E731
    corp = lambda name: f"CN={name},CN=Users,{CORP}"  # noqa: E731
    out = [_obj(DEV, ["domain", "domainDNS"], DEV_SID, "dev.local")]
    for sam, (rid, enabled) in DEV_USERS.items():
        extra = {"memberOf": DA_DN} if sam == "dlee" else {}            # direct cross-domain member
        out.append(_user(dev(sam), f"{DEV_SID}-{rid}", sam, enabled, **extra))
    for name, (rid, members) in DEV_GROUPS.items():
        out.append(_obj(dev(name), ["group"], f"{DEV_SID}-{rid}", name, sAMAccountName=name,
                        member=[dev(m) for m in members]))
    # parent groups: the tier-0 group sits in Domain Admins and nests the
    # child's ops group plus one child account; two ordinary groups nest
    # the other child groups (distractors)
    out.append(_obj(corp("CORP-Tier0-Admins"), ["group"], f"{CORP_SID}-5001", "CORP-Tier0-Admins",
                    sAMAccountName="CORP-Tier0-Admins", memberOf=DA_DN,
                    member=[dev("DEV-Ops"), dev("dkim")]))
    out.append(_obj(corp("CORP-App-Readers"), ["group"], f"{CORP_SID}-5002", "CORP-App-Readers",
                    sAMAccountName="CORP-App-Readers", member=[dev("DEV-Engineering")]))
    out.append(_obj(corp("CORP-Support"), ["group"], f"{CORP_SID}-5003", "CORP-Support",
                    sAMAccountName="CORP-Support", member=[dev("DEV-Helpdesk")]))
    return base.rstrip("\n") + "\n\n" + "\n\n".join(out) + "\n"


def lab_ldif() -> str:
    """lab.local exported without group membership: no member / memberOf on
    any object (an ldapsearch that did not request them)."""
    lab = lambda name: f"CN={name},CN=Users,{LAB}"   # noqa: E731
    out = ["# lab.local export (synthetic; membership attributes not requested)", f"# {EXPORT_AT}",
           "version: 1", "", _obj(LAB, ["domain", "domainDNS"], LAB_SID, "lab.local")]
    for i, sam in enumerate(LAB_USERS):
        out.append(_user(lab(sam), f"{LAB_SID}-{1101 + i}", sam, True))
    for i, name in enumerate(LAB_GROUPS):
        out.append(_obj(lab(name), ["group"], f"{LAB_SID}-{1201 + i}", name, sAMAccountName=name))
    return "\n\n".join(out) + "\n"


# ------------------------------------------------------------------ xdomain #

def _member_of(store, ref: EntityRef) -> list[EntityRef]:
    return [o.object for o in _obs(store, ref, limit=2000)
            if o.predicate == "member_of" and isinstance(o.object, EntityRef)]


def _enabled(store, ref: EntityRef) -> bool | None:
    vals = [o for o in _obs(store, ref, limit=500) if o.predicate == "enabled"]
    return bool(max(vals, key=lambda o: o.observed_at).object) if vals else None


def _truth_xdomain(store) -> dict:
    """Every dev.local account whose member_of closure reaches Domain Admins,
    walked in the store (so the truth is what was loaded, not what the
    fixture meant), with its enabled state."""
    members, others = {}, []
    for sam, (rid, _) in DEV_USERS.items():
        start = EntityRef(type="user", key=f"{DEV_SID}-{rid}")
        seen, todo, hit = {start.key}, deque([start]), False
        while todo and not hit:
            for g in _member_of(store, todo.popleft()):
                if g.key == DOMAIN_ADMINS.key:
                    hit = True
                    break
                if g.key not in seen:
                    seen.add(g.key)
                    todo.append(g)
        if hit:
            members[sam] = _enabled(store, start)
        else:
            others.append(sam)
    return {"members": members, "others": others}


# a sentence that names an account only to exclude it
_EXCLUDES = re.compile(r"\b(?:not|no|none|neither|nor|never|without|excluded?|isn't|aren't|doesn't|don't|"
                       r"rather than|instead of)\b", re.I)
_DISABLED = re.compile(r"\bdisabled\b|\bnot enabled\b|\binactive\b|\baccountdisable\b", re.I)


# a table cell or a field saying "not enabled": "| no |", "| **No**—…", "enabled: no"
_DISABLED_CELL = re.compile(r"\|\s*\**\s*no\b|\benabled\W{0,4}no\b", re.I)
_BLOCK_LINE = re.compile(r"\s*(?:[-*+|]|\d+[.)])")
_ADMIN = re.compile(r"domain admins|tier0|tier-0", re.I)
# typographic apostrophes some models emit ("can’t", "isn’t")
_QUOTES = str.maketrans({"\u2019": "'", "\u2018": "'"})


def _sentences(answer: str, key: str) -> list[str]:
    return [s for p in answer.split("\n") for s in _CVE_SENTENCE.split(p) if _mentions(s, key)]


def _lines(answer: str, key: str) -> list[tuple[str, str]]:
    """Each line (a table row or list item is one line) that names `key`,
    with its lead-in: the line that introduces the list or table it sits in
    ("The remaining accounts never reach Domain Admins:") — D-089's lesson,
    a ruling-out often lives there, not in the row."""
    lines, out = answer.split("\n"), []
    for i, line in enumerate(lines):
        if not _mentions(line, key):
            continue
        j = i - 1
        while j >= 0 and (_BLOCK_LINE.match(lines[j]) or not lines[j].strip()):
            j -= 1
        lead = lines[j].strip().strip("*").strip() if j >= 0 and _BLOCK_LINE.match(lines[i]) else ""
        # only a line that introduces the list is a lead-in: it ends with ":"
        # or is a heading — a prose sentence above a bullet is not
        out.append((line, lead if lead.endswith(":") or lead.startswith("#") else ""))
    return out


def _score_xdomain(answer: str, truth: dict, seen: set[str], store) -> dict:
    answer = answer.translate(_QUOTES)
    members, others = truth["members"], truth["others"]
    named = sorted(m for m in members if _mentions(answer, m))
    disabled = [m for m, on in members.items() if on is False]
    flagged = [m for m in disabled
               if any(_DISABLED.search(line) or _DISABLED_CELL.search(line) for line, _ in _lines(answer, m))]
    # a non-member counts only where a line puts it forward as an admin (it
    # or its lead-in names Domain Admins / the tier-0 group, or it is a table
    # row) and neither
    # the line nor its lead-in rules it out
    false_members = sorted(o for o in others if any(
        not _EXCLUDES.search(line) and not _EXCLUDES.search(lead)
        and (_ADMIN.search(line) or _ADMIN.search(lead) or line.lstrip().startswith("|"))
        for line, lead in _lines(answer, o)))
    cites = _cited(answer, seen)
    ok = bool(members) and len(named) == len(members) and len(flagged) == len(disabled) and not false_members
    return {"members_expected": sorted(members), "members_named": named,
            "disabled_expected": disabled, "disabled_flagged": flagged,
            "false_members": false_members, **cites, "pass": ok and _faithful(cites)}


# ----------------------------------------------------------------- coverage #

def _truth_coverage(store) -> dict:
    groups = [o.object.key for o in _obs(store, EntityRef(type="user", key=f"{LAB_SID}-1102"), limit=500)
              if o.predicate == "member_of" and isinstance(o.object, EntityRef)]
    return {"account": LAB_ACCOUNT, "stored_memberships": groups, "groups": LAB_GROUPS}


# the answer says membership was not collected / cannot be determined
_NOT_COLLECTED = re.compile(
    r"not (?:been )?(?:collected|exported|included|captured|recorded|requested|dumped|available|present)"
    r"|(?:wasn't|weren't|was not|were not|isn't|is not) (?:collected|exported|included|captured|recorded|"
    r"requested|dumped|available|present)"
    r"|no (?:group[- ]?)?membership (?:data|information|attributes?|records?)"
    r"|(?:membership|group) (?:data|information|attributes?) (?:is |are |was |were )?(?:missing|absent|unavailable)"
    r"|coverage|(?:can(?:not|'t)|could(?:n't| not)|unable to) (?:be )?"
    r"(?:determin|tell|confirm|say|verif|identify|establish|reliably)\w*"
    r"|\bunknown\b|incomplete|partial (?:export|collection|data)",
    re.I)
# a flat "it is in no group" with no hedge
_DEFINITIVE_NONE = re.compile(r"not a member of any|\bis (?:not|no) member|\bno group memberships?\b|"
                              r"belongs to no\b|member of no\b|isn't a member of any", re.I)


# "there is no account named X": the account exists — that is a failed
# lookup, not an honest "not collected"
_NO_ACCOUNT = re.compile(r"no (?:such )?(?:account|user|entity)\b[^.]{0,40}?\b(?:named|called|matching)"
                         r"|(?:account|user)\b[^.]{0,40}?\b(?:does not|doesn't) exist"
                         r"|(?:could(?:n't| not)|can(?:not|'t)|unable to|did not|didn't) (?:find|locate|resolve) "
                         r"(?:the |an |any |that )?(?:account|user|entity)\b(?!'s)(?!\s+(?:group|membership))", re.I)


def _score_coverage(answer: str, truth: dict, seen: set[str], store) -> dict:
    answer = answer.translate(_QUOTES)
    asserted = _asserted(answer)
    first = _SENTENCE.split(asserted.strip())[0]
    hedged = bool(_NOT_COLLECTED.search(answer))
    flat_none = bool(_DEFINITIVE_NONE.search(first)) and not _NOT_COLLECTED.search(first)
    # a lab group put forward as a membership, in a sentence that neither
    # hedges nor excludes it, is a guess the data cannot support
    guessed = sorted(g for g in truth["groups"]
                     if any(not (_NOT_COLLECTED.search(s) or _EXCLUDES.search(s) or
                                 re.search(r"\b(?:may|might|could|likely|probably|possibly|perhaps)\b", s, re.I))
                            for s in _sentences(answer, g)))
    no_account = bool(_NO_ACCOUNT.search(_asserted(answer)))    # anywhere, asides aside
    cites = _cited(answer, seen)
    # flat_none is reported, not failed on: "the expansion returned no group
    # memberships" describes the data; an answer that never hedges fails anyway
    ok = hedged and not guessed and not no_account
    return {"hedged": hedged, "flat_none": flat_none, "guessed_groups": guessed, "no_account": no_account,
            "first_sentence": first[:120], **cites, "pass": ok and _faithful(cites)}


EXTENDED_TASKS = [
    Task("xdomain",
         "Access review for the forest trust between corp.local and its child domain dev.local: which "
         "accounts from dev.local are effective members of the Domain Admins group in corp.local, "
         "directly or through nested groups? For each account, name the group it is added through and "
         "say whether the account is enabled. Cite observation ids.",
         _truth_xdomain, _score_xdomain),
    Task("coverage",
         f"Which groups is the lab.local account {LAB_ACCOUNT} a member of? Cite observation ids.",
         _truth_coverage, _score_coverage),
]


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loomctx.agent_eval_ext", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare", help="write forest.ldif and lab.ldif into DIR")
    prep.add_argument("dir")
    prep.add_argument("--seed", type=int, default=7)
    args = parser.parse_args(argv)
    os.makedirs(args.dir, exist_ok=True)
    with open(os.path.join(args.dir, "forest.ldif"), "w", encoding="utf-8") as fh:
        fh.write(forest_ldif(args.seed))
    with open(os.path.join(args.dir, "lab.ldif"), "w", encoding="utf-8") as fh:
        fh.write(lab_ldif())
    print(f"wrote {args.dir}/forest.ldif and {args.dir}/lab.ldif (namespace {NAMESPACE})")


if __name__ == "__main__":
    main()
