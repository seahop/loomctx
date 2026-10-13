"""Extended agent-eval tasks — five Active Directory audits, run on demand
and published as their own scorecard in `docs/models.md` ("Active Directory
audits"), separate from the four core tasks.

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

* **groups** — a group-membership report for the corp.local account
  `mreyes`: every group it belongs to, direct (2) and through nesting (3
  more, the last four levels up — past a scope walk's depth cap). A group
  nested *into* one of its groups and a sibling group are distractors.
* **delegation** — a Kerberos delegation hardening review: which computer
  accounts other than domain controllers are trusted for unconstrained
  delegation — three servers among thousands of computers; the domain
  controllers (which are, by design) and a server with *constrained*
  delegation are distractors.
* **trusts** — a trust review: each domain corp.local trusts, with its
  direction, whether it is transitive and whether SID filtering is on
  (dev.local: bidirectional, transitive; partner.local: non-transitive;
  fabrikam.local: SID-filtered).

The directory is the synthetic `ad_gen` forest (seed 7, `large` by default:
10,000 users, 1,500 groups, 2,000 computers; `--scale small` for tests) exported
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
# groups: mreyes's memberships — name -> (rid, parent)
GROUPS_ACCOUNT = "mreyes"
GROUP_CHAIN = {"CORP-Finance-Users": (95004, "CORP-Finance-All"), "CORP-Finance-All": (95005, "CORP-ERP-Access"),
               "CORP-ERP-Access": (95006, "CORP-Remote-Apps"), "CORP-Remote-Apps": (95007, None),
               "CORP-VPN-Users": (95008, None)}
GROUP_DIRECT = ["CORP-Finance-Users", "CORP-VPN-Users"]
GROUP_DISTRACTORS = {"CORP-Finance-Interns": (95009, "CORP-Finance-Users"),     # nested INTO hers
                     "CORP-Finance-Managers": (95010, "CORP-Finance-All")}     # a sibling
# delegation: computers planted in OU=Servers — name -> (rid, unconstrained, constrained target)
DELEGATION_HOSTS = {"APP-LEGACY01": (95201, True, None), "PRINT-HQ02": (95202, True, None),
                    "SQL-OLD03": (95203, True, None), "WEB-KCD04": (95204, False, "HTTP/intranet.corp.local")}
UAC_WORKSTATION, UAC_UNCONSTRAINED = 0x1000, 0x80000
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


def forest_ldif(seed: int = 7, scale: str = "large", style: str = "plain") -> str:
    """The generated corp.local directory plus a dev.local child domain and
    the parent groups that nest it, the groups task's account and groups and
    the delegation task's servers — one forest-wide export."""
    base, _ = ad_gen.generate(seed, scale, style)
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
    out.append(_obj(corp("CORP-Tier0-Admins"), ["group"], f"{CORP_SID}-95001", "CORP-Tier0-Admins",
                    sAMAccountName="CORP-Tier0-Admins", memberOf=DA_DN,
                    member=[dev("DEV-Ops"), dev("dkim")]))
    out.append(_obj(corp("CORP-App-Readers"), ["group"], f"{CORP_SID}-95002", "CORP-App-Readers",
                    sAMAccountName="CORP-App-Readers", member=[dev("DEV-Engineering")]))
    out.append(_obj(corp("CORP-Support"), ["group"], f"{CORP_SID}-95003", "CORP-Support",
                    sAMAccountName="CORP-Support", member=[dev("DEV-Helpdesk")]))
    # groups: mreyes, its chain, and the distractors (each with a member)
    for name, (rid, parent) in {**GROUP_CHAIN, **GROUP_DISTRACTORS}.items():
        out.append(_obj(corp(name), ["group"], f"{CORP_SID}-{rid}", name, sAMAccountName=name,
                        **({"memberOf": corp(parent)} if parent else {})))
    out.append(_user(corp(GROUPS_ACCOUNT), f"{CORP_SID}-95101", GROUPS_ACCOUNT, True,
                     memberOf=[corp(g) for g in GROUP_DIRECT]))
    out.append(_user(corp("iwalsh"), f"{CORP_SID}-95102", "iwalsh", True, memberOf=corp("CORP-Finance-Interns")))
    out.append(_user(corp("kbrandt"), f"{CORP_SID}-95103", "kbrandt", True, memberOf=corp("CORP-Finance-Managers")))
    # delegation: three legacy servers trusted for unconstrained delegation,
    # one with constrained delegation only
    for name, (rid, unconstrained, target) in DELEGATION_HOSTS.items():
        extra = {"msDS-AllowedToDelegateTo": target} if target else {}
        out.append(_obj(f"CN={name},OU=Servers,{CORP}", ["computer"], f"{CORP_SID}-{rid}", name,
                        sAMAccountName=f"{name}$", operatingSystem="Windows Server 2016 Standard",
                        userAccountControl=UAC_WORKSTATION | (UAC_UNCONSTRAINED if unconstrained else 0),
                        **extra))
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


# a table cell or a field saying "not enabled": "| no |", "| **No**—…", "enabled: no",
# "**Enabled Status:** No" (a label word between, as the realistic forest's answers write it)
_DISABLED_CELL = re.compile(r"\|\s*\**\s*(?:no|false)\b"
                            r"|\benabled(?:\s+(?:status|state|flag))?\W{0,6}(?:no|false)\b", re.I)
_BLOCK_LINE = re.compile(r"\s*(?:[-+|]|\*(?!\*)|\d+[.)])")     # "**Bold:**" is a lead-in, not a bullet
_ADMIN = re.compile(r"domain admins|tier0|tier-0", re.I)
# typographic apostrophes some models emit ("can’t", "isn’t")
_QUOTES = str.maketrans({"\u2019": "'", "\u2018": "'"})


def _sentences(answer: str, key: str) -> list[str]:
    return [s for p in answer.split("\n") for s in _CVE_SENTENCE.split(p) if _mentions(s, key)]


_ITEM_START = re.compile(r"\s*(?:#|\**\s*\d+[.)])")


def _marker(line: str) -> str:
    """A list line's kind: numbered, table row, or bullet."""
    t = line.lstrip().lstrip("*").lstrip()
    return "num" if re.match(r"\d+[.)]", t) else "row" if line.lstrip().startswith("|") else "bullet"


def _lines(answer: str, key: str, others: tuple[str, ...] = ()) -> list[tuple[str, str]]:
    """Each list item or table row that names `key` — the line plus the
    lines under it up to a blank line, a heading, the next numbered item or
    a line naming another account ("**5. dnguyen**" then "- **Enabled**:
    No"; "5) dnguyen" then "   - Enabled: False") — with its
    lead-in: the line that introduces the list or table it sits in ("The
    remaining accounts never reach Domain Admins:") — D-089's lesson, a
    ruling-out often lives there, not in the row."""
    lines, out = answer.split("\n"), []
    for i, raw in enumerate(lines):
        if not _mentions(raw, key):
            continue
        k, line = i + 1, raw
        heading = bool(re.match(r"\s*(?:#|\*\*\s*\d+[.)])", raw))   # "### 2. fabrikam.local", "**3. partner.local**"
        while (k < len(lines) and (lines[k].strip() or heading)
               and not (heading and re.match(r"\s*(?:#|\*\*\s*\d+[.)])", lines[k]))
               and not (not heading and _ITEM_START.match(lines[k]))
               # the next list item of the same kind at this level is its own
               # line; a numbered item's "- field" bullets and sub-bullets stay
               and not (not heading and _BLOCK_LINE.match(lines[k]) and _BLOCK_LINE.match(raw)
                        and _marker(lines[k]) == _marker(raw)
                        and len(lines[k]) - len(lines[k].lstrip()) <= len(raw) - len(raw.lstrip()))
               and not any(_mentions(lines[k], o) for o in others if o != key)):
            line += "\n" + lines[k]
            k += 1
        j = i - 1
        while j >= 0 and (_BLOCK_LINE.match(lines[j]) or not lines[j].strip()):
            j -= 1
        lead = lines[j].strip().strip("*").strip() if j >= 0 and _BLOCK_LINE.match(lines[i]) else ""
        # only a line that introduces the list is a lead-in: it ends with ":"
        # or is a heading — a prose sentence above a bullet is not
        lead = lead if lead.endswith(":") or lead.startswith("#") else ""
        # a nested bullet's parent ("- Two groups … are **not** mreyes's
        # groups:") and the section's heading ("### Not a finding") frame it too
        indent = len(raw) - len(raw.lstrip())
        for k2 in range(i - 1, -1, -1):
            above = lines[k2]
            if above.strip() and len(above) - len(above.lstrip()) < indent and _BLOCK_LINE.match(above):
                if above.rstrip().rstrip("*").endswith(":"):
                    lead += " " + above.strip()
                break
        heading = next((lines[k2].strip() for k2 in range(i - 1, -1, -1) if lines[k2].lstrip().startswith("#")), "")
        out.append((line, (lead + " " + heading).strip()))
    return out


def _score_xdomain(answer: str, truth: dict, seen: set[str], store) -> dict:
    answer = answer.translate(_QUOTES)
    members, others = truth["members"], truth["others"]
    accounts = (*members, *others)
    named = sorted(m for m in members if _mentions(answer, m))
    disabled = [m for m, on in members.items() if on is False]
    flagged = [m for m in disabled
               if any(_DISABLED.search(line) or _DISABLED_CELL.search(line) for line, _ in _lines(answer, m, accounts))]
    # a non-member counts only where a line puts it forward as an admin (it
    # or its lead-in names Domain Admins / the tier-0 group, or it is a table
    # row) and neither
    # the line nor its lead-in rules it out
    false_members = sorted(o for o in others if any(
        not _EXCLUDES.search(line) and not _EXCLUDES.search(lead)
        and (_ADMIN.search(line) or _ADMIN.search(lead) or line.lstrip().startswith("|"))
        for line, lead in _lines(answer, o, accounts)))
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
    r"|(?:did(?:n't| not)|does(?:n't| not)|do(?:n't| not)) (?:collect|export|include|capture|record)"
    r"|missing(?: data)?,? (?:rather than|not) (?:necessarily )?(?:empty|absen\w*|none)"
    r"|(?:does(?:n't| not)|do(?:n't| not)) have (?:any |its |their )?(?:group )?(?:memberships? )?collected"
    r"|coverage|(?:can(?:not|'t)|could(?:n't| not)|unable to) (?:be )?"
    r"(?:determin|tell|confirm|say|verif|identify|establish|reliably|name|list)\w*"
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
    # emphasis is not wording: "did **not** collect" hedges as plainly as without it
    answer = re.sub(r"\*{1,3}|(?<!\w)_{1,3}|_{1,3}(?!\w)", "", answer.translate(_QUOTES))
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


# ------------------------------------------------------------------- groups #

def _truth_groups(store) -> dict:
    """mreyes's member_of closure, walked in the store, by group name."""
    start = EntityRef(type="user", key=f"{CORP_SID}-95101")
    by_key = {f"{CORP_SID}-{rid}": name for name, (rid, _) in {**GROUP_CHAIN, **GROUP_DISTRACTORS}.items()}
    direct = [by_key.get(g.key, g.key) for g in _member_of(store, start)]
    seen, todo = set(), deque(_member_of(store, start))
    while todo:
        g = todo.popleft()
        if g.key in seen:
            continue
        seen.add(g.key)
        todo.extend(_member_of(store, g))
    groups = sorted(by_key.get(k, k) for k in seen)
    keys = {by_key.get(k, k): k for k in seen}
    return {"account": GROUPS_ACCOUNT, "groups": groups, "keys": keys, "direct": sorted(direct),
            "distractors": sorted(n for n in GROUP_DISTRACTORS if n not in groups)}


def _score_groups(answer: str, truth: dict, seen: set[str], store) -> dict:
    answer = answer.translate(_QUOTES)
    names = (*truth["groups"], *truth["distractors"])
    # a group named, or identified by its SID (a pack that could not name it)
    keys = truth.get("keys", {})
    named = sorted(g for g in truth["groups"] if _mentions(answer, g) or (g in keys and _mentions(answer, keys[g])))
    def claims(line: str, lead: str, d: str) -> bool:
        if _EXCLUDES.search(line) or _EXCLUDES.search(lead):
            return False
        # "CORP-Finance-Interns (…) is a member of CORP-Finance-Users" states
        # the directory's structure — as does "CORP-Finance-Interns →
        # CORP-Finance-Users"; it puts the distractor forward only where the
        # line also says the account inherits it
        plain = line.replace("*", "").replace("`", "")
        child = re.search(re.escape(d) + r"\S*\s*(?:\([^)]*\)\s*)*(?:(?:is|are)?\s*(?:a\s+)?(?:member|nested|contained)\w*\s+"
                          r"(?:of|in|into|inside)\b|(?:→|->|=>))", plain, re.I)
        return not (child and not re.search(r"inherit|\b" + re.escape(truth.get("account", GROUPS_ACCOUNT)), plain, re.I))
    false_groups = sorted(d for d in truth["distractors"] if any(
        claims(line, lead, d) for line, lead in _lines(answer, d, names)))
    cites = _cited(answer, seen)
    ok = bool(truth["groups"]) and named == truth["groups"] and not false_groups
    return {"groups_expected": truth["groups"], "groups_named": named, "false_groups": false_groups,
            **cites, "pass": ok and _faithful(cites)}


# --------------------------------------------------------------- delegation #

def _truth_delegation(store) -> dict:
    """Every corp.local computer trusted for unconstrained delegation that is
    not a domain controller — read from the store, all of them."""
    computers = store.search_entities(NAMESPACE, CORP_SID, limit=100_000, types=("computer",))
    refs = [EntityRef(type=c.type, key=c.key) for c in computers]
    rows = store.observations_for_many(NAMESPACE, refs, limit=50,
                                       predicates=["unconstrained_delegation", "is_dc", "sam"])
    hosts, dcs = [], []
    for ref in refs:
        mine = rows.get((ref.type, ref.key), [])
        facts = {o.predicate: o.object for o in mine}
        name = str(facts.get("sam", ref.key)).rstrip("$")
        if facts.get("unconstrained_delegation") is True:
            (dcs if facts.get("is_dc") is True else hosts).append(name)
    decoys = [n for n, (_, unconstrained, _) in DELEGATION_HOSTS.items() if not unconstrained]
    return {"hosts": sorted(hosts), "dcs": sorted(dcs), "decoys": decoys, "computers": len(refs)}


_DC = re.compile(r"domain controller|\bDCs?\b", re.I)


def _score_delegation(answer: str, truth: dict, seen: set[str], store) -> dict:
    """Every planted server named; a domain controller or the constrained-
    delegation server counts against the answer only where a line puts it
    forward as a finding — not where the line rules it out, calls it a
    domain controller, or calls its delegation constrained."""
    answer = answer.translate(_QUOTES)
    names = (*truth["hosts"], *truth["dcs"], *truth["decoys"])
    named = sorted(h for h in truth["hosts"] if _mentions(answer, h))

    def clause(line: str, name: str) -> str:
        parts = re.split(r"(?<=[.;!?])\s+|,\s+(?:but|while|whereas|although)\b|\s+—\s+", line)
        return next((p for p in parts if _mentions(p, name)), line)

    def put_forward(line: str, lead: str, name: str, dc: bool) -> bool:
        c = clause(line, name)
        sentences = [x for x in re.split(r"(?<=[.;!?])\s+", line) if _mentions(x, name)]
        if (_EXCLUDES.search(c) or _EXCLUDES.search(lead)
                or any(_EXCLUDES.search(x) or re.search(r"\bonly\b|\bother (?:computers|hosts|accounts|servers|machines|members)\b"
                                                          r"|(?<!un)constrained[- ]delegation host", x, re.I) for x in sentences)
                or re.search(r"\bonly\b|\bother (?:computers|hosts|accounts|servers|machines)\b", c, re.I)):
            return False
        # a domain controller named as one anywhere on its line or in its
        # lead-in is set aside ("…, so I didn't count them" is a sentence on)
        # …but "non-DC" / "other than domain controllers" is the finding's frame, not a DC
        ctx = re.sub(r"non[- ]?(?:dc|domain[- ]controller)s?\b|(?:other than|excluding|except)\s+(?:the\s+)?"
                     r"(?:dcs?|domain[- ]controllers?)", "", f"{line} {lead}", flags=re.I)
        if dc and (_DC.search(ctx) or re.search(r"is_dc|expected|by design|normal|excluded", ctx, re.I)):
            return False
        if re.search(r"(?<!un)constrained", c, re.I) and not re.search(r"unconstrained", c, re.I):
            return False
        if re.search(r"unconstrained|trusted for", c, re.I):
            return True
        # a bare list item or table row under a findings lead-in — a short
        # item naming the host, not a sentence of advice that mentions it
        bare = re.sub(r"\[[^\]]*\]|[`*_]|\([^)]*\)", "", c).strip(" -|.:")
        return (bool(_BLOCK_LINE.match(line)) and len(bare) <= 60
                and bool(re.search(r"unconstrained|trusted for|finding", lead, re.I)))
    false_hosts = sorted(d for d in (*truth["dcs"], *truth["decoys"]) if any(
        put_forward(line, lead, d, d in truth["dcs"]) for line, lead in _lines(answer, d, names)))
    cites = _cited(answer, seen)
    ok = bool(truth["hosts"]) and named == truth["hosts"] and not false_hosts
    return {"hosts_expected": truth["hosts"], "hosts_named": named, "false_hosts": false_hosts,
            **cites, "pass": ok and _faithful(cites)}


# ------------------------------------------------------------------- trusts #

def _truth_trusts(store) -> dict:
    """corp.local's trusts as the export states them: per partner, the
    direction and the transitive / SID-filtering flags (claim attrs)."""
    corp = EntityRef(type="domain", key="corp.local")        # keyed by DNS name (D-099)
    out: dict[str, dict] = {}
    for o in _obs(store, corp, limit=5000):
        if o.predicate != "trusts" or not isinstance(o.object, EntityRef):
            continue
        other = o.object if o.subject.key == corp.key else o.subject
        partner = str(o.attrs.get("partner") or other.key)
        out[partner] = {"direction": o.attrs.get("direction"), "transitive": o.attrs.get("transitive"),
                        "sid_filtering": o.attrs.get("sid_filtering")}
    return {"trusts": out}


_NON_TRANSITIVE = re.compile(r"non[- ]?transitive|intransitive|not transitive|\btransitive\W{0,8}(?:no|false)\b", re.I)
# "(quarantine)" beside "SID filtering" is the setting's other name, not its value
_QUARANTINE_LABEL = re.compile(r"\s*[(/]\s*quarantine\b\s*\)?", re.I)
_SID_FILTERED = re.compile(r"quarantined|quarantine\W{0,6}(?:on|enabled|yes|true)\b"
                           r"|sid[- ]filter\w*\W{0,12}(?:on|enabled|yes|true|applied|active)\b"
                           r"|(?:enabled|with|has|applies)\W{0,6}sid[- ]filter", re.I)
_SID_NOT_FILTERED = re.compile(r"sid[- ]filter\w*\W{0,12}(?:off|disabled|no|false|not)\b|no sid[- ]filter"
                               r"|without sid[- ]filter", re.I)


_YES = re.compile(r"^\W*(?:yes|true|on|enabled|applied|active|quarantined|✓|✔|y)\b", re.I)
_NO = re.compile(r"^\W*(?:no|false|off|disabled|none|not\b|✗|✘|n)\b", re.I)


def _table_rows(answer: str, keys: tuple[str, ...]) -> dict[str, dict[str, str]]:
    """A markdown table's row per key, as {lowercased header: cell}: a
    "| partner.local | bidirectional | No | No |" row under "| Partner |
    Direction | Transitive | SID filtering |" says non-transitive without
    the word."""
    out: dict[str, dict[str, str]] = {}
    header: list[str] | None = None
    for line in answer.split("\n"):
        if line.count("|") < 2:          # a row, with or without its outer pipes
            header = None
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if all(re.fullmatch(r":?-{2,}:?", c) for c in cells if c):
            continue
        if header is None:
            header = [c.lower() for c in cells]
            continue
        for k in keys:
            if any(_mentions(c, k) for c in cells):
                out[k] = dict(zip(header, cells))
    return out


_FIELD = re.compile(r"^[\s>*+\-\d.)]*([A-Za-z][^:|]{0,60}?)\s*:\s*(\S.*)$")


def _score_trusts(answer: str, truth: dict, seen: set[str], store) -> dict:
    answer = _QUARANTINE_LABEL.sub("", answer.translate(_QUOTES).replace("**", ""))
    trusts = truth["trusts"]
    partners = tuple(trusts)
    named = sorted(p for p in partners if _mentions(answer, p))
    rows = _table_rows(answer, partners)
    wrong: list[str] = []
    for p, t in trusts.items():
        # this partner's lines, less any that also name another partner (a
        # summary sentence "…while partner.local is non-transitive" is not
        # about dev.local)
        block = [sub for line, _ in _lines(answer, p, partners) for sub in line.split("\n")]
        solo = [ln for ln in block if not any(_mentions(ln, o) for o in partners if o != p)]
        if not block:
            continue
        text = "\n".join(solo)
        says_nt = bool(_NON_TRANSITIVE.search(text))
        says_sf = bool(_SID_FILTERED.search(text)) and not _SID_NOT_FILTERED.search(text)
        # a field ("Transitive: No", "SID Filtering Enabled: No") or a table
        # cell says it by its label, and outranks the free text
        fields = [(m.group(1).lower(), m.group(2)) for ln in solo
                  for part in re.split(r";\s*|,\s+(?=[A-Za-z ()]{3,40}:)", ln.replace("`", ""))
                  if (m := _FIELD.match(part)) is not None
                  and len(m.group(1)) <= 45 and "forest" not in m.group(1).lower()]
        for head, cell in [*fields, *rows.get(p, {}).items()]:
            if "non-transitiv" in head or "nontransitiv" in head:
                says_nt = says_nt or bool(_YES.search(cell))
            elif "transitiv" in head:
                says_nt = bool(_NO.search(cell)) and not _YES.search(cell) or (says_nt and not _YES.search(cell))
            elif "sid" in head or "quarantin" in head:
                says_sf = bool(_YES.search(cell)) or (says_sf and not _NO.search(cell))
        if t["transitive"] is False and not says_nt:
            wrong.append(f"{p}: non-transitive not stated")
        if t["transitive"] is True and says_nt:
            wrong.append(f"{p}: called non-transitive")
        if t["sid_filtering"] is True and not says_sf:
            wrong.append(f"{p}: SID filtering not stated")
        if t["sid_filtering"] is False and says_sf:
            wrong.append(f"{p}: called SID-filtered")
    cites = _cited(answer, seen)
    ok = bool(trusts) and named == sorted(partners) and not wrong
    return {"partners_expected": sorted(partners), "partners_named": named, "wrong": wrong,
            **cites, "pass": ok and _faithful(cites)}


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
    Task("groups",
         f"Group membership report for the corp.local account {GROUPS_ACCOUNT}: list every group it "
         "belongs to, directly or through nested groups, and say which memberships are direct. "
         "Cite observation ids.",
         _truth_groups, _score_groups),
    Task("delegation",
         "Kerberos delegation hardening review for corp.local: which computer accounts, other than "
         "domain controllers, are trusted for unconstrained delegation? Cite observation ids.",
         _truth_delegation, _score_delegation),
    Task("trusts",
         "Trust review for corp.local: list every domain trust it has — the partner domain, the trust "
         "direction, whether the trust is transitive, and whether SID filtering (quarantine) is "
         "enabled. Cite observation ids.",
         _truth_trusts, _score_trusts),
]


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loomctx.agent_eval_ext", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare", help="write forest.ldif and lab.ldif into DIR")
    prep.add_argument("dir")
    prep.add_argument("--seed", type=int, default=7)
    prep.add_argument("--scale", default="large", choices=sorted(ad_gen.SCALES),
                      help="ad_gen scale of corp.local (default large; small for tests)")
    prep.add_argument("--style", default="plain", choices=ad_gen.STYLES,
                      help="ad_gen style of corp.local: plain (the published runs) or realistic")
    args = parser.parse_args(argv)
    os.makedirs(args.dir, exist_ok=True)
    with open(os.path.join(args.dir, "forest.ldif"), "w", encoding="utf-8") as fh:
        fh.write(forest_ldif(args.seed, args.scale, args.style))
    with open(os.path.join(args.dir, "lab.ldif"), "w", encoding="utf-8") as fh:
        fh.write(lab_ldif())
    print(f"wrote {args.dir}/forest.ldif and {args.dir}/lab.ldif (namespace {NAMESPACE})")


if __name__ == "__main__":
    main()
