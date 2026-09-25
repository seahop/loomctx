"""Deterministic fake data for tests and demos.

Two domains show the domain-agnostic core:
  * ``netsec``      — hosts, users, IPs, logins, scans, alerts, incident docs
  * ``procurement`` — vendors, contracts, invoices, renewal notes

Deliberately planted demo moments (same seed -> same data, always):
  * IP 10.0.4.7 is leased to web-01 until Aug 10, then reassigned to
    laptop-17 — "which host had this IP during the incident?" (bitemporal)
  * Two sources disagree about web-01's OS, and about vendor Initech's
    contract owner — conflict surfacing
  * The contract DB corrects its own earlier record of Hooli's contract
    owner — a recorded supersession (D-050), not a conflict
  * An incident report document ties web-01 / jdoe / 10.0.4.7 together

Usage (inside Docker; see README):
  python -m loom.seed load                # ingest into $LOOM_DB
  python -m loom.seed generate --out DIR  # write claims.jsonl + docs/ files
"""

from __future__ import annotations

import argparse
import os
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .contracts import ClaimIn, DocumentIn, EntityRef
from .store.common import redact_dsn
from .store.factory import store_from_env, store_from_url

# Fixed epoch: the dataset describes July-September 2026 regardless of when
# it is generated, so demos and tests are perfectly reproducible.
BASE = datetime(2026, 7, 1, tzinfo=timezone.utc)

# attrs key on a seed claim that corrects an earlier one: the event_id of
# the observation it supersedes (resolved to its id at load time)
SUPERSEDES_EVENT = "seed_supersedes_event"

HOSTS = ["web-01", "web-02", "web-03", "db-01", "db-02", "vpn-01", "laptop-17"]
USERS = ["jdoe", "asmith", "mchen", "rlee", "svc-backup"]
VENDORS = ["initech", "hooli", "globex", "umbrella-it"]


def _at(day: float, hour: float = 0.0) -> datetime:
    return BASE + timedelta(days=day, hours=hour)


def _claim(ns, subj, pred, obj, day, hour, source, confidence=1.0, **kw):
    return ClaimIn(
        namespace=ns,
        subject=EntityRef(type=subj[0], key=subj[1]),
        predicate=pred,
        object=EntityRef(type=obj[0], key=obj[1]) if isinstance(obj, tuple) else obj,
        observed_at=_at(day, hour),
        source=source,
        confidence=confidence,
        **kw,
    )


def generate(seed: int = 42) -> tuple[list[ClaimIn], list[DocumentIn]]:
    rng = random.Random(seed)
    claims: list[ClaimIn] = []

    # ---------------------------------------------------------------- netsec
    ns = "netsec"

    # Inventory facts (scalar objects)
    os_by_host = {
        "web-01": "fedora-44", "web-02": "fedora-44", "web-03": "ubuntu-24.04",
        "db-01": "rhel-9", "db-02": "rhel-9", "vpn-01": "openbsd-7.6",
        "laptop-17": "fedora-44",
    }
    for host, os_name in os_by_host.items():
        claims.append(_claim(ns, ("host", host), "runs_os", os_name, 2, 9,
                             "asset-inventory"))
    # Planted conflict: a later scan disagrees about web-01's OS.
    claims.append(_claim(ns, ("host", "web-01"), "runs_os", "ubuntu-22.04",
                         48, 3, "nmap-scan", confidence=0.7))

    for host in ["web-01", "web-02", "web-03"]:
        for port in (80, 443):
            claims.append(_claim(ns, ("host", host), "listens_on_port", port,
                                 2, 10, "nmap-scan"))
    claims.append(_claim(ns, ("host", "db-01"), "listens_on_port", 5432, 2, 10,
                         "nmap-scan"))
    claims.append(_claim(ns, ("host", "vpn-01"), "listens_on_port", 51820, 2, 10,
                         "nmap-scan"))

    # The IP lease timeline (the bitemporal demo star): 10.0.4.7 belongs to
    # web-01 until Aug 10 (day 40), then to laptop-17.
    claims.append(ClaimIn(
        namespace=ns,
        subject=EntityRef(type="ip", key="10.0.4.7"),
        predicate="assigned_to",
        object=EntityRef(type="host", key="web-01"),
        observed_at=_at(1, 8), valid_from=_at(1, 8), valid_to=_at(40, 8),
        source="dhcp-log",
    ))
    claims.append(ClaimIn(
        namespace=ns,
        subject=EntityRef(type="ip", key="10.0.4.7"),
        predicate="assigned_to",
        object=EntityRef(type="host", key="laptop-17"),
        observed_at=_at(40, 9), valid_from=_at(40, 9), valid_to=None,
        source="dhcp-log",
    ))
    for i, host in enumerate(h for h in HOSTS if h not in ("web-01", "laptop-17")):
        claims.append(ClaimIn(
            namespace=ns,
            subject=EntityRef(type="ip", key=f"10.0.4.{10 + i}"),
            predicate="assigned_to",
            object=EntityRef(type="host", key=host),
            observed_at=_at(1, 8), valid_from=_at(1, 8), valid_to=None,
            source="dhcp-log",
        ))

    # ~400 login events over ~9 weeks; jdoe favors web-01 so questions about
    # either of them have an obvious right answer.
    for _ in range(400):
        day, hour = rng.uniform(0, 63), rng.uniform(0, 24)
        user = rng.choice(USERS)
        host = rng.choice(["web-01"] * 3 + HOSTS) if user == "jdoe" else rng.choice(HOSTS)
        claims.append(_claim(
            ns, ("host", host), "logged_in_by", ("user", user), day, hour,
            "auth-log", attrs={"method": rng.choice(["ssh", "console", "vpn"])},
        ))

    # Domain membership (scope demo: "what's happening in corp.local?")
    for host in HOSTS:
        claims.append(_claim(ns, ("host", host), "member_of",
                             ("domain", "corp.local"), 1, 9, "asset-inventory"))

    # ~120 host-to-host flows
    for _ in range(120):
        a, b = rng.sample(HOSTS, 2)
        claims.append(_claim(ns, ("host", a), "communicated_with", ("host", b),
                             rng.uniform(0, 63), rng.uniform(0, 24), "netflow",
                             confidence=0.9))

    # The incident thread: an alert on web-01 on Sep 1 (day 62)
    claims.append(_claim(ns, ("alert", "AL-2291"), "triggered_on",
                         ("host", "web-01"), 62, 14, "ids"))
    claims.append(_claim(ns, ("alert", "AL-2291"), "severity", "high", 62, 14, "ids"))
    claims.append(_claim(ns, ("host", "web-01"), "logged_in_by", ("user", "jdoe"),
                         62, 13.9, "auth-log", attrs={"method": "ssh"}))

    # ----------------------------------------------------------- procurement
    ns = "procurement"
    owners = {"initech": "asmith", "hooli": "mchen", "globex": "asmith",
              "umbrella-it": "rlee"}
    for vendor, owner in owners.items():
        claims.append(_claim(ns, ("vendor", vendor), "contract_owner",
                             owner, 5, 11, "contract-db"))
        claims.append(_claim(ns, ("vendor", vendor), "renewal_date",
                             f"2027-0{rng.randint(1, 6)}-01", 5, 11, "contract-db"))
        for _ in range(rng.randint(4, 9)):
            claims.append(_claim(
                ns, ("vendor", vendor), "invoiced_amount",
                round(rng.uniform(900, 42000), 2),
                rng.uniform(0, 60), rng.uniform(8, 18), "erp-export",
                attrs={"currency": "USD"},
            ))
    # Planted conflict: email trawl disagrees about initech's contract owner.
    claims.append(_claim(ns, ("vendor", "initech"), "contract_owner", "rlee",
                         50, 15, "email-extraction", confidence=0.6))
    # Planted correction (D-050): the contract DB later corrects its OWN
    # earlier hooli owner record. Not a conflict — one source, a recorded
    # supersession: the old row stays for audit and as_of reads, the new one
    # is current. `cmd_load` resolves the target's observation id (ids are
    # minted at load time) into ClaimIn.supersedes.
    hooli_owner_index = next(i for i, c in enumerate(claims)
                             if c.subject.key == "hooli" and c.predicate == "contract_owner")
    claims.append(_claim(ns, ("vendor", "hooli"), "contract_owner", "rlee", 58, 10, "contract-db",
                         attrs={SUPERSEDES_EVENT: f"seed:{seed}:c{hooli_owner_index}",
                                "note": "correction: owner field was stale"}))

    # ------------------------------------------------------------- documents
    docs = [
        DocumentIn(
            namespace="netsec",
            filename="IR-4432.txt",
            source="ir-pipeline",
            observed_at=_at(62, 18),
            text=(
                "INCIDENT REPORT IR-4432 (2026-09-01)\n\n"
                "IDS alert AL-2291 fired on web-01 at 14:02 UTC following an SSH "
                "login by jdoe. Outbound traffic was observed from 10.0.4.7. "
                "NOTE: DHCP records show 10.0.4.7 was reassigned from web-01 to "
                "laptop-17 on 2026-08-10 — verify which asset actually generated "
                "the traffic before attribution. Recommend interviewing jdoe and "
                "pulling netflow for both hosts."
            ),
        ),
        DocumentIn(
            namespace="netsec",
            filename="phish-2026-08-22.txt",
            source="mail-gateway",
            observed_at=_at(52, 9),
            text=(
                "Phishing campaign summary 2026-08-22: 14 messages spoofing "
                "'IT Support' delivered; mchen and rlee clicked. Password resets "
                "forced. Sender infrastructure overlaps with hooli-themed "
                "campaign from July."
            ),
        ),
        DocumentIn(
            namespace="netsec",
            filename="maintenance-window.txt",
            source="ops-wiki",
            observed_at=_at(38, 16),
            text=(
                "Maintenance 2026-08-08: web-01 rebuilt after disk failure; "
                "DHCP lease released. db-02 patched to rhel-9.4. vpn-01 config "
                "unchanged."
            ),
        ),
        DocumentIn(
            namespace="procurement",
            filename="initech-renewal-notes.txt",
            source="meeting-notes",
            observed_at=_at(55, 13),
            text=(
                "Initech renewal call 2026-08-25: pricing up 8%. Ownership of "
                "the contract is unclear — asmith is listed in the contract DB "
                "but rlee has been running the relationship since July. Decide "
                "before the 2027 renewal."
            ),
        ),
        DocumentIn(
            namespace="procurement",
            filename="q3-spend.b64",
            source="erp-export",
            observed_at=_at(60, 8),
            content_type="application/octet-stream",
            content_b64="UTMgc3BlbmQgc25hcHNob3QgKGJpbmFyeSBzYW1wbGUp",
        ),
    ]
    # Deterministic event ids make `seed load` idempotent: loading twice
    # into the same volume dedupes instead of doubling the corpus (H-F2).
    claims = [
        c.model_copy(update={"event_id": f"seed:{seed}:c{i}"})
        for i, c in enumerate(claims)
    ]
    docs = [
        d.model_copy(update={"event_id": f"seed:{seed}:d{i}"})
        for i, d in enumerate(docs)
    ]
    return claims, docs



def resolve_supersessions(claims: list[ClaimIn], recorded) -> list[ClaimIn]:
    """The correction claims with `supersedes` set to the id of the
    observation their SUPERSEDES_EVENT attr names, from the observations
    just recorded (by event_id). A target that did not land is an error:
    a supersession is recorded, never guessed."""
    by_event = {o.event_id: o.id for o in recorded if o.event_id}
    out = []
    for c in claims:
        target = c.attrs.get(SUPERSEDES_EVENT)
        if not target:
            continue
        if target not in by_event:
            raise ValueError(f"seed correction {c.event_id} supersedes unknown event {target!r}")
        attrs = {k: v for k, v in c.attrs.items() if k != SUPERSEDES_EVENT}
        out.append(c.model_copy(update={"supersedes": by_event[target], "attrs": attrs}))
    return out


def cmd_load(db_path: str | None, seed: int) -> None:
    """An explicit db_path opens that store alone; None opens whatever
    LOOM_DB / LOOM_SHARDS / LOOM_BLOB_* configure, exactly as the engine
    does — so the seed lands where the engine will look for it."""
    claims, docs = generate(seed)
    plain = [c for c in claims if SUPERSEDES_EVENT not in c.attrs]
    store = store_from_url(db_path) if db_path else store_from_env()
    try:
        recorded = store.record_claims(plain)
        # corrections go last, pointing at the observation ids just minted
        store.record_claims(resolve_supersessions(claims, recorded))
        for doc in docs:
            store.store_artifact(doc)
    finally:
        store.close()
    where = redact_dsn(db_path) if db_path else f"{redact_dsn(os.environ.get('LOOM_DB', 'loom.db'))} (env)"
    print(f"loaded {len(claims)} claims and {len(docs)} documents into {where}")


def cmd_generate(out_dir: str, seed: int) -> None:
    claims, docs = generate(seed)
    out = Path(out_dir)
    (out / "docs").mkdir(parents=True, exist_ok=True)
    with open(out / "claims.jsonl", "w") as fh:
        for claim in claims:
            fh.write(claim.model_dump_json() + "\n")
    with open(out / "documents.jsonl", "w") as fh:
        for doc in docs:
            fh.write(doc.model_dump_json() + "\n")
            if doc.text and doc.filename:
                (out / "docs" / doc.filename).write_text(doc.text)
    print(f"wrote {len(claims)} claims and {len(docs)} documents to {out}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="loom.seed", description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    sub = parser.add_subparsers(dest="command", required=True)
    load = sub.add_parser("load", help="ingest fake data into the store")
    load.add_argument("--db", help="explicit store URL/path; bypasses LOOM_SHARDS and LOOM_BLOB_* "
                                   "(default: the store LOOM_DB and friends configure)")
    gen = sub.add_parser("generate", help="write fake data to files")
    gen.add_argument("--out", default="seed-data")
    args = parser.parse_args()
    if args.command == "load":
        cmd_load(args.db, args.seed)
    else:
        cmd_generate(args.out, args.seed)


if __name__ == "__main__":
    main()
