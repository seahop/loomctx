"""API key management CLI (D-013a).

Generates real keys and maintains the keys file that LOOM_AUTH_FILE points
at. The plaintext key is printed EXACTLY ONCE at generation; only its
SHA-256 hash is stored, so neither the file, the repo, nor a backup can leak
credentials.

    python -m loom.keys generate --file keys.json --id netsec-shipper \
        --namespace netsec --perms w --entity-types host,ip --sources auth-log \
        --expires-days 180
    python -m loom.keys list   --file keys.json
    python -m loom.keys revoke --file keys.json --id netsec-shipper

Distribute the file to the engine/gateway as a mounted Secret; both hot-reload
it on change, so rotation is: generate new key -> hand it to the sender ->
revoke the old id -> done. No restarts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
from datetime import datetime, timedelta, timezone

KEY_PREFIX = "loomk_"  # recognizable in configs and (hashed) never in logs


def _load(path: str) -> dict:
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {"keys": []}


def _save(path: str, data: dict) -> None:
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")


def cmd_generate(args) -> None:
    data = _load(args.file)
    if any(k["id"] == args.id for k in data["keys"]):
        sys.exit(f"error: a key with id {args.id!r} already exists "
                 f"(revoke it or pick another id)")
    plaintext = KEY_PREFIX + secrets.token_urlsafe(32)
    entry = {
        "id": args.id,
        "sha256": hashlib.sha256(plaintext.encode()).hexdigest(),
        "namespaces": args.namespace,
        "perms": args.perms,
        "entity_types": (
            args.entity_types.split(",") if args.entity_types else None
        ),
        "sources": args.sources.split(",") if args.sources else None,
        "expires": (
            (datetime.now(timezone.utc) + timedelta(days=args.expires_days))
            .isoformat()
            if args.expires_days else None
        ),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "disabled": False,
    }
    data["keys"].append(entry)
    _save(args.file, data)
    print(f"# key id {args.id!r} written to {args.file} (hash only).", file=sys.stderr)
    print("# The plaintext below is shown ONCE — hand it to the sender now:",
          file=sys.stderr)
    print(plaintext)


def cmd_list(args) -> None:
    data = _load(args.file)
    if not data["keys"]:
        print("(no keys)")
        return
    for k in data["keys"]:
        state = "DISABLED" if k.get("disabled") else "active"
        gates = []
        if k.get("entity_types"):
            gates.append(f"types={','.join(k['entity_types'])}")
        if k.get("sources"):
            gates.append(f"sources={','.join(k['sources'])}")
        if k.get("expires"):
            gates.append(f"expires={k['expires'][:10]}")
        print(f"{k['id']:<24} {','.join(k['namespaces']):<16} "
              f"{k['perms']:<3} {state:<9} {' '.join(gates) or '(no extra gates)'}")


def cmd_revoke(args) -> None:
    data = _load(args.file)
    for k in data["keys"]:
        if k["id"] == args.id:
            k["disabled"] = True
            _save(args.file, data)
            print(f"revoked {args.id!r}")
            return
    sys.exit(f"error: no key with id {args.id!r}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="loom.keys", description=__doc__)
    parser.add_argument("--file", default="keys.json")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate")
    gen.add_argument("--id", required=True, help="stable name for audit logs")
    gen.add_argument("--namespace", action="append", required=True,
                     help="repeatable; use '*' for all namespaces")
    gen.add_argument("--perms", choices=["r", "w", "rw"], required=True)
    gen.add_argument("--entity-types", default=None,
                     help="comma list; omit for any (e.g. host,ip,user)")
    gen.add_argument("--sources", default=None,
                     help="comma list of allowed claim sources for writes")
    gen.add_argument("--expires-days", type=int, default=None)

    lst = sub.add_parser("list")
    rev = sub.add_parser("revoke")
    rev.add_argument("--id", required=True)

    args = parser.parse_args()
    {"generate": cmd_generate, "list": cmd_list, "revoke": cmd_revoke}[
        args.command
    ](args)


if __name__ == "__main__":
    main()
