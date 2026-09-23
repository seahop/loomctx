"""API key management CLI (D-013a).

Generates real keys and maintains the keys file that LOOM_AUTH_FILE points
at. The plaintext key is printed EXACTLY ONCE at generation; only its
SHA-256 hash is stored, so neither the file, the repo, nor a backup can leak
credentials.

    python -m loom.keys generate --id netsec-shipper \
        --namespace netsec --perms w --entity-types host,ip --sources auth-log \
        --expires-days 180
    python -m loom.keys list
    python -m loom.keys revoke --id netsec-shipper

The file defaults to secrets/keys.json (gitignored and dockerignored) and is
written atomically with mode 0600: a reader never sees a half-written file,
and the grants are not world-readable on a shared host.

Distribute the file to the engine/gateway as a mounted Secret; both hot-reload
it on change, so rotation is: generate new key -> hand it to the sender ->
revoke the old id -> done. No restarts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone

KEY_PREFIX = "loomk_"  # recognizable in configs and (hashed) never in logs
DEFAULT_FILE = "secrets/keys.json"


def _load(path: str) -> dict:
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {"keys": []}


def _save(path: str, data: dict) -> None:
    """Atomic replace (tmp file in the same directory + os.replace) so the
    engine's hot reload never parses a partial file, created 0600 so the
    grants are private to the operator. The parent directory is created
    if missing (the default lives under secrets/)."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    tmp = os.path.join(directory, f".{os.path.basename(path)}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


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


def cmd_update(args) -> None:
    """Change a key's GRANTS without re-minting the secret. The scope lives
    beside the hash, so widening or narrowing what a user may see is an edit
    + hot reload, and the sender keeps the same plaintext key."""
    data = _load(args.file)
    for k in data["keys"]:
        if k["id"] != args.id:
            continue
        if args.entity_types is not None:
            k["entity_types"] = (
                None if args.entity_types == "any"
                else args.entity_types.split(",")
            )
        if args.sources is not None:
            k["sources"] = (
                None if args.sources == "any" else args.sources.split(",")
            )
        if args.perms is not None:
            k["perms"] = args.perms
        if args.namespace:
            k["namespaces"] = args.namespace
        if args.expires_days is not None:
            k["expires"] = (
                None if args.expires_days == 0
                else (datetime.now(timezone.utc)
                      + timedelta(days=args.expires_days)).isoformat()
            )
        _save(args.file, data)
        print(f"updated {args.id!r}: namespaces={k['namespaces']} "
              f"perms={k['perms']} entity_types={k.get('entity_types')} "
              f"sources={k.get('sources')} expires={k.get('expires')}")
        return
    sys.exit(f"error: no key with id {args.id!r}")


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
    parser.add_argument("--file", default=DEFAULT_FILE,
                        help=f"keys file (default {DEFAULT_FILE}; written atomically, mode 0600)")
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

    upd = sub.add_parser("update", help="change grants without re-minting")
    upd.add_argument("--id", required=True)
    upd.add_argument("--entity-types", default=None,
                     help="comma list, or 'any' to remove the gate")
    upd.add_argument("--sources", default=None,
                     help="comma list, or 'any' to remove the gate")
    upd.add_argument("--perms", choices=["r", "w", "rw"], default=None)
    upd.add_argument("--namespace", action="append", default=None,
                     help="repeatable; replaces the namespace list")
    upd.add_argument("--expires-days", type=int, default=None,
                     help="from now; 0 = never expires")

    rev = sub.add_parser("revoke")
    rev.add_argument("--id", required=True)

    args = parser.parse_args()
    {"generate": cmd_generate, "list": cmd_list, "update": cmd_update,
     "revoke": cmd_revoke}[args.command](args)


if __name__ == "__main__":
    main()
