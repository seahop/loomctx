"""Host artifacts: process lists and file listings in, cited claims out (D-084).

    python -m loomctx.connectors.endpoint import procs.csv --host web-01            # tasklist /v /fo csv
    python -m loomctx.connectors.endpoint import ps.txt --host web-01               # ps -eo pid,ppid,user,lstart,args
    python -m loomctx.connectors.endpoint import results.log                        # osqueryd results (host inside)
    python -m loomctx.connectors.endpoint import listing.txt --host web-01 --all-files
    python -m loomctx.connectors.endpoint emit files.json --host web-01 > envelopes.jsonl
    python -m loomctx.connectors.endpoint schema

It PARSES what an operator or responder already collected on a host — it
runs nothing on any machine. Recognised (auto-detected, or `--format`):

  processes  osquery `processes` rows (osqueryi --json, or osqueryd results
             log lines), Windows `tasklist /v /fo csv`, PowerShell
             `Get-CimInstance Win32_Process | ConvertTo-Json` and
             `Get-Process | ConvertTo-Json`, `ps -eo pid,ppid,user,lstart,args`
             and `ps aux`
  files      osquery `file` / `hash` rows, `ls -laR --time-style=full-iso`,
             PowerShell `Get-ChildItem -Recurse | ConvertTo-Json` and
             `Get-FileHash | ConvertTo-Json`, `sha256sum` output, and any CSV
             with a `path` column (size, mtime, owner, sha256, md5 optional)

Model, in the environment's namespace (`netsec` by default):

  * `host:<name>` (lower-cased) with its hostname / FQDN identifiers (D-083)
  * `process:<host>:<pid>:<start>` — the start time is part of the key
    because PIDs are reused; `runs_on` the host, `spawned_by` its parent (the
    same snapshot's row for the parent pid, else the pid with an unknown
    start), `executes` its image file, `run_as` the account, plus `pid`,
    `name`, `cmdline`, `started_at`
  * `file:<host>:<path>` — `located_on` the host, `size`, `modified_at`,
    `owner`, `mode`; `has_hash` -> `hash:sha256:<hex>` (and md5), an entity
    SHARED across hosts, so one binary on many machines is one node
  * accounts as `user:<domain>\\<name>` with an `account` identifier, so
    `CORP\\jdoe` in a process list folds into the directory's user; local
    and built-in accounts are scoped to the host (`web-01\\root`)

A listing is a snapshot: it says what was running / present when it was
taken (`observed_at`), not when anything stopped. A full recursive listing
is large, so by default only executables, scripts, libraries, configs,
keys and anything with a hash are kept (`--all-files` keeps every entry;
the skipped count is reported). What the input carried — command lines,
parents, owners, hashes — is recorded as coverage (D-082).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Iterator

from .. import coverage
from .. import identity as ident
from ..contracts import (ClaimIn, EntityRef, EntityTypeDef, PredicateDef,
                         SchemaRegistration)

SOURCE_DEFAULT = "endpoint"
NAMESPACE_DEFAULT = "netsec"

KEEP_EXTENSIONS = frozenset("""
exe dll sys drv ocx cpl scr com msi msp lnk ps1 psm1 psd1 bat cmd vbs vbe js jse wsf wsh hta
jar war class py pyc pl rb php sh bash zsh ksh elf so ko dylib app
conf config cfg ini inf xml yaml yml json toml env properties plist reg
pem key crt cer pfx p12 kdbx ovpn ppk rdp sql db sqlite
""".split())
BUILTIN_DOMAINS = frozenset({"nt authority", "nt service", "window manager", "font driver host",
                             "iis apppool", "builtin"})

FORMATS = ("osquery", "tasklist", "win32_process", "get_process", "ps", "ps_aux",
           "ls", "get_childitem", "get_filehash", "sha256sum", "csv")


# ------------------------------------------------------------------ helpers #

def _eid(parts: str) -> str:
    if len(parts) <= 128:
        return parts
    return f"{parts[:96]}:{hashlib.sha256(parts.encode('utf-8', 'replace')).hexdigest()[:31]}"


def _clamp(when: datetime) -> datetime:
    now = datetime.now(timezone.utc)
    return when if when <= now else now


def _time(value: Any) -> datetime | None:
    """ISO text, epoch seconds, PowerShell's `/Date(ms)/`, or WMI's
    `yyyymmddHHMMSS.ffffff+mmm`."""
    if value in (None, "", 0, "0"):
        return None
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
        try:
            return datetime.fromtimestamp(int(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    m = re.match(r"^/Date\((-?\d+)\)/$", text)
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, tz=timezone.utc)
    m = re.match(r"^(\d{14})\.\d+([+-]\d{3})$", text)
    if m:
        dt = datetime.strptime(m.group(1), "%Y%m%d%H%M%S")
        return dt.replace(tzinfo=timezone.utc) - timedelta(minutes=int(m.group(2)))
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)   # ls full-iso prints nanoseconds
    for fmt in (None, "%a %b %d %H:%M:%S %Y", "%Y-%m-%d %H:%M:%S.%f %z", "%Y-%m-%d %H:%M:%S %z"):
        try:
            dt = (datetime.fromisoformat(text.replace("Z", "+00:00")) if fmt is None
                  else datetime.strptime(" ".join(text.split()), fmt))
        except ValueError:
            continue
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return None


def _host_key(name: str) -> str:
    return name.strip().lower().rstrip(".")


def _path_key(path: str) -> str:
    """Windows paths are case-insensitive: folded, with backslashes."""
    p = path.strip()
    if re.match(r"^[a-zA-Z]:[\\/]", p) or p.startswith("\\\\"):
        return p.replace("/", "\\").lower()
    return p


def _account(host: str, user: str | None) -> tuple[EntityRef, list] | None:
    """(the account entity, its identifier pairs): DOMAIN\\name when the
    input names a domain, else a local account of this host; built-in
    Windows accounts are always local."""
    if not user or not str(user).strip() or str(user).strip() in ("-", "N/A"):
        return None
    u = str(user).strip()
    if "\\" in u:
        domain, _, name = u.partition("\\")
        if domain.strip().lower() in BUILTIN_DOMAINS or domain.strip().lower() == host.split(".")[0]:
            u = f"{host.split('.')[0]}\\{name}"
    elif "@" in u:
        return EntityRef(type="user", key=u.lower()), [("upn", u)]
    else:
        u = f"{host.split('.')[0]}\\{u}"
    norm = ident.normalize("account", u)
    if norm is None:
        return None
    return EntityRef(type="user", key=norm), [("account", u)]


# --------------------------------------------------------------- detection #

def detect(text: str) -> str:
    head = text.lstrip()[:4000]
    first = head.splitlines()[0] if head else ""
    if head.startswith("[") or head.startswith("{"):
        rows = _json_rows(text)
        keys = set().union(*(r.keys() for r in rows[:50])) if rows else set()
        if {"hostIdentifier", "name"} <= keys:
            return "osquery"
        if "ProcessId" in keys:
            return "win32_process"
        if "ProcessName" in keys and "Id" in keys:
            return "get_process"
        if "FullName" in keys:
            return "get_childitem"
        if {"Algorithm", "Hash", "Path"} <= keys:
            return "get_filehash"
        if keys & {"pid", "path", "sha256", "directory"}:
            return "osquery"
        raise ValueError("unrecognised JSON rows (expected osquery, Win32_Process, Get-Process, "
                         "Get-ChildItem or Get-FileHash)")
    if first.startswith('"Image Name"'):
        return "tasklist"
    if re.match(r"^\s*PID\s+PPID\s+USER\s+STARTED\s+(COMMAND|CMD)", first):
        return "ps"
    if re.match(r"^\s*USER\s+PID\s+%CPU", first):
        return "ps_aux"
    if re.match(r"^[0-9a-f]{64}\s+\*?\S", first):
        return "sha256sum"
    if re.search(r"^total \d+$", head, re.M) or re.match(r"^\S.*:$", first):
        return "ls"
    if "path" in [c.strip().lower() for c in first.split(",")]:
        return "csv"
    raise ValueError("could not recognise the input format; pass --format")


def _json_rows(text: str) -> list[dict]:
    text = text.strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        rows = []
        for line in text.splitlines():   # NDJSON (osqueryd results log)
            line = line.strip()
            if line:
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    rows.append(obj)
        return rows
    if isinstance(data, dict):
        return [data]
    return [d for d in data if isinstance(d, dict)] if isinstance(data, list) else []


# ------------------------------------------------------------ normalisers #
# Every format becomes (host, observed_at | None, kind, row) with row keys
# pid ppid name path cmdline user start  |  path size mtime owner mode sha256 md5

Row = dict[str, Any]


def _osquery(text: str, host: str | None) -> Iterator[tuple[str | None, datetime | None, str, Row]]:
    for obj in _json_rows(text):
        if "hostIdentifier" in obj:        # osqueryd results log line
            h = obj.get("hostIdentifier")
            when = _time(obj.get("unixTime")) or _time(obj.get("calendarTime"))
            if obj.get("action") == "removed":
                continue
            rows = obj.get("snapshot") if isinstance(obj.get("snapshot"), list) else [obj.get("columns") or {}]
        else:
            h, when, rows = host, None, [obj]
        for r in rows:
            if not isinstance(r, dict):
                continue
            if "pid" in r:
                yield h, when, "process", {
                    "pid": r.get("pid"), "ppid": r.get("parent"), "name": r.get("name"),
                    "path": r.get("path"), "cmdline": r.get("cmdline"),
                    "user": r.get("username") or r.get("user"), "start": _time(r.get("start_time"))}
            elif "path" in r and r.get("type") != "directory":
                yield h, when, "file", {
                    "path": r.get("path"), "size": r.get("size"), "mtime": _time(r.get("mtime")),
                    "owner": r.get("username") or r.get("uid"), "mode": r.get("mode"),
                    "sha256": r.get("sha256"), "md5": r.get("md5"), "type": r.get("type")}


def _tasklist(text: str, host: str | None):
    for r in csv.DictReader(io.StringIO(text)):
        yield host, None, "process", {"pid": r.get("PID"), "name": r.get("Image Name"),
                                      "user": r.get("User Name")}


def _win32_process(text: str, host: str | None):
    for r in _json_rows(text):
        yield (r.get("CSName") or host), None, "process", {
            "pid": r.get("ProcessId"), "ppid": r.get("ParentProcessId"), "name": r.get("Name"),
            "path": r.get("ExecutablePath"), "cmdline": r.get("CommandLine"),
            "start": _time(r.get("CreationDate")), "user": r.get("Owner") or r.get("UserName")}


def _get_process(text: str, host: str | None):
    for r in _json_rows(text):
        yield (r.get("MachineName") if r.get("MachineName") not in (None, ".") else host), None, \
            "process", {"pid": r.get("Id"), "name": r.get("ProcessName"), "path": r.get("Path"),
                        "start": _time(r.get("StartTime")), "user": r.get("UserName")}


def _ps(text: str, host: str | None):
    lines = text.splitlines()
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 9 or not parts[0].isdigit():
            continue
        start = _time(" ".join(parts[3:8]))
        args = line.split(None, 8)[8] if len(line.split(None, 8)) > 8 else ""
        yield host, None, "process", {"pid": parts[0], "ppid": parts[1], "user": parts[2],
                                      "start": start, "cmdline": args,
                                      "name": os.path.basename(args.split()[0]) if args else None,
                                      "path": args.split()[0] if args.startswith("/") else None}


def _ps_aux(text: str, host: str | None):
    for line in text.splitlines()[1:]:
        parts = line.split(None, 10)
        if len(parts) < 11 or not parts[1].isdigit():
            continue
        args = parts[10]
        yield host, None, "process", {"pid": parts[1], "user": parts[0], "cmdline": args,
                                      "name": os.path.basename(args.split()[0]) if args else None,
                                      "path": args.split()[0] if args.startswith("/") else None}


_LS_LINE = re.compile(r"^([\-dlcbps])([rwxsStT\-]{9})[.+@]?\s+\d+\s+(\S+)\s+(\S+)\s+(\d+)\s+"
                      r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:\.\d+)? [+-]\d{4})\s+(.+)$")


def _ls(text: str, host: str | None):
    directory = ""
    for line in text.splitlines():
        if line.endswith(":") and not line.startswith(("-", "d", "l", "total")):
            directory = line[:-1]
            continue
        m = _LS_LINE.match(line)
        if not m:
            continue
        kind, mode, owner, _group, size, when, name = m.groups()
        if kind != "-" or name in (".", ".."):
            continue
        name = name.split(" -> ", 1)[0]
        path = name if name.startswith("/") else f"{directory.rstrip('/')}/{name}" if directory else name
        yield host, None, "file", {"path": path, "size": size, "mtime": _time(when), "owner": owner,
                                   "mode": f"{kind}{mode}"}


def _get_childitem(text: str, host: str | None):
    for r in _json_rows(text):
        if str(r.get("Mode", "")).startswith("d") or r.get("PSIsContainer"):
            continue
        yield host, None, "file", {"path": r.get("FullName"), "size": r.get("Length"),
                                   "mtime": _time(r.get("LastWriteTimeUtc") or r.get("LastWriteTime")),
                                   "mode": r.get("Mode")}


def _get_filehash(text: str, host: str | None):
    for r in _json_rows(text):
        algo = str(r.get("Algorithm", "")).lower()
        if algo in ("sha256", "md5"):
            yield host, None, "file", {"path": r.get("Path"), algo: r.get("Hash")}


def _sha256sum(text: str, host: str | None):
    for line in text.splitlines():
        m = re.match(r"^([0-9a-fA-F]{64})\s+\*?(.+)$", line.strip())
        if m:
            yield host, None, "file", {"path": m.group(2), "sha256": m.group(1)}


def _csv_files(text: str, host: str | None):
    for r in csv.DictReader(io.StringIO(text)):
        low = {k.strip().lower(): v for k, v in r.items() if k}
        yield (low.get("host") or host), None, "file", {
            "path": low.get("path"), "size": low.get("size"), "mtime": _time(low.get("mtime")),
            "owner": low.get("owner"), "mode": low.get("mode"), "sha256": low.get("sha256"),
            "md5": low.get("md5")}


PARSERS = {"osquery": _osquery, "tasklist": _tasklist, "win32_process": _win32_process,
           "get_process": _get_process, "ps": _ps, "ps_aux": _ps_aux, "ls": _ls,
           "get_childitem": _get_childitem, "get_filehash": _get_filehash,
           "sha256sum": _sha256sum, "csv": _csv_files}


# ---------------------------------------------------------------- claims #

def _keep(row: Row) -> bool:
    if row.get("sha256") or row.get("md5"):
        return True
    path = str(row.get("path") or "")
    ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] else ""
    if ext in KEEP_EXTENSIONS:
        return True
    mode = str(row.get("mode") or "")
    return len(mode) >= 4 and "x" in mode[1:4] and not mode.startswith("d")


def _int(value: Any) -> int | None:
    try:
        return int(str(value).replace(",", "").split()[0])
    except (TypeError, ValueError, IndexError):
        return None


def to_envelopes(text: str, namespace: str, source: str = SOURCE_DEFAULT, host: str | None = None,
                 fmt: str | None = None, as_of: datetime | None = None,
                 mtime: datetime | None = None, all_files: bool = False,
                 stats: dict[str, int] | None = None) -> Iterator[ClaimIn]:
    stats = stats if stats is not None else {}
    fmt = fmt or detect(text)
    if fmt not in PARSERS:
        raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")
    default_time = _clamp(as_of or mtime or datetime.now(timezone.utc))
    rows = list(PARSERS[fmt](text, host))
    shapes = coverage.Shapes()
    for _, _, kind, r in rows:
        shapes.add(f"endpoint:{fmt}:{kind}", [k for k, v in r.items() if v not in (None, "")])
    # the parent of a process is the same snapshot's row for its pid
    starts: dict[tuple[str, str], datetime | None] = {}
    for h, _, kind, r in rows:
        if kind == "process" and h and r.get("pid") is not None:
            starts[(_host_key(h), str(r["pid"]))] = r.get("start")
    tally: dict[tuple[str, str], dict[str, int]] = {}
    hosts_done: set[str] = set()
    for h, when, kind, r in rows:
        if not h:
            stats["no_host"] = stats.get("no_host", 0) + 1
            continue
        hk = _host_key(h)
        observed = _clamp(when or default_time)
        stamp = observed.strftime("%Y%m%dT%H%M%S")
        host_ref = EntityRef(type="host", key=hk)
        if hk not in hosts_done:
            hosts_done.add(hk)
            yield from ident.claims(namespace, host_ref, [("fqdn" if "." in hk else "hostname", hk)],
                                    observed, source)
        t = tally.setdefault((hk, kind), {})
        if kind == "process":
            yield from _process_claims(namespace, source, hk, host_ref, r, starts, observed, stamp, t)
        elif all_files or _keep(r):
            yield from _file_claims(namespace, source, hk, host_ref, r, observed, stamp, t)
        else:
            stats["file_skipped"] = stats.get("file_skipped", 0) + 1
            continue
        stats[kind] = stats.get(kind, 0) + 1
    # one record per format and kind, not per host: a fleet's listings would
    # otherwise write thousands of coverage records per import
    totals: dict[str, dict[str, int]] = {}
    for (_, kind), t in tally.items():
        agg = totals.setdefault(kind, {})
        for k, v in t.items():
            agg[k] = agg.get(k, 0) + v
    for kind, t in sorted(totals.items()):
        n = t.get("rows", 0)
        fields = (("spawned_by", "parent"), ("cmdline", "cmdline"), ("executes", "path"),
                  ("run_as", "user"), ("started_at", "start")) if kind == "process" else \
                 (("has_hash", "hash"), ("owner", "owner"), ("modified_at", "mtime"))
        for pred, key in fields:
            yield coverage.claim(namespace, source, f"{fmt} {kind} listings", pred, t.get(key, 0), n,
                                 default_time)
    yield from shapes.claims(namespace, source, default_time)


def _process_claims(ns, source, hk, host_ref, r, starts, observed, stamp, t):
    pid = _int(r.get("pid"))
    if pid is None:
        return
    start = r.get("start")
    pkey = f"{hk}:{pid}:{start.strftime('%Y%m%dT%H%M%S') if start else 'unknown'}"
    ref = EntityRef(type="process", key=pkey)
    t["rows"] = t.get("rows", 0) + 1

    def claim(pred, obj, **kw):
        return ClaimIn(namespace=ns, event_id=_eid(f"ep:{pkey}:{stamp}:{pred}"), subject=ref,
                       predicate=pred, object=obj, observed_at=observed, source=source,
                       attrs={"host": hk, **kw.pop("attrs", {})}, **kw)

    yield claim("runs_on", host_ref)
    yield claim("pid", pid)
    if r.get("name"):
        yield claim("name", str(r["name"]))
    if start:
        t["start"] = t.get("start", 0) + 1
        yield claim("started_at", start.isoformat())
    if r.get("cmdline"):
        t["cmdline"] = t.get("cmdline", 0) + 1
        yield claim("cmdline", str(r["cmdline"])[:2000])
    ppid = _int(r.get("ppid"))
    if ppid is not None and ppid > 0:
        t["parent"] = t.get("parent", 0) + 1
        pstart = starts.get((hk, str(ppid)))
        parent = EntityRef(type="process",
                           key=f"{hk}:{ppid}:{pstart.strftime('%Y%m%dT%H%M%S') if pstart else 'unknown'}")
        yield claim("spawned_by", parent)
    if r.get("path"):
        t["path"] = t.get("path", 0) + 1
        yield claim("executes", EntityRef(type="file", key=f"{hk}:{_path_key(str(r['path']))}"),
                    attrs={"path": str(r["path"])})
    account = _account(hk, r.get("user"))
    if account:
        t["user"] = t.get("user", 0) + 1
        user_ref, pairs = account
        yield claim("run_as", user_ref)
        yield from ident.claims(ns, user_ref, pairs, observed, source)


def _file_claims(ns, source, hk, host_ref, r, observed, stamp, t):
    path = str(r.get("path") or "").strip()
    if not path:
        return
    key = f"{hk}:{_path_key(path)}"
    ref = EntityRef(type="file", key=key)
    t["rows"] = t.get("rows", 0) + 1

    def claim(pred, obj, **kw):
        return ClaimIn(namespace=ns, event_id=_eid(f"ep:{key}:{stamp}:{pred}:{obj if pred == 'has_hash' else ''}"),
                       subject=ref, predicate=pred, object=obj, observed_at=observed,
                       source=source, attrs={"host": hk, "path": path}, **kw)

    yield claim("located_on", host_ref)
    size = _int(r.get("size"))
    if size is not None:
        yield claim("size", size)
    if r.get("mtime"):
        t["mtime"] = t.get("mtime", 0) + 1
        yield claim("modified_at", r["mtime"].isoformat())
    if r.get("owner") not in (None, ""):
        t["owner"] = t.get("owner", 0) + 1
        yield claim("owner", str(r["owner"]))
    if r.get("mode"):
        yield claim("mode", str(r["mode"]))
    hashed = False
    for algo in ("sha256", "md5"):
        value = str(r.get(algo) or "").strip().lower()
        if re.fullmatch(r"[0-9a-f]{64}" if algo == "sha256" else r"[0-9a-f]{32}", value):
            hashed = True
            yield claim("has_hash", EntityRef(type="hash", key=f"{algo}:{value}"))
    if hashed:
        t["hash"] = t.get("hash", 0) + 1


# ---------------------------------------------------------------- schema #

def schema(namespace: str) -> SchemaRegistration:
    return SchemaRegistration(
        namespace=namespace,
        entity_types=[
            EntityTypeDef(name="host", description="a machine (hostname as collected, lower-cased)"),
            EntityTypeDef(name="process", description="a process: host, pid and start time (pids are reused)"),
            EntityTypeDef(name="file", description="a file on a host, keyed host:path (Windows paths folded)"),
            EntityTypeDef(name="hash", description="a file content hash (sha256:/md5:), shared across hosts"),
            EntityTypeDef(name="user", description="an account: DOMAIN\\name, or host\\name for a local one"),
            coverage.ENTITY_TYPE, *ident.SCHEMA_TYPES,
        ],
        predicates=[
            *coverage.SCHEMA_PREDICATES, *ident.SCHEMA_PREDICATES,
            PredicateDef(name="runs_on", object_types=["host"], containment=True,
                         description="the process was running on this host when listed"),
            PredicateDef(name="spawned_by", object_types=["process"],
                         description="the process's parent (same snapshot row for the parent pid)"),
            PredicateDef(name="executes", object_types=["file"], description="the process image"),
            PredicateDef(name="run_as", object_types=["user"], description="the account the process ran as"),
            PredicateDef(name="located_on", object_types=["host"], containment=True,
                         description="the file was present on this host when listed"),
            PredicateDef(name="has_hash", object_types=["hash"],
                         description="the file's content hash (shared across hosts)"),
            PredicateDef(name="pid", description="process id"),
            PredicateDef(name="cmdline", description="process command line (first 2,000 chars)"),
            PredicateDef(name="started_at", description="process start time"),
            PredicateDef(name="size", description="file size in bytes"),
            PredicateDef(name="modified_at", description="file last-modified time"),
            PredicateDef(name="owner", description="file owner as listed"),
            PredicateDef(name="mode", description="file mode / attributes as listed"),
        ],
    )


# ------------------------------------------------------------------- CLI #

def _to_lines(envs: Iterable[ClaimIn]) -> Iterator[str]:
    for env in envs:
        yield env.model_dump_json(exclude_none=True) + "\n"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="loomctx.connectors.endpoint", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--namespace", default=NAMESPACE_DEFAULT)
    common.add_argument("--source", default=SOURCE_DEFAULT)
    common.add_argument("--host", help="the host the listing came from (inside osqueryd logs "
                                       "and Win32_Process output it is read from the data)")
    common.add_argument("--format", choices=FORMATS, help="skip auto-detection")
    common.add_argument("--as-of", dest="as_of", help="ISO collection time (default: file mtime)")
    common.add_argument("--all-files", action="store_true",
                        help="keep every file entry, not only executables/scripts/configs/hashed")
    sub = parser.add_subparsers(dest="command", required=True)
    imp = sub.add_parser("import", parents=[common], help="parse and ingest")
    imp.add_argument("files", nargs="+")
    imp.add_argument("--url")
    imp.add_argument("--db")
    imp.add_argument("--key", default=os.environ.get("LOOMCTX_API_KEY"), type=str.strip)
    imp.add_argument("--batch", type=int, default=500)
    imp.add_argument("--no-schema", action="store_true")
    emit = sub.add_parser("emit", parents=[common], help="write NDJSON envelopes to stdout")
    emit.add_argument("files", nargs="+")
    sub.add_parser("schema", parents=[common], help="print the schema")
    args = parser.parse_args(argv)

    if args.command == "schema":
        print(schema(args.namespace).model_dump_json(indent=2))
        return
    as_of = None
    if args.as_of:
        as_of = datetime.fromisoformat(args.as_of.replace("Z", "+00:00"))
        as_of = as_of if as_of.tzinfo else as_of.replace(tzinfo=timezone.utc)
    stats: dict[str, int] = {}

    def envs() -> Iterator[ClaimIn]:
        for path in args.files:
            with open(path, encoding="utf-8-sig", errors="replace") as fh:
                text = fh.read()
            mt = datetime.fromtimestamp(os.stat(path).st_mtime, tz=timezone.utc).replace(microsecond=0)
            yield from to_envelopes(text, args.namespace, args.source, args.host, args.format,
                                    as_of, mt, args.all_files, stats)

    if args.command == "emit":
        for line in _to_lines(envs()):
            sys.stdout.write(line)
        print(json.dumps({"envelopes": stats}), file=sys.stderr)
        return
    if args.url and args.db:
        parser.error("import: give --url or --db, not both")
    from ..ingest import fail_on_refusals, load_direct, post_batches
    from .vulns import register
    if not args.no_schema:
        register(schema(args.namespace), args.url, args.db, args.key)
    watch = coverage.Watch()
    lines = _to_lines(watch.wrap(envs()))
    totals = (post_batches(args.url, lines, args.batch, args.key) if args.url
              else load_direct(args.db, lines, args.batch))
    drift = watch.report(args.url, args.db, args.key)
    print(json.dumps({**totals, "envelopes": stats, "drift": [d.text() for d in drift]}))
    coverage.print_drift(drift)
    if stats.get("no_host"):
        print(f"{stats['no_host']} rows named no host: pass --host", file=sys.stderr)
    fail_on_refusals(totals, remote=bool(args.url))


if __name__ == "__main__":
    main()
