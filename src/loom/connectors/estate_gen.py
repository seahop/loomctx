"""A synthetic estate for the identity / host-artifact / drift / purple scale
check (`loom.estate_eval`; D-083…D-086).

    python -m loom.connectors.estate_gen --seed 7 --scale medium --out-dir /data/estate

Every machine is named the way each tool names it — the directory as
`WEB-0042$` with `dNSHostName` web-0042.corp.example, the scanner by FQDN
with its address and MAC, osquery by upper-case FQDN, tasklist by
`COMPUTERNAME`, the EDR by short hostname — so the files only line up
through identity resolution. Two traps are planted: pairs of machines in
two domains that share a short hostname (weak: must NOT fold), and
addresses reassigned from one machine to another between scans (never an
identifier). A red operation log of Atomic-style actions and the EDR's
detections carry a known outcome per action (detected / host-only /
missed). A second LDAP export drops `userAccountControl` (format drift).

Writes: ad.ldif, ad-later.ldif, scan.xml, rescan.xml, osquery.log,
tasklist/<host>.csv, oplog.csv, detections.ndjson, truth.json.
All names are generated; `example` domains only.
"""

from __future__ import annotations

import argparse
import base64
import json
import random
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCALES = {"small": 200, "medium": 2_000, "large": 6_000}
TECHNIQUES = ["T1003.001", "T1059.001", "T1053.005", "T1021.002", "T1047", "T1105", "T1082",
              "T1016", "T1087.002", "T1136.001", "T1543.003", "T1070.004"]
PROCS = ["svchost.exe", "lsass.exe", "explorer.exe", "powershell.exe", "cmd.exe", "winlogon.exe",
         "services.exe", "spoolsv.exe", "MsMpEng.exe", "chrome.exe", "outlook.exe", "sqlservr.exe"]
T0 = datetime(2026, 9, 20, 8, 0, tzinfo=timezone.utc)


def _sid(domain_n: int, rid: int) -> bytes:
    """Binary objectSid: revision 1, five sub-authorities, NT authority 5."""
    return (bytes([1, 5]) + (5).to_bytes(6, "big")
            + struct.pack("<IIIII", 21, 1000 + domain_n, 2000 + domain_n, 3000, rid))


def sid_text(domain_n: int, rid: int) -> str:
    return f"S-1-5-21-{1000 + domain_n}-{2000 + domain_n}-3000-{rid}"


class Estate:
    def __init__(self, seed: int, scale: str):
        self.rng = random.Random(seed)
        self.n = SCALES[scale]
        self.seed, self.scale = seed, scale
        self.hosts: list[dict] = []
        self.users: list[dict] = []
        self.ran_as: tuple[str, str] | None = None   # (user sid, host sid) a process shows

    def build(self) -> None:
        rng = self.rng
        # two domains; the second holds the twins of some first-domain names
        for i in range(self.n):
            dom = 0 if i < self.n * 0.9 else 1
            name = f"ws-{i:05d}" if dom == 0 else f"ws-{rng.randrange(0, int(self.n * 0.9)):05d}"
            domain = "corp.example" if dom == 0 else "lab.example"
            self.hosts.append({
                "i": i, "short": name, "domain": domain, "dom": dom, "rid": 5000 + i,
                "fqdn": f"{name}.{domain}", "ip": f"10.{dom}.{i // 250}.{i % 250 + 1}",
                "mac": ":".join(f"{rng.randrange(256):02x}" for _ in range(6)),
                "sid": sid_text(dom, 5000 + i)})
        for u in range(self.n // 2):
            self.users.append({"sam": f"user{u:05d}", "rid": 20000 + u, "sid": sid_text(0, 20000 + u)})

    # ---------------------------------------------------------------- files #
    def ldif(self, with_uac: bool = True) -> str:
        blocks = ["# exported"]
        for h in self.hosts:
            dc = ",".join(f"DC={p}" for p in h["domain"].split("."))
            block = [f"dn: CN={h['short'].upper()},OU=Computers,{dc}", "objectClass: computer",
                     f"objectSid:: {base64.b64encode(_sid(h['dom'], h['rid'])).decode()}",
                     f"sAMAccountName: {h['short'].upper()}$", f"dNSHostName: {h['fqdn']}"]
            if with_uac:
                block.append("userAccountControl: 4096")
            blocks.append("\n".join(block))
        for u in self.users:
            block = [f"dn: CN={u['sam']},OU=Staff,DC=corp,DC=example", "objectClass: user",
                     f"objectSid:: {base64.b64encode(_sid(0, u['rid'])).decode()}",
                     f"sAMAccountName: {u['sam']}", f"userPrincipalName: {u['sam']}@corp.example"]
            if with_uac:
                block.append("userAccountControl: 512")
            blocks.append("\n".join(block))
        return "\n\n".join(blocks) + "\n"

    def scan(self, shift: bool) -> str:
        """An nmap report of the first domain; with `shift`, a slice of hosts
        swapped addresses (DHCP) — the reassigned address is the trap."""
        hosts = [h for h in self.hosts if h["dom"] == 0]
        ips = [h["ip"] for h in hosts]
        if shift:
            k = len(hosts) // 20
            ips[:k] = ips[1:k] + ips[:1]
        start = int((T0 + (timedelta(days=1) if shift else timedelta())).timestamp())
        out = [f'<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -sV -O 10.0.0.0/16" '
               f'start="{start}">']
        for h, ip in zip(hosts, ips):
            out.append(f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/>'
                       f'<address addr="{h["mac"].upper()}" addrtype="mac"/>'
                       f'<hostnames><hostname name="{h["fqdn"]}" type="PTR"/></hostnames>'
                       f'<ports><port protocol="tcp" portid="445"><state state="open"/>'
                       f'<service name="microsoft-ds"/></port></ports></host>')
        out.append("</nmaprun>")
        return "\n".join(out)

    def osquery(self) -> str:
        lines = []
        for h in self.hosts[: self.n // 2]:
            snap = []
            for pid in range(4, 4 + 40 * 4, 4):
                u = self.rng.randrange(len(self.users))
                if self.ran_as is None:
                    self.ran_as = (self.users[u]["sid"], h["sid"])
                snap.append({"pid": str(pid), "parent": str(max(4, pid - 4 * self.rng.randrange(1, 4))),
                             "name": self.rng.choice(PROCS), "path": f"C:\\Windows\\System32\\{pid}.exe",
                             "cmdline": f"proc {pid}", "start_time": str(int(T0.timestamp()) - pid),
                             "username": f"CORP\\user{u:05d}"})
            lines.append(json.dumps({"name": "processes", "hostIdentifier": h["fqdn"].upper(),
                                     "unixTime": int(T0.timestamp()) + 3600, "action": "snapshot",
                                     "snapshot": snap}))
            lines.append(json.dumps({"name": "hashes", "hostIdentifier": h["fqdn"].upper(),
                                     "unixTime": int(T0.timestamp()) + 3600, "action": "snapshot",
                                     "snapshot": [{"path": "C:\\Tools\\agent.exe", "sha256": "c" * 64,
                                                   "size": "1024"}]}))
        return "\n".join(lines) + "\n"

    def tasklists(self) -> dict[str, str]:
        out = {}
        for h in self.hosts[self.n // 2: self.n // 2 + max(10, self.n // 20)]:
            rows = ['"Image Name","PID","Session Name","Session#","Mem Usage","Status","User Name",'
                    '"CPU Time","Window Title"']
            for pid in range(100, 100 + 30):
                rows.append(f'"{self.rng.choice(PROCS)}","{pid}","Services","0","1,000 K","Unknown",'
                            f'"{h["domain"].split(".")[0].upper()}\\user{pid % 50:05d}","0:00:01","N/A"')
            out[h["short"].upper()] = "\n".join(rows) + "\n"
        return out

    def purple(self) -> tuple[str, str, list[dict]]:
        """(op log CSV, detections NDJSON, per-action truth)."""
        rng = self.rng
        targets = [h for h in self.hosts if h["dom"] == 0]
        rows = ['"Execution Time (UTC)","Execution Time (Local)","Technique","Test Number",'
                '"Test Name","Hostname","IP Address","Username","GUID","ProcessId","ExitCode"']
        events, truth = [], []
        # one action per target host: a second action on the same host would
        # meet the first's detection in its window (a real "something fired")
        chosen = rng.sample(targets, min(len(targets), max(30, self.n // 10)))
        for a, h in enumerate(chosen):
            tech = rng.choice(TECHNIQUES)
            at = T0 + timedelta(hours=2, minutes=a * 3)
            gid = f"g{a:05d}"
            rows.append(f'"{at.strftime("%Y-%m-%dT%H:%M:%SZ")}","{at.strftime("%Y-%m-%dT%H:%M:%S")}",'
                        f'"{tech}","1","test {a}","{h["short"].upper()}","{h["ip"]}",'
                        f'"CORP\\redop","{gid}","{4000 + a}","0"')
            roll = rng.random()
            outcome = "detected" if roll < 0.55 else "host_only" if roll < 0.75 else "missed"
            latency = rng.randrange(20, 1800)
            if outcome != "missed":
                technique = tech if outcome == "detected" else "T1497"   # an unrelated technique
                det_at = at + timedelta(seconds=latency)
                events.append({
                    "class_uid": 2004, "time": int(det_at.timestamp() * 1000), "status_id": 1,
                    "severity_id": 4, "metadata": {"product": {"name": "EDR", "vendor_name": "Acme"}},
                    "finding_info": {"uid": f"det-{a:05d}", "title": f"alert {a}",
                                     "created_time": int(det_at.timestamp() * 1000),
                                     "attacks": [{"technique": {"uid": technique.split(".")[0]},
                                                  "sub_technique": {"uid": technique}}]},
                    "device": {"hostname": h["short"], "ip": h["ip"]}})
            truth.append({"guid": gid, "technique": tech, "host": h["short"], "outcome": outcome,
                          "latency": latency if outcome == "detected" else None})
        return "\n".join(rows) + "\n", "\n".join(json.dumps(e) for e in events) + "\n", truth

    def truth(self, actions: list[dict]) -> dict:
        corp = [h for h in self.hosts if h["dom"] == 0]
        twins = [h for h in self.hosts if h["dom"] == 1]
        return {"seed": self.seed, "scale": self.scale, "hosts": len(self.hosts),
                "corp_hosts": len(corp), "twins": [(t["short"], t["fqdn"]) for t in twins],
                "users": len(self.users), "ran_as": list(self.ran_as) if self.ran_as else None,
                "host_names": {h["sid"]: [h["fqdn"], h["fqdn"].upper(), h["short"]] for h in self.hosts},
                "actions": actions}


def generate(seed: int, scale: str, out_dir: str) -> dict:
    e = Estate(seed, scale)
    e.build()
    out = Path(out_dir)
    (out / "tasklist").mkdir(parents=True, exist_ok=True)
    (out / "ad.ldif").write_text(e.ldif(True))
    (out / "ad-later.ldif").write_text(e.ldif(False).replace("# exported", "# exported later"))
    (out / "scan.xml").write_text(e.scan(False))
    (out / "rescan.xml").write_text(e.scan(True))
    (out / "osquery.log").write_text(e.osquery())
    for host, text in e.tasklists().items():
        (out / "tasklist" / f"{host}.csv").write_text(text)
    oplog, detections, actions = e.purple()
    (out / "oplog.csv").write_text(oplog)
    (out / "detections.ndjson").write_text(detections)
    truth = e.truth(actions)
    (out / "truth.json").write_text(json.dumps(truth))
    return truth


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="loom.connectors.estate_gen", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--scale", default="medium", choices=sorted(SCALES))
    p.add_argument("--out-dir", required=True)
    a = p.parse_args(argv)
    t = generate(a.seed, a.scale, a.out_dir)
    print(json.dumps({"hosts": t["hosts"], "actions": len(t["actions"])}))


if __name__ == "__main__":
    main()
