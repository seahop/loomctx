# Act 3 transcript — before the alias merges

Rehearsal of 2026-09-10 with Claude Code over MCP stdio, before D-042 merged the `linux:kernel` / `linux:linux_kernel` aliases. Kept because the agent found the entity-resolution seam on its own (see the answer's last section) — the anecdote `docs/demo.md` tells in Act 3.

Model `claude-fable-5-1`; 22 tool calls, 23 turns, 145 s, $4.53. Source: `act3-claude-code.json` (the JSON carries the full arguments).

## Tool calls, in order

1. `ToolSearch` — query=select:mcp__loom__describe_namespace,mcp__loom__find_entity,mcp__loom__ask_scope,mcp__loom__expand,mcp__loo...; max_results=7
2. `describe_namespace` — namespace=netsec
3. `find_entity` — query=web-01; namespace=netsec
4. `ask_scope` — subjects=["host:web-01"]; question=Which software does web-01 run, and which CVEs affecting that software are listed by CISA as exploited in t...; namespace=netsec; expand_predicates=["runs_software", "affects"]; depth=2; budget=3000
5. `get_observations` — subject=host:web-01; namespace=netsec
6. `ask` — subject=host:web-01; question=What software products does web-01 run (runs_software)?; namespace=netsec; budget=1500
7. `ask` — subject=cve:CVE-2026-53362; question=Is this CVE listed in CISA KEV as exploited in the wild, and which products does it affect?; namespace=netsec; budget=800
8. `ask` — subject=cve:CVE-2026-31431; question=Is this CVE listed in CISA KEV as exploited in the wild, and which products does it affect?; namespace=netsec; budget=800
9. `ask` — subject=cve:CVE-2014-0160; question=Is this CVE listed in CISA KEV as exploited in the wild, and which products does it affect?; namespace=netsec; budget=800
10. `ask_scope` — subjects=["product:openbsd:openssh"]; question=Which CVEs affecting OpenSSH are listed by CISA KEV as exploited in the wild?; namespace=netsec; expand_predicates=["affects"]; depth=1; budget=1500
11. `ask_scope` — subjects=["product:nginx:nginx", "product:f5:nginx_open_source"]; question=Which CVEs affecting nginx are listed by CISA KEV as exploited in the wild?; namespace=netsec; expand_predicates=["affects"]; depth=1; budget=1500
12. `ask_scope` — subjects=["product:openssl:openssl"]; question=Which CVEs affecting OpenSSL are listed by CISA KEV as exploited in the wild?; namespace=netsec; expand_predicates=["affects"]; depth=1; budget=1500
13. `find_related` — question=CISA KEV known exploited vulnerability in Linux kernel, OpenSSL, OpenSSH, or nginx; namespace=netsec; limit=20
14. `find_entity` — query=linux:kernel; namespace=netsec
15. `ask_scope` — subjects=["product:linux:kernel"]; question=Which CVEs affecting the Linux kernel are listed in CISA KEV as exploited in the wild (exploited_in_wild)?; namespace=netsec; expand_predicates=["affects"]; depth=1; budget=2500
16. `ask_scope` — subjects=["product:linux:linux_kernel"]; question=Which CVEs affecting linux_kernel have exploited_in_wild True per cisa-kev?; namespace=netsec; expand_predicates=["affects"]; depth=1; budget=2500
17. `find_related` — question=Linux Kernel vulnerability exploited in the wild, CISA KEV required action apply mitigations; namespace=netsec; limit=20
18. `find_related` — question=OpenSSH sshd vulnerability listed in CISA KEV known exploited; namespace=netsec; limit=10
19. `find_related` — question=NGINX web server vulnerability listed in CISA KEV known exploited; namespace=netsec; limit=10
20. `ask` — subject=cve:CVE-2022-0995; question=Is it in CISA KEV (exploited_in_wild) and does it affect product:linux:linux_kernel per nvd?; namespace=netsec; budget=500
21. `ask` — subject=cve:CVE-2024-1086; question=Is it in CISA KEV (exploited_in_wild) and does it affect product:linux:linux_kernel per nvd?; namespace=netsec; budget=500
22. `ask` — subject=cve:CVE-2022-0847; question=Is it in CISA KEV (exploited_in_wild) and does it affect product:linux:linux_kernel per nvd?; namespace=netsec; budget=500

## Final answer (verbatim)

Done querying. Writing up the result now.

**Yes.** Loom links three CISA Known Exploited Vulnerabilities (KEV) entries directly to software that web-01 runs: two in the Linux kernel and one in OpenSSL. A further group of kernel KEV entries is one product alias away, explained below.

**What web-01 runs** (all from asset-inventory, observed 2026-07-03; no versions recorded):

| Product | Observation id |
|---|---|
| linux:linux_kernel | 44f97aad4d0242478a5d39433e85cc43 |
| openssl:openssl | 6b4210db9e724b0298ece31b48bc3c3f |
| openbsd:openssh | 50984b9757ec4d49bd3f94c95c784326 |
| f5:nginx_open_source | 78ac601a892145bbaf2d2a45c1e1f0c8 |
| nginx:nginx | 24ca4df71dbc4398828a8094588bcb1c |

**KEV CVEs directly linked to those products**

| CVE | Software | KEV listing (exploited_in_wild) | Affects link | Notes |
|---|---|---|---|---|
| CVE-2026-53362 | Linux kernel | 90a3927e32694e42a1beb8e512cc0fd4 (cisa-kev, 2026-08-27) | cc8a663f95ba4ec3b1075cb64537bf83 (nvd → linux:linux_kernel) | Privilege escalation via IPv6 subsystem, CVSS 7.8, KEV due date 2026-08-30 |
| CVE-2026-31431 | Linux kernel | 17578bc052554b8eb7b50ee132255fa9 (cisa-kev, 2026-05-01) | ab73fd8758054bb0bc26be426f0925df (nvd → linux:linux_kernel) | Privilege escalation, EPSS 0.999 (99.97th percentile), KEV due date 2026-05-15 |
| CVE-2014-0160 | OpenSSL | 5a7ac4de2fb8443ab1af62dc7c6fae66 (cisa-kev, 2022-05-04) | ec0cbac923514040a1eff88702524969 (cisa-kev → openssl:openssl) | Heartbleed, EPSS 0.99999 |

**OpenSSH and nginx:** no KEV entries found. Expanding both products over their CVEs surfaced only NVD records with no exploited_in_wild fact, and semantic searches for OpenSSH or nginx KEV listings returned nothing product-specific.

**Caveat: the kernel is double-keyed.** The KEV connector files kernel entries under `linux:kernel`, while NVD and the asset inventory use `linux:linux_kernel`. About 25 additional kernel KEV CVEs hang only off the KEV key and never reach web-01 through the graph. Three I verified directly, each with a KEV fact and an affects link only to `linux:kernel`:

- CVE-2022-0995, out-of-bounds write, KEV added 2026-08-26 (2d94188cc4ff44bcbad5913f9df76d58, f9709b0e37854705a3dfee19ee82ef2d)
- CVE-2024-1086, nf_tables use-after-free, known ransomware use (3077ad14e258493796ab6c3ea6b489b5, 961839c37ff34ff59ddba6a78d84b900)
- CVE-2022-0847, Dirty Pipe, EPSS 0.897 (5d4e724397894fdf9498d87b816308b8, 504cfd6faab0421e9c502b059276db34)

Others in that set include CVE-2022-0492, CVE-2018-14634, CVE-2024-50302, CVE-2024-53104, CVE-2024-53150, CVE-2024-53197, CVE-2023-0386, CVE-2025-38352, CVE-2022-2586, CVE-2022-0185, CVE-2021-22555, CVE-2021-3493, CVE-2017-1000253, CVE-2019-13272, and CVE-2016-5195. Whether any of them applies to web-01 depends on its kernel version, which the inventory does not record. Note also that the kernel scan was truncated to the newest 1,000 of 2,747 observations, so absence of an NVD link for these is not proven. A product alias between the two kernel keys in the schema registry would close this gap.

**Two things that weaken the answer:**

- **OS conflict, unresolved.** nmap-scan says web-01 runs ubuntu-22.04 as of 2026-08-18 (2ce373ffd50b4a67b7b80ed44f3eaa47); asset-inventory says fedora-44 as of 2026-07-03 (9918808e0d254811a9d3fd639e2fc349). Which distro it is determines which kernel and OpenSSL builds are in play.
- **Product-level matching only.** The runs_software claims carry no version, so "affected" here means the product is in scope of the CVE, not that the installed build is confirmed vulnerable.
