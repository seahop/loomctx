# Security policy

Loom is pre-1.0 and under active development ahead of a conference demo
(October 2026). It is designed to hold sensitive operational data — treat
any deployment as such.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for anything you believe is a
security problem. Use GitHub's private vulnerability reporting on the
repository ("Security" tab → "Report a vulnerability"). You'll get an
acknowledgement within a few days and a fix or a mitigation plan as fast as
a small project can manage.

## What the security model is

The bearer model, data-scoping gates, and their limits are documented in
`docs/administration.md` and `docs/decisions.md` (D-013, D-013a, D-021,
D-023). In short:

- **Capabilities are never gated — data is.** A valid reader always has the
  full query surface; keys control which namespaces, entity types, and
  sources they operate over, and every read path (including scope
  expansion and expansion handles) applies those gates to what a response
  *contains*.
- **Document text is untrusted input.** Extraction prompts label it as
  data; extracted claims are tagged and rank below sender-asserted facts.
- **Known gaps** are tracked openly in `docs/hardening.md`. Today the
  biggest is that the MCP streamable-HTTP transport carries no
  per-connection key of its own — it binds to localhost by default and must
  sit behind your own auth before being exposed.

## Supported versions

Only `main` is supported until a tagged release exists.
