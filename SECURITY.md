# Security policy

LoomCtx is pre-1.0 and under active development ahead of a conference demo
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
- **MCP transports:** stdio is local trust (the spawning agent owns the
  data); the HTTP transports require the same API key as the REST routes
  on every request and apply the key's data gates per tool call. The
  compose profile still binds to localhost by default.
- **Known gaps** are tracked openly in `docs/hardening.md`.

## Supported versions

`main` and the latest tagged release (`v0.1.0`, 2026-09-09) are
supported; a fix lands on `main` first and is re-tagged from the gated
image when it warrants a release (D-045). Older tags get no backports.

## What ships hardened

Images run non-root with read-only roots and no capabilities; base images
are pinned by digest and Python dependencies by a universal lock; CI pins
its actions by commit, scans both images with Trivy before publishing,
and publishes the exact image it tested. The Kubernetes manifests carry
default-deny ingress NetworkPolicies and no ServiceAccount tokens. See
`deploy/README.md` ("Pod posture") and `docs/hardening.md`.
