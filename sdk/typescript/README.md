# loomctx-sdk (TypeScript)

Thin, dependency-free client for the HTTP API of
[LoomCtx](https://github.com/seahop/loomctx), typed against
`src/contracts.ts`, which is **generated** from `contracts/schemas.json`
(itself exported from `src/loomctx/contracts.py`). CI regenerates it and
fails on drift, so the SDK cannot disagree with the server. Node 18+ or
any runtime with `fetch`; ES module only.

## Install

`loomctx-sdk` is not on npm yet (planned; [docs/releasing.md](https://github.com/seahop/loomctx/blob/main/docs/releasing.md)).
npm cannot install a package from a subdirectory of a git repository, so
until it is published, build a tarball from a checkout and install that:

```bash
# in the checkout: build and pack inside Node's image (writes loomctx-sdk-0.2.0.tgz here)
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$PWD/sdk/typescript:/app" -w /app \
  node:22-alpine sh -c "npm ci && npm pack"
# in your project
npm install /path/to/loomctx/sdk/typescript/loomctx-sdk-0.2.0.tgz
```

Once published: `npm install loomctx-sdk`.

## Use

```ts
import { LoomCtx, LoomCtxError } from "loomctx-sdk";

const loomctx = new LoomCtx("http://localhost:8000", { namespace: "netsec", apiKey: "loomctxk_..." });
const pack = await loomctx.ask(["host", "web-01"], "who logged in this week?", { budget: 800 });
for (const item of pack.items) console.log(item.kind, item.text, item.citations);

// fact time vs knowledge time (D-024)
await loomctx.ask(["ip", "10.0.4.7"], "which host?", { valid_at: "2026-08-20T00:00:00Z" });

try { await loomctx.artifact("nope"); } catch (e) { if (e instanceof LoomCtxError) console.log(e.status, e.detail); }
```

## Develop

Everything runs in Docker (project rule):

```bash
docker compose --profile sdk run --rm sdk-ts                       # regen-check + build + test against a live engine
docker compose --profile sdk run --rm sdk-ts npm run gen           # regenerate src/contracts.ts after a contract change
```

Apache-2.0; see `LICENSE` and `NOTICE`.
