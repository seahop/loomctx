# loom-sdk (TypeScript)

Thin, dependency-free client for Loom's HTTP API, typed against
`src/contracts.ts` — which is **generated** from `contracts/schemas.json`
(itself exported from `src/loom/contracts.py`). CI regenerates it and fails
on drift, so the SDK cannot disagree with the server.

```ts
import { Loom, LoomError } from "loom-sdk";

const loom = new Loom("http://localhost:8000", { namespace: "netsec", apiKey: "loomk_..." });
const pack = await loom.ask(["host", "web-01"], "who logged in this week?", { budget: 800 });
for (const item of pack.items) console.log(item.kind, item.text, item.citations);

// fact time vs knowledge time (D-024)
await loom.ask(["ip", "10.0.4.7"], "which host?", { valid_at: "2026-08-20T00:00:00Z" });

try { await loom.artifact("nope"); } catch (e) { if (e instanceof LoomError) console.log(e.status, e.detail); }
```

Everything runs in Docker (project rule):

```bash
docker compose --profile sdk run --rm sdk-ts                       # regen-check + build + test against a live engine
docker compose --profile sdk run --rm sdk-ts npm run gen           # regenerate src/contracts.ts after a contract change
```
