# loomctx-sdk

Thin, dependency-free Python client for LoomCtx's HTTP API (`docs/sdk.md`).
It contains no logic — just typed transport over the contract in
`contracts/schemas.json` — so it can never drift from the server.

```python
from loomctx_sdk import LoomCtx, LoomCtxError

loomctx = LoomCtx("http://localhost:8000", namespace="netsec", api_key="loomctxk_...")
pack = loomctx.ask(("host", "web-01"), "who logged in this week?", budget=800)
try:
    loomctx.artifact("not-a-real-id")
except LoomCtxError as exc:
    print(exc.status, exc.detail)   # 404 unknown artifact
```

Install from the repo (`pip install ./sdk/python`) or vendor `loomctx_sdk/`
directly onto a pipeline device — it is a single stdlib-only module.
