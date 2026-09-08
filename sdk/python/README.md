# loom-sdk

Thin, dependency-free Python client for Loom's HTTP API (`docs/sdk.md`).
It contains no logic — just typed transport over the contract in
`contracts/schemas.json` — so it can never drift from the server.

```python
from loom_sdk import Loom, LoomError

loom = Loom("http://localhost:8000", namespace="netsec", api_key="loomk_...")
pack = loom.ask(("host", "web-01"), "who logged in this week?", budget=800)
try:
    loom.artifact("not-a-real-id")
except LoomError as exc:
    print(exc.status, exc.detail)   # 404 unknown artifact
```

Install from the repo (`pip install ./sdk/python`) or vendor `loom_sdk/`
directly onto a pipeline device — it is a single stdlib-only module.
