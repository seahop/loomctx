# loomctx-sdk

Thin, dependency-free Python client for the HTTP API of
[LoomCtx](https://github.com/seahop/loomctx), a context engine for AI
agents ([docs/sdk.md](https://github.com/seahop/loomctx/blob/main/docs/sdk.md)).
It contains no logic, just typed transport over the contract in
`contracts/schemas.json`, so it can never drift from the server.

## Install

`loomctx-sdk` is not on PyPI yet (planned; [docs/releasing.md](https://github.com/seahop/loomctx/blob/main/docs/releasing.md)).
Until it is, install it from the repository:

```bash
pip install "git+https://github.com/seahop/loomctx#subdirectory=sdk/python"   # from GitHub
pip install ./sdk/python                                                      # from a checkout
```

Or vendor `loomctx_sdk/` onto a pipeline device: it is stdlib-only
(Python 3.10+), two files.

## Use

```python
from loomctx_sdk import LoomCtx, LoomCtxError

loomctx = LoomCtx("http://localhost:8000", namespace="netsec", api_key="loomctxk_...")
pack = loomctx.ask(("host", "web-01"), "who logged in this week?", budget=800)
try:
    loomctx.artifact("not-a-real-id")
except LoomCtxError as exc:
    print(exc.status, exc.detail)   # 404 unknown artifact
```

Registering a domain, sending claims in a batch and linking documents is
walked through in
[docs/bring-your-own-data.md](https://github.com/seahop/loomctx/blob/main/docs/bring-your-own-data.md).

Apache-2.0; see `LICENSE` and `NOTICE`.
