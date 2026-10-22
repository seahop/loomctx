# loomctx (Go SDK)

Thin, dependency-free Go client for LoomCtx's HTTP API. Its envelopes are
tested against `contracts/schemas.json` — the same schema the Go ingest
gateway enforces — so it cannot drift from the server.

## Install

The module is `github.com/seahop/loomctx/sdk/go` (Go 1.27+; the package is
`loomctx`). No SDK version is tagged yet, so `@latest` resolves to a
pseudo-version of `main`:

```bash
go get github.com/seahop/loomctx/sdk/go@latest
```

Tagged versions are planned as `sdk/go/vX.Y.Z` (a module in a
subdirectory is versioned by tags with that prefix,
[docs/releasing.md](https://github.com/seahop/loomctx/blob/main/docs/releasing.md));
once `sdk/go/v0.2.0` is pushed, `go get github.com/seahop/loomctx/sdk/go@v0.2.0`
resolves to it. The repository's
own `v0.2.0` tag versions the engine, not this module.

## Use

```go
import loomctx "github.com/seahop/loomctx/sdk/go"

c := loomctx.New("http://localhost:8000", "netsec")
c.APIKey = "loomctxk_..."
res, err := c.IngestBatch(ctx,
    loomctx.Claim{Subject: loomctx.EntityRef{Type: "host", Key: "web-01"}, Predicate: "logged_in_by",
               Object: loomctx.EntityRef{Type: "user", Key: "jdoe"}, ObservedAt: time.Now(), Source: "auth-log"},
)
pack, err := c.Ask(ctx, &loomctx.EntityRef{Type: "host", Key: "web-01"}, "who logged in this week?",
    loomctx.AskOptions{Budget: 800})
```

The client itself imports only the standard library; the JSON-schema
validator in `go.mod` is used by the contract drift test alone.

Build/test inside Docker: `docker compose --profile sdk run --rm sdk-go`
(needs the engine up: `docker compose up -d --wait loomctx`). The container
exits non-zero if `go mod tidy -diff`, `go vet` or any test fails.
