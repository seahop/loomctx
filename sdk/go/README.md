# loom (Go SDK)

Thin, dependency-free Go client for Loom's HTTP API. Its envelopes are
tested against `contracts/schemas.json` — the same schema the Go ingest
gateway enforces — so it cannot drift from the server.

```go
import loom "github.com/seahop/loom/sdk/go"

c := loom.New("http://localhost:8000", "netsec")
c.APIKey = "loomk_..."
res, err := c.IngestBatch(ctx,
    loom.Claim{Subject: loom.EntityRef{Type: "host", Key: "web-01"}, Predicate: "logged_in_by",
               Object: loom.EntityRef{Type: "user", Key: "jdoe"}, ObservedAt: time.Now(), Source: "auth-log"},
)
pack, err := c.Ask(ctx, &loom.EntityRef{Type: "host", Key: "web-01"}, "who logged in this week?",
    loom.AskOptions{Budget: 800})
```

The client itself imports only the standard library; the JSON-schema
validator in `go.mod` is used by the contract drift test alone.

Build/test inside Docker: `docker compose --profile sdk run --rm sdk-go`
(needs the engine up: `docker compose up -d --wait loom`). The container
exits non-zero if `go mod tidy -diff`, `go vet` or any test fails.
