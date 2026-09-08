# loom (Go SDK)

Thin, dependency-free Go client for Loom's HTTP API. Its envelopes are
tested against `contracts/schemas.json` — the same schema the Go ingest
gateway enforces — so it cannot drift from the server.

```go
import loom "github.com/seahop/loom/sdk/go"

c := loom.New("http://localhost:8000", "netsec")
c.APIKey = "loomk_..."
res, err := c.IngestBatch(ctx,
    loom.Claim{Subject: loom.EntityRef{"host", "web-01"}, Predicate: "logged_in_by",
               Object: loom.EntityRef{"user", "jdoe"}, ObservedAt: time.Now(), Source: "auth-log"},
)
pack, err := c.Ask(ctx, &loom.EntityRef{"host", "web-01"}, "who logged in this week?", loom.AskOptions{Budget: 800})
```

Build/test inside Docker: `docker compose --profile sdk run --rm sdk-go`.
