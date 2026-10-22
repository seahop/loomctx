# Go SDK toolchain (D-034): vet, contract drift test, live test against the engine.
# Same Go as the gateway (gateway/go.mod), pinned by digest.
FROM golang:1.27-alpine@sha256:d530cf60723abf1ffae0cd16bb546b379ec0550d2f3815e5b16ed69dbc00fba4
WORKDIR /app
# go.sum is committed: downloads are verified against it, never rewritten here
COPY sdk/go/go.mod sdk/go/go.sum ./
RUN go mod download all && go mod verify
COPY sdk/go/ ./
COPY contracts/schemas.json /contracts/schemas.json
ENV LOOMCTX_SCHEMAS=/contracts/schemas.json
# `go mod tidy -diff` fails (without writing) if go.mod/go.sum are stale.
# A passing run prints a filtered summary, a failing one the full log; either
# way the container exits with `go test`'s own status (sh has no pipefail, so
# the output is never piped into grep, whose status would mask a failure).
CMD ["sh", "-c", "go mod tidy -diff && go vet ./... || exit 1; go test ./... -v -run . > /tmp/go-test.log 2>&1; rc=$?; if [ $rc -eq 0 ]; then grep -E '^(=== RUN|--- |PASS|FAIL|ok|\\s+loomctx_test)' /tmp/go-test.log; else cat /tmp/go-test.log; fi; exit $rc"]
