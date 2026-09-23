# Go SDK toolchain (D-034): vet, contract drift test, live test against the engine.
# Same Go as the gateway (gateway/go.mod), pinned by digest.
FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414
WORKDIR /app
COPY sdk/go/go.mod ./
RUN go mod download && go mod tidy >/dev/null 2>&1 || true
COPY sdk/go/ ./
COPY contracts/schemas.json /contracts/schemas.json
ENV LOOM_SCHEMAS=/contracts/schemas.json
CMD ["sh", "-c", "go mod tidy && go vet ./... && go test ./... -v -run . 2>&1 | grep -E '^(=== RUN|--- |PASS|FAIL|ok|\\s+loom_test)' "]
