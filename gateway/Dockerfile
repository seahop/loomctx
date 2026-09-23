# Build context is the REPO ROOT (see docker-compose.yml) so the image can
# carry contracts/schemas.json — the language-neutral contract the gateway
# validates against. `go vet`, `govulncheck` and `go test` run as part of
# every build. Base images are pinned by digest (Dependabot bumps them).
FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build
WORKDIR /src
COPY gateway/go.mod gateway/go.sum ./
RUN go mod download
COPY gateway/ ./
COPY contracts /contracts
# tests read ../contracts/schemas.json, i.e. /contracts/schemas.json here
RUN go vet ./... && go test ./...
# known-vulnerable code paths in the module graph fail the build (the
# publish job additionally scans the finished image with Trivy)
RUN go run golang.org/x/vuln/cmd/govulncheck@latest ./...
RUN CGO_ENABLED=0 go build -trimpath -o /gateway .

FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
COPY --from=build /gateway /usr/local/bin/gateway
COPY contracts/schemas.json /etc/loom/schemas.json
# non-root (H-F8): the gateway reads only its schema and a mounted keys file
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=6 \
    CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["gateway"]
