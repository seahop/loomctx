# Build context is the REPO ROOT (see docker-compose.yml) so the image can
# carry contracts/schemas.json — the language-neutral contract the gateway
# validates against. `go vet`, `govulncheck` and `go test` run as part of
# every build. Base images are pinned by digest (Dependabot bumps them).
FROM golang:1.27-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build
WORKDIR /src
COPY gateway/go.mod gateway/go.sum ./
RUN go mod download
COPY gateway/ ./
COPY contracts /contracts
# tests read ../contracts/schemas.json, i.e. /contracts/schemas.json here
RUN go vet ./... && go test ./...
# known-vulnerable code paths in the module graph fail the build (the
# publish job additionally scans the finished image with Trivy). The tool is
# pinned (not @latest) so a build is reproducible; Dependabot cannot see a
# `go run pkg@version`, so bump it by hand — the vuln DATABASE it queries is
# always current regardless.
ARG GOVULNCHECK_VERSION=v1.8.0
RUN go run golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION} ./...
RUN CGO_ENABLED=0 go build -trimpath -o /gateway .

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
COPY --from=build /gateway /usr/local/bin/gateway
COPY contracts/schemas.json /etc/loomctx/schemas.json
# non-root (H-F8): the gateway reads only its schema and a mounted keys file
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=6 \
    CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["gateway"]
