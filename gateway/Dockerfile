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
# The binary statically links its dependencies and the Go runtime, whose
# licenses ask for their notices to travel with it: copy the license files
# of every module linked in (not test-only ones); a module without one fails
# the build.
RUN mkdir -p /licenses/go && cp "$(go env GOROOT)/LICENSE" /licenses/go/ \
 && go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}}@{{.Version}} {{.Dir}}{{end}}{{end}}' . \
    | sort -u | while read -r mod dir; do \
        mkdir -p "/licenses/$mod"; \
        for f in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE*; do \
          [ -f "$f" ] && cp "$f" "/licenses/$mod/"; \
        done; \
        [ -n "$(ls -A "/licenses/$mod")" ] || { echo "no license file for $mod" >&2; exit 1; }; \
      done

FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8
LABEL org.opencontainers.image.source="https://github.com/seahop/loomctx" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /gateway /usr/local/bin/gateway
COPY LICENSE NOTICE /usr/share/licenses/loomctx/
COPY --from=build /licenses /usr/share/licenses/third-party
COPY contracts/schemas.json /etc/loomctx/schemas.json
# non-root (H-F8): the gateway reads only its schema and a mounted keys file
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=6 \
    CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["gateway"]
