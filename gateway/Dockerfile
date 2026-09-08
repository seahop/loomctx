# Build context is the REPO ROOT (see docker-compose.yml) so the image can
# carry contracts/schemas.json — the language-neutral contract the gateway
# validates against. `go vet` + `go test` run as part of every build.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY gateway/go.mod gateway/go.sum ./
RUN go mod download
COPY gateway/ ./
COPY contracts /contracts
# tests read ../contracts/schemas.json, i.e. /contracts/schemas.json here
RUN go vet ./... && go test ./...
RUN CGO_ENABLED=0 go build -trimpath -o /gateway .

FROM alpine:3.20
COPY --from=build /gateway /usr/local/bin/gateway
COPY contracts/schemas.json /etc/loom/schemas.json
# non-root (H-F8): the gateway reads only its schema and a mounted keys file
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=6 \
    CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["gateway"]
