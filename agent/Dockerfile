# ── build ────────────────────────────────────────────────────────────────────
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/socblitz-agent .

# ── runtime ──────────────────────────────────────────────────────────────────
FROM alpine:3.20
# util-linux gives journalctl-less hosts a shell; apk lets inventory enumerate pkgs
RUN apk add --no-cache ca-certificates
COPY --from=build /out/socblitz-agent /usr/local/bin/socblitz-agent
ENTRYPOINT ["/usr/local/bin/socblitz-agent"]
