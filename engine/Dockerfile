# ── build ────────────────────────────────────────────────────────────────────
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/socblitz-engine .

# ── runtime (static binary on a minimal base) ─────────────────────────────────
FROM alpine:3.20
RUN adduser -D -u 10001 engine
WORKDIR /app
COPY --from=build /out/socblitz-engine /usr/local/bin/socblitz-engine
COPY rules /app/rules
COPY sigma /app/sigma
COPY decoders /app/decoders
COPY parsers /app/parsers
COPY yaral /app/yaral
COPY feeds /app/feeds
USER engine
# ingest API + syslog (UDP/TCP)
EXPOSE 8090 514/udp 514/tcp
ENTRYPOINT ["/usr/local/bin/socblitz-engine"]
