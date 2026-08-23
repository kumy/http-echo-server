# ---- Build stage -----------------------------------------------------------
FROM golang:1.27-alpine AS build

WORKDIR /src

# Cache dependencies before copying the full source tree
COPY go.mod go.su[m] ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w \
      -X github.com/kumy/https-echo-server/internal/version.Version=${VERSION} \
      -X github.com/kumy/https-echo-server/internal/version.Commit=${COMMIT} \
      -X github.com/kumy/https-echo-server/internal/version.Date=${DATE}" \
    -o /out/https-echo-server ./cmd/https-echo-server

# ---- Runtime stage ---------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="https-echo-server" \
      org.opencontainers.image.description="Echo HTTP/HTTPS request properties back to the client, with HTTP/2 and on-the-fly TLS" \
      org.opencontainers.image.source="https://github.com/kumy/https-echo-server" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /out/https-echo-server /usr/local/bin/https-echo-server

# Auto TLS mode persists its root CA here; mount a volume to keep/reuse it
VOLUME ["/certs"]
ENV TLS_CA_CERT_FILE=/certs/ca.crt \
    TLS_CA_KEY_FILE=/certs/ca.key

EXPOSE 8080 8443

USER nonroot

ENTRYPOINT ["/usr/local/bin/https-echo-server"]
