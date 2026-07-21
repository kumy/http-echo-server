# https-echo-server

[![CI](https://github.com/kumy/https-echo-server/actions/workflows/ci.yml/badge.svg)](https://github.com/kumy/https-echo-server/actions/workflows/ci.yml)
[![Release](https://github.com/kumy/https-echo-server/actions/workflows/release.yml/badge.svg)](https://github.com/kumy/https-echo-server/actions/workflows/release.yml)
[![Docs](https://github.com/kumy/https-echo-server/actions/workflows/docs.yml/badge.svg)](https://kumy.github.io/https-echo-server/)
[![Go Report Card](https://goreportcard.com/badge/github.com/kumy/https-echo-server)](https://goreportcard.com/report/github.com/kumy/https-echo-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A small Go daemon that echoes HTTP request properties back to the client — in the
response body and in the logs. Useful for debugging proxies, load balancers,
ingress controllers, TLS setups, and anything else that sits between a client
and a server.

Inspired by [mendhak/docker-http-https-echo](https://github.com/mendhak/docker-http-https-echo),
rewritten in Go with first-class **HTTP/2** and flexible **TLS** (bring your own
certs, an automatic on-the-fly CA, or [HashiCorp Vault](https://www.vaultproject.io/) as PKI).

📚 **Full documentation: <https://kumy.github.io/https-echo-server/>**
📋 **Functional specification: [docs/specification.md](docs/specification.md)**
🆚 **Everything added on top of mendhak's original: [docs/comparison.md](docs/comparison.md)**

## Features

- Echo request properties as structured JSON: method, path, query, headers,
  body, cookies, client IP(s), TLS/connection details
- **HTTP and HTTPS** listeners (`8080` / `8443` by default)
- **HTTP/2** everywhere: `h2` over TLS (ALPN) and `h2c` on the plaintext listener
- **Three TLS modes** (`TLS_MODE`):
  - `static` — pass your own certificate/key pair
  - `auto` *(default)* — auto-generate a root CA (printed and saved so you can
    feed it to `curl --cacert` or import it in a browser), then mint server
    certificates **on the fly matching the requested SNI**
  - `vault` — same on-the-fly SNI behaviour, but certificates are issued by a
    Vault PKI secrets engine (`VAULT_ADDR`, `VAULT_TOKEN`, mount & role)
- mTLS echo: request a client certificate and echo its details (no validation)
- Forward requests to a remote server (`FORWARD_URL`) and relay its responses
  back, dumping both directions — insert the daemon between two components to
  see exactly what they exchange
- `curl -v`-style verbose wire dump of every exchange (`VERBOSE=true`)
- Decode JWTs from a configurable header and include the decoded token
- JSON request bodies parsed and echoed as structured JSON
- Response shaping per request: custom status code, content type, artificial delay
- `response_body_only` mode, response body override from file, disable echo entirely
- CORS support, signed-cookie verification, trusted proxy configuration
- Prometheus metrics endpoint (optional)
- WebSocket echo (`ws://` and `wss://`)
- Structured logging with [zap](https://github.com/uber-go/zap), request logs,
  path-based log filtering
- Configuration via flags, environment variables, or config file with
  [viper](https://github.com/spf13/viper) — env names are compatible with
  `mendhak/http-https-echo` where applicable
- Distroless multi-arch Docker image, runs as non-root

## Quick start

### Docker

```shell
docker run -p 8080:8080 -p 8443:8443 --rm -t ghcr.io/kumy/https-echo-server
```

Issue a request:

```shell
curl -k -X PUT -H "Arbitrary:Header" -d aaa=bbb https://localhost:8443/hello-world
```

```json
{
  "path": "/hello-world",
  "method": "PUT",
  "protocol": "https",
  "httpVersion": "2.0",
  "hostname": "localhost",
  "ip": "172.17.0.1",
  "headers": {
    "Arbitrary": "Header",
    "Content-Type": "application/x-www-form-urlencoded"
  },
  "body": "aaa=bbb",
  "connection": {
    "servername": "localhost",
    "alpn": "h2",
    "tlsVersion": "TLS1.3"
  },
  "os": { "hostname": "5788ef8a2074" }
}
```

The same output appears in the container logs.

### Trust the auto-generated CA (no more `-k`)

In the default `auto` TLS mode the server prints its root CA at startup and
saves it to `certs/ca.crt`. Any server name you request is signed on the fly:

```shell
docker run -p 8443:8443 -v $PWD/certs:/certs --rm -t ghcr.io/kumy/https-echo-server
curl --cacert certs/ca.crt --resolve foo.example.com:8443:127.0.0.1 \
  https://foo.example.com:8443/
```

The certificate presented is minted for `foo.example.com` at handshake time.
You can also fetch the CA over plain HTTP from `http://localhost:8080/ca`.

### Binary

Download a release from the
[releases page](https://github.com/kumy/https-echo-server/releases), or build
from source:

```shell
make build
./bin/https-echo-server
```

## Configuration overview

Everything is configurable through CLI flags, environment variables, or a
config file (`--config config.yaml`); precedence is **flags > env > file >
defaults**. See the
[configuration reference](https://kumy.github.io/https-echo-server/configuration/)
for the full list. Highlights:

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `HTTP_PORT` / `HTTPS_PORT` | `8080` / `8443` | Listener ports |
| `HTTP2_ENABLED` / `HTTP2_H2C_ENABLED` | `true` / `true` | HTTP/2 via ALPN, h2c on the plaintext port |
| `TLS_MODE` | `auto` | `static`, `auto`, or `vault` |
| `HTTPS_CERT_FILE` / `HTTPS_KEY_FILE` | — | Your cert/key pair (`static` mode) |
| `TLS_CA_CERT_FILE` / `TLS_CA_KEY_FILE` | `certs/ca.crt` / `certs/ca.key` | Where the auto CA is persisted (`auto` mode) |
| `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_PKI_MOUNT`, `VAULT_PKI_ROLE` | — | Vault PKI issuance (`vault` mode) |
| `MTLS_ENABLE` | `false` | Request & echo client certificates |
| `JWT_HEADER` | — | Header to decode as JWT |
| `ECHO_BACK_TO_CLIENT` | `true` | Set `false` to echo only to logs |
| `ECHO_INCLUDE_ENV_VARS` | `false` | Include environment variables in echo |
| `OVERRIDE_RESPONSE_BODY_FILE_PATH` | — | Serve a file as the response body |
| `MAX_HEADER_SIZE` | `1048576` | Max request header size (bytes) |
| `FORWARD_URL` | — | Forward requests to this base URL, dumping the remote responses before relaying them |
| `VERBOSE` | `false` | `curl -v`-style dump of every exchange on stdout |
| `COOKIE_SECRET` | — | Verify signed cookies |
| `CORS_ALLOW_ORIGIN` (+ `_METHODS`, `_HEADERS`, `_CREDENTIALS`) | — | CORS behaviour |
| `ADDITIONAL_TRUSTED_PROXIES` | — | Extra proxies trusted for `X-Forwarded-*` |
| `LOG_LEVEL` / `LOG_FORMAT` | `info` / `json` | zap logging |
| `DISABLE_REQUEST_LOGS` | `false` | Suppress per-request log lines |
| `LOG_IGNORE_PATH` | — | Regex of paths to skip in request logs |
| `PROMETHEUS_ENABLED` | `false` | Expose `/metrics` |

### Per-request response shaping

Send these as request headers **or** query parameters:

| Name | Effect |
| --- | --- |
| `x-set-response-status-code` | Respond with the given HTTP status code |
| `x-set-response-content-type` | Override the response `Content-Type` |
| `x-set-response-delay-ms` | Delay the response by N milliseconds |
| `response_body_only=true` (query only) | Return just the request body |

```shell
curl https://localhost:8443/tea?x-set-response-status-code=418 -k -i
```

## TLS modes in one minute

```shell
# 1. static — bring your own pair
TLS_MODE=static HTTPS_CERT_FILE=./fullchain.pem HTTPS_KEY_FILE=./privkey.pem https-echo-server

# 2. auto (default) — root CA generated, printed, saved; leaf certs minted per SNI
https-echo-server

# 3. vault — leaf certs issued by a Vault PKI role per SNI
TLS_MODE=vault VAULT_ADDR=https://vault:8200 VAULT_TOKEN=... \
  VAULT_PKI_MOUNT=pki_int VAULT_PKI_ROLE=echo https-echo-server
```

Details, browser-import instructions, and the Vault policy you need are in the
[TLS guide](https://kumy.github.io/https-echo-server/tls/).

## Development

```shell
make help          # list all targets
make build         # build ./bin/https-echo-server
make test          # go test -race with coverage
make lint          # golangci-lint
make docker-build  # multi-stage docker image
make docs-serve    # live-preview the documentation (zensical)
make snapshot      # goreleaser snapshot build
```

Releases are fully automated: [Conventional Commits](https://www.conventionalcommits.org/)
drive [semantic-release](https://semantic-release.gitbook.io/), which tags and
publishes; [GoReleaser](https://goreleaser.com/) attaches binaries and pushes
multi-arch images to GHCR. Docs are built with
[zensical](https://zensical.org/) and deployed to GitHub Pages on every push to
`main`. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE) — © 2026 Mathieu A. (kumy).

Behavioural design borrowed with gratitude from
[mendhak/docker-http-https-echo](https://github.com/mendhak/docker-http-https-echo) (MIT).
