# Functional specification

This document is the contract for the implementation. Behavioural changes
require a spec update in the same PR.

## 1. Goals

- A single static Go binary that echoes HTTP request properties to the client
  and to structured logs, for debugging intermediaries (proxies, LBs,
  ingresses, service meshes, TLS termination).
- Environment-variable compatibility with
  [mendhak/http-https-echo](https://github.com/mendhak/docker-http-https-echo)
  wherever the equivalent feature exists, so it can be swapped in.
- First-class HTTP/2 (`h2` + `h2c`) and flexible TLS issuance (static pair,
  local auto CA with per-SNI minting, Vault PKI with per-SNI issuance).
- Optional **forwarding**: relay requests to a remote server and relay its
  responses back, capturing and dumping both legs of the exchange, so the
  daemon can be inserted between two components to observe their traffic.
- Optional **verbose wire dump** of every exchange in a `curl -v`-style
  format.

### Non-goals

- Not a production reverse proxy, API gateway, or mock-server DSL —
  forwarding is a diagnostic aid, not a traffic-serving feature.
- No certificate *validation* features (mTLS is echo-only).
- No TLS termination for other services.

## 2. Technology choices

| Concern | Choice |
| --- | --- |
| Language | Go ≥ 1.25, `CGO_ENABLED=0` |
| Config | [spf13/viper](https://github.com/spf13/viper) + [spf13/pflag](https://github.com/spf13/pflag) |
| Logging | [uber-go/zap](https://github.com/uber-go/zap) |
| HTTP/2 | stdlib `net/http` + `golang.org/x/net/http2` (`h2c` handler) |
| Metrics | `prometheus/client_golang` |
| WebSocket | `coder/websocket` (pure Go, maintained) |
| Vault | plain `net/http` client against the Vault HTTP API (no SDK dependency) |
| JWT decode | manual base64url decode of header/payload (no verification, no dependency) |
| Forwarding | stdlib `net/http` client with a dedicated transport |
| CLI UX | plain pflag; no cobra subcommands needed (single daemon + `--version`) |

## 3. Package layout

```
cmd/http-echo-server/      main: wire config → logger → servers, signal handling
internal/version/          Version/Commit/Date vars injected via ldflags
internal/config/           viper loading, validation, defaults; Config struct
internal/logging/          zap construction from config
internal/server/           listener setup (HTTP + HTTPS), h2c wrapping, routing,
                           response shaping, CORS, request logging, WebSocket echo
internal/echo/             request capture → echo.Response struct → JSON render
internal/forward/          forwarding client: request relay, response capture
internal/verbose/          curl -v-style exchange printer
internal/tlsmgr/           tls.Config assembly, GetCertificate dispatch by mode
internal/tlsmgr/autoca/    CA create/load/persist, leaf minting, LRU cache
internal/tlsmgr/vaultpki/  Vault issue client, CA chain fetch, TTL-aware cache
internal/metrics/          Prometheus registry/collectors
```

`internal/` everywhere — no public Go API commitment.

## 4. Configuration

- Precedence: **flags > env > config file > defaults**.
- Env names bind directly (no prefix), matching the tables in
  [Configuration](configuration.md); flag names are the kebab-case versions.
- `--config <path>` loads YAML/TOML/JSON; keys equal flag names.
- Validation happens once at startup; invalid config → log at `error` + exit
  code `2`.
  - `TLS_MODE=static` requires `HTTPS_CERT_FILE` + `HTTPS_KEY_FILE`.
  - `TLS_MODE=vault` requires `VAULT_ADDR`, `VAULT_TOKEN`, `VAULT_PKI_ROLE`.
  - At least one of `HTTP_ENABLED` / `HTTPS_ENABLED` must be true.
  - `FORWARD_URL`, when set, must be an absolute `http://` or `https://` URL.
- `--version` prints `version commit date` and exits `0`.

## 5. Listeners & HTTP/2

- Plaintext listener on `BIND_ADDRESS:HTTP_PORT` (default `:8080`):
  - HTTP/1.1 always.
  - `HTTP2_H2C_ENABLED=true`: wrap the handler with
    `h2c.NewHandler` so both prior-knowledge HTTP/2 and `Upgrade: h2c` work.
- TLS listener on `BIND_ADDRESS:HTTPS_PORT` (default `:8443`):
  - `HTTP2_ENABLED=true`: ALPN offers `h2, http/1.1`; otherwise `http/1.1`.
  - Min TLS version 1.2.
- Port `0` is allowed on either listener: an ephemeral port is chosen by the
  OS and the effective address is logged at startup (useful for embedding in
  tests).
- `MAX_HEADER_SIZE` maps to `http.Server.MaxHeaderBytes` on both.
- Graceful shutdown: on SIGINT/SIGTERM, stop accepting, drain for
  `SHUTDOWN_TIMEOUT` (default 10s), then exit `0` (or `1` on forced close).
- Startup failures (port busy, bad cert) → error log + exit `1`.

## 6. Echo semantics

### 6.1 Response object

Rendered as pretty-printed JSON (2-space indent), `Content-Type:
application/json; charset=utf-8`, status `200` unless shaped. Field-by-field:

| Field | Type | Source / notes |
| --- | --- | --- |
| `path` | string | URL path without query |
| `query` | object | Decoded query params; repeated keys → array of strings |
| `method` | string | Request method |
| `protocol` | string | `http` or `https` (actual listener, not XFP) |
| `httpVersion` | string | `1.0`, `1.1`, `2.0` |
| `host` | string | `Host` header / `:authority` |
| `hostname` | string | `host` without port |
| `ip` | string | Client IP after trusted-proxy resolution |
| `ips` | array | Full `X-Forwarded-For` chain when behind trusted proxies |
| `headers` | object | Names in canonical HTTP case (see §6.6); repeated → array |
| `cookies` | object | Parsed `Cookie` header |
| `signedCookies` | object | Only with `COOKIE_SECRET`; cookies whose HMAC-SHA256 signature (`s:<value>.<sig>` format, mendhak/Express-compatible) verifies |
| `body` | string | Raw body, capped at 1 MiB by default (`MAX_BODY_SIZE`, bytes); truncation flagged in `bodyTruncated: true` |
| `json` | any | Parsed body when `Content-Type` is `application/json` and parsing succeeds |
| `jwt` | object | `{header, payload}` decoded (not verified) from `JWT_HEADER` |
| `clientCertificate` | object | Subject, issuer, serial, validity, SANs, SHA-256 fingerprint |
| `connection` | object | `servername` (SNI), `alpn`, `tlsVersion`, `cipher` — TLS listener only |
| `os` | object | `{hostname}` of the server machine/container |
| `env` | object | Process env, only with `ECHO_INCLUDE_ENV_VARS=true` |

Empty/inapplicable fields are omitted (`omitempty` semantics).

### 6.2 Trusted proxies

Loopback, link-local, and RFC1918 ranges are always trusted;
`ADDITIONAL_TRUSTED_PROXIES` (comma-separated IPs/CIDRs) extends the set.
`ip` is the first untrusted address walking `X-Forwarded-For` right-to-left.
When the peer is untrusted (or no `X-Forwarded-For` is present), the socket
peer address is used; when every chain entry is trusted, the leftmost entry
is used (Express/mendhak behaviour).

### 6.3 Response shaping

Header **or** query parameter, header wins on conflict:

- `x-set-response-status-code` — int 100–599, else ignored + warn log.
- `x-set-response-content-type` — verbatim into `Content-Type`.
- `x-set-response-delay-ms` — non-negative int, capped at 120000 (2 min);
  the delay must not block other requests (sleep in handler goroutine) and
  must abort early if the client disconnects. Aborted requests are logged
  and counted with status `499` (client closed request).
- `response_body_only=true` — query param only (not honoured as a header,
  matching mendhak): respond with the raw request body, capped at
  `MAX_BODY_SIZE` like the echoed `body` field (status/content-type shaping
  still applies).
- Shaping parameters are always visible in the echoed `headers`/`query`.
- Shaping is ignored in forwarding mode (§7): the remote response is
  authoritative.

Precedence for the body: `ECHO_BACK_TO_CLIENT=false` (empty) >
`OVERRIDE_RESPONSE_BODY_FILE_PATH` (file content, read per request) >
`response_body_only` (raw body) > full JSON echo.

### 6.4 Reserved paths

Handled before echo and before forwarding, in this order:

1. `PROMETHEUS_METRICS_PATH` (only if `PROMETHEUS_ENABLED`) → metrics.
2. `TLS_CA_ENDPOINT` (only in `auto`/`vault` mode with the TLS listener
   enabled, non-empty) → CA PEM, `Content-Type: application/x-pem-file`.
   Served on **both** listeners; with `HTTPS_ENABLED=false` no CA exists and
   the path echoes like any other.

### 6.5 WebSocket echo

If `WS_ENABLED=true` and the request is a WebSocket upgrade, upgrade instead
of echoing. First message from server: the JSON echo of the upgrade request.
Then every client message (text/binary) is echoed back unchanged, with no
message-size limit. Close is mirrored. Works on both listeners (`ws://`, `wss://`), any path. WebSocket
upgrades are handled locally even in forwarding mode (§7) — WebSocket traffic
is never forwarded.

### 6.6 Header case

Header names are always echoed (and dumped, logged, and forwarded) in their
canonical HTTP form — e.g. `Content-Type`, `X-Arbitrary-Header` — never
lower-cased. HTTP/2 transmits header names lower-cased on the wire (RFC 9113
§8.2); they are canonicalized to the same form, so output is identical across
HTTP versions. There is no configuration option for this behaviour.

## 7. Forwarding

Setting `FORWARD_URL` switches the daemon into forwarding mode: instead of
answering with the JSON echo, it relays each request to the remote server and
relays the remote response back to the original client — while capturing and
dumping both request and response. This lets the daemon sit between two
components and expose the exact messages they exchange.

### 7.1 Request relay

- Target URL: scheme, host, and base path of `FORWARD_URL`, joined with the
  incoming request's path and query.
- Method and body are relayed unchanged. The request body is fully buffered
  (no size limit) so it can be dumped and relayed byte-for-byte; the echoed
  `body` field and verbose dumps still truncate at `MAX_BODY_SIZE`.
- Headers are relayed in canonical case (§6.6), except hop-by-hop headers
  (`Connection` and headers it names, `Keep-Alive`, `Proxy-Authenticate`,
  `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`).
- `Host` is rewritten to the target's host; `FORWARD_PRESERVE_HOST=true`
  keeps the client's original `Host` instead.
- Standard proxy headers are added: the direct peer's IP is appended to the
  (fully preserved) `X-Forwarded-For` chain; `X-Forwarded-Proto` is set to
  the original scheme and `X-Forwarded-Host` to the original `Host` (both
  only if not already present).
- Transport: HTTP/1.1 to `http://` targets, ALPN (`h2` or `http/1.1`) to
  `https://` targets; system trust store, or none with
  `FORWARD_SKIP_VERIFY=true`. Transparent response decompression is
  disabled so bodies pass through byte-for-byte.

### 7.2 Response relay

- The remote response is **fully read and dumped first** — status, headers,
  and body go into the request log (§10) and the verbose output (§8) — then
  relayed to the original client unchanged: same status code, same headers
  (minus hop-by-hop), same body.
- Remote failure (connection error, TLS error, timeout after
  `FORWARD_TIMEOUT`, default 30s) → `502 Bad Gateway` with a JSON error body
  `{"error": <message>, "target": <url>}` and an error log.

### 7.3 Interaction with other features

- The request is still captured and logged as a full echo object (§6.1).
- Reserved paths (§6.4) are served locally, never forwarded.
- WebSocket upgrades are handled locally (§6.5), never forwarded.
- Response shaping (§6.3) and echo body options (`ECHO_BACK_TO_CLIENT`,
  `OVERRIDE_RESPONSE_BODY_FILE_PATH`, `response_body_only`) do not apply.
- CORS handling (`CORS_ALLOW_*`) does not apply; the remote's CORS headers
  pass through untouched.

## 8. Verbose exchange dump

`VERBOSE=true` prints every exchange to stdout in a `curl -v`-style trace,
independent of `LOG_FORMAT`/`LOG_LEVEL` (like `TLS_CA_PRINT`, the output is
meant to be read and copy-pasted by a human):

- `* ` — informational lines: request sequence number, peer address,
  listener protocol, HTTP version, TLS details, forwarding target, response
  status and duration.
- `> ` — the incoming request: request line, one line per header, a bare
  `>` separator, then the request body (if any).
- `>> ` / `<< ` — in forwarding mode, the upstream leg: the relayed request
  and the remote response, in the same shape.
- `< ` — the response sent to the original client: status line, headers,
  separator, body.

Rules:

- Each exchange is printed as one atomic block (concurrent requests do not
  interleave).
- Bodies are truncated at `MAX_BODY_SIZE` with a trailing
  `* [body truncated]` marker.
- Header names appear in canonical case (§6.6); headers are sorted by name
  for deterministic output.
- Reserved paths (§6.4) are not dumped.
- WebSocket upgrades print the request leg and an informational
  `* WebSocket upgrade` line instead of a response block.

## 9. TLS subsystem

`internal/tlsmgr` produces a `*tls.Config`; only `GetCertificate` differs per
mode.

### 9.1 Common

- `MinVersion: TLS1.2`. ALPN per §5.
- `MTLS_ENABLE=true` → `ClientAuth: tls.RequestClientCert` (request, never
  verify).

### 9.2 `static`

`tls.LoadX509KeyPair` at startup; fatal on error; served for every SNI.

### 9.3 `auto`

- CA: load `TLS_CA_CERT_FILE`/`TLS_CA_KEY_FILE` if both exist and parse;
  otherwise generate ECDSA P-256, CN `http-echo-server Root CA`,
  `IsCA`, validity 10 years, and persist (cert `0644`, key `0600`,
  directories created as needed). Persist failure → warn, continue in-memory.
- Startup: print CA PEM to stdout if `TLS_CA_PRINT` (independent of log
  format/level, so it is copy-pasteable).
- Handshake: keyed by SNI (empty SNI → key `""`):
  - cache hit and cert valid > 5 min → serve;
  - miss → mint ECDSA P-256 leaf, validity `TLS_CERT_TTL`, `NotBefore` 5 min
    in the past; SANs: the SNI DNS name, or (no SNI) `localhost`, host
    hostname, `127.0.0.1`, `::1`. Wildcard SNI is used verbatim as SAN.
  - LRU cache, `TLS_CERT_CACHE_SIZE` entries; minting is single-flight per
    key (concurrent handshakes for one SNI trigger one mint).

### 9.4 `vault`

- Issue: `POST /v1/{VAULT_PKI_MOUNT}/issue/{VAULT_PKI_ROLE}` with
  `{"common_name": <sni>, "ttl": VAULT_PKI_TTL}`; no-SNI fallback uses the
  host's hostname as CN plus IP SANs as in `auto`.
- Response `certificate` + `ca_chain` + `private_key` → `tls.Certificate`
  (chain appended).
- Cache: same LRU + single-flight; entry refreshed when 2/3 of the issued
  cert's actual lifetime has elapsed; on refresh failure serve the stale cert
  until its real `NotAfter`, logging at `warn`.
- Vault client: `VAULT_ADDR`, `VAULT_TOKEN`, optional `VAULT_NAMESPACE`
  (header `X-Vault-Namespace`), `VAULT_CACERT`, `VAULT_SKIP_VERIFY`;
  5 s request timeout. Issuance failure with empty cache → handshake error
  (logged with SNI + Vault error).
- Startup: fetch `GET /v1/{mount}/ca_chain` for printing/`/ca` endpoint;
  failure is a warning, not fatal.
- Token renewal is **out of scope** (v1): provide a token with adequate TTL.

## 10. Logging

- zap; `LOG_FORMAT=json` → production encoder, `console` → console encoder
  with colors; `LOG_LEVEL` maps to zap levels.
- Per-request log (level `info`): message `request`, fields: the full echo
  object (§6.1) under `request`, plus `status`, `durationMs`.
- In forwarding mode the same log line additionally carries a `forward`
  object: `url`, `status`, `headers`, `body` (truncated at `MAX_BODY_SIZE`,
  with `bodyTruncated: true` when it was) of the remote response, or `error`
  when the relay failed.
- Suppression: `DISABLE_REQUEST_LOGS=true`, or path matches any
  `LOG_IGNORE_PATH` regex (comma-separated list; invalid regex → fatal at
  startup with exit code `2`).
- Reserved paths (metrics, CA) are logged at `debug` only.

## 11. Metrics

- Namespace `http_echo`. Collectors: default Go/process +
  `http_echo_requests_total{method,status[,path]}` and
  `http_echo_request_duration_seconds{...}` as summary or histogram
  (`PROMETHEUS_METRIC_TYPE`).
- Label sets controlled by `PROMETHEUS_WITH_METHOD/STATUS/PATH` (path off by
  default — cardinality).

## 12. Exit codes & signals

| Code | Meaning |
| --- | --- |
| `0` | Clean shutdown (signal, drained) or `--version` |
| `1` | Runtime failure (listener bind, cert load, forced shutdown) |
| `2` | Invalid configuration |

SIGINT/SIGTERM → graceful shutdown (§5). SIGHUP is ignored in v1 (no config
reload).

## 13. Security considerations

- The daemon intentionally reflects everything, including secrets present in
  headers (`Authorization`, cookies). **Never expose it publicly** with
  sensitive traffic; docs must state this.
- Forwarding relays traffic only to the operator-configured `FORWARD_URL` —
  the target is never taken from the request. Dumped exchanges (logs,
  verbose output) contain both legs in full, including credentials; treat
  the output accordingly.
- `ECHO_INCLUDE_ENV_VARS` can leak container secrets — off by default.
- Auto-CA private key file is written `0600`; the docs warn against trusting
  the CA outside test machines.
- `VAULT_TOKEN` is redacted from any log output and never echoed (env echo
  filters `VAULT_TOKEN`, `COOKIE_SECRET` values, replaced by `***`).
- Body size capped (`MAX_BODY_SIZE`, default 1 MiB) to bound memory in echo
  mode; header size capped by `MAX_HEADER_SIZE`. In forwarding mode bodies
  are fully buffered by design (diagnostic tool); do not front high-volume
  production traffic with it.
- Delay shaping capped at 2 min to limit trivial connection-exhaustion.

## 14. Testing requirements

- Unit tests: config precedence & validation, echo field derivation
  (trusted proxies, canonical header case, JWT, signed cookies), response
  shaping, forwarding (relay semantics, header rewriting, dump content,
  error mapping) against httptest backends, verbose formatting, auto-CA
  mint/reload/cache, Vault client against a mocked HTTP server.
- Integration tests (httptest + real listeners on `:0`): h2/h2c negotiation,
  SNI → certificate CN assertions for `auto` mode, mTLS echo, WebSocket echo,
  graceful shutdown.
- Race detector on in CI; coverage uploaded as artifact.
