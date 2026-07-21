# Compared to mendhak/http-https-echo

`https-echo-server` started as a Go rewrite of
[mendhak/docker-http-https-echo](https://github.com/mendhak/docker-http-https-echo)
(Node/Express). Environment variable names were kept compatible wherever the
same feature exists in both projects, so it can act as a drop-in replacement
— but a lot has been added on top. This page is an inventory of what's new.

## New capabilities

### HTTP/2

`h2` is negotiated via ALPN on the TLS listener, and cleartext `h2c` (both
prior-knowledge and `Upgrade:`) is accepted on the plaintext listener.
mendhak's image is HTTP/1.1 only. See [Listeners &
HTTP/2](getting-started.md).

- `HTTP2_ENABLED`, `HTTP2_H2C_ENABLED`

### Two extra TLS modes: on-the-fly CA and Vault PKI

mendhak only supports one mode: a static certificate/key pair served
identically for every connection, regardless of SNI. `https-echo-server` adds
two more, selected with `TLS_MODE`:

- **`auto`** *(default)* — generates a local root CA once (or loads one you
  already placed at `TLS_CA_CERT_FILE`/`TLS_CA_KEY_FILE`), then **mints a
  leaf certificate matching the client's SNI at handshake time**, cached in
  memory. Useful for testing many hostnames against one instance without
  juggling certificate files.
- **`vault`** — same per-SNI behaviour, but leaf certificates are issued on
  demand by a HashiCorp Vault PKI secrets engine, with automatic re-issuance
  and stale-serving on transient Vault failures.

Both new modes also serve their CA chain on a plaintext download endpoint
(`TLS_CA_ENDPOINT`, default `/ca`) and print it at startup (`TLS_CA_PRINT`),
so `curl --cacert` / browser import needs no manual certificate handling.
See the [TLS guide](tls.md).

- `TLS_MODE`, `TLS_CA_CERT_FILE`, `TLS_CA_KEY_FILE`, `TLS_CA_PRINT`,
  `TLS_CA_ENDPOINT`, `TLS_CERT_TTL`, `TLS_CERT_CACHE_SIZE`, `VAULT_ADDR`,
  `VAULT_TOKEN`, `VAULT_NAMESPACE`, `VAULT_PKI_MOUNT`, `VAULT_PKI_ROLE`,
  `VAULT_PKI_TTL`, `VAULT_CACERT`, `VAULT_SKIP_VERIFY`

### Forwarding to a remote server, with both legs dumped

`FORWARD_URL` turns the daemon into a relay: it forwards each request to a
remote server, fully captures the remote response, logs both legs, and
relays the response back to the original client unchanged. Nothing like this
exists in mendhak — it's for dropping the daemon **between** two real
components to see exactly what they send each other. See [Usage →
Forwarding](usage.md#forwarding-to-a-remote-server).

- `FORWARD_URL`, `FORWARD_PRESERVE_HOST`, `FORWARD_TIMEOUT`,
  `FORWARD_SKIP_VERIFY`

### `curl -v`-style verbose wire dump

`VERBOSE=true` prints an atomic, human-readable trace of every exchange to
stdout — request and response, and both legs when forwarding — instead of
(or alongside) the structured JSON echo. See [Usage → Verbose wire
dump](usage.md#verbose-wire-dump).

- `VERBOSE`

### WebSocket echo

`ws://` and `wss://` upgrades are accepted on both listeners: the first
server message is the JSON echo of the upgrade request, then every
subsequent message is mirrored back unchanged, with no message-size limit.
mendhak has no WebSocket support.

- `WS_ENABLED`

### Structured, leveled logging

Logs are structured (JSON or human-friendly console) via
[zap](https://github.com/uber-go/zap), with a configurable level
(`debug`/`info`/`warn`/`error`) and rich per-request/per-subsystem fields.
mendhak only offers a boolean `DISABLE_REQUEST_LOGS` toggle and
`LOG_WITHOUT_NEWLINE` on top of Express's fixed log-line format.

- `LOG_LEVEL`, `LOG_FORMAT`

### Configuration via CLI flags or a config file, not just env vars

Every option can be set as a `--kebab-case` flag, an environment variable, or
a key in a YAML/TOML/JSON config file (`--config config.yaml`), with
precedence **flags > env > file > defaults**. mendhak's image is configured
through environment variables only.

- `--config` / `CONFIG`

### Operational conveniences

- **Graceful shutdown** with a configurable drain window (`SHUTDOWN_TIMEOUT`)
  instead of an immediate stop.
- **Independent listener toggles** (`HTTP_ENABLED`, `HTTPS_ENABLED`) and a
  configurable **bind address** (`BIND_ADDRESS`), rather than always binding
  both ports on all interfaces.
- **Single static binary** (`CGO_ENABLED=0`), with multi-arch (amd64/arm64)
  release binaries in addition to the distroless Docker image — no Node.js
  runtime required.

## Behavioural differences (not regressions)

### Header case is always preserved

mendhak lower-cases response headers by default and requires
`PRESERVE_HEADER_CASE=true` to keep the original case. `https-echo-server`
always echoes headers in canonical HTTP case — there is no option, and
none is needed.

### No `LOG_WITHOUT_NEWLINE`

mendhak's Express logger could embed literal newlines in a log line, hence
the flag to strip them. zap's JSON and console encoders never emit embedded
newlines, so there's nothing to disable.

## Feature parity

These behave the same way and use the same environment variable names as
mendhak, so existing deployments migrate without changes:

| Feature | Env var(s) |
| --- | --- |
| Choose listener ports | `HTTP_PORT`, `HTTPS_PORT` |
| Bring your own certificate/key pair | `HTTPS_CERT_FILE`, `HTTPS_KEY_FILE` |
| Trusted proxy IPs/CIDRs for `X-Forwarded-*` | `ADDITIONAL_TRUSTED_PROXIES` |
| JWT header decoding | `JWT_HEADER` |
| Suppress per-request log lines | `DISABLE_REQUEST_LOGS` |
| Skip logging matching paths | `LOG_IGNORE_PATH` |
| JSON request body parsing/echo | *(automatic)* |
| Echo only to logs, empty response | `ECHO_BACK_TO_CLIENT` |
| Custom response status code | `x-set-response-status-code` (header or query) |
| Custom response `Content-Type` | `x-set-response-content-type` (header or query) |
| Artificial response delay | `x-set-response-delay-ms` (header or query) |
| Body-only response | `response_body_only=true` (query) |
| Include process env vars in the echo | `ECHO_INCLUDE_ENV_VARS` |
| CORS headers | `CORS_ALLOW_ORIGIN`, `CORS_ALLOW_METHODS`, `CORS_ALLOW_HEADERS`, `CORS_ALLOW_CREDENTIALS` |
| mTLS client certificate echo (no validation) | `MTLS_ENABLE` |
| Override response body from a file | `OVERRIDE_RESPONSE_BODY_FILE_PATH` |
| Maximum request header size | `MAX_HEADER_SIZE` |
| Cookies and signed cookies | `COOKIE_SECRET` |
| Prometheus metrics | `PROMETHEUS_ENABLED` and related `PROMETHEUS_*` variables |

See the [configuration reference](configuration.md) for the complete,
current list of every flag/env var, and [usage & endpoints](usage.md) for
the echo response format.
