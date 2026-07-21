# Configuration

Every option can be set through (highest precedence first):

1. **CLI flags** — kebab-case, e.g. `--https-port=9999`
2. **Environment variables** — upper snake-case, e.g. `HTTPS_PORT=9999`
3. **Config file** — `--config config.yaml` (YAML, TOML, or JSON; keys are the
   flag names)
4. **Built-in defaults**

Environment variable names are kept compatible with
[mendhak/http-https-echo](https://github.com/mendhak/docker-http-https-echo)
wherever the feature exists in both projects, so the image can act as a
drop-in replacement.

## Listeners

| Env var | Flag | Default | Description |
| --- | --- | --- | --- |
| `HTTP_PORT` | `--http-port` | `8080` | Plaintext listener port |
| `HTTPS_PORT` | `--https-port` | `8443` | TLS listener port |
| `HTTP_ENABLED` | `--http-enabled` | `true` | Enable the plaintext listener |
| `HTTPS_ENABLED` | `--https-enabled` | `true` | Enable the TLS listener |
| `BIND_ADDRESS` | `--bind-address` | *(all interfaces)* | Address to bind both listeners to |
| `SHUTDOWN_TIMEOUT` | `--shutdown-timeout` | `10s` | Graceful shutdown drain window |

## HTTP/2

| Env var | Flag | Default | Description |
| --- | --- | --- | --- |
| `HTTP2_ENABLED` | `--http2-enabled` | `true` | Offer `h2` via ALPN on the TLS listener |
| `HTTP2_H2C_ENABLED` | `--http2-h2c-enabled` | `true` | Accept cleartext HTTP/2 (`h2c`, prior-knowledge and `Upgrade`) on the plaintext listener |

## TLS

See the [TLS guide](tls.md) for details and examples.

| Env var | Flag | Default | Description |
| --- | --- | --- | --- |
| `TLS_MODE` | `--tls-mode` | `auto` | `static`, `auto`, or `vault` |
| `HTTPS_CERT_FILE` | `--https-cert-file` | — | Certificate (or full chain) PEM — `static` mode, **required** there |
| `HTTPS_KEY_FILE` | `--https-key-file` | — | Private key PEM — `static` mode, **required** there |
| `TLS_CA_CERT_FILE` | `--tls-ca-cert-file` | `certs/ca.crt` | Where the auto CA certificate is stored/loaded (`auto` mode) |
| `TLS_CA_KEY_FILE` | `--tls-ca-key-file` | `certs/ca.key` | Where the auto CA key is stored/loaded (`auto` mode) |
| `TLS_CA_PRINT` | `--tls-ca-print` | `true` | Print the CA certificate PEM to stdout at startup (`auto`/`vault`) |
| `TLS_CA_ENDPOINT` | `--tls-ca-endpoint` | `/ca` | HTTP path serving the CA certificate PEM; empty string disables |
| `TLS_CERT_TTL` | `--tls-cert-ttl` | `8760h` | Validity of on-the-fly leaf certificates (`auto` mode) |
| `TLS_CERT_CACHE_SIZE` | `--tls-cert-cache-size` | `128` | Max distinct SNI leaf certs kept in memory |
| `MTLS_ENABLE` | `--mtls-enable` | `false` | Request a client certificate and echo it (no validation) |

### Vault mode

| Env var | Flag | Default | Description |
| --- | --- | --- | --- |
| `VAULT_ADDR` | `--vault-addr` | — | Vault server URL, e.g. `https://vault:8200` (**required**) |
| `VAULT_TOKEN` | `--vault-token` | — | Vault token allowed to issue certs (**required**) |
| `VAULT_NAMESPACE` | `--vault-namespace` | — | Vault Enterprise namespace (optional) |
| `VAULT_PKI_MOUNT` | `--vault-pki-mount` | `pki` | Mount path of the PKI secrets engine |
| `VAULT_PKI_ROLE` | `--vault-pki-role` | — | PKI role used for issuance (**required**) |
| `VAULT_PKI_TTL` | `--vault-pki-ttl` | `24h` | Requested TTL for issued leaf certificates |
| `VAULT_CACERT` | `--vault-cacert` | — | CA bundle to verify the Vault server itself |
| `VAULT_SKIP_VERIFY` | `--vault-skip-verify` | `false` | Skip TLS verification of the Vault server (testing only) |

## Echo behaviour

| Env var | Flag | Default | Description |
| --- | --- | --- | --- |
| `ECHO_BACK_TO_CLIENT` | `--echo-back-to-client` | `true` | `false`: echo only to logs, respond with empty body |
| `ECHO_INCLUDE_ENV_VARS` | `--echo-include-env-vars` | `false` | Include the process environment in the echo body |
| `JWT_HEADER` | `--jwt-header` | — | Header name whose value is decoded as a JWT (`Bearer` prefix supported); decoded claims appear under `jwt` |
| `OVERRIDE_RESPONSE_BODY_FILE_PATH` | `--override-response-body-file-path` | — | Path to a file served as the response body instead of the echo |
| `MAX_HEADER_SIZE` | `--max-header-size` | `1048576` | Maximum request header size in bytes |
| `MAX_BODY_SIZE` | `--max-body-size` | `1048576` | Maximum request body bytes captured in the echo (`bodyTruncated: true` beyond) |
| `COOKIE_SECRET` | `--cookie-secret` | — | HMAC secret; cookies signed with it appear under `signedCookies` |
| `WS_ENABLED` | `--ws-enabled` | `true` | WebSocket echo on both listeners |

Header names are always echoed in canonical HTTP case (e.g.
`X-Arbitrary-Header`) — there is no lower-casing and no option to change
this.

## Forwarding

When `FORWARD_URL` is set, the daemon relays every request (except reserved
paths and WebSocket upgrades) to the remote server and relays its response
back — capturing both legs in the logs and in the [verbose
output](usage.md#verbose-wire-dump). See
[Usage → Forwarding](usage.md#forwarding-to-a-remote-server).

| Env var | Flag | Default | Description |
| --- | --- | --- | --- |
| `FORWARD_URL` | `--forward-url` | — | Absolute `http(s)://` base URL to forward requests to; enables forwarding mode |
| `FORWARD_PRESERVE_HOST` | `--forward-preserve-host` | `false` | Keep the client's `Host` header instead of the target's host |
| `FORWARD_TIMEOUT` | `--forward-timeout` | `30s` | Whole-exchange timeout for the upstream request |
| `FORWARD_SKIP_VERIFY` | `--forward-skip-verify` | `false` | Skip TLS verification of the remote server (testing only) |

## Verbose wire dump

| Env var | Flag | Default | Description |
| --- | --- | --- | --- |
| `VERBOSE` | `--verbose` | `false` | Print every exchange to stdout in a `curl -v`-style trace (both legs in forwarding mode) |

## Networking / proxies

| Env var | Flag | Default | Description |
| --- | --- | --- | --- |
| `ADDITIONAL_TRUSTED_PROXIES` | `--additional-trusted-proxies` | — | Comma-separated IPs/CIDRs trusted for `X-Forwarded-For` (loopback, link-local and private ranges are always trusted) |

## CORS

| Env var | Flag | Default | Description |
| --- | --- | --- | --- |
| `CORS_ALLOW_ORIGIN` | `--cors-allow-origin` | — | Comma-separated origins (or `*`); enables CORS handling |
| `CORS_ALLOW_METHODS` | `--cors-allow-methods` | *(all)* | Allowed methods for preflight |
| `CORS_ALLOW_HEADERS` | `--cors-allow-headers` | *(requested)* | Allowed headers for preflight |
| `CORS_ALLOW_CREDENTIALS` | `--cors-allow-credentials` | `false` | Send `Access-Control-Allow-Credentials: true` |

## Logging

| Env var | Flag | Default | Description |
| --- | --- | --- | --- |
| `LOG_LEVEL` | `--log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT` | `--log-format` | `json` | `json` (production) or `console` (human-friendly) |
| `DISABLE_REQUEST_LOGS` | `--disable-request-logs` | `false` | Suppress the per-request echo log lines |
| `LOG_IGNORE_PATH` | `--log-ignore-path` | — | Regex; matching request paths are not logged (repeatable / comma-separated) |

## Prometheus metrics

| Env var | Flag | Default | Description |
| --- | --- | --- | --- |
| `PROMETHEUS_ENABLED` | `--prometheus-enabled` | `false` | Expose Prometheus metrics |
| `PROMETHEUS_METRICS_PATH` | `--prometheus-metrics-path` | `/metrics` | Metrics endpoint path (this path is not echoed) |
| `PROMETHEUS_WITH_PATH` | `--prometheus-with-path` | `false` | Partition metrics by request path |
| `PROMETHEUS_WITH_METHOD` | `--prometheus-with-method` | `true` | Partition metrics by method |
| `PROMETHEUS_WITH_STATUS` | `--prometheus-with-status` | `true` | Partition metrics by status code |
| `PROMETHEUS_METRIC_TYPE` | `--prometheus-metric-type` | `summary` | `summary` or `histogram` |

## Config file example

```yaml
# config.yaml — start with: https-echo-server --config config.yaml
http-port: 8080
https-port: 8443
tls-mode: vault
vault-addr: https://vault.internal:8200
vault-pki-mount: pki_int
vault-pki-role: echo
log-format: console
prometheus-enabled: true
```

!!! warning "Secrets"
    Prefer passing `VAULT_TOKEN` (and `COOKIE_SECRET`) through the
    environment or a secret manager rather than the config file.
