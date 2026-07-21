# Usage & endpoints

## The echo response

Every path, every method (except the few reserved paths below) responds
`200 OK` with a JSON echo of the request:

```json
{
  "path": "/hello-world",
  "query": { "foo": "bar", "multi": ["1", "2"] },
  "method": "PUT",
  "protocol": "https",
  "httpVersion": "2.0",
  "host": "echo.example.com:8443",
  "hostname": "echo.example.com",
  "ip": "203.0.113.7",
  "ips": ["203.0.113.7", "10.0.0.3"],
  "headers": {
    "Content-Type": "application/json",
    "User-Agent": "curl/8.5.0"
  },
  "cookies": { "session": "abc123" },
  "signedCookies": { "user": "kumy" },
  "body": "{\"aaa\":\"bbb\"}",
  "json": { "aaa": "bbb" },
  "jwt": {
    "header": { "alg": "HS256", "typ": "JWT" },
    "payload": { "sub": "1234567890", "name": "John Doe" }
  },
  "clientCertificate": { "subject": "CN=my-client" },
  "connection": {
    "servername": "echo.example.com",
    "alpn": "h2",
    "tlsVersion": "TLS1.3",
    "cipher": "TLS_AES_128_GCM_SHA256"
  },
  "os": { "hostname": "5788ef8a2074" },
  "env": { "HOME": "/home/nonroot" }
}
```

Field notes:

- `ip` / `ips` — derived from the socket address and `X-Forwarded-For`,
  honouring trusted proxies (`ADDITIONAL_TRUSTED_PROXIES`).
- `headers` — names in canonical HTTP case (never lower-cased); HTTP/2
  requests, lower-cased on the wire, are canonicalized to the same form.
  Repeated headers become arrays.
- `json` — present only when `Content-Type: application/json` and the body
  parses.
- `jwt` — present only when `JWT_HEADER` is configured and that header
  contains a decodable JWT (signature is **not** verified).
- `signedCookies` — present only with `COOKIE_SECRET`.
- `clientCertificate` — present only with `MTLS_ENABLE` and a supplied cert.
- `env` — present only with `ECHO_INCLUDE_ENV_VARS=true`.
- Absent/empty sections are omitted.

The same information is logged (zap) for each request unless
`DISABLE_REQUEST_LOGS=true` or the path matches `LOG_IGNORE_PATH`.

## Reserved paths

| Path | Condition | Purpose |
| --- | --- | --- |
| `/ca` (configurable, `TLS_CA_ENDPOINT`) | `TLS_MODE` = `auto`/`vault` | Serves the CA certificate PEM |
| `/metrics` (configurable, `PROMETHEUS_METRICS_PATH`) | `PROMETHEUS_ENABLED=true` | Prometheus metrics |

Everything else echoes.

## Response shaping (per request)

Send these as **headers or query parameters**:

### Custom status code

```shell
curl -i -H "x-set-response-status-code: 404" http://localhost:8080/
curl -i "http://localhost:8080/?x-set-response-status-code=429"
```

Invalid codes (outside 100–599) are ignored and noted in the log.

### Custom content type

```shell
curl -i "http://localhost:8080/?x-set-response-content-type=text/plain"
```

### Delayed response

```shell
time curl "http://localhost:8080/?x-set-response-delay-ms=6000"
```

### Combined

```shell
curl -i "http://localhost:8080/?x-set-response-delay-ms=2000&x-set-response-status-code=503"
```

### Only the body, echoed back

```shell
curl -d '{"a": 1}' "http://localhost:8080/?response_body_only=true"
# → {"a": 1}
```

Pairs well with `x-set-response-content-type` to simulate arbitrary API
responses.

### Static response body

Start with `OVERRIDE_RESPONSE_BODY_FILE_PATH=/data/response.json` and every
request gets that file's content as body (request still fully logged).

### No echo at all

`ECHO_BACK_TO_CLIENT=false` → empty response body, everything still logged.

## Forwarding to a remote server

Set `FORWARD_URL` to relay requests to a remote server instead of answering
with the echo. The daemon then acts as a transparent observer between a
client and a server: every request is captured (logs + verbose output),
relayed to the remote, and the **remote response is captured and dumped
before being relayed back** to the original client — status, headers, and
body all pass through unchanged.

```shell
FORWARD_URL=http://backend:9093 VERBOSE=true LOG_FORMAT=console https-echo-server
# point the client that normally talks to backend:9093 at this daemon instead
```

Use it to see the exact payloads two components exchange — e.g. drop it
between a service and its API dependency to inspect the JSON messages flowing
in both directions.

Details:

- The request path and query are appended to `FORWARD_URL` (which may itself
  carry a base path).
- `Host` is rewritten to the target host (`FORWARD_PRESERVE_HOST=true` keeps
  the original), and `X-Forwarded-For` / `X-Forwarded-Proto` /
  `X-Forwarded-Host` are added.
- The request log gains a `forward` object with the remote response's
  `status`, `headers`, and `body`.
- Remote errors and timeouts (`FORWARD_TIMEOUT`, default 30s) return
  `502 Bad Gateway` with a JSON error body.
- Reserved paths (metrics, CA) and WebSocket upgrades are still handled
  locally; response shaping is disabled in forwarding mode.

## Verbose wire dump

`VERBOSE=true` prints each exchange to stdout in a `curl -v`-style trace —
`>` for the incoming request, `<` for the response sent back, and, in
forwarding mode, `>>` / `<<` for the upstream leg:

```text
* Request #1: 127.0.0.1:53210 → http (HTTP/1.1)
> POST /api/v2/alerts HTTP/1.1
> Host: localhost:8080
> Content-Type: application/json
>
> [{"labels":{"alertname":"Test"}}]
* Forwarding to http://backend:9093/api/v2/alerts
>> POST /api/v2/alerts
>> Content-Type: application/json
>>
>> [{"labels":{"alertname":"Test"}}]
<< HTTP/1.1 200 OK
<< Content-Type: application/json
<<
* Response #1: 200 (12ms)
< HTTP/1.1 200 OK
< Content-Type: application/json
<
```

Each exchange is printed as one atomic block, so concurrent requests never
interleave. Bodies longer than `MAX_BODY_SIZE` are truncated with a
`* [body truncated]` marker.

## JWT decoding

```shell
JWT_HEADER=Authorization https-echo-server
curl -H "Authorization: Bearer eyJhbGciOi..." http://localhost:8080/
```

Both raw tokens and the `Bearer <token>` scheme are understood. Header and
payload are base64-decoded and echoed; the signature is not verified.

## CORS

```shell
CORS_ALLOW_ORIGIN='*' https-echo-server
```

With any `CORS_ALLOW_*` configured, preflight `OPTIONS` requests are answered
accordingly, and simple requests get the matching `Access-Control-*` response
headers. Fine-tune with `CORS_ALLOW_METHODS`, `CORS_ALLOW_HEADERS`,
`CORS_ALLOW_CREDENTIALS`.

## WebSockets

Connect with `ws://` (either listener) or `wss://` (TLS listener); every
message sent is echoed back verbatim. On connect, a JSON echo of the upgrade
request is sent as the first message. Disable with `WS_ENABLED=false`.

```shell
websocat ws://localhost:8080/socket
hello
# ← hello
```

## Prometheus metrics

```shell
PROMETHEUS_ENABLED=true https-echo-server
curl http://localhost:8080/metrics
```

Exposes standard Go process metrics plus request duration/count, partitioned
by method and status (and path with `PROMETHEUS_WITH_PATH=true` — beware
cardinality). `PROMETHEUS_METRIC_TYPE` selects `summary` (default) or
`histogram`.

## Logging

- `LOG_FORMAT=json` (default): one JSON object per line, zap production
  encoder — friendly to Loki/ELK.
- `LOG_FORMAT=console`: human-readable, colored level names.
- Request logs include the full echo object under the `request` key.

```shell
LOG_IGNORE_PATH='^/(healthz|metrics)' https-echo-server
```
