# https-echo-server

A small Go daemon that echoes HTTP request properties back to the client — in
the response body and in the logs. Useful for debugging proxies, load
balancers, ingress controllers, TLS setups, and anything else that sits
between a client and a server.

Inspired by [mendhak/docker-http-https-echo](https://github.com/mendhak/docker-http-https-echo),
rewritten in Go with first-class **HTTP/2** and flexible **TLS**.

## Highlights

- **Echo everything**: method, path, query, headers, body, cookies, client
  IPs, TLS connection details — as structured JSON in the response and in the
  logs.
- **HTTP/2 everywhere**: `h2` via ALPN on the TLS listener, `h2c` on the
  plaintext listener.
- **Three TLS modes**:
    - `static` — bring your own certificate/key pair,
    - `auto` *(default)* — an auto-generated root CA signs server certificates
      **on the fly, matching the SNI** of each handshake,
    - `vault` — same on-the-fly behaviour, but leaf certificates are issued by
      a HashiCorp Vault PKI secrets engine.
- **mTLS echo**: request a client certificate and echo its details back.
- **Forwarding**: relay requests to a remote server and relay its responses
  back, dumping both directions — drop the daemon between two components to
  see exactly what they say to each other.
- **Verbose wire dump**: `curl -v`-style trace of every exchange on stdout.
- **Request introspection helpers**: JWT decoding, JSON body parsing,
  signed-cookie verification.
- **Response shaping** per request: status code, content type, delay, body
  override.
- **Operations-friendly**: zap structured logs, Prometheus metrics, CORS,
  trusted proxies, distroless non-root Docker image, graceful shutdown.

## Quick taste

```shell
docker run -p 8080:8080 -p 8443:8443 --rm -t ghcr.io/kumy/https-echo-server
curl -k https://localhost:8443/hello?foo=bar
```

```json
{
  "path": "/hello",
  "method": "GET",
  "protocol": "https",
  "httpVersion": "2.0",
  "query": { "foo": "bar" },
  "headers": { "User-Agent": "curl/8.5.0", "Accept": "*/*" },
  "connection": { "servername": "localhost", "alpn": "h2", "tlsVersion": "TLS1.3" },
  "os": { "hostname": "5788ef8a2074" }
}
```

## Where next

- [Getting started](getting-started.md) — run it with Docker or a binary
- [Configuration](configuration.md) — every flag / env var / config key
- [TLS](tls.md) — the three TLS modes in depth, including Vault setup
- [Usage & endpoints](usage.md) — echo format, response shaping, metrics
- [Compared to mendhak](comparison.md) — everything added on top of the
  original project
- [Specification](specification.md) — the formal functional spec
- [Development](development.md) — building, CI/CD, release automation
