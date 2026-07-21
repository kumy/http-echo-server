# Getting started

## Docker

```shell
docker run -p 8080:8080 -p 8443:8443 --rm -t ghcr.io/kumy/https-echo-server
```

Issue a request:

```shell
curl -k -X PUT -H "Arbitrary:Header" -d aaa=bbb https://localhost:8443/hello-world
```

The response (and the container log) contains the echoed request:

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
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "curl/8.5.0"
  },
  "body": "aaa=bbb",
  "connection": { "servername": "localhost", "alpn": "h2", "tlsVersion": "TLS1.3" },
  "os": { "hostname": "5788ef8a2074" }
}
```

!!! tip "Pin a version"
    Prefer a specific tag over `:latest`, e.g.
    `ghcr.io/kumy/https-echo-server:1.2.3`. Images are tagged with
    `MAJOR`, `MAJOR.MINOR`, and full version.

### Choose your ports

```shell
docker run -e HTTP_PORT=8888 -e HTTPS_PORT=9999 -p 8888:8888 -p 9999:9999 \
  --rm -t ghcr.io/kumy/https-echo-server
```

### Drop `-k`: trust the auto-generated CA

In the default `auto` TLS mode the server generates a root CA on first start,
prints it to the logs, and saves it (in the container: `/certs/ca.crt`). Mount
a volume to grab and persist it:

```shell
docker run -p 8443:8443 -v $PWD/certs:/certs --rm -t ghcr.io/kumy/https-echo-server

curl --cacert certs/ca.crt https://localhost:8443/
```

Server certificates are minted at handshake time for whatever SNI the client
sends:

```shell
curl --cacert certs/ca.crt --resolve anything.example.test:8443:127.0.0.1 \
  https://anything.example.test:8443/
```

You can also download the CA over plain HTTP at `http://localhost:8080/ca`
(see [TLS](tls.md#the-ca-download-endpoint)).

## Binary

Grab an archive for your OS/arch from the
[releases page](https://github.com/kumy/https-echo-server/releases):

```shell
tar xzf https-echo-server_*_linux_amd64.tar.gz
./https-echo-server
```

Or build from source (Go ≥ 1.25):

```shell
git clone https://github.com/kumy/https-echo-server
cd https-echo-server
make build
./bin/https-echo-server
```

## HTTP/2

Both listeners speak HTTP/2:

```shell
# h2 negotiated via ALPN on the TLS listener
curl -sk --http2 https://localhost:8443/ -o /dev/null -w '%{http_version}\n'   # → 2

# h2c (cleartext HTTP/2, prior knowledge) on the plaintext listener
curl -s --http2-prior-knowledge http://localhost:8080/ | jq .httpVersion       # → "2.0"
```

## docker-compose

```yaml
services:
  echo:
    image: ghcr.io/kumy/https-echo-server:1
    ports:
      - "8080:8080"
      - "8443:8443"
    volumes:
      - ./certs:/certs
    environment:
      LOG_FORMAT: console
      JWT_HEADER: Authorization
```

## Kubernetes

The image is distroless and runs as a non-root user; it works under restricted
Pod Security Standards. Any path can serve as liveness/readiness probe since
every path echoes with `200`:

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
```
