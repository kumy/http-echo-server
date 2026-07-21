package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"go.uber.org/zap"
	"golang.org/x/net/http2"

	"github.com/kumy/https-echo-server/internal/config"
)

// startServer builds and starts a Server on ephemeral ports.
func startServer(t *testing.T, args ...string) (*Server, context.CancelFunc) {
	t.Helper()
	dir := t.TempDir()
	base := []string{
		"--http-port=0", "--https-port=0", "--bind-address=127.0.0.1",
		"--tls-ca-cert-file=" + filepath.Join(dir, "ca.crt"),
		"--tls-ca-key-file=" + filepath.Join(dir, "ca.key"),
		"--shutdown-timeout=2s",
	}
	cfg, err := config.Load(append(base, args...))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run returned error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("server did not shut down in time")
		}
	})
	return srv, cancel
}

func tlsClient(srv *Server, serverName string, forceH2 bool) *http.Client {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(srv.CAPEM())
	tlsCfg := &tls.Config{RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS12}
	transport := &http.Transport{TLSClientConfig: tlsCfg, ForceAttemptHTTP2: forceH2}
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func getJSON(t *testing.T, client *http.Client, url string) (int, map[string]any) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	var parsed map[string]any
	if len(body) > 0 {
		_ = json.Unmarshal(body, &parsed)
	}
	return resp.StatusCode, parsed
}

func TestHTTPListenerEcho(t *testing.T) {
	srv, _ := startServer(t)
	status, body := getJSON(t, http.DefaultClient, "http://"+srv.HTTPAddr()+"/hi")
	if status != http.StatusOK || body["path"] != "/hi" {
		t.Errorf("status=%d body=%v", status, body)
	}
	if body["protocol"] != "http" || body["httpVersion"] != "1.1" {
		t.Errorf("protocol fields: %v", body)
	}
}

func TestH2CPriorKnowledge(t *testing.T) {
	srv, _ := startServer(t)
	client := &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		},
		Timeout: 5 * time.Second,
	}
	status, body := getJSON(t, client, "http://"+srv.HTTPAddr()+"/h2c")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if body["httpVersion"] != "2.0" {
		t.Errorf("httpVersion = %v, want 2.0 over h2c", body["httpVersion"])
	}
}

func TestH2CDisabled(t *testing.T) {
	srv, _ := startServer(t, "--http2-h2c-enabled=false")
	client := &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		},
		Timeout: 2 * time.Second,
	}
	if _, err := client.Get("http://" + srv.HTTPAddr() + "/"); err == nil {
		t.Error("prior-knowledge h2c should fail when disabled")
	}
}

func TestHTTPSAutoModeSNI(t *testing.T) {
	srv, _ := startServer(t)
	host, port, _ := net.SplitHostPort(srv.HTTPSAddr())
	_ = host

	client := tlsClient(srv, "sni-test.example.com", true)
	status, body := getJSON(t, client, "https://127.0.0.1:"+port+"/tls")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if body["protocol"] != "https" {
		t.Errorf("protocol = %v", body["protocol"])
	}
	conn := body["connection"].(map[string]any)
	if conn["servername"] != "sni-test.example.com" {
		t.Errorf("SNI echoed = %v", conn["servername"])
	}
	// ALPN must have negotiated h2.
	if conn["alpn"] != "h2" || body["httpVersion"] != "2.0" {
		t.Errorf("h2 not negotiated: %v", conn)
	}
}

func TestHTTPSHTTP2Disabled(t *testing.T) {
	srv, _ := startServer(t, "--http2-enabled=false")
	_, port, _ := net.SplitHostPort(srv.HTTPSAddr())
	client := tlsClient(srv, "localhost", true)
	status, body := getJSON(t, client, "https://127.0.0.1:"+port+"/")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if body["httpVersion"] != "1.1" {
		t.Errorf("httpVersion = %v, want 1.1 with h2 disabled", body["httpVersion"])
	}
}

func TestCAEndpointServed(t *testing.T) {
	srv, _ := startServer(t)
	resp, err := http.Get("http://" + srv.HTTPAddr() + "/ca")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.Header.Get("Content-Type") != "application/x-pem-file" {
		t.Errorf("content-type = %q", resp.Header.Get("Content-Type"))
	}
	if string(body) != string(srv.CAPEM()) {
		t.Error("CA endpoint body differs from CAPEM")
	}
}

func TestMTLSEcho(t *testing.T) {
	srv, _ := startServer(t, "--mtls-enable=true")
	_, port, _ := net.SplitHostPort(srv.HTTPSAddr())

	clientCert := makeClientCert(t)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(srv.CAPEM())
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      pool,
			ServerName:   "localhost",
			Certificates: []tls.Certificate{clientCert},
			MinVersion:   tls.VersionTLS12,
		}},
		Timeout: 5 * time.Second,
	}

	status, body := getJSON(t, client, "https://127.0.0.1:"+port+"/")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	cc, ok := body["clientCertificate"].(map[string]any)
	if !ok {
		t.Fatalf("clientCertificate missing: %v", body)
	}
	if cc["subject"] != "CN=mtls-client" {
		t.Errorf("subject = %v", cc["subject"])
	}
}

func TestWebSocketEcho(t *testing.T) {
	srv, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, "ws://"+srv.HTTPAddr()+"/socket", nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.CloseNow() //nolint:errcheck

	// First message: the JSON echo of the upgrade request.
	typ, first, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("reading initial echo: %v", err)
	}
	if typ != websocket.MessageText {
		t.Errorf("first message type = %v", typ)
	}
	var echoObj map[string]any
	if err := json.Unmarshal(first, &echoObj); err != nil || echoObj["path"] != "/socket" {
		t.Errorf("initial echo = %s (err %v)", first, err)
	}

	// Then messages are mirrored.
	if err := conn.Write(ctx, websocket.MessageText, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	_, msg, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg) != "hello" {
		t.Errorf("echoed = %q", msg)
	}

	if err := conn.Close(websocket.StatusNormalClosure, "done"); err != nil {
		t.Errorf("close: %v", err)
	}
}

func TestWebSocketLargeMessage(t *testing.T) {
	srv, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, "ws://"+srv.HTTPAddr()+"/socket", nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.CloseNow() //nolint:errcheck
	// The library defaults every connection (client side too) to a 32 KiB
	// read limit; lift it here so the test client can receive the large
	// echoed message the server fix is meant to allow through.
	conn.SetReadLimit(-1)

	// Drain the initial JSON echo.
	if _, _, err := conn.Read(ctx); err != nil {
		t.Fatalf("reading initial echo: %v", err)
	}

	// The server's default read limit is also 32 KiB; it must lift it so
	// larger messages are echoed instead of aborting the connection.
	big := strings.Repeat("x", 100*1024)
	if err := conn.Write(ctx, websocket.MessageText, []byte(big)); err != nil {
		t.Fatal(err)
	}
	_, msg, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("reading large echoed message: %v", err)
	}
	if string(msg) != big {
		t.Errorf("echoed message length = %d, want %d", len(msg), len(big))
	}
}

func TestWebSocketDisabled(t *testing.T) {
	srv, _ := startServer(t, "--ws-enabled=false")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// With WS disabled the upgrade request receives the JSON echo instead.
	_, resp, err := websocket.Dial(ctx, "ws://"+srv.HTTPAddr()+"/", nil)
	if err == nil {
		t.Fatal("expected websocket dial to fail")
	}
	if resp != nil && resp.StatusCode != http.StatusOK {
		t.Errorf("expected the echo (200), got %d", resp.StatusCode)
	}
}

func TestGracefulShutdown(t *testing.T) {
	srv, cancel := startServer(t)
	// In-flight request finishes during the drain.
	url := "http://" + srv.HTTPAddr() + "/?x-set-response-delay-ms=300"
	errCh := make(chan error, 1)
	go func() {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
		}
		errCh <- err
	}()
	time.Sleep(100 * time.Millisecond)
	cancel() // triggers shutdown; Cleanup asserts Run returned nil

	if err := <-errCh; err != nil {
		t.Errorf("in-flight request failed during graceful shutdown: %v", err)
	}
}

func TestPrometheusEndToEnd(t *testing.T) {
	srv, _ := startServer(t, "--prometheus-enabled=true")
	_, _ = getJSON(t, http.DefaultClient, "http://"+srv.HTTPAddr()+"/hello")

	resp, err := http.Get("http://" + srv.HTTPAddr() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if !contains(body, "http_echo_requests_total") {
		t.Error("metrics endpoint missing request counter")
	}
}

func TestHTTPOnlyMode(t *testing.T) {
	srv, _ := startServer(t, "--https-enabled=false")
	if srv.HTTPSAddr() != "" {
		t.Error("HTTPS listener should not be bound")
	}
	status, _ := getJSON(t, http.DefaultClient, "http://"+srv.HTTPAddr()+"/")
	if status != http.StatusOK {
		t.Errorf("status = %d", status)
	}
}

// --- helpers ---

func makeClientCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "mtls-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func contains(b []byte, s string) bool {
	return strings.Contains(string(b), s)
}
