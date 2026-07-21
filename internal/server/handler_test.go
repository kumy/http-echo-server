package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/kumy/https-echo-server/internal/config"
	"github.com/kumy/https-echo-server/internal/forward"
	"github.com/kumy/https-echo-server/internal/metrics"
	"github.com/kumy/https-echo-server/internal/verbose"
)

// testConfig returns a validated default config.
func testConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load(nil)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func observedHandler(cfg *config.Config) (*Handler, *observer.ObservedLogs) {
	core, logs := observer.New(zap.DebugLevel)
	return NewHandler(cfg, zap.New(core), nil, nil, nil, nil), logs
}

func doEcho(t *testing.T, h *Handler, r *http.Request) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.For(false).ServeHTTP(rec, r)
	var body map[string]any
	if rec.Body.Len() > 0 && strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("response is not JSON: %v\n%s", err, rec.Body.String())
		}
	}
	return rec, body
}

func TestEchoResponse(t *testing.T) {
	h, logs := observedHandler(testConfig(t))
	r := httptest.NewRequest(http.MethodPut, "/hello-world?foo=bar", strings.NewReader("aaa=bbb"))
	r.Header.Set("Arbitrary", "Header")

	rec, body := doEcho(t, h, r)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("content-type = %q", ct)
	}
	if body["path"] != "/hello-world" || body["method"] != "PUT" || body["body"] != "aaa=bbb" {
		t.Errorf("echo body = %v", body)
	}
	headers := body["headers"].(map[string]any)
	if headers["Arbitrary"] != "Header" {
		t.Errorf("headers not canonical-cased: %v", headers)
	}

	// The request must be logged at info with status and duration fields.
	entries := logs.FilterMessage("request").All()
	if len(entries) != 1 {
		t.Fatalf("got %d request logs, want 1", len(entries))
	}
	ctx := entries[0].ContextMap()
	if ctx["status"] != int64(200) {
		t.Errorf("logged status = %v", ctx["status"])
	}
	if _, ok := ctx["durationMs"]; !ok {
		t.Error("durationMs missing from request log")
	}
}

func TestShapingStatusCode(t *testing.T) {
	h, logs := observedHandler(testConfig(t))

	r := httptest.NewRequest(http.MethodGet, "/?x-set-response-status-code=418", nil)
	rec, _ := doEcho(t, h, r)
	if rec.Code != http.StatusTeapot {
		t.Errorf("query shaping: status = %d", rec.Code)
	}

	// Header wins over query.
	r = httptest.NewRequest(http.MethodGet, "/?x-set-response-status-code=418", nil)
	r.Header.Set("x-set-response-status-code", "503")
	rec, _ = doEcho(t, h, r)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("header should win: status = %d", rec.Code)
	}

	// Invalid code ignored with a warning.
	r = httptest.NewRequest(http.MethodGet, "/?x-set-response-status-code=999", nil)
	rec, _ = doEcho(t, h, r)
	if rec.Code != http.StatusOK {
		t.Errorf("invalid code must be ignored: status = %d", rec.Code)
	}
	if logs.FilterLevelExact(zap.WarnLevel).Len() == 0 {
		t.Error("expected a warning for the invalid status code")
	}
}

func TestShapingContentTypeAndBodyOnly(t *testing.T) {
	h, _ := observedHandler(testConfig(t))

	r := httptest.NewRequest(http.MethodPost, "/?response_body_only=true&x-set-response-content-type=text/plain",
		strings.NewReader(`{"a": 1}`))
	rec := httptest.NewRecorder()
	h.For(false).ServeHTTP(rec, r)
	if rec.Body.String() != `{"a": 1}` {
		t.Errorf("body = %q", rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "text/plain" {
		t.Errorf("content-type = %q", rec.Header().Get("Content-Type"))
	}
}

func TestShapingDelay(t *testing.T) {
	h, _ := observedHandler(testConfig(t))
	r := httptest.NewRequest(http.MethodGet, "/?x-set-response-delay-ms=120", nil)
	start := time.Now()
	rec, _ := doEcho(t, h, r)
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("delay not applied: %v", elapsed)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d", rec.Code)
	}
}

func TestEchoBackToClientDisabled(t *testing.T) {
	cfg := testConfig(t)
	cfg.EchoBackToClient = false
	h, logs := observedHandler(cfg)

	rec := httptest.NewRecorder()
	h.For(false).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Body.Len() != 0 {
		t.Errorf("body should be empty, got %q", rec.Body.String())
	}
	if logs.FilterMessage("request").Len() != 1 {
		t.Error("request must still be logged")
	}
}

func TestOverrideResponseBodyFile(t *testing.T) {
	cfg := testConfig(t)
	file := filepath.Join(t.TempDir(), "override.txt")
	if err := os.WriteFile(file, []byte("static content"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.OverrideResponseBodyFilePath = file
	h, _ := observedHandler(cfg)

	rec := httptest.NewRecorder()
	h.For(false).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Body.String() != "static content" {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestBodyTruncation(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxBodySize = 8
	h, _ := observedHandler(cfg)

	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("0123456789abcdef"))
	_, body := doEcho(t, h, r)
	if body["body"] != "01234567" {
		t.Errorf("body = %q", body["body"])
	}
	if body["bodyTruncated"] != true {
		t.Error("bodyTruncated missing")
	}
}

func TestReservedPathMetrics(t *testing.T) {
	cfg := testConfig(t)
	cfg.PrometheusEnabled = true
	core, logs := observer.New(zap.DebugLevel)
	m := metrics.New(metrics.Options{WithMethod: true, WithStatus: true, MetricType: "summary"})
	h := NewHandler(cfg, zap.New(core), m, nil, nil, nil)

	// One echo request, then scrape.
	rec := httptest.NewRecorder()
	h.For(false).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/hello", nil))

	rec = httptest.NewRecorder()
	h.For(false).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `http_echo_requests_total{method="GET",status="200"}`) {
		t.Errorf("metrics scrape missing counter:\n%s", firstLines(rec.Body.String(), 5))
	}

	// Reserved path must be logged at debug, not info.
	for _, entry := range logs.FilterMessage("request").All() {
		if entry.ContextMap()["request"] != nil {
			req := entry.ContextMap()
			_ = req
		}
		if entry.Level == zap.InfoLevel {
			if strings.Contains(entry.Message+entryPath(entry.ContextMap()), "/metrics") {
				t.Error("/metrics must not be logged at info")
			}
		}
	}
}

func TestReservedPathCA(t *testing.T) {
	cfg := testConfig(t)
	h, _ := observedHandler(cfg)
	h.caPEM = []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")

	rec := httptest.NewRecorder()
	h.For(false).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ca", nil))
	if rec.Header().Get("Content-Type") != "application/x-pem-file" {
		t.Errorf("content-type = %q", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Body.String(), "BEGIN CERTIFICATE") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestCORS(t *testing.T) {
	cfg := testConfig(t)
	cfg.CORSAllowOrigin = "https://app.example.com"
	cfg.CORSAllowCredentials = true
	h, _ := observedHandler(cfg)

	// Preflight.
	r := httptest.NewRequest(http.MethodOptions, "/", nil)
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "PUT")
	r.Header.Set("Access-Control-Request-Headers", "X-Custom")
	rec := httptest.NewRecorder()
	h.For(false).ServeHTTP(rec, r)
	if rec.Code != http.StatusNoContent {
		t.Errorf("preflight status = %d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Errorf("ACAO = %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("credentials header missing")
	}
	if rec.Header().Get("Access-Control-Allow-Headers") != "X-Custom" {
		t.Errorf("allow-headers = %q", rec.Header().Get("Access-Control-Allow-Headers"))
	}

	// Simple request from an allowed origin still echoes.
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Origin", "https://app.example.com")
	rec, body := doEcho(t, h, r)
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Error("ACAO missing on simple request")
	}
	if body["method"] != "GET" {
		t.Error("echo body missing on CORS request")
	}

	// Disallowed origin: no ACAO header.
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Origin", "https://evil.example.com")
	rec, _ = doEcho(t, h, r)
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("ACAO must be absent for disallowed origins")
	}
}

func TestLogSuppression(t *testing.T) {
	cfg := testConfig(t)
	cfg.DisableRequestLogs = true
	h, logs := observedHandler(cfg)
	rec := httptest.NewRecorder()
	h.For(false).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if logs.FilterMessage("request").Len() != 0 {
		t.Error("request logged despite DISABLE_REQUEST_LOGS")
	}
}

func TestLogIgnorePath(t *testing.T) {
	cfg, err := config.Load([]string{"--log-ignore-path=^/healthz"})
	if err != nil {
		t.Fatal(err)
	}
	h, logs := observedHandler(cfg)

	rec := httptest.NewRecorder()
	h.For(false).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	rec = httptest.NewRecorder()
	h.For(false).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/other", nil))

	entries := logs.FilterMessage("request").All()
	if len(entries) != 1 {
		t.Fatalf("got %d request logs, want 1 (healthz suppressed)", len(entries))
	}
}

func TestForwardEndToEnd(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "am")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))
	defer backend.Close()

	cfg, err := config.Load([]string{"--forward-url=" + backend.URL})
	if err != nil {
		t.Fatal(err)
	}
	core, logs := observer.New(zap.DebugLevel)
	var dump bytes.Buffer
	vp := verbose.New(&dump, cfg.MaxBodySize)
	fwd := forward.New(forward.Options{Target: cfg.ForwardTarget, Timeout: cfg.ForwardTimeout})
	h := NewHandler(cfg, zap.New(core), nil, vp, fwd, nil)

	r := httptest.NewRequest(http.MethodPost, "/api/v2/alerts", strings.NewReader(`[{"labels":{}}]`))
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.For(false).ServeHTTP(rec, r)

	// Remote response relayed unchanged.
	if rec.Code != http.StatusAccepted {
		t.Errorf("status = %d", rec.Code)
	}
	if rec.Header().Get("X-Backend") != "am" {
		t.Error("remote headers not relayed")
	}
	if rec.Body.String() != `{"status":"success"}` {
		t.Errorf("body = %q", rec.Body.String())
	}

	// Request log carries the forward object with the remote response.
	entries := logs.FilterMessage("request").All()
	if len(entries) != 1 {
		t.Fatalf("got %d request logs", len(entries))
	}
	fl, ok := entries[0].ContextMap()["forward"].(*forwardLog)
	if !ok {
		t.Fatalf("forward field missing: %v", entries[0].ContextMap())
	}
	if fl.Status != http.StatusAccepted || fl.Body != `{"status":"success"}` {
		t.Errorf("forward log = %+v", fl)
	}

	// Verbose dump shows both legs.
	out := dump.String()
	for _, want := range []string{
		"> POST /api/v2/alerts HTTP/1.1",
		"* Forwarding to " + backend.URL + "/api/v2/alerts",
		">> POST " + backend.URL + "/api/v2/alerts",
		`<< HTTP/1.1 202 Accepted`,
		`<< {"status":"success"}`,
		"< HTTP/1.1 202 Accepted",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("verbose dump missing %q:\n%s", want, out)
		}
	}
}

func TestForwardUpstreamFailure(t *testing.T) {
	cfg, err := config.Load([]string{"--forward-url=http://127.0.0.1:1", "--forward-timeout=200ms"})
	if err != nil {
		t.Fatal(err)
	}
	core, logs := observer.New(zap.DebugLevel)
	fwd := forward.New(forward.Options{Target: cfg.ForwardTarget, Timeout: cfg.ForwardTimeout})
	h := NewHandler(cfg, zap.New(core), nil, nil, fwd, nil)

	rec := httptest.NewRecorder()
	h.For(false).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("502 body not JSON: %q", rec.Body.String())
	}
	if body["error"] == "" || body["target"] == "" {
		t.Errorf("502 body = %v", body)
	}
	if logs.FilterLevelExact(zap.ErrorLevel).Len() == 0 {
		t.Error("expected an error log for the failed forward")
	}
}

func TestForwardShapingIgnored(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	cfg, err := config.Load([]string{"--forward-url=" + backend.URL})
	if err != nil {
		t.Fatal(err)
	}
	fwd := forward.New(forward.Options{Target: cfg.ForwardTarget, Timeout: cfg.ForwardTimeout})
	h := NewHandler(cfg, zap.NewNop(), nil, nil, fwd, nil)

	rec := httptest.NewRecorder()
	h.For(false).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/?x-set-response-status-code=418", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("shaping must be ignored in forward mode: status = %d", rec.Code)
	}
}

func TestForwardAppendsDirectPeerIP(t *testing.T) {
	var gotXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
	}))
	defer backend.Close()

	cfg, err := config.Load([]string{"--forward-url=" + backend.URL})
	if err != nil {
		t.Fatal(err)
	}
	fwd := forward.New(forward.Options{Target: cfg.ForwardTarget, Timeout: cfg.ForwardTimeout})
	h := NewHandler(cfg, zap.NewNop(), nil, nil, fwd, nil)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.9:54321"
	// An untrusted, client-supplied X-Forwarded-For must be kept as-is, with
	// only the real connecting peer (never the header value) appended.
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	rec := httptest.NewRecorder()
	h.For(false).ServeHTTP(rec, r)

	if gotXFF != "198.51.100.1, 203.0.113.9" {
		t.Errorf("XFF = %q, want existing chain plus the direct peer IP without its port", gotXFF)
	}
}

func TestDelayAbortLogsStatus499(t *testing.T) {
	h, logs := observedHandler(testConfig(t))
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest(http.MethodGet, "/?x-set-response-delay-ms=200", nil).WithContext(ctx)
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	rec := httptest.NewRecorder()
	h.For(false).ServeHTTP(rec, r)
	if rec.Body.Len() != 0 {
		t.Errorf("aborted request must write nothing to the wire, got %q", rec.Body.String())
	}

	entries := logs.FilterMessage("request").All()
	if len(entries) != 1 {
		t.Fatalf("got %d request logs, want 1", len(entries))
	}
	if status := entries[0].ContextMap()["status"]; status != int64(499) {
		t.Errorf("logged status = %v, want 499", status)
	}
}

func TestResponseBodyOnlyNoSentinelByte(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxBodySize = 8
	h, _ := observedHandler(cfg)

	r := httptest.NewRequest(http.MethodPost, "/?response_body_only=true", strings.NewReader("0123456789abcdef"))
	rec := httptest.NewRecorder()
	h.For(false).ServeHTTP(rec, r)
	if got := rec.Body.String(); got != "01234567" {
		t.Errorf("body = %q (len %d), want exactly MaxBodySize bytes with no extra sentinel byte", got, len(got))
	}
}

func TestVerboseEchoDump(t *testing.T) {
	cfg := testConfig(t)
	var dump bytes.Buffer
	h := NewHandler(cfg, zap.NewNop(), nil, verbose.New(&dump, cfg.MaxBodySize), nil, nil)

	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("payload"))
	r.Header.Set("X-Test", "v")
	rec := httptest.NewRecorder()
	h.For(false).ServeHTTP(rec, r)

	out := dump.String()
	for _, want := range []string{"> POST /x HTTP/1.1", "> X-Test: v", "> payload", "< HTTP/1.1 200 OK"} {
		if !strings.Contains(out, want) {
			t.Errorf("dump missing %q:\n%s", want, out)
		}
	}
}

// --- helpers ---

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

func entryPath(ctx map[string]any) string {
	if req, ok := ctx["request"]; ok {
		b, _ := json.Marshal(req)
		return string(b)
	}
	return ""
}
