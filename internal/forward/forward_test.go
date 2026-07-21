package forward

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newForwarder(t *testing.T, target string, opts func(*Options)) *Forwarder {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	o := Options{Target: u, Timeout: 5 * time.Second}
	if opts != nil {
		opts(&o)
	}
	return New(o)
}

func TestRelayBasics(t *testing.T) {
	var got *http.Request
	var gotBody []byte
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(r.Context())
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("X-Backend", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()

	f := newForwarder(t, backend.URL, nil)
	r := httptest.NewRequest(http.MethodPost, "http://echo.local:8080/api/v2/alerts?x=1", strings.NewReader("ignored"))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Connection", "keep-alive")

	res := f.Do(r, []byte(`[{"a":1}]`), "203.0.113.7", "http")
	if res.Err != nil {
		t.Fatalf("Do: %v", res.Err)
	}

	if got.URL.Path != "/api/v2/alerts" || got.URL.RawQuery != "x=1" {
		t.Errorf("backend saw %s?%s", got.URL.Path, got.URL.RawQuery)
	}
	if got.Method != http.MethodPost {
		t.Errorf("method = %s", got.Method)
	}
	if string(gotBody) != `[{"a":1}]` {
		t.Errorf("body = %q", gotBody)
	}
	if got.Header.Get("Content-Type") != "application/json" {
		t.Errorf("content-type not relayed")
	}
	if got.Header.Get("X-Forwarded-For") != "203.0.113.7" {
		t.Errorf("XFF = %q", got.Header.Get("X-Forwarded-For"))
	}
	if got.Header.Get("X-Forwarded-Proto") != "http" {
		t.Errorf("XFP = %q", got.Header.Get("X-Forwarded-Proto"))
	}
	if got.Header.Get("X-Forwarded-Host") != "echo.local:8080" {
		t.Errorf("XFH = %q", got.Header.Get("X-Forwarded-Host"))
	}
	// Host rewritten to target by default.
	if got.Host == "echo.local:8080" {
		t.Errorf("Host not rewritten: %q", got.Host)
	}

	if res.Code != http.StatusCreated {
		t.Errorf("code = %d", res.Code)
	}
	if res.Header.Get("X-Backend") != "yes" {
		t.Errorf("response headers not captured: %v", res.Header)
	}
	if string(res.Body) != `{"ok":true}` {
		t.Errorf("response body = %q", res.Body)
	}
	if res.URL != backend.URL+"/api/v2/alerts?x=1" {
		t.Errorf("res.URL = %q", res.URL)
	}
}

func TestPreserveHost(t *testing.T) {
	var gotHost string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
	}))
	defer backend.Close()

	f := newForwarder(t, backend.URL, func(o *Options) { o.PreserveHost = true })
	r := httptest.NewRequest(http.MethodGet, "http://original.example.com/x", nil)
	res := f.Do(r, nil, "1.2.3.4", "http")
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if gotHost != "original.example.com" {
		t.Errorf("Host = %q, want original.example.com", gotHost)
	}
	if res.SentHost != "original.example.com" {
		t.Errorf("SentHost = %q", res.SentHost)
	}
}

func TestBasePathJoin(t *testing.T) {
	var gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
	}))
	defer backend.Close()

	f := newForwarder(t, backend.URL+"/base/", nil)
	r := httptest.NewRequest(http.MethodGet, "/sub/path", nil)
	if res := f.Do(r, nil, "", "http"); res.Err != nil {
		t.Fatal(res.Err)
	}
	if gotPath != "/base/sub/path" {
		t.Errorf("path = %q, want /base/sub/path", gotPath)
	}
}

func TestXFFAppends(t *testing.T) {
	var gotXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
	}))
	defer backend.Close()

	f := newForwarder(t, backend.URL, nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	if res := f.Do(r, nil, "203.0.113.7", "https"); res.Err != nil {
		t.Fatal(res.Err)
	}
	if gotXFF != "198.51.100.1, 203.0.113.7" {
		t.Errorf("XFF = %q", gotXFF)
	}
}

func TestPercentEncodedPathPreserved(t *testing.T) {
	var gotRequestURI string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequestURI = r.RequestURI
	}))
	defer backend.Close()

	f := newForwarder(t, backend.URL+"/base/", nil)
	r := httptest.NewRequest(http.MethodGet, "/segment%2Fwith%2Fslash", nil)
	if res := f.Do(r, nil, "", "http"); res.Err != nil {
		t.Fatal(res.Err)
	}
	if gotRequestURI != "/base/segment%2Fwith%2Fslash" {
		t.Errorf("RequestURI = %q, want the escaped path preserved byte-for-byte", gotRequestURI)
	}
}

func TestXFFMultiLinePreserved(t *testing.T) {
	var gotXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotXFF = r.Header.Get("X-Forwarded-For")
	}))
	defer backend.Close()

	f := newForwarder(t, backend.URL, nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	// Two separate header lines, not one comma-joined value.
	r.Header.Add("X-Forwarded-For", "198.51.100.1")
	r.Header.Add("X-Forwarded-For", "198.51.100.2")
	if res := f.Do(r, nil, "203.0.113.7", "https"); res.Err != nil {
		t.Fatal(res.Err)
	}
	if gotXFF != "198.51.100.1, 198.51.100.2, 203.0.113.7" {
		t.Errorf("XFF = %q, want every prior line preserved plus the peer appended", gotXFF)
	}
}

func TestHopByHopStripped(t *testing.T) {
	var got http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
	}))
	defer backend.Close()

	f := newForwarder(t, backend.URL, nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Connection", "close, X-Conn-Named")
	r.Header.Set("X-Conn-Named", "drop-me")
	r.Header.Set("Te", "trailers")
	r.Header.Set("Upgrade", "h2c")
	r.Header.Set("X-Keep", "yes")
	if res := f.Do(r, nil, "", "http"); res.Err != nil {
		t.Fatal(res.Err)
	}
	for _, name := range []string{"X-Conn-Named", "Te", "Upgrade"} {
		if got.Get(name) != "" {
			t.Errorf("%s should have been stripped", name)
		}
	}
	if got.Get("X-Keep") != "yes" {
		t.Error("X-Keep should have been relayed")
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://elsewhere.example.com/", http.StatusFound)
	}))
	defer backend.Close()

	f := newForwarder(t, backend.URL, nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	res := f.Do(r, nil, "", "http")
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if res.Code != http.StatusFound {
		t.Errorf("code = %d, want 302 relayed as-is", res.Code)
	}
	if res.Header.Get("Location") != "http://elsewhere.example.com/" {
		t.Errorf("Location = %q", res.Header.Get("Location"))
	}
}

func TestUpstreamError(t *testing.T) {
	f := newForwarder(t, "http://127.0.0.1:1", nil) // nothing listens on port 1
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	res := f.Do(r, nil, "", "http")
	if res.Err == nil {
		t.Fatal("expected connection error")
	}
}

func TestTimeout(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer backend.Close()

	f := newForwarder(t, backend.URL, func(o *Options) { o.Timeout = 50 * time.Millisecond })
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	res := f.Do(r, nil, "", "http")
	if res.Err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestCompressedBodyPassthrough(t *testing.T) {
	// With DisableCompression the backend's Content-Encoding survives and the
	// body is relayed byte-for-byte.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") == "gzip" {
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write([]byte("raw-gzip-bytes"))
			return
		}
		_, _ = w.Write([]byte("plain"))
	}))
	defer backend.Close()

	f := newForwarder(t, backend.URL, nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	res := f.Do(r, nil, "", "http")
	if res.Err != nil {
		t.Fatal(res.Err)
	}
	if res.Header.Get("Content-Encoding") != "gzip" || string(res.Body) != "raw-gzip-bytes" {
		t.Errorf("passthrough broken: enc=%q body=%q", res.Header.Get("Content-Encoding"), res.Body)
	}
}

func TestJoinPath(t *testing.T) {
	cases := []struct{ base, path, want string }{
		{"", "/x", "/x"},
		{"/", "/x", "/x"},
		{"/base", "/x", "/base/x"},
		{"/base/", "/x", "/base/x"},
		{"/base", "", "/base"},
	}
	for _, tc := range cases {
		if got := joinPath(tc.base, tc.path); got != tc.want {
			t.Errorf("joinPath(%q, %q) = %q, want %q", tc.base, tc.path, got, tc.want)
		}
	}
}
