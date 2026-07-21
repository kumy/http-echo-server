package echo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCaptureBasics(t *testing.T) {
	r := httptest.NewRequest(http.MethodPut, "http://echo.example.com:8080/hello?foo=bar&multi=1&multi=2", strings.NewReader("aaa=bbb"))
	r.Header.Set("Arbitrary", "Header")
	r.Header.Add("X-Multi", "one")
	r.Header.Add("X-Multi", "two")
	r.RemoteAddr = "203.0.113.7:55555"

	resp := Capture(r, []byte("aaa=bbb"), false, false, Options{Proxies: NewProxyChecker(nil)})

	if resp.Path != "/hello" || resp.Method != http.MethodPut {
		t.Errorf("path/method wrong: %+v", resp)
	}
	if resp.Protocol != "http" || resp.HTTPVersion != "1.1" {
		t.Errorf("protocol/version wrong: %s %s", resp.Protocol, resp.HTTPVersion)
	}
	if resp.Host != "echo.example.com:8080" || resp.Hostname != "echo.example.com" {
		t.Errorf("host wrong: %s / %s", resp.Host, resp.Hostname)
	}
	if resp.IP != "203.0.113.7" {
		t.Errorf("ip = %q", resp.IP)
	}
	if resp.Query["foo"] != "bar" {
		t.Errorf("query foo = %v", resp.Query["foo"])
	}
	if multi, ok := resp.Query["multi"].([]string); !ok || len(multi) != 2 {
		t.Errorf("query multi = %v", resp.Query["multi"])
	}
	if resp.Body != "aaa=bbb" || resp.BodyTruncated {
		t.Errorf("body wrong: %q truncated=%v", resp.Body, resp.BodyTruncated)
	}
	if resp.Connection != nil {
		t.Error("connection must be nil for plaintext requests")
	}
	if resp.OS == nil || resp.OS.Hostname == "" {
		t.Error("os.hostname missing")
	}
}

func TestCaptureHeaderCase(t *testing.T) {
	// Headers must be echoed in canonical HTTP case, never lower-cased
	// (spec §6.6), and repeated headers become arrays.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("content-type", "text/plain")
	r.Header.Add("x-multi", "a")
	r.Header.Add("X-MULTI", "b")

	resp := Capture(r, nil, false, false, Options{})
	if _, ok := resp.Headers["content-type"]; ok {
		t.Error("headers must not be lower-cased")
	}
	if got := resp.Headers["Content-Type"]; got != "text/plain" {
		t.Errorf("Content-Type = %v", got)
	}
	if vals, ok := resp.Headers["X-Multi"].([]string); !ok || len(vals) != 2 {
		t.Errorf("X-Multi = %v", resp.Headers["X-Multi"])
	}
	if resp.Headers["Host"] != "example.com" {
		t.Errorf("Host header missing: %v", resp.Headers["Host"])
	}
}

func TestCaptureJSONBody(t *testing.T) {
	body := []byte(`{"aaa":"bbb"}`)
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json; charset=utf-8")

	resp := Capture(r, body, false, false, Options{})
	parsed, ok := resp.JSON.(map[string]any)
	if !ok || parsed["aaa"] != "bbb" {
		t.Errorf("json = %v", resp.JSON)
	}

	// Broken JSON: body still echoed, json omitted.
	r2 := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{broken"))
	r2.Header.Set("Content-Type", "application/json")
	resp2 := Capture(r2, []byte("{broken"), false, false, Options{})
	if resp2.JSON != nil {
		t.Errorf("json should be omitted on parse failure, got %v", resp2.JSON)
	}
	if resp2.Body != "{broken" {
		t.Errorf("body = %q", resp2.Body)
	}
}

func TestCaptureTruncatedFlag(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("full body"))
	resp := Capture(r, []byte("full"), true, false, Options{})
	if !resp.BodyTruncated {
		t.Error("bodyTruncated must be set")
	}
}

func TestCaptureCookies(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Cookie", "session=abc123; theme=dark")
	resp := Capture(r, nil, false, false, Options{})
	if resp.Cookies["session"] != "abc123" || resp.Cookies["theme"] != "dark" {
		t.Errorf("cookies = %v", resp.Cookies)
	}
}

func TestCaptureTLSAndClientCert(t *testing.T) {
	cert := makeCert(t)
	r := httptest.NewRequest(http.MethodGet, "https://localhost/", nil)
	r.TLS = &tls.ConnectionState{
		ServerName:         "echo.example.com",
		NegotiatedProtocol: "h2",
		Version:            tls.VersionTLS13,
		CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates:   []*x509.Certificate{cert},
	}

	resp := Capture(r, nil, false, true, Options{})
	if resp.Protocol != "https" {
		t.Errorf("protocol = %q", resp.Protocol)
	}
	conn := resp.Connection
	if conn == nil || conn.ServerName != "echo.example.com" || conn.ALPN != "h2" || conn.TLSVersion != "TLS1.3" {
		t.Errorf("connection = %+v", conn)
	}
	cc := resp.ClientCert
	if cc == nil {
		t.Fatal("clientCertificate missing")
	}
	if !strings.Contains(cc.Subject, "CN=my-client") {
		t.Errorf("subject = %q", cc.Subject)
	}
	if cc.FingerprintSHA256 == "" || !strings.Contains(cc.FingerprintSHA256, ":") {
		t.Errorf("fingerprint = %q", cc.FingerprintSHA256)
	}
	if len(cc.DNSNames) != 1 || cc.DNSNames[0] != "client.example.com" {
		t.Errorf("dnsNames = %v", cc.DNSNames)
	}
}

func TestCaptureEnvRedaction(t *testing.T) {
	env := captureEnv([]string{"HOME=/home/x", "VAULT_TOKEN=hvs.secret", "COOKIE_SECRET=abc"})
	if env["HOME"] != "/home/x" {
		t.Errorf("HOME = %q", env["HOME"])
	}
	if env["VAULT_TOKEN"] != "***" || env["COOKIE_SECRET"] != "***" {
		t.Errorf("secrets not redacted: %v", env)
	}
}

func TestRender(t *testing.T) {
	resp := &Response{Path: "/x", Method: "GET"}
	out := resp.Render()
	if !strings.HasPrefix(string(out), "{\n  \"path\": \"/x\"") {
		t.Errorf("render not pretty-printed: %q", out)
	}
	if !strings.HasSuffix(string(out), "\n") {
		t.Error("render must end with newline")
	}
	var check map[string]any
	if err := json.Unmarshal(out, &check); err != nil {
		t.Fatalf("render is not valid JSON: %v", err)
	}
	if _, ok := check["body"]; ok {
		t.Error("empty fields must be omitted")
	}
}

func TestProxyResolve(t *testing.T) {
	checker := NewProxyChecker(nil)

	// Direct connection from an untrusted peer: XFF is ignored.
	ip, ips := checker.Resolve("203.0.113.7:1234", []string{"1.2.3.4"})
	if ip != "203.0.113.7" || ips != nil {
		t.Errorf("untrusted peer: ip=%q ips=%v", ip, ips)
	}

	// Trusted peer: walk right-to-left to the first untrusted hop.
	ip, ips = checker.Resolve("10.0.0.3:1234", []string{"203.0.113.7, 10.0.0.2"})
	if ip != "203.0.113.7" {
		t.Errorf("ip = %q, want 203.0.113.7", ip)
	}
	if len(ips) != 2 || ips[0] != "203.0.113.7" || ips[1] != "10.0.0.2" {
		t.Errorf("ips = %v", ips)
	}

	// Entirely trusted chain: leftmost entry wins.
	ip, _ = checker.Resolve("127.0.0.1:9", []string{"192.168.1.5, 10.0.0.2"})
	if ip != "192.168.1.5" {
		t.Errorf("ip = %q, want 192.168.1.5", ip)
	}

	// Multiple XFF header values are concatenated in order.
	ip, ips = checker.Resolve("127.0.0.1:9", []string{"198.51.100.9", "10.1.1.1"})
	if ip != "198.51.100.9" || len(ips) != 2 {
		t.Errorf("multi-header: ip=%q ips=%v", ip, ips)
	}

	// IPv6 loopback peer.
	ip, _ = checker.Resolve("[::1]:9", []string{"203.0.113.9"})
	if ip != "203.0.113.9" {
		t.Errorf("ipv6 peer: ip=%q", ip)
	}
}

func TestProxyCheckerExtra(t *testing.T) {
	extra := NewProxyChecker([]netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")})
	if !extra.Trusted("203.0.113.7") {
		t.Error("extra range should be trusted")
	}
	if extra.Trusted("198.51.100.1") {
		t.Error("unrelated range must not be trusted")
	}
}

func TestDecodeJWT(t *testing.T) {
	token := makeJWT(t, map[string]any{"alg": "HS256", "typ": "JWT"}, map[string]any{"sub": "1234", "name": "John Doe"})

	for _, value := range []string{token, "Bearer " + token, "bearer " + token} {
		jwt := DecodeJWT(value)
		if jwt == nil {
			t.Fatalf("DecodeJWT(%q) = nil", value)
		}
		header := jwt.Header.(map[string]any)
		payload := jwt.Payload.(map[string]any)
		if header["alg"] != "HS256" || payload["sub"] != "1234" {
			t.Errorf("decoded = %+v", jwt)
		}
	}

	for _, bad := range []string{"", "not-a-jwt", "a.b", "!!!.###.$$$", "Bearer"} {
		if got := DecodeJWT(bad); got != nil {
			t.Errorf("DecodeJWT(%q) = %+v, want nil", bad, got)
		}
	}
}

func TestSignedCookies(t *testing.T) {
	secret := "keyboard cat"
	signed := signCookie("kumy", secret)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Cookie", "user="+url.QueryEscape(signed)+"; plain=x; forged="+url.QueryEscape("s:evil.AAAA"))
	resp := Capture(r, nil, false, false, Options{CookieSecret: secret})

	if resp.SignedCookies["user"] != "kumy" {
		t.Errorf("signedCookies = %v", resp.SignedCookies)
	}
	if _, ok := resp.SignedCookies["plain"]; ok {
		t.Error("unsigned cookie must not appear in signedCookies")
	}
	if _, ok := resp.SignedCookies["forged"]; ok {
		t.Error("forged signature must not verify")
	}
	// Raw values still visible under cookies.
	if resp.Cookies["plain"] != "x" {
		t.Errorf("cookies = %v", resp.Cookies)
	}
}

func TestSignedCookiesWithoutSecret(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Cookie", "user="+url.QueryEscape(signCookie("kumy", "s")))
	resp := Capture(r, nil, false, false, Options{})
	if resp.SignedCookies != nil {
		t.Error("signedCookies must be absent without COOKIE_SECRET")
	}
}

// --- helpers ---

func makeCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x0f32),
		Subject:      pkix.Name{CommonName: "my-client"},
		Issuer:       pkix.Name{CommonName: "some-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"client.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func makeJWT(t *testing.T, header, payload map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(p) + ".fakesig"
}

func signCookie(value, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value))
	sig := strings.TrimRight(base64.StdEncoding.EncodeToString(mac.Sum(nil)), "=")
	return "s:" + value + "." + sig
}
