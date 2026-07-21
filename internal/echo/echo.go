// Package echo captures HTTP request properties into a Response structure
// rendered as JSON in the response body and in the request logs
// (docs/specification.md §6).
package echo

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

// Response is the echo object (spec §6.1). Field order follows the spec table.
type Response struct {
	Path          string            `json:"path,omitempty"`
	Query         map[string]any    `json:"query,omitempty"`
	Method        string            `json:"method,omitempty"`
	Protocol      string            `json:"protocol,omitempty"`
	HTTPVersion   string            `json:"httpVersion,omitempty"`
	Host          string            `json:"host,omitempty"`
	Hostname      string            `json:"hostname,omitempty"`
	IP            string            `json:"ip,omitempty"`
	IPs           []string          `json:"ips,omitempty"`
	Headers       map[string]any    `json:"headers,omitempty"`
	Cookies       map[string]string `json:"cookies,omitempty"`
	SignedCookies map[string]string `json:"signedCookies,omitempty"`
	Body          string            `json:"body,omitempty"`
	BodyTruncated bool              `json:"bodyTruncated,omitempty"`
	JSON          any               `json:"json,omitempty"`
	JWT           *JWT              `json:"jwt,omitempty"`
	ClientCert    *ClientCert       `json:"clientCertificate,omitempty"`
	Connection    *Connection       `json:"connection,omitempty"`
	OS            *OSInfo           `json:"os,omitempty"`
	Env           map[string]string `json:"env,omitempty"`
}

// Connection describes the TLS connection (TLS listener only).
type Connection struct {
	ServerName string `json:"servername,omitempty"`
	ALPN       string `json:"alpn,omitempty"`
	TLSVersion string `json:"tlsVersion,omitempty"`
	Cipher     string `json:"cipher,omitempty"`
}

// ClientCert describes the client certificate echoed under mTLS.
type ClientCert struct {
	Subject           string   `json:"subject,omitempty"`
	Issuer            string   `json:"issuer,omitempty"`
	Serial            string   `json:"serial,omitempty"`
	NotBefore         string   `json:"notBefore,omitempty"`
	NotAfter          string   `json:"notAfter,omitempty"`
	DNSNames          []string `json:"dnsNames,omitempty"`
	IPAddresses       []string `json:"ipAddresses,omitempty"`
	FingerprintSHA256 string   `json:"fingerprintSHA256,omitempty"`
}

// OSInfo carries the server machine details.
type OSInfo struct {
	Hostname string `json:"hostname,omitempty"`
}

// Options configures what Capture extracts.
type Options struct {
	JWTHeader    string
	CookieSecret string
	IncludeEnv   bool
	Proxies      *ProxyChecker
}

// envRedacted lists environment variables whose values are never echoed.
var envRedacted = map[string]bool{"VAULT_TOKEN": true, "COOKIE_SECRET": true}

// Capture builds the echo Response for a request. body is the (possibly
// truncated) request body; isTLS tells which listener received the request.
func Capture(r *http.Request, body []byte, bodyTruncated, isTLS bool, opts Options) *Response {
	resp := &Response{
		Path:          r.URL.Path,
		Query:         collapseValues(r.URL.Query()),
		Method:        r.Method,
		Protocol:      "http",
		HTTPVersion:   fmt.Sprintf("%d.%d", r.ProtoMajor, r.ProtoMinor),
		Host:          r.Host,
		Hostname:      stripPort(r.Host),
		Headers:       captureHeaders(r),
		Cookies:       captureCookies(r),
		Body:          string(body),
		BodyTruncated: bodyTruncated,
	}
	if isTLS {
		resp.Protocol = "https"
	}

	if opts.Proxies != nil {
		resp.IP, resp.IPs = opts.Proxies.Resolve(r.RemoteAddr, r.Header.Values("X-Forwarded-For"))
	}

	if ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err == nil && ct == "application/json" {
		var parsed any
		if json.Unmarshal(body, &parsed) == nil {
			resp.JSON = parsed
		}
	}

	if opts.JWTHeader != "" {
		resp.JWT = DecodeJWT(r.Header.Get(opts.JWTHeader))
	}
	if opts.CookieSecret != "" {
		resp.SignedCookies = verifySignedCookies(r.Cookies(), opts.CookieSecret)
	}

	if r.TLS != nil {
		resp.Connection = &Connection{
			ServerName: r.TLS.ServerName,
			ALPN:       r.TLS.NegotiatedProtocol,
			TLSVersion: TLSVersionName(r.TLS.Version),
			Cipher:     tls.CipherSuiteName(r.TLS.CipherSuite),
		}
		if len(r.TLS.PeerCertificates) > 0 {
			resp.ClientCert = captureClientCert(r.TLS.PeerCertificates[0])
		}
	}

	if hostname := serverHostname(); hostname != "" {
		resp.OS = &OSInfo{Hostname: hostname}
	}

	if opts.IncludeEnv {
		resp.Env = captureEnv(os.Environ())
	}
	return resp
}

// Render returns the pretty-printed JSON representation (2-space indent,
// trailing newline).
func (r *Response) Render() []byte {
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		// A Response is always marshalable; this is unreachable in practice.
		out = []byte(fmt.Sprintf("{%q: %q}", "error", err.Error()))
	}
	return append(out, '\n')
}

// CollapseHeader renders a header set with names in canonical HTTP case
// (spec §6.6): single values are strings, repeated values arrays. It is
// shared by the echo object and the forward log so both formats stay
// identical.
func CollapseHeader(header http.Header) map[string]any {
	if len(header) == 0 {
		return nil
	}
	out := make(map[string]any, len(header))
	for name, values := range header {
		out[name] = collapse(values)
	}
	return out
}

// captureHeaders returns the request headers plus the Host pseudo-header.
func captureHeaders(r *http.Request) map[string]any {
	headers := CollapseHeader(r.Header)
	if headers == nil {
		headers = make(map[string]any, 1)
	}
	if r.Host != "" {
		headers["Host"] = r.Host
	}
	return headers
}

// serverHostname caches os.Hostname, which cannot change for the process
// lifetime, to keep the syscall off the per-request path.
func serverHostname() string {
	hostnameOnce.Do(func() {
		hostname, err := os.Hostname()
		if err == nil {
			cachedHostname = hostname
		}
	})
	return cachedHostname
}

var (
	hostnameOnce   sync.Once
	cachedHostname string
)

func captureCookies(r *http.Request) map[string]string {
	cookies := r.Cookies()
	if len(cookies) == 0 {
		return nil
	}
	out := make(map[string]string, len(cookies))
	for _, c := range cookies {
		out[c.Name] = c.Value
	}
	return out
}

func captureClientCert(cert *x509.Certificate) *ClientCert {
	sum := sha256.Sum256(cert.Raw)
	ips := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}
	return &ClientCert{
		Subject:           cert.Subject.String(),
		Issuer:            cert.Issuer.String(),
		Serial:            colonHex(cert.SerialNumber.Bytes()),
		NotBefore:         cert.NotBefore.UTC().Format("2006-01-02T15:04:05Z"),
		NotAfter:          cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		DNSNames:          cert.DNSNames,
		IPAddresses:       ips,
		FingerprintSHA256: colonHex(sum[:]),
	}
}

func captureEnv(environ []string) map[string]string {
	env := make(map[string]string, len(environ))
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		if envRedacted[name] {
			value = "***"
		}
		env[name] = value
	}
	return env
}

func collapse(values []string) any {
	if len(values) == 1 {
		return values[0]
	}
	return values
}

func collapseValues(values map[string][]string) map[string]any {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]any, len(values))
	for key, vals := range values {
		out[key] = collapse(vals)
	}
	return out
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return strings.Trim(host, "[]")
}

func colonHex(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02X", x)
	}
	return strings.Join(parts, ":")
}

// TLSVersionName renders a TLS version in the spec's space-less form
// ("TLS1.3"), delegating the naming to the stdlib so new versions are
// covered automatically.
func TLSVersionName(v uint16) string {
	return strings.ReplaceAll(tls.VersionName(v), " ", "")
}
