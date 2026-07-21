// Package forward relays requests to a remote server and captures the
// remote responses so they can be dumped before being relayed back to the
// original client (docs/specification.md §7).
package forward

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// hopByHopHeaders are never relayed in either direction (RFC 9110 §7.6.1).
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// Forwarder relays requests to a fixed target URL.
type Forwarder struct {
	target       *url.URL
	client       *http.Client
	preserveHost bool
}

// Options configures a Forwarder.
type Options struct {
	Target       *url.URL
	Timeout      time.Duration
	SkipVerify   bool
	PreserveHost bool
}

// Result is the outcome of one relayed exchange. On success Status, Header,
// and Body describe the full remote response; on failure Err is set.
type Result struct {
	// URL is the effective upstream URL the request was sent to.
	URL string
	// SentHeader is the header set actually relayed upstream (post rewrite).
	SentHeader http.Header
	// SentHost is the Host header used for the upstream request.
	SentHost string
	Proto    string
	Status   string
	Code     int
	Header   http.Header
	Body     []byte
	Err      error
}

// New builds a Forwarder.
func New(opts Options) *Forwarder {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true // relay bodies byte-for-byte
	if opts.SkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- explicit diagnostic opt-in
	}
	return &Forwarder{
		target:       opts.Target,
		preserveHost: opts.PreserveHost,
		client: &http.Client{
			Transport: transport,
			Timeout:   opts.Timeout,
			// Redirects are relayed to the client, not followed.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Do relays the request (with its fully buffered body) to the target and
// returns the captured remote response. peerIP is the direct peer's address
// appended to X-Forwarded-For; scheme is the original listener's scheme.
func (f *Forwarder) Do(r *http.Request, body []byte, peerIP, scheme string) *Result {
	target := *f.target
	target.Path, target.RawPath = joinURLPath(f.target, r.URL)
	target.RawQuery = r.URL.RawQuery
	res := &Result{URL: target.String()}

	out, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		res.Err = err
		return res
	}

	out.Header = relayHeader(r.Header)
	if f.preserveHost {
		out.Host = r.Host
	}
	if peerIP != "" {
		// Values() sees every X-Forwarded-For header line, so multi-line
		// chains are preserved when the peer is appended (spec §7.1).
		chain := append(r.Header.Values("X-Forwarded-For"), peerIP)
		out.Header.Set("X-Forwarded-For", strings.Join(chain, ", "))
	}
	if out.Header.Get("X-Forwarded-Proto") == "" {
		out.Header.Set("X-Forwarded-Proto", scheme)
	}
	if out.Header.Get("X-Forwarded-Host") == "" {
		out.Header.Set("X-Forwarded-Host", r.Host)
	}
	res.SentHeader = out.Header
	res.SentHost = out.Host
	if res.SentHost == "" {
		res.SentHost = target.Host
	}

	resp, err := f.client.Do(out) // #nosec G704 -- the target is the operator-configured FORWARD_URL, never taken from the request
	if err != nil {
		res.Err = err
		return res
	}
	defer func() { _ = resp.Body.Close() }()

	// The remote response is fully read (and thus dumpable) before being
	// relayed back to the original client.
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		res.Err = err
		return res
	}
	res.Proto = resp.Proto
	res.Status = resp.Status
	res.Code = resp.StatusCode
	res.Header = relayHeader(resp.Header)
	res.Body = respBody
	return res
}

// relayHeader copies a header set minus hop-by-hop headers, including those
// named by the Connection header.
func relayHeader(in http.Header) http.Header {
	out := in.Clone()
	for _, value := range in.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			if name = strings.TrimSpace(name); name != "" {
				out.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		out.Del(name)
	}
	return out
}

func joinPath(base, path string) string {
	switch {
	case base == "" || base == "/":
		return path
	case path == "":
		return base
	default:
		return strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(path, "/")
	}
}

// joinURLPath joins the target base path with the request path, preserving
// the request's percent-encoding (RawPath) so escaped segments like %2F are
// relayed byte-for-byte (spec §7.1).
func joinURLPath(base, req *url.URL) (path, rawPath string) {
	path = joinPath(base.Path, req.Path)
	if base.RawPath == "" && req.RawPath == "" {
		return path, ""
	}
	return path, joinPath(base.EscapedPath(), req.EscapedPath())
}
