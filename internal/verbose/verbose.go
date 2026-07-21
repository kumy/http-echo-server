// Package verbose prints exchanges in a curl -v-style trace
// (docs/specification.md §8): `*` for informational lines, `>`/`<` for the
// client leg, `>>`/`<<` for the upstream leg in forwarding mode.
package verbose

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Printer serializes exchange blocks onto a writer. Each exchange is written
// atomically so concurrent requests never interleave.
type Printer struct {
	mu      sync.Mutex
	w       io.Writer
	maxBody int64
	seq     atomic.Uint64
}

// New returns a Printer that truncates dumped bodies at maxBody bytes.
func New(w io.Writer, maxBody int64) *Printer {
	return &Printer{w: w, maxBody: maxBody}
}

// Exchange buffers one request/response trace until Flush.
type Exchange struct {
	p     *Printer
	id    uint64
	buf   bytes.Buffer
	start time.Time
}

// RequestInfo describes the incoming request for the trace header.
type RequestInfo struct {
	RemoteAddr string
	Scheme     string // "http" or "https"
	Proto      string // e.g. "HTTP/1.1"
	TLSVersion string // optional, e.g. "TLS1.3"
	SNI        string // optional
	Method     string
	RequestURI string // path + query
	Host       string
	Header     http.Header
	Body       []byte
}

// Start begins a new exchange block.
func (p *Printer) Start() *Exchange {
	return &Exchange{p: p, id: p.seq.Add(1), start: time.Now()}
}

// Request writes the incoming-request section (`>` prefix).
func (e *Exchange) Request(info RequestInfo) {
	conn := fmt.Sprintf("%s (%s", info.Scheme, info.Proto)
	if info.TLSVersion != "" {
		conn += ", " + info.TLSVersion
	}
	if info.SNI != "" {
		conn += ", SNI " + info.SNI
	}
	conn += ")"
	fmt.Fprintf(&e.buf, "* Request #%d: %s → %s\n", e.id, info.RemoteAddr, conn)
	e.section(">", fmt.Sprintf("%s %s %s", info.Method, info.RequestURI, info.Proto),
		info.Host, info.Header, info.Body)
}

// Forward writes the relayed upstream request (`>>` prefix).
func (e *Exchange) Forward(target, method, host string, header http.Header, body []byte) {
	fmt.Fprintf(&e.buf, "* Forwarding to %s\n", target)
	e.section(">>", fmt.Sprintf("%s %s", method, target), host, header, body)
}

// ForwardResponse writes the remote response (`<<` prefix).
func (e *Exchange) ForwardResponse(proto, status string, header http.Header, body []byte) {
	e.section("<<", fmt.Sprintf("%s %s", proto, status), "", header, body)
}

// ForwardError notes a failed upstream exchange.
func (e *Exchange) ForwardError(err error) {
	fmt.Fprintf(&e.buf, "* Forward error: %v\n", err)
}

// WebSocketUpgrade notes that the request upgraded to a WebSocket instead of
// receiving a response block.
func (e *Exchange) WebSocketUpgrade() {
	fmt.Fprintf(&e.buf, "* WebSocket upgrade\n")
}

// Response writes the client response section (`<` prefix) with the timing
// info line.
func (e *Exchange) Response(proto string, statusCode int, header http.Header, body []byte) {
	fmt.Fprintf(&e.buf, "* Response #%d: %d (%dms)\n", e.id, statusCode,
		time.Since(e.start).Milliseconds())
	// Non-standard codes (e.g. 499) have no status text; trim the gap.
	status := strings.TrimSpace(fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)))
	e.section("<", fmt.Sprintf("%s %s", proto, status), "", header, body)
}

// Flush writes the buffered block atomically.
func (e *Exchange) Flush() {
	e.p.mu.Lock()
	defer e.p.mu.Unlock()
	_, _ = e.p.w.Write(e.buf.Bytes())
}

// section renders one leg: first line, Host first, remaining headers sorted
// by name, a bare-prefix separator, then the body (truncated at maxBody).
func (e *Exchange) section(prefix, firstLine, host string, header http.Header, body []byte) {
	fmt.Fprintf(&e.buf, "%s %s\n", prefix, firstLine)
	if host != "" {
		fmt.Fprintf(&e.buf, "%s Host: %s\n", prefix, host)
	}
	names := make([]string, 0, len(header))
	for name := range header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, value := range header[name] {
			fmt.Fprintf(&e.buf, "%s %s: %s\n", prefix, name, value)
		}
	}
	fmt.Fprintf(&e.buf, "%s\n", prefix)

	truncated := false
	if e.p.maxBody > 0 && int64(len(body)) > e.p.maxBody {
		body = body[:e.p.maxBody]
		truncated = true
	}
	if len(body) > 0 {
		for _, line := range strings.Split(string(body), "\n") {
			fmt.Fprintf(&e.buf, "%s %s\n", prefix, strings.TrimSuffix(line, "\r"))
		}
	}
	if truncated {
		fmt.Fprintf(&e.buf, "* [body truncated]\n")
	}
}
