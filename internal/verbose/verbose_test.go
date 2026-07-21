package verbose

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestEchoExchangeFormat(t *testing.T) {
	var out bytes.Buffer
	p := New(&out, 1<<20)

	ex := p.Start()
	ex.Request(RequestInfo{
		RemoteAddr: "127.0.0.1:53210",
		Scheme:     "http",
		Proto:      "HTTP/1.1",
		Method:     "POST",
		RequestURI: "/api?x=1",
		Host:       "localhost:8080",
		Header:     http.Header{"Content-Type": {"application/json"}, "Accept": {"*/*"}},
		Body:       []byte(`{"a":1}`),
	})
	ex.Response("HTTP/1.1", 200, http.Header{"Content-Type": {"application/json"}}, []byte("{}"))
	ex.Flush()

	got := out.String()
	wantLines := []string{
		"* Request #1: 127.0.0.1:53210 → http (HTTP/1.1)",
		"> POST /api?x=1 HTTP/1.1",
		"> Host: localhost:8080",
		"> Accept: */*",
		"> Content-Type: application/json",
		">",
		`> {"a":1}`,
		"< HTTP/1.1 200 OK",
		"< Content-Type: application/json",
		"<",
		"< {}",
	}
	for _, line := range wantLines {
		if !strings.Contains(got, line+"\n") {
			t.Errorf("output missing line %q\n--- got:\n%s", line, got)
		}
	}
	if !strings.Contains(got, "* Response #1: 200 (") {
		t.Errorf("missing response info line:\n%s", got)
	}
	// Host must come before the sorted headers.
	if strings.Index(got, "> Host:") > strings.Index(got, "> Accept:") {
		t.Error("Host must be printed first")
	}
}

func TestTLSRequestInfoLine(t *testing.T) {
	var out bytes.Buffer
	p := New(&out, 1<<20)
	ex := p.Start()
	ex.Request(RequestInfo{
		RemoteAddr: "10.0.0.1:1",
		Scheme:     "https",
		Proto:      "HTTP/2.0",
		TLSVersion: "TLS1.3",
		SNI:        "echo.example.com",
		Method:     "GET",
		RequestURI: "/",
		Host:       "echo.example.com",
	})
	ex.Flush()
	if !strings.Contains(out.String(), "→ https (HTTP/2.0, TLS1.3, SNI echo.example.com)") {
		t.Errorf("info line wrong:\n%s", out.String())
	}
}

func TestForwardLeg(t *testing.T) {
	var out bytes.Buffer
	p := New(&out, 1<<20)
	ex := p.Start()
	ex.Forward("http://backend:9093/api", "POST", "backend:9093",
		http.Header{"Content-Type": {"application/json"}}, []byte("[1]"))
	ex.ForwardResponse("HTTP/1.1", "200 OK", http.Header{"Server": {"am"}}, []byte(`{"ok":true}`))
	ex.Flush()

	got := out.String()
	for _, line := range []string{
		"* Forwarding to http://backend:9093/api",
		">> POST http://backend:9093/api",
		">> Host: backend:9093",
		">> Content-Type: application/json",
		">>",
		">> [1]",
		"<< HTTP/1.1 200 OK",
		"<< Server: am",
		"<<",
		`<< {"ok":true}`,
	} {
		if !strings.Contains(got, line+"\n") {
			t.Errorf("missing %q in:\n%s", line, got)
		}
	}
}

func TestForwardErrorAndWebSocket(t *testing.T) {
	var out bytes.Buffer
	p := New(&out, 1<<20)
	ex := p.Start()
	ex.ForwardError(errors.New("connection refused"))
	ex.WebSocketUpgrade()
	ex.Flush()
	if !strings.Contains(out.String(), "* Forward error: connection refused") {
		t.Errorf("missing forward error:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "* WebSocket upgrade") {
		t.Errorf("missing websocket marker:\n%s", out.String())
	}
}

func TestBodyTruncation(t *testing.T) {
	var out bytes.Buffer
	p := New(&out, 4)
	ex := p.Start()
	ex.Request(RequestInfo{
		RemoteAddr: "1.2.3.4:5", Scheme: "http", Proto: "HTTP/1.1",
		Method: "POST", RequestURI: "/", Host: "h",
		Body: []byte("0123456789"),
	})
	ex.Flush()
	got := out.String()
	if !strings.Contains(got, "> 0123\n") {
		t.Errorf("body not truncated at maxBody:\n%s", got)
	}
	if strings.Contains(got, "0123456789") {
		t.Errorf("full body leaked:\n%s", got)
	}
	if !strings.Contains(got, "* [body truncated]") {
		t.Errorf("missing truncation marker:\n%s", got)
	}
}

func TestMultilineAndCRLFBody(t *testing.T) {
	var out bytes.Buffer
	p := New(&out, 1<<20)
	ex := p.Start()
	ex.Request(RequestInfo{
		RemoteAddr: "1.2.3.4:5", Scheme: "http", Proto: "HTTP/1.1",
		Method: "POST", RequestURI: "/", Host: "h",
		Body: []byte("line1\r\nline2"),
	})
	ex.Flush()
	got := out.String()
	if !strings.Contains(got, "> line1\n> line2\n") {
		t.Errorf("multi-line body wrong:\n%s", got)
	}
}

func TestResponseNonStandardStatusNoTrailingSpace(t *testing.T) {
	var out bytes.Buffer
	p := New(&out, 1<<20)
	ex := p.Start()
	ex.Response("HTTP/1.1", 499, nil, nil)
	ex.Flush()

	got := out.String()
	if !strings.Contains(got, "< HTTP/1.1 499\n") {
		t.Errorf("status line must have no trailing space for a code with no http.StatusText:\n%s", got)
	}
	if strings.Contains(got, "499 \n") {
		t.Errorf("trailing space leaked before newline:\n%s", got)
	}
}

func TestSequenceAndAtomicity(t *testing.T) {
	var out bytes.Buffer
	p := New(&out, 1<<20)

	first := p.Start()
	second := p.Start()
	if first.id+1 != second.id {
		t.Errorf("ids not sequential: %d, %d", first.id, second.id)
	}

	// Concurrent flushes must not interleave: every line carries a prefix.
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ex := p.Start()
			ex.Request(RequestInfo{
				RemoteAddr: "1.1.1.1:1", Scheme: "http", Proto: "HTTP/1.1",
				Method: "GET", RequestURI: "/", Host: "h", Body: []byte("b"),
			})
			ex.Flush()
		}()
	}
	wg.Wait()

	for _, line := range strings.Split(strings.TrimRight(out.String(), "\n"), "\n") {
		if !strings.HasPrefix(line, "*") && !strings.HasPrefix(line, ">") {
			t.Fatalf("interleaved/malformed line: %q", line)
		}
	}
}
