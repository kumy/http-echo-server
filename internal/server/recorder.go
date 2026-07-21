package server

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"net/http"
)

// StatusClientClosedRequest marks requests aborted by the client before a
// response was written (nginx's 499 convention); it appears in logs and
// metrics only, never on the wire.
const StatusClientClosedRequest = 499

// recorder wraps a ResponseWriter to capture the status code and, when the
// verbose dump needs it, a bounded copy of the body.
type recorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	body        bytes.Buffer
	bodyCap     int64 // 0 disables body capture (verbose off)
}

func newRecorder(w http.ResponseWriter, bodyCap int64) *recorder {
	return &recorder{ResponseWriter: w, bodyCap: bodyCap}
}

func (rec *recorder) WriteHeader(code int) {
	if rec.wroteHeader {
		return
	}
	rec.wroteHeader = true
	rec.status = code
	rec.ResponseWriter.WriteHeader(code)
}

func (rec *recorder) Write(b []byte) (int, error) {
	if !rec.wroteHeader {
		rec.WriteHeader(http.StatusOK)
	}
	if remaining := rec.bodyCap - int64(rec.body.Len()); remaining > 0 {
		if int64(len(b)) > remaining {
			rec.body.Write(b[:remaining])
		} else {
			rec.body.Write(b)
		}
	}
	return rec.ResponseWriter.Write(b) // #nosec G705 -- reflecting request data is this server's purpose; echoes are JSON-encoded
}

// abort records a status for a request that got no response (e.g. the client
// disconnected during a shaped delay) without touching the wire.
func (rec *recorder) abort(code int) {
	if !rec.wroteHeader {
		rec.wroteHeader = true
		rec.status = code
	}
}

// Status returns the response status, defaulting to 200 as net/http does.
func (rec *recorder) Status() int {
	if rec.wroteHeader {
		return rec.status
	}
	return http.StatusOK
}

// BodyBytes returns the captured (bounded) response body.
func (rec *recorder) BodyBytes() []byte {
	return rec.body.Bytes()
}

func (rec *recorder) Flush() {
	if f, ok := rec.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack lets WebSocket upgrades take over the underlying connection.
func (rec *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rec.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, errors.New("http.Hijacker not supported by underlying ResponseWriter")
}

// Unwrap supports http.ResponseController passthrough.
func (rec *recorder) Unwrap() http.ResponseWriter {
	return rec.ResponseWriter
}
