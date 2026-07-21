package server

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/http/httpguts"

	"github.com/kumy/http-echo-server/internal/config"
	"github.com/kumy/http-echo-server/internal/echo"
	"github.com/kumy/http-echo-server/internal/forward"
	"github.com/kumy/http-echo-server/internal/metrics"
	"github.com/kumy/http-echo-server/internal/verbose"
)

// Shaping parameter names (spec §6.3).
const (
	headerStatusCode  = "X-Set-Response-Status-Code"
	headerContentType = "X-Set-Response-Content-Type"
	headerDelayMS     = "X-Set-Response-Delay-Ms"
	queryBodyOnly     = "response_body_only"
)

// Handler routes requests: reserved paths, WebSocket echo, forwarding, or
// the JSON echo (spec §6.4, §6.5, §7).
type Handler struct {
	cfg     *config.Config
	log     *zap.Logger
	metrics *metrics.Metrics   // nil when disabled
	verbose *verbose.Printer   // nil when disabled
	fwd     *forward.Forwarder // nil when not forwarding
	caPEM   []byte             // nil when unavailable

	echoOpts echo.Options
	// dumpCap is the recorder body-capture bound: one byte beyond
	// MAX_BODY_SIZE so the verbose printer can detect truncation, or 0 when
	// verbose is off and capturing would be dead work.
	dumpCap     int64
	corsOrigins []string // trimmed allow-list; nil when CORS is off
	corsAll     bool
}

// NewHandler assembles the request handler.
func NewHandler(cfg *config.Config, log *zap.Logger, m *metrics.Metrics,
	vp *verbose.Printer, fwd *forward.Forwarder, caPEM []byte) *Handler {
	h := &Handler{
		cfg:     cfg,
		log:     log,
		metrics: m,
		verbose: vp,
		fwd:     fwd,
		caPEM:   caPEM,
		echoOpts: echo.Options{
			JWTHeader:    cfg.JWTHeader,
			CookieSecret: cfg.CookieSecret,
			IncludeEnv:   cfg.EchoIncludeEnvVars,
			Proxies:      echo.NewProxyChecker(cfg.ExtraTrustedProxies),
		},
	}
	if vp != nil {
		h.dumpCap = cfg.MaxBodySize + 1
	}
	if cfg.CORSAllowOrigin == "*" {
		h.corsAll = true
	} else {
		for _, origin := range strings.Split(cfg.CORSAllowOrigin, ",") {
			if origin = strings.TrimSpace(origin); origin != "" {
				h.corsOrigins = append(h.corsOrigins, origin)
			}
		}
	}
	return h
}

// For returns the http.Handler for one listener; isTLS selects the echoed
// protocol and verbose/forward scheme.
func (h *Handler) For(isTLS bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.serve(w, r, isTLS)
	})
}

// forwardLog is the `forward` object attached to request logs (spec §10).
type forwardLog struct {
	URL           string         `json:"url"`
	Status        int            `json:"status,omitempty"`
	Headers       map[string]any `json:"headers,omitempty"`
	Body          string         `json:"body,omitempty"`
	BodyTruncated bool           `json:"bodyTruncated,omitempty"`
	Error         string         `json:"error,omitempty"`
}

func (h *Handler) serve(w http.ResponseWriter, r *http.Request, isTLS bool) {
	start := time.Now()
	rec := newRecorder(w, h.dumpCap)

	// Reserved paths (spec §6.4): served locally, logged at debug, no dump.
	if h.metrics != nil && r.URL.Path == h.cfg.PrometheusMetricsPath {
		h.log.Debug("serving metrics endpoint", zap.String("path", r.URL.Path))
		h.metrics.Handler().ServeHTTP(rec, r)
		h.finish(r, nil, rec, isTLS, start, nil, true)
		return
	}
	if h.caPEM != nil && h.cfg.TLSCAEndpoint != "" && r.URL.Path == h.cfg.TLSCAEndpoint {
		h.log.Debug("serving CA certificate", zap.String("path", r.URL.Path))
		rec.Header().Set("Content-Type", "application/x-pem-file")
		rec.WriteHeader(http.StatusOK)
		_, _ = rec.Write(h.caPEM)
		h.finish(r, nil, rec, isTLS, start, nil, true)
		return
	}

	// WebSocket upgrades are handled locally even in forwarding mode (§6.5).
	if h.cfg.WSEnabled && isWebSocketUpgrade(r) {
		h.handleWebSocket(rec, r, isTLS, start)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, h.bodyLimit()))
	if err != nil {
		h.log.Warn("reading request body failed", zap.Error(err))
		http.Error(rec, "reading request body: "+err.Error(), http.StatusBadRequest)
		h.finish(r, nil, rec, isTLS, start, nil, false)
		return
	}
	echoBody, echoTruncated := capBody(body, h.cfg.MaxBodySize)

	ec := echo.Capture(r, echoBody, echoTruncated, isTLS, h.echoOpts)

	var ex *verbose.Exchange
	if h.verbose != nil {
		ex = h.verbose.Start()
		ex.Request(requestInfo(r, isTLS, body))
	}

	var fl *forwardLog
	if h.fwd != nil {
		fl = h.handleForward(rec, r, body, ex, isTLS)
	} else {
		h.handleEcho(rec, r, echoBody, ec)
	}

	if ex != nil {
		ex.Response(r.Proto, rec.Status(), rec.Header().Clone(), rec.BodyBytes())
		ex.Flush()
	}
	h.finish(r, ec, rec, isTLS, start, fl, false)
}

// handleForward relays the request and dumps the remote response before
// relaying it back (spec §7).
func (h *Handler) handleForward(rec *recorder, r *http.Request, body []byte,
	ex *verbose.Exchange, isTLS bool) *forwardLog {
	h.log.Debug("forwarding request",
		zap.String("method", r.Method),
		zap.String("path", r.URL.RequestURI()),
		zap.Int("bodyBytes", len(body)))

	res := h.fwd.Do(r, body, echo.PeerIP(r.RemoteAddr), scheme(isTLS))

	if ex != nil {
		ex.Forward(res.URL, r.Method, res.SentHost, res.SentHeader, body)
		if res.Err != nil {
			ex.ForwardError(res.Err)
		} else {
			ex.ForwardResponse(res.Proto, res.Status, res.Header, res.Body)
		}
	}

	fl := &forwardLog{URL: res.URL}
	if res.Err != nil {
		fl.Error = res.Err.Error()
		h.log.Error("forward failed", zap.String("url", res.URL), zap.Error(res.Err))
		rec.Header().Set("Content-Type", "application/json; charset=utf-8")
		rec.WriteHeader(http.StatusBadGateway)
		msg, _ := json.Marshal(map[string]string{"error": res.Err.Error(), "target": res.URL})
		_, _ = rec.Write(append(msg, '\n'))
		return fl
	}

	logBody, logTruncated := capBody(res.Body, h.cfg.MaxBodySize)
	fl.Status = res.Code
	fl.Headers = echo.CollapseHeader(res.Header)
	fl.Body = string(logBody)
	fl.BodyTruncated = logTruncated

	h.log.Debug("relaying remote response",
		zap.String("url", res.URL),
		zap.Int("status", res.Code),
		zap.Int("bodyBytes", len(res.Body)))

	dst := rec.Header()
	for name, values := range res.Header {
		dst[name] = values
	}
	rec.WriteHeader(res.Code)
	_, _ = rec.Write(res.Body)
	return fl
}

// handleEcho renders the JSON echo with response shaping and CORS
// (spec §6.1, §6.3). body is the echo-view request body (capped at
// MAX_BODY_SIZE), used for response_body_only.
func (h *Handler) handleEcho(rec *recorder, r *http.Request, body []byte, ec *echo.Response) {
	if (h.corsAll || h.corsOrigins != nil) && h.applyCORS(rec, r) {
		return
	}

	status := http.StatusOK
	if v := shapeValue(r, headerStatusCode); v != "" {
		if code, err := strconv.Atoi(v); err == nil && code >= 100 && code <= 599 {
			status = code
		} else {
			h.log.Warn("ignoring invalid x-set-response-status-code", zap.String("value", v))
		}
	}
	contentType := shapeValue(r, headerContentType)

	if !h.delay(r) {
		h.log.Debug("client disconnected during shaped delay",
			zap.String("path", r.URL.Path))
		rec.abort(StatusClientClosedRequest)
		return
	}

	var respBody []byte
	isJSON := false
	switch {
	case !h.cfg.EchoBackToClient:
		// Echo only to logs; empty response body.
	case h.cfg.OverrideResponseBodyFilePath != "":
		fileBody, err := os.ReadFile(h.cfg.OverrideResponseBodyFilePath) // #nosec G304 -- operator-configured path
		if err != nil {
			h.log.Warn("reading override response body file failed, echoing instead",
				zap.String("path", h.cfg.OverrideResponseBodyFilePath), zap.Error(err))
			respBody, isJSON = ec.Render(), true
		} else {
			respBody = fileBody
		}
	case r.URL.Query().Get(queryBodyOnly) == "true":
		respBody = body
	default:
		respBody, isJSON = ec.Render(), true
	}

	if contentType == "" && isJSON {
		contentType = "application/json; charset=utf-8"
	}
	if contentType != "" {
		rec.Header().Set("Content-Type", contentType)
	}
	rec.WriteHeader(status)
	_, _ = rec.Write(respBody)
}

// applyCORS adds the Access-Control-* headers; returns true when the request
// was an answered preflight.
func (h *Handler) applyCORS(rec *recorder, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	allowed := ""
	if h.corsAll {
		allowed = "*"
	} else if origin != "" {
		for _, candidate := range h.corsOrigins {
			if candidate == origin {
				allowed = origin
				rec.Header().Add("Vary", "Origin")
				break
			}
		}
	}
	if allowed != "" {
		rec.Header().Set("Access-Control-Allow-Origin", allowed)
		if h.cfg.CORSAllowCredentials {
			rec.Header().Set("Access-Control-Allow-Credentials", "true")
		}
	}

	if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
		methods := h.cfg.CORSAllowMethods
		if methods == "" {
			methods = "GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS"
		}
		rec.Header().Set("Access-Control-Allow-Methods", methods)
		headers := h.cfg.CORSAllowHeaders
		if headers == "" {
			headers = r.Header.Get("Access-Control-Request-Headers")
		}
		if headers != "" {
			rec.Header().Set("Access-Control-Allow-Headers", headers)
		}
		h.log.Debug("answered CORS preflight",
			zap.String("origin", origin),
			zap.String("requestMethod", r.Header.Get("Access-Control-Request-Method")))
		rec.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

// delay applies x-set-response-delay-ms; returns false when the client went
// away during the wait (spec §6.3).
func (h *Handler) delay(r *http.Request) bool {
	v := shapeValue(r, headerDelayMS)
	if v == "" {
		return true
	}
	ms, err := strconv.Atoi(v)
	if err != nil || ms < 0 {
		h.log.Warn("ignoring invalid x-set-response-delay-ms", zap.String("value", v))
		return true
	}
	if ms > config.MaxDelayMS {
		h.log.Debug("capping shaped delay",
			zap.Int("requestedMs", ms), zap.Int("cappedMs", config.MaxDelayMS))
		ms = config.MaxDelayMS
	}
	if ms == 0 {
		return true
	}
	h.log.Debug("delaying response", zap.Int("delayMs", ms), zap.String("path", r.URL.Path))
	timer := time.NewTimer(time.Duration(ms) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-r.Context().Done():
		return false
	}
}

// finish records the metrics observation and the request log for every
// handled request. ec may be nil (reserved paths, body-read failures); a
// minimal echo is then captured for the log. Reserved paths log at debug
// (spec §10).
func (h *Handler) finish(r *http.Request, ec *echo.Response, rec *recorder,
	isTLS bool, start time.Time, fl *forwardLog, reserved bool) {
	duration := time.Since(start)
	if h.metrics != nil {
		h.metrics.Observe(r.Method, r.URL.Path, rec.Status(), duration)
	}
	if h.cfg.DisableRequestLogs || h.ignored(r.URL.Path) {
		return
	}
	if ec == nil {
		ec = echo.Capture(r, nil, false, isTLS, h.echoOpts)
	}
	fields := []zap.Field{
		zap.Any("request", ec),
		zap.Int("status", rec.Status()),
		zap.Int64("durationMs", duration.Milliseconds()),
	}
	if fl != nil {
		fields = append(fields, zap.Any("forward", fl))
	}
	if reserved {
		h.log.Debug("request", fields...)
	} else {
		h.log.Info("request", fields...)
	}
}

func (h *Handler) ignored(path string) bool {
	for _, re := range h.cfg.LogIgnoreRegexps {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

func (h *Handler) bodyLimit() int64 {
	if h.fwd != nil {
		// Forwarding relays bodies byte-for-byte, so no cap (spec §7.1).
		return int64(1) << 40
	}
	return h.cfg.MaxBodySize + 1
}

// requestInfo builds the verbose trace header for the incoming request,
// shared by the HTTP and WebSocket paths.
func requestInfo(r *http.Request, isTLS bool, body []byte) verbose.RequestInfo {
	info := verbose.RequestInfo{
		RemoteAddr: r.RemoteAddr,
		Scheme:     scheme(isTLS),
		Proto:      r.Proto,
		Method:     r.Method,
		RequestURI: r.URL.RequestURI(),
		Host:       r.Host,
		Header:     r.Header,
		Body:       body,
	}
	if r.TLS != nil {
		info.TLSVersion = echo.TLSVersionName(r.TLS.Version)
		info.SNI = r.TLS.ServerName
	}
	return info
}

// shapeValue reads a shaping parameter from header or query; header wins.
func shapeValue(r *http.Request, name string) string {
	if v := r.Header.Get(name); v != "" {
		return v
	}
	return r.URL.Query().Get(strings.ToLower(name))
}

func capBody(body []byte, limit int64) ([]byte, bool) {
	if int64(len(body)) > limit {
		return body[:limit], true
	}
	return body, false
}

func scheme(isTLS bool) string {
	if isTLS {
		return "https"
	}
	return "http"
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		httpguts.HeaderValuesContainsToken(r.Header.Values("Connection"), "Upgrade")
}
