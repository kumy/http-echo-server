package server

import (
	"net/http"
	"time"

	"github.com/coder/websocket"
	"go.uber.org/zap"

	"github.com/kumy/http-echo-server/internal/echo"
)

// handleWebSocket upgrades and echoes every message back (spec §6.5): the
// first server message is the JSON echo of the upgrade request, then each
// client message is mirrored unchanged.
func (h *Handler) handleWebSocket(rec *recorder, r *http.Request, isTLS bool, start time.Time) {
	ec := echo.Capture(r, nil, false, isTLS, h.echoOpts)

	if h.verbose != nil {
		ex := h.verbose.Start()
		ex.Request(requestInfo(r, isTLS, nil))
		ex.WebSocketUpgrade()
		ex.Flush()
	}

	// Accept writes the 101 through rec before hijacking, so the recorder
	// observes the real status for logs and metrics.
	conn, err := websocket.Accept(rec, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		h.log.Warn("websocket upgrade failed",
			zap.String("path", r.URL.Path), zap.Error(err))
		h.finish(r, ec, rec, isTLS, start, nil, false)
		return
	}
	h.log.Debug("websocket connection established",
		zap.String("path", r.URL.Path), zap.String("remote", r.RemoteAddr))
	h.finish(r, ec, rec, isTLS, start, nil, false)

	// Every message is echoed unchanged regardless of size (spec §6.5), so
	// lift the library's default 32 KiB message limit.
	conn.SetReadLimit(-1)

	ctx := r.Context()
	defer conn.CloseNow() //nolint:errcheck // best-effort teardown

	if err := conn.Write(ctx, websocket.MessageText, ec.Render()); err != nil {
		h.log.Debug("websocket initial echo write failed", zap.Error(err))
		return
	}

	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			status := websocket.CloseStatus(err)
			if status == websocket.StatusNormalClosure || status == websocket.StatusGoingAway {
				h.log.Debug("websocket closed by client",
					zap.String("remote", r.RemoteAddr), zap.Int("code", int(status)))
				// Mirror the close (spec §6.5).
				_ = conn.Close(status, "")
			} else {
				h.log.Debug("websocket read ended", zap.Error(err))
			}
			return
		}
		h.log.Debug("echoing websocket message",
			zap.Int("bytes", len(data)), zap.String("type", typ.String()))
		if err := conn.Write(ctx, typ, data); err != nil {
			h.log.Debug("websocket echo write failed", zap.Error(err))
			return
		}
	}
}
