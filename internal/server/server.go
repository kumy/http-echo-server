// Package server wires the configuration into listeners, the routing
// handler, and graceful shutdown (docs/specification.md §5).
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/kumy/http-echo-server/internal/config"
	"github.com/kumy/http-echo-server/internal/forward"
	"github.com/kumy/http-echo-server/internal/metrics"
	"github.com/kumy/http-echo-server/internal/tlsmgr"
	"github.com/kumy/http-echo-server/internal/verbose"
)

// Server runs the plaintext and TLS listeners.
type Server struct {
	cfg   *config.Config
	log   *zap.Logger
	caPEM []byte

	httpSrv  *http.Server
	httpsSrv *http.Server
	tlsCfg   *tls.Config

	httpLn  net.Listener
	httpsLn net.Listener
}

// New builds the full server from configuration: metrics, verbose printer,
// forwarder, TLS material, and the two http.Servers.
func New(cfg *config.Config, logger *zap.Logger) (*Server, error) {
	var m *metrics.Metrics
	if cfg.PrometheusEnabled {
		logger.Info("prometheus metrics enabled",
			zap.String("path", cfg.PrometheusMetricsPath),
			zap.String("type", cfg.PrometheusMetricType))
		m = metrics.New(metrics.Options{
			WithMethod: cfg.PrometheusWithMethod,
			WithStatus: cfg.PrometheusWithStatus,
			WithPath:   cfg.PrometheusWithPath,
			MetricType: cfg.PrometheusMetricType,
		})
	}

	var vp *verbose.Printer
	if cfg.Verbose {
		logger.Info("verbose wire dump enabled")
		vp = verbose.New(os.Stdout, cfg.MaxBodySize)
	}

	var fwd *forward.Forwarder
	if cfg.ForwardTarget != nil {
		logger.Info("forwarding mode enabled",
			zap.String("target", cfg.ForwardTarget.String()),
			zap.Bool("preserveHost", cfg.ForwardPreserveHost),
			zap.Duration("timeout", cfg.ForwardTimeout),
			zap.Bool("skipVerify", cfg.ForwardSkipVerify))
		fwd = forward.New(forward.Options{
			Target:       cfg.ForwardTarget,
			Timeout:      cfg.ForwardTimeout,
			SkipVerify:   cfg.ForwardSkipVerify,
			PreserveHost: cfg.ForwardPreserveHost,
		})
	}

	s := &Server{cfg: cfg, log: logger}

	if cfg.HTTPSEnabled {
		logger.Debug("assembling TLS configuration", zap.String("mode", cfg.TLSMode))
		tlsRes, err := tlsmgr.Build(cfg, logger)
		if err != nil {
			return nil, err
		}
		s.tlsCfg = tlsRes.Config
		s.caPEM = tlsRes.CAPEM
	}

	handler := NewHandler(cfg, logger, m, vp, fwd, s.caPEM)

	httpHandler := handler.For(false)
	if cfg.HTTP2H2CEnabled {
		logger.Debug("h2c enabled on plaintext listener")
		httpHandler = h2c.NewHandler(httpHandler, &http2.Server{})
	}
	s.httpSrv = &http.Server{
		Handler:           httpHandler,
		MaxHeaderBytes:    cfg.MaxHeaderSize,
		ReadHeaderTimeout: 30 * time.Second,
	}
	s.httpsSrv = &http.Server{
		Handler:           handler.For(true),
		MaxHeaderBytes:    cfg.MaxHeaderSize,
		ReadHeaderTimeout: 30 * time.Second,
		TLSConfig:         s.tlsCfg,
	}
	if cfg.HTTPSEnabled && !cfg.HTTP2Enabled {
		// A non-nil empty map disables the stdlib's automatic h2 support.
		s.httpsSrv.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	}
	return s, nil
}

// CAPEM returns the CA chain for startup printing (nil in static mode).
func (s *Server) CAPEM() []byte {
	return s.caPEM
}

// Start binds the configured listeners; the effective addresses are logged
// (ports may be 0 in the config, spec §5).
func (s *Server) Start() error {
	if s.cfg.HTTPEnabled {
		addr := fmt.Sprintf("%s:%d", s.cfg.BindAddress, s.cfg.HTTPPort)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("binding plaintext listener on %s: %w", addr, err)
		}
		s.httpLn = ln
		s.log.Info("plaintext listener ready",
			zap.String("addr", ln.Addr().String()),
			zap.Bool("h2c", s.cfg.HTTP2H2CEnabled))
	}
	if s.cfg.HTTPSEnabled {
		addr := fmt.Sprintf("%s:%d", s.cfg.BindAddress, s.cfg.HTTPSPort)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("binding TLS listener on %s: %w", addr, err)
		}
		s.httpsLn = ln
		s.log.Info("TLS listener ready",
			zap.String("addr", ln.Addr().String()),
			zap.String("tlsMode", s.cfg.TLSMode),
			zap.Bool("http2", s.cfg.HTTP2Enabled),
			zap.Bool("mtls", s.cfg.MTLSEnable))
	}
	return nil
}

// HTTPAddr returns the bound plaintext address ("" when disabled/unbound).
func (s *Server) HTTPAddr() string {
	if s.httpLn == nil {
		return ""
	}
	return s.httpLn.Addr().String()
}

// HTTPSAddr returns the bound TLS address ("" when disabled/unbound).
func (s *Server) HTTPSAddr() string {
	if s.httpsLn == nil {
		return ""
	}
	return s.httpsLn.Addr().String()
}

// Run starts serving until ctx is cancelled, then drains gracefully for
// SHUTDOWN_TIMEOUT (spec §5). It returns nil on a clean shutdown.
func (s *Server) Run(ctx context.Context) error {
	if s.httpLn == nil && s.httpsLn == nil {
		if err := s.Start(); err != nil {
			return err
		}
	}

	errCh := make(chan error, 2)
	if s.httpLn != nil {
		go func() {
			s.log.Debug("serving plaintext listener", zap.String("addr", s.HTTPAddr()))
			if err := s.httpSrv.Serve(s.httpLn); !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("plaintext listener: %w", err)
			}
		}()
	}
	if s.httpsLn != nil {
		go func() {
			s.log.Debug("serving TLS listener", zap.String("addr", s.HTTPSAddr()))
			if err := s.httpsSrv.ServeTLS(s.httpsLn, "", ""); !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("TLS listener: %w", err)
			}
		}()
	}

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	s.log.Info("shutting down", zap.Duration("drainTimeout", s.cfg.ShutdownTimeout))
	shutdownCtx, cancel := context.WithTimeout(context.Background(), s.cfg.ShutdownTimeout)
	defer cancel()

	var shutdownErr error
	for _, srv := range []*http.Server{s.httpSrv, s.httpsSrv} {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			shutdownErr = err
		}
	}
	if shutdownErr != nil {
		s.log.Error("forced shutdown: connections did not drain in time", zap.Error(shutdownErr))
		return fmt.Errorf("forced shutdown: %w", shutdownErr)
	}
	s.log.Info("shutdown complete")
	return nil
}
