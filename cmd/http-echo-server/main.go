// Command http-echo-server echoes HTTP request properties back to the
// client — in the response body and in the logs — and can optionally
// forward requests to a remote server while dumping both legs of the
// exchange. See https://kumy.github.io/http-echo-server/.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/pflag"
	"go.uber.org/zap"

	"github.com/kumy/http-echo-server/internal/config"
	"github.com/kumy/http-echo-server/internal/logging"
	"github.com/kumy/http-echo-server/internal/server"
	"github.com/kumy/http-echo-server/internal/version"
)

// Exit codes (docs/specification.md §12).
const (
	exitOK      = 0
	exitRuntime = 1
	exitConfig  = 2
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	cfg, err := config.Load(args)
	if errors.Is(err, pflag.ErrHelp) {
		return exitOK
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		return exitConfig
	}
	if cfg.ShowVersion {
		fmt.Println("http-echo-server " + version.String())
		return exitOK
	}

	logger, err := logging.New(cfg.LogLevel, cfg.LogFormat)
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		return exitConfig
	}
	defer func() { _ = logger.Sync() }()

	logger.Info("starting http-echo-server",
		zap.String("version", version.Version),
		zap.String("commit", version.Commit),
		zap.String("built", version.Date),
		zap.String("tlsMode", cfg.TLSMode),
		zap.Bool("forwarding", cfg.ForwardTarget != nil),
		zap.Bool("verbose", cfg.Verbose),
	)
	if cfg.ConfigFile != "" {
		logger.Info("loaded config file", zap.String("path", cfg.ConfigFile))
	}

	srv, err := server.New(cfg, logger)
	if err != nil {
		logger.Error("startup failed", zap.Error(err))
		return exitRuntime
	}

	// Print the CA PEM to stdout so it is copy-pasteable regardless of the
	// log format (spec §9.3).
	if cfg.TLSCAPrint && cfg.HTTPSEnabled && len(srv.CAPEM()) > 0 {
		fmt.Println("CA certificate (import it or pass it to curl --cacert):")
		fmt.Print(string(srv.CAPEM()))
	}

	if err := srv.Start(); err != nil {
		logger.Error("startup failed", zap.Error(err))
		return exitRuntime
	}

	// SIGHUP is ignored: no config reload in v1 (spec §12).
	signal.Ignore(syscall.SIGHUP)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx); err != nil {
		logger.Error("server error", zap.Error(err))
		return exitRuntime
	}
	return exitOK
}
