// Package tlsmgr assembles the *tls.Config for the TLS listener, dispatching
// certificate issuance per TLS_MODE (docs/specification.md §9).
package tlsmgr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"go.uber.org/zap"

	"github.com/kumy/https-echo-server/internal/config"
	"github.com/kumy/https-echo-server/internal/tlsmgr/autoca"
	"github.com/kumy/https-echo-server/internal/tlsmgr/vaultpki"
)

// Result is the assembled TLS material.
type Result struct {
	// Config is ready for the TLS listener (nil when HTTPS is disabled).
	Config *tls.Config
	// CAPEM is the CA certificate chain served on the CA endpoint and
	// printed at startup; nil in static mode or when unavailable.
	CAPEM []byte
}

// Build assembles the TLS configuration for cfg.
func Build(cfg *config.Config, logger *zap.Logger) (*Result, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if cfg.HTTP2Enabled {
		tlsCfg.NextProtos = []string{"h2", "http/1.1"}
	} else {
		tlsCfg.NextProtos = []string{"http/1.1"}
	}
	if cfg.MTLSEnable {
		tlsCfg.ClientAuth = tls.RequestClientCert
	}

	res := &Result{Config: tlsCfg}
	switch cfg.TLSMode {
	case config.TLSModeStatic:
		pair, err := tls.LoadX509KeyPair(cfg.HTTPSCertFile, cfg.HTTPSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading static certificate pair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}

	case config.TLSModeAuto:
		ca, err := loadOrCreateCA(cfg, logger)
		if err != nil {
			return nil, err
		}
		res.CAPEM = ca.PEM()
		cache := newCertCache(cfg.TLSCertCacheSize, func(sni string) (*tls.Certificate, error) {
			start := time.Now()
			cert, err := ca.Mint(sni, cfg.TLSCertTTL)
			if err == nil {
				logger.Debug("minted certificate",
					zap.String("sni", sni),
					zap.Time("notAfter", cert.Leaf.NotAfter),
					zap.Duration("took", time.Since(start)))
			}
			return cert, err
		})
		tlsCfg.GetCertificate = getCertificate(cache, logger)

	case config.TLSModeVault:
		client, err := vaultpki.New(vaultpki.Config{
			Addr:       cfg.VaultAddr,
			Token:      cfg.VaultToken,
			Namespace:  cfg.VaultNamespace,
			Mount:      cfg.VaultPKIMount,
			Role:       cfg.VaultPKIRole,
			TTL:        cfg.VaultPKITTL,
			CACert:     cfg.VaultCACert,
			SkipVerify: cfg.VaultSkipVerify,
		})
		if err != nil {
			return nil, fmt.Errorf("building vault client: %w", err)
		}
		if chain, err := client.CAChain(context.Background()); err != nil {
			logger.Warn("fetching vault CA chain failed", zap.Error(err))
		} else {
			res.CAPEM = chain
		}
		cache := newCertCache(cfg.TLSCertCacheSize, func(sni string) (*tls.Certificate, error) {
			logger.Debug("requesting certificate from vault",
				zap.String("sni", sni),
				zap.String("mount", cfg.VaultPKIMount),
				zap.String("role", cfg.VaultPKIRole))
			start := time.Now()
			cert, err := client.Issue(sni)
			if err == nil {
				logger.Debug("vault issued certificate",
					zap.String("sni", sni),
					zap.Time("notAfter", cert.Leaf.NotAfter),
					zap.Duration("took", time.Since(start)))
			}
			return cert, err
		})
		// Refresh when 2/3 of the issued certificate's lifetime has elapsed;
		// serve stale (until real expiry) when re-issuance fails (spec §9.4).
		cache.needsRefresh = vaultRefreshPolicy(time.Now)
		cache.staleOK = true
		cache.onRefreshError = func(sni string, err error) {
			logger.Warn("vault re-issuance failed, serving cached certificate",
				zap.String("sni", sni), zap.Error(err))
		}
		tlsCfg.GetCertificate = getCertificate(cache, logger)

	default:
		return nil, fmt.Errorf("unknown TLS mode %q", cfg.TLSMode)
	}
	return res, nil
}

func loadOrCreateCA(cfg *config.Config, logger *zap.Logger) (*autoca.CA, error) {
	ca, loadErr := autoca.Load(cfg.TLSCACertFile, cfg.TLSCAKeyFile)
	if loadErr == nil {
		logger.Info("loaded existing CA", zap.String("cert", cfg.TLSCACertFile))
		return ca, nil
	}
	if !errors.Is(loadErr, fs.ErrNotExist) {
		// The files exist but are unusable: regenerating silently would
		// invalidate every client that trusted the old CA, so say why.
		logger.Warn("existing CA is unusable, generating a new one",
			zap.String("cert", cfg.TLSCACertFile),
			zap.String("key", cfg.TLSCAKeyFile),
			zap.Error(loadErr))
	}
	ca, err := autoca.New()
	if err != nil {
		return nil, fmt.Errorf("generating CA: %w", err)
	}
	if err := ca.Persist(cfg.TLSCACertFile, cfg.TLSCAKeyFile); err != nil {
		logger.Warn("persisting CA failed, continuing in-memory",
			zap.String("cert", cfg.TLSCACertFile), zap.Error(err))
	} else {
		logger.Info("generated new CA",
			zap.String("cert", cfg.TLSCACertFile), zap.String("key", cfg.TLSCAKeyFile))
	}
	return ca, nil
}

func getCertificate(cache *certCache, logger *zap.Logger) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := cache.Get(hello.ServerName)
		if err != nil {
			logger.Error("certificate issuance failed",
				zap.String("sni", hello.ServerName), zap.Error(err))
			return nil, err
		}
		return cert, nil
	}
}

func vaultRefreshPolicy(now func() time.Time) func(*x509.Certificate) bool {
	return func(leaf *x509.Certificate) bool {
		lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
		return now().Sub(leaf.NotBefore) > lifetime*2/3
	}
}
