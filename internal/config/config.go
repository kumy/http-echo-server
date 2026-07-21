// Package config loads and validates the daemon configuration from CLI
// flags, environment variables, and an optional config file, with the
// precedence flags > env > file > defaults (see docs/specification.md §4).
package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// TLS_MODE values.
const (
	TLSModeStatic = "static"
	TLSModeAuto   = "auto"
	TLSModeVault  = "vault"
)

// MaxDelayMS caps x-set-response-delay-ms (spec §6.3).
const MaxDelayMS = 120000

// Config holds every user-facing option. Field names map 1:1 to kebab-case
// flag names (mapstructure tags) and UPPER_SNAKE env vars.
type Config struct {
	// Listeners
	HTTPEnabled     bool          `mapstructure:"http-enabled"`
	HTTPPort        int           `mapstructure:"http-port"`
	HTTPSEnabled    bool          `mapstructure:"https-enabled"`
	HTTPSPort       int           `mapstructure:"https-port"`
	BindAddress     string        `mapstructure:"bind-address"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown-timeout"`

	// HTTP/2
	HTTP2Enabled    bool `mapstructure:"http2-enabled"`
	HTTP2H2CEnabled bool `mapstructure:"http2-h2c-enabled"`

	// TLS
	TLSMode          string        `mapstructure:"tls-mode"`
	HTTPSCertFile    string        `mapstructure:"https-cert-file"`
	HTTPSKeyFile     string        `mapstructure:"https-key-file"`
	TLSCACertFile    string        `mapstructure:"tls-ca-cert-file"`
	TLSCAKeyFile     string        `mapstructure:"tls-ca-key-file"`
	TLSCAPrint       bool          `mapstructure:"tls-ca-print"`
	TLSCAEndpoint    string        `mapstructure:"tls-ca-endpoint"`
	TLSCertTTL       time.Duration `mapstructure:"tls-cert-ttl"`
	TLSCertCacheSize int           `mapstructure:"tls-cert-cache-size"`
	MTLSEnable       bool          `mapstructure:"mtls-enable"`

	// Vault
	VaultAddr       string        `mapstructure:"vault-addr"`
	VaultToken      string        `mapstructure:"vault-token"`
	VaultNamespace  string        `mapstructure:"vault-namespace"`
	VaultPKIMount   string        `mapstructure:"vault-pki-mount"`
	VaultPKIRole    string        `mapstructure:"vault-pki-role"`
	VaultPKITTL     time.Duration `mapstructure:"vault-pki-ttl"`
	VaultCACert     string        `mapstructure:"vault-cacert"`
	VaultSkipVerify bool          `mapstructure:"vault-skip-verify"`

	// Echo behaviour
	EchoBackToClient             bool   `mapstructure:"echo-back-to-client"`
	EchoIncludeEnvVars           bool   `mapstructure:"echo-include-env-vars"`
	JWTHeader                    string `mapstructure:"jwt-header"`
	OverrideResponseBodyFilePath string `mapstructure:"override-response-body-file-path"`
	MaxHeaderSize                int    `mapstructure:"max-header-size"`
	MaxBodySize                  int64  `mapstructure:"max-body-size"`
	CookieSecret                 string `mapstructure:"cookie-secret"`
	WSEnabled                    bool   `mapstructure:"ws-enabled"`

	// Forwarding
	ForwardURL          string        `mapstructure:"forward-url"`
	ForwardPreserveHost bool          `mapstructure:"forward-preserve-host"`
	ForwardTimeout      time.Duration `mapstructure:"forward-timeout"`
	ForwardSkipVerify   bool          `mapstructure:"forward-skip-verify"`

	// Verbose wire dump
	Verbose bool `mapstructure:"verbose"`

	// Networking / proxies
	AdditionalTrustedProxies string `mapstructure:"additional-trusted-proxies"`

	// CORS
	CORSAllowOrigin      string `mapstructure:"cors-allow-origin"`
	CORSAllowMethods     string `mapstructure:"cors-allow-methods"`
	CORSAllowHeaders     string `mapstructure:"cors-allow-headers"`
	CORSAllowCredentials bool   `mapstructure:"cors-allow-credentials"`

	// Logging
	LogLevel           string `mapstructure:"log-level"`
	LogFormat          string `mapstructure:"log-format"`
	DisableRequestLogs bool   `mapstructure:"disable-request-logs"`
	LogIgnorePath      string `mapstructure:"log-ignore-path"`

	// Prometheus
	PrometheusEnabled     bool   `mapstructure:"prometheus-enabled"`
	PrometheusMetricsPath string `mapstructure:"prometheus-metrics-path"`
	PrometheusWithPath    bool   `mapstructure:"prometheus-with-path"`
	PrometheusWithMethod  bool   `mapstructure:"prometheus-with-method"`
	PrometheusWithStatus  bool   `mapstructure:"prometheus-with-status"`
	PrometheusMetricType  string `mapstructure:"prometheus-metric-type"`

	// Derived (populated by Validate, not bound to flags/env/file)
	ShowVersion         bool             `mapstructure:"-"`
	ConfigFile          string           `mapstructure:"-"`
	LogIgnoreRegexps    []*regexp.Regexp `mapstructure:"-"`
	ForwardTarget       *url.URL         `mapstructure:"-"`
	ExtraTrustedProxies []netip.Prefix   `mapstructure:"-"`
}

// EnvName returns the environment variable bound to a flag name, e.g.
// "https-port" → "HTTPS_PORT".
func EnvName(flag string) string {
	return strings.ToUpper(strings.ReplaceAll(flag, "-", "_"))
}

func newFlagSet() *pflag.FlagSet {
	fs := pflag.NewFlagSet("https-echo-server", pflag.ContinueOnError)
	fs.SortFlags = false

	fs.Bool("http-enabled", true, "enable the plaintext listener")
	fs.Int("http-port", 8080, "plaintext listener port (0 picks an ephemeral port)")
	fs.Bool("https-enabled", true, "enable the TLS listener")
	fs.Int("https-port", 8443, "TLS listener port (0 picks an ephemeral port)")
	fs.String("bind-address", "", "address to bind both listeners to (default: all interfaces)")
	fs.Duration("shutdown-timeout", 10*time.Second, "graceful shutdown drain window")

	fs.Bool("http2-enabled", true, "offer h2 via ALPN on the TLS listener")
	fs.Bool("http2-h2c-enabled", true, "accept cleartext HTTP/2 (h2c) on the plaintext listener")

	fs.String("tls-mode", TLSModeAuto, "TLS mode: static, auto, or vault")
	fs.String("https-cert-file", "", "certificate (or full chain) PEM (static mode)")
	fs.String("https-key-file", "", "private key PEM (static mode)")
	fs.String("tls-ca-cert-file", "certs/ca.crt", "where the auto CA certificate is stored/loaded")
	fs.String("tls-ca-key-file", "certs/ca.key", "where the auto CA key is stored/loaded")
	fs.Bool("tls-ca-print", true, "print the CA certificate PEM to stdout at startup")
	fs.String("tls-ca-endpoint", "/ca", "HTTP path serving the CA certificate PEM; empty disables")
	fs.Duration("tls-cert-ttl", 8760*time.Hour, "validity of on-the-fly leaf certificates (auto mode)")
	fs.Int("tls-cert-cache-size", 128, "max distinct SNI leaf certs kept in memory")
	fs.Bool("mtls-enable", false, "request a client certificate and echo it (no validation)")

	fs.String("vault-addr", "", "Vault server URL (vault mode)")
	fs.String("vault-token", "", "Vault token allowed to issue certs (vault mode)")
	fs.String("vault-namespace", "", "Vault Enterprise namespace")
	fs.String("vault-pki-mount", "pki", "mount path of the PKI secrets engine")
	fs.String("vault-pki-role", "", "PKI role used for issuance (vault mode)")
	fs.Duration("vault-pki-ttl", 24*time.Hour, "requested TTL for issued leaf certificates")
	fs.String("vault-cacert", "", "CA bundle to verify the Vault server itself")
	fs.Bool("vault-skip-verify", false, "skip TLS verification of the Vault server (testing only)")

	fs.Bool("echo-back-to-client", true, "false: echo only to logs, respond with empty body")
	fs.Bool("echo-include-env-vars", false, "include the process environment in the echo body")
	fs.String("jwt-header", "", "header name whose value is decoded as a JWT")
	fs.String("override-response-body-file-path", "", "file served as the response body instead of the echo")
	fs.Int("max-header-size", 1<<20, "maximum request header size in bytes")
	fs.Int64("max-body-size", 1<<20, "maximum request body bytes captured in the echo")
	fs.String("cookie-secret", "", "HMAC secret; cookies signed with it appear under signedCookies")
	fs.Bool("ws-enabled", true, "WebSocket echo on both listeners")

	fs.String("forward-url", "", "forward requests to this base URL, dumping the remote responses before relaying them")
	fs.Bool("forward-preserve-host", false, "keep the client's Host header instead of the target's host")
	fs.Duration("forward-timeout", 30*time.Second, "whole-exchange timeout for the upstream request")
	fs.Bool("forward-skip-verify", false, "skip TLS verification of the remote server (testing only)")

	fs.Bool("verbose", false, "print every exchange to stdout in a curl -v-style trace")

	fs.String("additional-trusted-proxies", "", "comma-separated IPs/CIDRs trusted for X-Forwarded-For")

	fs.String("cors-allow-origin", "", "comma-separated origins (or *); enables CORS handling")
	fs.String("cors-allow-methods", "", "allowed methods for preflight (default: all)")
	fs.String("cors-allow-headers", "", "allowed headers for preflight (default: requested)")
	fs.Bool("cors-allow-credentials", false, "send Access-Control-Allow-Credentials: true")

	fs.String("log-level", "info", "log level: debug, info, warn, error")
	fs.String("log-format", "json", "log format: json or console")
	fs.Bool("disable-request-logs", false, "suppress the per-request echo log lines")
	fs.String("log-ignore-path", "", "comma-separated regexes; matching request paths are not logged")

	fs.Bool("prometheus-enabled", false, "expose Prometheus metrics")
	fs.String("prometheus-metrics-path", "/metrics", "metrics endpoint path")
	fs.Bool("prometheus-with-path", false, "partition metrics by request path")
	fs.Bool("prometheus-with-method", true, "partition metrics by method")
	fs.Bool("prometheus-with-status", true, "partition metrics by status code")
	fs.String("prometheus-metric-type", "summary", "summary or histogram")

	fs.String("config", "", "path to a config file (YAML, TOML, or JSON)")
	fs.BoolP("version", "v", false, "print version and exit")
	return fs
}

// Load parses flags, environment variables, and the optional config file
// into a validated Config. It returns pflag.ErrHelp when --help was asked.
func Load(args []string) (*Config, error) {
	fs := newFlagSet()
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	v := viper.New()
	if err := v.BindPFlags(fs); err != nil {
		return nil, err
	}
	fs.VisitAll(func(f *pflag.Flag) {
		if f.Name == "config" || f.Name == "version" || f.Name == "help" {
			return
		}
		_ = v.BindEnv(f.Name, EnvName(f.Name))
	})

	configFile, _ := fs.GetString("config")
	if configFile != "" {
		v.SetConfigFile(configFile)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
	}

	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("decoding configuration: %w", err)
	}
	cfg.ShowVersion, _ = fs.GetBool("version")
	cfg.ConfigFile = configFile

	if cfg.ShowVersion {
		return cfg, nil
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate checks cross-field constraints and populates the derived fields.
func (c *Config) Validate() error {
	if !c.HTTPEnabled && !c.HTTPSEnabled {
		return fmt.Errorf("at least one of HTTP_ENABLED / HTTPS_ENABLED must be true")
	}
	if err := validPort("HTTP_PORT", c.HTTPPort); err != nil {
		return err
	}
	if err := validPort("HTTPS_PORT", c.HTTPSPort); err != nil {
		return err
	}

	switch c.TLSMode {
	case TLSModeStatic:
		if c.HTTPSCertFile == "" || c.HTTPSKeyFile == "" {
			return fmt.Errorf("TLS_MODE=static requires HTTPS_CERT_FILE and HTTPS_KEY_FILE")
		}
	case TLSModeAuto:
	case TLSModeVault:
		if c.VaultAddr == "" || c.VaultToken == "" || c.VaultPKIRole == "" {
			return fmt.Errorf("TLS_MODE=vault requires VAULT_ADDR, VAULT_TOKEN, and VAULT_PKI_ROLE")
		}
		if _, err := parseHTTPURL(c.VaultAddr); err != nil {
			return fmt.Errorf("invalid VAULT_ADDR: %w", err)
		}
	default:
		return fmt.Errorf("invalid TLS_MODE %q: must be static, auto, or vault", c.TLSMode)
	}

	if c.MaxHeaderSize <= 0 {
		return fmt.Errorf("MAX_HEADER_SIZE must be positive")
	}
	if c.MaxBodySize <= 0 {
		return fmt.Errorf("MAX_BODY_SIZE must be positive")
	}
	if c.TLSCertCacheSize <= 0 {
		return fmt.Errorf("TLS_CERT_CACHE_SIZE must be positive")
	}
	if c.TLSCertTTL <= 0 {
		return fmt.Errorf("TLS_CERT_TTL must be positive")
	}
	if c.VaultPKITTL <= 0 {
		return fmt.Errorf("VAULT_PKI_TTL must be positive")
	}
	if c.ShutdownTimeout <= 0 {
		return fmt.Errorf("SHUTDOWN_TIMEOUT must be positive")
	}
	if c.ForwardTimeout <= 0 {
		return fmt.Errorf("FORWARD_TIMEOUT must be positive")
	}
	if c.TLSCAEndpoint != "" && !strings.HasPrefix(c.TLSCAEndpoint, "/") {
		return fmt.Errorf("TLS_CA_ENDPOINT must start with /")
	}
	if !strings.HasPrefix(c.PrometheusMetricsPath, "/") {
		return fmt.Errorf("PROMETHEUS_METRICS_PATH must start with /")
	}

	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("invalid LOG_LEVEL %q: must be debug, info, warn, or error", c.LogLevel)
	}
	switch c.LogFormat {
	case "json", "console":
	default:
		return fmt.Errorf("invalid LOG_FORMAT %q: must be json or console", c.LogFormat)
	}
	switch c.PrometheusMetricType {
	case "summary", "histogram":
	default:
		return fmt.Errorf("invalid PROMETHEUS_METRIC_TYPE %q: must be summary or histogram", c.PrometheusMetricType)
	}

	c.LogIgnoreRegexps = nil
	for _, expr := range splitNonEmpty(c.LogIgnorePath) {
		re, err := regexp.Compile(expr)
		if err != nil {
			return fmt.Errorf("invalid LOG_IGNORE_PATH regex %q: %w", expr, err)
		}
		c.LogIgnoreRegexps = append(c.LogIgnoreRegexps, re)
	}

	c.ForwardTarget = nil
	if c.ForwardURL != "" {
		u, err := parseHTTPURL(c.ForwardURL)
		if err != nil {
			return fmt.Errorf("invalid FORWARD_URL: %w", err)
		}
		c.ForwardTarget = u
	}

	c.ExtraTrustedProxies = nil
	for _, entry := range splitNonEmpty(c.AdditionalTrustedProxies) {
		prefix, err := parseIPOrCIDR(entry)
		if err != nil {
			return fmt.Errorf("invalid ADDITIONAL_TRUSTED_PROXIES entry %q: %w", entry, err)
		}
		c.ExtraTrustedProxies = append(c.ExtraTrustedProxies, prefix)
	}
	return nil
}

func validPort(name string, port int) error {
	if port < 0 || port > 65535 {
		return fmt.Errorf("%s must be between 0 and 65535, got %d", name, port)
	}
	return nil
}

func parseHTTPURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("%q is not an absolute http(s) URL", raw)
	}
	return u, nil
}

func parseIPOrCIDR(s string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(s); err == nil {
		return prefix, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
