package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/pflag"
)

func TestDefaults(t *testing.T) {
	cfg, err := Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.HTTPEnabled || cfg.HTTPPort != 8080 {
		t.Errorf("http defaults wrong: %+v", cfg)
	}
	if !cfg.HTTPSEnabled || cfg.HTTPSPort != 8443 {
		t.Errorf("https defaults wrong: %+v", cfg)
	}
	if cfg.TLSMode != TLSModeAuto {
		t.Errorf("TLSMode = %q, want auto", cfg.TLSMode)
	}
	if cfg.ShutdownTimeout != 10*time.Second {
		t.Errorf("ShutdownTimeout = %v", cfg.ShutdownTimeout)
	}
	if cfg.MaxBodySize != 1<<20 || cfg.MaxHeaderSize != 1<<20 {
		t.Errorf("size defaults wrong: body=%d header=%d", cfg.MaxBodySize, cfg.MaxHeaderSize)
	}
	if cfg.ForwardURL != "" || cfg.ForwardTarget != nil {
		t.Errorf("forwarding should be off by default")
	}
	if cfg.Verbose {
		t.Errorf("verbose should be off by default")
	}
	if !cfg.WSEnabled || !cfg.EchoBackToClient {
		t.Errorf("ws/echo defaults wrong")
	}
	if cfg.PrometheusMetricType != "summary" {
		t.Errorf("PrometheusMetricType = %q", cfg.PrometheusMetricType)
	}
}

func TestEnvOverride(t *testing.T) {
	t.Setenv("HTTPS_PORT", "9999")
	t.Setenv("TLS_MODE", "static")
	t.Setenv("HTTPS_CERT_FILE", "/tmp/c.pem")
	t.Setenv("HTTPS_KEY_FILE", "/tmp/k.pem")
	t.Setenv("SHUTDOWN_TIMEOUT", "3s")
	t.Setenv("VERBOSE", "true")
	t.Setenv("FORWARD_URL", "http://remote:9093/base")

	cfg, err := Load(nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTPSPort != 9999 {
		t.Errorf("HTTPSPort = %d, want 9999", cfg.HTTPSPort)
	}
	if cfg.TLSMode != TLSModeStatic {
		t.Errorf("TLSMode = %q", cfg.TLSMode)
	}
	if cfg.ShutdownTimeout != 3*time.Second {
		t.Errorf("ShutdownTimeout = %v", cfg.ShutdownTimeout)
	}
	if !cfg.Verbose {
		t.Errorf("Verbose not picked up from env")
	}
	if cfg.ForwardTarget == nil || cfg.ForwardTarget.Host != "remote:9093" || cfg.ForwardTarget.Path != "/base" {
		t.Errorf("ForwardTarget = %v", cfg.ForwardTarget)
	}
}

func TestFlagBeatsEnv(t *testing.T) {
	t.Setenv("HTTP_PORT", "1111")
	cfg, err := Load([]string{"--http-port=2222"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTPPort != 2222 {
		t.Errorf("HTTPPort = %d, want flag value 2222", cfg.HTTPPort)
	}
}

func TestEnvBeatsConfigFile(t *testing.T) {
	file := writeConfig(t, "http-port: 3333\nlog-level: debug\n")
	t.Setenv("HTTP_PORT", "4444")
	cfg, err := Load([]string{"--config", file})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.HTTPPort != 4444 {
		t.Errorf("HTTPPort = %d, want env value 4444", cfg.HTTPPort)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want config-file value debug", cfg.LogLevel)
	}
}

func TestConfigFileDurationsAndBools(t *testing.T) {
	file := writeConfig(t, "shutdown-timeout: 42s\nprometheus-enabled: true\nforward-timeout: 5s\n")
	cfg, err := Load([]string{"--config", file})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ShutdownTimeout != 42*time.Second {
		t.Errorf("ShutdownTimeout = %v", cfg.ShutdownTimeout)
	}
	if !cfg.PrometheusEnabled {
		t.Errorf("PrometheusEnabled not read from file")
	}
	if cfg.ForwardTimeout != 5*time.Second {
		t.Errorf("ForwardTimeout = %v", cfg.ForwardTimeout)
	}
}

func TestMissingConfigFile(t *testing.T) {
	if _, err := Load([]string{"--config", "/does/not/exist.yaml"}); err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestVersionSkipsValidation(t *testing.T) {
	// tls-mode static without cert files is invalid, but --version short-circuits.
	cfg, err := Load([]string{"--version", "--tls-mode=static"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.ShowVersion {
		t.Error("ShowVersion not set")
	}
}

func TestHelp(t *testing.T) {
	if _, err := Load([]string{"--help"}); err != pflag.ErrHelp {
		t.Fatalf("err = %v, want pflag.ErrHelp", err)
	}
}

func TestValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no listeners", []string{"--http-enabled=false", "--https-enabled=false"}, "at least one"},
		{"bad port", []string{"--http-port=70000"}, "HTTP_PORT"},
		{"static without files", []string{"--tls-mode=static"}, "static"},
		{"vault without params", []string{"--tls-mode=vault"}, "vault"},
		{"vault bad addr", []string{"--tls-mode=vault", "--vault-addr=::bad::", "--vault-token=t", "--vault-pki-role=r"}, "VAULT_ADDR"},
		{"bad tls mode", []string{"--tls-mode=nope"}, "TLS_MODE"},
		{"bad log level", []string{"--log-level=chatty"}, "LOG_LEVEL"},
		{"bad log format", []string{"--log-format=xml"}, "LOG_FORMAT"},
		{"bad metric type", []string{"--prometheus-metric-type=gauge"}, "PROMETHEUS_METRIC_TYPE"},
		{"bad ignore regex", []string{"--log-ignore-path=("}, "LOG_IGNORE_PATH"},
		{"bad forward url", []string{"--forward-url=not-a-url"}, "FORWARD_URL"},
		{"forward url wrong scheme", []string{"--forward-url=ftp://host/"}, "FORWARD_URL"},
		{"bad trusted proxy", []string{"--additional-trusted-proxies=999.1.2.3"}, "ADDITIONAL_TRUSTED_PROXIES"},
		{"bad max body", []string{"--max-body-size=0"}, "MAX_BODY_SIZE"},
		{"bad max header", []string{"--max-header-size=-1"}, "MAX_HEADER_SIZE"},
		{"bad ca endpoint", []string{"--tls-ca-endpoint=ca"}, "TLS_CA_ENDPOINT"},
		{"bad metrics path", []string{"--prometheus-metrics-path=metrics"}, "PROMETHEUS_METRICS_PATH"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(tc.args)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestLogIgnoreRegexps(t *testing.T) {
	cfg, err := Load([]string{"--log-ignore-path=^/healthz, ^/metrics$"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.LogIgnoreRegexps) != 2 {
		t.Fatalf("got %d regexps, want 2", len(cfg.LogIgnoreRegexps))
	}
	if !cfg.LogIgnoreRegexps[0].MatchString("/healthz") {
		t.Error("first regex should match /healthz")
	}
	if cfg.LogIgnoreRegexps[1].MatchString("/metrics2") {
		t.Error("second regex should be anchored")
	}
}

func TestTrustedProxiesParsing(t *testing.T) {
	cfg, err := Load([]string{"--additional-trusted-proxies=203.0.113.7,198.51.100.0/24,2001:db8::/32"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.ExtraTrustedProxies) != 3 {
		t.Fatalf("got %d prefixes, want 3", len(cfg.ExtraTrustedProxies))
	}
	if got := cfg.ExtraTrustedProxies[0].String(); got != "203.0.113.7/32" {
		t.Errorf("single IP → %q, want /32", got)
	}
}

func TestEnvName(t *testing.T) {
	if got := EnvName("https-cert-file"); got != "HTTPS_CERT_FILE" {
		t.Errorf("EnvName = %q", got)
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
