package tlsmgr

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/kumy/http-echo-server/internal/config"
	"github.com/kumy/http-echo-server/internal/tlsmgr/autoca"
)

func baseConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{
		TLSMode:          config.TLSModeAuto,
		TLSCACertFile:    filepath.Join(dir, "ca.crt"),
		TLSCAKeyFile:     filepath.Join(dir, "ca.key"),
		TLSCertTTL:       time.Hour,
		TLSCertCacheSize: 8,
		HTTP2Enabled:     true,
	}
}

func TestBuildAutoMode(t *testing.T) {
	cfg := baseConfig(t)
	res, err := Build(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(res.CAPEM) == 0 {
		t.Error("CAPEM missing in auto mode")
	}
	if res.Config.MinVersion != tls.VersionTLS12 {
		t.Error("MinVersion must be TLS 1.2")
	}

	cert, err := res.Config.GetCertificate(&tls.ClientHelloInfo{ServerName: "sni.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert.Leaf.Subject.CommonName != "sni.example.com" {
		t.Errorf("CN = %q", cert.Leaf.Subject.CommonName)
	}

	// The CA must have been persisted, and a rebuild must reuse it.
	pem1, err := os.ReadFile(cfg.TLSCACertFile)
	if err != nil {
		t.Fatalf("CA not persisted: %v", err)
	}
	res2, err := Build(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if string(res2.CAPEM) != string(pem1) {
		t.Error("rebuild did not reuse the persisted CA")
	}
}

func TestBuildAutoPersistFailureIsNonFatal(t *testing.T) {
	cfg := baseConfig(t)
	// Point the CA files somewhere unwritable.
	cfg.TLSCACertFile = "/proc/nonexistent/ca.crt"
	cfg.TLSCAKeyFile = "/proc/nonexistent/ca.key"
	res, err := Build(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("Build must warn, not fail, on persist errors: %v", err)
	}
	if len(res.CAPEM) == 0 {
		t.Error("in-memory CA missing")
	}
}

func TestBuildStaticMode(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "leaf.crt")
	keyFile := filepath.Join(dir, "leaf.key")
	writeStaticPair(t, certFile, keyFile)

	cfg := baseConfig(t)
	cfg.TLSMode = config.TLSModeStatic
	cfg.HTTPSCertFile = certFile
	cfg.HTTPSKeyFile = keyFile

	res, err := Build(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(res.Config.Certificates) != 1 {
		t.Error("static pair not loaded")
	}
	if res.CAPEM != nil {
		t.Error("CAPEM must be nil in static mode")
	}
}

func TestBuildStaticModeBadPair(t *testing.T) {
	cfg := baseConfig(t)
	cfg.TLSMode = config.TLSModeStatic
	cfg.HTTPSCertFile = "/does/not/exist.crt"
	cfg.HTTPSKeyFile = "/does/not/exist.key"
	if _, err := Build(cfg, zap.NewNop()); err == nil {
		t.Fatal("expected error for missing static pair")
	}
}

func TestBuildALPNAndMTLS(t *testing.T) {
	cfg := baseConfig(t)
	res, _ := Build(cfg, zap.NewNop())
	if got := strings.Join(res.Config.NextProtos, ","); got != "h2,http/1.1" {
		t.Errorf("NextProtos = %q", got)
	}
	if res.Config.ClientAuth != tls.NoClientCert {
		t.Error("ClientAuth must be off by default")
	}

	cfg2 := baseConfig(t)
	cfg2.HTTP2Enabled = false
	cfg2.MTLSEnable = true
	res2, _ := Build(cfg2, zap.NewNop())
	if got := strings.Join(res2.Config.NextProtos, ","); got != "http/1.1" {
		t.Errorf("NextProtos = %q", got)
	}
	if res2.Config.ClientAuth != tls.RequestClientCert {
		t.Error("ClientAuth must be RequestClientCert with MTLS_ENABLE")
	}
}

func TestBuildVaultMode(t *testing.T) {
	// Reuse autoca as the "vault" backend: mint on demand.
	ca, err := autoca.New()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/ca_chain"):
			_, _ = w.Write(ca.PEM())
		case strings.Contains(r.URL.Path, "/issue/"):
			var payload struct {
				CommonName string `json:"common_name"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			cert, err := ca.Mint(payload.CommonName, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			keyDER, _ := marshalKey(cert)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})),
					"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := baseConfig(t)
	cfg.TLSMode = config.TLSModeVault
	cfg.VaultAddr = srv.URL
	cfg.VaultToken = "t"
	cfg.VaultPKIMount = "pki"
	cfg.VaultPKIRole = "echo"
	cfg.VaultPKITTL = time.Hour

	res, err := Build(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !strings.Contains(string(res.CAPEM), "BEGIN CERTIFICATE") {
		t.Error("vault CA chain not fetched")
	}
	cert, err := res.Config.GetCertificate(&tls.ClientHelloInfo{ServerName: "vaulted.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert.Leaf.Subject.CommonName != "vaulted.example.com" {
		t.Errorf("CN = %q", cert.Leaf.Subject.CommonName)
	}
}

func TestBuildVaultModeChainFetchFailureNonFatal(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	cfg := baseConfig(t)
	cfg.TLSMode = config.TLSModeVault
	cfg.VaultAddr = srv.URL
	cfg.VaultToken = "t"
	cfg.VaultPKIMount = "pki"
	cfg.VaultPKIRole = "echo"
	cfg.VaultPKITTL = time.Hour

	res, err := Build(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("CA chain fetch failure must not be fatal: %v", err)
	}
	if res.CAPEM != nil {
		t.Error("CAPEM should be nil when the chain fetch failed")
	}
}

// --- helpers ---

func writeStaticPair(t *testing.T, certFile, keyFile string) {
	t.Helper()
	ca, err := autoca.New()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.Mint("static.example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := marshalKey(cert)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func marshalKey(cert *tls.Certificate) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
}
