package autoca

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewCA(t *testing.T) {
	ca, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !ca.cert.IsCA {
		t.Error("certificate is not a CA")
	}
	if ca.cert.Subject.CommonName != "http-echo-server Root CA" {
		t.Errorf("CN = %q", ca.cert.Subject.CommonName)
	}
	if validity := ca.cert.NotAfter.Sub(ca.cert.NotBefore); validity < 9*365*24*time.Hour {
		t.Errorf("validity too short: %v", validity)
	}
	if len(ca.PEM()) == 0 {
		t.Error("PEM is empty")
	}
}

func TestPersistAndLoad(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "nested", "ca.crt")
	keyFile := filepath.Join(dir, "nested", "ca.key")

	ca, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Persist(certFile, keyFile); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	certInfo, _ := os.Stat(certFile)
	keyInfo, _ := os.Stat(keyFile)
	if certInfo.Mode().Perm() != 0o644 {
		t.Errorf("cert mode = %v, want 0644", certInfo.Mode().Perm())
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %v, want 0600", keyInfo.Mode().Perm())
	}

	loaded, err := Load(certFile, keyFile)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.cert.SerialNumber.Cmp(ca.cert.SerialNumber) != 0 {
		t.Error("loaded CA differs from persisted CA")
	}

	// A certificate minted by the reloaded CA must chain to the original.
	leaf, err := loaded.Mint("reload.example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	verifyChainsTo(t, leaf.Leaf, ca)
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "missing.crt"), filepath.Join(dir, "missing.key")); err == nil {
		t.Error("expected error for missing files")
	}

	bad := filepath.Join(dir, "bad.crt")
	_ = os.WriteFile(bad, []byte("not pem"), 0o600)
	badKey := filepath.Join(dir, "bad.key")
	_ = os.WriteFile(badKey, []byte("not pem"), 0o600)
	if _, err := Load(bad, badKey); err == nil {
		t.Error("expected error for garbage files")
	}
}

func TestLoadDetectsKeyCertMismatch(t *testing.T) {
	dir := t.TempDir()
	ca1, err := New()
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := New()
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, "ca.crt")
	keyFile := filepath.Join(dir, "ca.key")
	// Persist ca1's key but ca2's certificate: a mismatched pair that still
	// parses fine on its own, so only a public-key comparison catches it.
	if err := ca1.Persist(filepath.Join(dir, "unused.crt"), keyFile); err != nil {
		t.Fatal(err)
	}
	if err := ca2.Persist(certFile, filepath.Join(dir, "unused.key")); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(certFile, keyFile); err == nil {
		t.Error("Load must reject a certificate/key pair that don't match")
	}
}

func TestMintSNI(t *testing.T) {
	ca, _ := New()
	cert, err := ca.Mint("foo.example.com", 24*time.Hour)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	leaf := cert.Leaf
	if leaf.Subject.CommonName != "foo.example.com" {
		t.Errorf("CN = %q", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "foo.example.com" {
		t.Errorf("DNSNames = %v", leaf.DNSNames)
	}
	if !leaf.NotBefore.Before(time.Now()) {
		t.Error("NotBefore must be backdated")
	}
	verifyChainsTo(t, leaf, ca)
	if err := leaf.VerifyHostname("foo.example.com"); err != nil {
		t.Errorf("VerifyHostname: %v", err)
	}
}

func TestMintWildcard(t *testing.T) {
	ca, _ := New()
	cert, err := ca.Mint("*.example.com", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Leaf.DNSNames) != 1 || cert.Leaf.DNSNames[0] != "*.example.com" {
		t.Errorf("wildcard SAN = %v", cert.Leaf.DNSNames)
	}
}

func TestMintIPSNI(t *testing.T) {
	ca, _ := New()
	cert, err := ca.Mint("192.0.2.1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Leaf.IPAddresses) != 1 || cert.Leaf.IPAddresses[0].String() != "192.0.2.1" {
		t.Errorf("IP SAN = %v", cert.Leaf.IPAddresses)
	}
}

func TestMintNoSNI(t *testing.T) {
	ca, _ := New()
	cert, err := ca.Mint("", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf := cert.Leaf
	if err := leaf.VerifyHostname("localhost"); err != nil {
		t.Errorf("no-SNI cert must cover localhost: %v", err)
	}
	if err := leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("no-SNI cert must cover 127.0.0.1: %v", err)
	}
	if err := leaf.VerifyHostname("::1"); err != nil {
		t.Errorf("no-SNI cert must cover ::1: %v", err)
	}
}

func verifyChainsTo(t *testing.T, leaf *x509.Certificate, ca *CA) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Errorf("leaf does not chain to CA: %v", err)
	}
}
