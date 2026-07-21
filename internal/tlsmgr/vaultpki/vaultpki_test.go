package vaultpki

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testPKI holds a throwaway CA able to answer issue requests.
type testPKI struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  string
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test vault CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testPKI{
		caCert: cert,
		caKey:  key,
		caPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
	}
}

// issue returns leaf cert + key PEM for the given CN.
func (p *testPKI) issue(t *testing.T, cn string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     []string{cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

func TestIssue(t *testing.T) {
	pki := newTestPKI(t)
	var gotPath, gotToken, gotNamespace string
	var gotPayload map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotToken = r.Header.Get("X-Vault-Token")
		gotNamespace = r.Header.Get("X-Vault-Namespace")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotPayload)

		cn, _ := gotPayload["common_name"].(string)
		certPEM, keyPEM := pki.issue(t, cn)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"certificate": certPEM,
				"private_key": keyPEM,
				"ca_chain":    []string{pki.caPEM},
			},
		})
	}))
	defer srv.Close()

	client, err := New(Config{
		Addr: srv.URL, Token: "hvs.test", Namespace: "ns1",
		Mount: "pki_int", Role: "echo", TTL: 12 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	cert, err := client.Issue("foo.example.com")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if gotPath != "/v1/pki_int/issue/echo" {
		t.Errorf("path = %q", gotPath)
	}
	if gotToken != "hvs.test" || gotNamespace != "ns1" {
		t.Errorf("auth headers: token=%q ns=%q", gotToken, gotNamespace)
	}
	if gotPayload["common_name"] != "foo.example.com" || gotPayload["ttl"] != "12h0m0s" {
		t.Errorf("payload = %v", gotPayload)
	}
	if cert.Leaf == nil || cert.Leaf.Subject.CommonName != "foo.example.com" {
		t.Errorf("leaf = %+v", cert.Leaf)
	}
	if len(cert.Certificate) != 2 {
		t.Errorf("chain length = %d, want leaf + CA", len(cert.Certificate))
	}
}

func TestIssueNoSNIFallback(t *testing.T) {
	pki := newTestPKI(t)
	var gotPayload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotPayload)
		cn, _ := gotPayload["common_name"].(string)
		certPEM, keyPEM := pki.issue(t, cn)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"certificate": certPEM, "private_key": keyPEM},
		})
	}))
	defer srv.Close()

	client, _ := New(Config{Addr: srv.URL, Token: "t", Mount: "pki", Role: "r", TTL: time.Hour})
	if _, err := client.Issue(""); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if gotPayload["common_name"] == "" {
		t.Error("no-SNI issue must fall back to a hostname CN")
	}
	if gotPayload["ip_sans"] != "127.0.0.1,::1" {
		t.Errorf("ip_sans = %v", gotPayload["ip_sans"])
	}
	altNames, _ := gotPayload["alt_names"].(string)
	if !strings.Contains(altNames, "localhost") {
		t.Errorf("alt_names = %q", altNames)
	}
}

func TestIssueErrorMapping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"errors":["permission denied"]}`)
	}))
	defer srv.Close()

	client, _ := New(Config{Addr: srv.URL, Token: "t", Mount: "pki", Role: "r", TTL: time.Hour})
	_, err := client.Issue("x")
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("err = %v, want vault error surfaced", err)
	}
}

func TestCAChain(t *testing.T) {
	pki := newTestPKI(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/pki_int/ca_chain" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = fmt.Fprint(w, pki.caPEM)
	}))
	defer srv.Close()

	client, _ := New(Config{Addr: srv.URL, Token: "t", Mount: "pki_int", Role: "r", TTL: time.Hour})
	chain, err := client.CAChain(context.Background())
	if err != nil {
		t.Fatalf("CAChain: %v", err)
	}
	if !strings.Contains(string(chain), "BEGIN CERTIFICATE") {
		t.Errorf("chain = %q", chain)
	}
}

func TestCAChainErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "empty") {
			_, _ = fmt.Fprint(w, "no pem here")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client, _ := New(Config{Addr: srv.URL, Token: "t", Mount: "pki", Role: "r", TTL: time.Hour})
	if _, err := client.CAChain(context.Background()); err == nil {
		t.Error("expected error on 404")
	}
	client2, _ := New(Config{Addr: srv.URL, Token: "t", Mount: "empty", Role: "r", TTL: time.Hour})
	if _, err := client2.CAChain(context.Background()); err == nil {
		t.Error("expected error on non-PEM body")
	}
}

func TestNoSNIAltNamesDedup(t *testing.T) {
	if got := noSNIAltNames("localhost"); got != "localhost" {
		t.Errorf("noSNIAltNames(localhost) = %q, want no duplicate", got)
	}
	if got := noSNIAltNames("myhost"); got != "localhost,myhost" {
		t.Errorf("noSNIAltNames(myhost) = %q", got)
	}
}

func TestNewWithBadCACert(t *testing.T) {
	if _, err := New(Config{Addr: "http://x", CACert: "/does/not/exist.pem"}); err == nil {
		t.Error("expected error for missing CA cert file")
	}
}
