// Package autoca implements the local on-the-fly certificate authority for
// TLS_MODE=auto (docs/specification.md §9.3): a persisted ECDSA P-256 root
// CA minting leaf certificates per SNI at handshake time.
package autoca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// caCommonName is the CN of generated root CAs.
const caCommonName = "http-echo-server Root CA"

// caValidity is the validity of generated root CAs.
const caValidity = 10 * 365 * 24 * time.Hour

// notBeforeSkew backdates certificates to tolerate clock skew.
const notBeforeSkew = 5 * time.Minute

// CA is a certificate authority able to mint leaf certificates.
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

// New generates a fresh root CA.
func New() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: caCommonName},
		NotBefore:             now.Add(-notBeforeSkew),
		NotAfter:              now.Add(caValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("creating CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}

// Load reads an existing CA pair from disk.
func Load(certFile, keyFile string) (*CA, error) {
	certPEM, err := os.ReadFile(certFile) // #nosec G304 -- operator-configured path
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyFile) // #nosec G304 -- operator-configured path
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("no CERTIFICATE block in CA cert file")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CA certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("stored certificate is not a CA")
	}
	key, err := parseECKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing CA key: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("CA private key does not match the CA certificate")
	}
	return &CA{cert: cert, key: key, certPEM: certPEM}, nil
}

// Persist writes the CA pair to disk (cert 0644, key 0600), creating parent
// directories as needed.
func (ca *CA) Persist(certFile, keyFile string) error {
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	for _, dir := range []string{filepath.Dir(certFile), filepath.Dir(keyFile)} {
		if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- cert dir is world-readable
			return err
		}
	}
	if err := os.WriteFile(certFile, ca.certPEM, 0o644); err != nil { // #nosec G306 -- CA cert is public
		return err
	}
	return os.WriteFile(keyFile, keyPEM, 0o600)
}

// PEM returns the CA certificate in PEM form.
func (ca *CA) PEM() []byte {
	return ca.certPEM
}

// Mint issues a leaf certificate for the given SNI (spec §9.3): the SNI DNS
// name verbatim (wildcards included), or the localhost/hostname/loopback set
// when the SNI is empty.
func (ca *CA) Mint(sni string, ttl time.Duration) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: leafCommonName(sni)},
		NotBefore:    now.Add(-notBeforeSkew),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	if sni != "" {
		if ip := net.ParseIP(sni); ip != nil {
			tmpl.IPAddresses = []net.IP{ip}
		} else {
			tmpl.DNSNames = []string{sni}
		}
	} else {
		tmpl.DNSNames = []string{"localhost"}
		if hostname, err := os.Hostname(); err == nil && hostname != "localhost" {
			tmpl.DNSNames = append(tmpl.DNSNames, hostname)
		}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("minting certificate for %q: %w", sni, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

func leafCommonName(sni string) string {
	if sni != "" {
		return sni
	}
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}
	return "localhost"
}

func parseECKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("no PEM block in key file")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("CA key is not an ECDSA key")
		}
		return ecKey, nil
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func randomSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial: %w", err)
	}
	return serial, nil
}
