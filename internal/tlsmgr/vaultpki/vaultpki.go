// Package vaultpki issues leaf certificates from a HashiCorp Vault PKI
// secrets engine (docs/specification.md §9.4) using a plain net/http client.
package vaultpki

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// requestTimeout bounds every Vault API call.
const requestTimeout = 5 * time.Second

// Config configures the Vault client.
type Config struct {
	Addr       string
	Token      string
	Namespace  string
	Mount      string
	Role       string
	TTL        time.Duration
	CACert     string
	SkipVerify bool
}

// Client talks to the Vault HTTP API.
type Client struct {
	cfg  Config
	http *http.Client
}

// New builds a Client.
func New(cfg Config) (*Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.SkipVerify {
		tlsCfg.InsecureSkipVerify = true // #nosec G402 -- explicit VAULT_SKIP_VERIFY opt-in
	}
	if cfg.CACert != "" {
		pemBytes, err := os.ReadFile(cfg.CACert) // #nosec G304 -- operator-configured path
		if err != nil {
			return nil, fmt.Errorf("reading VAULT_CACERT: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("no certificates found in VAULT_CACERT %s", cfg.CACert)
		}
		tlsCfg.RootCAs = pool
	}
	transport.TLSClientConfig = tlsCfg
	return &Client{
		cfg:  cfg,
		http: &http.Client{Transport: transport, Timeout: requestTimeout},
	}, nil
}

type issueResponse struct {
	Data struct {
		Certificate string   `json:"certificate"`
		PrivateKey  string   `json:"private_key"`
		CAChain     []string `json:"ca_chain"`
		IssuingCA   string   `json:"issuing_ca"`
	} `json:"data"`
}

type errorResponse struct {
	Errors []string `json:"errors"`
}

// Issue requests a certificate for the given SNI. An empty SNI falls back to
// the host's hostname as CN plus localhost/loopback SANs (spec §9.4).
func (c *Client) Issue(sni string) (*tls.Certificate, error) {
	payload := map[string]any{"ttl": c.cfg.TTL.String()}
	if sni != "" {
		payload["common_name"] = sni
	} else {
		hostname, err := os.Hostname()
		if err != nil || hostname == "" {
			hostname = "localhost"
		}
		payload["common_name"] = hostname
		payload["alt_names"] = noSNIAltNames(hostname)
		payload["ip_sans"] = "127.0.0.1,::1"
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/v1/%s/issue/%s", strings.TrimSuffix(c.cfg.Addr, "/"), c.cfg.Mount, c.cfg.Role)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	c.auth(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault issue request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("vault issue failed: %s: %s", resp.Status, vaultErrors(respBody))
	}

	var issued issueResponse
	if err := json.Unmarshal(respBody, &issued); err != nil {
		return nil, fmt.Errorf("decoding vault issue response: %w", err)
	}
	if issued.Data.Certificate == "" || issued.Data.PrivateKey == "" {
		return nil, fmt.Errorf("vault issue response missing certificate or private_key")
	}

	chain := issued.Data.Certificate
	for _, ca := range issued.Data.CAChain {
		chain += "\n" + strings.TrimSpace(ca)
	}
	cert, err := tls.X509KeyPair([]byte(chain), []byte(issued.Data.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("assembling vault certificate: %w", err)
	}
	if cert.Leaf == nil {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			cert.Leaf = leaf
		}
	}
	return &cert, nil
}

// CAChain fetches the PEM CA chain of the PKI mount for printing and the CA
// endpoint. Failure is not fatal to the caller (spec §9.4).
func (c *Client) CAChain(ctx context.Context) ([]byte, error) {
	url := fmt.Sprintf("%s/v1/%s/ca_chain", strings.TrimSuffix(c.cfg.Addr, "/"), c.cfg.Mount)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	c.auth(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault ca_chain request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("vault ca_chain failed: %s: %s", resp.Status, vaultErrors(body))
	}
	if !bytes.Contains(body, []byte("BEGIN CERTIFICATE")) {
		return nil, fmt.Errorf("vault ca_chain returned no PEM data")
	}
	return body, nil
}

// noSNIAltNames builds the alt_names value for the no-SNI fallback, avoiding
// a duplicate "localhost" entry when the host's own hostname is "localhost".
func noSNIAltNames(hostname string) string {
	if hostname == "localhost" {
		return "localhost"
	}
	return "localhost," + hostname
}

func (c *Client) auth(req *http.Request) {
	req.Header.Set("X-Vault-Token", c.cfg.Token)
	if c.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.cfg.Namespace)
	}
}

func vaultErrors(body []byte) string {
	var er errorResponse
	if json.Unmarshal(body, &er) == nil && len(er.Errors) > 0 {
		return strings.Join(er.Errors, "; ")
	}
	return strings.TrimSpace(string(body))
}
