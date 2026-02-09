package tui

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCertPEM(t *testing.T, dir string, c *x509.Certificate, key *rsa.PrivateKey) string {
	t.Helper()

	der, err := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	p := filepath.Join(dir, "test.pem")
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create pem: %v", err)
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encode pem: %v", err)
	}
	return p
}

func TestRenderParsedCert_ShowsSANsAndUsages(t *testing.T) {
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	u, _ := url.Parse("spiffe://example.com/service")

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example.com"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		DNSNames:              []string{"a.example.com", "b.example.com"},
		IPAddresses:           []net.IP{net.ParseIP("10.0.0.1")},
		EmailAddresses:        []string{"ops@example.com"},
		URIs:                  []*url.URL{u},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certPath := writeCertPEM(t, dir, template, key)
	out, err := renderParsedCert(certPath, "", nil, context.Background())
	if err != nil {
		t.Fatalf("renderParsedCert: %v", err)
	}

	for _, s := range []string{
		"Identity\n",
		"Validity\n",
		"Subject Alternative Names\n",
		"DNS: a.example.com",
		"IP: 10.0.0.1",
		"Email: ops@example.com",
		"URI: spiffe://example.com/service",
		"Key Usage\n",
		"Extended Key Usage:",
		"Server Auth",
		"Fingerprints\n",
		"SHA-256:",
	} {
		if !strings.Contains(out, s) {
			t.Fatalf("expected output to contain %q, got:\n%s", s, out)
		}
	}
}

func TestRenderParsedCert_ShowsExpiredStatus(t *testing.T) {
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expired.example.com"},
		NotBefore:    time.Now().Add(-72 * time.Hour),
		NotAfter:     time.Now().Add(-48 * time.Hour),
	}

	certPath := writeCertPEM(t, dir, template, key)
	out, err := renderParsedCert(certPath, "", nil, context.Background())
	if err != nil {
		t.Fatalf("renderParsedCert: %v", err)
	}
	if !strings.Contains(out, "EXPIRED") {
		t.Fatalf("expected EXPIRED status, got:\n%s", out)
	}
}
