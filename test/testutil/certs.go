package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CertPair holds paths to a generated cert and key in a temp directory.
type CertPair struct {
	CertPath string
	KeyPath  string
	Dir      string
}

// MakeCertPair generates an ephemeral RSA certificate and key pair for testing.
func MakeCertPair(t *testing.T) *CertPair {
	t.Helper()

	dir := t.TempDir()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test.local",
			Organization: []string{"CertConv Test"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		// Mark the generated cert as a CA so it can be used as its own trust
		// anchor for openssl verify in tests.
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPath := filepath.Join(dir, "test.pem")
	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("encode cert PEM: %v", err)
	}
	certFile.Close()

	keyPath := filepath.Join(dir, "test.key")
	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatalf("encode key PEM: %v", err)
	}
	keyFile.Close()
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatalf("chmod key: %v", err)
	}

	return &CertPair{
		CertPath: certPath,
		KeyPath:  keyPath,
		Dir:      dir,
	}
}

// MakeECCertPair generates an ephemeral EC certificate and key pair for testing.
func MakeECCertPair(t *testing.T) *CertPair {
	t.Helper()

	dir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "ec-test.local",
			Organization: []string{"CertConv Test"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		// Mark the generated cert as a CA so it can be used as its own trust
		// anchor for openssl verify in tests.
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create EC certificate: %v", err)
	}

	certPath := filepath.Join(dir, "ec-test.pem")
	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("encode cert PEM: %v", err)
	}
	certFile.Close()

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}

	keyPath := filepath.Join(dir, "ec-test.key")
	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatalf("encode key PEM: %v", err)
	}
	keyFile.Close()
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatalf("chmod key: %v", err)
	}

	return &CertPair{
		CertPath: certPath,
		KeyPath:  keyPath,
		Dir:      dir,
	}
}

// MakeDERCert writes a DER-encoded certificate from an existing PEM cert.
func MakeDERCert(t *testing.T, pemPath string) string {
	t.Helper()

	data, err := os.ReadFile(pemPath)
	if err != nil {
		t.Fatalf("read pem: %v", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("failed to decode PEM")
	}

	dir := t.TempDir()
	derPath := filepath.Join(dir, "test.der")
	if err := os.WriteFile(derPath, block.Bytes, 0o644); err != nil {
		t.Fatalf("write DER: %v", err)
	}
	return derPath
}

// MakeCombinedPEM creates a combined cert+key PEM file.
func MakeCombinedPEM(t *testing.T, certPath, keyPath string) string {
	t.Helper()

	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}

	dir := t.TempDir()
	combinedPath := filepath.Join(dir, "combined.pem")
	combined := append(certData, '\n')
	combined = append(combined, keyData...)
	if err := os.WriteFile(combinedPath, combined, 0o644); err != nil {
		t.Fatalf("write combined: %v", err)
	}
	return combinedPath
}
