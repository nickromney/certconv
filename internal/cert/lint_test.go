package cert

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

func makeCert(t *testing.T, opts func(*x509.Certificate, any) any) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.local"},
	}
	var signer any = key
	if opts != nil {
		signer = opts(tmpl, key)
	}

	signerKey := signer
	signerCert := tmpl
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, publicKey(signerKey), privateKey(signerKey))
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c
}

func publicKey(k any) any {
	switch k := k.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	}
	return nil
}

func privateKey(k any) any {
	return k
}

func writeCertFile(t *testing.T, c *x509.Certificate) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	_ = f.Close()
	return path
}

func TestLint_CleanCert(t *testing.T) {
	c := makeCert(t, nil)
	issues := LintCertificate(c)
	if len(issues) != 0 {
		t.Errorf("expected clean, got %d issues: %v", len(issues), issues)
	}
}

func TestLint_Expired(t *testing.T) {
	c := makeCert(t, func(tmpl *x509.Certificate, key any) any {
		tmpl.NotBefore = time.Now().Add(-48 * time.Hour)
		tmpl.NotAfter = time.Now().Add(-24 * time.Hour)
		return key
	})
	issues := LintCertificate(c)
	found := false
	for _, i := range issues {
		if i.Code == "expired" {
			found = true
		}
	}
	if !found {
		t.Error("expected expired issue")
	}
}

func TestLint_NotYetValid(t *testing.T) {
	c := makeCert(t, func(tmpl *x509.Certificate, key any) any {
		tmpl.NotBefore = time.Now().Add(24 * time.Hour)
		tmpl.NotAfter = time.Now().Add(48 * time.Hour)
		return key
	})
	issues := LintCertificate(c)
	found := false
	for _, i := range issues {
		if i.Code == "not-yet-valid" {
			found = true
		}
	}
	if !found {
		t.Error("expected not-yet-valid issue")
	}
}

func TestLint_MissingSANs(t *testing.T) {
	c := makeCert(t, func(tmpl *x509.Certificate, key any) any {
		tmpl.DNSNames = nil
		return key
	})
	issues := LintCertificate(c)
	found := false
	for _, i := range issues {
		if i.Code == "missing-sans" {
			found = true
		}
	}
	if !found {
		t.Error("expected missing-sans issue")
	}
}

func TestLint_LongValidity(t *testing.T) {
	c := makeCert(t, func(tmpl *x509.Certificate, key any) any {
		tmpl.NotAfter = time.Now().Add(500 * 24 * time.Hour)
		return key
	})
	issues := LintCertificate(c)
	found := false
	for _, i := range issues {
		if i.Code == "long-validity" {
			found = true
		}
	}
	if !found {
		t.Error("expected long-validity issue")
	}
}

func TestLint_LongValidity_CA_NoWarning(t *testing.T) {
	c := makeCert(t, func(tmpl *x509.Certificate, key any) any {
		tmpl.IsCA = true
		tmpl.KeyUsage = x509.KeyUsageCertSign
		tmpl.NotAfter = time.Now().Add(3650 * 24 * time.Hour)
		return key
	})
	issues := LintCertificate(c)
	for _, i := range issues {
		if i.Code == "long-validity" {
			t.Error("CA cert should not trigger long-validity warning")
		}
	}
}

func TestLint_WeakKey(t *testing.T) {
	// Use a small RSA key (1024 bits).
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "weak"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		DNSNames:              []string{"weak.local"},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	issues := LintCertificate(c)
	found := false
	for _, i := range issues {
		if i.Code == "weak-key" {
			found = true
		}
	}
	if !found {
		t.Error("expected weak-key issue")
	}
}

func TestLint_ECKey_NoWeakKeyIssue(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ec"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		DNSNames:              []string{"ec.local"},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	issues := LintCertificate(c)
	for _, i := range issues {
		if i.Code == "weak-key" {
			t.Error("EC key should not trigger weak-key")
		}
	}
}

func TestLint_CAAsLeaf(t *testing.T) {
	c := makeCert(t, func(tmpl *x509.Certificate, key any) any {
		tmpl.IsCA = true
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature // CA=true but no CertSign
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		return key
	})
	issues := LintCertificate(c)
	found := false
	for _, i := range issues {
		if i.Code == "ca-as-leaf" {
			found = true
		}
	}
	if !found {
		t.Error("expected ca-as-leaf issue")
	}
}

func TestLint_CAAsLeaf_WithCertSign_NoWarning(t *testing.T) {
	c := makeCert(t, func(tmpl *x509.Certificate, key any) any {
		tmpl.IsCA = true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		return key
	})
	issues := LintCertificate(c)
	for _, i := range issues {
		if i.Code == "ca-as-leaf" {
			t.Error("CA with CertSign should not trigger ca-as-leaf")
		}
	}
}

func TestLint_CAAsLeaf_NoServerAuth_NoWarning(t *testing.T) {
	c := makeCert(t, func(tmpl *x509.Certificate, key any) any {
		tmpl.IsCA = true
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
		return key
	})
	issues := LintCertificate(c)
	for _, i := range issues {
		if i.Code == "ca-as-leaf" {
			t.Error("CA without ServerAuth should not trigger ca-as-leaf")
		}
	}
}

func TestLintFile_NonexistentFile(t *testing.T) {
	_, err := LintFile("/nonexistent/file.pem")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestLintFile(t *testing.T) {
	c := makeCert(t, func(tmpl *x509.Certificate, key any) any {
		tmpl.DNSNames = nil // trigger missing-sans
		return key
	})
	path := writeCertFile(t, c)

	result, err := LintFile(path)
	if err != nil {
		t.Fatalf("LintFile: %v", err)
	}
	if result.Clean {
		t.Error("expected issues, got clean")
	}
	if result.File != path {
		t.Errorf("File = %q, want %q", result.File, path)
	}
}
