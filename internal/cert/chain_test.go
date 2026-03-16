package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// makeChain creates a root→intermediate→leaf chain and returns PEM blocks in the given order.
func makeChain(t *testing.T, order []int) string {
	t.Helper()

	rootKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	intKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{1},
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	intTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Intermediate CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		SubjectKeyId:          []byte{2},
		AuthorityKeyId:        []byte{1},
	}
	intDER, _ := x509.CreateCertificate(rand.Reader, intTmpl, rootCert, &intKey.PublicKey, rootKey)
	intCert, _ := x509.ParseCertificate(intDER)

	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"leaf.example.com"},
		SubjectKeyId:          []byte{3},
		AuthorityKeyId:        []byte{2},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, intCert, &leafKey.PublicKey, intKey)

	allDER := [][]byte{rootDER, intDER, leafDER} // index: 0=root, 1=int, 2=leaf

	var buf strings.Builder
	for _, idx := range order {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: allDER[idx]})
	}
	return buf.String()
}

func writeBundle(t *testing.T, pemData string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.pem")
	_ = os.WriteFile(path, []byte(pemData), 0o644)
	return path
}

func TestOrderChain_CorrectOrder(t *testing.T) {
	// Input already in correct order: leaf, intermediate, root
	pemData := makeChain(t, []int{2, 1, 0})
	result, ordered, err := OrderChainFromPEM([]byte(pemData))
	if err != nil {
		t.Fatalf("OrderChainFromPEM: %v", err)
	}
	if len(result.Certs) != 3 {
		t.Fatalf("expected 3 certs, got %d", len(result.Certs))
	}
	if len(result.Warnings) != 0 {
		t.Errorf("expected no warnings, got %v", result.Warnings)
	}
	// First cert should be the leaf.
	if !strings.Contains(result.Certs[0].Subject, "leaf") {
		t.Errorf("first cert should be leaf, got %q", result.Certs[0].Subject)
	}
	// Last cert should be root.
	if !strings.Contains(result.Certs[2].Subject, "Root") {
		t.Errorf("last cert should be root, got %q", result.Certs[2].Subject)
	}
	if !result.Certs[2].IsSelfSigned {
		t.Error("root should be self-signed")
	}
	if len(ordered) == 0 {
		t.Error("expected PEM output")
	}
}

func TestOrderChain_ReverseInput(t *testing.T) {
	// Input in reverse order: root, intermediate, leaf
	pemData := makeChain(t, []int{0, 1, 2})
	result, _, err := OrderChainFromPEM([]byte(pemData))
	if err != nil {
		t.Fatalf("OrderChainFromPEM: %v", err)
	}
	if len(result.Certs) != 3 {
		t.Fatalf("expected 3 certs, got %d", len(result.Certs))
	}
	// First cert should be the leaf.
	if !strings.Contains(result.Certs[0].Subject, "leaf") {
		t.Errorf("first cert should be leaf, got %q", result.Certs[0].Subject)
	}
	// Last cert should be root.
	if !strings.Contains(result.Certs[2].Subject, "Root") {
		t.Errorf("last cert should be root, got %q", result.Certs[2].Subject)
	}
}

func TestOrderChain_SingleSelfSigned(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "self-signed"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	var buf strings.Builder
	_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})

	result, _, err := OrderChainFromPEM([]byte(buf.String()))
	if err != nil {
		t.Fatalf("OrderChainFromPEM: %v", err)
	}
	if len(result.Certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(result.Certs))
	}
	if !result.Certs[0].IsSelfSigned {
		t.Error("expected self-signed")
	}
}

func TestOrderChain_File(t *testing.T) {
	pemData := makeChain(t, []int{0, 2, 1}) // shuffled: root, leaf, intermediate
	path := writeBundle(t, pemData)

	result, _, err := OrderChain(path)
	if err != nil {
		t.Fatalf("OrderChain: %v", err)
	}
	if !strings.Contains(result.Certs[0].Subject, "leaf") {
		t.Errorf("first cert should be leaf, got %q", result.Certs[0].Subject)
	}
}

func TestOrderChain_NoCerts(t *testing.T) {
	_, _, err := OrderChainFromPEM([]byte("not a PEM"))
	if err == nil {
		t.Error("expected error for no certs")
	}
}
