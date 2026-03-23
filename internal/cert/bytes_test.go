package cert

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/nickromney/certconv/test/testutil"
)

func TestDetectTypeFromNameAndBytes(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	certData, err := os.ReadFile(pair.CertPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	keyData, err := os.ReadFile(pair.KeyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	combinedData, err := os.ReadFile(testutil.MakeCombinedPEM(t, pair.CertPath, pair.KeyPath))
	if err != nil {
		t.Fatalf("read combined: %v", err)
	}
	derData, err := os.ReadFile(testutil.MakeDERCert(t, pair.CertPath))
	if err != nil {
		t.Fatalf("read der: %v", err)
	}

	tests := []struct {
		name string
		file string
		data []byte
		want FileType
	}{
		{name: "cert", file: "server.pem", data: certData, want: FileTypeCert},
		{name: "key", file: "server.key", data: keyData, want: FileTypeKey},
		{name: "combined", file: "combined.pem", data: combinedData, want: FileTypeCombined},
		{name: "der", file: "server.der", data: derData, want: FileTypeDER},
		{name: "base64", file: "server.b64", data: []byte(base64.StdEncoding.EncodeToString(certData)), want: FileTypeBase64},
		{name: "openssh pub", file: "id_ed25519.pub", data: []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIATnq5llxM85EAvJmIsY5c8J9oHhncfvF4o0xNQpRkQ demo@example"), want: FileTypePublicKey},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectTypeFromNameAndBytes(tc.file, tc.data); got != tc.want {
				t.Fatalf("DetectTypeFromNameAndBytes() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSummaryFromBytes(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	certData, err := os.ReadFile(pair.CertPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}

	s, err := SummaryFromBytes("test.pem", certData)
	if err != nil {
		t.Fatalf("SummaryFromBytes() error = %v", err)
	}

	if s.FileType != FileTypeCert {
		t.Fatalf("FileType = %v, want cert", s.FileType)
	}
	if s.Subject == "" || s.Issuer == "" || s.NotBefore == "" || s.NotAfter == "" {
		t.Fatalf("expected populated summary, got %+v", s)
	}
	if s.Fingerprint == "" {
		t.Fatalf("expected fingerprint to be populated")
	}
}

func TestSummaryFromBytesWithPassword_PFX(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	pfxPath := testutil.MakePFX(t, pair, "secret")
	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		t.Fatalf("read pfx: %v", err)
	}

	s, err := SummaryFromBytesWithPassword("test.p12", pfxData, "secret")
	if err != nil {
		t.Fatalf("SummaryFromBytesWithPassword() error = %v", err)
	}

	if s.FileType != FileTypePFX {
		t.Fatalf("FileType = %v, want pfx", s.FileType)
	}
	if s.Subject == "" || s.Issuer == "" || s.Fingerprint == "" {
		t.Fatalf("expected populated PFX summary, got %+v", s)
	}
}

func TestSummaryFromBytesWithPassword_PFXWrongPassword(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	pfxPath := testutil.MakePFX(t, pair, "secret")
	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		t.Fatalf("read pfx: %v", err)
	}

	_, err = SummaryFromBytesWithPassword("test.p12", pfxData, "wrong")
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsPFXIncorrectPassword(err) {
		t.Fatalf("expected incorrect password error, got %v", err)
	}
}

func TestLintBytes(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	certData, err := os.ReadFile(pair.CertPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}

	result, err := LintBytes("test.pem", certData)
	if err != nil {
		t.Fatalf("LintBytes() error = %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if result.File != "test.pem" {
		t.Fatalf("File = %q, want test.pem", result.File)
	}
}

func TestLintBytesWithPassword_PFX(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	pfxPath := testutil.MakePFX(t, pair, "secret")
	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		t.Fatalf("read pfx: %v", err)
	}

	result, err := LintBytesWithPassword("test.p12", pfxData, "secret")
	if err != nil {
		t.Fatalf("LintBytesWithPassword() error = %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if result.File != "test.p12" {
		t.Fatalf("File = %q, want test.p12", result.File)
	}
}

func TestCertToAndFromDERBytes(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	certData, err := os.ReadFile(pair.CertPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}

	der, err := CertToDERBytes(certData)
	if err != nil {
		t.Fatalf("CertToDERBytes() error = %v", err)
	}
	if len(der) == 0 {
		t.Fatal("expected DER bytes")
	}

	pemOut, err := CertFromDERBytes(der)
	if err != nil {
		t.Fatalf("CertFromDERBytes() error = %v", err)
	}
	if !strings.Contains(string(pemOut), "BEGIN CERTIFICATE") {
		t.Fatalf("expected PEM certificate, got %q", string(pemOut))
	}
}

func TestFromBase64Bytes(t *testing.T) {
	encoded := []byte(base64.StdEncoding.EncodeToString([]byte("hello")))
	out, err := FromBase64Bytes(encoded)
	if err != nil {
		t.Fatalf("FromBase64Bytes() error = %v", err)
	}
	if string(out) != "hello" {
		t.Fatalf("decoded = %q, want hello", string(out))
	}
}
