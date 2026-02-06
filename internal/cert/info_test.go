package cert

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nickromney/certconv/test/testutil"
)

func TestSummary_PEMCert(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	eng := NewDefaultEngine()

	s, err := eng.Summary(context.Background(), pair.CertPath, "")
	if err != nil {
		t.Fatalf("Summary() error = %v", err)
	}

	if s.FileType != FileTypeCert {
		t.Errorf("FileType = %v, want cert", s.FileType)
	}
	if s.Subject == "" {
		t.Error("Subject is empty")
	}
	if s.Issuer == "" {
		t.Error("Issuer is empty")
	}
	if s.NotBefore == "" {
		t.Error("NotBefore is empty")
	}
	if s.NotAfter == "" {
		t.Error("NotAfter is empty")
	}
	if s.Serial == "" {
		t.Error("Serial is empty")
	}
}

func TestSummary_Key(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	eng := NewDefaultEngine()

	s, err := eng.Summary(context.Background(), pair.KeyPath, "")
	if err != nil {
		t.Fatalf("Summary() error = %v", err)
	}

	if s.FileType != FileTypeKey {
		t.Errorf("FileType = %v, want key", s.FileType)
	}
	if s.KeyType != KeyTypeRSA {
		t.Errorf("KeyType = %v, want RSA", s.KeyType)
	}
}

func TestSummary_ECKey(t *testing.T) {
	pair := testutil.MakeECCertPair(t)
	eng := NewDefaultEngine()

	s, err := eng.Summary(context.Background(), pair.KeyPath, "")
	if err != nil {
		t.Fatalf("Summary() error = %v", err)
	}

	if s.KeyType != KeyTypeEC {
		t.Errorf("KeyType = %v, want EC", s.KeyType)
	}
}

func TestSummary_OpenSSHPublicKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "id_ed25519.pub")
	os.WriteFile(path, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIATnq5llxM85EAvJmIsY5c8J9oHhncfvF4o0xNQpRkQ test@example\n"), 0o644)

	eng := NewDefaultEngine()
	s, err := eng.Summary(context.Background(), path, "")
	if err != nil {
		t.Fatalf("Summary() error = %v", err)
	}
	if s.FileType != FileTypePublicKey {
		t.Fatalf("FileType = %v, want public-key", s.FileType)
	}
	if s.PublicKeyAlgorithm != "ssh-ed25519" {
		t.Fatalf("PublicKeyAlgorithm = %q, want ssh-ed25519", s.PublicKeyAlgorithm)
	}
	if s.PublicKeyComment != "test@example" {
		t.Fatalf("PublicKeyComment = %q, want test@example", s.PublicKeyComment)
	}
}

func TestSummary_Combined(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	combined := testutil.MakeCombinedPEM(t, pair.CertPath, pair.KeyPath)
	eng := NewDefaultEngine()

	s, err := eng.Summary(context.Background(), combined, "")
	if err != nil {
		t.Fatalf("Summary() error = %v", err)
	}

	if s.FileType != FileTypeCombined {
		t.Errorf("FileType = %v, want combined", s.FileType)
	}
	if s.Subject == "" {
		t.Error("Subject is empty for combined file")
	}
}

func TestDetails_PEMCert(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	eng := NewDefaultEngine()

	d, err := eng.Details(context.Background(), pair.CertPath, "")
	if err != nil {
		t.Fatalf("Details() error = %v", err)
	}

	if d.RawText == "" {
		t.Error("RawText is empty")
	}
}

func TestDetails_UnsupportedType(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	os.WriteFile(path, []byte("hello"), 0o644)

	eng := NewDefaultEngine()
	_, err := eng.Details(context.Background(), path, "")
	if err == nil {
		t.Error("expected error for unknown file type")
	}
}

func TestExpiry_ValidCert(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	eng := NewDefaultEngine()

	result, err := eng.Expiry(context.Background(), pair.CertPath, 30)
	if err != nil {
		t.Fatalf("Expiry() error = %v", err)
	}

	if !result.Valid {
		t.Error("expected cert to be valid for 30 days")
	}
	if result.ExpiryDate == "" {
		t.Error("ExpiryDate is empty")
	}
	if result.DaysLeft <= 0 {
		t.Errorf("DaysLeft = %d, want > 0", result.DaysLeft)
	}
}

func TestExpiry_LargeWindow(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	eng := NewDefaultEngine()

	// Cert is valid for 365 days, check for 400
	result, err := eng.Expiry(context.Background(), pair.CertPath, 400)
	if err != nil {
		t.Fatalf("Expiry() error = %v", err)
	}

	if result.Valid {
		t.Error("expected cert to NOT be valid for 400 days")
	}
}
