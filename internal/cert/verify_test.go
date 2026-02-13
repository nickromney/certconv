package cert

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nickromney/certconv/test/testutil"
)

func TestVerifyChain_SelfSigned(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	eng := NewDefaultEngine()

	// Self-signed cert verified against itself
	result, err := eng.VerifyChain(context.Background(), pair.CertPath, pair.CertPath)
	if err != nil {
		t.Fatalf("VerifyChain() error = %v", err)
	}

	if !result.Valid {
		t.Errorf("expected self-signed cert to verify against itself, output: %s", result.Output)
	}
}

func TestVerifyChain_WrongCA(t *testing.T) {
	pair1 := testutil.MakeCertPair(t)
	pair2 := testutil.MakeCertPair(t)
	eng := NewDefaultEngine()

	// cert from pair1 against CA from pair2 should fail
	result, err := eng.VerifyChain(context.Background(), pair1.CertPath, pair2.CertPath)
	if err != nil {
		t.Fatalf("VerifyChain() error = %v", err)
	}

	if result.Valid {
		t.Error("expected verification to fail with wrong CA")
	}
}

func TestMatchKeyToCert_Match(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	eng := NewDefaultEngine()

	result, err := eng.MatchKeyToCert(context.Background(), pair.CertPath, pair.KeyPath, "")
	if err != nil {
		t.Fatalf("MatchKeyToCert() error = %v", err)
	}

	if !result.Match {
		t.Error("expected key to match cert")
	}
}

func TestMatchKeyToCert_NoMatch(t *testing.T) {
	pair1 := testutil.MakeCertPair(t)
	pair2 := testutil.MakeCertPair(t)
	eng := NewDefaultEngine()

	result, err := eng.MatchKeyToCert(context.Background(), pair1.CertPath, pair2.KeyPath, "")
	if err != nil {
		t.Fatalf("MatchKeyToCert() error = %v", err)
	}

	if result.Match {
		t.Error("expected key NOT to match cert from different pair")
	}
}

func TestValidatePEMCert_Valid(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	if err := ValidatePEMCert(pair.CertPath); err != nil {
		t.Errorf("ValidatePEMCert() unexpected error: %v", err)
	}
}

func TestValidatePEMCert_Invalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not-a-cert.pem")
	if err := os.WriteFile(path, []byte("just text"), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	if err := ValidatePEMCert(path); err == nil {
		t.Error("expected error for non-cert file")
	}
}

func TestValidatePEMKey_Valid(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	if err := ValidatePEMKey(pair.KeyPath); err != nil {
		t.Errorf("ValidatePEMKey() unexpected error: %v", err)
	}
}

func TestValidatePEMKey_Invalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not-a-key.pem")
	if err := os.WriteFile(path, []byte("just text"), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	if err := ValidatePEMKey(path); err == nil {
		t.Error("expected error for non-key file")
	}
}
