package cert

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nickromney/certconv/test/testutil"
)

func TestToPFX_AndFromPFX(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	eng := NewDefaultEngine()
	ctx := context.Background()

	// Create PFX
	pfxPath := filepath.Join(pair.Dir, "test.pfx")
	err := eng.ToPFX(ctx, pair.CertPath, pair.KeyPath, pfxPath, "", "", "")
	if err != nil {
		t.Fatalf("ToPFX() error = %v", err)
	}

	if info, err := os.Stat(pfxPath); err != nil || info.Size() == 0 {
		t.Fatal("PFX file not created or empty")
	}

	// Extract PFX
	outDir := filepath.Join(pair.Dir, "extracted")
	result, err := eng.FromPFX(ctx, pfxPath, outDir, "")
	if err != nil {
		t.Fatalf("FromPFX() error = %v", err)
	}

	if result.CertFile == "" {
		t.Error("CertFile is empty")
	}
	if result.KeyFile == "" {
		t.Error("KeyFile is empty")
	}

	// Verify extracted cert is valid PEM
	if err := ValidatePEMCert(result.CertFile); err != nil {
		t.Errorf("extracted cert not valid PEM: %v", err)
	}
	if err := ValidatePEMKey(result.KeyFile); err != nil {
		t.Errorf("extracted key not valid PEM: %v", err)
	}
}

func TestToPFX_WithPassword(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	eng := NewDefaultEngine()
	ctx := context.Background()

	pfxPath := filepath.Join(pair.Dir, "test-pass.pfx")
	err := eng.ToPFX(ctx, pair.CertPath, pair.KeyPath, pfxPath, "testpass", "", "")
	if err != nil {
		t.Fatalf("ToPFX() error = %v", err)
	}

	// Extract with correct password
	outDir := filepath.Join(pair.Dir, "extracted-pass")
	_, err = eng.FromPFX(ctx, pfxPath, outDir, "testpass")
	if err != nil {
		t.Fatalf("FromPFX() with correct password error = %v", err)
	}
}

func TestFromPFX_WrongPassword_HasHelpfulError(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	eng := NewDefaultEngine()
	ctx := context.Background()

	pfxPath := filepath.Join(pair.Dir, "test-pass.pfx")
	if err := eng.ToPFX(ctx, pair.CertPath, pair.KeyPath, pfxPath, "secret", "", ""); err != nil {
		t.Fatalf("ToPFX() error = %v", err)
	}

	_, err := eng.FromPFX(ctx, pfxPath, filepath.Join(pair.Dir, "out"), "wrong")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "incorrect password") {
		t.Fatalf("expected incorrect password message, got: %v", err)
	}
}

func TestToPFX_MismatchedKey(t *testing.T) {
	pair1 := testutil.MakeCertPair(t)
	pair2 := testutil.MakeCertPair(t)
	eng := NewDefaultEngine()

	pfxPath := filepath.Join(pair1.Dir, "mismatch.pfx")
	err := eng.ToPFX(context.Background(), pair1.CertPath, pair2.KeyPath, pfxPath, "", "", "")
	if err == nil {
		t.Error("expected error for mismatched key")
	}
	if !strings.Contains(err.Error(), "does NOT match") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestToDER_AndFromDER(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	eng := NewDefaultEngine()
	ctx := context.Background()

	// Convert to DER
	derPath := filepath.Join(pair.Dir, "test.der")
	err := eng.ToDER(ctx, pair.CertPath, derPath, false, "")
	if err != nil {
		t.Fatalf("ToDER() error = %v", err)
	}

	// Check it's DER
	isDER, err := IsDEREncoded(derPath)
	if err != nil {
		t.Fatalf("IsDEREncoded() error = %v", err)
	}
	if !isDER {
		t.Error("output file is not DER encoded")
	}

	// Convert back to PEM
	pemPath := filepath.Join(pair.Dir, "from-der.pem")
	err = eng.FromDER(ctx, derPath, pemPath, false, "")
	if err != nil {
		t.Fatalf("FromDER() error = %v", err)
	}

	if err := ValidatePEMCert(pemPath); err != nil {
		t.Errorf("converted PEM not valid: %v", err)
	}
}

func TestToDER_Key(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	eng := NewDefaultEngine()
	ctx := context.Background()

	derPath := filepath.Join(pair.Dir, "test-key.der")
	err := eng.ToDER(ctx, pair.KeyPath, derPath, true, "")
	if err != nil {
		t.Fatalf("ToDER(key) error = %v", err)
	}

	if info, err := os.Stat(derPath); err != nil || info.Size() == 0 {
		t.Fatal("DER key file not created or empty")
	}
}

func TestToBase64_AndFromBase64(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	eng := NewDefaultEngine()
	ctx := context.Background()

	// Encode to base64
	b64Path := filepath.Join(pair.Dir, "test.b64")
	err := eng.ToBase64(ctx, pair.CertPath, b64Path)
	if err != nil {
		t.Fatalf("ToBase64() error = %v", err)
	}

	// Check it's valid base64
	b64Data, _ := os.ReadFile(b64Path)
	_, err = base64.StdEncoding.DecodeString(string(b64Data))
	if err != nil {
		t.Errorf("output is not valid base64: %v", err)
	}

	// Decode back
	decodedPath := filepath.Join(pair.Dir, "decoded.pem")
	err = eng.FromBase64(ctx, b64Path, decodedPath)
	if err != nil {
		t.Fatalf("FromBase64() error = %v", err)
	}

	// Compare with original
	original, _ := os.ReadFile(pair.CertPath)
	decoded, _ := os.ReadFile(decodedPath)
	if string(original) != string(decoded) {
		t.Error("decoded content doesn't match original")
	}
}

func TestFromBase64_PEMInput(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	eng := NewDefaultEngine()

	outPath := filepath.Join(pair.Dir, "should-fail")
	err := eng.FromBase64(context.Background(), pair.CertPath, outPath)
	if err == nil {
		t.Error("expected error when decoding PEM as base64")
	}
	if !strings.Contains(err.Error(), "PEM format") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestFromBase64_InvalidBase64(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "bad.b64")
	out := filepath.Join(dir, "out.bin")
	os.WriteFile(in, []byte("not base64!!!"), 0o644)

	eng := NewDefaultEngine()
	err := eng.FromBase64(context.Background(), in, out)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "base64 decoding failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCombinePEM(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	eng := NewDefaultEngine()
	ctx := context.Background()

	outPath := filepath.Join(pair.Dir, "combined.pem")
	err := eng.CombinePEM(ctx, pair.CertPath, pair.KeyPath, outPath, "", "")
	if err != nil {
		t.Fatalf("CombinePEM() error = %v", err)
	}

	content, _ := os.ReadFile(outPath)
	if !strings.Contains(string(content), "BEGIN CERTIFICATE") {
		t.Error("combined file missing certificate")
	}
	if !strings.Contains(string(content), "BEGIN RSA PRIVATE KEY") {
		t.Error("combined file missing key")
	}

	// Check file permissions
	info, _ := os.Stat(outPath)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %o, want 600", info.Mode().Perm())
	}
}

func TestCombinePEM_MismatchedKey(t *testing.T) {
	pair1 := testutil.MakeCertPair(t)
	pair2 := testutil.MakeCertPair(t)
	eng := NewDefaultEngine()

	outPath := filepath.Join(pair1.Dir, "mismatch-combined.pem")
	err := eng.CombinePEM(context.Background(), pair1.CertPath, pair2.KeyPath, outPath, "", "")
	if err == nil {
		t.Error("expected error for mismatched key")
	}
}

func TestNoOverwrite_OffersSuggestion(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	eng := NewDefaultEngine()
	ctx := context.Background()

	outPath := filepath.Join(pair.Dir, "combined.pem")
	if err := eng.CombinePEM(ctx, pair.CertPath, pair.KeyPath, outPath, "", ""); err != nil {
		t.Fatalf("CombinePEM() error = %v", err)
	}

	// Second attempt should fail with suggestion.
	err := eng.CombinePEM(ctx, pair.CertPath, pair.KeyPath, outPath, "", "")
	if err == nil {
		t.Fatalf("expected overwrite error")
	}
	if !strings.Contains(err.Error(), "output already exists") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "try:") {
		t.Fatalf("expected suggestion in error: %v", err)
	}
}

func TestFromDER_NonDERFile(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	eng := NewDefaultEngine()

	// PEM file is not DER
	outPath := filepath.Join(pair.Dir, "should-fail.pem")
	err := eng.FromDER(context.Background(), pair.CertPath, outPath, false, "")
	if err == nil {
		t.Error("expected error for non-DER input")
	}
	if !strings.Contains(err.Error(), "DER encoded") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNoOverwrite_AllConversions(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	eng := NewDefaultEngine()
	ctx := context.Background()

	tests := []struct {
		name string
		run  func(out string) error
		out  string
	}{
		{
			name: "ToDER(cert)",
			out:  filepath.Join(pair.Dir, "exists.der"),
			run: func(out string) error {
				return eng.ToDER(ctx, pair.CertPath, out, false, "")
			},
		},
		{
			name: "FromDER(cert)",
			out:  filepath.Join(pair.Dir, "exists-from-der.pem"),
			run: func(out string) error {
				der := filepath.Join(pair.Dir, "tmp.der")
				if err := eng.ToDER(ctx, pair.CertPath, der, false, ""); err != nil {
					return err
				}
				return eng.FromDER(ctx, der, out, false, "")
			},
		},
		{
			name: "ToBase64",
			out:  filepath.Join(pair.Dir, "exists.b64"),
			run: func(out string) error {
				return eng.ToBase64(ctx, pair.CertPath, out)
			},
		},
		{
			name: "FromBase64",
			out:  filepath.Join(pair.Dir, "exists-from-b64.pem"),
			run: func(out string) error {
				b64 := filepath.Join(pair.Dir, "tmp.b64")
				if err := eng.ToBase64(ctx, pair.CertPath, b64); err != nil {
					return err
				}
				return eng.FromBase64(ctx, b64, out)
			},
		},
		{
			name: "ToPFX",
			out:  filepath.Join(pair.Dir, "exists.pfx"),
			run: func(out string) error {
				return eng.ToPFX(ctx, pair.CertPath, pair.KeyPath, out, "", "", "")
			},
		},
		{
			name: "CombinePEM",
			out:  filepath.Join(pair.Dir, "exists-combined.pem"),
			run: func(out string) error {
				return eng.CombinePEM(ctx, pair.CertPath, pair.KeyPath, out, "", "")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(tt.out, []byte("do not clobber"), 0o644); err != nil {
				t.Fatal(err)
			}

			err := tt.run(tt.out)
			if err == nil {
				t.Fatalf("expected overwrite error")
			}
			if !IsOutputExists(err) {
				t.Fatalf("expected OutputExistsError, got: %v", err)
			}

			got, rerr := os.ReadFile(tt.out)
			if rerr != nil {
				t.Fatal(rerr)
			}
			if string(got) != "do not clobber" {
				t.Fatalf("expected output preserved, got %q", string(got))
			}
		})
	}
}
