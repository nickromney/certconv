package cert

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nickromney/certconv/test/testutil"
)

func TestFixtures_ToDER_BadPEM_NoHeader(t *testing.T) {
	engine := NewDefaultEngine()

	out := filepath.Join(t.TempDir(), "out.der")
	err := engine.ToDER(context.Background(), testutil.FixturePath(t, "bad-no-header.pem"), out, false, "")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "not a PEM certificate") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("expected output not to exist, got stat error: %v", statErr)
	}
}

func TestFixtures_ToDER_BadPEM_Empty(t *testing.T) {
	engine := NewDefaultEngine()

	out := filepath.Join(t.TempDir(), "out.der")
	err := engine.ToDER(context.Background(), testutil.FixturePath(t, "bad-empty.pem"), out, false, "")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "not a PEM certificate") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("expected output not to exist, got stat error: %v", statErr)
	}
}

func TestFixtures_ToDER_BadPEM_GarbageCertPrefersStderr(t *testing.T) {
	engine := NewDefaultEngine()

	out := filepath.Join(t.TempDir(), "out.der")
	err := engine.ToDER(context.Background(), testutil.FixturePath(t, "bad-cert-garbage.pem"), out, false, "")
	if err == nil {
		t.Fatalf("expected error")
	}
	// The key point is that we don't bubble up a useless "exit status 1" as the
	// whole message.
	if strings.Contains(err.Error(), "exit status") {
		t.Fatalf("expected stderr-based error message, got: %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("expected output not to exist, got stat error: %v", statErr)
	}
}

func TestFixtures_FromDER_BadDER(t *testing.T) {
	engine := NewDefaultEngine()

	out := filepath.Join(t.TempDir(), "out.pem")
	err := engine.FromDER(context.Background(), testutil.FixturePath(t, "bad-der.bin"), out, false, "")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "file may not be DER encoded") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFixtures_FromPFX_Invalid(t *testing.T) {
	engine := NewDefaultEngine()

	outDir := filepath.Join(t.TempDir(), "out")
	_, err := engine.FromPFX(context.Background(), testutil.FixturePath(t, "bad.pfx"), outDir, "")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "PKCS#12/PFX") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFixtures_FromPFX_CertAsPFX(t *testing.T) {
	engine := NewDefaultEngine()

	outDir := filepath.Join(t.TempDir(), "out")
	_, err := engine.FromPFX(context.Background(), testutil.FixturePath(t, "cert-as-pfx.pfx"), outDir, "")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "PKCS#12/PFX") {
		t.Fatalf("unexpected error: %v", err)
	}
}
