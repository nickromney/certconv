package cert

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNextAvailablePath(t *testing.T) {
	dir := t.TempDir()

	// No file exists yet.
	p := filepath.Join(dir, "out.pem")
	if got := NextAvailablePath(p); got != p {
		t.Fatalf("expected %q, got %q", p, got)
	}

	// First exists -> suggest -1.
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	p1 := filepath.Join(dir, "out-1.pem")
	if got := NextAvailablePath(p); got != p1 {
		t.Fatalf("expected %q, got %q", p1, got)
	}

	// out-1 exists -> suggest -2.
	if err := os.WriteFile(p1, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	p2 := filepath.Join(dir, "out-2.pem")
	if got := NextAvailablePath(p); got != p2 {
		t.Fatalf("expected %q, got %q", p2, got)
	}
}

func TestWriteFileExclusive_DoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "exists.txt")
	if err := os.WriteFile(dest, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := writeFileExclusive(dest, []byte("new"), 0o644)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !IsOutputExists(err) {
		t.Fatalf("expected OutputExistsError, got: %v", err)
	}

	got, rerr := os.ReadFile(dest)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if string(got) != "original" {
		t.Fatalf("expected original content preserved, got %q", string(got))
	}
}
