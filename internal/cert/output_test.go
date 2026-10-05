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

func TestCommitStagedOutputs_RollsBackOnlyOwnedLinks(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "out.crt")
	key := filepath.Join(dir, "out.key")
	tmpCert, err := newTempPath(cert)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpCert)
	tmpKey, err := newTempPath(key)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpKey)
	if err := os.WriteFile(tmpCert, []byte("certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmpKey, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A dangling symlink must also count as an existing output.
	if err := os.Symlink(filepath.Join(dir, "missing"), key); err != nil {
		t.Fatal(err)
	}
	err = commitStagedOutputs([]stagedOutput{{tmpCert, cert, 0o644}, {tmpKey, key, 0o600}})
	if !IsOutputExists(err) {
		t.Fatalf("expected conflict: %v", err)
	}
	if _, err := os.Lstat(cert); !os.IsNotExist(err) {
		t.Fatalf("owned certificate not removed: %v", err)
	}
	if target, err := os.Readlink(key); err != nil || target != filepath.Join(dir, "missing") {
		t.Fatalf("existing symlink changed: %q %v", target, err)
	}
	if data, err := os.ReadFile(tmpKey); err != nil || string(data) != "key" {
		t.Fatalf("staging file changed: %q %v", data, err)
	}
	info, err := os.Stat(tmpKey)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key staging mode: %o", info.Mode().Perm())
	}
}
