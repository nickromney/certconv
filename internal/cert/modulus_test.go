package cert

import (
	"context"
	"errors"
	"os"
	"testing"
)

type modulusFakeExec struct {
	stdout []byte
	stderr []byte
	err    error
	last   []string
}

func (m *modulusFakeExec) Run(ctx context.Context, args ...string) (stdout, stderr []byte, err error) {
	_ = ctx
	m.last = append([]string(nil), args...)
	return m.stdout, m.stderr, m.err
}

func TestParseModulus(t *testing.T) {
	mod, ok := parseModulus([]byte("Modulus=ABCDEF\n"))
	if !ok || mod != "ABCDEF" {
		t.Fatalf("expected ABCDEF, got %q ok=%v", mod, ok)
	}
}

func TestModulusDigestsHex_Deterministic(t *testing.T) {
	sha1, md1 := ModulusDigestsHex("ABCDEF")
	sha2, md2 := ModulusDigestsHex("ABCDEF")
	if sha1 != sha2 || md1 != md2 {
		t.Fatalf("expected deterministic digests")
	}
	if sha1 == "" || md1 == "" {
		t.Fatalf("expected non-empty digests")
	}
}

func TestRSAModulus_NonRSAClassified(t *testing.T) {
	exec := &modulusFakeExec{
		stdout: nil,
		stderr: []byte("Can't use -modulus with non-RSA certificates"),
		err:    errors.New("exit status 1"),
	}
	e := NewEngine(exec)

	// Force type detection to cert by using extension.
	dir := t.TempDir()
	path := dir + "/x.pem"
	// We don't read the file in RSAModulus; DetectType will scan it though.
	// Provide a minimal cert marker to avoid DetectType error.
	writeTestFile(t, path, "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n")

	_, err := e.RSAModulus(context.Background(), path)
	if !errors.Is(err, ErrNotRSA) {
		t.Fatalf("expected ErrNotRSA, got %v", err)
	}
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
