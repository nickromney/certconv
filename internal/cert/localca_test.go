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
	"testing"
	"time"
)

func makeTestCACert(t *testing.T, dir, name string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name, Organization: []string{"Test CA"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+".pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDiscoverLocalCAs_CustomDir(t *testing.T) {
	dir := t.TempDir()
	makeTestCACert(t, dir, "myca")

	// Override mkcert to not find anything
	orig := mkcertCARootFn
	origDefault := defaultMkcertCARootFn
	mkcertCARootFn = func() (string, error) { return "", os.ErrNotExist }
	defaultMkcertCARootFn = func() string { return "" }
	defer func() { mkcertCARootFn = orig; defaultMkcertCARootFn = origDefault }()

	result, err := DiscoverLocalCAs([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result.Entries))
	}
	e := result.Entries[0]
	if e.Source != "custom" {
		t.Errorf("source = %q, want custom", e.Source)
	}
	if !e.IsCA {
		t.Error("expected IsCA=true")
	}
	if e.Subject == "" {
		t.Error("expected non-empty subject")
	}
}

func TestDiscoverLocalCAs_MkcertDir(t *testing.T) {
	dir := t.TempDir()
	makeTestCACert(t, dir, "rootCA")

	orig := mkcertCARootFn
	origDefault := defaultMkcertCARootFn
	mkcertCARootFn = func() (string, error) { return dir, nil }
	defaultMkcertCARootFn = func() string { return "" }
	defer func() { mkcertCARootFn = orig; defaultMkcertCARootFn = origDefault }()

	result, err := DiscoverLocalCAs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result.Entries))
	}
	if result.Entries[0].Source != "mkcert" {
		t.Errorf("source = %q, want mkcert", result.Entries[0].Source)
	}
}

func TestDiscoverLocalCAs_NoResults(t *testing.T) {
	orig := mkcertCARootFn
	origDefault := defaultMkcertCARootFn
	mkcertCARootFn = func() (string, error) { return "", os.ErrNotExist }
	defaultMkcertCARootFn = func() string { return "" }
	defer func() { mkcertCARootFn = orig; defaultMkcertCARootFn = origDefault }()

	result, err := DiscoverLocalCAs(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(result.Entries))
	}
}

func TestDiscoverLocalCAs_NonexistentDir(t *testing.T) {
	orig := mkcertCARootFn
	origDefault := defaultMkcertCARootFn
	mkcertCARootFn = func() (string, error) { return "", os.ErrNotExist }
	defaultMkcertCARootFn = func() string { return "" }
	defer func() { mkcertCARootFn = orig; defaultMkcertCARootFn = origDefault }()

	result, err := DiscoverLocalCAs([]string{"/nonexistent/path/here"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(result.Entries))
	}
}

func TestDiscoverLocalCAs_DERCert(t *testing.T) {
	dir := t.TempDir()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "DER CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	_ = os.WriteFile(filepath.Join(dir, "ca.der"), der, 0o644)

	orig := mkcertCARootFn
	origDefault := defaultMkcertCARootFn
	mkcertCARootFn = func() (string, error) { return "", os.ErrNotExist }
	defaultMkcertCARootFn = func() string { return "" }
	defer func() { mkcertCARootFn = orig; defaultMkcertCARootFn = origDefault }()

	result, err := DiscoverLocalCAs([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result.Entries))
	}
	if result.Entries[0].Subject == "" {
		t.Error("expected non-empty subject for DER cert")
	}
}

func TestDiscoverLocalCAs_SkipsNonCertFiles(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hello"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "data.json"), []byte("{}"), 0o644)

	orig := mkcertCARootFn
	origDefault := defaultMkcertCARootFn
	mkcertCARootFn = func() (string, error) { return "", os.ErrNotExist }
	defaultMkcertCARootFn = func() string { return "" }
	defer func() { mkcertCARootFn = orig; defaultMkcertCARootFn = origDefault }()

	result, err := DiscoverLocalCAs([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(result.Entries))
	}
}

func TestDiscoverLocalCAs_MultipleDirs(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	makeTestCACert(t, dir1, "ca1")
	makeTestCACert(t, dir2, "ca2")

	orig := mkcertCARootFn
	origDefault := defaultMkcertCARootFn
	mkcertCARootFn = func() (string, error) { return "", os.ErrNotExist }
	defaultMkcertCARootFn = func() string { return "" }
	defer func() { mkcertCARootFn = orig; defaultMkcertCARootFn = origDefault }()

	result, err := DiscoverLocalCAs([]string{dir1, dir2})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result.Entries))
	}
}

func TestDefaultMkcertCAROOT(t *testing.T) {
	// Just verify it returns a non-empty string (platform-dependent)
	root := defaultMkcertCAROOT()
	if root == "" {
		t.Error("expected non-empty default mkcert CAROOT")
	}
}

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	tests := []struct {
		input string
		want  string
	}{
		{"~", home},
		{"", ""},
		{"/absolute/path", "/absolute/path"},
	}
	for _, tt := range tests {
		got := expandHome(tt.input)
		if got != tt.want {
			t.Errorf("expandHome(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
