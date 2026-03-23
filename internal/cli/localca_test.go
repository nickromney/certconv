package cli

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nickromney/certconv/internal/cert"
)

func makeTestCA(t *testing.T, dir, name string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
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
	f, err := os.Create(filepath.Join(dir, name+".pem"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestLocalCA_JSON(t *testing.T) {
	dir := t.TempDir()
	makeTestCA(t, dir, "test-ca")

	oldMkcert := cert.MkcertCARootFnForTest()
	oldDefault := cert.DefaultMkcertCARootFnForTest()
	t.Cleanup(func() {
		cert.SetMkcertCARootFnForTest(oldMkcert)
		cert.SetDefaultMkcertCARootFnForTest(oldDefault)
	})
	cert.SetMkcertCARootFnForTest(func() (string, error) { return "", os.ErrNotExist })
	cert.SetDefaultMkcertCARootFnForTest(func() string { return "" })

	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	engine := cert.NewDefaultEngine()
	root := NewRootCmd(engine, nil, BuildInfo{})
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"local-ca", "--json", "--dir", dir})

	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	var result cert.LocalCAResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("json decode: %v\noutput: %s", err, buf.String())
	}
	if len(result.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result.Entries))
	}
	if result.Entries[0].Source != "custom" {
		t.Errorf("source = %q, want custom", result.Entries[0].Source)
	}
}

func TestLocalCA_HumanOutput(t *testing.T) {
	dir := t.TempDir()
	makeTestCA(t, dir, "my-ca")

	oldMkcert := cert.MkcertCARootFnForTest()
	oldDefault := cert.DefaultMkcertCARootFnForTest()
	t.Cleanup(func() {
		cert.SetMkcertCARootFnForTest(oldMkcert)
		cert.SetDefaultMkcertCARootFnForTest(oldDefault)
	})
	cert.SetMkcertCARootFnForTest(func() (string, error) { return "", os.ErrNotExist })
	cert.SetDefaultMkcertCARootFnForTest(func() string { return "" })

	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	engine := cert.NewDefaultEngine()
	root := NewRootCmd(engine, nil, BuildInfo{})
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"local-ca", "--dir", dir})

	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Found 1 local CA") {
		t.Errorf("expected 'Found 1 local CA' in output, got: %s", out)
	}
	if !strings.Contains(out, "CUSTOM") {
		t.Errorf("expected 'CUSTOM' in output, got: %s", out)
	}
}

func TestLocalCA_NoResults(t *testing.T) {
	oldMkcert := cert.MkcertCARootFnForTest()
	oldDefault := cert.DefaultMkcertCARootFnForTest()
	t.Cleanup(func() {
		cert.SetMkcertCARootFnForTest(oldMkcert)
		cert.SetDefaultMkcertCARootFnForTest(oldDefault)
	})
	cert.SetMkcertCARootFnForTest(func() (string, error) { return "", os.ErrNotExist })
	cert.SetDefaultMkcertCARootFnForTest(func() string { return "" })

	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	engine := cert.NewDefaultEngine()
	root := NewRootCmd(engine, nil, BuildInfo{})
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs([]string{"local-ca"})

	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "No local CA") {
		t.Errorf("expected 'No local CA' in output, got: %s", out)
	}
}
