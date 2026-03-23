package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nickromney/certconv/internal/cert"
	"github.com/nickromney/certconv/test/testutil"
)

// --- Lint CLI tests ---

func TestLint_JSON_CleanCert(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	pair := testutil.MakeCertPair(t)

	engine := cert.NewDefaultEngine()
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"lint", pair.CertPath, "--json"})

	if err := cmd.Execute(); err != nil {
		// lint returns exit 1 when issues found; that's OK.
		if _, _, ok := ExitCode(err); !ok {
			t.Fatalf("expected no error or ExitError, got %v", err)
		}
	}
	var result cert.LintResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("expected valid JSON, got %q err=%v", out.String(), err)
	}
	if result.File != pair.CertPath {
		t.Errorf("File = %q, want %q", result.File, pair.CertPath)
	}
}

func TestLint_HumanOutput_WithIssues(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	pair := testutil.MakeCertPair(t)

	engine := cert.NewDefaultEngine()
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	var out bytes.Buffer
	var errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetArgs([]string{"--plain", "lint", pair.CertPath})

	err := cmd.Execute()
	// If issues found, exit code 1 (silent). If clean, no error.
	if err != nil {
		code, silent, ok := ExitCode(err)
		if !ok || code != 1 || !silent {
			t.Fatalf("expected silent exit 1, got %v", err)
		}
		// Verify human output has issue codes.
		combined := out.String() + errBuf.String()
		if !strings.Contains(combined, "[") {
			t.Errorf("expected issue codes in output, got %q", combined)
		}
	}
}

func TestLint_MissingFile(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	engine := cert.NewDefaultEngine()
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"lint", "/nonexistent/file.pem"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLint_BadCert(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	_ = os.WriteFile(path, []byte("not a cert"), 0o644)

	engine := cert.NewDefaultEngine()
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"lint", path})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for bad cert")
	}
}

func TestLint_NoArgs(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	engine := cert.NewDefaultEngine()
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"lint"})

	err := cmd.Execute()
	code, _, ok := ExitCode(err)
	if !ok || code != 2 {
		t.Fatalf("expected exit code 2, got %T: %v", err, err)
	}
}

// --- Chain CLI tests ---

func TestChain_JSON_Output(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	pair := testutil.MakeCertPair(t)

	engine := cert.NewDefaultEngine()
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"chain", pair.CertPath, "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	var result cert.ChainResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("expected valid JSON, got %q err=%v", out.String(), err)
	}
	if len(result.Certs) == 0 {
		t.Error("expected at least 1 cert in chain")
	}
}

func TestChain_PEM_Output(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	pair := testutil.MakeCertPair(t)

	engine := cert.NewDefaultEngine()
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"chain", pair.CertPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !strings.Contains(out.String(), "BEGIN CERTIFICATE") {
		t.Error("expected PEM output")
	}
}

func TestChain_MissingFile(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	engine := cert.NewDefaultEngine()
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"chain", "/nonexistent/bundle.pem"})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestChain_NoArgs(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	engine := cert.NewDefaultEngine()
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"chain"})

	err := cmd.Execute()
	code, _, ok := ExitCode(err)
	if !ok || code != 2 {
		t.Fatalf("expected exit code 2, got %T: %v", err, err)
	}
}

func TestChain_BadPEM(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	_ = os.WriteFile(path, []byte("not a pem"), 0o644)

	engine := cert.NewDefaultEngine()
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"chain", path})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for bad PEM")
	}
}

// --- from-p7b CLI tests ---

type p7bCLIFakeExec struct{}

func (f p7bCLIFakeExec) Run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	return f.RunWithExtraFiles(ctx, nil, args...)
}

func (p7bCLIFakeExec) RunWithExtraFiles(_ context.Context, _ []cert.ExtraFile, args ...string) ([]byte, []byte, error) {
	if len(args) == 0 {
		return nil, nil, nil
	}
	switch args[0] {
	case "pkcs7":
		return []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), nil, nil
	case "x509":
		return []byte("subject=CN=test\nissuer=CN=issuer\nnotBefore=Jan  1 00:00:00 2020 GMT\nnotAfter=Jan  1 00:00:00 2030 GMT\nserial=01\n"), nil, nil
	default:
		return nil, nil, nil
	}
}

func TestFromP7B_JSON_Output(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	dir := t.TempDir()
	p7bPath := filepath.Join(dir, "test.p7b")
	_ = os.WriteFile(p7bPath, []byte("dummy"), 0o644)

	engine := cert.NewEngine(p7bCLIFakeExec{})
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	outDir := filepath.Join(dir, "extracted")
	cmd.SetArgs([]string{"from-p7b", p7bPath, outDir, "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	var result cert.FromP7BResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("expected valid JSON, got %q err=%v", out.String(), err)
	}
	if len(result.CertFiles) == 0 {
		t.Error("expected at least 1 cert file")
	}
}

func TestFromP7B_HumanOutput(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	dir := t.TempDir()
	p7bPath := filepath.Join(dir, "test.p7b")
	_ = os.WriteFile(p7bPath, []byte("dummy"), 0o644)

	engine := cert.NewEngine(p7bCLIFakeExec{})
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	outDir := filepath.Join(dir, "extracted")
	cmd.SetArgs([]string{"--plain", "from-p7b", p7bPath, outDir})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !strings.Contains(out.String(), "Certificate:") {
		t.Errorf("expected Certificate output, got %q", out.String())
	}
}

func TestFromP7B_MissingFile(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	engine := cert.NewEngine(p7bCLIFakeExec{})
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"from-p7b", "/nonexistent.p7b", "/tmp/out"})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestFromP7B_NoArgs(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	engine := cert.NewDefaultEngine()
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"from-p7b"})

	err := cmd.Execute()
	code, _, ok := ExitCode(err)
	if !ok || code != 2 {
		t.Fatalf("expected exit code 2, got %T: %v", err, err)
	}
}
