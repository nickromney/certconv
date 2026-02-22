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
)

type showFakeExec struct{}

func (f showFakeExec) Run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	return f.RunWithExtraFiles(ctx, nil, args...)
}

func (showFakeExec) RunWithExtraFiles(_ context.Context, _ []cert.ExtraFile, args ...string) ([]byte, []byte, error) {
	if len(args) == 0 {
		return nil, nil, nil
	}
	switch args[0] {
	case "pkcs12":
		return []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), nil, nil
	case "x509":
		return []byte(
			"subject=CN=test\n" +
				"issuer=CN=issuer\n" +
				"notBefore=Jan  1 00:00:00 2020 GMT\n" +
				"notAfter=Jan  1 00:00:00 2030 GMT\n" +
				"serial=01\n",
		), nil, nil
	default:
		return nil, nil, nil
	}
}

type matchFakeExec struct{}

func (m matchFakeExec) Run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	return m.RunWithExtraFiles(ctx, nil, args...)
}

func (matchFakeExec) RunWithExtraFiles(_ context.Context, _ []cert.ExtraFile, args ...string) ([]byte, []byte, error) {
	switch args[0] {
	case "x509":
		return []byte("-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----\n"), nil, nil
	case "pkey":
		return []byte("-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----\n"), nil, nil
	default:
		return nil, nil, nil
	}
}

type verifyFakeExec struct {
	ok bool
}

func (v verifyFakeExec) Run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	return v.RunWithExtraFiles(ctx, nil, args...)
}

func (v verifyFakeExec) RunWithExtraFiles(_ context.Context, _ []cert.ExtraFile, args ...string) ([]byte, []byte, error) {
	if len(args) == 0 {
		return nil, nil, nil
	}
	if args[0] != "verify" {
		return nil, nil, nil
	}
	if v.ok {
		return []byte("x: OK\n"), nil, nil
	}
	return []byte("x: FAIL\n"), []byte("unable to get local issuer certificate\n"), context.Canceled // any non-nil error
}

type expiryFakeExec struct {
	valid bool
}

func (e expiryFakeExec) Run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	return e.RunWithExtraFiles(ctx, nil, args...)
}

func (e expiryFakeExec) RunWithExtraFiles(_ context.Context, _ []cert.ExtraFile, args ...string) ([]byte, []byte, error) {
	if len(args) == 0 {
		return nil, nil, nil
	}
	if args[0] != "x509" {
		return nil, nil, nil
	}
	// expiry reads -enddate and then does -checkend N -noout.
	for _, a := range args {
		if a == "-enddate" {
			return []byte("notAfter=Jan  1 00:00:00 2030 GMT\n"), nil, nil
		}
	}
	for _, a := range args {
		if a == "-checkend" {
			if e.valid {
				return nil, nil, nil
			}
			return nil, []byte("certificate has expired\n"), context.Canceled
		}
	}
	return nil, nil, nil
}

type captureExtraExec struct {
	calls []struct {
		extra []cert.ExtraFile
		args  []string
	}
}

func (c *captureExtraExec) Run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	return c.RunWithExtraFiles(ctx, nil, args...)
}

func (c *captureExtraExec) RunWithExtraFiles(_ context.Context, extra []cert.ExtraFile, args ...string) ([]byte, []byte, error) {
	c.calls = append(c.calls, struct {
		extra []cert.ExtraFile
		args  []string
	}{
		extra: append([]cert.ExtraFile(nil), extra...),
		args:  append([]string(nil), args...),
	})
	switch args[0] {
	case "pkcs12":
		return []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), nil, nil
	case "x509":
		return []byte(
			"subject=CN=test\n" +
				"issuer=CN=issuer\n" +
				"notBefore=Jan  1 00:00:00 2020 GMT\n" +
				"notAfter=Jan  1 00:00:00 2030 GMT\n" +
				"serial=01\n",
		), nil, nil
	default:
		return nil, nil, nil
	}
}

type convertFakeExec struct{}

func (c convertFakeExec) Run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	return c.RunWithExtraFiles(ctx, nil, args...)
}

func (convertFakeExec) RunWithExtraFiles(_ context.Context, _ []cert.ExtraFile, args ...string) ([]byte, []byte, error) {
	if len(args) == 0 {
		return nil, nil, nil
	}

	writeOut := func(path string, data []byte) {
		if strings.TrimSpace(path) == "" {
			return
		}
		_ = os.WriteFile(path, data, 0o600)
	}
	outArg := func(flag string) string {
		for i := 0; i < len(args)-1; i++ {
			if args[i] == flag {
				return args[i+1]
			}
		}
		return ""
	}

	switch args[0] {
	case "x509":
		// Summary/detect and also DER conversions.
		if contains(args, "-outform") && contains(args, "DER") && !contains(args, "-out") {
			return []byte{0x30, 0x82, 0x01, 0x01}, nil, nil
		}
		if contains(args, "-out") {
			writeOut(outArg("-out"), []byte{0x01, 0x02, 0x03})
			return nil, nil, nil
		}
		if contains(args, "-pubkey") {
			return []byte("-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----\n"), nil, nil
		}
		return []byte(
			"subject=CN=test\n" +
				"issuer=CN=issuer\n" +
				"notBefore=Jan  1 00:00:00 2020 GMT\n" +
				"notAfter=Jan  1 00:00:00 2030 GMT\n" +
				"serial=01\n",
		), nil, nil

	case "pkey":
		if contains(args, "-out") {
			writeOut(outArg("-out"), []byte{0x04, 0x05})
			return nil, nil, nil
		}
		return []byte("-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----\n"), nil, nil

	case "pkcs12":
		if contains(args, "-noout") {
			return nil, nil, nil
		}
		if contains(args, "-nokeys") && !contains(args, "-out") {
			return []byte("-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"), nil, nil
		}
		if contains(args, "-export") && contains(args, "-out") {
			writeOut(outArg("-out"), []byte("PFX"))
			return nil, nil, nil
		}
		if contains(args, "-out") {
			// from-pfx extract outputs.
			writeOut(outArg("-out"), []byte("-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"))
			return nil, nil, nil
		}
		return nil, nil, nil

	default:
		return nil, nil, nil
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func TestRoot_NoArgs_NonInteractive_ShowsHelpAndExit2(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	engine := cert.NewDefaultEngine()
	called := false
	runTUI := func(_ string) error { called = true; return nil }

	cmd := NewRootCmd(engine, runTUI, BuildInfo{Version: "test"})
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	code, silent, ok := ExitCode(err)
	if !ok {
		t.Fatalf("expected ExitError, got %T: %v", err, err)
	}
	if code != 2 || !silent {
		t.Fatalf("expected exit code 2 silent, got code=%d silent=%v err=%v", code, silent, err)
	}
	if called {
		t.Fatalf("expected TUI not to run in non-interactive mode")
	}
	if strings.TrimSpace(out.String()) == "" {
		t.Fatalf("expected help output on stdout")
	}
	if got := errOut.String(); strings.TrimSpace(got) != "" {
		t.Fatalf("expected empty stderr, got %q", got)
	}
}

func TestConversions_JSON_OutputParses(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	engine := cert.NewEngine(convertFakeExec{})

	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "c.key")
	derPath := filepath.Join(dir, "c.der")
	b64Path := filepath.Join(dir, "c.b64")
	pfxPath := filepath.Join(dir, "c.pfx")

	if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(derPath, []byte{0x30, 0x82, 0x01, 0x00}, 0o644); err != nil { // looks like DER SEQUENCE
		t.Fatal(err)
	}
	if err := os.WriteFile(b64Path, []byte("QUJD"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pfxPath, []byte("PFX"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		args []string
	}{
		{args: []string{"to-pfx", "--json", certPath, keyPath, filepath.Join(dir, "out.pfx")}},
		{args: []string{"from-pfx", "--json", pfxPath, filepath.Join(dir, "extracted")}},
		{args: []string{"to-der", "--json", certPath, filepath.Join(dir, "c2.der")}},
		{args: []string{"from-der", "--json", derPath, filepath.Join(dir, "c2.pem")}},
		{args: []string{"to-base64", "--json", certPath, filepath.Join(dir, "c2.b64")}},
		{args: []string{"from-base64", "--json", b64Path, filepath.Join(dir, "c2.dec")}},
		{args: []string{"combine", "--json", certPath, keyPath, filepath.Join(dir, "combined.pem")}},
	}

	for _, tt := range tests {
		cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
		cmd.SetArgs(tt.args)
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&bytes.Buffer{})
		err := cmd.Execute()
		if err != nil {
			t.Fatalf("args %v: expected ok, got %v", tt.args, err)
		}
		var js any
		if jerr := json.Unmarshal(out.Bytes(), &js); jerr != nil {
			t.Fatalf("args %v: expected json, got %q: %v", tt.args, out.String(), jerr)
		}
	}
}

func TestRoot_NoArgs_Interactive_RunsTUI(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return true }

	engine := cert.NewDefaultEngine()
	called := false
	runTUI := func(_ string) error { called = true; return nil }

	cmd := NewRootCmd(engine, runTUI, BuildInfo{Version: "test"})
	cmd.SetArgs([]string{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !called {
		t.Fatalf("expected TUI to run in interactive mode")
	}
}

func TestRoot_PathArg_Interactive_RequiresExplicitCLICommand(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return true }

	engine := cert.NewDefaultEngine()
	called := false
	runTUI := func(startDir string) error { called = true; _ = startDir; return nil }

	cmd := NewRootCmd(engine, runTUI, BuildInfo{Version: "test"})
	someArg := filepath.Join(t.TempDir(), "x")
	cmd.SetArgs([]string{someArg})

	err := cmd.Execute()
	code, _, ok := ExitCode(err)
	if !ok || code != 2 {
		t.Fatalf("expected exit code 2, got %T: %v", err, err)
	}
	if called {
		t.Fatalf("expected TUI not to run when root receives positional args without --tui")
	}
}

func TestRoot_TUIFlag_PathArg_Interactive_RunsTUIWithResolvedDir(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return true }

	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o755); err != nil {
		t.Fatal(err)
	}

	engine := cert.NewDefaultEngine()
	var gotDir string
	runTUI := func(startDir string) error {
		gotDir = startDir
		return nil
	}

	cmd := NewRootCmd(engine, runTUI, BuildInfo{Version: "test"})
	cmd.SetArgs([]string{"--tui", "~/.ssh"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if gotDir != sshDir {
		t.Fatalf("expected start dir %q, got %q", sshDir, gotDir)
	}
}

func TestRoot_QuickDER_FromPEM_WritesStdout(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	engine := cert.NewEngine(convertFakeExec{})
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{certPath, "--der"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !bytes.Equal(out.Bytes(), []byte{0x30, 0x82, 0x01, 0x01}) {
		t.Fatalf("expected DER bytes on stdout, got %v", out.Bytes())
	}
}

func TestRoot_QuickDER_FromPFX_WritesStdout(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	dir := t.TempDir()
	pfxPath := filepath.Join(dir, "cert.pfx")
	if err := os.WriteFile(pfxPath, []byte("PFX"), 0o644); err != nil {
		t.Fatal(err)
	}

	engine := cert.NewEngine(convertFakeExec{})
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{pfxPath, "--der"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !bytes.Equal(out.Bytes(), []byte{0x30, 0x82, 0x01, 0x01}) {
		t.Fatalf("expected DER bytes on stdout, got %v", out.Bytes())
	}
}

func TestRoot_QuickDER_RequiresSingleFileArg(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	engine := cert.NewEngine(convertFakeExec{})
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	cmd.SetArgs([]string{"--der"})
	err := cmd.Execute()
	code, _, ok := ExitCode(err)
	if !ok || code != 2 {
		t.Fatalf("expected exit code 2, got %T: %v", err, err)
	}
}

func TestRoot_TUIFlag_NonInteractive_Exit2(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	engine := cert.NewDefaultEngine()
	called := false
	runTUI := func(_ string) error { called = true; return nil }

	cmd := NewRootCmd(engine, runTUI, BuildInfo{Version: "test"})
	cmd.SetArgs([]string{"--tui"})

	err := cmd.Execute()
	code, silent, ok := ExitCode(err)
	if !ok {
		t.Fatalf("expected ExitError, got %T: %v", err, err)
	}
	if code != 2 || silent {
		t.Fatalf("expected exit code 2 (not silent), got code=%d silent=%v err=%v", code, silent, err)
	}
	if called {
		t.Fatalf("expected TUI not to run without a TTY")
	}
}

func TestTUISubcommand_PathArg_Interactive_RunsTUIWithResolvedDir(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return true }

	home := t.TempDir()
	t.Setenv("HOME", home)
	docsDir := filepath.Join(home, "Documents")
	if err := os.MkdirAll(docsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	engine := cert.NewDefaultEngine()
	var gotDir string
	runTUI := func(startDir string) error {
		gotDir = startDir
		return nil
	}

	cmd := NewRootCmd(engine, runTUI, BuildInfo{Version: "test"})
	cmd.SetArgs([]string{"tui", "~/Documents"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if gotDir != docsDir {
		t.Fatalf("expected start dir %q, got %q", docsDir, gotDir)
	}
}

func TestTUISubcommand_NonInteractive_Exit2(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	engine := cert.NewDefaultEngine()
	called := false
	runTUI := func(_ string) error { called = true; return nil }

	cmd := NewRootCmd(engine, runTUI, BuildInfo{Version: "test"})
	cmd.SetArgs([]string{"tui"})

	err := cmd.Execute()
	code, _, ok := ExitCode(err)
	if !ok || code != 2 {
		t.Fatalf("expected exit code 2, got %T: %v", err, err)
	}
	if called {
		t.Fatalf("expected TUI not to run without a TTY")
	}
}

func TestShow_PasswordStdin_DoesNotError(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	engine := cert.NewEngine(showFakeExec{})
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})

	pfxPath := t.TempDir() + "/x.pfx"
	if err := os.WriteFile(pfxPath, []byte("dummy"), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetIn(strings.NewReader("\n"))
	cmd.SetArgs([]string{"show", pfxPath, "--password-stdin"})

	err := cmd.Execute()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestShow_PasswordFile_LoadsAndPassesSecret(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	exec := &captureExtraExec{}
	engine := cert.NewEngine(exec)
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})

	pfxPath := t.TempDir() + "/x.pfx"
	if err := os.WriteFile(pfxPath, []byte("dummy"), 0o644); err != nil {
		t.Fatal(err)
	}
	pwFile := t.TempDir() + "/pw.txt"
	if err := os.WriteFile(pwFile, []byte("sekret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs([]string{"show", pfxPath, "--password-file", pwFile})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	foundSecret := false
	for _, call := range exec.calls {
		if len(call.extra) > 0 {
			if string(call.extra[0].Data) != "sekret" {
				t.Fatalf("expected secret %q, got %q", "sekret", string(call.extra[0].Data))
			}
			foundSecret = true
		}
		// Ensure we're not using pass: in argv.
		for _, a := range call.args {
			if strings.Contains(a, "pass:") {
				t.Fatalf("expected no pass: in args, got %v", call.args)
			}
		}
	}
	if !foundSecret {
		t.Fatalf("expected secret passed via extra files, got calls=%+v", exec.calls)
	}
}

func TestShow_PasswordSources_MutuallyExclusive(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	engine := cert.NewEngine(showFakeExec{})
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})

	pfxPath := t.TempDir() + "/x.pfx"
	if err := os.WriteFile(pfxPath, []byte("dummy"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd.SetIn(strings.NewReader("pw"))
	cmd.SetArgs([]string{"show", pfxPath, "--password-stdin", "--password-file", pfxPath})
	err := cmd.Execute()
	code, _, ok := ExitCode(err)
	if !ok || code != 2 {
		t.Fatalf("expected exit code 2, got %T: %v", err, err)
	}
}

func TestInlineSecretWarning_PrintsToTTYStderrOnly(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(f *os.File) bool { return f == os.Stderr }

	// Reset one-time warnings for this test.
	inlineSecretWarnMu.Lock()
	inlineSecretWarned = map[string]bool{}
	inlineSecretWarnMu.Unlock()

	exec := &captureExtraExec{}
	engine := cert.NewEngine(exec)
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	var errOut bytes.Buffer
	cmd.SetErr(&errOut)

	pfxPath := t.TempDir() + "/x.pfx"
	if err := os.WriteFile(pfxPath, []byte("dummy"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd.SetArgs([]string{"show", pfxPath, "--password", "sekret"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if !strings.Contains(errOut.String(), "Warning: --password") {
		t.Fatalf("expected warning on stderr, got %q", errOut.String())
	}

	// Non-TTY stderr: no warning.
	isTerminalFn = func(_ *os.File) bool { return false }
	inlineSecretWarnMu.Lock()
	inlineSecretWarned = map[string]bool{}
	inlineSecretWarnMu.Unlock()
	errOut.Reset()

	cmd2 := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	cmd2.SetErr(&errOut)
	cmd2.SetArgs([]string{"show", pfxPath, "--password", "sekret"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if strings.Contains(errOut.String(), "Warning:") {
		t.Fatalf("expected no warning on non-tty stderr, got %q", errOut.String())
	}
}

func TestToPFX_DoubleStdinSecrets_IsUsageError(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	engine := cert.NewEngine(showFakeExec{})
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	cmd.SetIn(strings.NewReader("pw"))
	cmd.SetArgs([]string{"to-pfx", "a.pem", "b.key", "out.pfx", "--password-stdin", "--key-password-stdin"})
	err := cmd.Execute()
	code, _, ok := ExitCode(err)
	if !ok || code != 2 {
		t.Fatalf("expected exit code 2, got %T: %v", err, err)
	}
}

func TestShow_JSON_OutputParses(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	engine := cert.NewEngine(showFakeExec{})
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})

	pfxPath := t.TempDir() + "/x.pfx"
	if err := os.WriteFile(pfxPath, []byte("dummy"), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetIn(strings.NewReader("\n"))
	cmd.SetArgs([]string{"show", pfxPath, "--json", "--password-stdin"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	var s cert.CertSummary
	if err := json.Unmarshal(out.Bytes(), &s); err != nil {
		t.Fatalf("expected valid JSON, got %q err=%v", out.String(), err)
	}
	if s.FileType != cert.FileTypePFX {
		t.Fatalf("expected filetype pfx, got %q", s.FileType)
	}
	if s.Subject == "" {
		t.Fatalf("expected non-empty subject")
	}
}

func TestMatch_JSON_ExitCodeAndOutput(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	engine := cert.NewEngine(matchFakeExec{})
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	var out bytes.Buffer
	cmd.SetOut(&out)

	certPath := t.TempDir() + "/c.pem"
	keyPath := t.TempDir() + "/k.key"
	if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd.SetArgs([]string{"match", certPath, keyPath, "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	var r cert.MatchResult
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("expected valid JSON, got %q err=%v", out.String(), err)
	}
	if !r.Match {
		t.Fatalf("expected match true")
	}
}

func TestVerify_JSON_ExitCodeAndOutput(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	certPath := t.TempDir() + "/c.pem"
	caPath := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(certPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("valid", func(t *testing.T) {
		engine := cert.NewEngine(verifyFakeExec{ok: true})
		cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"verify", certPath, caPath, "--json"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		var r cert.VerifyResult
		if err := json.Unmarshal(out.Bytes(), &r); err != nil {
			t.Fatalf("expected valid JSON, got %q err=%v", out.String(), err)
		}
		if !r.Valid {
			t.Fatalf("expected valid true")
		}
	})

	t.Run("invalid", func(t *testing.T) {
		engine := cert.NewEngine(verifyFakeExec{ok: false})
		cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"verify", certPath, caPath, "--json"})
		err := cmd.Execute()
		code, silent, ok := ExitCode(err)
		if !ok || code != 1 || !silent {
			t.Fatalf("expected silent exit code 1, got %T: %v", err, err)
		}
		var r cert.VerifyResult
		if err := json.Unmarshal(out.Bytes(), &r); err != nil {
			t.Fatalf("expected valid JSON, got %q err=%v", out.String(), err)
		}
		if r.Valid {
			t.Fatalf("expected valid false")
		}
	})
}

func TestExpiry_JSON_ExitCodeAndOutput(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	certPath := t.TempDir() + "/c.pem"
	if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("valid", func(t *testing.T) {
		engine := cert.NewEngine(expiryFakeExec{valid: true})
		cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"expiry", certPath, "--days", "30", "--json"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		var r cert.ExpiryResult
		if err := json.Unmarshal(out.Bytes(), &r); err != nil {
			t.Fatalf("expected valid JSON, got %q err=%v", out.String(), err)
		}
		if !r.Valid {
			t.Fatalf("expected valid true")
		}
	})

	t.Run("invalid", func(t *testing.T) {
		engine := cert.NewEngine(expiryFakeExec{valid: false})
		cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"expiry", certPath, "--days", "30", "--json"})
		err := cmd.Execute()
		code, silent, ok := ExitCode(err)
		if !ok || code != 1 || !silent {
			t.Fatalf("expected silent exit code 1, got %T: %v", err, err)
		}
		var r cert.ExpiryResult
		if err := json.Unmarshal(out.Bytes(), &r); err != nil {
			t.Fatalf("expected valid JSON, got %q err=%v", out.String(), err)
		}
		if r.Valid {
			t.Fatalf("expected valid false")
		}
	})
}

func TestVerify_PlainOutput_DisablesANSIAndUnicode(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(f *os.File) bool { return f == os.Stdout }

	certPath := t.TempDir() + "/c.pem"
	caPath := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(certPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}

	engine := cert.NewEngine(verifyFakeExec{ok: true})
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--plain", "verify", certPath, caPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	s := out.String()
	if strings.Contains(s, "\x1b[") {
		t.Fatalf("expected no ANSI escapes, got %q", s)
	}
	if strings.Contains(s, "→") || strings.Contains(s, "✓") {
		t.Fatalf("expected ASCII-only, got %q", s)
	}
	if !strings.Contains(s, ">  Verifying") || !strings.Contains(s, "OK  Certificate chain verified") {
		t.Fatalf("expected plain markers, got %q", s)
	}
}

func TestResolvePath_ExpandsHomeAndCertsDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmpWD := t.TempDir()
	if err := os.Chdir(tmpWD); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(wd) })

	homeFile := filepath.Join(home, "from-home.pem")
	if err := os.WriteFile(homeFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := resolvePath("~/from-home.pem"); got != homeFile {
		t.Fatalf("expected expanded home path %q, got %q", homeFile, got)
	}

	certsDir := filepath.Join(home, "certs")
	if err := os.MkdirAll(certsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(certsDir, "from-env.pem")
	if err := os.WriteFile(envFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CERTCONV_CERTS_DIR", "~/certs")
	if got := resolvePath("from-env.pem"); got != envFile {
		t.Fatalf("expected env-resolved path %q, got %q", envFile, got)
	}
}

func TestQuiet_SuppressesStatus_ToBase64(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	// to-base64 doesn't use openssl; executor can be nil-backed via showFakeExec.
	engine := cert.NewEngine(showFakeExec{})
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)

	in := t.TempDir() + "/in.bin"
	outFile := t.TempDir() + "/out.b64"
	if err := os.WriteFile(in, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd.SetArgs([]string{"--quiet", "to-base64", in, outFile})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if strings.TrimSpace(out.String()) != "" {
		t.Fatalf("expected no stdout with --quiet, got %q", out.String())
	}
	if strings.TrimSpace(errOut.String()) != "" {
		t.Fatalf("expected no stderr, got %q", errOut.String())
	}
	if _, err := os.Stat(outFile); err != nil {
		t.Fatalf("expected output file, got %v", err)
	}
}

func TestShow_PathStdin_ResolvesInputPath(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	engine := cert.NewEngine(showFakeExec{})
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})

	pfxPath := t.TempDir() + "/x.pfx"
	if err := os.WriteFile(pfxPath, []byte("dummy"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd.SetIn(strings.NewReader(pfxPath + "\n"))
	cmd.SetArgs([]string{"show", "--path-stdin"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestVerify_Path0Stdin_ResolvesFirstPath(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	certPath := t.TempDir() + "/c.pem"
	caPath := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(certPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}

	engine := cert.NewEngine(verifyFakeExec{ok: true})
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	cmd.SetIn(strings.NewReader(certPath + "\x00"))
	cmd.SetArgs([]string{"verify", "--json", "--path0-stdin", caPath})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestShow_PathStdin_ConflictsWithSecretStdin(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	engine := cert.NewEngine(showFakeExec{})
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})

	pfxPath := t.TempDir() + "/x.pfx"
	if err := os.WriteFile(pfxPath, []byte("dummy"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd.SetIn(strings.NewReader(pfxPath + "\n"))
	cmd.SetArgs([]string{"show", "--path-stdin", "--password-stdin"})
	err := cmd.Execute()
	code, _, ok := ExitCode(err)
	if !ok || code != 2 {
		t.Fatalf("expected exit code 2, got %T: %v", err, err)
	}
}
