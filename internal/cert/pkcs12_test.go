package cert

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type fakeExecutor struct {
	calls [][]string
}

func (f *fakeExecutor) Run(ctx context.Context, args ...string) (stdout, stderr []byte, err error) {
	return f.RunWithExtraFiles(ctx, nil, args...)
}

func (f *fakeExecutor) RunWithExtraFiles(ctx context.Context, _ []ExtraFile, args ...string) (stdout, stderr []byte, err error) {
	_ = ctx
	cp := make([]string, len(args))
	copy(cp, args)
	f.calls = append(f.calls, cp)

	if len(args) == 0 {
		return nil, nil, nil
	}

	switch args[0] {
	case "pkcs12":
		// Simulate OpenSSL 3 failing to load legacy provider on first attempt.
		if !hasArg(args, "-legacy") {
			return nil, []byte("...inner_evp_generic_fetch:unsupported..."), errors.New("exit status 1")
		}
		// Second attempt with -legacy succeeds and returns PEM (content isn't parsed by our fake x509).
		return []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), nil, nil

	case "x509":
		// Summary parsing expects these lines.
		return []byte(
			"subject=CN=test\n" +
				"issuer=CN=issuer\n" +
				"notBefore=Jan  1 00:00:00 2020 GMT\n" +
				"notAfter=Jan  1 00:00:00 2030 GMT\n" +
				"serial=01\n",
		), nil, nil
	}

	return nil, nil, nil
}

func TestEngine_Summary_PFX_RetriesWithLegacy(t *testing.T) {
	dir := t.TempDir()
	pfxPath := filepath.Join(dir, "test.pfx")
	if err := os.WriteFile(pfxPath, []byte("dummy"), 0o644); err != nil {
		t.Fatal(err)
	}

	exec := &fakeExecutor{}
	e := NewEngine(exec)

	s, err := e.Summary(context.Background(), pfxPath, "")
	if err != nil {
		t.Fatalf("Summary error: %v", err)
	}
	if s.Subject != "CN=test" {
		t.Fatalf("expected Subject %q, got %q", "CN=test", s.Subject)
	}

	if len(exec.calls) < 2 {
		t.Fatalf("expected at least 2 openssl calls, got %d", len(exec.calls))
	}
	if exec.calls[0][0] != "pkcs12" || hasArg(exec.calls[0], "-legacy") {
		t.Fatalf("expected first call to be pkcs12 without -legacy, got %v", exec.calls[0])
	}
	if exec.calls[1][0] != "pkcs12" || !hasArg(exec.calls[1], "-legacy") {
		t.Fatalf("expected second call to be pkcs12 with -legacy, got %v", exec.calls[1])
	}
}

func TestPFXReadError_LegacyUnsupported(t *testing.T) {
	err := pfxReadError(errors.New("exit status 1"), []byte("inner_evp_generic_fetch:unsupported"))
	if !errors.Is(err, ErrPFXLegacyUnsupported) {
		t.Fatalf("expected ErrPFXLegacyUnsupported, got: %v", err)
	}
}
