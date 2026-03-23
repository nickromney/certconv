package cert

import (
	"context"
	"testing"
)

type p7bFakeExec struct{}

func (f p7bFakeExec) Run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	return f.RunWithExtraFiles(ctx, nil, args...)
}

func (p7bFakeExec) RunWithExtraFiles(_ context.Context, _ []ExtraFile, args ...string) ([]byte, []byte, error) {
	if len(args) == 0 {
		return nil, nil, nil
	}
	switch args[0] {
	case "pkcs7":
		return []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"), nil, nil
	case "x509":
		// Check if it's a summary or details request.
		for _, a := range args {
			if a == "-text" {
				return []byte("Certificate:\n    Data:\n        Subject: CN=test\n"), nil, nil
			}
		}
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

type p7bErrorExec struct{}

func (f p7bErrorExec) Run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	return f.RunWithExtraFiles(ctx, nil, args...)
}

func (p7bErrorExec) RunWithExtraFiles(_ context.Context, _ []ExtraFile, args ...string) ([]byte, []byte, error) {
	return nil, []byte("error reading p7b"), context.Canceled
}

type p7bNoCertsExec struct{}

func (f p7bNoCertsExec) Run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	return f.RunWithExtraFiles(ctx, nil, args...)
}

func (p7bNoCertsExec) RunWithExtraFiles(_ context.Context, _ []ExtraFile, args ...string) ([]byte, []byte, error) {
	// Return non-PEM data (no certificates).
	return []byte("subject = CN = test\nissuer = CN = test\n"), nil, nil
}

func TestP7BSummary_Error(t *testing.T) {
	eng := NewEngine(p7bErrorExec{})
	_, err := eng.P7BSummary(context.Background(), "test.p7b")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestP7BDetails_Error(t *testing.T) {
	eng := NewEngine(p7bErrorExec{})
	_, err := eng.P7BDetails(context.Background(), "test.p7b")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFromP7B_Error(t *testing.T) {
	eng := NewEngine(p7bErrorExec{})
	_, err := eng.FromP7B(context.Background(), "test.p7b", t.TempDir())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFromP7B_NoCerts(t *testing.T) {
	eng := NewEngine(p7bNoCertsExec{})
	_, err := eng.FromP7B(context.Background(), "test.p7b", t.TempDir())
	if err == nil {
		t.Fatal("expected error for no certs")
	}
}

func TestP7BSummary_Fake(t *testing.T) {
	eng := NewEngine(p7bFakeExec{})
	s, err := eng.P7BSummary(context.Background(), "test.p7b")
	if err != nil {
		t.Fatalf("P7BSummary: %v", err)
	}
	if s.FileType != FileTypeP7B {
		t.Errorf("FileType = %v, want p7b", s.FileType)
	}
	if s.Subject == "" {
		t.Error("Subject is empty")
	}
}

func TestP7BDetails_Fake(t *testing.T) {
	eng := NewEngine(p7bFakeExec{})
	d, err := eng.P7BDetails(context.Background(), "test.p7b")
	if err != nil {
		t.Fatalf("P7BDetails: %v", err)
	}
	if d.RawText == "" {
		t.Error("RawText is empty")
	}
	if d.FileType != FileTypeP7B {
		t.Errorf("FileType = %v, want p7b", d.FileType)
	}
}

func TestFromP7B_Fake(t *testing.T) {
	eng := NewEngine(p7bFakeExec{})
	outDir := t.TempDir()
	result, err := eng.FromP7B(context.Background(), "test.p7b", outDir)
	if err != nil {
		t.Fatalf("FromP7B: %v", err)
	}
	if len(result.CertFiles) != 1 {
		t.Fatalf("expected 1 cert file, got %d", len(result.CertFiles))
	}
}
