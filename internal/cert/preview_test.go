package cert

import (
	"context"
	"errors"
	"os"
	"testing"
)

type previewFakeExec struct{}

func (p previewFakeExec) Run(ctx context.Context, args ...string) (stdout, stderr []byte, err error) {
	_ = ctx
	if len(args) == 0 {
		return nil, nil, nil
	}

	switch args[0] {
	case "x509":
		// MatchKeyToCert: x509 -pubkey -noout
		if hasArg(args, "-pubkey") && hasArg(args, "-noout") {
			return []byte("-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----\n"), nil, nil
		}
		// CertDER: x509 -outform DER
		if hasArg(args, "-outform") && hasArg(args, "DER") {
			return []byte{0x30, 0x82, 0x01, 0x0a}, nil, nil
		}
		return nil, nil, nil

	case "pkey":
		// MatchKeyToCert: pkey -pubout
		if hasArg(args, "-pubout") {
			return []byte("-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----\n"), nil, nil
		}
		return nil, nil, nil

	case "pkcs12":
		// PFXBytes: pkcs12 -export -out <path> ...
		out := ""
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "-out" {
				out = args[i+1]
				break
			}
		}
		if out == "" {
			return nil, []byte("missing -out"), errors.New("exit status 1")
		}
		if err := os.WriteFile(out, []byte("PFXBYTES"), 0o600); err != nil {
			return nil, []byte(err.Error()), err
		}
		return nil, nil, nil
	}

	return nil, nil, nil
}

func TestEngine_CertDER_Preview(t *testing.T) {
	// CertDER validates PEM cert via marker scan, so create a minimal marker file.
	f := t.TempDir() + "/cert.pem"
	if err := os.WriteFile(f, []byte("-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	e := NewEngine(previewFakeExec{})
	b, err := e.CertDER(context.Background(), f)
	if err != nil {
		t.Fatalf("CertDER error: %v", err)
	}
	if len(b) == 0 || b[0] != 0x30 {
		t.Fatalf("expected DER bytes, got %v", b)
	}
}

func TestEngine_PFXBytes_Preview(t *testing.T) {
	dir := t.TempDir()
	certPath := dir + "/cert.pem"
	keyPath := dir + "/key.pem"
	if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	e := NewEngine(previewFakeExec{})
	b, err := e.PFXBytes(context.Background(), certPath, keyPath, "", "")
	if err != nil {
		t.Fatalf("PFXBytes error: %v", err)
	}
	if string(b) != "PFXBYTES" {
		t.Fatalf("unexpected PFX bytes: %q", string(b))
	}
}
