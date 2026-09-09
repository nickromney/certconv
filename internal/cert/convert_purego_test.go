package cert

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nickromney/certconv/test/testutil"
)

// unavailableExecutor simulates a machine with no openssl on PATH.
type unavailableExecutor struct {
	calls int
}

func (u *unavailableExecutor) Run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	return u.RunWithExtraFiles(ctx, nil, args...)
}

func (u *unavailableExecutor) RunWithExtraFiles(_ context.Context, _ []ExtraFile, _ ...string) ([]byte, []byte, error) {
	u.calls++
	return nil, nil, errors.New(`exec: "openssl": executable file not found in $PATH`)
}

func TestToDER_Cert_WithoutOpenSSL(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	exec := &unavailableExecutor{}
	eng := NewEngine(exec)

	derPath := filepath.Join(pair.Dir, "purego.der")
	if err := eng.ToDER(context.Background(), pair.CertPath, derPath, false, ""); err != nil {
		t.Fatalf("ToDER(cert) without openssl: %v", err)
	}
	if exec.calls != 0 {
		t.Errorf("expected no openssl invocations for a well-formed cert, got %d", exec.calls)
	}

	// Output must be exactly the certificate's DER bytes.
	pemData, err := os.ReadFile(pair.CertPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("test fixture is not PEM")
	}
	got, err := os.ReadFile(derPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, block.Bytes) {
		t.Error("DER output does not match certificate DER bytes")
	}

	info, err := os.Stat(derPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("DER cert file mode = %o, want 644", info.Mode().Perm())
	}
}

func TestFromDER_Cert_WithoutOpenSSL(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	real := NewDefaultEngine()
	ctx := context.Background()

	derPath := filepath.Join(pair.Dir, "roundtrip.der")
	if err := real.ToDER(ctx, pair.CertPath, derPath, false, ""); err != nil {
		t.Fatalf("seed DER: %v", err)
	}

	exec := &unavailableExecutor{}
	eng := NewEngine(exec)
	pemPath := filepath.Join(pair.Dir, "purego-from-der.pem")
	if err := eng.FromDER(ctx, derPath, pemPath, false, ""); err != nil {
		t.Fatalf("FromDER(cert) without openssl: %v", err)
	}
	if exec.calls != 0 {
		t.Errorf("expected no openssl invocations for a well-formed DER cert, got %d", exec.calls)
	}
	if err := ValidatePEMCert(pemPath); err != nil {
		t.Errorf("converted PEM not valid: %v", err)
	}

	// Round-trip: PEM back to DER must equal the input DER.
	pemData, err := os.ReadFile(pemPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("output is not PEM")
	}
	derData, err := os.ReadFile(derPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(block.Bytes, derData) {
		t.Error("PEM output does not round-trip to input DER")
	}
}

// writingFakeExecutor emulates an openssl that succeeds by writing plausible
// output to the path following "-out". It lets tests prove the openssl
// fallback engages without depending on a cert that Go rejects but a real
// openssl accepts.
type writingFakeExecutor struct {
	calls   int
	payload []byte
}

func (w *writingFakeExecutor) Run(ctx context.Context, args ...string) ([]byte, []byte, error) {
	return w.RunWithExtraFiles(ctx, nil, args...)
}

func (w *writingFakeExecutor) RunWithExtraFiles(_ context.Context, _ []ExtraFile, args ...string) ([]byte, []byte, error) {
	w.calls++
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-out" {
			if err := os.WriteFile(args[i+1], w.payload, 0o600); err != nil {
				return nil, nil, err
			}
		}
	}
	return nil, nil, nil
}

func TestToDER_Cert_FallsBackToOpenSSLWhenGoParseFails(t *testing.T) {
	dir := t.TempDir()

	// A PEM CERTIFICATE block whose payload is not a parseable certificate:
	// passes the marker check, fails crypto/x509, and so must reach openssl.
	garbage := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("this is not DER at all"),
	})
	certPath := filepath.Join(dir, "odd.pem")
	if err := os.WriteFile(certPath, garbage, 0o644); err != nil {
		t.Fatal(err)
	}

	exec := &writingFakeExecutor{payload: []byte{0x30, 0x03, 0x02, 0x01, 0x01}}
	eng := NewEngine(exec)

	outPath := filepath.Join(dir, "fallback.der")
	if err := eng.ToDER(context.Background(), certPath, outPath, false, ""); err != nil {
		t.Fatalf("ToDER with openssl fallback: %v", err)
	}
	if exec.calls == 0 {
		t.Fatal("expected openssl fallback to be invoked for a cert Go cannot parse")
	}
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("fallback output missing: %v", err)
	}
}

func TestToDER_Cert_ErrorMentionsBothPathsWhenAllFail(t *testing.T) {
	dir := t.TempDir()
	garbage := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("still not DER"),
	})
	certPath := filepath.Join(dir, "odd.pem")
	if err := os.WriteFile(certPath, garbage, 0o644); err != nil {
		t.Fatal(err)
	}

	eng := NewEngine(&unavailableExecutor{})
	err := eng.ToDER(context.Background(), certPath, filepath.Join(dir, "nope.der"), false, "")
	if err == nil {
		t.Fatal("expected error when both pure-Go and openssl paths fail")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("convert cert to DER")) {
		t.Errorf("error should keep the operation context, got: %v", err)
	}
}

func TestFromDER_Cert_Base64OutputStableAcrossPaths(t *testing.T) {
	// The pure-Go path must produce byte-identical PEM to what the openssl
	// path produced historically (64-column base64 body, standard headers).
	pair := testutil.MakeCertPair(t)
	ctx := context.Background()

	derPath := filepath.Join(pair.Dir, "stable.der")
	if err := NewDefaultEngine().ToDER(ctx, pair.CertPath, derPath, false, ""); err != nil {
		t.Fatalf("seed DER: %v", err)
	}

	viaOpenSSL := filepath.Join(pair.Dir, "via-openssl.pem")
	if _, _, err := (&OSExecutor{}).Run(ctx, "x509", "-in", derPath, "-inform", "DER", "-out", viaOpenSSL, "-outform", "PEM"); err != nil {
		t.Skipf("openssl unavailable for parity check: %v", err)
	}

	viaGo := filepath.Join(pair.Dir, "via-go.pem")
	if err := NewEngine(&unavailableExecutor{}).FromDER(ctx, derPath, viaGo, false, ""); err != nil {
		t.Fatalf("FromDER pure-Go: %v", err)
	}

	a, err := os.ReadFile(viaOpenSSL)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(viaGo)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("PEM output differs between openssl and pure-Go paths:\nopenssl: %q\ngo:      %q",
			firstLine(a), firstLine(b))
	}
}

func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
