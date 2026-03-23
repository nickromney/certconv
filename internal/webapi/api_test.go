package webapi

import (
	"encoding/base64"
	"os"
	"testing"

	"github.com/nickromney/certconv/internal/cert"
	"github.com/nickromney/certconv/test/testutil"
)

func TestAnalyzeFile_Certificate(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	data, err := os.ReadFile(pair.CertPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}

	analysis := AnalyzeFile("test.pem", data, "")
	if analysis.FileType != cert.FileTypeCert {
		t.Fatalf("FileType = %v, want cert", analysis.FileType)
	}
	if analysis.Summary == nil {
		t.Fatal("expected summary")
	}
	if analysis.Lint == nil {
		t.Fatal("expected lint")
	}
	if len(analysis.Actions) == 0 {
		t.Fatal("expected actions")
	}
}

func TestAnalyzeFile_PFX(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	pfxPath := testutil.MakePFX(t, pair, "secret")
	data, err := os.ReadFile(pfxPath)
	if err != nil {
		t.Fatalf("read pfx: %v", err)
	}

	analysis := AnalyzeFile("test.p12", data, "secret")
	if analysis.FileType != cert.FileTypePFX {
		t.Fatalf("FileType = %v, want pfx", analysis.FileType)
	}
	if analysis.Summary == nil {
		t.Fatal("expected summary")
	}
	if analysis.Lint == nil {
		t.Fatal("expected lint")
	}
	if analysis.CertCount != 1 {
		t.Fatalf("CertCount = %d, want 1", analysis.CertCount)
	}
}

func TestAnalyzeFile_PFXRequiresPassword(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	pfxPath := testutil.MakePFX(t, pair, "secret")
	data, err := os.ReadFile(pfxPath)
	if err != nil {
		t.Fatalf("read pfx: %v", err)
	}

	analysis := AnalyzeFile("test.p12", data, "")
	if !analysis.PasswordRequired {
		t.Fatal("expected passwordRequired")
	}
	if analysis.Summary != nil {
		t.Fatal("did not expect summary without password")
	}
}

func TestInvoke_ConvertToDER(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	data, err := os.ReadFile(pair.CertPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}

	resp := Invoke(Request{
		Op:          "convert-to-der",
		Name:        "test.pem",
		InputBase64: base64.StdEncoding.EncodeToString(data),
	})
	if !resp.OK {
		t.Fatalf("expected OK response, got error: %s", resp.Error)
	}
	if resp.Output == nil {
		t.Fatal("expected output")
	}
	if resp.Output.Kind != "binary" {
		t.Fatalf("Kind = %q, want binary", resp.Output.Kind)
	}
	if resp.Output.Name != "test.der" {
		t.Fatalf("Name = %q, want test.der", resp.Output.Name)
	}
}

func TestInvoke_OrderChain(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	data, err := os.ReadFile(pair.CertPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}

	resp := Invoke(Request{
		Op:          "order-chain",
		Name:        "bundle.pem",
		InputBase64: base64.StdEncoding.EncodeToString(data),
	})
	if !resp.OK {
		t.Fatalf("expected OK response, got error: %s", resp.Error)
	}
	if resp.Output == nil || resp.Output.Text == "" {
		t.Fatal("expected text output")
	}
}
