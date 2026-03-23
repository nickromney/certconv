package webapi

import (
	"encoding/base64"
	"os"
	"strings"
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
	if !hasAction(analysis.Actions, "view-details") {
		t.Fatal("expected details view action")
	}
	if !hasAction(analysis.Actions, "view-rsa-modulus") {
		t.Fatal("expected RSA modulus view action")
	}
	if !hasAction(analysis.Actions, "encode-base64") {
		t.Fatal("expected base64 view action")
	}
	if !hasAction(analysis.Actions, "view-der-base64") {
		t.Fatal("expected DER view action")
	}
	if !hasAction(analysis.Actions, "view-pfx-base64") {
		t.Fatal("expected PFX view action")
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

func TestAnalyzeFile_KeyIncludesTUIStylePrimitives(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	data, err := os.ReadFile(pair.KeyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}

	analysis := AnalyzeFile("example.key", data, "")
	if analysis.FileType != cert.FileTypeKey {
		t.Fatalf("FileType = %v, want key", analysis.FileType)
	}
	if !hasAction(analysis.Actions, "view-rsa-modulus") {
		t.Fatal("expected RSA modulus action for key input")
	}
	if !hasAction(analysis.Actions, "view-one-line") {
		t.Fatal("expected one-line action for key input")
	}
}

func TestInvoke_ViewRSAModulus_Key(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	data, err := os.ReadFile(pair.KeyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}

	resp := Invoke(Request{
		Op:          "view-rsa-modulus",
		Name:        "example.key",
		InputBase64: base64.StdEncoding.EncodeToString(data),
	})
	if !resp.OK {
		t.Fatalf("expected OK response, got error: %s", resp.Error)
	}
	if resp.Output == nil || resp.Output.Text == "" {
		t.Fatal("expected modulus output")
	}
	if !containsAll(resp.Output.Text, "Modulus (hex):", "SHA256(modulus):", "MD5(modulus):") {
		t.Fatalf("unexpected modulus output:\n%s", resp.Output.Text)
	}
}

func TestInvoke_ViewDetails(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	data, err := os.ReadFile(pair.CertPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}

	resp := Invoke(Request{
		Op:          "view-details",
		Name:        "example.pem",
		InputBase64: base64.StdEncoding.EncodeToString(data),
	})
	if !resp.OK {
		t.Fatalf("expected OK response, got error: %s", resp.Error)
	}
	if resp.Output == nil || resp.Output.Text == "" {
		t.Fatal("expected parsed certificate output")
	}
	if !containsAll(resp.Output.Text, "Identity", "Validity", "Fingerprints") {
		t.Fatalf("unexpected details output:\n%s", resp.Output.Text)
	}
}

func TestInvoke_ViewPFXBase64_CertOnlyPEM(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	data, err := os.ReadFile(pair.CertPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}

	resp := Invoke(Request{
		Op:          "view-pfx-base64",
		Name:        "example.pem",
		InputBase64: base64.StdEncoding.EncodeToString(data),
	})
	if !resp.OK {
		t.Fatalf("expected OK response, got error: %s", resp.Error)
	}
	if resp.Output == nil || resp.Output.Text == "" {
		t.Fatal("expected PFX output")
	}
	if _, err := base64.StdEncoding.DecodeString(resp.Output.Text); err != nil {
		t.Fatalf("expected valid base64 PFX output: %v", err)
	}
}

func TestInvoke_ViewPFXBase64_CombinedPEM(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	combinedPath := testutil.MakeCombinedPEM(t, pair.CertPath, pair.KeyPath)
	data, err := os.ReadFile(combinedPath)
	if err != nil {
		t.Fatalf("read combined pem: %v", err)
	}

	resp := Invoke(Request{
		Op:          "view-pfx-base64",
		Name:        "combined.pem",
		InputBase64: base64.StdEncoding.EncodeToString(data),
	})
	if !resp.OK {
		t.Fatalf("expected OK response, got error: %s", resp.Error)
	}
	if resp.Output == nil || resp.Output.Text == "" {
		t.Fatal("expected PFX output")
	}
	if _, err := base64.StdEncoding.DecodeString(resp.Output.Text); err != nil {
		t.Fatalf("expected valid base64 PFX output: %v", err)
	}
}

func hasAction(actions []Action, id string) bool {
	for _, action := range actions {
		if action.ID == id {
			return true
		}
	}
	return false
}

func containsAll(text string, snippets ...string) bool {
	for _, snippet := range snippets {
		if !strings.Contains(text, snippet) {
			return false
		}
	}
	return true
}
