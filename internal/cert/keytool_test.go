package cert

import (
	"context"
	"os"
	"testing"
)

type fakeKeytoolExec struct {
	listOutput   []byte
	exportOutput []byte
}

func (f fakeKeytoolExec) Run(_ context.Context, args ...string) ([]byte, []byte, error) {
	if len(args) == 0 {
		return nil, nil, nil
	}
	switch args[0] {
	case "-list":
		return f.listOutput, nil, nil
	case "-exportcert":
		// Write DER to the -file arg.
		for i, a := range args {
			if a == "-file" && i+1 < len(args) {
				_ = os.WriteFile(args[i+1], f.exportOutput, 0o644)
			}
		}
		return nil, nil, nil
	}
	return nil, nil, nil
}

func TestParseKeytoolListOutput(t *testing.T) {
	output := []byte(`Keystore type: JKS
Keystore provider: SUN

Your keystore contains 2 entries

Alias name: server
Creation date: Jan 1, 2024
Entry type: trustedCertEntry

Owner: CN=server.local
Issuer: CN=Test CA
Serial number: 1

Alias name: ca
Creation date: Jan 1, 2024
Entry type: trustedCertEntry

Owner: CN=Test CA
Issuer: CN=Test CA
Serial number: 2
`)

	aliases := parseKeytoolListOutput(output)
	if len(aliases) != 2 {
		t.Fatalf("expected 2 aliases, got %d", len(aliases))
	}
	if aliases[0].Alias != "server" {
		t.Errorf("first alias = %q, want server", aliases[0].Alias)
	}
	if aliases[0].Subject != "CN=server.local" {
		t.Errorf("first subject = %q, want CN=server.local", aliases[0].Subject)
	}
	if aliases[1].Alias != "ca" {
		t.Errorf("second alias = %q, want ca", aliases[1].Alias)
	}
}

func TestHasKeytool_Default(t *testing.T) {
	eng := NewDefaultEngine()
	if eng.HasKeytool() {
		t.Error("default engine should not have keytool")
	}
}

func TestHasKeytool_WithKeytool(t *testing.T) {
	eng := NewDefaultEngine()
	eng.SetKeytool(fakeKeytoolExec{})
	if !eng.HasKeytool() {
		t.Error("engine should have keytool after SetKeytool")
	}
}

func TestFromJKS_NoKeytool(t *testing.T) {
	eng := NewDefaultEngine()
	_, err := eng.FromJKS(context.Background(), "test.jks", t.TempDir(), "changeit", "")
	if err == nil {
		t.Fatal("expected error when keytool not configured")
	}
}

func TestJKSList_NoKeytool(t *testing.T) {
	eng := NewDefaultEngine()
	// keytoolExec is nil by default.
	_, err := eng.JKSList(context.Background(), "test.jks", "changeit")
	if err == nil {
		t.Fatal("expected error when keytool not configured")
	}
}

func TestJKSList_Fake(t *testing.T) {
	eng := NewDefaultEngine()
	eng.SetKeytool(fakeKeytoolExec{
		listOutput: []byte("Alias name: myalias\nEntry type: trustedCertEntry\nOwner: CN=test\n"),
	})

	summary, err := eng.JKSList(context.Background(), "test.jks", "changeit")
	if err != nil {
		t.Fatalf("JKSList: %v", err)
	}
	if len(summary.Aliases) != 1 {
		t.Fatalf("expected 1 alias, got %d", len(summary.Aliases))
	}
	if summary.Aliases[0].Alias != "myalias" {
		t.Errorf("alias = %q, want myalias", summary.Aliases[0].Alias)
	}
}

func TestFromJKS_Fake(t *testing.T) {
	// Minimal DER: just enough for PEM encoding.
	fakeDER := []byte{0x30, 0x82, 0x01, 0x00}

	eng := NewDefaultEngine()
	eng.SetKeytool(fakeKeytoolExec{
		listOutput:   []byte("Alias name: myalias\nEntry type: trustedCertEntry\nOwner: CN=test\n"),
		exportOutput: fakeDER,
	})

	outDir := t.TempDir()
	result, err := eng.FromJKS(context.Background(), "test.jks", outDir, "changeit", "")
	if err != nil {
		t.Fatalf("FromJKS: %v", err)
	}
	if len(result.CertFiles) != 1 {
		t.Fatalf("expected 1 cert file, got %d", len(result.CertFiles))
	}
	// Verify the file was written.
	if _, err := os.Stat(result.CertFiles[0]); err != nil {
		t.Errorf("cert file not found: %v", err)
	}
}

func TestFromJKS_AliasNotFound(t *testing.T) {
	eng := NewDefaultEngine()
	eng.SetKeytool(fakeKeytoolExec{
		listOutput: []byte("Alias name: other\nEntry type: trustedCertEntry\nOwner: CN=test\n"),
	})

	outDir := t.TempDir()
	_, err := eng.FromJKS(context.Background(), "test.jks", outDir, "changeit", "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent alias")
	}
}
