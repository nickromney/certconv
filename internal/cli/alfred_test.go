package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/nickromney/certconv/internal/cert"
	"github.com/nickromney/certconv/test/testutil"
)

type failExec struct{}

func (failExec) Run(context.Context, ...string) ([]byte, []byte, error) {
	return nil, nil, errors.New("unexpected openssl execution")
}

func (failExec) RunWithExtraFiles(context.Context, []cert.ExtraFile, ...string) ([]byte, []byte, error) {
	return nil, nil, errors.New("unexpected openssl execution")
}

func TestShowCommand_UsesFastPathForValidPEM(t *testing.T) {
	pair := testutil.MakeCertPair(t)
	engine := cert.NewEngine(failExec{})
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"show", pair.CertPath, "--json", "--plain"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	var summary cert.CertSummary
	if err := json.Unmarshal(out.Bytes(), &summary); err != nil {
		t.Fatalf("unmarshal summary: %v", err)
	}
	if summary.FileType != cert.FileTypeCert {
		t.Fatalf("expected file type cert, got %q", summary.FileType)
	}
	if summary.Subject == "" || summary.NotAfter == "" {
		t.Fatalf("expected populated summary, got %+v", summary)
	}
	if errOut.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", errOut.String())
	}
}

func TestAlfredCatalog_ItemsFiltersByQuery(t *testing.T) {
	resp := newAlfredCatalog().Items("pfx")
	if len(resp.Items) == 0 {
		t.Fatal("expected at least one Alfred item")
	}

	foundPFX := false
	foundDER := false
	for _, item := range resp.Items {
		if item.Arg == "pfx-to-pem" || item.Arg == "pem-cert-key-to-pfx" {
			foundPFX = true
		}
		if item.Arg == "pem-cert-to-der" {
			foundDER = true
		}
	}

	if !foundPFX {
		t.Fatalf("expected pfx-related actions in %+v", resp.Items)
	}
	if foundDER {
		t.Fatalf("did not expect DER-only actions in %+v", resp.Items)
	}
}

func TestAlfredCatalog_ItemsIncludesShowActionsFirst(t *testing.T) {
	resp := newAlfredCatalog().Items("")
	if len(resp.Items) < 2 {
		t.Fatalf("expected at least 2 items, got %d", len(resp.Items))
	}
	if resp.Items[0].Arg != "show-summary" || resp.Items[1].Arg != "show-full" {
		t.Fatalf("expected show actions first, got %+v", resp.Items[:2])
	}
}

type fakeAlfredUI struct {
	files         []string
	folders       []string
	savePaths     []string
	secrets       []string
	previews      []struct{ name, text string }
	revealedPaths []string
	notifications []string
}

func (f *fakeAlfredUI) ChooseFile(_ context.Context, _ string) (string, error) {
	if len(f.files) == 0 {
		return "", errAlfredCancelled
	}
	v := f.files[0]
	f.files = f.files[1:]
	return v, nil
}

func (f *fakeAlfredUI) ChooseFolder(_ context.Context, _ string) (string, error) {
	if len(f.folders) == 0 {
		return "", errAlfredCancelled
	}
	v := f.folders[0]
	f.folders = f.folders[1:]
	return v, nil
}

func (f *fakeAlfredUI) SaveFile(_ context.Context, _, _ string) (string, error) {
	if len(f.savePaths) == 0 {
		return "", errAlfredCancelled
	}
	v := f.savePaths[0]
	f.savePaths = f.savePaths[1:]
	return v, nil
}

func (f *fakeAlfredUI) PromptSecret(_ context.Context, _ string) (string, error) {
	if len(f.secrets) == 0 {
		return "", nil
	}
	v := f.secrets[0]
	f.secrets = f.secrets[1:]
	return v, nil
}

func (f *fakeAlfredUI) Notify(_ context.Context, title, body string) error {
	f.notifications = append(f.notifications, title+": "+body)
	return nil
}

func (f *fakeAlfredUI) PreviewText(_ context.Context, name, text string) error {
	f.previews = append(f.previews, struct{ name, text string }{name: name, text: text})
	return nil
}

func (f *fakeAlfredUI) Reveal(_ context.Context, path string) error {
	f.revealedPaths = append(f.revealedPaths, path)
	return nil
}

type fakeAlfredOps struct {
	summaryCalls []struct{ input, password string }
	detailCalls  []struct{ input, password string }
	summary      *cert.CertSummary
	details      *cert.CertDetails
	toDERCalls   []struct {
		input, output string
		isKey         bool
	}
	fromPFXCalls []struct{ input, outDir, password string }
}

func (f *fakeAlfredOps) ShowSummary(_ context.Context, inputPath, password string) (*cert.CertSummary, error) {
	f.summaryCalls = append(f.summaryCalls, struct{ input, password string }{input: inputPath, password: password})
	if f.summary != nil {
		return f.summary, nil
	}
	return &cert.CertSummary{
		File:     inputPath,
		FileType: cert.FileTypeCert,
		Subject:  "CN=test.local",
		NotAfter: "Jan  1 00:00:00 2030 GMT",
	}, nil
}

func (f *fakeAlfredOps) ShowDetails(_ context.Context, inputPath, password string) (*cert.CertDetails, error) {
	f.detailCalls = append(f.detailCalls, struct{ input, password string }{input: inputPath, password: password})
	if f.details != nil {
		return f.details, nil
	}
	return &cert.CertDetails{
		File:     inputPath,
		FileType: cert.FileTypeCert,
		RawText:  "Certificate:\n    Data:\n",
	}, nil
}

func (f *fakeAlfredOps) ToDER(_ context.Context, inputPath, outputPath string, isKey bool, _ string) error {
	f.toDERCalls = append(f.toDERCalls, struct {
		input  string
		output string
		isKey  bool
	}{input: inputPath, output: outputPath, isKey: isKey})
	return nil
}

func (f *fakeAlfredOps) FromDER(context.Context, string, string, bool, string) error {
	return errors.New("unexpected FromDER call")
}

func (f *fakeAlfredOps) FromPFX(_ context.Context, inputPath, outDir, password string) (*cert.FromPFXResult, error) {
	f.fromPFXCalls = append(f.fromPFXCalls, struct {
		input    string
		outDir   string
		password string
	}{input: inputPath, outDir: outDir, password: password})
	return &cert.FromPFXResult{
		CertFile: filepath.Join(outDir, "example.crt"),
		KeyFile:  filepath.Join(outDir, "example.key"),
	}, nil
}

func (f *fakeAlfredOps) ToPFX(context.Context, string, string, string, string, string, string) error {
	return errors.New("unexpected ToPFX call")
}

func (f *fakeAlfredOps) FromP7B(context.Context, string, string) (*cert.FromP7BResult, error) {
	return nil, errors.New("unexpected FromP7B call")
}

func (f *fakeAlfredOps) ToBase64(context.Context, string, string) error {
	return errors.New("unexpected ToBase64 call")
}

func (f *fakeAlfredOps) FromBase64(context.Context, string, string) error {
	return errors.New("unexpected FromBase64 call")
}

func (f *fakeAlfredOps) CombinePEM(context.Context, string, string, string, string, string) error {
	return errors.New("unexpected CombinePEM call")
}

func TestAlfredRunner_ShowSummaryOpensPreview(t *testing.T) {
	ui := &fakeAlfredUI{
		files: []string{"/tmp/example.pem"},
	}
	ops := &fakeAlfredOps{}
	runner := newAlfredRunner(ops, ui)

	if err := runner.Run(context.Background(), "show-summary"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(ops.summaryCalls) != 1 {
		t.Fatalf("expected 1 summary call, got %d", len(ops.summaryCalls))
	}
	if ops.summaryCalls[0].password != "" {
		t.Fatalf("did not expect password for PEM input, got %+v", ops.summaryCalls[0])
	}
	if len(ui.previews) != 1 {
		t.Fatalf("expected 1 preview, got %d", len(ui.previews))
	}
	if ui.previews[0].name != "example-summary.txt" {
		t.Fatalf("unexpected preview name: %+v", ui.previews[0])
	}
	if !bytes.Contains([]byte(ui.previews[0].text), []byte("Subject: CN=test.local")) {
		t.Fatalf("expected summary text, got %q", ui.previews[0].text)
	}
}

func TestAlfredRunner_ShowFullPromptsForPFXPassword(t *testing.T) {
	ui := &fakeAlfredUI{
		files:   []string{"/tmp/example.p12"},
		secrets: []string{"s3cret"},
	}
	ops := &fakeAlfredOps{}
	runner := newAlfredRunner(ops, ui)

	if err := runner.Run(context.Background(), "show-full"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(ops.detailCalls) != 1 {
		t.Fatalf("expected 1 details call, got %d", len(ops.detailCalls))
	}
	if ops.detailCalls[0].password != "s3cret" {
		t.Fatalf("expected prompted password, got %+v", ops.detailCalls[0])
	}
	if len(ui.previews) != 1 || ui.previews[0].name != "example-details.txt" {
		t.Fatalf("unexpected previews: %+v", ui.previews)
	}
}

func TestAlfredRunner_PEMCertToDER(t *testing.T) {
	ui := &fakeAlfredUI{
		files:     []string{"/tmp/example.pem"},
		savePaths: []string{"/tmp/example.der"},
	}
	ops := &fakeAlfredOps{}
	runner := newAlfredRunner(ops, ui)

	if err := runner.Run(context.Background(), "pem-cert-to-der"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(ops.toDERCalls) != 1 {
		t.Fatalf("expected 1 ToDER call, got %d", len(ops.toDERCalls))
	}
	call := ops.toDERCalls[0]
	if call.input != "/tmp/example.pem" || call.output != "/tmp/example.der" || call.isKey {
		t.Fatalf("unexpected ToDER call: %+v", call)
	}
	if len(ui.revealedPaths) != 1 || ui.revealedPaths[0] != "/tmp/example.der" {
		t.Fatalf("unexpected revealed paths: %+v", ui.revealedPaths)
	}
}

func TestAlfredRunner_PFXToPEMUsesPromptedPassword(t *testing.T) {
	parent := t.TempDir()
	ui := &fakeAlfredUI{
		files:   []string{"/tmp/example.p12"},
		folders: []string{parent},
		secrets: []string{"s3cret"},
	}
	ops := &fakeAlfredOps{}
	runner := newAlfredRunner(ops, ui)

	if err := runner.Run(context.Background(), "pfx-to-pem"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(ops.fromPFXCalls) != 1 {
		t.Fatalf("expected 1 FromPFX call, got %d", len(ops.fromPFXCalls))
	}
	call := ops.fromPFXCalls[0]
	wantDir := filepath.Join(parent, "example-extracted")
	if call.input != "/tmp/example.p12" || call.outDir != wantDir || call.password != "s3cret" {
		t.Fatalf("unexpected FromPFX call: %+v", call)
	}
	if len(ui.revealedPaths) != 1 || ui.revealedPaths[0] != wantDir {
		t.Fatalf("unexpected revealed paths: %+v", ui.revealedPaths)
	}
}
