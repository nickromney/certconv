package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nickromney/certconv/internal/cert"
	"github.com/nickromney/certconv/test/testutil"
)

func TestPaneID_String(t *testing.T) {
	if PaneFiles.String() != "Files" || PaneInfo.String() != "Info" || PaneContent.String() != "Content" {
		t.Fatalf("unexpected PaneID strings")
	}
	if PaneID(123).String() != "?" {
		t.Fatalf("expected unknown pane string")
	}
}

func TestFormatHex(t *testing.T) {
	if got := formatHex([]byte{0x00, 0xAB, 0x10}); got != "00:AB:10" {
		t.Fatalf("unexpected formatHex: %q", got)
	}
}

func TestContentPaneMode_Title(t *testing.T) {
	if contentPaneModeContent.Title() == "?" || contentPaneModeDetails.Title() == "?" {
		t.Fatalf("expected known titles")
	}
	if contentPaneMode(999).Title() != "?" {
		t.Fatalf("expected unknown title")
	}
}

func TestContentPane_Update_ScrollKeys(t *testing.T) {
	cp := newContentPane(64)
	cp.SetSize(20, 3)
	cp.SetContent("t", strings.Repeat("x\n", 50))
	cp.SetMode(contentPaneModeContent)

	if cp.Update(tea.KeyMsg{Type: tea.KeyDown}) != nil {
		t.Fatalf("expected nil cmd")
	}
	if cp.Update(tea.KeyMsg{Type: tea.KeyUp}) != nil {
		t.Fatalf("expected nil cmd")
	}
}

func TestContentPane_ErrorSetters(t *testing.T) {
	cp := newContentPane(64)
	cp.SetSize(40, 5)

	cp.SetMode(contentPaneModeParsed)
	cp.SetParsedError("parse failed")
	if cp.parsedErr == "" {
		t.Fatalf("expected parsedErr set")
	}

	cp.SetMode(contentPaneModeModulus)
	cp.SetModulusError("mod failed")
	if cp.modulusErr == "" {
		t.Fatalf("expected modulusErr set")
	}

	cp.SetMode(contentPaneModeOneLine)
	cp.SetOneLineError("one failed")
	if cp.oneLineErr == "" {
		t.Fatalf("expected oneLineErr set")
	}

	cp.SetMode(contentPaneModeBase64)
	cp.SetBase64Error("b64 failed")
	if cp.base64Err == "" {
		t.Fatalf("expected base64Err set")
	}

	cp.SetMode(contentPaneModeDERBase64)
	cp.SetDERBase64Error("der failed")
	if cp.derBase64Err == "" {
		t.Fatalf("expected derBase64Err set")
	}

	cp.SetMode(contentPaneModePFXBase64)
	cp.SetPFXBase64Error("pfx failed")
	if cp.pfxBase64Err == "" {
		t.Fatalf("expected pfxBase64Err set")
	}
}

func TestHelpPaneAndInfoPane_UpdateAndSetters(t *testing.T) {
	hp := newHelpPane()
	hp.SetSize(20, 3)
	hp.SetContent(strings.Repeat("line\n", 50))
	if hp.Update(tea.KeyMsg{Type: tea.KeyDown}) != nil {
		t.Fatalf("expected nil cmd")
	}

	ip := newInfoPane()
	ip.SetSize(40, 5)
	ip.SetSummary(&cert.CertSummary{FileType: cert.FileTypeCert, Subject: "CN=x", Issuer: "CN=y"})
	if ip.summary == nil {
		t.Fatalf("expected summary set")
	}
	ip.SetError("nope")
	if ip.errText == "" {
		t.Fatalf("expected error set")
	}
	if ip.Update(tea.KeyMsg{Type: tea.KeyDown}) != nil {
		t.Fatalf("expected nil cmd")
	}
}

func TestAutoMatchEnabled(t *testing.T) {
	m := Model{autoMatchKey: true}
	if !m.autoMatchEnabled() {
		t.Fatalf("expected enabled")
	}
	m.autoMatchKey = false
	if m.autoMatchEnabled() {
		t.Fatalf("expected disabled")
	}
}

func TestUpdate_StatusMsg_ClearsOnNavigation(t *testing.T) {
	m := Model{
		keyNextView:          "n",
		keyPrevView:          "p",
		keyResizeFileLess:    "[",
		keyResizeFileMore:    "]",
		keyResizeSummaryLess: "-",
		keyResizeSummaryMore: "=",
	}

	next, _ := m.Update(ToastMsg{Text: "Content copied to clipboard"})
	m = next.(Model)
	if m.statusMsg == "" || m.statusAutoClearOnNav != true {
		t.Fatalf("expected auto-clear status set")
	}

	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = next.(Model)
	if m.statusMsg != "" {
		t.Fatalf("expected status cleared on navigation")
	}
}

func TestUpdate_ActionSelected_DispatchesHandleAction(t *testing.T) {
	m := Model{
		engine:       cert.NewEngine(tuiFakeExec{}),
		selectedFile: "/tmp/x.pem",
		filePane:     filePane{dir: t.TempDir()},
		contentPane:  newContentPane(64),
		infoPane:     newInfoPane(),
	}

	next, cmd := m.Update(ActionSelectedMsg{ID: "verify"})
	m = next.(Model)
	if cmd != nil {
		t.Fatalf("expected nil cmd for verify (prompts for input)")
	}
	if !m.input.active() || m.input.action != "verify" {
		t.Fatalf("expected verify prompt active, got %+v", m.input)
	}
}

func TestUpdate_AutoKeyMatch_TriggersPFXPreview(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	keyPath := filepath.Join(dir, "c.key")
	if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	m := Model{
		engine:       cert.NewEngine(tuiFakeExec{}),
		selectedFile: certPath,
		selectedType: cert.FileTypeCert,
		contentPane:  newContentPane(64),
		infoPane:     newInfoPane(),
	}

	// Key match should set status and return a cmd to compute PFX preview.
	next, cmd := m.Update(AutoKeyMatchMsg{CertPath: certPath, KeyPath: keyPath})
	m = next.(Model)
	if cmd == nil {
		t.Fatalf("expected pfx preview cmd")
	}
	if m.autoMatchedKeyPath != keyPath {
		t.Fatalf("expected autoMatchedKeyPath set, got %q", m.autoMatchedKeyPath)
	}

	// Execute cmd -> ContentPFXBase64Msg then feed through Update.
	msg := cmd()
	cpfx, ok := msg.(ContentPFXBase64Msg)
	if !ok {
		t.Fatalf("expected ContentPFXBase64Msg, got %T", msg)
	}
	next, _ = m.Update(cpfx)
	m = next.(Model)
	if strings.TrimSpace(m.contentPane.pfxBase64Text) == "" {
		t.Fatalf("expected pfx base64 populated")
	}
}

func TestLoadDerivedDERBase64_AndLoadContentParsed_AndLoadContentModulus(t *testing.T) {
	pair := testutil.MakeCertPair(t)

	m := Model{
		engine:       cert.NewEngine(tuiFakeExec{}),
		selectedFile: pair.CertPath,
		selectedType: cert.FileTypeCert,
		contentPane:  newContentPane(64),
		infoPane:     newInfoPane(),
	}

	// DER base64 preview.
	derMsg, ok := m.loadDerivedDERBase64(pair.CertPath)().(ContentDERBase64Msg)
	if !ok {
		t.Fatalf("expected ContentDERBase64Msg")
	}
	next, _ := m.Update(derMsg)
	m = next.(Model)
	if strings.TrimSpace(m.contentPane.derBase64Text) == "" {
		t.Fatalf("expected der base64 populated")
	}

	// Parsed view (pure Go parse of PEM cert).
	parsedMsg, ok := m.loadContentParsed(pair.CertPath)().(ContentParsedMsg)
	if !ok {
		t.Fatalf("expected ContentParsedMsg")
	}
	next, _ = m.Update(parsedMsg)
	m = next.(Model)
	if strings.TrimSpace(m.contentPane.parsedText) == "" {
		t.Fatalf("expected parsed text populated")
	}

	// Modulus view (uses fake exec).
	modMsg, ok := m.loadContentModulus(pair.CertPath)().(ContentModulusMsg)
	if !ok {
		t.Fatalf("expected ContentModulusMsg")
	}
	next, _ = m.Update(modMsg)
	m = next.(Model)
	if strings.TrimSpace(m.contentPane.modulusText) == "" {
		t.Fatalf("expected modulus populated")
	}
}

func TestSaveThemeCmd_WritesToTempConfigHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	m := Model{
		themeName:   "default",
		configPath:  "~/.config/certconv/config.yml",
		contentPane: newContentPane(64),
	}

	cmd := m.saveThemeCmd()
	if cmd == nil {
		t.Fatalf("expected cmd")
	}
	msg := cmd()
	sm, ok := msg.(StatusMsg)
	if !ok {
		t.Fatalf("expected StatusMsg, got %T", msg)
	}
	if sm.IsErr {
		t.Fatalf("expected save ok, got err: %q", sm.Text)
	}
}

func TestLoadCertSummary_AndLoadContentDetails_PEM(t *testing.T) {
	pair := testutil.MakeCertPair(t)

	m := Model{
		engine:       cert.NewEngine(tuiFakeExec{}),
		selectedFile: pair.CertPath,
		actionPanel:  newActionPanel(),
		contentPane:  newContentPane(64),
		infoPane:     newInfoPane(),
		focused:      PaneContent,
	}
	m.contentPane.SetMode(contentPaneModeDetails)

	// Summary cmd -> Update(CertSummaryMsg)
	sumMsg, ok := m.loadCertSummary(pair.CertPath)().(CertSummaryMsg)
	if !ok {
		t.Fatalf("expected CertSummaryMsg")
	}
	next, _ := m.Update(sumMsg)
	m = next.(Model)
	if m.selectedType != cert.FileTypeCert {
		t.Fatalf("expected selectedType cert, got %q", m.selectedType)
	}
	if m.infoPane.summary == nil {
		t.Fatalf("expected infoPane summary set")
	}
	if len(m.actionPanel.actions) == 0 {
		t.Fatalf("expected actions set")
	}

	// Details cmd -> Update(ContentDetailsMsg)
	detailsMsg, ok := m.loadContentDetails(pair.CertPath)().(ContentDetailsMsg)
	if !ok {
		t.Fatalf("expected ContentDetailsMsg")
	}
	next, _ = m.Update(detailsMsg)
	m = next.(Model)
	if got := m.contentPane.detailsText; !strings.Contains(got, "Chain: 1 certificate") || !strings.Contains(got, "Certificate:") {
		t.Fatalf("expected chain+details prefix, got:\n%s", got)
	}
}

func TestUpdateFocusedPane_RoutesToInfoAndHelp(t *testing.T) {
	m := Model{
		width:       80,
		height:      24,
		infoPane:    newInfoPane(),
		helpPane:    newHelpPane(),
		contentPane: newContentPane(64),
		focused:     PaneInfo,
	}
	m.layoutPanes()
	m.infoPane.SetSize(40, 5)
	m.infoPane.viewport.SetContent(strings.Repeat("line\n", 50))
	// Route key to infoPane.Update.
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = next.(Model)

	// Now route to help pane.
	m.focused = PaneContent
	m.showHelp = true
	m.helpPane.SetSize(40, 5)
	m.helpPane.SetContent(strings.Repeat("line\n", 50))
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	_ = next.(Model)
}

func TestFilePane_Update_MoreNavigationKeys(t *testing.T) {
	dir := t.TempDir()
	// At least a few files so page/half-page moves do something.
	for i := 0; i < 30; i++ {
		p := filepath.Join(dir, fmt.Sprintf("f-%02d.pem", i))
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	fp := newFilePane(dir)
	fp.width = 80
	fp.height = 5

	_ = fp.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("G")})
	_ = fp.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("g")})
	_ = fp.Update(tea.KeyMsg{Type: tea.KeyCtrlD})
	_ = fp.Update(tea.KeyMsg{Type: tea.KeyCtrlU})
	_ = fp.Update(tea.KeyMsg{Type: tea.KeyPgDown})
	_ = fp.Update(tea.KeyMsg{Type: tea.KeyPgUp})
}
