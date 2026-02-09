package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nickromney/certconv/internal/cert"
	"github.com/nickromney/certconv/test/testutil"
)

func TestEnvKey_DefaultAndOverride(t *testing.T) {
	t.Setenv("CERTCONV_TEST_KEY", "")
	if got := envKey("CERTCONV_TEST_KEY", "n"); got != "n" {
		t.Fatalf("expected default, got %q", got)
	}

	t.Setenv("CERTCONV_TEST_KEY", "  x  ")
	if got := envKey("CERTCONV_TEST_KEY", "n"); got != "x" {
		t.Fatalf("expected trimmed override, got %q", got)
	}
}

func TestUpdateKey_NumberJumpFocus(t *testing.T) {
	m := Model{focused: PaneContent}

	next, _ := m.updateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("1")})
	m1 := next.(Model)
	if m1.focused != PaneFiles {
		t.Fatalf("expected PaneFiles, got %v", m1.focused)
	}

	next, _ = m1.updateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("2")})
	m2 := next.(Model)
	if m2.focused != PaneInfo {
		t.Fatalf("expected PaneInfo, got %v", m2.focused)
	}

	next, _ = m2.updateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("3")})
	m3 := next.(Model)
	if m3.focused != PaneContent {
		t.Fatalf("expected PaneContent, got %v", m3.focused)
	}
}

func TestUpdateKey_TabAndShiftTab_CycleFocus(t *testing.T) {
	m := Model{focused: PaneFiles}
	next, _ := m.updateKey(tea.KeyMsg{Type: tea.KeyTab})
	m1 := next.(Model)
	if m1.focused != PaneInfo {
		t.Fatalf("expected PaneInfo, got %v", m1.focused)
	}

	next, _ = m1.updateKey(tea.KeyMsg{Type: tea.KeyTab})
	m2 := next.(Model)
	if m2.focused != PaneContent {
		t.Fatalf("expected PaneContent, got %v", m2.focused)
	}

	// Wrap.
	next, _ = m2.updateKey(tea.KeyMsg{Type: tea.KeyTab})
	m3 := next.(Model)
	if m3.focused != PaneFiles {
		t.Fatalf("expected wrap to PaneFiles, got %v", m3.focused)
	}

	// Reverse.
	next, _ = m3.updateKey(tea.KeyMsg{Type: tea.KeyShiftTab})
	m4 := next.(Model)
	if m4.focused != PaneContent {
		t.Fatalf("expected shift+tab to PaneContent, got %v", m4.focused)
	}
}

func TestUpdateKey_CtrlH_TogglesHelpAndEscCloses(t *testing.T) {
	m := Model{
		focused:  PaneFiles,
		helpPane: newHelpPane(),
	}
	// Large size so the "ctrl+h" hint is visible without scrolling.
	m.helpPane.SetSize(120, 200)
	if m.showHelp {
		t.Fatalf("expected showHelp false")
	}

	next, _ := m.updateKey(tea.KeyMsg{Type: tea.KeyCtrlH})
	m1 := next.(Model)
	if !m1.showHelp {
		t.Fatalf("expected showHelp true")
	}
	if m1.focused != PaneContent {
		t.Fatalf("expected focused PaneContent, got %v", m1.focused)
	}
	if !strings.Contains(m1.helpPane.viewport.View(), "ctrl+h") {
		t.Fatalf("expected help content to mention ctrl+h, got %q", m1.helpPane.viewport.View())
	}

	// Close help with esc.
	next, _ = m1.updateKey(tea.KeyMsg{Type: tea.KeyEsc})
	m2 := next.(Model)
	if m2.showHelp {
		t.Fatalf("expected showHelp false after esc")
	}
}

func TestUpdateKey_ActionPanel_ToggleAndSelect(t *testing.T) {
	m := Model{
		selectedFile: "x",
		selectedType: cert.FileTypeCert,
		actionPanel:  newActionPanel(),
	}
	m.actionPanel.SetActions(cert.FileTypeCert)

	// Toggle open with '?'.
	next, _ := m.updateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("?")})
	m1 := next.(Model)
	if !m1.actionPanel.visible {
		t.Fatalf("expected action panel visible")
	}

	// Enter should return an ActionSelectedMsg cmd.
	nextModel, cmd := m1.updateKey(tea.KeyMsg{Type: tea.KeyEnter})
	m2 := nextModel.(Model)
	if m2.actionPanel.visible {
		t.Fatalf("expected action panel hidden after enter")
	}
	if cmd == nil {
		t.Fatalf("expected cmd from enter")
	}
	msg := cmd()
	asm, ok := msg.(ActionSelectedMsg)
	if !ok {
		t.Fatalf("expected ActionSelectedMsg, got %T", msg)
	}
	if asm.ID == "" {
		t.Fatalf("expected non-empty action ID")
	}
}

func TestUpdateKey_ActionPanel_QuestionMarkCloses(t *testing.T) {
	m := Model{
		selectedFile: "x",
		selectedType: cert.FileTypeCert,
		actionPanel:  newActionPanel(),
	}
	m.actionPanel.SetActions(cert.FileTypeCert)
	m.actionPanel.visible = true

	next, _ := m.updateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("?")})
	m1 := next.(Model)
	if m1.actionPanel.visible {
		t.Fatalf("expected action panel hidden")
	}
}

func TestUpdateKey_ZoomTogglesAndFocusesContent(t *testing.T) {
	m := Model{focused: PaneFiles}
	next, _ := m.updateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("z")})
	m1 := next.(Model)
	if !m1.zoomContent {
		t.Fatalf("expected zoomContent true")
	}
	if m1.focused != PaneContent {
		t.Fatalf("expected focus PaneContent when zoom enabled, got %v", m1.focused)
	}
}

func TestUpdateKey_CycleContentPane_NextAndPrev(t *testing.T) {
	cp := newContentPane(64)
	cp.SetDetails("DETAILS")
	cp.SetParsed("PARSED")
	cp.SetModulus("MOD")
	cp.SetOneLine("ONE")
	cp.SetBase64("B64")
	cp.SetDERBase64("DERB64")

	m := Model{
		selectedFile: "x.pem",
		selectedType: cert.FileTypeCert,
		focused:      PaneContent,
		keyNextView:  "n",
		keyPrevView:  "p",
		contentPane:  cp,
	}

	// content -> details
	next, cmd := m.updateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	m1 := next.(Model)
	if cmd != nil {
		t.Fatalf("expected nil cmd (preloaded content)")
	}
	if m1.contentPane.Mode() != contentPaneModeDetails {
		t.Fatalf("expected details, got %v", m1.contentPane.Mode())
	}

	// details -> parsed
	next, cmd = m1.updateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	m2 := next.(Model)
	if cmd != nil {
		t.Fatalf("expected nil cmd (preloaded content)")
	}
	if m2.contentPane.Mode() != contentPaneModeParsed {
		t.Fatalf("expected parsed, got %v", m2.contentPane.Mode())
	}

	// parsed -> modulus
	next, _ = m2.updateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	m3 := next.(Model)
	if m3.contentPane.Mode() != contentPaneModeModulus {
		t.Fatalf("expected modulus, got %v", m3.contentPane.Mode())
	}

	// modulus -> one-line
	next, _ = m3.updateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	m4 := next.(Model)
	if m4.contentPane.Mode() != contentPaneModeOneLine {
		t.Fatalf("expected one-line, got %v", m4.contentPane.Mode())
	}

	// one-line -> base64
	next, _ = m4.updateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	m5 := next.(Model)
	if m5.contentPane.Mode() != contentPaneModeBase64 {
		t.Fatalf("expected base64, got %v", m5.contentPane.Mode())
	}

	// base64 -> DER (base64)
	next, _ = m5.updateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	m6 := next.(Model)
	if m6.contentPane.Mode() != contentPaneModeDERBase64 {
		t.Fatalf("expected der base64, got %v", m6.contentPane.Mode())
	}

	// DER (base64) -> wrap to content
	next, _ = m6.updateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	m7 := next.(Model)
	if m7.contentPane.Mode() != contentPaneModeContent {
		t.Fatalf("expected wrap to content, got %v", m7.contentPane.Mode())
	}

	// Prev from content -> DER (base64)
	next, _ = m7.updateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("p")})
	m8 := next.(Model)
	if m8.contentPane.Mode() != contentPaneModeDERBase64 {
		t.Fatalf("expected prev to der base64, got %v", m8.contentPane.Mode())
	}
}

func TestCertSummary_PFXPasswordDoesNotPromptOnSummaryError(t *testing.T) {
	m := Model{
		selectedFile: "/tmp/test.pfx",
		infoPane:     newInfoPane(),
		pfxPasswords: map[string]string{},
	}

	next, _ := m.updateCertSummary(CertSummaryMsg{
		Path:    "/tmp/test.pfx",
		Summary: &cert.CertSummary{File: "/tmp/test.pfx", FileType: cert.FileTypePFX},
		Err:     fmt.Errorf("read pfx: %w", cert.ErrPFXIncorrectPassword),
	})
	m2 := next.(Model)

	if m2.input.active() {
		t.Fatalf("expected no prompt, got input.mode=%q", m2.input.mode)
	}
	if !strings.Contains(m2.infoPane.inlineErrText, "PFX password required") {
		t.Fatalf("expected inline error, got %q", m2.infoPane.inlineErrText)
	}
}

func TestAutoMatchKeyCmd_FindsSiblingKey(t *testing.T) {
	pair := testutil.MakeCertPair(t)

	m := Model{engine: cert.NewDefaultEngine()}
	msg := m.autoMatchKeyCmd(pair.CertPath)()

	am, ok := msg.(AutoKeyMatchMsg)
	if !ok {
		t.Fatalf("expected AutoKeyMatchMsg, got %T", msg)
	}
	if am.Err != nil {
		t.Fatalf("unexpected error: %v", am.Err)
	}
	if am.KeyPath == "" {
		t.Fatalf("expected key match, got none")
	}
}

type countingExecutor struct {
	calls int
}

func (c *countingExecutor) Run(ctx context.Context, args ...string) (stdout, stderr []byte, err error) {
	return c.RunWithExtraFiles(ctx, nil, args...)
}

func (c *countingExecutor) RunWithExtraFiles(ctx context.Context, _ []cert.ExtraFile, args ...string) (stdout, stderr []byte, err error) {
	c.calls++
	switch args[0] {
	case "x509":
		return []byte("-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----\n"), nil, nil
	case "pkey":
		return []byte("-----BEGIN PUBLIC KEY-----\nBBB\n-----END PUBLIC KEY-----\n"), nil, nil
	default:
		return nil, []byte("unexpected"), nil
	}
}

func TestAutoMatchKeyCmd_RespectsCandidateLimit(t *testing.T) {
	dir := t.TempDir()

	certPath := filepath.Join(dir, "test.pem")
	if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	// Create lots of candidate key files that pass the lightweight filters.
	keyBody := []byte("-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\n")
	for i := 0; i < autoMatchMaxCandidates+25; i++ {
		p := filepath.Join(dir, fmt.Sprintf("k-%03d.key", i))
		if err := os.WriteFile(p, keyBody, 0o600); err != nil {
			t.Fatalf("write key: %v", err)
		}
	}
	// Preferred sibling name.
	if err := os.WriteFile(filepath.Join(dir, "test.key"), keyBody, 0o600); err != nil {
		t.Fatalf("write preferred key: %v", err)
	}

	exec := &countingExecutor{}
	m := Model{engine: cert.NewEngine(exec)}

	msg := m.autoMatchKeyCmd(certPath)()
	am, ok := msg.(AutoKeyMatchMsg)
	if !ok {
		t.Fatalf("expected AutoKeyMatchMsg, got %T", msg)
	}
	if am.Err != nil {
		t.Fatalf("unexpected error: %v", am.Err)
	}
	if am.KeyPath != "" {
		t.Fatalf("expected no match, got: %q", am.KeyPath)
	}

	if exec.calls != 2*autoMatchMaxCandidates {
		t.Fatalf("expected %d openssl calls, got %d", 2*autoMatchMaxCandidates, exec.calls)
	}
}

func TestAutoMatchKeyCmd_StopsEarlyOnCanceledContext(t *testing.T) {
	exec := &countingExecutor{}
	m := Model{engine: cert.NewEngine(exec)}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.loadCtx = ctx

	msg := m.autoMatchKeyCmd("/tmp/does-not-matter.pem")()
	am, ok := msg.(AutoKeyMatchMsg)
	if !ok {
		t.Fatalf("expected AutoKeyMatchMsg, got %T", msg)
	}
	if am.Err == nil || am.Err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", am.Err)
	}
	if exec.calls != 0 {
		t.Fatalf("expected 0 openssl calls, got %d", exec.calls)
	}
}

func TestCopyToClipboardCmd_NoClipboardToolFound(t *testing.T) {
	// Make exec.LookPath deterministic across OS by clearing PATH.
	t.Setenv("PATH", "")

	m := Model{}
	msg := m.copyToClipboardCmd("hello")()

	sm, ok := msg.(StatusMsg)
	if !ok {
		t.Fatalf("expected StatusMsg, got %T", msg)
	}
	if !sm.IsErr {
		t.Fatalf("expected error status, got ok: %q", sm.Text)
	}
	if !strings.Contains(strings.ToLower(sm.Text), "clipboard") {
		t.Fatalf("expected clipboard mention, got: %q", sm.Text)
	}
	if !strings.Contains(sm.Text, "pbcopy") {
		t.Fatalf("expected candidate list mention, got: %q", sm.Text)
	}
}

func TestUpdateKey_CopyFromPaneFiles(t *testing.T) {
	t.Setenv("PATH", "")

	cp := newContentPane(64)
	cp.SetContent("x", "content")

	m := Model{
		focused:      PaneFiles,
		selectedFile: "dummy",
		contentPane:  cp,
		keyCopy:      "c",
	}

	_, cmd := m.updateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("c")})
	if cmd == nil {
		t.Fatalf("expected copy cmd")
	}
	msg := cmd()
	sm, ok := msg.(StatusMsg)
	if !ok {
		t.Fatalf("expected StatusMsg, got %T", msg)
	}
	if !sm.IsErr {
		t.Fatalf("expected error (no clipboard tool), got ok: %q", sm.Text)
	}
	if !strings.Contains(strings.ToLower(sm.Text), "clipboard") {
		t.Fatalf("expected clipboard mention, got: %q", sm.Text)
	}
}

func TestUpdateIgnoresStaleContentMsgs(t *testing.T) {
	cp := newContentPane(64)
	cp.SetLoading()

	m := Model{
		selectedFile: "/tmp/a",
		contentPane:  cp,
	}

	// Stale content shouldn't replace current view.
	m.updateFileContent(FileContentMsg{Path: "/tmp/b", Content: "nope"})
	if strings.Contains(m.contentPane.CopyText(), "nope") {
		t.Fatalf("expected stale FileContentMsg to be ignored")
	}

	m.updateContentOneLine(ContentOneLineMsg{Path: "/tmp/b", Text: "nope"})
	if m.contentPane.oneLineText == "nope" {
		t.Fatalf("expected stale ContentOneLineMsg to be ignored")
	}

	m.updateContentBase64(ContentBase64Msg{Path: "/tmp/b", Text: "nope"})
	if m.contentPane.base64Text == "nope" {
		t.Fatalf("expected stale ContentBase64Msg to be ignored")
	}
}

func TestHelpRendersInPane3(t *testing.T) {
	m := Model{
		width:  120,
		height: 40,
	}
	m.layoutPanes()
	m.showHelp = true
	m.helpPane = newHelpPane()
	m.helpPane.SetSize(m.contentPane.width, m.contentPane.height)
	m.helpPane.SetContent(m.helpText())

	v := m.View()
	if !strings.Contains(v, "[3]-Help-") {
		t.Fatalf("expected pane 3 title to be Help")
	}
	if !strings.Contains(v, "Keyboard Shortcuts") {
		t.Fatalf("expected help content")
	}
}

func TestZoomContentPane_RendersWithoutGrid(t *testing.T) {
	m := Model{
		width:       80,
		height:      20,
		focused:     PaneContent,
		zoomContent: true,
		contentPane: newContentPane(64),
		helpPane:    newHelpPane(),
	}
	m.layoutPanes()
	m.contentPane.SetContent("example.pem", "-----BEGIN CERTIFICATE-----\nABC\n")

	v := m.renderPanes()
	if strings.Contains(v, "[1]-Files-") {
		t.Fatalf("expected zoom view to not render the grid/files pane")
	}
	if !strings.Contains(v, "(z to unzoom)") {
		t.Fatalf("expected zoom header hint")
	}
	if !strings.Contains(v, "BEGIN CERTIFICATE") {
		t.Fatalf("expected content in zoom view")
	}
}

func TestCycleContentPane_DetailsNoBagDoesNotReloadIfCached(t *testing.T) {
	m := Model{
		selectedFile: "dummy",
		contentPane:  newContentPane(64),
	}
	m.contentPane.SetDetails("Bag Attributes\nfriendlyName: x\n-----BEGIN CERTIFICATE-----\nAAA\n")
	m.contentPane.SetMode(contentPaneModeDetails)

	nextModel, cmd := m.cycleContentPane(true)
	if cmd != nil {
		t.Fatalf("expected no cmd when details cached")
	}

	m2, ok := nextModel.(Model)
	if !ok {
		t.Fatalf("expected Model, got %T", nextModel)
	}
	if m2.contentPane.Mode() != contentPaneModeDetailsNoBag {
		t.Fatalf("expected mode %v, got %v", contentPaneModeDetailsNoBag, m2.contentPane.Mode())
	}
}

func TestCopyStatusClearsOnViewCycle(t *testing.T) {
	m := Model{
		focused:              PaneContent,
		selectedFile:         "dummy",
		contentPane:          newContentPane(64),
		keyNextView:          "n",
		keyPrevView:          "p",
		statusMsg:            "Copied to clipboard",
		statusIsErr:          false,
		statusAutoClearOnNav: true,
	}

	next, _ := m.updateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	m2 := next.(Model)
	if m2.statusMsg != "" {
		t.Fatalf("expected status cleared, got %q", m2.statusMsg)
	}
}

func TestUpdateKey_ContentPane_HL_CycleViews(t *testing.T) {
	cp := newContentPane(64)
	cp.SetContent("x", "content")
	cp.SetDetails("details")
	cp.SetOneLineWithMeta("one", false)
	cp.SetBase64("b64")
	cp.SetMode(contentPaneModeDetails)

	m := Model{
		focused:      PaneContent,
		selectedFile: "dummy",
		contentPane:  cp,
		keyNextView:  "n",
		keyPrevView:  "p",
	}

	next, _ := m.updateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("l")})
	m2 := next.(Model)
	if m2.contentPane.Mode() != contentPaneModeOneLine {
		t.Fatalf("expected mode %v, got %v", contentPaneModeOneLine, m2.contentPane.Mode())
	}

	next, _ = m2.updateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("h")})
	m3 := next.(Model)
	if m3.contentPane.Mode() != contentPaneModeDetails {
		t.Fatalf("expected mode %v, got %v", contentPaneModeDetails, m3.contentPane.Mode())
	}

	next, _ = m3.updateKey(tea.KeyMsg{Type: tea.KeyRight})
	m4 := next.(Model)
	if m4.contentPane.Mode() != contentPaneModeOneLine {
		t.Fatalf("expected mode %v, got %v", contentPaneModeOneLine, m4.contentPane.Mode())
	}

	next, _ = m4.updateKey(tea.KeyMsg{Type: tea.KeyLeft})
	m5 := next.(Model)
	if m5.contentPane.Mode() != contentPaneModeDetails {
		t.Fatalf("expected mode %v, got %v", contentPaneModeDetails, m5.contentPane.Mode())
	}
}

func TestCycleContentPane_SkipsDetailsNoBagWhenUnchanged(t *testing.T) {
	m := Model{
		selectedFile: "dummy",
		contentPane:  newContentPane(64),
	}
	m.contentPane.SetDetails("details")
	m.contentPane.SetMode(contentPaneModeDetails)

	nextModel, cmd := m.cycleContentPane(true)
	if cmd == nil {
		t.Fatalf("expected cmd to generate one-line view")
	}

	m2 := nextModel.(Model)
	if m2.contentPane.Mode() != contentPaneModeOneLine {
		t.Fatalf("expected mode %v, got %v", contentPaneModeOneLine, m2.contentPane.Mode())
	}
}

func TestUpdateKey_CyclesTheme(t *testing.T) {
	defer ApplyTheme(themeDefault)

	ApplyTheme(themeDefault)
	m := Model{themeName: "default"}

	next, _ := m.updateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("t")})
	m2 := next.(Model)
	if m2.themeName != "github-dark" {
		t.Fatalf("expected github-dark, got %q", m2.themeName)
	}
	if accentColor != themeGitHubDark.Accent {
		t.Fatalf("expected ApplyTheme to update global accentColor")
	}

	next, _ = m2.updateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("t")})
	m3 := next.(Model)
	if m3.themeName != "github-dark-high-contrast" {
		t.Fatalf("expected github-dark-high-contrast, got %q", m3.themeName)
	}
}

func TestRenderStatusBar_ShowsTheme(t *testing.T) {
	m := Model{width: 120, themeName: "default"}
	s := m.renderStatusBar()
	if !strings.Contains(s, "theme:") || !strings.Contains(s, "default") {
		t.Fatalf("expected theme in status bar, got: %q", s)
	}
}
