package tui

import (
	"fmt"
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

	if m2.inputMode != "" {
		t.Fatalf("expected no prompt, got inputMode=%q", m2.inputMode)
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

func TestCopyToClipboardCmd_PbcopyMissing(t *testing.T) {
	// Make exec.LookPath("pbcopy") deterministic across OS by clearing PATH.
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
	if !strings.Contains(sm.Text, "pbcopy") {
		t.Fatalf("expected pbcopy mention, got: %q", sm.Text)
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
		t.Fatalf("expected error (pbcopy missing), got ok: %q", sm.Text)
	}
	if !strings.Contains(sm.Text, "pbcopy") {
		t.Fatalf("expected pbcopy mention, got: %q", sm.Text)
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
