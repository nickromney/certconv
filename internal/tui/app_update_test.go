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
	"github.com/nickromney/certconv/internal/config"
)

type tuiFakeExec struct{}

func (tuiFakeExec) Run(ctx context.Context, args ...string) (stdout, stderr []byte, err error) {
	return tuiFakeExec{}.RunWithExtraFiles(ctx, nil, args...)
}

func (tuiFakeExec) RunWithExtraFiles(ctx context.Context, _ []cert.ExtraFile, args ...string) (stdout, stderr []byte, err error) {
	if len(args) == 0 {
		return nil, []byte("missing args"), fmt.Errorf("missing args")
	}

	switch args[0] {
	case "verify":
		// openssl verify prints "<certpath>: OK" on success.
		certPath := args[len(args)-1]
		return []byte(certPath + ": OK\n"), nil, nil

	case "x509":
		// Minimal output for summary and details calls.
		if hasArg(args, "-outform") && argValue(args, "-outform") == "DER" {
			return []byte{0x01, 0x02, 0x03}, nil, nil
		}
		if hasArg(args, "-modulus") {
			return []byte("Modulus=ABCDEF\n"), nil, nil
		}
		if hasArg(args, "-pubkey") {
			return []byte("-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----\n"), nil, nil
		}
		if hasArg(args, "-subject") || hasArg(args, "-issuer") || hasArg(args, "-dates") || hasArg(args, "-serial") {
			return []byte(strings.Join([]string{
				"subject=CN=test",
				"issuer=CN=issuer",
				"notBefore=Jan  1 00:00:00 2020 GMT",
				"notAfter=Jan  1 00:00:00 2030 GMT",
				"serial=01",
				"",
			}, "\n")), nil, nil
		}
		if hasArg(args, "-text") {
			return []byte("Certificate:\n    Data:\n"), nil, nil
		}
		return []byte("x509 ok\n"), nil, nil

	case "pkey":
		// Used by MatchKeyToCert: "pkey -pubout -passin fd:3".
		return []byte("-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----\n"), nil, nil

	case "pkcs12":
		// Used by PFX preview generation. We simulate success by writing the output file.
		out := argValue(args, "-out")
		if out != "" {
			_ = os.WriteFile(out, []byte("PFXBYTES"), 0o600)
		}
		return nil, nil, nil
	}

	return nil, []byte("unexpected subcommand: " + args[0]), fmt.Errorf("unexpected subcommand: %s", args[0])
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func argValue(args []string, key string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == key {
			return args[i+1]
		}
	}
	return ""
}

func TestNew_UsesConfigAndEnvOverrides(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}

	cfg := config.Default()
	cfg.CertsDir = "~"
	cfg.Theme = "github-dark"
	cfg.Keys.Copy = "x"

	t.Setenv("CERTCONV_THEME", "github-dark-high-contrast")
	t.Setenv("CERTCONV_KEY_COPY", "c") // override config

	m := New(cert.NewEngine(tuiFakeExec{}), cfg)

	if m.filePane.dir != home {
		t.Fatalf("expected certs dir expanded to home %q, got %q", home, m.filePane.dir)
	}
	if m.themeName != "github-dark-high-contrast" {
		t.Fatalf("expected theme override, got %q", m.themeName)
	}
	if m.keyCopy != "c" {
		t.Fatalf("expected key override, got %q", m.keyCopy)
	}
}

func TestInit_ReturnsWindowSizeCmd(t *testing.T) {
	m := Model{}
	cmd := m.Init()
	if cmd == nil {
		t.Fatalf("expected init cmd")
	}
	// This is a special cmd, but it should still be safe to execute.
	_ = cmd()
}

func TestUpdate_WindowSizeAndHelpContent(t *testing.T) {
	m := Model{
		helpPane: newHelpPane(),
		showHelp: true,
	}
	next, _ := m.Update(tea.WindowSizeMsg{Width: 90, Height: 30})
	m2 := next.(Model)
	if m2.width != 90 || m2.height != 30 {
		t.Fatalf("expected window size set, got %dx%d", m2.width, m2.height)
	}
	// When help is toggled on, window size refresh re-renders help content.
	if got := m2.helpPane.viewport.View(); !strings.Contains(got, "Keyboard Shortcuts") {
		t.Fatalf("expected help content, got %q", got)
	}
}

func TestUpdate_FileFocusDebounce_SelectsAndLoads(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.pem")
	if err := os.WriteFile(p, []byte("hello\nworld\n"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	cfg := config.Default()
	cfg.CertsDir = dir
	cfg.AutoMatchKey = false

	m := New(cert.NewEngine(tuiFakeExec{}), cfg)
	m.focusDebounce = 0

	// Establish layout sizes.
	next, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = next.(Model)

	// Move from ".." to the file to emit FileFocusedMsg.
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = next.(Model)
	if cmd == nil {
		t.Fatalf("expected FileFocused cmd")
	}
	ff, ok := cmd().(FileFocusedMsg)
	if !ok || ff.Path != p {
		t.Fatalf("expected FileFocusedMsg(%q), got %T %+v", p, ff, ff)
	}

	// Model.Update(FileFocusedMsg) should schedule a debounced selection.
	next, tick := m.Update(ff)
	m = next.(Model)
	if tick == nil {
		t.Fatalf("expected debounce tick cmd")
	}

	// With 0 debounce, the cmd should fire immediately.
	db, ok := tick().(FileFocusDebouncedMsg)
	if !ok {
		t.Fatalf("expected FileFocusDebouncedMsg, got %T", db)
	}
	next, _ = m.Update(db)
	m = next.(Model)

	if m.selectedFile != p {
		t.Fatalf("expected selected file %q, got %q", p, m.selectedFile)
	}
	if m.filePane.selected != p {
		t.Fatalf("expected file pane selected %q, got %q", p, m.filePane.selected)
	}
	if m.contentPane.Mode() != contentPaneModeContent {
		t.Fatalf("expected content mode reset, got %v", m.contentPane.Mode())
	}

	// Drive a few of the generated load cmds to cover message handlers.
	fc := m.loadFileContent(p)().(FileContentMsg)
	next, _ = m.Update(fc)
	m = next.(Model)
	if !strings.Contains(m.contentPane.CopyText(), "hello") {
		t.Fatalf("expected content loaded")
	}

	ol := m.loadContentOneLine(p)().(ContentOneLineMsg)
	next, _ = m.Update(ol)
	m = next.(Model)
	if strings.TrimSpace(m.contentPane.oneLineText) == "" {
		t.Fatalf("expected one-line populated")
	}

	b64 := m.loadContentBase64(p)().(ContentBase64Msg)
	next, _ = m.Update(b64)
	m = next.(Model)
	if strings.TrimSpace(m.contentPane.base64Text) == "" {
		t.Fatalf("expected base64 populated")
	}
}

func TestUpdate_InputMode_EditingAndEnter_ExecutesVerify(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(caPath, []byte("-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	m := Model{
		engine:       cert.NewEngine(tuiFakeExec{}),
		filePane:     filePane{dir: dir},
		contentPane:  newContentPane(64),
		infoPane:     newInfoPane(),
		actionPanel:  newActionPanel(),
		helpPane:     newHelpPane(),
		selectedFile: certPath,
	}

	// Enter input mode via action.
	_ = m.handleAction("verify")
	if !m.input.active() || m.input.action != "verify" {
		t.Fatalf("expected verify prompt active, got %+v", m.input)
	}

	// Type a relative path, edit it, then confirm.
	var next tea.Model
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	m = next.(Model)
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	m = next.(Model)
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(filepath.Base(caPath))})
	m = next.(Model)

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if m.input.active() {
		t.Fatalf("expected input mode exited on enter")
	}
	if cmd == nil {
		t.Fatalf("expected cmd for verify")
	}

	// Execute the cmd and feed the result back through Update so status/last-action are updated.
	ar, ok := cmd().(ActionResultMsg)
	if !ok {
		t.Fatalf("expected ActionResultMsg, got %T", ar)
	}
	next, _ = m.Update(ar)
	m = next.(Model)

	if m.statusIsErr {
		t.Fatalf("expected status ok, got err: %q", m.statusMsg)
	}
	if !strings.Contains(m.statusMsg, "verified") {
		t.Fatalf("expected verify success status, got %q", m.statusMsg)
	}
	if strings.TrimSpace(m.contentPane.lastActionText) == "" {
		t.Fatalf("expected last action text populated")
	}
}

func TestUpdate_ActionPanelOverlay_RendersAndCenters(t *testing.T) {
	m := Model{
		width:       80,
		height:      24,
		actionPanel: newActionPanel(),
	}
	m.actionPanel.SetActions(cert.FileTypeCert)
	m.actionPanel.visible = true

	out := m.View()
	if !strings.Contains(out, "Actions") {
		t.Fatalf("expected action panel rendered")
	}
	if !strings.Contains(out, "esc/a") {
		t.Fatalf("expected action panel close hint")
	}
}

func TestUpdate_ContentDetails_PFXIncorrectPassword_PromptsWhenViewingDetails(t *testing.T) {
	p := "/tmp/test.pfx"

	m := Model{
		engine:       cert.NewEngine(tuiFakeExec{}),
		selectedFile: p,
		selectedType: cert.FileTypePFX,
		focused:      PaneContent,
		contentPane:  newContentPane(64),
		infoPane:     newInfoPane(),
	}
	m.contentPane.SetMode(contentPaneModeDetails)

	next, _ := m.Update(ContentDetailsMsg{Path: p, Err: fmt.Errorf("read pfx: %w", cert.ErrPFXIncorrectPassword)})
	m = next.(Model)
	if !m.input.active() || m.input.action != "pfx-view-password" {
		t.Fatalf("expected password prompt active, got %+v", m.input)
	}

	// Provide a password via input mode.
	for _, r := range "secret" {
		next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		m = next.(Model)
	}
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if cmd == nil {
		t.Fatalf("expected cmd batch after password confirm")
	}
	if m.input.active() {
		t.Fatalf("expected input mode cleared after enter")
	}
	if got := m.pfxPassword(p); got != "secret" {
		t.Fatalf("expected password cached, got %q", got)
	}
}

func TestUpdate_FilePicker_OpenEscAndSelect(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CERTCONV_PICKER_START_DIR", dir)
	a := filepath.Join(dir, "a.pem")
	b := filepath.Join(dir, "b.key")
	if err := os.WriteFile(a, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := Model{
		engine:      cert.NewEngine(tuiFakeExec{}),
		filePane:    newFilePane(dir),
		contentPane: newContentPane(64),
		infoPane:    newInfoPane(),
		actionPanel: newActionPanel(),
		helpPane:    newHelpPane(),
		width:       100,
		height:      30,
	}

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("f")})
	m = next.(Model)
	if !m.fzfPanel.visible {
		t.Fatalf("expected picker visible after f")
	}

	// Focus is trapped while picker is open: tab should not switch panes.
	prevFocused := m.focused
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = next.(Model)
	if cmd != nil {
		t.Fatalf("expected picker to trap focus (no global cmd), got cmd")
	}
	if m.focused != prevFocused {
		t.Fatalf("expected focus unchanged while picker is open")
	}
	if !m.fzfPanel.visible {
		t.Fatalf("expected picker still visible")
	}

	// Filter and select b.key.
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("b")})
	m = next.(Model)
	next, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	if cmd == nil {
		t.Fatalf("expected selection cmd")
	}
	msg := cmd()
	fs, ok := msg.(FileSelectedMsg)
	if !ok {
		t.Fatalf("expected FileSelectedMsg, got %T", msg)
	}
	if fs.Path != b {
		t.Fatalf("expected %q, got %q", b, fs.Path)
	}
	if m.fzfPanel.visible {
		t.Fatalf("expected picker hidden after enter")
	}

	// Process selection message.
	next, _ = m.Update(fs)
	m = next.(Model)
	if m.selectedFile != b {
		t.Fatalf("expected selected file %q, got %q", b, m.selectedFile)
	}

	// Re-open then cancel with esc.
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("f")})
	m = next.(Model)
	if !m.fzfPanel.visible {
		t.Fatalf("expected picker visible after reopen")
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = next.(Model)
	if m.fzfPanel.visible {
		t.Fatalf("expected picker closed on esc")
	}
}

func TestUpdate_FilePicker_BackspaceNavigatesParent(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CERTCONV_PICKER_START_DIR", child)

	m := Model{
		filePane: newFilePane(child),
		width:    100,
		height:   30,
	}

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("f")})
	m = next.(Model)
	if !m.fzfPanel.visible {
		t.Fatalf("expected picker visible")
	}
	if m.fzfPanel.rootDir != child {
		t.Fatalf("expected child root %q, got %q", child, m.fzfPanel.rootDir)
	}

	// Empty query + backspace => parent directory.
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	m = next.(Model)
	if m.fzfPanel.rootDir != root {
		t.Fatalf("expected parent root %q, got %q", root, m.fzfPanel.rootDir)
	}
}

// TestUpdate_FilePicker_DefaultsToFilePaneDir verifies that the picker opens
// at the directory the file pane is currently showing, not at $HOME.
func TestUpdate_FilePicker_DefaultsToFilePaneDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CERTCONV_PICKER_START_DIR", "")

	m := Model{
		filePane: newFilePane(dir),
		width:    100,
		height:   30,
	}

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("f")})
	m = next.(Model)
	if !m.fzfPanel.visible {
		t.Fatalf("expected picker visible")
	}
	if m.fzfPanel.rootDir != dir {
		t.Fatalf("expected filePane dir %q as picker root, got %q", dir, m.fzfPanel.rootDir)
	}
}

// TestUpdate_FilePicker_DefaultsToHomeDir verifies the $HOME fallback when
// the file pane has no directory set and CERTCONV_PICKER_START_DIR is empty.
func TestUpdate_FilePicker_DefaultsToHomeDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CERTCONV_PICKER_START_DIR", "")

	// Empty filePane.dir triggers the HOME fallback.
	m := Model{
		filePane: newFilePane(""),
		width:    100,
		height:   30,
	}

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("f")})
	m = next.(Model)
	if !m.fzfPanel.visible {
		t.Fatalf("expected picker visible")
	}
	if m.fzfPanel.rootDir != home {
		t.Fatalf("expected HOME fallback %q as picker root, got %q", home, m.fzfPanel.rootDir)
	}
}

// TestUpdate_FilePicker_SubdirFileMatchesQuery mirrors the original bug: a
// cert file one level inside a subdirectory should be found by typing its
// extension, without having to navigate into the subdirectory first.
func TestUpdate_FilePicker_SubdirFileMatchesQuery(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CERTCONV_PICKER_START_DIR", "")

	certsDir := filepath.Join(root, "certs")
	if err := os.MkdirAll(certsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pfxFile := filepath.Join(certsDir, "example.pfx")
	if err := os.WriteFile(pfxFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := Model{
		filePane: newFilePane(root),
		width:    100,
		height:   30,
	}

	// Open picker — should start at root (filePane.dir).
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("f")})
	m = next.(Model)
	if m.fzfPanel.rootDir != root {
		t.Fatalf("expected root %q, got %q", root, m.fzfPanel.rootDir)
	}

	// Type "pfx" — should surface certs/example.pfx without navigating in.
	for _, ch := range "pfx" {
		next, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{ch}})
		m = next.(Model)
	}
	found := false
	for _, e := range m.fzfPanel.filter {
		if e.path == pfxFile {
			found = true
		}
	}
	if !found {
		var names []string
		for _, e := range m.fzfPanel.filter {
			names = append(names, e.name)
		}
		t.Fatalf("expected %q in filter results after typing 'pfx', got: %v", pfxFile, names)
	}
}

func TestUpdate_FilePicker_AtAliasOpensPicker(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CERTCONV_PICKER_START_DIR", "")

	m := Model{
		filePane: newFilePane(home),
		width:    100,
		height:   30,
	}

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("@")})
	m = next.(Model)
	if !m.fzfPanel.visible {
		t.Fatalf("expected picker visible after @")
	}
	if m.fzfPanel.rootDir != home {
		t.Fatalf("expected home picker root %q, got %q", home, m.fzfPanel.rootDir)
	}
}
