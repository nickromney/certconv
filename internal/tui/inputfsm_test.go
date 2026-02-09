package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestInputState_BeginResetActive(t *testing.T) {
	var is inputState
	if is.active() {
		t.Fatalf("expected inactive")
	}

	is.begin("text", "Hello: ", "verify")
	if !is.active() {
		t.Fatalf("expected active")
	}
	if is.mode != "text" || is.prompt != "Hello: " || is.action != "verify" {
		t.Fatalf("unexpected state: %+v", is)
	}

	is.reset()
	if is.active() {
		t.Fatalf("expected inactive after reset")
	}
	if is.mode != "" || is.prompt != "" || is.action != "" || is.value != "" || is.note != "" || is.context != nil {
		t.Fatalf("expected fully reset, got: %+v", is)
	}
}

func TestInputState_BeginWithValue(t *testing.T) {
	var is inputState
	is.beginWithValue("text", "Output: ", "x.pem", "to-der")
	if is.mode != "text" || is.prompt != "Output: " || is.value != "x.pem" || is.action != "to-der" {
		t.Fatalf("unexpected state: %+v", is)
	}
}

func TestRenderInput_MasksPassword(t *testing.T) {
	m := Model{}
	m.input.begin("password", "Password: ", "noop")
	m.input.value = "secret"

	out := m.renderInput()
	if strings.Contains(out, "secret") {
		t.Fatalf("expected password to be masked")
	}
	if !strings.Contains(out, "******") {
		t.Fatalf("expected masked asterisks, got: %q", out)
	}
	if !strings.Contains(out, "Password:") {
		t.Fatalf("expected prompt, got: %q", out)
	}
}

func TestHandleAction_FromPFX_DefaultDirValue(t *testing.T) {
	dir := t.TempDir()

	// Force the default suggestion to bump to "-1".
	if err := os.Mkdir(filepath.Join(dir, "foo-extracted"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	pfxPath := filepath.Join(dir, "foo.pfx")
	if err := os.WriteFile(pfxPath, []byte("dummy"), 0o644); err != nil {
		t.Fatalf("write pfx: %v", err)
	}

	m := Model{
		selectedFile: pfxPath,
		filePane:     filePane{dir: dir},
	}
	cmd := m.handleAction("from-pfx")
	if cmd != nil {
		t.Fatalf("expected no cmd")
	}
	if m.input.mode != "text" || m.input.action != "from-pfx" {
		t.Fatalf("unexpected input state: %+v", m.input)
	}
	if m.input.prompt != "Output directory: " {
		t.Fatalf("unexpected prompt: %q", m.input.prompt)
	}
	if m.input.value != "foo-extracted-1" {
		t.Fatalf("unexpected default output dir: %q", m.input.value)
	}
	if m.input.context == nil {
		t.Fatalf("expected context map")
	}
}

func TestProcessInputResult_ToPFXKey_SetsNextPrompt(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "c.pem")
	if err := os.WriteFile(certPath, []byte("dummy"), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	m := Model{
		selectedFile: certPath,
		filePane:     filePane{dir: dir},
	}
	m.input.context = map[string]string{}

	next, cmd := m.processInputResult("to-pfx-key", "k.key")
	if cmd != nil {
		t.Fatalf("expected no cmd")
	}
	m2 := next.(Model)

	if m2.input.action != "to-pfx-output" {
		t.Fatalf("expected next action to-pfx-output, got %q", m2.input.action)
	}
	if m2.input.context == nil || m2.input.context["key"] != filepath.Join(dir, "k.key") {
		t.Fatalf("expected resolved key path in context, got: %+v", m2.input.context)
	}
	if m2.input.mode != "text" || !strings.HasPrefix(m2.input.prompt, "Output PFX file:") {
		t.Fatalf("unexpected next prompt: mode=%q prompt=%q", m2.input.mode, m2.input.prompt)
	}
	if !strings.HasSuffix(m2.input.value, ".pfx") {
		t.Fatalf("expected .pfx default output, got %q", m2.input.value)
	}
}

func TestHandleInputKey_TypingAndEscAndCtrlU(t *testing.T) {
	m := Model{}
	m.input.begin("text", "X: ", "noop")

	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	m2 := next.(Model)
	if m2.input.value != "a" {
		t.Fatalf("expected value 'a', got %q", m2.input.value)
	}

	next, _ = m2.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("b")})
	m3 := next.(Model)
	if m3.input.value != "ab" {
		t.Fatalf("expected value 'ab', got %q", m3.input.value)
	}

	// Clear with ctrl+u.
	next, _ = m3.Update(tea.KeyMsg{Type: tea.KeyCtrlU})
	m4 := next.(Model)
	if m4.input.value != "" {
		t.Fatalf("expected cleared value, got %q", m4.input.value)
	}

	// Esc exits input mode.
	next, _ = m4.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m5 := next.(Model)
	if m5.input.active() {
		t.Fatalf("expected input inactive after esc")
	}
}
