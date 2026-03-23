package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestHelpText_CloseHintMatchesBindings(t *testing.T) {
	m := Model{
		width:  120,
		height: 40,
	}
	m.layoutPanes()

	text := m.helpText()
	if !strings.Contains(text, "Press u or esc to close") {
		t.Fatalf("expected updated close hint, got %q", text)
	}
	if strings.Contains(strings.ToLower(text), "ctrl+h") {
		t.Fatalf("did not expect stale ctrl+h close hint, got %q", text)
	}
}

func TestRenderStatusBar_StaysSingleLineOnNarrowWidth(t *testing.T) {
	m := Model{
		width:                80,
		themeName:            "github-dark-high-contrast",
		statusMsg:            "Output command ready (c to copy, Esc/o to close)",
		keyNextView:          "n",
		keyPrevView:          "p",
		keyCopy:              "c",
		keyResizeFileLess:    "[",
		keyResizeFileMore:    "]",
		keyResizeSummaryLess: "-",
		keyResizeSummaryMore: "=",
	}

	s := m.renderStatusBar()
	if strings.Contains(s, "\n") {
		t.Fatalf("expected single-line status bar, got %q", s)
	}
	if got := lipgloss.Width(s); got != 80 {
		t.Fatalf("expected width 80, got %d (%q)", got, s)
	}
}

func TestRenderInput_StaysSingleLineWithinWidth(t *testing.T) {
	m := Model{width: 80}
	m.input.begin("password", "PFX password (empty for none): ", "noop")
	m.input.note = "Empty password didn't work. Enter password or press esc."
	m.input.value = "super-secret-value"

	out := m.renderInput()
	if strings.Contains(out, "\n") {
		t.Fatalf("expected single-line input bar, got %q", out)
	}
	if got := lipgloss.Width(out); got != 80 {
		t.Fatalf("expected width 80, got %d (%q)", got, out)
	}
	if !strings.Contains(out, "PFX password") {
		t.Fatalf("expected prompt in output, got %q", out)
	}
	if !strings.Contains(out, "_") {
		t.Fatalf("expected cursor in output, got %q", out)
	}
}

func TestFZFPanelView_BoundsChromeWidth(t *testing.T) {
	root := t.TempDir()
	deepRoot := filepath.Join(root, "very", "deep", "directory", "tree", "with", "an", "intentionally", "long", "path")
	if err := os.MkdirAll(deepRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deepRoot, "example.pem"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := newFZFPanel()
	p.Open(deepRoot)
	p.query = "really-long-search-query-that-keeps-growing"
	p.errText = "this is a deliberately long picker error message to exercise truncation"
	p.applyFilter()

	totalW := 60
	listHeight := 6
	view := p.View(totalW, 20, listHeight)
	for _, line := range strings.Split(view, "\n") {
		if got := lipgloss.Width(line); got > totalW {
			t.Fatalf("expected line width <= %d, got %d (%q)", totalW, got, line)
		}
	}
	if strings.Contains(view, deepRoot) {
		t.Fatalf("expected long picker root path to be truncated, got %q", view)
	}
}
