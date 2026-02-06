package tui

import (
	"os"
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestFilePane_CursorMoveEmitsFileSelected(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.pem")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	fp := newFilePane(dir)
	fp.width = 80
	fp.height = 10

	// Cursor starts at ".." (dir entry). Move down to first file.
	cmd := fp.Update(tea.KeyMsg{Type: tea.KeyDown})
	if cmd == nil {
		t.Fatalf("expected cmd")
	}
	msg := cmd()
	fs, ok := msg.(FileFocusedMsg)
	if !ok {
		t.Fatalf("expected FileFocusedMsg, got %T", msg)
	}
	if fs.Path != p {
		t.Fatalf("expected %q, got %q", p, fs.Path)
	}
}
