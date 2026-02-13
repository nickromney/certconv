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

func TestFilePane_DefaultsToCertLikeExtensionsOnly(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "cert.pem")
	drop := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(keep, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(drop, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	fp := newFilePane(dir)
	if fp.showAll {
		t.Fatalf("expected filtered mode by default")
	}

	var names []string
	for _, e := range fp.entries {
		names = append(names, e.name)
	}
	if !containsString(names, "cert.pem") {
		t.Fatalf("expected cert.pem in entries: %v", names)
	}
	if containsString(names, "notes.txt") {
		t.Fatalf("expected notes.txt to be filtered out: %v", names)
	}
}

func TestFilePane_ToggleShowAll(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	fp := newFilePane(dir)
	if got := fp.ToggleShowAll(); !got {
		t.Fatalf("expected showAll=true after first toggle")
	}

	var names []string
	for _, e := range fp.entries {
		names = append(names, e.name)
	}
	if !containsString(names, "notes.txt") {
		t.Fatalf("expected notes.txt visible in show-all mode: %v", names)
	}

	if got := fp.ToggleShowAll(); got {
		t.Fatalf("expected showAll=false after second toggle")
	}
	names = names[:0]
	for _, e := range fp.entries {
		names = append(names, e.name)
	}
	if containsString(names, "notes.txt") {
		t.Fatalf("expected notes.txt hidden in filtered mode: %v", names)
	}
}

func containsString(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
