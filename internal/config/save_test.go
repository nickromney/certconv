package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveTheme_CreatesConfigWhenMissing(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)

	path, err := SaveTheme("high-contrast")
	if err != nil {
		t.Fatalf("SaveTheme: %v", err)
	}
	if path == "" {
		t.Fatalf("expected path")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if strings.TrimSpace(string(data)) != "theme: high-contrast" {
		t.Fatalf("unexpected config contents:\n%s", string(data))
	}
}

func TestSaveTheme_UpdatesExistingThemePreservingOtherLines(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)

	p, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	in := "" +
		"# header\n" +
		"certs_dir: ./certs\n" +
		"theme: default  # keep comment\n" +
		"keys:\n" +
		"  next_view: n\n"
	if err := os.WriteFile(p, []byte(in), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := SaveTheme("github-dark-high-contrast"); err != nil {
		t.Fatalf("SaveTheme: %v", err)
	}

	out, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, "theme: github-dark-high-contrast  # keep comment") {
		t.Fatalf("expected theme update with comment preserved, got:\n%s", s)
	}
	if !strings.Contains(s, "certs_dir: ./certs") || !strings.Contains(s, "keys:\n  next_view: n") {
		t.Fatalf("expected other content preserved, got:\n%s", s)
	}
}

func TestSaveTheme_InsertsBeforeKeysSection(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)

	p, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	in := "" +
		"certs_dir: ./certs\n" +
		"keys:\n" +
		"  next_view: n\n"
	if err := os.WriteFile(p, []byte(in), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if _, err := SaveTheme("default"); err != nil {
		t.Fatalf("SaveTheme: %v", err)
	}

	out, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	s := string(out)
	idxTheme := strings.Index(s, "theme: default")
	idxKeys := strings.Index(s, "keys:")
	if idxTheme < 0 || idxKeys < 0 || idxTheme > idxKeys {
		t.Fatalf("expected theme inserted before keys, got:\n%s", s)
	}
}
