package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnvBool_DefaultAndOverride(t *testing.T) {
	t.Setenv("CERTCONV_TEST_BOOL", "")
	if got := envBool("CERTCONV_TEST_BOOL", true); !got {
		t.Fatalf("expected default true")
	}

	t.Setenv("CERTCONV_TEST_BOOL", "false")
	if got := envBool("CERTCONV_TEST_BOOL", true); got {
		t.Fatalf("expected false")
	}

	// Unknown values fall back to default.
	t.Setenv("CERTCONV_TEST_BOOL", "maybe")
	if got := envBool("CERTCONV_TEST_BOOL", false); got {
		t.Fatalf("expected default false on unknown")
	}
}

func TestListPickerEntries_SortsAndFilters(t *testing.T) {
	root := t.TempDir()
	mk := func(rel string) string {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		return p
	}

	keepA := mk("a.pem")
	dropExt := mk("notes.txt")
	mk("sub/nested.pfx")
	// Two levels deep: should NOT appear (only one level of look-ahead).
	mk("sub/deep/too-deep.pem")

	entries, err := listPickerEntries(root)
	if err != nil {
		t.Fatalf("listPickerEntries: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("expected entries")
	}
	// First entry should be parent pointer.
	if entries[0].name != "../" || !entries[0].isDir {
		t.Fatalf("expected parent entry first, got %+v", entries[0])
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.name)
	}
	// Directory entry still present for navigation.
	if !containsString(names, "sub/") {
		t.Fatalf("expected directory navigation entry, got: %v", names)
	}
	// Direct cert file at root should appear.
	if !containsString(names, filepath.Base(keepA)) {
		t.Fatalf("expected direct cert file in entries, got: %v", names)
	}
	// Cert file one level inside a subdirectory should appear prefixed.
	if !containsString(names, "sub/nested.pfx") {
		t.Fatalf("expected one-level-deep cert file in entries, got: %v", names)
	}
	// Cert file two levels deep should NOT appear.
	if containsString(names, "sub/deep/too-deep.pem") {
		t.Fatalf("expected two-level-deep file excluded, got: %v", names)
	}
	// Non-cert file should be excluded.
	if containsString(names, filepath.Base(dropExt)) {
		t.Fatalf("expected unsupported extension excluded, got: %v", names)
	}
}

func TestApplyFilter_ParentEntryAlwaysPinned(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "certs")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "example.pfx"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := newFZFPanel()
	p.Open(root)

	// Sanity: parent entry exists in the unfiltered list.
	parentInAll := false
	for _, e := range p.all {
		if e.name == "../" {
			parentInAll = true
		}
	}
	if !parentInAll {
		t.Fatalf("expected ../ in p.all")
	}

	// Type a query that only matches the pfx file, not "../".
	p.query = "pfx"
	p.applyFilter()

	parentInFilter := false
	for _, e := range p.filter {
		if e.name == "../" {
			parentInFilter = true
		}
	}
	if !parentInFilter {
		t.Fatalf("expected ../ pinned in filter even when query %q does not match it", p.query)
	}

	// The matching file should also be present.
	fileInFilter := false
	for _, e := range p.filter {
		if strings.HasSuffix(e.name, "example.pfx") {
			fileInFilter = true
		}
	}
	if !fileInFilter {
		t.Fatalf("expected example.pfx in filter, got: %v", p.filter)
	}
}

func TestFileCount_ReflectsFilteredAndTotal(t *testing.T) {
	root := t.TempDir()
	mk := func(rel string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("a.pem")
	mk("b.pfx")
	mk("sub/c.key")

	p := newFZFPanel()
	p.Open(root)

	_, total := p.fileCount()
	if total != 3 {
		t.Fatalf("expected 3 total files, got %d", total)
	}

	p.query = "pfx"
	p.applyFilter()
	filtered, _ := p.fileCount()
	if filtered != 1 {
		t.Fatalf("expected 1 filtered file for query 'pfx', got %d", filtered)
	}
}

func TestSystemRootDir_NotEmpty(t *testing.T) {
	root := systemRootDir()
	if strings.TrimSpace(root) == "" {
		t.Fatalf("expected non-empty root dir")
	}
}
