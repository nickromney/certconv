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

func TestSystemRootDir_NotEmpty(t *testing.T) {
	root := systemRootDir()
	if strings.TrimSpace(root) == "" {
		t.Fatalf("expected non-empty root dir")
	}
}
