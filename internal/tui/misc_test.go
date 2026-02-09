package tui

import (
	"os"
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

func TestCreateTempSelectionFile_AndNewFZFCommand(t *testing.T) {
	path, err := createTempSelectionFile()
	if err != nil {
		t.Fatalf("create temp selection file: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })

	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("expected temp file to exist, stat err: %v", statErr)
	}

	c := newFZFCommand("/tmp", path)
	if c == nil || c.Path == "" {
		t.Fatalf("expected command")
	}
}
