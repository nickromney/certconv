package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/nickromney/certconv/internal/cert"
)

func TestDoctor_AllPresent(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	oldLookPath := lookPathFn
	t.Cleanup(func() { lookPathFn = oldLookPath })
	lookPathFn = func(name string) (string, error) {
		return "/usr/bin/" + name, nil
	}

	oldVersionFn := toolVersionFn
	t.Cleanup(func() { toolVersionFn = oldVersionFn })
	toolVersionFn = func(name string, args ...string) ([]byte, error) {
		return []byte(name + " 1.0.0\n"), nil
	}

	engine := cert.NewDefaultEngine()
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"doctor", "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	var checks []toolCheck
	if err := json.Unmarshal(out.Bytes(), &checks); err != nil {
		t.Fatalf("expected valid JSON, got %q err=%v", out.String(), err)
	}

	if len(checks) != 2 {
		t.Fatalf("expected 2 tool checks, got %d", len(checks))
	}
	for _, c := range checks {
		if !c.Found {
			t.Errorf("expected %s to be found", c.Name)
		}
		if c.Version == "" {
			t.Errorf("expected %s to have a version", c.Name)
		}
	}
}

func TestDoctor_SomeMissing(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	oldLookPath := lookPathFn
	t.Cleanup(func() { lookPathFn = oldLookPath })
	lookPathFn = func(name string) (string, error) {
		if name == "fzf" {
			return "", exec.ErrNotFound
		}
		return "/usr/bin/" + name, nil
	}

	oldVersionFn := toolVersionFn
	t.Cleanup(func() { toolVersionFn = oldVersionFn })
	toolVersionFn = func(name string, args ...string) ([]byte, error) {
		return []byte(name + " 1.0.0\n"), nil
	}

	engine := cert.NewDefaultEngine()
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"doctor", "--json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	var checks []toolCheck
	if err := json.Unmarshal(out.Bytes(), &checks); err != nil {
		t.Fatalf("expected valid JSON, got %q err=%v", out.String(), err)
	}

	foundMissing := false
	for _, c := range checks {
		if c.Name == "fzf" {
			foundMissing = true
			if c.Found {
				t.Error("expected fzf to NOT be found")
			}
		}
	}
	if !foundMissing {
		t.Error("expected missing tool check in output")
	}
}

func TestDoctor_HumanOutput(t *testing.T) {
	oldIsTTY := isTerminalFn
	t.Cleanup(func() { isTerminalFn = oldIsTTY })
	isTerminalFn = func(_ *os.File) bool { return false }

	oldLookPath := lookPathFn
	t.Cleanup(func() { lookPathFn = oldLookPath })
	lookPathFn = func(name string) (string, error) {
		if name == "fzf" {
			return "", exec.ErrNotFound
		}
		return "/usr/bin/" + name, nil
	}

	oldVersionFn := toolVersionFn
	t.Cleanup(func() { toolVersionFn = oldVersionFn })
	toolVersionFn = func(name string, args ...string) ([]byte, error) {
		return []byte(name + " 1.0.0\n"), nil
	}

	engine := cert.NewDefaultEngine()
	cmd := NewRootCmd(engine, nil, BuildInfo{Version: "test"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--plain", "doctor"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	got := out.String()
	if !strings.Contains(got, "fzf") {
		t.Errorf("expected fzf in output, got %q", got)
	}
	if !strings.Contains(got, "not found") {
		t.Errorf("expected 'not found' in output, got %q", got)
	}
}
