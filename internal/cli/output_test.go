package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestOutputOptions_ColorAndUnicode(t *testing.T) {
	oldOut := outStdout
	oldErr := outStderr
	oldOpt := outOpt
	t.Cleanup(func() {
		outStdout = oldOut
		outStderr = oldErr
		outOpt = oldOpt
	})

	var out bytes.Buffer
	var errOut bytes.Buffer

	setOutputOptions(&out, &errOut, outputOptions{color: true, unicode: true})
	out.Reset()
	success("hello")
	got := out.String()
	if !strings.Contains(got, "\x1b[") {
		t.Fatalf("expected ANSI escapes when color enabled, got %q", got)
	}
	if !strings.Contains(got, "✓") {
		t.Fatalf("expected unicode glyph when unicode enabled, got %q", got)
	}

	setOutputOptions(&out, &errOut, outputOptions{color: false, unicode: false})
	out.Reset()
	success("hello")
	got = out.String()
	if strings.Contains(got, "\x1b[") {
		t.Fatalf("expected no ANSI escapes when color disabled, got %q", got)
	}
	if !strings.Contains(got, "OK") {
		t.Fatalf("expected ASCII fallback when unicode disabled, got %q", got)
	}
}

func TestOutputOptions_QuietSuppressesStatusLines(t *testing.T) {
	oldOut := outStdout
	oldErr := outStderr
	oldOpt := outOpt
	t.Cleanup(func() {
		outStdout = oldOut
		outStderr = oldErr
		outOpt = oldOpt
	})

	var out bytes.Buffer
	var errOut bytes.Buffer
	setOutputOptions(&out, &errOut, outputOptions{color: false, unicode: false, quiet: true})

	info("a")
	success("b")
	warn("c")
	step("d")

	if strings.TrimSpace(out.String()) != "" {
		t.Fatalf("expected no stdout when quiet, got %q", out.String())
	}

	errMsg("e")
	if !strings.Contains(errOut.String(), "ERR") {
		t.Fatalf("expected errMsg to still print, got %q", errOut.String())
	}
}
