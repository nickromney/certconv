package tui

import (
	"strings"
	"testing"
)

func TestContentPaneMode_CycleWraps(t *testing.T) {
	mode := contentPaneModeContent
	for range int(contentPaneModeCount) {
		mode = mode.Next()
	}
	if mode != contentPaneModeContent {
		t.Fatalf("expected Next to wrap back to content, got %v", mode)
	}

	mode = contentPaneModeContent
	mode = mode.Prev()
	if mode != contentPaneModeCount-1 {
		t.Fatalf("expected Prev from content to wrap to last mode, got %v", mode)
	}
}

func TestContentPane_DetailsNoBagStrips(t *testing.T) {
	cp := newContentPane(64)
	cp.SetDetails("Bag Attributes\nfriendlyName: x\n-----BEGIN CERTIFICATE-----\nAAA\n")
	cp.SetMode(contentPaneModeDetailsNoBag)

	got := cp.CopyText()
	if strings.Contains(got, "Bag Attributes") || strings.Contains(got, "friendlyName") {
		t.Fatalf("expected bag attributes stripped, got:\n%s", got)
	}
	if !strings.Contains(got, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("expected PEM preserved, got:\n%s", got)
	}
}

func TestContentPane_CopyIncludesLastAction(t *testing.T) {
	cp := newContentPane(64)
	cp.SetDetails("details-here")
	cp.SetLastAction("action-output", false)
	cp.SetMode(contentPaneModeDetails)

	got := cp.CopyText()
	if !strings.Contains(got, "details-here") || !strings.Contains(got, "Last action:") || !strings.Contains(got, "action-output") {
		t.Fatalf("expected details + last action, got:\n%s", got)
	}
}

func TestContentPane_CanCopyRespectsModeAndLoading(t *testing.T) {
	cp := newContentPane(64)
	cp.SetContent("x", "hello")
	cp.SetMode(contentPaneModeContent)
	if !cp.CanCopy() {
		t.Fatalf("expected CanCopy in content mode")
	}

	cp.SetMode(contentPaneModeBase64)
	if cp.CanCopy() {
		t.Fatalf("expected CanCopy false when base64 not generated")
	}
	cp.SetBase64("abc")
	if !cp.CanCopy() {
		t.Fatalf("expected CanCopy true when base64 present")
	}

	cp.SetLoading()
	if cp.CanCopy() {
		t.Fatalf("expected CanCopy false while loading")
	}
}

func TestContentPane_OneLineAlreadySingleLine_WrapsDisplayButCopyStaysOneLine(t *testing.T) {
	cp := newContentPane(64)
	cp.SetSize(80, 10)
	cp.SetMode(contentPaneModeOneLine)
	cp.SetOneLineWithMeta("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz", true)

	// Display should be wrapped.
	v := cp.View(true)
	if !strings.Contains(v, "\n") {
		t.Fatalf("expected wrapped display to include newlines")
	}

	// Copy text should remain a single line.
	c := cp.CopyText()
	if strings.Contains(c, "\n") {
		t.Fatalf("expected CopyText to be single-line")
	}
}
