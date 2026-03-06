package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestRenderGrid_DimensionsAndJunctions(t *testing.T) {
	totalW, totalH := 60, 16
	fileW := 20
	rightW := totalW - fileW + 1
	infoH := 7
	contentH := totalH - infoH + 1

	out := renderGrid(
		totalW, totalH,
		fileW, rightW, infoH, contentH,
		[]string{"left-1", "left-2"},
		[]string{"top-1", "top-2"},
		[]string{"bot-1", "bot-2"},
		PaneFiles,
		"color",
		"Summary",
		"Content",
	)

	lines := strings.Split(out, "\n")
	if len(lines) != totalH {
		t.Fatalf("expected %d lines, got %d", totalH, len(lines))
	}
	for i, l := range lines {
		if lipgloss.Width(l) != totalW {
			t.Fatalf("line %d: expected width %d, got %d\n%s", i, totalW, lipgloss.Width(l), l)
		}
	}

	// We use a styled border, so junction characters won't necessarily be at the
	// start/end of the string (ANSI). Checking containment is sufficient.
	if !strings.Contains(lines[0], "┬") {
		t.Fatalf("expected top junction ┬ in first line:\n%s", lines[0])
	}
	if !strings.Contains(out, "├") {
		t.Fatalf("expected split junction ├ in output")
	}
	if !strings.Contains(lines[len(lines)-1], "┴") {
		t.Fatalf("expected bottom junction ┴ in last line:\n%s", lines[len(lines)-1])
	}

	if !strings.Contains(out, "[1]-Files-") {
		t.Fatalf("expected left pane label present")
	}
	if !strings.Contains(out, "[2]-Summary-") {
		t.Fatalf("expected top pane label present")
	}
	if !strings.Contains(out, "[3]-Content-") {
		t.Fatalf("expected bottom pane label present")
	}
}

func TestRenderGrid_FocusIndicatorMarker_IsMarkerOnly(t *testing.T) {
	out := renderGrid(
		60, 16,
		20, 41, 7, 10,
		[]string{"left-1", "left-2"},
		[]string{"top-1", "top-2"},
		[]string{"bot-1", "bot-2"},
		PaneFiles,
		"marker",
		"Summary",
		"Content",
	)

	if !strings.Contains(out, "[1*]-Files-") {
		t.Fatalf("expected focused pane marker in output")
	}
	if focusIndicatorUsesColor("marker") {
		t.Fatalf("expected marker mode to disable active color styling")
	}
	if !focusIndicatorUsesColor("color") {
		t.Fatalf("expected color mode to enable active color styling")
	}
	if !focusIndicatorUsesColor("both") {
		t.Fatalf("expected both mode to enable active color styling")
	}
}
