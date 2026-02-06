package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestPaneLayout_OverlapsSumToTotal(t *testing.T) {
	m := Model{filePanePct: 28, summaryPanePct: 38}

	cases := []struct {
		w int
		h int
	}{
		{80, 24},
		{120, 40},
		{40, 10},
		{25, 8},  // tiny
		{10, 4},  // very tiny
		{1, 1},   // degenerate
		{0, 0},   // degenerate
		{5, 100}, // skinny
	}

	for _, tc := range cases {
		fileW, rightW, infoH, contentH := m.paneLayout(tc.w, tc.h)

		// Shared border overlaps.
		if tc.w > 0 && fileW+rightW-1 != tc.w {
			t.Fatalf("w=%d: expected fileW+rightW-1=%d, got %d (fileW=%d rightW=%d)", tc.w, tc.w, fileW+rightW-1, fileW, rightW)
		}
		if tc.h > 0 && infoH+contentH-1 != tc.h {
			t.Fatalf("h=%d: expected infoH+contentH-1=%d, got %d (infoH=%d contentH=%d)", tc.h, tc.h, infoH+contentH-1, infoH, contentH)
		}

		// Should never go negative.
		if fileW < 0 || rightW < 0 || infoH < 0 || contentH < 0 {
			t.Fatalf("w=%d h=%d: negative dimension (fileW=%d rightW=%d infoH=%d contentH=%d)", tc.w, tc.h, fileW, rightW, infoH, contentH)
		}
	}
}

func TestUpdateKey_ResizesLayout(t *testing.T) {
	m := Model{
		filePanePct:          28,
		summaryPanePct:       38,
		width:                120,
		height:               40,
		keyResizeFileLess:    "[",
		keyResizeFileMore:    "]",
		keyResizeSummaryLess: "-",
		keyResizeSummaryMore: "=",
	}

	next, _ := m.updateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("]")})
	m2 := next.(Model)
	if m2.filePanePct <= m.filePanePct {
		t.Fatalf("expected filePanePct to increase, got %d -> %d", m.filePanePct, m2.filePanePct)
	}

	next, _ = m2.updateKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("-")})
	m3 := next.(Model)
	if m3.summaryPanePct >= m2.summaryPanePct {
		t.Fatalf("expected summaryPanePct to decrease, got %d -> %d", m2.summaryPanePct, m3.summaryPanePct)
	}
}
