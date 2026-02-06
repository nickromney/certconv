package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// helpPane renders the help content in pane 3, with scrolling.
type helpPane struct {
	viewport viewport.Model
	width    int
	height   int
}

func newHelpPane() helpPane {
	vp := viewport.New(0, 0)
	vp.SetContent("")
	return helpPane{viewport: vp}
}

func (hp *helpPane) SetSize(w, h int) {
	hp.width = w
	hp.height = h
	if w < 0 {
		w = 0
	}
	if h < 0 {
		h = 0
	}
	hp.viewport.Width = w
	hp.viewport.Height = h
}

func (hp *helpPane) SetContent(content string) {
	hp.viewport.SetContent(content)
	hp.viewport.GotoTop()
}

func (hp *helpPane) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "j", "down":
			hp.viewport.LineDown(1)
		case "k", "up":
			hp.viewport.LineUp(1)
		case "ctrl+d":
			hp.viewport.HalfViewDown()
		case "ctrl+u":
			hp.viewport.HalfViewUp()
		case "pgdown":
			hp.viewport.ViewDown()
		case "pgup":
			hp.viewport.ViewUp()
		case "G":
			hp.viewport.GotoBottom()
		case "g":
			hp.viewport.GotoTop()
		default:
			hp.viewport, cmd = hp.viewport.Update(msg)
		}
	default:
		hp.viewport, cmd = hp.viewport.Update(msg)
	}
	return cmd
}

func (hp *helpPane) View(_ bool) string {
	return lipgloss.NewStyle().Width(hp.width).Height(hp.height).Render(hp.viewport.View())
}

func helpTable(width int, title string, sections []helpSection) string {
	if width <= 0 {
		width = 80
	}

	var lines []string
	lines = append(lines, lipgloss.NewStyle().Foreground(accentColor).Bold(true).Render(title))
	lines = append(lines, "")

	// Compute a key column width that avoids wrapping long env vars.
	maxKey := 0
	for _, s := range sections {
		for _, it := range s.items {
			if l := len(it.key); l > maxKey {
				maxKey = l
			}
		}
	}

	// Clamp: we want descriptions to remain readable.
	keyW := maxKey + 2
	if keyW < 18 {
		keyW = 18
	}
	if keyW > 44 {
		keyW = 44
	}
	if keyW > width-10 {
		keyW = max(10, width-10)
	}
	descW := max(0, width-2-keyW)

	keyStyle := lipgloss.NewStyle().Foreground(accentColor).Width(keyW)
	descStyle := lipgloss.NewStyle().Foreground(textColor).Width(descW)
	secStyle := lipgloss.NewStyle().Bold(true).Foreground(textColor)

	for _, s := range sections {
		lines = append(lines, secStyle.Render(s.title))
		for _, it := range s.items {
			k := truncateEnd(it.key, keyW)
			lines = append(lines, "  "+keyStyle.Render(k)+descStyle.Render(it.desc))
		}
		lines = append(lines, "")
	}

	lines = append(lines, lipgloss.NewStyle().Foreground(dimColor).Render("Press ctrl+h or esc to close"))
	return strings.Join(lines, "\n")
}

type helpSection struct {
	title string
	items []helpItem
}

type helpItem struct {
	key  string
	desc string
}

func truncateEnd(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if len(s) <= w {
		return s
	}
	if w <= 1 {
		return s[:w]
	}
	return s[:w-1] + "..."
}
