package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/nickromney/certconv/internal/cert"
)

// action represents a single actionable operation.
type action struct {
	Name string
	Key  string // shortcut key display
	ID   string // internal identifier
}

// actionPanel shows context-aware actions as an overlay.
type actionPanel struct {
	visible bool
	actions []action
	cursor  int
	width   int
	height  int
}

func newActionPanel() actionPanel {
	return actionPanel{}
}

// SetActions updates the available actions based on file type.
func (ap *actionPanel) SetActions(ft cert.FileType) {
	ap.cursor = 0
	ap.actions = nil

	switch ft {
	case cert.FileTypeCert, cert.FileTypeCombined:
		ap.actions = []action{
			{Name: "Check expiry", Key: "e", ID: "expiry"},
			{Name: "Verify chain", Key: "v", ID: "verify"},
			{Name: "Match key", Key: "m", ID: "match"},
			{Name: "Convert to PFX", Key: "1", ID: "to-pfx"},
			{Name: "Convert to DER", Key: "2", ID: "to-der"},
			{Name: "Encode to Base64", Key: "3", ID: "to-base64"},
			{Name: "Combine with key", Key: "4", ID: "combine"},
		}
	case cert.FileTypePFX:
		ap.actions = []action{
			{Name: "Extract to PEM", Key: "1", ID: "from-pfx"},
			{Name: "Encode to Base64", Key: "2", ID: "to-base64"},
		}
	case cert.FileTypeDER:
		ap.actions = []action{
			{Name: "Check expiry", Key: "e", ID: "expiry"},
			{Name: "Convert to PEM", Key: "1", ID: "from-der"},
			{Name: "Encode to Base64", Key: "2", ID: "to-base64"},
		}
	case cert.FileTypeKey:
		ap.actions = []action{
			{Name: "Convert to DER", Key: "1", ID: "to-der-key"},
			{Name: "Encode to Base64", Key: "2", ID: "to-base64"},
			{Name: "Combine with cert", Key: "3", ID: "combine-key"},
		}
	case cert.FileTypePublicKey:
		ap.actions = []action{
			{Name: "Encode to Base64", Key: "1", ID: "to-base64"},
		}
	case cert.FileTypeBase64:
		ap.actions = []action{
			{Name: "Decode Base64", Key: "1", ID: "from-base64"},
		}
	default:
		ap.actions = []action{
			{Name: "Encode to Base64", Key: "1", ID: "to-base64"},
		}
	}
}

func (ap *actionPanel) Toggle() {
	ap.visible = !ap.visible
	ap.cursor = 0
}

func (ap *actionPanel) Hide() {
	ap.visible = false
}

// SelectedAction returns the action ID of the currently selected action.
type ActionSelectedMsg struct {
	ID string
}

func (ap *actionPanel) Update(msg tea.Msg) tea.Cmd {
	if !ap.visible {
		return nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if ap.cursor > 0 {
				ap.cursor--
			}
		case "down", "j":
			if ap.cursor < len(ap.actions)-1 {
				ap.cursor++
			}
		case "enter":
			if len(ap.actions) > 0 {
				id := ap.actions[ap.cursor].ID
				ap.Hide()
				return func() tea.Msg {
					return ActionSelectedMsg{ID: id}
				}
			}
		case "esc", "?":
			ap.Hide()
			return nil
		default:
			// Check shortcut keys
			for _, a := range ap.actions {
				if msg.String() == a.Key {
					ap.Hide()
					id := a.ID
					return func() tea.Msg {
						return ActionSelectedMsg{ID: id}
					}
				}
			}
		}
	}
	return nil
}

func (ap *actionPanel) View() string {
	if !ap.visible || len(ap.actions) == 0 {
		return ""
	}

	titleStyle := lipgloss.NewStyle().
		Foreground(accentColor).
		Bold(true).
		Padding(0, 1)

	var lines []string
	lines = append(lines, titleStyle.Render("Actions"))
	lines = append(lines, "")

	for i, a := range ap.actions {
		keyDisp := lipgloss.NewStyle().
			Foreground(accentColor).
			Bold(true).
			Width(3).
			Render(a.Key)
		nameDisp := lipgloss.NewStyle().Foreground(textColor).Render(a.Name)

		line := "  " + keyDisp + " " + nameDisp
		if i == ap.cursor {
			line = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#1a1b26")).
				Background(accentColor).
				Bold(true).
				Render(" " + a.Key + " " + a.Name + " ")
		}
		lines = append(lines, line)
	}

	lines = append(lines, "")
	lines = append(lines, lipgloss.NewStyle().Foreground(dimColor).Render("  esc/? to close"))

	content := lipgloss.JoinVertical(lipgloss.Left, lines...)

	return lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(accentColor).
		Padding(1, 2).
		Render(content)
}
