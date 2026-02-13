package tui

import (
	"sort"
	"strings"

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
			{Name: "Check Expiry", Key: "e", ID: "expiry"},
			{Name: "Combine with Key", Key: "k", ID: "combine"},
			{Name: "Convert to DER", Key: "d", ID: "to-der"},
			{Name: "Convert to PFX", Key: "p", ID: "to-pfx"},
			{Name: "Encode to Base64", Key: "b", ID: "to-base64"},
			{Name: "Match Key", Key: "m", ID: "match"},
			{Name: "Verify Chain", Key: "v", ID: "verify"},
		}
	case cert.FileTypePFX:
		ap.actions = []action{
			{Name: "Encode to Base64", Key: "b", ID: "to-base64"},
			{Name: "Extract to PEM", Key: "e", ID: "from-pfx"},
		}
	case cert.FileTypeDER:
		ap.actions = []action{
			{Name: "Check Expiry", Key: "e", ID: "expiry"},
			{Name: "Convert to PEM", Key: "p", ID: "from-der"},
			{Name: "Encode to Base64", Key: "b", ID: "to-base64"},
		}
	case cert.FileTypeKey:
		ap.actions = []action{
			{Name: "Combine with Cert", Key: "k", ID: "combine-key"},
			{Name: "Convert to DER", Key: "d", ID: "to-der-key"},
			{Name: "Encode to Base64", Key: "b", ID: "to-base64"},
		}
	case cert.FileTypePublicKey:
		ap.actions = []action{
			{Name: "Encode to Base64", Key: "b", ID: "to-base64"},
		}
	case cert.FileTypeBase64:
		ap.actions = []action{
			{Name: "Decode Base64", Key: "d", ID: "from-base64"},
		}
	default:
		ap.actions = []action{
			{Name: "Encode to Base64", Key: "b", ID: "to-base64"},
		}
	}

	sort.Slice(ap.actions, func(i, j int) bool {
		if ap.actions[i].Key == ap.actions[j].Key {
			return ap.actions[i].Name < ap.actions[j].Name
		}
		return ap.actions[i].Key < ap.actions[j].Key
	})
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
		case "esc", "?", "a":
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
		nameDisp := lipgloss.NewStyle().Foreground(paneTextColor).Render(underlineActionMnemonic(a.Name, a.Key))

		line := "  " + keyDisp + " " + nameDisp
		if i == ap.cursor {
			line = lipgloss.NewStyle().
				Foreground(bgColor).
				Background(accentColor).
				Bold(true).
				Render(" " + a.Key + " " + underlineActionMnemonic(a.Name, a.Key) + " ")
		}
		lines = append(lines, line)
	}

	lines = append(lines, "")
	lines = append(lines, lipgloss.NewStyle().Foreground(paneDimColor).Render("  esc/a to close"))

	content := lipgloss.JoinVertical(lipgloss.Left, lines...)

	return lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(accentColor).
		Padding(1, 2).
		Render(content)
}

func underlineActionMnemonic(name, key string) string {
	name = strings.TrimSpace(name)
	key = strings.TrimSpace(key)
	if name == "" || key == "" {
		return name
	}

	lowerName := strings.ToLower(name)
	lowerKey := strings.ToLower(key)
	idx := strings.Index(lowerName, lowerKey)
	if idx < 0 {
		return name
	}

	end := idx + len(key)
	if end > len(name) {
		end = len(name)
	}

	return name[:idx] + lipgloss.NewStyle().Underline(true).Render(name[idx:end]) + name[end:]
}
