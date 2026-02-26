package tui

import "github.com/charmbracelet/lipgloss"

// Theme defines the colour palette for the TUI. Each field maps to a
// semantic role used throughout the UI. Named themes provide different
// palettes for accessibility (colour-blind, high-contrast).
type Theme struct {
	Name string

	// Core palette
	Accent         lipgloss.Color
	Dim            lipgloss.Color
	Text           lipgloss.Color
	PaneText       lipgloss.Color // optional override for pane content text
	PaneDim        lipgloss.Color // optional override for pane secondary text
	Bg             lipgloss.Color
	ActiveBorder   lipgloss.Color
	InactiveBorder lipgloss.Color
	Success        lipgloss.Color
	Error          lipgloss.Color
}

// Built-in themes. The default is Tokyo Night (the original palette).
// High-contrast themes avoid relying solely on red/green distinction and
// use wider colour separation for colour-blind users.

var themeDefault = Theme{
	Name:           "default",
	Accent:         lipgloss.Color("#7aa2f7"), // blue
	Dim:            lipgloss.Color("#565f89"), // dim gray
	Text:           lipgloss.Color("#c0caf5"), // light text
	Bg:             lipgloss.Color("#1a1b26"), // dark background
	ActiveBorder:   lipgloss.Color("#7aa2f7"), // blue
	InactiveBorder: lipgloss.Color("#3b4261"), // dim
	Success:        lipgloss.Color("#9ece6a"), // green
	Error:          lipgloss.Color("#f7768e"), // red
}

// GitHub/Primer theme variants (colours taken from @primer/primitives v11.4.0
// functional theme CSS, extracted 2026-02-07). We only use a tiny subset of
// the full token set: accent/default/muted/success/danger fg, default bg,
// and a single border color.

var themeGitHubDark = Theme{
	Name:           "github-dark",
	Accent:         lipgloss.Color("#4493f8"),
	Dim:            lipgloss.Color("#9198a1"),
	Text:           lipgloss.Color("#f0f6fc"),
	Bg:             lipgloss.Color("#0d1117"),
	ActiveBorder:   lipgloss.Color("#4493f8"),
	InactiveBorder: lipgloss.Color("#3d444d"),
	Success:        lipgloss.Color("#3fb950"),
	Error:          lipgloss.Color("#f85149"),
}

var themeGitHubDarkHighContrast = Theme{
	Name:           "github-dark-high-contrast",
	Accent:         lipgloss.Color("#74b9ff"),
	Dim:            lipgloss.Color("#b7bdc8"),
	Text:           lipgloss.Color("#ffffff"),
	PaneText:       lipgloss.Color("#f7f056"), // bright yellow for maximum contrast on black
	PaneDim:        lipgloss.Color("#b7bdc8"),
	Bg:             lipgloss.Color("#010409"),
	ActiveBorder:   lipgloss.Color("#74b9ff"),
	InactiveBorder: lipgloss.Color("#b7bdc8"),
	Success:        lipgloss.Color("#2bd853"),
	Error:          lipgloss.Color("#ff9492"),
}

// Terminal-adaptive theme using ANSI base colours. These indices map to the
// user's terminal palette and work well across light/dark terminal profiles.
var themeTerminal = Theme{
	Name:           "terminal",
	Accent:         lipgloss.Color("11"), // bright yellow
	Dim:            lipgloss.Color("7"),  // white/light gray
	Text:           lipgloss.Color("15"), // bright white
	Bg:             lipgloss.Color("0"),  // black
	ActiveBorder:   lipgloss.Color("10"), // bright green
	InactiveBorder: lipgloss.Color("8"),  // bright black/gray
	Success:        lipgloss.Color("10"), // bright green
	Error:          lipgloss.Color("9"),  // bright red
}

// ThemeByName returns a named theme. Falls back to default for unknown names.
func ThemeByName(name string) Theme {
	switch name {
	case "github-dark":
		return themeGitHubDark
	case "github-dark-high-contrast":
		return themeGitHubDarkHighContrast
	case "terminal":
		return themeTerminal

	// Back-compat aliases.
	case "high-contrast":
		return themeGitHubDarkHighContrast
	case "default":
		return themeDefault
	case "":
		return themeGitHubDarkHighContrast
	default:
		return themeDefault
	}
}

// ApplyTheme sets the package-level colour and style variables from a Theme.
// Call this once at startup before rendering.
func ApplyTheme(t Theme) {
	accentColor = t.Accent
	dimColor = t.Dim
	textColor = t.Text
	paneTextColor = t.Text
	paneDimColor = t.Dim
	if string(t.PaneText) != "" {
		paneTextColor = t.PaneText
	}
	if string(t.PaneDim) != "" {
		paneDimColor = t.PaneDim
	}
	bgColor = t.Bg
	activeBorder = t.ActiveBorder
	inactiveBorder = t.InactiveBorder
	successColor = t.Success
	errorColor = t.Error

	statusBarStyle = lipgloss.NewStyle().
		Foreground(textColor).
		Padding(0, 1)

	statusKeyStyle = lipgloss.NewStyle().
		Foreground(accentColor).
		Bold(true)

	statusDescStyle = lipgloss.NewStyle().
		Foreground(dimColor)

	infoKeyStyle = lipgloss.NewStyle().
		Foreground(accentColor).
		Bold(true)

	infoValueStyle = lipgloss.NewStyle().
		Foreground(paneTextColor)

	successStyle = lipgloss.NewStyle().Foreground(successColor)
	errorStyle = lipgloss.NewStyle().Foreground(errorColor)
	paneHeaderActiveStyle = lipgloss.NewStyle().
		Foreground(bgColor).
		Background(activeBorder).
		Bold(true)
	paneHeaderInactiveStyle = lipgloss.NewStyle().
		Foreground(dimColor)
	paneBorderActiveStyle = lipgloss.NewStyle().
		Foreground(paneTextColor).
		Bold(true)
	paneBorderInactiveStyle = lipgloss.NewStyle().
		Foreground(inactiveBorder)
}

// ThemeNames returns the available theme names for help text.
func ThemeNames() []string {
	return []string{
		"default",
		"github-dark",
		"github-dark-high-contrast",
		"terminal",
	}
}
