package tui

import "github.com/charmbracelet/lipgloss"

var (
	// Colours - lazygit-inspired theme
	accentColor    = lipgloss.Color("#7aa2f7") // blue
	dimColor       = lipgloss.Color("#565f89") // dim gray
	textColor      = lipgloss.Color("#c0caf5") // light text
	paneTextColor  = lipgloss.Color("#c0caf5") // defaults to textColor; may differ for high-contrast themes
	paneDimColor   = lipgloss.Color("#565f89") // defaults to dimColor; may differ for high-contrast themes
	bgColor        = lipgloss.Color("#1a1b26") // dark background
	activeBorder   = lipgloss.Color("#7aa2f7") // blue for active pane
	inactiveBorder = lipgloss.Color("#3b4261") // dim for inactive pane
	successColor   = lipgloss.Color("#9ece6a") // green
	errorColor     = lipgloss.Color("#f7768e") // red

	// Status bar
	statusBarStyle = lipgloss.NewStyle().
			Foreground(textColor).
			Padding(0, 1)

	statusKeyStyle = lipgloss.NewStyle().
			Foreground(accentColor).
			Bold(true)

	statusDescStyle = lipgloss.NewStyle().
			Foreground(dimColor)

	// Info pane key-value
	infoKeyStyle = lipgloss.NewStyle().
			Foreground(accentColor).
			Bold(true)

	infoValueStyle = lipgloss.NewStyle().
			Foreground(paneTextColor)

	// Status message styles
	successStyle = lipgloss.NewStyle().Foreground(successColor)
	errorStyle   = lipgloss.NewStyle().Foreground(errorColor)

	// Grid pane header styles
	paneHeaderActiveStyle = lipgloss.NewStyle().
				Foreground(bgColor).
				Background(activeBorder).
				Bold(true)
	paneHeaderInactiveStyle = lipgloss.NewStyle().
				Foreground(dimColor)

	// Grid border styles
	paneBorderActiveStyle = lipgloss.NewStyle().
				Foreground(paneTextColor).
				Bold(true)
	paneBorderInactiveStyle = lipgloss.NewStyle().
				Foreground(inactiveBorder)
)
