package tui

import (
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nickromney/certconv/internal/cert"
	"github.com/nickromney/certconv/internal/config"
)

func (m Model) updateWindowSize(msg tea.WindowSizeMsg) (tea.Model, tea.Cmd) {
	m.width = msg.Width
	m.height = msg.Height
	m.layoutPanes()
	if m.showHelp {
		m.helpPane.SetContent(m.helpText())
	}
	return m, nil
}

func (m Model) updateKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Non-sticky toasts dismiss on any key. Sticky toasts require Esc.
	if m.toastText != "" {
		if m.toastSticky {
			if msg.String() == "esc" || (msg.String() == "o" && strings.TrimSpace(m.opensslCommandText) != "") {
				m.dismissToast()
				return m, nil
			}
		} else {
			m.toastText = ""
		}
	}

	if m.input.active() {
		return m.handleInputKey(msg)
	}

	// Floating picker traps focus until Enter (select) or Esc (close).
	if m.fzfPanel.visible {
		return m, m.fzfPanel.Update(msg, m.fzfListHeight())
	}

	// Action panel takes priority when visible.
	if m.actionPanel.visible {
		switch msg.String() {
		case "u":
			m.actionPanel.Hide()
			m.showHelp = !m.showHelp
			if m.showHelp {
				m.focused = PaneContent
				m.helpPane.SetContent(m.helpText())
			}
			return m, nil
		case "o":
			m.actionPanel.Hide()
			return m.showOpenSSLCommand()
		}
		return m, m.actionPanel.Update(msg)
	}

	m.maybeClearQuitPrompt(msg.String())
	m.maybeClearCopyStatus(msg.String())

	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "q":
		if m.quitArmed {
			return m, tea.Quit
		}
		m.armQuitPrompt()
		return m, nil

	case "z":
		m.zoomContent = !m.zoomContent
		if m.zoomContent {
			m.focused = PaneContent
		}
		m.layoutPanes()
		if m.showHelp {
			m.helpPane.SetContent(m.helpText())
		}
		return m, nil

	case "ctrl+left":
		m.filePanePct = clampInt(m.filePanePct-2, 5, 95, 28)
		m.layoutPanes()
		return m, nil
	case "ctrl+right":
		m.filePanePct = clampInt(m.filePanePct+2, 5, 95, 28)
		m.layoutPanes()
		return m, nil
	case "ctrl+up":
		m.summaryPanePct = clampInt(m.summaryPanePct+2, 5, 95, 38)
		m.layoutPanes()
		return m, nil
	case "ctrl+down":
		m.summaryPanePct = clampInt(m.summaryPanePct-2, 5, 95, 38)
		m.layoutPanes()
		return m, nil
	case m.keyResizeFileLess:
		m.filePanePct = clampInt(m.filePanePct-2, 5, 95, 28)
		m.layoutPanes()
		return m, nil
	case m.keyResizeFileMore:
		m.filePanePct = clampInt(m.filePanePct+2, 5, 95, 28)
		m.layoutPanes()
		return m, nil
	case m.keyResizeSummaryMore:
		m.summaryPanePct = clampInt(m.summaryPanePct+2, 5, 95, 38)
		m.layoutPanes()
		return m, nil
	case m.keyResizeSummaryLess:
		m.summaryPanePct = clampInt(m.summaryPanePct-2, 5, 95, 38)
		m.layoutPanes()
		return m, nil

	case "tab":
		m.focused = m.focused.Next()
		return m, nil

	case "shift+tab":
		m.focused = m.focused.Prev()
		return m, nil

	case "1":
		m.focused = PaneFiles
		return m, nil

	case "2":
		m.focused = PaneInfo
		return m, nil

	case "3":
		m.focused = PaneContent
		return m, nil

	case m.keyCopy:
		if m.toastSticky && strings.TrimSpace(m.opensslCommandText) != "" {
			return m, m.copyToClipboardStatusCmd(m.opensslCommandText, "Output command")
		}
		switch m.focused {
		case PaneFiles:
			if path := m.filePane.CurrentEntryPath(); path != "" {
				return m, m.copyToClipboardCmd(path, "Path")
			}
		case PaneInfo:
			if m.infoPane.CanCopy() {
				return m, m.copyToClipboardCmd(m.infoPane.CopyText(), "Summary")
			}
		case PaneContent:
			if m.selectedFile != "" && m.contentPane.CanCopy() {
				label := m.contentPane.Mode().CopyLabel()
				return m, m.copyToClipboardCmd(m.contentPane.CopyText(), label)
			}
		}
		return m, nil

	case "a", "?":
		return m.toggleReadOnlyActions()

	case "u":
		m.showHelp = !m.showHelp
		if m.showHelp {
			m.focused = PaneContent
			m.helpPane.SetContent(m.helpText())
		}
		return m, nil

	case "o":
		return m.showOpenSSLCommand()

	case "esc":
		if m.quitArmed {
			m.disarmQuitPrompt()
			return m, nil
		}
		if m.showHelp {
			m.showHelp = false
			return m, nil
		}

	case "f", "@":
		return m.openFZFPicker()

	case "v":
		showAll := m.filePane.ToggleShowAll()
		if m.selectedFile != "" {
			m.filePane.SelectFile(m.selectedFile)
		}
		if showAll {
			m.statusMsg = "Files: showing all files (including hidden)"
		} else {
			m.statusMsg = "Files: showing cert/key file types only"
		}
		m.statusIsErr = false
		m.statusAutoClearOnNav = false
		return m, nil

	case "t":
		m.cycleTheme(true)
		if m.showHelp {
			m.helpPane.SetContent(m.helpText())
		}
		// Keep the message short; the theme name is always shown in the status bar.
		m.statusMsg = "Theme changed"
		m.statusIsErr = false
		m.statusAutoClearOnNav = false
		return m, nil

	case "T":
		m.statusMsg = "TUI is read-only: saving theme is disabled"
		m.statusIsErr = true
		m.statusAutoClearOnNav = true
		return m, nil
	}

	// When the output-command toast is visible, treat view-cycling keys as pane-3
	// actions regardless of the focused pane so the command preview tracks.
	if m.toastSticky && strings.TrimSpace(m.opensslCommandText) != "" {
		switch msg.String() {
		case m.keyNextView, "l", "right":
			return m.cycleContentPane(true)
		case m.keyPrevView, "h", "left":
			return m.cycleContentPane(false)
		}
	}

	if m.focused == PaneContent {
		switch msg.String() {
		case m.keyNextView:
			return m.cycleContentPane(true)
		case m.keyPrevView:
			return m.cycleContentPane(false)
		case "l":
			return m.cycleContentPane(true)
		case "h":
			return m.cycleContentPane(false)
		case "right":
			return m.cycleContentPane(true)
		case "left":
			return m.cycleContentPane(false)
		}
	}

	return m.updateFocusedPane(msg)
}

func (m Model) toggleReadOnlyActions() (tea.Model, tea.Cmd) {
	if m.selectedFile != "" {
		if m.selectedType == "" || m.selectedType == cert.FileTypeUnknown {
			if ft, err := cert.DetectType(m.selectedFile); err == nil {
				m.selectedType = ft
			}
		}
		m.actionPanel.SetActions(m.selectedType)
		if len(m.actionPanel.actions) == 0 {
			m.statusMsg = "No read-only actions for this file type"
			m.statusIsErr = true
			m.statusAutoClearOnNav = true
			return m, nil
		}
		m.actionPanel.Toggle()
		return m, nil
	}

	path := m.filePane.CurrentFilePath()
	if path == "" {
		m.statusMsg = "Select a file first to show actions"
		m.statusIsErr = true
		m.statusAutoClearOnNav = true
		return m, nil
	}

	nextModel, cmd := m.updateFileSelected(FileSelectedMsg{Path: path})
	next := nextModel.(Model)
	if ft, err := cert.DetectType(path); err == nil {
		next.selectedType = ft
	}
	next.actionPanel.SetActions(next.selectedType)
	if len(next.actionPanel.actions) == 0 {
		next.statusMsg = "No read-only actions for this file type"
		next.statusIsErr = true
		next.statusAutoClearOnNav = true
		return next, cmd
	}
	next.actionPanel.Toggle()
	return next, cmd
}

func (m *Model) cycleTheme(next bool) {
	names := ThemeNames()
	if len(names) == 0 {
		return
	}

	idx := 0
	for i, name := range names {
		if name == m.themeName {
			idx = i
			break
		}
	}

	if next {
		idx = (idx + 1) % len(names)
	} else {
		idx = (idx - 1 + len(names)) % len(names)
	}

	m.themeName = names[idx]
	ApplyTheme(ThemeByName(m.themeName))
}

func (m Model) saveThemeCmd() tea.Cmd {
	theme := strings.TrimSpace(m.themeName)
	cfgPathDisp := strings.TrimSpace(m.configPath)
	return func() tea.Msg {
		if theme == "" {
			theme = "default"
		}

		if _, err := config.SaveTheme(theme); err != nil {
			return StatusMsg{Text: "Failed to save theme: " + err.Error(), IsErr: true}
		}

		note := ""
		if strings.TrimSpace(os.Getenv("CERTCONV_THEME")) != "" {
			note = " (CERTCONV_THEME overrides)"
		}

		if cfgPathDisp == "" {
			cfgPathDisp = "config.yml"
		}
		return StatusMsg{Text: "Saved theme to " + cfgPathDisp + note, IsErr: false}
	}
}

func (m Model) updateFocusedPane(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.focused {
	case PaneFiles:
		return m, m.filePane.Update(msg)
	case PaneInfo:
		return m, m.infoPane.Update(msg)
	case PaneContent:
		if m.showHelp {
			return m, m.helpPane.Update(msg)
		}
		return m, m.contentPane.Update(msg)
	default:
		return m, nil
	}
}
func (m *Model) dismissToast() {
	m.toastText = ""
	m.toastSticky = false
	m.opensslCommandText = ""
}

func (m *Model) armQuitPrompt() {
	m.quitArmed = true
	m.statusMsg = quitConfirmPrompt
	m.statusIsErr = false
	m.statusAutoClearOnNav = false
	m.toastText = quitConfirmPrompt
	m.toastSticky = false
	m.opensslCommandText = ""
}

func (m *Model) disarmQuitPrompt() {
	if !m.quitArmed {
		return
	}
	m.quitArmed = false
	if m.statusMsg == quitConfirmPrompt {
		m.statusMsg = ""
		m.statusIsErr = false
		m.statusAutoClearOnNav = false
	}
	if m.toastText == quitConfirmPrompt {
		m.dismissToast()
	}
}

func (m *Model) maybeClearQuitPrompt(key string) {
	if !m.quitArmed {
		return
	}
	switch key {
	case "q", "esc":
		return
	default:
		m.disarmQuitPrompt()
	}
}

func (m *Model) maybeClearCopyStatus(key string) {
	if !m.statusAutoClearOnNav {
		return
	}

	switch key {
	// Pane switching.
	case "tab", "shift+tab", "1", "2", "3":
		m.statusMsg = ""
		m.statusIsErr = false
		m.statusAutoClearOnNav = false
		return

	case "z":
		m.statusMsg = ""
		m.statusIsErr = false
		m.statusAutoClearOnNav = false
		return

	// View switching.
	case m.keyNextView, m.keyPrevView:
		m.statusMsg = ""
		m.statusIsErr = false
		m.statusAutoClearOnNav = false
		return

	// Common navigation keys across panes.
	case "up", "down", "j", "k", "pgup", "pgdown", "ctrl+u", "ctrl+d", "g", "G", "h", "l", "left", "right", "enter",
		m.keyResizeFileLess, m.keyResizeFileMore, m.keyResizeSummaryLess, m.keyResizeSummaryMore,
		"ctrl+left", "ctrl+right", "ctrl+up", "ctrl+down":
		m.statusMsg = ""
		m.statusIsErr = false
		m.statusAutoClearOnNav = false
		return
	}
}
