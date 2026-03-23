package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func (m Model) View() string {
	if m.width == 0 {
		return "Loading..."
	}

	panes := m.renderPanes()
	statusBar := m.renderStatusBar()

	if m.actionPanel.visible {
		return m.renderActionPanel(statusBar)
	}

	if m.input.active() {
		return lipgloss.JoinVertical(lipgloss.Left, panes, m.renderInput())
	}

	screen := lipgloss.JoinVertical(lipgloss.Left, panes, statusBar)

	if m.fzfPanel.visible {
		panel := m.fzfPanel.View(m.width, max(0, m.height-1), m.fzfListHeight())
		return m.overlayModal(screen, panel)
	}

	if m.toastText != "" {
		screen = m.overlayToast(screen)
	}

	return screen
}
func (m Model) renderPanes() string {
	// We reserve 1 line for the status bar.
	gridW := m.width
	gridH := max(0, m.height-1)

	// Layout panes to their INNER sizes.
	m.layoutPanes()

	if m.zoomContent {
		title := m.contentPane.BorderTitle()
		body := m.contentPane.View(true)
		if m.showHelp {
			title = "Help"
			body = m.helpPane.View(true)
		}

		headerStyle := lipgloss.NewStyle().Foreground(paneDimColor)
		if focusIndicatorUsesColor(m.focusIndicatorMode) {
			headerStyle = headerStyle.Foreground(activeBorder).Bold(true)
		}
		header := headerStyle.Render(fmt.Sprintf("%s-%s-  (z to unzoom)", paneLabel(3, true, m.focusIndicatorMode), title))
		header = padWidth(header, gridW)

		lines := []string{header}
		lines = append(lines, strings.Split(body, "\n")...)
		lines = padExact(lines, gridH)
		for i := range lines {
			lines[i] = padWidth(lines[i], gridW)
		}
		return strings.Join(lines, "\n")
	}

	fileW, rightW, infoH, contentH := m.paneLayout(gridW, gridH)
	leftBody := strings.Split(m.filePane.View(m.focused == PaneFiles), "\n")
	topBody := strings.Split(m.infoPane.View(m.focused == PaneInfo), "\n")
	bottomTitle := m.contentPane.BorderTitle()
	var bottomBody []string
	if m.showHelp {
		bottomTitle = "Help"
		bottomBody = strings.Split(m.helpPane.View(m.focused == PaneContent), "\n")
	} else {
		bottomBody = strings.Split(m.contentPane.View(m.focused == PaneContent), "\n")
	}

	topTitle := "Summary"
	if m.selectedType != "" {
		topTitle = fmt.Sprintf("Summary [%s]", m.selectedType)
	}
	if strings.TrimSpace(m.selectedFile) != "" {
		topTitle = fmt.Sprintf("%s [%s]", topTitle, filepath.Base(m.selectedFile))
	}

	return renderGrid(
		gridW, gridH,
		fileW, rightW, infoH, contentH,
		leftBody, topBody, bottomBody,
		m.focused,
		m.focusIndicatorMode,
		topTitle,
		bottomTitle,
	)
}

func (m Model) renderActionPanel(statusBar string) string {
	actionView := m.actionPanel.View()
	paneH := m.height - 1

	// Centre the action panel overlay.
	panelW := lipgloss.Width(actionView)
	panelH := lipgloss.Height(actionView)
	padLeft := (m.width - panelW) / 2
	padTop := (paneH - panelH) / 2
	if padLeft < 0 {
		padLeft = 0
	}
	if padTop < 0 {
		padTop = 0
	}

	overlay := lipgloss.NewStyle().
		MarginLeft(padLeft).
		MarginTop(padTop).
		Render(actionView)

	return lipgloss.JoinVertical(lipgloss.Left, overlay, statusBar)
}

// overlayModal paints a floating panel in the centre of the current screen.
func (m Model) overlayModal(screen string, panel string) string {
	if strings.TrimSpace(panel) == "" {
		return screen
	}

	lines := strings.Split(screen, "\n")
	panelLines := strings.Split(panel, "\n")
	panelH := len(panelLines)
	panelW := 0
	for _, line := range panelLines {
		panelW = max(panelW, lipgloss.Width(line))
	}

	row := (len(lines) - panelH) / 2
	col := (m.width - panelW) / 2
	if row < 0 {
		row = 0
	}
	if col < 0 {
		col = 0
	}
	for i, line := range panelLines {
		r := row + i
		if r < 0 || r >= len(lines) {
			continue
		}
		left := strings.Repeat(" ", col)
		rightW := m.width - col - lipgloss.Width(line)
		if rightW < 0 {
			rightW = 0
		}
		lines[r] = padWidth(left+line+strings.Repeat(" ", rightW), m.width)
	}
	return strings.Join(lines, "\n")
}

// overlayToast renders a centred toast notification over the existing screen.
func (m Model) overlayToast(screen string) string {
	if m.toastSticky && strings.TrimSpace(m.opensslCommandText) != "" {
		title := paneHeaderActiveStyle.Render("Output Command")
		cmdLine := lipgloss.NewStyle().
			Foreground(paneTextColor).
			Render(m.opensslCommandText)
		hint := lipgloss.NewStyle().
			Foreground(paneDimColor).
			Render("Esc/o to close   " + m.keyCopy + " to copy")

		content := lipgloss.JoinVertical(
			lipgloss.Left,
			title,
			"",
			cmdLine,
			"",
			hint,
		)
		toastStyle := lipgloss.NewStyle().
			Foreground(textColor).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(activeBorder).
			Padding(0, 2)
		if m.width > 0 {
			toastStyle = toastStyle.Width(m.width).MaxWidth(m.width)
		}
		toast := toastStyle.Render(content)
		return m.overlayModal(screen, toast)
	}

	toast := lipgloss.NewStyle().
		Foreground(textColor).
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(successColor).
		Bold(true).
		Padding(0, 2).
		Render(m.toastText)
	return m.overlayModal(screen, toast)
}

func (m Model) fzfListHeight() int {
	return clampInt(m.height-12, 6, 20, 10)
}

func (m Model) openFZFPicker() (tea.Model, tea.Cmd) {
	startDir := strings.TrimSpace(os.Getenv("CERTCONV_PICKER_START_DIR"))
	if startDir == "" {
		if strings.TrimSpace(m.filePane.dir) != "" {
			startDir = m.filePane.dir
		} else if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
			startDir = home
		} else {
			startDir = systemRootDir()
		}
	}
	startDir = expandHomeDir(startDir)
	m.fzfPanel.Open(startDir)
	m.statusMsg = ""
	m.statusIsErr = false
	m.statusAutoClearOnNav = false
	return m, nil
}

func (m Model) absolutePath(path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

func (m *Model) layoutPanes() {
	// We reserve 1 line for the status bar.
	gridW := m.width
	gridH := max(0, m.height-1)

	if m.zoomContent {
		// Reserve 1 header line inside the pane area.
		bodyH := max(0, gridH-1)
		m.filePane.width = 0
		m.filePane.height = 0
		m.infoPane.SetSize(0, 0)
		m.contentPane.SetSize(max(0, gridW), bodyH)
		m.helpPane.SetSize(max(0, gridW), bodyH)
		return
	}

	fileW, rightW, infoH, contentH := m.paneLayout(gridW, gridH)

	// These pane dimensions are INNER sizes (borders/titles are rendered by the grid).
	m.filePane.width = max(0, fileW-2)
	m.filePane.height = max(0, gridH-2)
	m.infoPane.SetSize(max(0, rightW-2), max(0, infoH-2))
	m.contentPane.SetSize(max(0, rightW-2), max(0, contentH-2))
	m.helpPane.SetSize(max(0, rightW-2), max(0, contentH-2))
}

func (m Model) paneLayout(totalW, totalH int) (fileW, rightW, infoH, contentH int) {
	if totalH < 0 {
		totalH = 0
	}

	// Widths
	if totalW <= 0 {
		return 0, 0, 0, 0
	}

	pct := m.filePanePct
	if pct == 0 {
		pct = 28
	}
	fileW = totalW * pct / 100
	if fileW < 1 {
		fileW = 1
	}
	if fileW > totalW {
		fileW = totalW
	}

	// Keep overlap math consistent: fileW + rightW - 1 == totalW.
	rightW = totalW - fileW + 1
	if rightW < 1 {
		rightW = 1
		fileW = totalW - rightW + 1
	}

	// Prefer to keep at least "border-only" space for both panes when possible.
	if totalW >= 3 {
		if fileW < 2 {
			fileW = 2
		}
		if totalW-fileW+1 < 2 {
			fileW = totalW - 2 + 1
		}
		rightW = totalW - fileW + 1
	}

	// Clamp widths to keep both sides usable on normal terminals.
	minFileW := 18
	minRightW := 30
	if totalW >= (minFileW + minRightW - 1) {
		if fileW < minFileW {
			fileW = minFileW
		}
		if totalW-fileW+1 < minRightW {
			fileW = totalW - minRightW + 1
		}
		rightW = totalW - fileW + 1
	}

	// Heights (right side). Prefer ~38% info, but always fit in totalH.
	if totalH <= 0 {
		infoH = 0
		contentH = 0
	} else {
		pct := m.summaryPanePct
		if pct == 0 {
			pct = 38
		}
		infoH = totalH * pct / 100
		if infoH < 1 {
			infoH = 1
		}
		if infoH > totalH {
			infoH = totalH
		}

		// Keep overlap math consistent: infoH + contentH - 1 == totalH.
		contentH = totalH - infoH + 1
		if contentH < 1 {
			contentH = 1
			infoH = totalH - contentH + 1
		}

		// Prefer to keep at least "border-only" space for both panes when possible.
		if totalH >= 3 {
			if infoH < 2 {
				infoH = 2
			}
			if totalH-infoH+1 < 2 {
				infoH = totalH - 2 + 1
			}
			contentH = totalH - infoH + 1
		}

		// Clamp heights to keep both sides usable on normal terminals.
		minInfoH := 6
		minContentH := 6
		if totalH >= (minInfoH + minContentH - 1) {
			if infoH < minInfoH {
				infoH = minInfoH
			}
			if totalH-infoH+1 < minContentH {
				infoH = totalH - minContentH + 1
			}
			contentH = totalH - infoH + 1
		}
	}

	// Final clamp to avoid negative sizes on tiny terminals.
	if fileW < 1 {
		fileW = 1
	}
	if rightW < 1 {
		rightW = 1
	}
	if infoH < 0 {
		infoH = 0
	}
	if contentH < 0 {
		contentH = 0
	}

	return fileW, rightW, infoH, contentH
}

func (m Model) renderStatusBar() string {
	totalW := m.width
	if totalW <= 0 {
		totalW = 80
	}
	if totalW <= 2 {
		return strings.Repeat(" ", totalW)
	}

	innerW := totalW - 2
	sep := "  "
	hint := func(key, desc string) lineSegment {
		return fixedLineSegment(statusKeyStyle.Render(key) + " " + statusDescStyle.Render(desc))
	}

	leftSegments := []lineSegment{
		hint("tab", "pane"),
		hint("1/2/3", "jump"),
		hint("a", "checks"),
		hint("f/@", "picker"),
		hint("o", "output"),
		hint("v", "view all/filter"),
		hint(m.keyNextView+"/"+m.keyPrevView+",h/l", "view"),
		hint("z", "zoom"),
		hint(m.resizeKeysHint(), "resize"),
		hint(m.keyCopy, "copy"),
		hint("t", "theme"),
		hint("u", "usage"),
		hint("q", "quit?"),
	}

	rightSegments := []lineSegment{
		labeledValueSegment("files: ", m.fileFilterModeLabel(), statusDescStyle, statusKeyStyle),
		labeledValueSegment("theme: ", m.themeName, statusDescStyle, statusKeyStyle),
	}
	if m.statusMsg != "" {
		msgStyle := successStyle
		if m.statusIsErr {
			msgStyle = errorStyle
		}
		rightSegments = append(rightSegments, styledTextSegment(m.statusMsg, msgStyle))
	}

	right, rightW := fitSuffixSegments(rightSegments, innerW, sep)
	leftMax := innerW - rightW
	if rightW > 0 {
		leftMax--
	}
	if leftMax < 0 {
		leftMax = 0
	}
	left, leftW := fitPrefixSegments(leftSegments, leftMax, sep)

	gap := innerW - leftW - rightW
	if left != "" && right != "" && gap < 1 {
		left, leftW = fitPrefixSegments(leftSegments, max(0, innerW-rightW-1), sep)
		gap = innerW - leftW - rightW
	}
	if gap < 0 {
		gap = 0
	}

	content := left + strings.Repeat(" ", gap) + right
	if left == "" && right != "" {
		content = strings.Repeat(" ", max(0, innerW-rightW)) + right
	}

	return statusBarStyle.Render(padWidth(content, innerW))
}

func (m Model) fileFilterModeLabel() string {
	if m.filePane.showAll {
		return "all"
	}
	return "cert/key"
}

func (m Model) resizeKeysHint() string {
	// Keep it compact for the status bar.
	parts := []string{}
	if strings.TrimSpace(m.keyResizeFileLess) != "" && strings.TrimSpace(m.keyResizeFileMore) != "" {
		parts = append(parts, m.keyResizeFileLess+m.keyResizeFileMore)
	}
	if strings.TrimSpace(m.keyResizeSummaryLess) != "" && strings.TrimSpace(m.keyResizeSummaryMore) != "" {
		parts = append(parts, m.keyResizeSummaryLess+m.keyResizeSummaryMore)
	}
	if len(parts) == 0 {
		return "resize"
	}
	return strings.Join(parts, ",")
}

func (m Model) helpText() string {
	sections := []helpSection{
		{
			title: "Layout",
			items: []helpItem{
				{key: fmt.Sprintf("%s / %s", m.keyResizeFileLess, m.keyResizeFileMore), desc: "Resize pane 1"},
				{key: fmt.Sprintf("%s / %s", m.keyResizeSummaryMore, m.keyResizeSummaryLess), desc: "Resize pane 2/3 split"},
				{key: "ctrl+arrows", desc: "Also supported if your terminal passes them through"},
			},
		},
		{
			title: "Navigation",
			items: []helpItem{
				{key: "tab / shift+tab", desc: "Cycle panes"},
				{key: "1 / 2 / 3", desc: "Jump to pane"},
				{key: "j/k or arrows", desc: "Up/Down"},
				{key: "pgup / pgdown", desc: "Page up/down"},
				{key: "enter / l / right", desc: "Select / Open directory"},
				{key: "h / left", desc: "Parent directory"},
				{key: "g / G", desc: "Top / Bottom"},
				{key: "ctrl+d / ctrl+u", desc: "Half page down/up"},
				{key: "v", desc: "Toggle all files (incl. hidden) vs cert/key file types"},
				{key: fmt.Sprintf("%s / %s", m.keyNextView, m.keyPrevView), desc: "Pane 3: cycle views"},
				{key: "h / l or left/right", desc: "Pane 3: prev/next view"},
				{key: m.keyCopy, desc: "Copy selected path (pane 1) or current view"},
				{key: "z", desc: "Zoom pane 3 (for easier selection)"},
			},
		},
		{
			title: "Actions",
			items: []helpItem{
				{key: "a", desc: "Toggle read-only checks (expiry/match/verify)"},
				{key: "f / @", desc: "Open floating file picker (Enter opens dirs; Esc closes)"},
				{key: "o", desc: "Show output command for current pane-3 view (Esc closes; c copies)"},
				{key: "t", desc: "Cycle theme (session)"},
				{key: "T", desc: "Disabled (TUI is read-only; no file writes)"},
				{key: "u", desc: "Show usage"},
				{key: "q (confirm, Esc cancels) / ctrl+c", desc: "Quit"},
			},
		},
		{
			title: "Config",
			items: []helpItem{
				{key: m.configPath, desc: "YAML (optional); env vars override"},
				{key: "auto_match_key", desc: "true/false"},
				{key: "one_line_wrap_width", desc: "Default: 64"},
				{key: "file_pane_width_pct", desc: "Default: 28"},
				{key: "summary_pane_height_pct", desc: "Default: 38"},
				{key: "theme", desc: strings.Join(ThemeNames(), ", ")},
				{key: "keys: ...", desc: "Key overrides"},
			},
		},
		{
			title: "Overrides (env)",
			items: []helpItem{
				{key: "CERTCONV_THEME", desc: "same values as theme"},
				{key: "CERTCONV_AUTO_MATCH_KEY", desc: "Default: true"},
				{key: "CERTCONV_KEY_NEXT_VIEW", desc: "Default: n"},
				{key: "CERTCONV_KEY_PREV_VIEW", desc: "Default: p"},
				{key: "CERTCONV_KEY_COPY", desc: "Default: c"},
				{key: "CERTCONV_KEY_RESIZE_FILE_LESS", desc: "Default: ["},
				{key: "CERTCONV_KEY_RESIZE_FILE_MORE", desc: "Default: ]"},
				{key: "CERTCONV_KEY_RESIZE_SUMMARY_LESS", desc: "Default: -"},
				{key: "CERTCONV_KEY_RESIZE_SUMMARY_MORE", desc: "Default: ="},
				{key: "CERTCONV_EAGER_VIEWS", desc: "Default: true (precompute pane 3 views)"},
				{key: "CERTCONV_FOCUS_INDICATOR", desc: "color|marker|both (Default: color)"},
			},
		},
	}

	return helpTable(m.contentPane.width, "certconv - Keyboard Shortcuts", sections)
}
