package tui

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/nickromney/certconv/internal/cert"
	"github.com/nickromney/certconv/internal/config"
)

func (m Model) pfxPassword(path string) string {
	if m.pfxPasswords == nil {
		return ""
	}
	return m.pfxPasswords[path]
}

func (m Model) ctx() context.Context {
	if m.loadCtx != nil {
		return m.loadCtx
	}
	return context.Background()
}

func (m *Model) beginPFXPasswordPrompt(path string, note string) {
	if m.inputMode != "" {
		return
	}
	m.inputMode = "password"
	m.inputPrompt = "PFX password (empty for none): "
	m.inputValue = ""
	m.inputNote = note
	m.inputAction = "pfx-view-password"
	m.inputContext = map[string]string{"path": path}
}

// Model is the root Bubbletea model for the TUI.
type Model struct {
	engine *cert.Engine

	// Panes
	filePane    filePane
	contentPane contentPane
	infoPane    infoPane
	actionPanel actionPanel
	helpPane    helpPane

	// State
	focused              PaneID
	width, height        int
	selectedFile         string
	selectedType         cert.FileType
	autoMatchedKeyPath   string
	statusMsg            string
	statusIsErr          bool
	showHelp             bool
	autoMatchKey         bool
	configPath           string
	statusAutoClearOnNav bool

	// Keybindings (minimally overridable via env vars).
	keyNextView          string
	keyPrevView          string
	keyCopy              string
	keyResizeFileLess    string
	keyResizeFileMore    string
	keyResizeSummaryLess string
	keyResizeSummaryMore string

	// Per-file PFX password cache for viewing/extracting within the current session.
	pfxPasswords map[string]string
	// Tracks whether an empty password ("pass:") has already been rejected for this PFX.
	pfxEmptyRejected map[string]bool

	// Cancel in-flight loads when the file selection changes (important when scrolling quickly).
	loadCtx    context.Context
	loadCancel context.CancelFunc

	// Debounced file focus (pane 1 cursor changes).
	focusDebounce time.Duration
	focusSeq      int
	focusPath     string

	// Resizable layout (keyboard-only). Percentages.
	filePanePct    int
	summaryPanePct int

	// Input mode for actions that need extra input
	inputMode    string // "" = none, "password", "file", "text"
	inputPrompt  string
	inputValue   string
	inputNote    string
	inputAction  string // which action triggered input
	inputContext map[string]string
}

// New creates a new TUI model with the given engine.
func New(engine *cert.Engine, cfg config.Config) Model {
	cfgPath, err := config.Path()
	if err != nil || strings.TrimSpace(cfgPath) == "" {
		cfgPath = "~/.config/certconv/config.yml"
	} else {
		if home, herr := os.UserHomeDir(); herr == nil && strings.HasPrefix(cfgPath, home+string(filepath.Separator)) {
			cfgPath = "~" + strings.TrimPrefix(cfgPath, home)
		}
	}
	startDir := strings.TrimSpace(os.Getenv("CERTCONV_CERTS_DIR"))
	if startDir == "" {
		startDir = strings.TrimSpace(cfg.CertsDir)
	}
	startDir = expandHomeDir(startDir)
	if startDir == "" {
		startDir, _ = os.Getwd()
	}
	if !filepath.IsAbs(startDir) {
		abs, err := filepath.Abs(startDir)
		if err == nil {
			startDir = abs
		}
	}

	return Model{
		engine:               engine,
		filePane:             newFilePane(startDir),
		contentPane:          newContentPane(cfg.OneLineWrapWidth),
		infoPane:             newInfoPane(),
		actionPanel:          newActionPanel(),
		helpPane:             newHelpPane(),
		focused:              PaneFiles,
		autoMatchKey:         envBool("CERTCONV_AUTO_MATCH_KEY", cfg.AutoMatchKey),
		configPath:           cfgPath,
		keyNextView:          envKey("CERTCONV_KEY_NEXT_VIEW", cfg.Keys.NextView),
		keyPrevView:          envKey("CERTCONV_KEY_PREV_VIEW", cfg.Keys.PrevView),
		keyCopy:              envKey("CERTCONV_KEY_COPY", cfg.Keys.Copy),
		keyResizeFileLess:    envKey("CERTCONV_KEY_RESIZE_FILE_LESS", cfg.Keys.ResizeFileLess),
		keyResizeFileMore:    envKey("CERTCONV_KEY_RESIZE_FILE_MORE", cfg.Keys.ResizeFileMore),
		keyResizeSummaryLess: envKey("CERTCONV_KEY_RESIZE_SUMMARY_LESS", cfg.Keys.ResizeSummaryLess),
		keyResizeSummaryMore: envKey("CERTCONV_KEY_RESIZE_SUMMARY_MORE", cfg.Keys.ResizeSummaryMore),
		pfxPasswords:         map[string]string{},
		pfxEmptyRejected:     map[string]bool{},
		loadCtx:              context.Background(),
		focusDebounce:        160 * time.Millisecond,
		filePanePct:          clampInt(cfg.FilePaneWidthPct, 5, 95, 28),
		summaryPanePct:       clampInt(cfg.SummaryPanePct, 5, 95, 38),
	}
}

func clampInt(v, lo, hi, def int) int {
	if v == 0 {
		return def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func expandHomeDir(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return path
	}
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
		return path
	}
	if strings.HasPrefix(path, "~"+string(filepath.Separator)) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~"+string(filepath.Separator)))
		}
	}
	return path
}

func (m Model) Init() tea.Cmd {
	return tea.WindowSize()
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		return m.updateWindowSize(msg)

	case tea.KeyMsg:
		return m.updateKey(msg)

	case tea.MouseMsg:
		return m.updateMouse(msg)

	case FileFocusedMsg:
		return m.updateFileFocused(msg)

	case FileFocusDebouncedMsg:
		return m.updateFileFocusDebounced(msg)

	case FileSelectedMsg:
		return m.updateFileSelected(msg)

	case FileContentMsg:
		m.updateFileContent(msg)
		return m, nil

	case ContentOneLineMsg:
		m.updateContentOneLine(msg)
		return m, nil

	case ContentBase64Msg:
		m.updateContentBase64(msg)
		return m, nil

	case ContentDERBase64Msg:
		m.updateContentDERBase64(msg)
		return m, nil

	case ContentPFXBase64Msg:
		m.updateContentPFXBase64(msg)
		return m, nil

	case ContentModulusMsg:
		m.updateContentModulus(msg)
		return m, nil

	case CertSummaryMsg:
		return m.updateCertSummary(msg)

	case ActionSelectedMsg:
		return m.updateActionSelected(msg)

	case ActionResultMsg:
		m.updateActionResult(msg)
		return m, nil

	case ContentDetailsMsg:
		m.updateContentDetails(msg)
		return m, nil

	case AutoKeyMatchMsg:
		cmd := m.updateAutoKeyMatch(msg)
		return m, cmd

	case StatusMsg:
		m.updateStatus(msg)
		return m, nil
	}

	return m, nil
}

func (m Model) updateMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	// Don't steal focus while an input prompt or modal overlay is active.
	if m.inputMode != "" || m.actionPanel.visible || m.showHelp {
		return m, nil
	}

	me := tea.MouseEvent(msg)
	if me.Button != tea.MouseButtonLeft || me.Action != tea.MouseActionPress {
		return m, nil
	}

	p, ok := m.paneAt(me.X, me.Y)
	if !ok {
		return m, nil
	}
	m.focused = p
	return m, nil
}

func (m Model) paneAt(x, y int) (PaneID, bool) {
	// Pane grid excludes the status line.
	gridW := m.width
	gridH := max(0, m.height-1)
	if gridW <= 0 || gridH <= 0 {
		return PaneFiles, false
	}
	if x < 0 || x >= gridW || y < 0 || y >= gridH {
		return PaneFiles, false
	}

	fileW, _, infoH, _ := m.paneLayout(gridW, gridH)
	if fileW <= 0 {
		return PaneFiles, true
	}
	if infoH <= 0 {
		return PaneFiles, true
	}

	// Shared-border layout: we include border columns/rows in the pane region.
	if x < fileW {
		return PaneFiles, true
	}
	if y < infoH {
		return PaneInfo, true
	}
	return PaneContent, true
}

func (m Model) updateFileFocused(msg FileFocusedMsg) (tea.Model, tea.Cmd) {
	path := strings.TrimSpace(msg.Path)
	if path == "" {
		return m, nil
	}

	m.focusSeq++
	seq := m.focusSeq
	m.focusPath = path

	return m, tea.Tick(m.focusDebounce, func(time.Time) tea.Msg {
		return FileFocusDebouncedMsg{Path: path, Seq: seq}
	})
}

func (m Model) updateFileFocusDebounced(msg FileFocusDebouncedMsg) (tea.Model, tea.Cmd) {
	if msg.Seq != m.focusSeq {
		return m, nil
	}
	if strings.TrimSpace(msg.Path) == "" || msg.Path != m.focusPath {
		return m, nil
	}
	return m.updateFileSelected(FileSelectedMsg{Path: msg.Path})
}

func (m Model) View() string {
	if m.width == 0 {
		return "Loading..."
	}

	panes := m.renderPanes()
	statusBar := m.renderStatusBar()

	if m.actionPanel.visible {
		return m.renderActionPanel(statusBar)
	}

	if m.inputMode != "" {
		return lipgloss.JoinVertical(lipgloss.Left, panes, m.renderInput())
	}

	return lipgloss.JoinVertical(lipgloss.Left, panes, statusBar)
}

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
	if m.inputMode != "" {
		return m.handleInputKey(msg)
	}

	// Action panel takes priority when visible.
	if m.actionPanel.visible {
		return m, m.actionPanel.Update(msg)
	}

	m.maybeClearCopyStatus(msg.String())

	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit

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
		// Copy is global: users expect it to work even when focus is on pane 1/2.
		if m.selectedFile != "" && m.contentPane.CanCopy() {
			return m, m.copyToClipboardCmd(m.contentPane.CopyText())
		}
		return m, nil

	case "?":
		if m.selectedFile != "" {
			m.actionPanel.Toggle()
		}
		return m, nil

	case "ctrl+h":
		m.showHelp = !m.showHelp
		if m.showHelp {
			m.focused = PaneContent
			m.helpPane.SetContent(m.helpText())
		}
		return m, nil

	case "esc":
		if m.showHelp {
			m.showHelp = false
			return m, nil
		}

	case "f":
		return m.runFZF()
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

func (m Model) updateFileSelected(msg FileSelectedMsg) (tea.Model, tea.Cmd) {
	path := m.absolutePath(msg.Path)

	// Invalidate any pending debounced focus.
	m.focusSeq++
	m.focusPath = ""

	// If the selection came from an external picker (fzf), keep the file pane
	// in sync by jumping to the file's directory and focusing it.
	m.filePane.SelectFile(path)

	// Cancel in-flight loads for the previous selection.
	if m.loadCancel != nil {
		m.loadCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.loadCtx = ctx
	m.loadCancel = cancel

	m.selectedFile = path
	m.autoMatchedKeyPath = ""
	m.statusMsg = ""
	m.infoPane.SetAutoKeyStatus("")
	m.contentPane.ResetForFile()
	m.contentPane.SetMode(contentPaneModeContent)
	m.contentPane.SetLoading()
	m.infoPane.SetLoading()

	cmds := []tea.Cmd{
		m.loadFileContent(path),
		m.loadCertSummary(path),
	}

	// Pre-generate alternative views so pane 3 is ready immediately.
	cmds = append(cmds,
		m.loadContentOneLine(path),
		m.loadContentBase64(path),
	)
	if ft, err := cert.DetectType(path); err == nil {
		switch ft {
		case cert.FileTypeCert, cert.FileTypeCombined, cert.FileTypeDER, cert.FileTypePublicKey:
			cmds = append(cmds, m.loadContentDetails(path))
		}
		switch ft {
		case cert.FileTypeCert, cert.FileTypeCombined:
			cmds = append(cmds, m.loadDerivedDERBase64(path))
		}
	}

	return m, tea.Batch(cmds...)
}

func (m *Model) updateFileContent(msg FileContentMsg) {
	// Ignore stale results.
	if msg.Path == "" || msg.Path != m.selectedFile {
		return
	}

	if msg.Err != nil {
		m.contentPane.SetContent("Error", msg.Err.Error())
		return
	}

	name := filepath.Base(msg.Path)
	m.contentPane.SetContent(name, msg.Content)
}

func (m *Model) updateContentOneLine(msg ContentOneLineMsg) {
	// Ignore stale results.
	if msg.Path == "" || msg.Path != m.selectedFile {
		return
	}

	if msg.Err != nil {
		m.contentPane.SetOneLineError(msg.Err.Error())
		return
	}
	m.contentPane.SetOneLineWithMeta(msg.Text, msg.AlreadySingleLine)
}

func (m *Model) updateContentBase64(msg ContentBase64Msg) {
	// Ignore stale results.
	if msg.Path == "" || msg.Path != m.selectedFile {
		return
	}

	if msg.Err != nil {
		m.contentPane.SetBase64Error(msg.Err.Error())
		return
	}
	m.contentPane.SetBase64(msg.Text)
}

func (m *Model) updateContentDERBase64(msg ContentDERBase64Msg) {
	// Ignore stale results.
	if msg.Path == "" || msg.Path != m.selectedFile {
		return
	}

	if msg.Err != nil {
		m.contentPane.SetDERBase64Error(msg.Err.Error())
		return
	}
	m.contentPane.SetDERBase64(msg.Text)
}

func (m *Model) updateContentPFXBase64(msg ContentPFXBase64Msg) {
	// Ignore stale results.
	if msg.Path == "" || msg.Path != m.selectedFile {
		return
	}

	if msg.Err != nil {
		m.contentPane.SetPFXBase64Error(msg.Err.Error())
		return
	}
	m.contentPane.SetPFXBase64(msg.Text)
}

func (m *Model) updateContentModulus(msg ContentModulusMsg) {
	// Ignore stale results.
	if msg.Path == "" || msg.Path != m.selectedFile {
		return
	}

	if msg.Err != nil {
		m.contentPane.SetModulusError(msg.Err.Error())
		return
	}
	m.contentPane.SetModulus(msg.Text)
}

func (m Model) updateCertSummary(msg CertSummaryMsg) (tea.Model, tea.Cmd) {
	// Ignore stale results.
	if msg.Path == "" || msg.Path != m.selectedFile {
		return m, nil
	}

	if msg.Err != nil {
		// Keep file type + actions even on error so the UI doesn't get stuck on "unknown".
		if msg.Summary != nil {
			m.selectedType = msg.Summary.FileType
			m.actionPanel.SetActions(msg.Summary.FileType)
		}

		if cert.IsPFXIncorrectPassword(msg.Err) && msg.Summary != nil {
			m.infoPane.SetSummaryWithInlineError(msg.Summary, "PFX password required (cycle to Details to enter password, or press ? -> Extract to PEM).")
			return m, nil
		}

		if msg.Summary != nil {
			m.infoPane.SetSummaryWithInlineError(msg.Summary, msg.Err.Error())
			return m, nil
		}
		m.infoPane.SetError(msg.Err.Error())
		return m, nil
	}

	m.infoPane.SetSummary(msg.Summary)
	m.selectedType = msg.Summary.FileType
	m.actionPanel.SetActions(msg.Summary.FileType)

	// Opportunistic key matching.
	if m.autoMatchEnabled() {
		switch msg.Summary.FileType {
		case cert.FileTypeCombined:
			m.infoPane.SetAutoKeyStatus("Key: embedded (combined file)")
			return m, nil
		case cert.FileTypeCert, cert.FileTypeDER:
			m.infoPane.SetAutoKeyStatus("Key: searching...")
			return m, m.autoMatchKeyCmd(msg.Path)
		}
	}

	return m, nil
}

func (m *Model) updateAutoKeyMatch(msg AutoKeyMatchMsg) tea.Cmd {
	// Ignore stale results.
	if msg.CertPath == "" || msg.CertPath != m.selectedFile {
		return nil
	}

	if msg.Err != nil {
		m.autoMatchedKeyPath = ""
		m.infoPane.SetAutoKeyStatus("Key: auto-match failed (" + msg.Err.Error() + ")")
		return nil
	}
	if strings.TrimSpace(msg.KeyPath) == "" {
		m.autoMatchedKeyPath = ""
		m.infoPane.SetAutoKeyStatus("Key: no match found in directory")
		return nil
	}
	m.autoMatchedKeyPath = msg.KeyPath
	m.infoPane.SetAutoKeyStatus("Key: " + filepath.Base(msg.KeyPath) + " (matches)")

	// If this is a cert file, eagerly generate PFX preview now that we have a key.
	switch m.selectedType {
	case cert.FileTypeCert, cert.FileTypeCombined:
		if !m.contentPane.HasPFXBase64() {
			return m.loadDerivedPFXBase64(m.selectedFile, msg.KeyPath)
		}
	}
	return nil
}

func (m Model) autoMatchEnabled() bool {
	return m.autoMatchKey
}

func (m Model) autoMatchKeyCmd(certPath string) tea.Cmd {
	return func() tea.Msg {
		dir := filepath.Dir(certPath)

		entries, err := os.ReadDir(dir)
		if err != nil {
			return AutoKeyMatchMsg{CertPath: certPath, Err: err}
		}

		base := strings.TrimSuffix(filepath.Base(certPath), filepath.Ext(certPath))
		var candidates []string

		// Preferred sibling names.
		for _, name := range []string{base + ".key", base + ".pem"} {
			p := filepath.Join(dir, name)
			if p != certPath {
				candidates = append(candidates, p)
			}
		}

		// Then scan directory for likely key files.
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasPrefix(name, ".") {
				continue
			}
			ext := strings.ToLower(filepath.Ext(name))
			if ext != ".key" && ext != ".pem" {
				continue
			}
			candidates = append(candidates, filepath.Join(dir, name))
		}

		seen := map[string]bool{}
		for _, keyPath := range candidates {
			if keyPath == "" || seen[keyPath] {
				continue
			}
			seen[keyPath] = true

			ft, _ := cert.DetectType(keyPath)
			if ft != cert.FileTypeKey && ft != cert.FileTypeCombined {
				continue
			}

			// Only consider private keys for matching.
			if err := cert.ValidatePEMKey(keyPath); err != nil {
				continue
			}

			r, err := m.engine.MatchKeyToCert(m.ctx(), certPath, keyPath)
			if err != nil {
				continue
			}
			if r != nil && r.Match {
				return AutoKeyMatchMsg{CertPath: certPath, KeyPath: keyPath}
			}
		}

		return AutoKeyMatchMsg{CertPath: certPath, KeyPath: ""}
	}
}

func (m Model) updateActionSelected(msg ActionSelectedMsg) (tea.Model, tea.Cmd) {
	return m, m.handleAction(msg.ID)
}

func (m *Model) updateActionResult(msg ActionResultMsg) {
	m.statusMsg = msg.Message
	m.statusIsErr = msg.IsErr
	m.filePane.loadDir()

	text := msg.Message
	if strings.TrimSpace(msg.Details) != "" {
		text = msg.Details
	}
	m.contentPane.SetLastAction(text, msg.IsErr)
}

func (m *Model) updateContentDetails(msg ContentDetailsMsg) {
	// Ignore stale results.
	if msg.Path == "" || msg.Path != m.selectedFile {
		return
	}

	if msg.Err != nil {
		if cert.IsPFXIncorrectPassword(msg.Err) {
			// Only prompt when the user explicitly tries to view details (pane 3).
			if m.focused == PaneContent && (m.contentPane.Mode() == contentPaneModeDetails || m.contentPane.Mode() == contentPaneModeDetailsNoBag) {
				if m.pfxPassword(msg.Path) == "" {
					if m.pfxEmptyRejected == nil {
						m.pfxEmptyRejected = map[string]bool{}
					}
					m.pfxEmptyRejected[msg.Path] = true
				}
				note := "Incorrect password. Try again or press esc."
				if m.pfxPassword(msg.Path) == "" {
					note = "Empty password didn't work. Enter password or press esc."
				}
				m.beginPFXPasswordPrompt(msg.Path, note)
				m.contentPane.SetDetails("PFX password required")
				return
			}

			m.contentPane.SetDetails("PFX password required (cycle to Details in pane 3 to enter password, or press ? -> Extract to PEM).")
			return
		}
		m.contentPane.SetDetails(msg.Err.Error())
		return
	}

	m.contentPane.SetDetails(msg.Details.RawText)
}

func (m *Model) updateStatus(msg StatusMsg) {
	m.statusMsg = msg.Text
	m.statusIsErr = msg.IsErr
	m.statusAutoClearOnNav = !msg.IsErr && msg.Text == "Copied to clipboard"
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

func (m Model) renderPanes() string {
	// We reserve 1 line for the status bar.
	gridW := m.width
	gridH := max(0, m.height-1)
	fileW, rightW, infoH, contentH := m.paneLayout(gridW, gridH)

	// Layout panes to their INNER sizes.
	m.layoutPanes()

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

	return renderGrid(
		gridW, gridH,
		fileW, rightW, infoH, contentH,
		leftBody, topBody, bottomBody,
		m.focused,
		topTitle,
		bottomTitle,
	)
}

func (m Model) renderActionPanel(statusBar string) string {
	actionView := m.actionPanel.View()
	paneH := m.height - 1

	// Center the action panel overlay.
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

func envKey(name string, def string) string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	return v
}

func envBool(name string, def bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if v == "" {
		return def
	}
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

func (m Model) copyToClipboardCmd(text string) tea.Cmd {
	return func() tea.Msg {
		if strings.TrimSpace(text) == "" {
			return StatusMsg{Text: "Nothing to copy", IsErr: true}
		}

		if _, err := exec.LookPath("pbcopy"); err != nil {
			return StatusMsg{Text: "pbcopy not found", IsErr: true}
		}

		cmd := exec.Command("pbcopy")
		cmd.Stdin = strings.NewReader(text)
		if err := cmd.Run(); err != nil {
			return StatusMsg{Text: "Failed to copy to clipboard: " + err.Error(), IsErr: true}
		}

		return StatusMsg{Text: "Copied to clipboard", IsErr: false}
	}
}

func (m Model) cycleContentPane(next bool) (tea.Model, tea.Cmd) {
	if m.selectedFile == "" {
		return m, nil
	}

	m.maybeClearCopyStatus(func() string {
		if next {
			return m.keyNextView
		}
		return m.keyPrevView
	}())

	// Build the cycle list dynamically so we don't show "Details (No Bag Attributes)"
	// when it's identical to "Details".
	modes := []contentPaneMode{
		contentPaneModeContent,
		contentPaneModeDetails,
	}
	if m.contentPane.HasBagAttributes() {
		modes = append(modes, contentPaneModeDetailsNoBag)
	}
	// RSA modulus view is useful for matching RSA certs/keys.
	if m.selectedType == cert.FileTypeCert || m.selectedType == cert.FileTypeCombined || m.selectedType == cert.FileTypeDER || m.selectedType == cert.FileTypeKey {
		modes = append(modes, contentPaneModeModulus)
	}
	modes = append(modes, contentPaneModeOneLine, contentPaneModeBase64)

	// Preview-only conversion views for PEM certs.
	if m.selectedType == cert.FileTypeCert || m.selectedType == cert.FileTypeCombined {
		modes = append(modes, contentPaneModeDERBase64)
		if strings.TrimSpace(m.autoMatchedKeyPath) != "" {
			modes = append(modes, contentPaneModePFXBase64)
		}
	}

	cur := m.contentPane.Mode()
	idx := 0
	for i, v := range modes {
		if v == cur {
			idx = i
			break
		}
	}
	if next {
		idx = (idx + 1) % len(modes)
	} else {
		idx = (idx - 1 + len(modes)) % len(modes)
	}
	mode := modes[idx]
	m.contentPane.SetMode(mode)

	switch mode {
	case contentPaneModeDetails:
		fallthrough
	case contentPaneModeDetailsNoBag:
		if !m.contentPane.HasDetails() {
			m.contentPane.SetLoading()
			return m, m.loadContentDetails(m.selectedFile)
		}
	case contentPaneModeOneLine:
		if !m.contentPane.HasOneLine() {
			m.contentPane.SetLoading()
			return m, m.loadContentOneLine(m.selectedFile)
		}
	case contentPaneModeBase64:
		if !m.contentPane.HasBase64() {
			m.contentPane.SetLoading()
			return m, m.loadContentBase64(m.selectedFile)
		}
	case contentPaneModeModulus:
		if !m.contentPane.HasModulus() {
			m.contentPane.SetLoading()
			return m, m.loadContentModulus(m.selectedFile)
		}
	case contentPaneModeDERBase64:
		if !m.contentPane.HasDERBase64() {
			m.contentPane.SetLoading()
			return m, m.loadDerivedDERBase64(m.selectedFile)
		}
	case contentPaneModePFXBase64:
		if !m.contentPane.HasPFXBase64() {
			if strings.TrimSpace(m.autoMatchedKeyPath) == "" {
				m.contentPane.SetPFXBase64Error("No matching key found in directory (needed for PFX preview).")
				return m, nil
			}
			m.contentPane.SetLoading()
			return m, m.loadDerivedPFXBase64(m.selectedFile, m.autoMatchedKeyPath)
		}
	}

	return m, nil
}

func (m *Model) layoutPanes() {
	// We reserve 1 line for the status bar.
	gridW := m.width
	gridH := max(0, m.height-1)
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
	var parts []string

	add := func(key, desc string) {
		parts = append(parts,
			statusKeyStyle.Render(key)+" "+statusDescStyle.Render(desc))
	}

	add("tab", "pane")
	add("1/2/3", "jump")
	add("?", "actions")
	add("f", "fzf")
	add(m.keyNextView+"/"+m.keyPrevView+",h/l", "view")
	add(m.resizeKeysHint(), "resize")
	add(m.keyCopy, "copy")
	add("ctrl+h", "help")
	add("q", "quit")

	left := strings.Join(parts, "  ")

	// Status message on the right
	right := ""
	if m.statusMsg != "" {
		if m.statusIsErr {
			right = errorStyle.Render(m.statusMsg)
		} else {
			right = successStyle.Render(m.statusMsg)
		}
	}

	gap := m.width - lipgloss.Width(left) - lipgloss.Width(right) - 2
	if gap < 1 {
		gap = 1
	}

	return statusBarStyle.Render(left + strings.Repeat(" ", gap) + right)
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
				{key: "enter / l", desc: "Select / Open directory"},
				{key: "h", desc: "Parent directory"},
				{key: "g / G", desc: "Top / Bottom"},
				{key: "ctrl+d / ctrl+u", desc: "Half page down/up"},
				{key: fmt.Sprintf("%s / %s", m.keyNextView, m.keyPrevView), desc: "Pane 3: cycle views"},
				{key: "h / l or left/right", desc: "Pane 3: prev/next view"},
				{key: m.keyCopy, desc: "Copy current view"},
			},
		},
		{
			title: "Actions",
			items: []helpItem{
				{key: "?", desc: "Toggle action panel"},
				{key: "f", desc: "Open fzf file picker"},
				{key: "ctrl+h", desc: "Toggle help"},
				{key: "q / ctrl+c", desc: "Quit"},
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
				{key: "keys: ...", desc: "Key overrides"},
			},
		},
		{
			title: "Overrides (env)",
			items: []helpItem{
				{key: "CERTCONV_AUTO_MATCH_KEY", desc: "Default: true"},
				{key: "CERTCONV_KEY_NEXT_VIEW", desc: "Default: n"},
				{key: "CERTCONV_KEY_PREV_VIEW", desc: "Default: p"},
				{key: "CERTCONV_KEY_COPY", desc: "Default: c"},
				{key: "CERTCONV_KEY_RESIZE_FILE_LESS", desc: "Default: ["},
				{key: "CERTCONV_KEY_RESIZE_FILE_MORE", desc: "Default: ]"},
				{key: "CERTCONV_KEY_RESIZE_SUMMARY_LESS", desc: "Default: -"},
				{key: "CERTCONV_KEY_RESIZE_SUMMARY_MORE", desc: "Default: ="},
			},
		},
	}

	return helpTable(m.contentPane.width, "certconv - Keyboard Shortcuts", sections)
}

// loadFileContent reads a file and returns a FileContentMsg.
func (m Model) loadFileContent(path string) tea.Cmd {
	return func() tea.Msg {
		data, err := os.ReadFile(path)
		if err != nil {
			return FileContentMsg{Path: path, Err: err}
		}

		content := string(data)
		// Truncate very large files
		const maxDisplay = 10000
		if len(content) > maxDisplay {
			content = content[:maxDisplay] + fmt.Sprintf("\n\n... (truncated, %d bytes total)", len(data))
		}

		// Check if binary
		isBinary := false
		for _, b := range data[:min(512, len(data))] {
			if b == 0 {
				isBinary = true
				break
			}
		}
		if isBinary {
			content = fmt.Sprintf("[Binary file, %d bytes]", len(data))
		}

		return FileContentMsg{Path: path, Content: content}
	}
}

// loadCertSummary runs Engine.Summary and returns a CertSummaryMsg.
func (m Model) loadCertSummary(path string) tea.Cmd {
	return func() tea.Msg {
		pw := m.pfxPassword(path)
		s, err := m.engine.Summary(m.ctx(), path, pw)
		return CertSummaryMsg{Path: path, Summary: s, Err: err}
	}
}

func (m Model) loadContentDetails(path string) tea.Cmd {
	return func() tea.Msg {
		pw := m.pfxPassword(path)
		d, err := m.engine.Details(m.ctx(), path, pw)
		if err != nil || d == nil {
			return ContentDetailsMsg{Path: path, Details: d, Err: err}
		}

		var prefixParts []string

		// Chain summary from the file (PEM/DER) or extracted from PFX.
		if chain, ok := chainSummaryForFile(path); ok {
			prefixParts = append(prefixParts, chain)
		} else if d.FileType == cert.FileTypePFX {
			pemOut, pemErr := m.engine.PFXCertsPEM(m.ctx(), path, pw)
			if pemErr == nil {
				if chain, ok := chainSummaryFromBytes(pemOut); ok {
					prefixParts = append(prefixParts, chain)
				}
			}
		}

		if d.FileType == cert.FileTypePFX {
			if pw == "" {
				prefixParts = append(prefixParts,
					"PFX password: empty (pass:). This is not a meaningful security boundary.",
				)
			} else {
				if m.pfxEmptyRejected != nil && m.pfxEmptyRejected[path] {
					prefixParts = append(prefixParts, "PFX password: non-empty (user-provided; empty password rejected).")
				} else {
					prefixParts = append(prefixParts, "PFX password: non-empty (user-provided).")
				}
			}
		}

		if len(prefixParts) > 0 {
			d.RawText = strings.Join(prefixParts, "\n\n") + "\n\n" + d.RawText
		}

		return ContentDetailsMsg{Path: path, Details: d}
	}
}

func (m Model) loadDerivedDERBase64(path string) tea.Cmd {
	return func() tea.Msg {
		der, err := m.engine.CertDER(m.ctx(), path)
		if err != nil {
			return ContentDERBase64Msg{Path: path, Err: err}
		}
		enc := base64.StdEncoding.EncodeToString(der)
		return ContentDERBase64Msg{Path: path, Text: enc}
	}
}

func (m Model) loadDerivedPFXBase64(certPath, keyPath string) tea.Cmd {
	return func() tea.Msg {
		pfx, err := m.engine.PFXBytes(m.ctx(), certPath, keyPath, "", "")
		if err != nil {
			return ContentPFXBase64Msg{Path: certPath, Err: err}
		}
		enc := base64.StdEncoding.EncodeToString(pfx)
		return ContentPFXBase64Msg{Path: certPath, Text: enc}
	}
}

func (m Model) loadContentModulus(path string) tea.Cmd {
	return func() tea.Msg {
		mod, err := m.engine.RSAModulus(m.ctx(), path)
		if err != nil {
			if errors.Is(err, cert.ErrNotRSA) {
				return ContentModulusMsg{Path: path, Err: fmt.Errorf("modulus is RSA-only (not an RSA key/certificate)")}
			}
			return ContentModulusMsg{Path: path, Err: err}
		}

		sha, md := cert.ModulusDigestsHex(mod)

		var b strings.Builder

		labelW := 18
		kv := func(k, v string) {
			if v == "" {
				return
			}
			b.WriteString(fmt.Sprintf("%-*s %s\n", labelW, k+":", v))
		}

		b.WriteString("Modulus (hex):\n")
		b.WriteString(wrapFixed(mod, m.contentPane.oneLineWrapWidth))
		b.WriteString("\n\n")
		kv("SHA256(modulus)", sha)
		kv("MD5(modulus)", md)

		// If we auto-matched a key for a cert, show the comparison (RSA only).
		if (m.selectedType == cert.FileTypeCert || m.selectedType == cert.FileTypeCombined || m.selectedType == cert.FileTypeDER) &&
			strings.TrimSpace(m.autoMatchedKeyPath) != "" {
			keyMod, kerr := m.engine.RSAModulus(m.ctx(), m.autoMatchedKeyPath)
			if kerr == nil {
				ksha, kmd := cert.ModulusDigestsHex(keyMod)
				match := "NO"
				if strings.TrimSpace(mod) == strings.TrimSpace(keyMod) {
					match = "YES"
				}
				b.WriteString("\n")
				kv("Auto-matched key", filepath.Base(m.autoMatchedKeyPath))
				kv("Key SHA256(modulus)", ksha)
				kv("Key MD5(modulus)", kmd)
				kv("Match", match)
			} else if errors.Is(kerr, cert.ErrNotRSA) {
				b.WriteString("\n")
				kv("Auto-matched key", filepath.Base(m.autoMatchedKeyPath)+" (not RSA; no modulus)")
			}
		}

		return ContentModulusMsg{Path: path, Text: b.String()}
	}
}

func (m Model) loadContentOneLine(path string) tea.Cmd {
	return func() tea.Msg {
		data, err := os.ReadFile(path)
		if err != nil {
			return ContentOneLineMsg{Path: path, Err: err}
		}

		const maxBytes = 256 * 1024
		if len(data) > maxBytes {
			return ContentOneLineMsg{Path: path, Err: fmt.Errorf("file too large for one-line view (%d bytes)", len(data))}
		}

		// If binary, don't try to render; guide the user to Base64 view.
		for _, b := range data[:min(512, len(data))] {
			if b == 0 {
				return ContentOneLineMsg{Path: path, Err: fmt.Errorf("binary file; use base64 view")}
			}
		}

		s := string(data)
		alreadySingleLine := !strings.Contains(s, "\n") && !strings.Contains(s, "\r")
		s = strings.ReplaceAll(s, "\r", "")
		s = strings.ReplaceAll(s, "\n", "")
		return ContentOneLineMsg{Path: path, Text: s, AlreadySingleLine: alreadySingleLine}
	}
}

func (m Model) loadContentBase64(path string) tea.Cmd {
	return func() tea.Msg {
		data, err := os.ReadFile(path)
		if err != nil {
			return ContentBase64Msg{Path: path, Err: err}
		}

		const maxBytes = 2 * 1024 * 1024
		if len(data) > maxBytes {
			return ContentBase64Msg{Path: path, Err: fmt.Errorf("file too large for base64 view (%d bytes)", len(data))}
		}

		// Single-line output to match common Azure KeyVault workflows.
		enc := base64.StdEncoding.EncodeToString(data)
		return ContentBase64Msg{Path: path, Text: enc}
	}
}

// handleAction processes an action selection.
func (m *Model) handleAction(id string) tea.Cmd {
	switch id {
	case "details":
		m.contentPane.SetMode(contentPaneModeDetails)
		m.contentPane.SetLoading()
		return m.loadContentDetails(m.selectedFile)

	case "expiry":
		return func() tea.Msg {
			r, err := m.engine.Expiry(context.Background(), m.selectedFile, 30)
			if err != nil {
				return ActionResultMsg{Message: err.Error(), Details: err.Error(), IsErr: true}
			}
			if r.Valid {
				msg := fmt.Sprintf("Valid for %d more days (expires %s)", r.DaysLeft, r.ExpiryDate)
				return ActionResultMsg{
					Message: msg,
					Details: msg,
				}
			}
			msg := fmt.Sprintf("Expires within 30 days! (%s)", r.ExpiryDate)
			return ActionResultMsg{
				Message: msg,
				Details: msg,
				IsErr:   true,
			}
		}

	case "verify":
		// Need to pick a CA file
		m.inputMode = "text"
		m.inputPrompt = "CA bundle path: "
		m.inputValue = ""
		m.inputAction = "verify"
		return nil

	case "match":
		m.inputMode = "text"
		m.inputPrompt = "Private key path: "
		m.inputValue = ""
		m.inputAction = "match"
		return nil

	case "to-pfx":
		m.inputMode = "text"
		m.inputPrompt = "Private key path: "
		m.inputValue = ""
		m.inputAction = "to-pfx-key"
		m.inputContext = map[string]string{}
		return nil

	case "from-pfx":
		base := strings.TrimSuffix(filepath.Base(m.selectedFile), filepath.Ext(m.selectedFile))
		// Default to a new directory to avoid accidental overwrites.
		defaultDir := filepath.Join(m.filePane.dir, base+"-extracted")
		for i := 1; ; i++ {
			if _, err := os.Stat(defaultDir); os.IsNotExist(err) {
				break
			}
			defaultDir = filepath.Join(m.filePane.dir, fmt.Sprintf("%s-extracted-%d", base, i))
		}
		m.inputMode = "text"
		m.inputPrompt = "Output directory: "
		m.inputValue = filepath.Base(defaultDir)
		m.inputAction = "from-pfx"
		m.inputContext = map[string]string{}
		return nil

	case "to-der", "to-der-key":
		ext := ".der"
		base := strings.TrimSuffix(filepath.Base(m.selectedFile), filepath.Ext(m.selectedFile))
		suggest := cert.NextAvailablePath(filepath.Join(m.filePane.dir, base+ext))
		m.inputMode = "text"
		m.inputPrompt = "Output file: "
		m.inputValue = filepath.Base(suggest)
		m.inputAction = id
		return nil

	case "from-der":
		base := strings.TrimSuffix(filepath.Base(m.selectedFile), filepath.Ext(m.selectedFile))
		suggest := cert.NextAvailablePath(filepath.Join(m.filePane.dir, base+".pem"))
		m.inputMode = "text"
		m.inputPrompt = "Output file: "
		m.inputValue = filepath.Base(suggest)
		m.inputAction = "from-der"
		return nil

	case "to-base64":
		suggest := cert.NextAvailablePath(filepath.Join(m.filePane.dir, filepath.Base(m.selectedFile)+".b64"))
		m.inputMode = "text"
		m.inputPrompt = "Output file: "
		m.inputValue = filepath.Base(suggest)
		m.inputAction = "to-base64"
		return nil

	case "from-base64":
		base := strings.TrimSuffix(filepath.Base(m.selectedFile), filepath.Ext(m.selectedFile))
		suggest := cert.NextAvailablePath(filepath.Join(m.filePane.dir, base+".decoded"))
		m.inputMode = "text"
		m.inputPrompt = "Output file: "
		m.inputValue = filepath.Base(suggest)
		m.inputAction = "from-base64"
		return nil

	case "combine", "combine-key":
		if id == "combine-key" {
			m.inputMode = "text"
			m.inputPrompt = "Certificate path: "
			m.inputAction = "combine-cert-input"
		} else {
			m.inputMode = "text"
			m.inputPrompt = "Private key path: "
			m.inputAction = "combine-key-input"
		}
		m.inputValue = ""
		m.inputContext = map[string]string{}
		return nil
	}

	return nil
}

// handleInputKey processes key presses when in input mode.
func (m Model) handleInputKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.inputMode = ""
		m.inputAction = ""
		m.inputContext = nil
		m.inputNote = ""
		return m, nil

	case "enter":
		value := m.inputValue
		action := m.inputAction
		m.inputMode = ""
		m.inputNote = ""

		return m.processInputResult(action, value)

	case "backspace":
		if len(m.inputValue) > 0 {
			m.inputValue = m.inputValue[:len(m.inputValue)-1]
		}
		return m, nil

	case "ctrl+u":
		m.inputValue = ""
		return m, nil

	default:
		if len(msg.String()) == 1 || msg.String() == " " {
			m.inputValue += msg.String()
		}
		return m, nil
	}
}

// processInputResult executes the action after input is collected.
func (m Model) processInputResult(action, value string) (tea.Model, tea.Cmd) {
	dir := m.filePane.dir

	resolveInDir := func(v string) string {
		if filepath.IsAbs(v) {
			return v
		}
		return filepath.Join(dir, v)
	}

	switch action {
	case "pfx-view-password":
		path := ""
		if m.inputContext != nil {
			path = m.inputContext["path"]
		}
		m.inputContext = nil
		if strings.TrimSpace(path) == "" {
			// Nothing to do.
			return m, nil
		}
		if m.pfxPasswords == nil {
			m.pfxPasswords = map[string]string{}
		}
		m.pfxPasswords[path] = value

		// Reload summary; reload details if the details mode is active.
		cmds := []tea.Cmd{m.loadCertSummary(path)}
		switch m.contentPane.Mode() {
		case contentPaneModeDetails, contentPaneModeDetailsNoBag:
			m.contentPane.SetLoading()
			cmds = append(cmds, m.loadContentDetails(path))
		}
		return m, tea.Batch(cmds...)

	case "verify":
		caPath := resolveInDir(value)
		return m, func() tea.Msg {
			r, err := m.engine.VerifyChain(context.Background(), m.selectedFile, caPath)
			if err != nil {
				return ActionResultMsg{Message: err.Error(), Details: err.Error(), IsErr: true}
			}
			if r.Valid {
				details := r.Output
				if strings.TrimSpace(details) == "" {
					details = "Certificate chain verified"
				}
				return ActionResultMsg{Message: "Certificate chain verified", Details: details}
			}
			msg := "Chain verification failed"
			if r.Details != "" {
				msg += ": " + r.Details
			}
			details := r.Output
			if strings.TrimSpace(details) == "" {
				details = msg
			}
			return ActionResultMsg{Message: msg, Details: details, IsErr: true}
		}

	case "match":
		keyPath := resolveInDir(value)
		return m, func() tea.Msg {
			r, err := m.engine.MatchKeyToCert(context.Background(), m.selectedFile, keyPath)
			if err != nil {
				return ActionResultMsg{Message: err.Error(), Details: err.Error(), IsErr: true}
			}
			if r.Match {
				msg := "Private key matches certificate"
				return ActionResultMsg{Message: msg, Details: msg}
			}
			msg := "Private key does NOT match certificate"
			return ActionResultMsg{Message: msg, Details: msg, IsErr: true}
		}

	case "to-pfx-key":
		m.inputContext["key"] = resolveInDir(value)
		m.inputMode = "text"
		m.inputPrompt = "Output PFX file: "
		base := strings.TrimSuffix(filepath.Base(m.selectedFile), filepath.Ext(m.selectedFile))
		m.inputValue = filepath.Base(cert.NextAvailablePath(filepath.Join(m.filePane.dir, base+".pfx")))
		m.inputAction = "to-pfx-output"
		return m, nil

	case "to-pfx-output":
		m.inputContext["output"] = resolveInDir(value)
		m.inputMode = "password"
		m.inputPrompt = "Export password (empty for none): "
		m.inputValue = ""
		m.inputAction = "to-pfx-exec"
		return m, nil

	case "to-pfx-exec":
		password := value
		keyPath := m.inputContext["key"]
		output := m.inputContext["output"]
		m.inputContext = nil
		certPath := m.selectedFile
		return m, func() tea.Msg {
			if err := m.engine.ToPFX(context.Background(), certPath, keyPath, output, password, ""); err != nil {
				return ActionResultMsg{Message: err.Error(), Details: err.Error(), IsErr: true}
			}
			msg := "Created: " + output
			return ActionResultMsg{Message: msg, Details: msg}
		}

	case "from-pfx":
		outDir := resolveInDir(value)
		m.inputContext["outdir"] = outDir
		m.inputMode = "password"
		m.inputPrompt = "PFX password (empty for none): "
		m.inputValue = ""
		m.inputAction = "from-pfx-exec"
		return m, nil

	case "from-pfx-exec":
		password := value
		outDir := m.inputContext["outdir"]
		m.inputContext = nil
		input := m.selectedFile
		return m, func() tea.Msg {
			r, err := m.engine.FromPFX(context.Background(), input, outDir, password)
			if err != nil {
				return ActionResultMsg{Message: err.Error(), Details: err.Error(), IsErr: true}
			}
			msg := "Extracted: " + r.CertFile + ", " + r.KeyFile
			if r.CAFile != "" {
				msg += ", " + r.CAFile
			}
			return ActionResultMsg{Message: msg, Details: msg}
		}

	case "to-der":
		output := resolveInDir(value)
		certPath := m.selectedFile
		return m, func() tea.Msg {
			if err := m.engine.ToDER(context.Background(), certPath, output, false); err != nil {
				return ActionResultMsg{Message: err.Error(), Details: err.Error(), IsErr: true}
			}
			msg := "Created: " + output
			return ActionResultMsg{Message: msg, Details: msg}
		}

	case "to-der-key":
		output := resolveInDir(value)
		keyPath := m.selectedFile
		return m, func() tea.Msg {
			if err := m.engine.ToDER(context.Background(), keyPath, output, true); err != nil {
				return ActionResultMsg{Message: err.Error(), Details: err.Error(), IsErr: true}
			}
			msg := "Created: " + output
			return ActionResultMsg{Message: msg, Details: msg}
		}

	case "from-der":
		output := resolveInDir(value)
		derPath := m.selectedFile
		return m, func() tea.Msg {
			if err := m.engine.FromDER(context.Background(), derPath, output, false); err != nil {
				return ActionResultMsg{Message: err.Error(), Details: err.Error(), IsErr: true}
			}
			msg := "Created: " + output
			return ActionResultMsg{Message: msg, Details: msg}
		}

	case "to-base64":
		output := resolveInDir(value)
		input := m.selectedFile
		return m, func() tea.Msg {
			if err := m.engine.ToBase64(context.Background(), input, output); err != nil {
				return ActionResultMsg{Message: err.Error(), Details: err.Error(), IsErr: true}
			}
			msg := "Created: " + output
			return ActionResultMsg{Message: msg, Details: msg}
		}

	case "from-base64":
		output := resolveInDir(value)
		input := m.selectedFile
		return m, func() tea.Msg {
			if err := m.engine.FromBase64(context.Background(), input, output); err != nil {
				return ActionResultMsg{Message: err.Error(), Details: err.Error(), IsErr: true}
			}
			msg := "Created: " + output
			return ActionResultMsg{Message: msg, Details: msg}
		}

	case "combine-key-input":
		m.inputContext["key"] = resolveInDir(value)
		m.inputMode = "text"
		m.inputPrompt = "Output file: "
		m.inputValue = filepath.Base(cert.NextAvailablePath(filepath.Join(m.filePane.dir, "combined.pem")))
		m.inputAction = "combine-exec"
		return m, nil

	case "combine-cert-input":
		m.inputContext["cert"] = resolveInDir(value)
		m.inputMode = "text"
		m.inputPrompt = "Output file: "
		m.inputValue = filepath.Base(cert.NextAvailablePath(filepath.Join(m.filePane.dir, "combined.pem")))
		m.inputAction = "combine-exec-from-key"
		return m, nil

	case "combine-exec":
		output := resolveInDir(value)
		keyPath := m.inputContext["key"]
		m.inputContext = nil
		certPath := m.selectedFile
		return m, func() tea.Msg {
			if err := m.engine.CombinePEM(context.Background(), certPath, keyPath, output, ""); err != nil {
				return ActionResultMsg{Message: err.Error(), Details: err.Error(), IsErr: true}
			}
			msg := "Created: " + output
			return ActionResultMsg{Message: msg, Details: msg}
		}

	case "combine-exec-from-key":
		output := resolveInDir(value)
		certPath := m.inputContext["cert"]
		m.inputContext = nil
		keyPath := m.selectedFile
		return m, func() tea.Msg {
			if err := m.engine.CombinePEM(context.Background(), certPath, keyPath, output, ""); err != nil {
				return ActionResultMsg{Message: err.Error(), Details: err.Error(), IsErr: true}
			}
			msg := "Created: " + output
			return ActionResultMsg{Message: msg, Details: msg}
		}
	}

	return m, nil
}

func (m Model) renderInput() string {
	prompt := lipgloss.NewStyle().
		Foreground(accentColor).
		Bold(true).
		Render(m.inputPrompt)

	note := ""
	if strings.TrimSpace(m.inputNote) != "" {
		note = errorStyle.Render("["+strings.TrimSpace(m.inputNote)+"]") + " "
	}

	cursor := lipgloss.NewStyle().
		Foreground(accentColor).
		Render("_")

	renderValue := m.inputValue
	if m.inputMode == "password" {
		renderValue = strings.Repeat("*", len(m.inputValue))
	}
	value := lipgloss.NewStyle().
		Foreground(textColor).
		Render(renderValue)

	return statusBarStyle.Render(prompt + note + value + cursor + "  " +
		lipgloss.NewStyle().Foreground(dimColor).Render("(enter to confirm, esc to cancel)"))
}

// runFZF launches fzf as an external process, captures selection via temp file.
func (m Model) runFZF() (tea.Model, tea.Cmd) {
	_, err := exec.LookPath("fzf")
	if err != nil {
		m.statusMsg = "fzf not found (brew install fzf)"
		m.statusIsErr = true
		return m, nil
	}

	dir := m.filePane.dir

	tmpPath, err := createTempSelectionFile()
	if err != nil {
		m.statusMsg = "failed to create temp file"
		m.statusIsErr = true
		return m, nil
	}
	c := newFZFCommand(dir, tmpPath)

	return m, tea.ExecProcess(c, func(err error) tea.Msg {
		defer os.Remove(tmpPath)
		if err != nil {
			return StatusMsg{Text: "fzf cancelled", IsErr: false}
		}
		data, readErr := os.ReadFile(tmpPath)
		if readErr != nil || len(data) == 0 {
			return StatusMsg{Text: "No file selected", IsErr: false}
		}
		selected := strings.TrimSpace(string(data))
		if selected == "" {
			return StatusMsg{Text: "No file selected", IsErr: false}
		}
		return FileSelectedMsg{Path: selected}
	})
}

func createTempSelectionFile() (string, error) {
	tmpFile, err := os.CreateTemp("", "certconv-fzf-*")
	if err != nil {
		return "", err
	}
	path := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func newFZFCommand(dir, tmpPath string) *exec.Cmd {
	// Use positional args to avoid shell-escaping edge cases in paths.
	script := `find "$1" -maxdepth 3 -type f \( -iname '*.pem' -o -iname '*.crt' -o -iname '*.cer' -o -iname '*.key' -o -iname '*.pub' -o -iname '*.pfx' -o -iname '*.p12' -o -iname '*.der' -o -iname '*.b64' \) 2>/dev/null | sort | fzf --height 15 --reverse > "$2"`
	return exec.Command("sh", "-c", script, "sh", dir, tmpPath)
}
