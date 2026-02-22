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
	if m.input.active() {
		return
	}
	m.input.begin("password", "PFX password (empty for none): ", "pfx-view-password")
	m.input.note = note
	m.input.context = map[string]string{"path": path}
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
	fzfPanel    fzfPanel

	// State
	focused              PaneID
	zoomContent          bool
	width, height        int
	selectedFile         string
	selectedType         cert.FileType
	autoMatchedKeyPath   string
	statusMsg            string
	statusIsErr          bool
	quitArmed            bool
	showHelp             bool
	autoMatchKey         bool
	configPath           string
	statusAutoClearOnNav bool
	themeName            string

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

	// When true, precompute multiple derived views on file selection (one-line,
	// base64, details, parsed, modulus, previews). Improves UX but costs work.
	eagerViews bool

	// Input mode for actions that need extra input.
	input inputState

	// Toast overlay (auto-dismissing confirmation).
	toastText          string
	toastSticky        bool
	opensslCommandText string
}

const quitConfirmPrompt = "Quit? Press q again, or Esc"

// New creates a new TUI model with the given engine.
func New(engine *cert.Engine, cfg config.Config, startDirOverride ...string) Model {
	themeName := envKey("CERTCONV_THEME", cfg.Theme)
	ApplyTheme(ThemeByName(themeName))
	cfgPath, err := config.Path()
	if err != nil || strings.TrimSpace(cfgPath) == "" {
		cfgPath = "~/.config/certconv/config.yml"
	} else {
		if home, herr := os.UserHomeDir(); herr == nil && strings.HasPrefix(cfgPath, home+string(filepath.Separator)) {
			cfgPath = "~" + strings.TrimPrefix(cfgPath, home)
		}
	}
	startDir := ""
	if len(startDirOverride) > 0 {
		startDir = strings.TrimSpace(startDirOverride[0])
	}
	if startDir == "" {
		startDir = strings.TrimSpace(os.Getenv("CERTCONV_CERTS_DIR"))
		if startDir == "" {
			startDir = strings.TrimSpace(cfg.CertsDir)
		}
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
		fzfPanel:             newFZFPanel(),
		focused:              PaneFiles,
		autoMatchKey:         envBool("CERTCONV_AUTO_MATCH_KEY", cfg.AutoMatchKey),
		configPath:           cfgPath,
		themeName:            ThemeByName(themeName).Name,
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
		eagerViews:           envBool("CERTCONV_EAGER_VIEWS", cfg.EagerViews),
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

	case ContentParsedMsg:
		m.updateContentParsed(msg)
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

	case ToastMsg:
		m.toastText = msg.Text
		m.toastSticky = msg.Sticky
		m.statusMsg = msg.Text
		m.statusIsErr = false
		m.statusAutoClearOnNav = !msg.Sticky
		if msg.Sticky {
			return m, nil
		}
		return m, tea.Tick(1500*time.Millisecond, func(time.Time) tea.Msg {
			return ToastDismissMsg{}
		})

	case ToastDismissMsg:
		if m.toastSticky {
			return m, nil
		}
		m.toastText = ""
		return m, nil
	}

	return m, nil
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
			if msg.String() == "esc" {
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
			return m, m.copyToClipboardStatusCmd(m.opensslCommandText, "OpenSSL command")
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
		if m.selectedFile != "" {
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
		next.actionPanel.Toggle()
		return next, cmd

	case "u":
		m.showHelp = !m.showHelp
		if m.showHelp {
			m.focused = PaneContent
			m.helpPane.SetContent(m.helpText())
		}
		return m, nil

	case "o":
		cmd, err := m.opensslCommandForCurrentContext()
		if err != nil {
			m.statusMsg = "OpenSSL command unavailable: " + err.Error()
			m.statusIsErr = true
			m.statusAutoClearOnNav = true
			return m, nil
		}
		m.opensslCommandText = cmd
		m.toastText = "OpenSSL command:\n" + cmd + "\n\nEsc dismisses • " + m.keyCopy + " copies"
		m.toastSticky = true
		m.statusMsg = "OpenSSL command ready (" + m.keyCopy + " to copy, Esc to dismiss)"
		m.statusIsErr = false
		m.statusAutoClearOnNav = false
		return m, nil

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
		// Persist current theme to config.yml (optional; not done on plain theme cycling).
		return m, m.saveThemeCmd()
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

	if m.eagerViews {
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

func (m *Model) updateContentParsed(msg ContentParsedMsg) {
	if msg.Path == "" || msg.Path != m.selectedFile {
		return
	}
	if msg.Err != nil {
		m.contentPane.SetParsedError(msg.Err.Error())
		return
	}
	m.contentPane.SetParsed(msg.Text)
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

const autoMatchMaxCandidates = 10

func (m Model) autoMatchKeyCmd(certPath string) tea.Cmd {
	return func() tea.Msg {
		ctx := m.ctx()
		if err := ctx.Err(); err != nil {
			return AutoKeyMatchMsg{CertPath: certPath, Err: err}
		}

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
		attempts := 0
		for _, keyPath := range candidates {
			if err := ctx.Err(); err != nil {
				return AutoKeyMatchMsg{CertPath: certPath, Err: err}
			}
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

			if attempts >= autoMatchMaxCandidates {
				break
			}
			attempts++

			r, err := m.engine.MatchKeyToCert(ctx, certPath, keyPath, "")
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

		header := lipgloss.NewStyle().
			Foreground(activeBorder).
			Bold(true).
			Render(fmt.Sprintf("[3]-%s-  (z to unzoom)", title))
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

// overlayModal paints a floating panel in the center of the current screen.
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
	toast := lipgloss.NewStyle().
		Foreground(textColor).
		Background(bgColor).
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

type clipboardCmd struct {
	name string
	args []string
}

func clipboardCandidates() []clipboardCmd {
	return []clipboardCmd{
		{name: "pbcopy"},
		{name: "wl-copy"},
		{name: "xclip", args: []string{"-selection", "clipboard"}},
		{name: "xsel", args: []string{"--clipboard", "--input"}},
		// Windows / WSL.
		{name: "clip.exe"},
		{name: "clip"},
	}
}

func writeClipboard(text string) error {
	var chosen *clipboardCmd
	candidates := clipboardCandidates()
	for i := range candidates {
		if _, err := exec.LookPath(candidates[i].name); err == nil {
			chosen = &candidates[i]
			break
		}
	}
	if chosen == nil {
		var names []string
		for _, c := range candidates {
			names = append(names, c.name)
		}
		return fmt.Errorf("No clipboard tool found (tried: %s)", strings.Join(names, ", "))
	}
	cmd := exec.Command(chosen.name, chosen.args...)
	cmd.Stdin = strings.NewReader(text)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Failed to copy to clipboard: %w", err)
	}
	return nil
}

func (m Model) copyToClipboardStatusCmd(text string, label string) tea.Cmd {
	return func() tea.Msg {
		if strings.TrimSpace(text) == "" {
			return StatusMsg{Text: "Nothing to copy", IsErr: true}
		}
		if err := writeClipboard(text); err != nil {
			return StatusMsg{Text: err.Error(), IsErr: true}
		}
		return StatusMsg{Text: label + " copied to clipboard", IsErr: false}
	}
}

func (m Model) copyToClipboardCmd(text string, label string) tea.Cmd {
	return func() tea.Msg {
		if strings.TrimSpace(text) == "" {
			return StatusMsg{Text: "Nothing to copy", IsErr: true}
		}
		if err := writeClipboard(text); err != nil {
			return StatusMsg{Text: err.Error(), IsErr: true}
		}
		return ToastMsg{Text: label + " copied to clipboard"}
	}
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func (m Model) opensslPassInArg(path string) string {
	if pw, ok := m.pfxPasswords[path]; ok && pw == "" {
		return "pass:''"
	}
	return "pass:'<password>'"
}

func (m Model) opensslCommandForCurrentContext() (string, error) {
	path := strings.TrimSpace(m.selectedFile)
	if path == "" {
		path = strings.TrimSpace(m.filePane.CurrentFilePath())
	}
	if path == "" {
		return "", fmt.Errorf("select a file first")
	}

	ft := m.selectedType
	if ft == "" || ft == cert.FileTypeUnknown {
		detected, err := cert.DetectType(path)
		if err != nil {
			return "", err
		}
		ft = detected
	}

	switch m.focused {
	case PaneContent:
		return m.opensslCommandForContentMode(path, ft, m.contentPane.Mode())
	default:
		return m.opensslCommandForSummary(path, ft)
	}
}

func (m Model) opensslCommandForSummary(path string, ft cert.FileType) (string, error) {
	p := shellQuote(path)
	switch ft {
	case cert.FileTypeCert, cert.FileTypeCombined:
		return "openssl x509 -in " + p + " -noout -subject -issuer -dates -serial", nil
	case cert.FileTypeDER:
		return "openssl x509 -in " + p + " -inform DER -noout -subject -issuer -dates -serial", nil
	case cert.FileTypePFX:
		return "openssl pkcs12 -in " + p + " -nokeys -passin " + m.opensslPassInArg(path) + " | openssl x509 -noout -subject -issuer -dates -serial", nil
	default:
		return "", fmt.Errorf("no equivalent OpenSSL summary command for %s", ft)
	}
}

func (m Model) opensslDetailsBase(path string, ft cert.FileType) (string, error) {
	p := shellQuote(path)
	switch ft {
	case cert.FileTypeCert, cert.FileTypeCombined:
		return "openssl x509 -in " + p + " -text -noout", nil
	case cert.FileTypeDER:
		return "openssl x509 -in " + p + " -inform DER -text -noout", nil
	case cert.FileTypePFX:
		return "openssl pkcs12 -in " + p + " -nokeys -passin " + m.opensslPassInArg(path) + " | openssl x509 -text -noout", nil
	case cert.FileTypePublicKey:
		line, err := cert.ReadFirstNonEmptyLine(path)
		if err == nil && strings.HasPrefix(strings.TrimSpace(line), "ssh-") {
			return "", fmt.Errorf("OpenSSH public-key view has no direct OpenSSL equivalent")
		}
		return "openssl pkey -pubin -in " + p + " -text -noout", nil
	default:
		return "", fmt.Errorf("no equivalent OpenSSL details command for %s", ft)
	}
}

func (m Model) opensslModulusCommand(path string, ft cert.FileType) (string, error) {
	p := shellQuote(path)
	switch ft {
	case cert.FileTypeCert, cert.FileTypeCombined:
		return "openssl x509 -in " + p + " -noout -modulus", nil
	case cert.FileTypeDER:
		return "openssl x509 -in " + p + " -inform DER -noout -modulus", nil
	case cert.FileTypeKey:
		return "openssl rsa -in " + p + " -noout -modulus", nil
	case cert.FileTypePublicKey:
		line, err := cert.ReadFirstNonEmptyLine(path)
		if err == nil && strings.HasPrefix(strings.TrimSpace(line), "ssh-") {
			return "", fmt.Errorf("OpenSSH public-key modulus is not available via OpenSSL rsa -modulus")
		}
		return "openssl rsa -pubin -in " + p + " -noout -modulus", nil
	default:
		return "", fmt.Errorf("no equivalent OpenSSL modulus command for %s", ft)
	}
}

func (m Model) opensslCommandForContentMode(path string, ft cert.FileType, mode contentPaneMode) (string, error) {
	switch mode {
	case contentPaneModeDetails:
		return m.opensslDetailsBase(path, ft)
	case contentPaneModeDetailsNoBag:
		base, err := m.opensslDetailsBase(path, ft)
		if err != nil {
			return "", err
		}
		return base + " | awk 'BEGIN{skip=0} /^ *Bag Attributes$/{skip=1;next} skip && /^-----BEGIN /{skip=0} !skip {print}'", nil
	case contentPaneModeModulus:
		return m.opensslModulusCommand(path, ft)
	case contentPaneModeBase64:
		return "cat " + shellQuote(path) + " | openssl base64 -A", nil
	default:
		return "", fmt.Errorf("no direct OpenSSL command for %s view", mode.Title())
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
	// Parsed certificate view (Go crypto/x509 - no openssl).
	if m.selectedType == cert.FileTypeCert || m.selectedType == cert.FileTypeCombined || m.selectedType == cert.FileTypeDER || m.selectedType == cert.FileTypePFX {
		modes = append(modes, contentPaneModeParsed)
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
	case contentPaneModeParsed:
		if !m.contentPane.HasParsed() {
			m.contentPane.SetLoading()
			return m, m.loadContentParsed(m.selectedFile)
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
	var parts []string

	add := func(key, desc string) {
		parts = append(parts,
			statusKeyStyle.Render(key)+" "+statusDescStyle.Render(desc))
	}

	add("tab", "pane")
	add("1/2/3", "jump")
	add("a", "actions")
	add("f/@", "picker")
	add("o", "openssl")
	add("v", "view all/filter")
	add(m.keyNextView+"/"+m.keyPrevView+",h/l", "view")
	add("z", "zoom")
	add(m.resizeKeysHint(), "resize")
	add(m.keyCopy, "copy")
	add("t", "theme")
	add("u", "usage")
	add("q", "quit?")

	left := strings.Join(parts, "  ")

	// Theme is always shown on the right; ephemeral status message follows.
	rightParts := []string{
		statusDescStyle.Render("files: ") + statusKeyStyle.Render(m.fileFilterModeLabel()),
		statusDescStyle.Render("theme: ") + statusKeyStyle.Render(m.themeName),
	}
	if m.statusMsg != "" {
		if m.statusIsErr {
			rightParts = append(rightParts, errorStyle.Render(m.statusMsg))
		} else {
			rightParts = append(rightParts, successStyle.Render(m.statusMsg))
		}
	}
	right := strings.Join(rightParts, "  ")

	gap := m.width - lipgloss.Width(left) - lipgloss.Width(right) - 2
	if gap < 1 {
		gap = 1
	}

	return statusBarStyle.Render(left + strings.Repeat(" ", gap) + right)
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
				{key: "enter / l", desc: "Select / Open directory"},
				{key: "h", desc: "Parent directory"},
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
				{key: "a", desc: "Toggle action panel"},
				{key: "f / @", desc: "Open floating file picker (Enter opens dirs; Esc closes)"},
				{key: "o", desc: "Show equivalent OpenSSL command (Esc closes; c copies)"},
				{key: "t", desc: "Cycle theme (session)"},
				{key: "T", desc: "Save theme to config.yml"},
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
				{key: "theme", desc: "default, github-dark, github-dark-high-contrast"},
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

func (m Model) loadContentParsed(path string) tea.Cmd {
	return func() tea.Msg {
		text, err := renderParsedCert(path, m.pfxPassword(path), m.engine, m.ctx())
		if err != nil {
			return ContentParsedMsg{Path: path, Err: err}
		}
		return ContentParsedMsg{Path: path, Text: text}
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
