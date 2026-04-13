package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	initialSelection     string
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
	focusIndicatorMode   string

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
		focusIndicatorMode:   normalizeFocusIndicatorMode(envKey("CERTCONV_FOCUS_INDICATOR", cfg.FocusIndicator)),
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

func (m Model) WithInitialSelection(path string) Model {
	path = strings.TrimSpace(path)
	if path == "" {
		return m
	}
	m.initialSelection = path
	m.filePane.SelectFile(path)
	m.selectedFile = path
	return m
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

func normalizeFocusIndicatorMode(v string) string {
	switch strings.TrimSpace(strings.ToLower(v)) {
	case "color", "marker", "both":
		return strings.TrimSpace(strings.ToLower(v))
	default:
		return "color"
	}
}
