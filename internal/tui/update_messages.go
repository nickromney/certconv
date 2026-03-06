package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nickromney/certconv/internal/cert"
)

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
	m.selectedType = cert.FileTypeUnknown
	m.autoMatchedKeyPath = ""
	m.statusMsg = ""
	m.infoPane.SetAutoKeyStatus("")
	m.contentPane.ResetForFile()
	m.contentPane.SetMode(contentPaneModeContent)
	m.contentPane.SetLoading()
	m.infoPane.SetLoading()
	m.syncOpenSSLToastForContext()

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
			m.syncOpenSSLToastForContext()
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
	m.syncOpenSSLToastForContext()

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
	switch msg.ID {
	case "expiry", "match", "verify":
		return m, m.handleAction(msg.ID)
	default:
		m.statusMsg = "TUI write actions are disabled (read-only mode)"
		m.statusIsErr = true
		m.statusAutoClearOnNav = true
		return m, nil
	}
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
