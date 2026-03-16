package tui

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nickromney/certconv/internal/cert"
)

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
		return fmt.Errorf("no clipboard tool found (tried: %s)", strings.Join(names, ", "))
	}
	cmd := exec.Command(chosen.name, chosen.args...)
	cmd.Stdin = strings.NewReader(text)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to copy to clipboard: %w", err)
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

func rawContentOutputCommand(path string) string {
	if _, err := exec.LookPath("bat"); err == nil {
		return "bat --plain --paging=never < " + shellQuote(path)
	}
	return "cat < " + shellQuote(path)
}

func oneLineOutputCommand(path string) string {
	if _, err := exec.LookPath("bat"); err == nil {
		return "bat --plain --paging=never < " + shellQuote(path) + " | tr -d '\\r\\n' && printf '\\n'"
	}
	return "tr -d '\\r\\n' < " + shellQuote(path) + " && printf '\\n'"
}

func (m Model) showOpenSSLCommand() (tea.Model, tea.Cmd) {
	cmd, err := m.opensslCommandForCurrentContext()
	if err != nil {
		m.opensslCommandText = ""
		m.toastText = "Output command unavailable:\n" + err.Error() + "\n\nEsc/o to close"
		m.toastSticky = true
		m.statusMsg = "Output command unavailable: " + err.Error()
		m.statusIsErr = true
		m.statusAutoClearOnNav = true
		return m, nil
	}

	m.opensslCommandText = cmd
	m.toastText = "Output command:\n" + cmd + "\n\nEsc/o to close   " + m.keyCopy + " to copy"
	m.toastSticky = true
	m.statusMsg = "Output command ready (" + m.keyCopy + " to copy, Esc/o to close)"
	m.statusIsErr = false
	m.statusAutoClearOnNav = false
	return m, nil
}

func (m *Model) syncOpenSSLToastForContext() {
	if !m.toastSticky || strings.TrimSpace(m.opensslCommandText) == "" {
		return
	}

	cmd, err := m.opensslCommandForCurrentContext()
	if err != nil {
		m.opensslCommandText = ""
		m.toastText = "Output command unavailable:\n" + err.Error() + "\n\nEsc/o to close"
		return
	}
	m.opensslCommandText = cmd
	m.toastText = "Output command:\n" + cmd + "\n\nEsc/o to close   " + m.keyCopy + " to copy"
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

	mode := m.contentPane.Mode()

	type resolver struct {
		name string
		fn   func() (string, error)
	}
	attempts := []resolver{
		{name: "content view", fn: func() (string, error) { return m.opensslCommandForContentMode(path, ft, mode) }},
		{name: "summary", fn: func() (string, error) { return m.opensslCommandForSummary(path, ft) }},
		{name: "details", fn: func() (string, error) { return m.opensslDetailsBase(path, ft) }},
	}

	var errs []string
	for _, r := range attempts {
		cmd, err := r.fn()
		if err == nil && strings.TrimSpace(cmd) != "" {
			return cmd, nil
		}
		if err != nil {
			errs = append(errs, r.name+": "+err.Error())
		}
	}
	return "", errors.New(strings.Join(errs, "; "))
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
	case cert.FileTypeKey:
		return "openssl pkey -in " + p + " -text -noout", nil
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
	case contentPaneModeContent:
		return rawContentOutputCommand(path), nil
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
	case contentPaneModeOneLine:
		return oneLineOutputCommand(path), nil
	case contentPaneModeBase64:
		return "openssl base64 -A < " + shellQuote(path) + " && printf '\\n'", nil
	case contentPaneModeDERBase64:
		switch ft {
		case cert.FileTypeCert, cert.FileTypeCombined:
			return "openssl x509 -in " + shellQuote(path) + " -outform DER | openssl base64 -A && printf '\\n'", nil
		case cert.FileTypeDER:
			return "openssl base64 -A < " + shellQuote(path) + " && printf '\\n'", nil
		default:
			return "", fmt.Errorf("no direct DER base64 OpenSSL command for %s", ft)
		}
	case contentPaneModePFXBase64:
		keyPath := strings.TrimSpace(m.autoMatchedKeyPath)
		if keyPath == "" {
			return "", fmt.Errorf("no matching key available for PFX base64 preview")
		}
		switch ft {
		case cert.FileTypeCert, cert.FileTypeCombined:
			return "openssl pkcs12 -export -inkey " + shellQuote(keyPath) +
				" -in " + shellQuote(path) +
				" -passout pass:'' | openssl base64 -A && printf '\\n'", nil
		default:
			return "", fmt.Errorf("no direct PFX base64 OpenSSL command for %s", ft)
		}
	case contentPaneModeParsed:
		return m.opensslDetailsBase(path, ft)
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
	m.syncOpenSSLToastForContext()

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
