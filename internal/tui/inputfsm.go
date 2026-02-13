package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/nickromney/certconv/internal/cert"
)

// inputState holds the transient state for multi-step input prompts
// (e.g. password entry, file path entry for actions).
type inputState struct {
	mode    string // "" = none, "password", "text"
	prompt  string
	value   string
	note    string
	action  string            // which action triggered input
	context map[string]string // carries values between multi-step prompts
}

func (is *inputState) active() bool {
	return is.mode != ""
}

func (is *inputState) reset() {
	is.mode = ""
	is.action = ""
	is.context = nil
	is.note = ""
	is.value = ""
	is.prompt = ""
}

func (is *inputState) begin(mode, prompt, action string) {
	is.mode = mode
	is.prompt = prompt
	is.value = ""
	is.action = action
}

func (is *inputState) beginWithValue(mode, prompt, value, action string) {
	is.mode = mode
	is.prompt = prompt
	is.value = value
	is.action = action
}

// handleInputKey processes key presses when in input mode.
func (m Model) handleInputKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.input.reset()
		return m, nil

	case "enter":
		value := m.input.value
		action := m.input.action
		m.input.mode = ""
		m.input.note = ""
		return m.processInputResult(action, value)

	case "backspace":
		if len(m.input.value) > 0 {
			m.input.value = m.input.value[:len(m.input.value)-1]
		}
		return m, nil

	case "ctrl+u":
		m.input.value = ""
		return m, nil

	default:
		if len(msg.String()) == 1 || msg.String() == " " {
			m.input.value += msg.String()
		}
		return m, nil
	}
}

// handleAction processes an action selection and sets up input prompts.
func (m *Model) handleAction(id string) tea.Cmd {
	switch id {
	case "details":
		m.contentPane.SetMode(contentPaneModeDetails)
		m.contentPane.SetLoading()
		return m.loadContentDetails(m.selectedFile)

	case "expiry":
		m.input.beginWithValue("text", "Days threshold: ", "30", "expiry-days")
		return nil

	case "verify":
		m.input.begin("text", "CA bundle path: ", "verify")
		return nil

	case "match":
		m.input.begin("text", "Private key path: ", "match-key")
		m.input.context = map[string]string{}
		return nil

	case "to-pfx":
		m.input.begin("text", "Private key path: ", "to-pfx-key")
		m.input.context = map[string]string{}
		return nil

	case "from-pfx":
		base := strings.TrimSuffix(filepath.Base(m.selectedFile), filepath.Ext(m.selectedFile))
		defaultDir := filepath.Join(m.filePane.dir, base+"-extracted")
		for i := 1; ; i++ {
			if !pathExistsCheck(defaultDir) {
				break
			}
			defaultDir = filepath.Join(m.filePane.dir, fmt.Sprintf("%s-extracted-%d", base, i))
		}
		m.input.beginWithValue("text", "Output directory: ", filepath.Base(defaultDir), "from-pfx")
		m.input.context = map[string]string{}
		return nil

	case "to-der":
		base := strings.TrimSuffix(filepath.Base(m.selectedFile), filepath.Ext(m.selectedFile))
		suggest := cert.NextAvailablePath(filepath.Join(m.filePane.dir, base+".der"))
		m.input.beginWithValue("text", "Output file: ", filepath.Base(suggest), "to-der")
		return nil

	case "to-der-key":
		base := strings.TrimSuffix(filepath.Base(m.selectedFile), filepath.Ext(m.selectedFile))
		suggest := cert.NextAvailablePath(filepath.Join(m.filePane.dir, base+".der"))
		m.input.beginWithValue("text", "Output file: ", filepath.Base(suggest), "to-der-key-output")
		return nil

	case "from-der":
		base := strings.TrimSuffix(filepath.Base(m.selectedFile), filepath.Ext(m.selectedFile))
		suggest := cert.NextAvailablePath(filepath.Join(m.filePane.dir, base+".pem"))
		m.input.beginWithValue("text", "Output file: ", filepath.Base(suggest), "from-der")
		return nil

	case "to-base64":
		suggest := cert.NextAvailablePath(filepath.Join(m.filePane.dir, filepath.Base(m.selectedFile)+".b64"))
		m.input.beginWithValue("text", "Output file: ", filepath.Base(suggest), "to-base64")
		return nil

	case "from-base64":
		base := strings.TrimSuffix(filepath.Base(m.selectedFile), filepath.Ext(m.selectedFile))
		suggest := cert.NextAvailablePath(filepath.Join(m.filePane.dir, base+".decoded"))
		m.input.beginWithValue("text", "Output file: ", filepath.Base(suggest), "from-base64")
		return nil

	case "combine", "combine-key":
		if id == "combine-key" {
			m.input.begin("text", "Certificate path: ", "combine-cert-input")
		} else {
			m.input.begin("text", "Private key path: ", "combine-key-input")
		}
		m.input.context = map[string]string{}
		return nil
	}

	return nil
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
	case "expiry-days":
		daysText := strings.TrimSpace(value)
		days, err := strconv.Atoi(daysText)
		if err != nil || days < 0 {
			m.input.beginWithValue("text", "Days threshold: ", daysText, "expiry-days")
			m.input.note = "Enter a non-negative whole number"
			return m, nil
		}
		return m, func() tea.Msg {
			r, err := m.engine.Expiry(context.Background(), m.selectedFile, days)
			if err != nil {
				return ActionResultMsg{Message: err.Error(), Details: err.Error(), IsErr: true}
			}
			if r.Valid {
				msg := fmt.Sprintf("Valid for %d more days (expires %s)", r.DaysLeft, r.ExpiryDate)
				return ActionResultMsg{Message: msg, Details: msg}
			}
			msg := fmt.Sprintf("Expires within %d days! (%s)", days, r.ExpiryDate)
			return ActionResultMsg{Message: msg, Details: msg, IsErr: true}
		}

	case "pfx-view-password":
		path := ""
		if m.input.context != nil {
			path = m.input.context["path"]
		}
		m.input.context = nil
		if strings.TrimSpace(path) == "" {
			return m, nil
		}
		if m.pfxPasswords == nil {
			m.pfxPasswords = map[string]string{}
		}
		m.pfxPasswords[path] = value

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

	case "match-key":
		if m.input.context == nil {
			m.input.context = map[string]string{}
		}
		m.input.context["key"] = resolveInDir(value)
		m.input.begin("password", "Private key password (empty for none): ", "match-exec")
		return m, nil

	case "match-exec":
		keyPath := m.input.context["key"]
		m.input.context = nil
		keyPassword := value
		return m, func() tea.Msg {
			r, err := m.engine.MatchKeyToCert(context.Background(), m.selectedFile, keyPath, keyPassword)
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
		m.input.context["key"] = resolveInDir(value)
		base := strings.TrimSuffix(filepath.Base(m.selectedFile), filepath.Ext(m.selectedFile))
		m.input.beginWithValue("text", "Output PFX file: ",
			filepath.Base(cert.NextAvailablePath(filepath.Join(m.filePane.dir, base+".pfx"))),
			"to-pfx-output")
		return m, nil

	case "to-pfx-output":
		m.input.context["output"] = resolveInDir(value)
		m.input.begin("password", "Export password (empty for none): ", "to-pfx-password")
		return m, nil

	case "to-pfx-password":
		m.input.context["export_password"] = value
		m.input.begin("password", "Private key password (empty for none): ", "to-pfx-key-password")
		return m, nil

	case "to-pfx-key-password":
		m.input.context["key_password"] = value
		m.input.begin("text", "CA bundle path (optional): ", "to-pfx-exec")
		return m, nil

	case "to-pfx-exec":
		password := m.input.context["export_password"]
		keyPassword := m.input.context["key_password"]
		keyPath := m.input.context["key"]
		output := m.input.context["output"]
		caPath := ""
		if strings.TrimSpace(value) != "" {
			caPath = resolveInDir(value)
		}
		m.input.context = nil
		certPath := m.selectedFile
		return m, func() tea.Msg {
			if err := m.engine.ToPFX(context.Background(), certPath, keyPath, output, password, caPath, keyPassword); err != nil {
				return ActionResultMsg{Message: err.Error(), Details: err.Error(), IsErr: true}
			}
			msg := "Created: " + output
			return ActionResultMsg{Message: msg, Details: msg}
		}

	case "from-pfx":
		outDir := resolveInDir(value)
		m.input.context["outdir"] = outDir
		m.input.begin("password", "PFX password (empty for none): ", "from-pfx-exec")
		return m, nil

	case "from-pfx-exec":
		password := value
		outDir := m.input.context["outdir"]
		m.input.context = nil
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
			if err := m.engine.ToDER(context.Background(), certPath, output, false, ""); err != nil {
				return ActionResultMsg{Message: err.Error(), Details: err.Error(), IsErr: true}
			}
			msg := "Created: " + output
			return ActionResultMsg{Message: msg, Details: msg}
		}

	case "to-der-key-output":
		if m.input.context == nil {
			m.input.context = map[string]string{}
		}
		m.input.context["output"] = resolveInDir(value)
		m.input.begin("password", "Private key password (empty for none): ", "to-der-key-exec")
		return m, nil

	case "to-der-key-exec":
		output := m.input.context["output"]
		keyPath := m.selectedFile
		keyPassword := value
		m.input.context = nil
		return m, func() tea.Msg {
			if err := m.engine.ToDER(context.Background(), keyPath, output, true, keyPassword); err != nil {
				return ActionResultMsg{Message: err.Error(), Details: err.Error(), IsErr: true}
			}
			msg := "Created: " + output
			return ActionResultMsg{Message: msg, Details: msg}
		}

	case "from-der":
		if m.input.context == nil {
			m.input.context = map[string]string{}
		}
		m.input.context["output"] = resolveInDir(value)
		m.input.beginWithValue("text", "Input is private key? (y/N): ", "n", "from-der-key-flag")
		return m, nil

	case "from-der-key-flag":
		flagText := strings.TrimSpace(strings.ToLower(value))
		isKey := flagText == "y" || flagText == "yes" || flagText == "true" || flagText == "1"
		validFalse := flagText == "" || flagText == "n" || flagText == "no" || flagText == "false" || flagText == "0"
		if !isKey && !validFalse {
			m.input.beginWithValue("text", "Input is private key? (y/N): ", value, "from-der-key-flag")
			m.input.note = "Enter y/n"
			return m, nil
		}
		if isKey {
			m.input.context["is_key"] = "true"
			m.input.begin("password", "Private key password (empty for none): ", "from-der-exec")
			return m, nil
		}
		m.input.context["is_key"] = "false"
		return m.processInputResult("from-der-exec", "")

	case "from-der-exec":
		output := m.input.context["output"]
		derPath := m.selectedFile
		isKey := strings.EqualFold(m.input.context["is_key"], "true")
		keyPassword := value
		if !isKey {
			keyPassword = ""
		}
		m.input.context = nil
		return m, func() tea.Msg {
			if err := m.engine.FromDER(context.Background(), derPath, output, isKey, keyPassword); err != nil {
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
		m.input.context["key"] = resolveInDir(value)
		m.input.beginWithValue("text", "Output file: ",
			filepath.Base(cert.NextAvailablePath(filepath.Join(m.filePane.dir, "combined.pem"))),
			"combine-output")
		return m, nil

	case "combine-cert-input":
		m.input.context["cert"] = resolveInDir(value)
		m.input.beginWithValue("text", "Output file: ",
			filepath.Base(cert.NextAvailablePath(filepath.Join(m.filePane.dir, "combined.pem"))),
			"combine-output")
		return m, nil

	case "combine-output":
		if m.input.context == nil {
			m.input.context = map[string]string{}
		}
		m.input.context["output"] = resolveInDir(value)
		m.input.begin("password", "Private key password (empty for none): ", "combine-key-password")
		return m, nil

	case "combine-key-password":
		m.input.context["key_password"] = value
		m.input.begin("text", "CA bundle path (optional): ", "combine-exec")
		return m, nil

	case "combine-exec":
		output := m.input.context["output"]
		certPath := m.input.context["cert"]
		keyPath := m.input.context["key"]
		if certPath == "" {
			certPath = m.selectedFile
		}
		if keyPath == "" {
			keyPath = m.selectedFile
		}
		caPath := ""
		if strings.TrimSpace(value) != "" {
			caPath = resolveInDir(value)
		}
		keyPassword := m.input.context["key_password"]
		m.input.context = nil
		return m, func() tea.Msg {
			if err := m.engine.CombinePEM(context.Background(), certPath, keyPath, output, caPath, keyPassword); err != nil {
				return ActionResultMsg{Message: err.Error(), Details: err.Error(), IsErr: true}
			}
			msg := "Created: " + output
			return ActionResultMsg{Message: msg, Details: msg}
		}
	}

	return m, nil
}

// renderInput renders the input prompt bar.
func (m Model) renderInput() string {
	prompt := lipgloss.NewStyle().
		Foreground(accentColor).
		Bold(true).
		Render(m.input.prompt)

	note := ""
	if strings.TrimSpace(m.input.note) != "" {
		note = errorStyle.Render("["+strings.TrimSpace(m.input.note)+"]") + " "
	}

	cursor := lipgloss.NewStyle().
		Foreground(accentColor).
		Render("_")

	renderValue := m.input.value
	if m.input.mode == "password" {
		renderValue = strings.Repeat("*", len(m.input.value))
	}
	value := lipgloss.NewStyle().
		Foreground(textColor).
		Render(renderValue)

	return statusBarStyle.Render(prompt + note + value + cursor + "  " +
		lipgloss.NewStyle().Foreground(dimColor).Render("(enter to confirm, esc to cancel)"))
}

// pathExistsCheck is a simple existence check for input default suggestions.
func pathExistsCheck(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
