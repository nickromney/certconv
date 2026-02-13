package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/nickromney/certconv/internal/cert"
)

// infoPane shows parsed cert properties (summary only).
type infoPane struct {
	viewport      viewport.Model
	width         int
	height        int
	summary       *cert.CertSummary
	autoKeyStatus string
	loading       bool
	errText       string
	inlineErrText string
}

func newInfoPane() infoPane {
	vp := viewport.New(0, 0)
	vp.SetContent("Select a file to view its properties")
	return infoPane{viewport: vp}
}

func (ip *infoPane) SetSize(w, h int) {
	ip.width = w
	ip.height = h
	if w < 0 {
		w = 0
	}
	if h < 0 {
		h = 0
	}
	ip.viewport.Width = w
	ip.viewport.Height = h
}

func (ip *infoPane) SetSummary(s *cert.CertSummary) {
	ip.summary = s
	ip.loading = false
	ip.errText = ""
	ip.inlineErrText = ""
	ip.viewport.SetContent(ip.renderSummary())
	ip.viewport.GotoTop()
}

func (ip *infoPane) SetSummaryWithInlineError(s *cert.CertSummary, inlineErr string) {
	ip.summary = s
	ip.loading = false
	ip.errText = ""
	ip.inlineErrText = strings.TrimSpace(inlineErr)
	ip.viewport.SetContent(ip.renderSummary())
	ip.viewport.GotoTop()
}

func (ip *infoPane) SetAutoKeyStatus(status string) {
	ip.autoKeyStatus = status
	// Re-render if we already have summary content; otherwise it will show once
	// summary is loaded.
	ip.viewport.SetContent(ip.renderSummary())
}

func (ip *infoPane) SetError(err string) {
	ip.summary = nil
	ip.loading = false
	ip.errText = err
	ip.inlineErrText = ""
	ip.viewport.SetContent(errorStyle.Render(err))
	ip.viewport.GotoTop()
}

func (ip *infoPane) SetLoading() {
	ip.loading = true
	ip.errText = ""
	ip.inlineErrText = ""
	ip.viewport.SetContent(lipgloss.NewStyle().Foreground(paneDimColor).Render("Loading..."))
	ip.viewport.GotoTop()
}

// CanCopy returns true when the summary pane has copyable content.
func (ip *infoPane) CanCopy() bool {
	return ip.summary != nil
}

// CopyText returns a plain-text version of the summary for clipboard use.
func (ip *infoPane) CopyText() string {
	return ip.renderPlainSummary()
}

// renderPlainSummary produces an unstyled, aligned text version of the summary
// suitable for copying to the clipboard.
func (ip *infoPane) renderPlainSummary() string {
	s := ip.summary
	if s == nil {
		return ""
	}

	kvs := ip.summaryKVs()
	colW := kvColumnWidth(kvs)

	var lines []string
	for _, kv := range kvs {
		if kv.key == "" {
			lines = append(lines, "")
			continue
		}
		lines = append(lines, fmt.Sprintf("%-*s  %s", colW, kv.key+":", kv.value))
	}

	if strings.TrimSpace(ip.autoKeyStatus) != "" {
		lines = append(lines, "")
		lines = append(lines, ip.autoKeyStatus)
	}

	return strings.Join(lines, "\n")
}

type summaryKV struct {
	key   string
	value string
}

// summaryKVs collects the key-value pairs for the current summary. Empty-key
// entries represent blank separator lines.
func (ip *infoPane) summaryKVs() []summaryKV {
	s := ip.summary
	if s == nil {
		return nil
	}

	var kvs []summaryKV
	add := func(key, value string) {
		if value == "" {
			return
		}
		kvs = append(kvs, summaryKV{key: key, value: value})
	}
	sep := func() { kvs = append(kvs, summaryKV{}) }

	add("Type", string(s.FileType))
	sep()

	if s.FileType == cert.FileTypeKey {
		add("Key Type", string(s.KeyType))
	} else if s.FileType == cert.FileTypePublicKey {
		if strings.TrimSpace(s.PublicKeyAlgorithm) != "" {
			add("Key Type", s.PublicKeyAlgorithm)
		} else {
			add("Key Type", "Public key")
		}
		if strings.TrimSpace(s.PublicKeyComment) != "" {
			add("Comment", s.PublicKeyComment)
		}
	} else {
		add("Subject", s.Subject)
		add("Issuer", s.Issuer)
		if len(s.SANs) > 0 {
			add("SANs", cert.FormatSANsShort(s.SANs))
		}
		sep()
		add("Not Before", s.NotBefore)
		add("Not After", s.NotAfter)
		sep()
		add("Serial", s.Serial)
		if s.PublicKeyInfo != "" {
			add("Public Key", s.PublicKeyInfo)
		}
		if s.SignatureAlgorithm != "" {
			add("Sig Algo", s.SignatureAlgorithm)
		}
		if s.IsCA {
			add("CA", "Yes")
		}
	}

	return kvs
}

// kvColumnWidth returns the width of the longest key (plus colon) across all entries.
func kvColumnWidth(kvs []summaryKV) int {
	w := 0
	for _, kv := range kvs {
		if kv.key == "" {
			continue
		}
		if n := len(kv.key) + 1; n > w { // +1 for the colon
			w = n
		}
	}
	return w
}

func (ip *infoPane) renderSummary() string {
	s := ip.summary
	if s == nil {
		if ip.loading {
			return "Loading..."
		}
		if ip.errText != "" {
			return ip.errText
		}
		return "No data"
	}

	kvs := ip.summaryKVs()
	colW := kvColumnWidth(kvs)

	var lines []string
	for _, kv := range kvs {
		if kv.key == "" {
			lines = append(lines, "")
			continue
		}
		label := fmt.Sprintf("%-*s", colW, kv.key+":")
		k := infoKeyStyle.Render(label)
		v := infoValueStyle.Render("  " + kv.value)
		lines = append(lines, k+v)
	}

	if strings.TrimSpace(ip.autoKeyStatus) != "" {
		lines = append(lines, "")
		lines = append(lines, infoValueStyle.Render(ip.autoKeyStatus))
	}

	if strings.TrimSpace(ip.inlineErrText) != "" {
		lines = append(lines, "")
		lines = append(lines, errorStyle.Render(ip.inlineErrText))
	}

	lines = append(lines, "")
	lines = append(lines, lipgloss.NewStyle().Foreground(paneDimColor).Render("Press ? for actions"))

	return strings.Join(lines, "\n")
}

func (ip *infoPane) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "j", "down":
			ip.viewport.LineDown(1)
		case "k", "up":
			ip.viewport.LineUp(1)
		case "ctrl+d":
			ip.viewport.HalfViewDown()
		case "ctrl+u":
			ip.viewport.HalfViewUp()
		case "pgdown":
			ip.viewport.ViewDown()
		case "pgup":
			ip.viewport.ViewUp()
		case "G":
			ip.viewport.GotoBottom()
		case "g":
			ip.viewport.GotoTop()
		default:
			ip.viewport, cmd = ip.viewport.Update(msg)
		}
	default:
		ip.viewport, cmd = ip.viewport.Update(msg)
	}
	return cmd
}

func (ip *infoPane) View(focused bool) string {
	_ = focused // borders/labels are handled by the grid renderer.
	return lipgloss.NewStyle().Width(ip.width).Height(ip.height).Render(ip.viewport.View())
}
