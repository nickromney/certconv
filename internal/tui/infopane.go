package tui

import (
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

	var lines []string

	addKV := func(key, value string) {
		if value == "" {
			return
		}
		k := infoKeyStyle.Render(key + ":")
		v := infoValueStyle.Render(" " + value)
		lines = append(lines, k+v)
	}

	addKV("Type", string(s.FileType))
	lines = append(lines, "")

	if s.FileType == cert.FileTypeKey {
		addKV("Key Type", string(s.KeyType))
	} else if s.FileType == cert.FileTypePublicKey {
		if strings.TrimSpace(s.PublicKeyAlgorithm) != "" {
			addKV("Key Type", s.PublicKeyAlgorithm)
		} else {
			addKV("Key Type", "Public key")
		}
		if strings.TrimSpace(s.PublicKeyComment) != "" {
			addKV("Comment", s.PublicKeyComment)
		}
	} else {
		addKV("Subject", s.Subject)
		addKV("Issuer", s.Issuer)
		if len(s.SANs) > 0 {
			addKV("SANs", cert.FormatSANsShort(s.SANs))
		}
		lines = append(lines, "")
		addKV("Not Before", s.NotBefore)
		addKV("Not After", s.NotAfter)
		lines = append(lines, "")
		addKV("Serial", s.Serial)
		if s.PublicKeyInfo != "" {
			addKV("Public Key", s.PublicKeyInfo)
		}
		if s.SignatureAlgorithm != "" {
			addKV("Sig Algo", s.SignatureAlgorithm)
		}
		if s.IsCA {
			addKV("CA", "Yes")
		}
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
