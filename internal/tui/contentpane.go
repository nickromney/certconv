package tui

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type contentPaneMode int

const (
	contentPaneModeContent contentPaneMode = iota
	contentPaneModeDetails
	contentPaneModeDetailsNoBag
	contentPaneModeModulus
	contentPaneModeOneLine
	contentPaneModeBase64
	contentPaneModeDERBase64
	contentPaneModePFXBase64
	contentPaneModeParsed
	contentPaneModeCount // sentinel for wrapping
)

func (m contentPaneMode) Next() contentPaneMode {
	return (m + 1) % contentPaneModeCount
}

func (m contentPaneMode) Prev() contentPaneMode {
	return (m - 1 + contentPaneModeCount) % contentPaneModeCount
}

func (m contentPaneMode) Title() string {
	switch m {
	case contentPaneModeContent:
		return "Content"
	case contentPaneModeDetails:
		return "Details"
	case contentPaneModeDetailsNoBag:
		return "Details (No Bag Attributes)"
	case contentPaneModeModulus:
		return "RSA Modulus"
	case contentPaneModeOneLine:
		return "Content (One Line)"
	case contentPaneModeBase64:
		return "Content (Base64)"
	case contentPaneModeDERBase64:
		return "DER (Base64)"
	case contentPaneModePFXBase64:
		return "PFX (Base64)"
	case contentPaneModeParsed:
		return "Parsed Certificate"
	default:
		return "?"
	}
}

// contentPane is the bottom-right pane. It cycles between raw content,
// certificate details (with chain when possible), and alternative encodings.
type contentPane struct {
	viewport viewport.Model
	width    int
	height   int

	mode contentPaneMode

	// Content view
	contentTitle string
	contentText  string

	// Details view
	detailsText      string
	detailsNoBagText string

	// Alternative encodings
	modulusText              string
	modulusErr               string
	oneLineText              string
	oneLineAlreadySingleLine bool
	oneLineWrapWidth         int
	base64Text               string
	derBase64Text            string
	pfxBase64Text            string
	parsedText               string
	parsedErr                string
	oneLineErr               string
	base64Err                string
	derBase64Err             string
	pfxBase64Err             string

	// Last action output is shown in Details mode.
	lastActionText  string
	lastActionIsErr bool

	loading bool
}

func newContentPane(oneLineWrapWidth int) contentPane {
	vp := viewport.New(0, 0)
	vp.SetContent("Select a file to view its content")
	if oneLineWrapWidth <= 0 {
		oneLineWrapWidth = 64
	}
	return contentPane{
		viewport:         vp,
		mode:             contentPaneModeContent,
		contentTitle:     "Content",
		contentText:      "Select a file to view its content",
		detailsText:      "",
		oneLineText:      "",
		base64Text:       "",
		oneLineWrapWidth: oneLineWrapWidth,
		loading:          false,
	}
}

func (cp *contentPane) BorderTitle() string {
	return cp.titleText()
}

func (cp *contentPane) SetSize(w, h int) {
	cp.width = w
	cp.height = h
	if w < 0 {
		w = 0
	}
	if h < 0 {
		h = 0
	}
	cp.viewport.Width = w
	cp.viewport.Height = h
}

func (cp *contentPane) Mode() contentPaneMode {
	return cp.mode
}

func (cp *contentPane) SetMode(mode contentPaneMode) {
	if cp.mode == mode {
		return
	}
	cp.mode = mode
	cp.refreshViewport(true)
}

func (cp *contentPane) ResetForFile() {
	cp.detailsText = ""
	cp.detailsNoBagText = ""
	cp.modulusText = ""
	cp.modulusErr = ""
	cp.parsedText = ""
	cp.parsedErr = ""
	cp.oneLineText = ""
	cp.base64Text = ""
	cp.derBase64Text = ""
	cp.pfxBase64Text = ""
	cp.oneLineErr = ""
	cp.base64Err = ""
	cp.derBase64Err = ""
	cp.pfxBase64Err = ""
	cp.lastActionText = ""
	cp.lastActionIsErr = false
}

func (cp *contentPane) HasDetails() bool {
	return strings.TrimSpace(cp.detailsText) != ""
}

func (cp *contentPane) HasModulus() bool {
	return strings.TrimSpace(cp.modulusText) != "" || strings.TrimSpace(cp.modulusErr) != ""
}

func (cp *contentPane) HasOneLine() bool {
	return strings.TrimSpace(cp.oneLineText) != "" || strings.TrimSpace(cp.oneLineErr) != ""
}

func (cp *contentPane) HasBase64() bool {
	return strings.TrimSpace(cp.base64Text) != "" || strings.TrimSpace(cp.base64Err) != ""
}

func (cp *contentPane) HasDERBase64() bool {
	return strings.TrimSpace(cp.derBase64Text) != "" || strings.TrimSpace(cp.derBase64Err) != ""
}

func (cp *contentPane) HasPFXBase64() bool {
	return strings.TrimSpace(cp.pfxBase64Text) != "" || strings.TrimSpace(cp.pfxBase64Err) != ""
}

func (cp *contentPane) SetContent(title, content string) {
	cp.contentTitle = title
	cp.contentText = content
	cp.loading = false
	if cp.mode == contentPaneModeContent {
		cp.refreshViewport(true)
	}
}

func (cp *contentPane) SetDetails(text string) {
	cp.detailsText = text
	cp.detailsNoBagText = stripBagAttributes(text)
	cp.loading = false
	if cp.mode == contentPaneModeDetails || cp.mode == contentPaneModeDetailsNoBag {
		cp.refreshViewport(true)
	}
}

func (cp *contentPane) SetModulus(text string) {
	cp.modulusText = text
	cp.modulusErr = ""
	cp.loading = false
	if cp.mode == contentPaneModeModulus {
		cp.refreshViewport(true)
	}
}

func (cp *contentPane) HasParsed() bool {
	return strings.TrimSpace(cp.parsedText) != "" || strings.TrimSpace(cp.parsedErr) != ""
}

func (cp *contentPane) SetParsed(text string) {
	cp.parsedText = text
	cp.parsedErr = ""
	cp.loading = false
	if cp.mode == contentPaneModeParsed {
		cp.refreshViewport(true)
	}
}

func (cp *contentPane) SetParsedError(err string) {
	cp.parsedText = ""
	cp.parsedErr = err
	cp.loading = false
	if cp.mode == contentPaneModeParsed {
		cp.refreshViewport(true)
	}
}

func (cp *contentPane) SetModulusError(err string) {
	cp.modulusText = ""
	cp.modulusErr = err
	cp.loading = false
	if cp.mode == contentPaneModeModulus {
		cp.refreshViewport(true)
	}
}

func (cp *contentPane) SetOneLine(text string) {
	cp.oneLineText = text
	cp.oneLineAlreadySingleLine = false
	cp.oneLineErr = ""
	cp.loading = false
	if cp.mode == contentPaneModeOneLine {
		cp.refreshViewport(true)
	}
}

func (cp *contentPane) SetOneLineWithMeta(text string, alreadySingleLine bool) {
	cp.oneLineText = text
	cp.oneLineAlreadySingleLine = alreadySingleLine
	cp.oneLineErr = ""
	cp.loading = false
	if cp.mode == contentPaneModeOneLine {
		cp.refreshViewport(true)
	}
}

func (cp *contentPane) SetOneLineError(err string) {
	cp.oneLineText = ""
	cp.oneLineAlreadySingleLine = false
	cp.oneLineErr = err
	cp.loading = false
	if cp.mode == contentPaneModeOneLine {
		cp.refreshViewport(true)
	}
}

func (cp *contentPane) SetBase64(text string) {
	cp.base64Text = text
	cp.base64Err = ""
	cp.loading = false
	if cp.mode == contentPaneModeBase64 {
		cp.refreshViewport(true)
	}
}

func (cp *contentPane) SetBase64Error(err string) {
	cp.base64Text = ""
	cp.base64Err = err
	cp.loading = false
	if cp.mode == contentPaneModeBase64 {
		cp.refreshViewport(true)
	}
}

func (cp *contentPane) SetDERBase64(text string) {
	cp.derBase64Text = text
	cp.derBase64Err = ""
	cp.loading = false
	if cp.mode == contentPaneModeDERBase64 {
		cp.refreshViewport(true)
	}
}

func (cp *contentPane) SetDERBase64Error(err string) {
	cp.derBase64Text = ""
	cp.derBase64Err = err
	cp.loading = false
	if cp.mode == contentPaneModeDERBase64 {
		cp.refreshViewport(true)
	}
}

func (cp *contentPane) SetPFXBase64(text string) {
	cp.pfxBase64Text = text
	cp.pfxBase64Err = ""
	cp.loading = false
	if cp.mode == contentPaneModePFXBase64 {
		cp.refreshViewport(true)
	}
}

func (cp *contentPane) SetPFXBase64Error(err string) {
	cp.pfxBase64Text = ""
	cp.pfxBase64Err = err
	cp.loading = false
	if cp.mode == contentPaneModePFXBase64 {
		cp.refreshViewport(true)
	}
}

func (cp *contentPane) SetLastAction(text string, isErr bool) {
	cp.lastActionText = text
	cp.lastActionIsErr = isErr
	if cp.mode == contentPaneModeDetails || cp.mode == contentPaneModeDetailsNoBag {
		cp.refreshViewport(false)
	}
}

func (cp *contentPane) SetLoading() {
	cp.loading = true
	cp.refreshViewport(false)
}

func (cp *contentPane) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "j", "down":
			cp.viewport.LineDown(1)
		case "k", "up":
			cp.viewport.LineUp(1)
		case "ctrl+d":
			cp.viewport.HalfViewDown()
		case "ctrl+u":
			cp.viewport.HalfViewUp()
		case "pgdown":
			cp.viewport.ViewDown()
		case "pgup":
			cp.viewport.ViewUp()
		case "G":
			cp.viewport.GotoBottom()
		case "g":
			cp.viewport.GotoTop()
		default:
			cp.viewport, cmd = cp.viewport.Update(msg)
		}
	default:
		cp.viewport, cmd = cp.viewport.Update(msg)
	}
	return cmd
}

func (cp *contentPane) View(focused bool) string {
	_ = focused // borders/labels are handled by the grid renderer.
	view := cp.viewport.View()
	// Apply paneTextColor to lines that don't already carry ANSI styling.
	// This gives high-contrast themes correct coloring on plain-text lines
	// (PEM, base64, openssl output) while preserving intentional styling on
	// lines that use lipgloss (dim notes, error messages).
	lines := strings.Split(view, "\n")
	for i, line := range lines {
		if !strings.Contains(line, "\x1b[") {
			lines[i] = lipgloss.NewStyle().Foreground(paneTextColor).Render(line)
		}
	}
	view = strings.Join(lines, "\n")
	return lipgloss.NewStyle().Width(cp.width).Height(cp.height).Render(view)
}

func (cp *contentPane) HasBagAttributes() bool {
	if strings.TrimSpace(cp.detailsText) == "" {
		return false
	}
	// Only expose the "no bag" view when it actually changes output.
	if !strings.Contains(cp.detailsText, "Bag Attributes") {
		return false
	}
	return cp.detailsNoBagText != cp.detailsText
}

func (cp *contentPane) CanCopy() bool {
	if cp.loading {
		return false
	}

	switch cp.mode {
	case contentPaneModeContent:
		return strings.TrimSpace(cp.contentText) != ""
	case contentPaneModeDetails:
		return strings.TrimSpace(cp.detailsText) != "" || strings.TrimSpace(cp.lastActionText) != ""
	case contentPaneModeDetailsNoBag:
		return strings.TrimSpace(cp.detailsNoBagText) != "" || strings.TrimSpace(cp.lastActionText) != ""
	case contentPaneModeModulus:
		return strings.TrimSpace(cp.modulusText) != ""
	case contentPaneModeParsed:
		return strings.TrimSpace(cp.parsedText) != ""
	case contentPaneModeOneLine:
		return strings.TrimSpace(cp.oneLineText) != ""
	case contentPaneModeBase64:
		return strings.TrimSpace(cp.base64Text) != ""
	case contentPaneModeDERBase64:
		return strings.TrimSpace(cp.derBase64Text) != ""
	case contentPaneModePFXBase64:
		return strings.TrimSpace(cp.pfxBase64Text) != ""
	default:
		return false
	}
}

func (cp *contentPane) CopyText() string {
	switch cp.mode {
	case contentPaneModeContent:
		return cp.contentText
	case contentPaneModeDetails:
		return cp.detailsCopyText(cp.detailsText)
	case contentPaneModeDetailsNoBag:
		return cp.detailsCopyText(cp.detailsNoBagText)
	case contentPaneModeModulus:
		return cp.modulusText
	case contentPaneModeParsed:
		return cp.parsedText
	case contentPaneModeOneLine:
		return cp.oneLineText
	case contentPaneModeBase64:
		return cp.base64Text
	case contentPaneModeDERBase64:
		return cp.derBase64Text
	case contentPaneModePFXBase64:
		return cp.pfxBase64Text
	default:
		return ""
	}
}

func (cp *contentPane) detailsCopyText(details string) string {
	details = strings.TrimRight(details, "\n")
	last := strings.TrimSpace(cp.lastActionText)
	if last == "" {
		return details
	}
	if details == "" {
		return "Last action:\n" + cp.lastActionText
	}
	return details + "\n\nLast action:\n" + cp.lastActionText
}

// CopyLabel returns a human-readable description for toast messages
// when the current view is copied to the clipboard.
func (m contentPaneMode) CopyLabel() string {
	switch m {
	case contentPaneModeContent:
		return "File content"
	case contentPaneModeDetails:
		return "Details"
	case contentPaneModeDetailsNoBag:
		return "Details (no bag attributes)"
	case contentPaneModeModulus:
		return "RSA modulus"
	case contentPaneModeOneLine:
		return "One-line content"
	case contentPaneModeBase64:
		return "Base64"
	case contentPaneModeDERBase64:
		return "DER base64"
	case contentPaneModePFXBase64:
		return "PFX base64"
	case contentPaneModeParsed:
		return "Parsed certificate"
	default:
		return "Content"
	}
}

func (cp *contentPane) titleText() string {
	title := cp.mode.Title()
	if cp.contentTitle != "" {
		return title + " [" + cp.contentTitle + "]"
	}
	return title
}

func (cp *contentPane) refreshViewport(resetScroll bool) {
	if cp.loading {
		cp.viewport.SetContent(lipgloss.NewStyle().Foreground(paneDimColor).Render("Loading..."))
		if resetScroll {
			cp.viewport.GotoTop()
		}
		return
	}

	var text string
	switch cp.mode {
	case contentPaneModeContent:
		text = cp.contentText
	case contentPaneModeDetails:
		text = cp.detailsViewText(cp.detailsText)
	case contentPaneModeDetailsNoBag:
		text = cp.detailsViewText(cp.detailsNoBagText)
	case contentPaneModeModulus:
		if strings.TrimSpace(cp.modulusErr) != "" {
			text = errorStyle.Render(cp.modulusErr)
		} else if strings.TrimSpace(cp.modulusText) == "" {
			text = lipgloss.NewStyle().Foreground(paneDimColor).Render("Not generated. Cycle views to generate.")
		} else {
			text = cp.modulusText
		}
	case contentPaneModeParsed:
		if strings.TrimSpace(cp.parsedErr) != "" {
			text = errorStyle.Render(cp.parsedErr)
		} else if strings.TrimSpace(cp.parsedText) == "" {
			text = lipgloss.NewStyle().Foreground(paneDimColor).Render("Not generated. Cycle views to generate.")
		} else {
			text = cp.parsedText
		}
	case contentPaneModeOneLine:
		if strings.TrimSpace(cp.oneLineErr) != "" {
			text = errorStyle.Render(cp.oneLineErr)
		} else if strings.TrimSpace(cp.oneLineText) == "" {
			text = lipgloss.NewStyle().Foreground(paneDimColor).Render("Not generated. Cycle views to generate.")
		} else if cp.oneLineAlreadySingleLine {
			// If the file is already one line, show a wrapped view for readability.
			// Copy still uses the exact single-line string.
			wrapped := wrapFixed(cp.oneLineText, cp.oneLineWrapWidth)
			note := lipgloss.NewStyle().Foreground(paneDimColor).Render(
				"Already single-line; wrapped to " + strconv.Itoa(cp.oneLineWrapWidth) + " columns for display. Copy keeps the single line.",
			)
			text = wrapped + "\n\n" + note
		} else {
			text = cp.oneLineText
		}
	case contentPaneModeBase64:
		if strings.TrimSpace(cp.base64Err) != "" {
			text = errorStyle.Render(cp.base64Err)
		} else if strings.TrimSpace(cp.base64Text) == "" {
			text = lipgloss.NewStyle().Foreground(paneDimColor).Render("Not generated. Cycle views to generate.")
		} else {
			text = cp.wrappedBase64View(cp.base64Text, "Wrapped for display. Copy keeps a single line.")
		}
	case contentPaneModeDERBase64:
		if strings.TrimSpace(cp.derBase64Err) != "" {
			text = errorStyle.Render(cp.derBase64Err)
		} else if strings.TrimSpace(cp.derBase64Text) == "" {
			text = lipgloss.NewStyle().Foreground(paneDimColor).Render("Not generated. Cycle views to generate.")
		} else {
			text = cp.wrappedBase64View(cp.derBase64Text, "DER preview. Wrapped for display; copy keeps a single line.")
		}
	case contentPaneModePFXBase64:
		if strings.TrimSpace(cp.pfxBase64Err) != "" {
			text = errorStyle.Render(cp.pfxBase64Err)
		} else if strings.TrimSpace(cp.pfxBase64Text) == "" {
			text = lipgloss.NewStyle().Foreground(paneDimColor).Render("Not generated. Cycle views to generate.")
		} else {
			text = cp.wrappedBase64View(cp.pfxBase64Text, "PFX preview (export password: empty). Wrapped for display; copy keeps a single line.")
		}
	default:
		text = ""
	}

	cp.viewport.SetContent(text)
	if resetScroll {
		cp.viewport.GotoTop()
	}
}

func (cp *contentPane) wrappedBase64View(s string, note string) string {
	w := cp.oneLineWrapWidth
	if w <= 0 {
		w = 64
	}
	wrapped := wrapFixed(s, w)
	if strings.TrimSpace(note) == "" {
		return wrapped
	}
	n := lipgloss.NewStyle().Foreground(paneDimColor).Render(note)
	return wrapped + "\n\n" + n
}

func (cp *contentPane) detailsViewText(details string) string {
	if strings.TrimSpace(details) == "" {
		return lipgloss.NewStyle().Foreground(paneDimColor).Render("No details loaded. Cycle views to load details.")
	}

	text := details
	if strings.TrimSpace(cp.lastActionText) == "" {
		return text
	}

	sep := "\n\n" + lipgloss.NewStyle().Foreground(paneDimColor).Render("Last action:") + "\n"
	if cp.lastActionIsErr {
		return text + sep + errorStyle.Render(cp.lastActionText)
	}
	return text + sep + cp.lastActionText
}

func wrapFixed(s string, width int) string {
	if width <= 0 || s == "" {
		return s
	}

	// Note: this is for base64-ish content; we keep it byte-based for simplicity.
	var b strings.Builder
	for i := 0; i < len(s); i += width {
		end := i + width
		if end > len(s) {
			end = len(s)
		}
		b.WriteString(s[i:end])
		if end < len(s) {
			b.WriteByte('\n')
		}
	}
	return b.String()
}
