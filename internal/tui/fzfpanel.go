package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type pickerEntry struct {
	name  string
	path  string
	isDir bool
}

var pickerFileExtensions = map[string]bool{
	".pem": true,
	".der": true,
	".pfx": true,
	".p12": true,
	".cer": true,
	".crt": true,
	".key": true,
	".pub": true,
	".b64": true,
}

// fzfPanel is an in-app floating picker with basic fzf-like filtering.
// It behaves as a directory browser: Enter opens directories, or selects files.
type fzfPanel struct {
	visible bool
	rootDir string
	query   string
	all     []pickerEntry
	filter  []pickerEntry
	cursor  int
	offset  int
	errText string
}

func newFZFPanel() fzfPanel {
	return fzfPanel{}
}

func (p *fzfPanel) Open(rootDir string) {
	p.visible = true
	p.openDir(rootDir)
}

func (p *fzfPanel) Hide() {
	p.visible = false
}

func (p *fzfPanel) openDir(rootDir string) {
	rootDir = strings.TrimSpace(rootDir)
	if rootDir == "" {
		rootDir = "."
	}
	if abs, err := filepath.Abs(rootDir); err == nil {
		rootDir = abs
	}

	p.rootDir = rootDir
	p.query = ""
	p.cursor = 0
	p.offset = 0
	p.errText = ""
	p.all = nil
	p.filter = nil

	entries, err := listPickerEntries(rootDir)
	if err != nil {
		p.errText = err.Error()
	}
	p.all = entries
	p.applyFilter()
}

func (p *fzfPanel) goParent() {
	if strings.TrimSpace(p.rootDir) == "" {
		return
	}
	parent := filepath.Dir(p.rootDir)
	if parent == p.rootDir {
		return
	}
	p.openDir(parent)
}

func (p *fzfPanel) applyFilter() {
	q := strings.ToLower(strings.TrimSpace(p.query))
	p.filter = p.filter[:0]

	if q == "" {
		p.filter = append(p.filter, p.all...)
	} else {
		for _, e := range p.all {
			// Always keep the parent entry visible so the user can navigate
			// up without having to clear the query first.
			if e.name == "../" {
				p.filter = append(p.filter, e)
				continue
			}
			if strings.Contains(strings.ToLower(e.name), q) || strings.Contains(strings.ToLower(e.path), q) {
				p.filter = append(p.filter, e)
			}
		}
	}

	if len(p.filter) == 0 {
		p.cursor = 0
		p.offset = 0
		return
	}

	// When a query is active, the pinned ../ entry is at index 0 but should
	// not be the default cursor target — skip to the first file match so
	// pressing Enter immediately selects a file rather than navigating up.
	firstSelectable := 0
	if q != "" && len(p.filter) > 0 && p.filter[0].name == "../" {
		firstSelectable = 1
	}
	if p.cursor < firstSelectable {
		p.cursor = firstSelectable
	}
	if p.cursor >= len(p.filter) {
		p.cursor = len(p.filter) - 1
	}
	if p.cursor < 0 {
		p.cursor = 0
	}
	if p.offset > p.cursor {
		p.offset = p.cursor
	}
	if p.offset < 0 {
		p.offset = 0
	}
}

func (p *fzfPanel) ensureVisible(listHeight int) {
	if listHeight < 1 {
		listHeight = 1
	}
	if p.cursor < p.offset {
		p.offset = p.cursor
	}
	if p.cursor >= p.offset+listHeight {
		p.offset = p.cursor - listHeight + 1
	}
	if p.offset < 0 {
		p.offset = 0
	}
}

func (p *fzfPanel) Update(msg tea.KeyMsg, listHeight int) tea.Cmd {
	if !p.visible {
		return nil
	}

	switch msg.String() {
	case "esc":
		p.Hide()
		return nil
	case "up", "k", "ctrl+p":
		if p.cursor > 0 {
			p.cursor--
			p.ensureVisible(listHeight)
		}
		return nil
	case "down", "j", "ctrl+n":
		if p.cursor < len(p.filter)-1 {
			p.cursor++
			p.ensureVisible(listHeight)
		}
		return nil
	case "pgup":
		step := max(1, listHeight)
		p.cursor = max(0, p.cursor-step)
		p.ensureVisible(listHeight)
		return nil
	case "pgdown":
		step := max(1, listHeight)
		p.cursor = min(len(p.filter)-1, p.cursor+step)
		p.ensureVisible(listHeight)
		return nil
	case "g":
		p.cursor = 0
		p.ensureVisible(listHeight)
		return nil
	case "G":
		p.cursor = max(0, len(p.filter)-1)
		p.ensureVisible(listHeight)
		return nil
	case "backspace", "ctrl+h":
		if p.query == "" {
			p.goParent()
			return nil
		}
		r := []rune(p.query)
		if len(r) > 0 {
			p.query = string(r[:len(r)-1])
			p.cursor = 0
			p.offset = 0
			p.applyFilter()
		}
		return nil
	case "ctrl+u":
		p.query = ""
		p.cursor = 0
		p.offset = 0
		p.applyFilter()
		return nil
	case "enter", "right", "l":
		if len(p.filter) == 0 || p.cursor < 0 || p.cursor >= len(p.filter) {
			return nil
		}
		selected := p.filter[p.cursor]
		if selected.isDir {
			p.openDir(selected.path)
			return nil
		}
		p.Hide()
		return func() tea.Msg {
			return FileSelectedMsg{Path: selected.path}
		}
	}

	if msg.Type == tea.KeyRunes && len(msg.Runes) > 0 {
		p.query += string(msg.Runes)
		p.cursor = 0
		p.offset = 0
		p.applyFilter()
	}
	return nil
}

// fileCount returns the number of file entries (non-directory) in the full
// list and in the current filtered view.
func (p fzfPanel) fileCount() (filtered, total int) {
	for _, e := range p.all {
		if !e.isDir {
			total++
		}
	}
	for _, e := range p.filter {
		if !e.isDir {
			filtered++
		}
	}
	return
}

func (p fzfPanel) View(totalW, _ int, listHeight int) string {
	if !p.visible {
		return ""
	}
	if listHeight < 1 {
		listHeight = 1
	}

	panelW := max(56, (totalW*3)/4)
	panelW = min(panelW, max(24, totalW-4))
	if panelW > totalW {
		panelW = totalW
	}
	innerW := max(0, panelW-4)

	var lines []string
	lines = append(lines, lipgloss.NewStyle().Foreground(accentColor).Bold(true).Render("File Picker"))
	lines = append(lines, lipgloss.NewStyle().Foreground(paneDimColor).Render(p.rootDir))
	lines = append(lines, "")
	queryLine := lipgloss.NewStyle().Foreground(accentColor).Bold(true).Render("query: ") +
		lipgloss.NewStyle().Foreground(paneTextColor).Render(p.query) +
		lipgloss.NewStyle().Foreground(accentColor).Render("▌")
	if strings.TrimSpace(p.query) != "" {
		filtered, total := p.fileCount()
		queryLine += "  " + lipgloss.NewStyle().Foreground(paneDimColor).Render(fmt.Sprintf("%d / %d", filtered, total))
	}
	lines = append(lines, queryLine)
	lines = append(lines, "")

	if strings.TrimSpace(p.errText) != "" {
		lines = append(lines, errorStyle.Render("Error: "+p.errText))
		lines = append(lines, "")
	}

	if len(p.filter) == 0 {
		lines = append(lines, lipgloss.NewStyle().Foreground(paneDimColor).Render("No matches"))
	} else {
		start := p.offset
		end := min(len(p.filter), start+listHeight)
		for i := start; i < end; i++ {
			e := p.filter[i]
			row := fitTail(e.name, innerW-2)
			if i == p.cursor {
				row = lipgloss.NewStyle().
					Foreground(bgColor).
					Background(accentColor).
					Bold(true).
					Width(innerW).
					Render(" " + row)
			} else {
				style := lipgloss.NewStyle().Foreground(paneTextColor).Width(innerW)
				if e.isDir {
					style = style.Foreground(accentColor)
				}
				row = style.Render(" " + row)
			}
			lines = append(lines, row)
		}
		for i := end - start; i < listHeight; i++ {
			lines = append(lines, lipgloss.NewStyle().Width(innerW).Render(""))
		}
	}

	lines = append(lines, "")
	lines = append(lines, lipgloss.NewStyle().Foreground(paneDimColor).Render("enter: select   backspace: parent   ctrl+u: clear   esc: close"))
	content := lipgloss.JoinVertical(lipgloss.Left, lines...)

	return lipgloss.NewStyle().
		Width(panelW).
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(accentColor).
		Padding(1, 1).
		Render(content)
}

func fitTail(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= width {
		return s
	}
	r := []rune(s)
	if len(r) <= 1 {
		return s
	}
	for len(r) > 1 && lipgloss.Width("..."+string(r)) > width {
		r = r[1:]
	}
	return "..." + string(r)
}

func listPickerEntries(root string) ([]pickerEntry, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		root = "."
	}

	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, nil
	}

	var out []pickerEntry
	parent := filepath.Dir(root)
	if parent != root {
		out = append(out, pickerEntry{name: "../", path: parent, isDir: true})
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}

	var dirs, files []pickerEntry
	for _, e := range entries {
		name := e.Name()
		path := filepath.Join(root, name)
		if e.IsDir() {
			dirs = append(dirs, pickerEntry{name: name + "/", path: path, isDir: true})
			// Also surface cert files one level inside each subdirectory so
			// they are discoverable without having to navigate in.
			if subFiles, err := certFilesInDir(path, name+"/"); err == nil {
				files = append(files, subFiles...)
			}
			continue
		}
		if pickerFileExtensions[strings.ToLower(filepath.Ext(name))] {
			files = append(files, pickerEntry{name: name, path: path, isDir: false})
		}
	}

	sort.Slice(dirs, func(i, j int) bool { return dirs[i].name < dirs[j].name })
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })

	out = append(out, dirs...)
	out = append(out, files...)
	return out, nil
}

// certFilesInDir returns cert files directly inside dir, with names prefixed
// by prefix (e.g. "certs/") so they are identifiable in the flat list.
func certFilesInDir(dir, prefix string) ([]pickerEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []pickerEntry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if pickerFileExtensions[strings.ToLower(filepath.Ext(name))] {
			out = append(out, pickerEntry{
				name:  prefix + name,
				path:  filepath.Join(dir, name),
				isDir: false,
			})
		}
	}
	return out, nil
}

func systemRootDir() string {
	wd, err := os.Getwd()
	if err != nil {
		return string(filepath.Separator)
	}
	vol := filepath.VolumeName(wd)
	if vol != "" {
		return vol + string(filepath.Separator)
	}
	return string(filepath.Separator)
}
