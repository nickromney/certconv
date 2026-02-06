package tui

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// fileEntry represents a single file/directory in the listing.
type fileEntry struct {
	name  string
	path  string
	isDir bool
}

// filePane is a simple file browser (we roll our own for better control than bubbles/filepicker).
type filePane struct {
	entries  []fileEntry
	cursor   int
	dir      string
	width    int
	height   int
	offset   int // scroll offset
	selected string
}

func newFilePane(startDir string) filePane {
	fp := filePane{dir: startDir}
	fp.loadDir()
	return fp
}

func (fp *filePane) loadDir() {
	fp.entries = nil
	fp.cursor = 0
	fp.offset = 0
	fp.selected = ""

	entries, err := os.ReadDir(fp.dir)
	if err != nil {
		return
	}

	// Parent directory
	if fp.dir != "/" {
		fp.entries = append(fp.entries, fileEntry{
			name:  "..",
			path:  filepath.Dir(fp.dir),
			isDir: true,
		})
	}

	var dirs, files []fileEntry
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue // skip hidden files
		}
		path := filepath.Join(fp.dir, e.Name())
		if e.IsDir() {
			dirs = append(dirs, fileEntry{name: e.Name() + "/", path: path, isDir: true})
		} else {
			files = append(files, fileEntry{name: e.Name(), path: path, isDir: false})
		}
	}

	sort.Slice(dirs, func(i, j int) bool { return dirs[i].name < dirs[j].name })
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })

	fp.entries = append(fp.entries, dirs...)
	fp.entries = append(fp.entries, files...)
}

func (fp *filePane) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		emit := func() tea.Cmd {
			if len(fp.entries) == 0 {
				return nil
			}
			entry := fp.entries[fp.cursor]
			if entry.isDir {
				return nil
			}
			if fp.selected == entry.path {
				return nil
			}
			fp.selected = entry.path
			return func() tea.Msg {
				return FileFocusedMsg{Path: entry.path}
			}
		}

		switch msg.String() {
		case "up", "k":
			if fp.cursor > 0 {
				fp.cursor--
				fp.ensureVisible()
			}
			return emit()
		case "down", "j":
			if fp.cursor < len(fp.entries)-1 {
				fp.cursor++
				fp.ensureVisible()
			}
			return emit()
		case "ctrl+d":
			// Half page down
			visibleHeight := fp.height
			step := max(1, visibleHeight/2)
			fp.cursor = min(len(fp.entries)-1, fp.cursor+step)
			fp.ensureVisible()
			return emit()
		case "ctrl+u":
			// Half page up
			visibleHeight := fp.height
			step := max(1, visibleHeight/2)
			fp.cursor = max(0, fp.cursor-step)
			fp.ensureVisible()
			return emit()
		case "pgdown":
			visibleHeight := fp.height
			step := max(1, visibleHeight)
			fp.cursor = min(len(fp.entries)-1, fp.cursor+step)
			fp.ensureVisible()
			return emit()
		case "pgup":
			visibleHeight := fp.height
			step := max(1, visibleHeight)
			fp.cursor = max(0, fp.cursor-step)
			fp.ensureVisible()
			return emit()
		case "enter", "l":
			if len(fp.entries) == 0 {
				return nil
			}
			entry := fp.entries[fp.cursor]
			if entry.isDir {
				fp.dir = entry.path
				fp.loadDir()
				return nil
			}
			fp.selected = entry.path
			return func() tea.Msg {
				return FileSelectedMsg{Path: entry.path}
			}
		case "h":
			// Go to parent
			parent := filepath.Dir(fp.dir)
			if parent != fp.dir {
				fp.dir = parent
				fp.loadDir()
			}
		case "G":
			fp.cursor = max(0, len(fp.entries)-1)
			fp.ensureVisible()
			return emit()
		case "g":
			fp.cursor = 0
			fp.ensureVisible()
			return emit()
		}
	case RefreshFilesMsg:
		fp.loadDir()
	}
	return nil
}

// SelectFile updates the file pane to show and focus the given file, switching
// directories if needed. This is useful for external pickers (e.g. fzf).
func (fp *filePane) SelectFile(path string) {
	if path == "" {
		return
	}
	dir := filepath.Dir(path)
	if dir != fp.dir {
		fp.dir = dir
		fp.loadDir()
	}

	fp.selected = path
	for i, e := range fp.entries {
		if e.path == path {
			fp.cursor = i
			fp.ensureVisible()
			return
		}
	}
}

func (fp *filePane) ensureVisible() {
	visibleHeight := fp.height
	if visibleHeight < 1 {
		visibleHeight = 1
	}
	if fp.cursor < fp.offset {
		fp.offset = fp.cursor
	}
	if fp.cursor >= fp.offset+visibleHeight {
		fp.offset = fp.cursor - visibleHeight + 1
	}
}

func (fp *filePane) View(focused bool) string {
	visibleHeight := fp.height
	if visibleHeight < 1 {
		visibleHeight = 1
	}

	var lines []string
	end := fp.offset + visibleHeight
	if end > len(fp.entries) {
		end = len(fp.entries)
	}

	for i := fp.offset; i < end; i++ {
		entry := fp.entries[i]
		line := entry.name

		// Keep some room for cursor marker/padding.
		if fp.width > 6 && len(line) > fp.width-4 {
			line = line[:fp.width-7] + "..."
		}

		if i == fp.cursor {
			if focused {
				line = lipgloss.NewStyle().
					Foreground(bgColor).
					Background(accentColor).
					Bold(true).
					Width(fp.width).
					Render(line)
			} else {
				line = lipgloss.NewStyle().
					Foreground(textColor).
					Bold(true).
					Width(fp.width).
					Render("> " + line)
			}
		} else if entry.isDir {
			line = lipgloss.NewStyle().Foreground(accentColor).Width(fp.width).Render("  " + line)
		} else {
			line = lipgloss.NewStyle().Foreground(textColor).Width(fp.width).Render("  " + line)
		}

		lines = append(lines, line)
	}

	// Pad to fill height
	for len(lines) < visibleHeight {
		lines = append(lines, "")
	}

	content := lipgloss.JoinVertical(lipgloss.Left, lines...)
	return lipgloss.NewStyle().Width(fp.width).Height(fp.height).Render(content)
}
