package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SaveTheme updates (or inserts) the top-level `theme:` key in config.yml.
// It preserves existing content as much as possible and writes atomically.
func SaveTheme(theme string) (string, error) {
	theme = strings.TrimSpace(theme)
	if theme == "" {
		theme = "default"
	}

	path, err := Path()
	if err != nil {
		return "", err
	}

	var mode os.FileMode = 0o644
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
		data = nil
	} else {
		if st, serr := os.Stat(path); serr == nil {
			mode = st.Mode().Perm()
		}
	}

	updated := upsertTopLevelTheme(string(data), theme)
	if !strings.HasSuffix(updated, "\n") {
		updated += "\n"
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "config.yml.*")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return "", err
	}
	if _, err := tmp.WriteString(updated); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return "", fmt.Errorf("rename temp config: %w", err)
	}

	return path, nil
}

func upsertTopLevelTheme(in string, theme string) string {
	lines := strings.Split(in, "\n")

	stripComment := func(s string) string {
		if i := strings.IndexByte(s, '#'); i >= 0 {
			return s[:i]
		}
		return s
	}

	leadingSpaces := func(s string) int {
		n := 0
		for _, r := range s {
			if r != ' ' {
				break
			}
			n++
		}
		return n
	}

	// Replace existing top-level `theme:` if present.
	for i, raw := range lines {
		if leadingSpaces(raw) != 0 {
			continue
		}
		check := strings.TrimSpace(stripComment(raw))
		if !strings.HasPrefix(check, "theme:") {
			continue
		}

		comment := ""
		if ci := strings.IndexByte(raw, '#'); ci >= 0 {
			comment = strings.TrimSpace(raw[ci:])
		}
		out := "theme: " + theme
		if comment != "" {
			out += "  " + comment
		}
		lines[i] = out
		return strings.Join(lines, "\n")
	}

	// Insert (prefer placing it before `keys:` if present).
	insertAt := len(lines)
	for i, raw := range lines {
		if leadingSpaces(raw) != 0 {
			continue
		}
		check := strings.TrimSpace(stripComment(raw))
		if check == "keys:" {
			insertAt = i
			break
		}
	}

	themeLine := "theme: " + theme
	lines = append(lines, "")
	copy(lines[insertAt+1:], lines[insertAt:])
	lines[insertAt] = themeLine

	// Avoid leading blank line in an empty file.
	if len(lines) >= 2 && lines[0] == "" {
		lines = lines[1:]
	}
	return strings.Join(lines, "\n")
}
