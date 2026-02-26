package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config is intentionally small and flat. It's a TUI-focused config for now.
//
// File location: ~/.config/certconv/config.yml (or $XDG_CONFIG_HOME/certconv/config.yml)
type Config struct {
	CertsDir         string
	AutoMatchKey     bool
	EagerViews       bool
	OneLineWrapWidth int
	FilePaneWidthPct int
	SummaryPanePct   int
	Theme            string // "default", "github-dark", "github-dark-high-contrast", "terminal"
	Keys             KeysConfig
}

type KeysConfig struct {
	NextView          string
	PrevView          string
	Copy              string
	ResizeFileLess    string
	ResizeFileMore    string
	ResizeSummaryLess string
	ResizeSummaryMore string
}

func Default() Config {
	return Config{
		AutoMatchKey:     true,
		EagerViews:       true,
		OneLineWrapWidth: 64,
		FilePaneWidthPct: 28,
		SummaryPanePct:   38,
		Keys: KeysConfig{
			NextView:          "n",
			PrevView:          "p",
			Copy:              "c",
			ResizeFileLess:    "[",
			ResizeFileMore:    "]",
			ResizeSummaryLess: "-",
			ResizeSummaryMore: "=",
		},
	}
}

func Path() (string, error) {
	base := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME"))
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "certconv", "config.yml"), nil
}

// Load reads config.yml if present. If missing, returns Default() with nil error.
func Load() (Config, error) {
	cfg := Default()

	path, err := Path()
	if err != nil {
		return cfg, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}

	patch, err := parseYAMLSubset(data)
	if err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}

	if patch.CertsDir != "" {
		cfg.CertsDir = patch.CertsDir
	}
	if patch.OneLineWrapWidth != 0 {
		cfg.OneLineWrapWidth = patch.OneLineWrapWidth
	}
	if patch.FilePaneWidthPct != 0 {
		cfg.FilePaneWidthPct = patch.FilePaneWidthPct
	}
	if patch.SummaryPanePct != 0 {
		cfg.SummaryPanePct = patch.SummaryPanePct
	}
	if patch.Keys.NextView != "" {
		cfg.Keys.NextView = patch.Keys.NextView
	}
	if patch.Keys.PrevView != "" {
		cfg.Keys.PrevView = patch.Keys.PrevView
	}
	if patch.Keys.Copy != "" {
		cfg.Keys.Copy = patch.Keys.Copy
	}
	if patch.Keys.ResizeFileLess != "" {
		cfg.Keys.ResizeFileLess = patch.Keys.ResizeFileLess
	}
	if patch.Keys.ResizeFileMore != "" {
		cfg.Keys.ResizeFileMore = patch.Keys.ResizeFileMore
	}
	if patch.Keys.ResizeSummaryLess != "" {
		cfg.Keys.ResizeSummaryLess = patch.Keys.ResizeSummaryLess
	}
	if patch.Keys.ResizeSummaryMore != "" {
		cfg.Keys.ResizeSummaryMore = patch.Keys.ResizeSummaryMore
	}
	if patch.autoMatchSet {
		cfg.AutoMatchKey = patch.AutoMatchKey
	}
	if patch.eagerViewsSet {
		cfg.EagerViews = patch.EagerViews
	}
	if patch.Theme != "" {
		cfg.Theme = patch.Theme
	}

	return cfg, nil
}

type partialConfig struct {
	CertsDir         string
	AutoMatchKey     bool
	EagerViews       bool
	OneLineWrapWidth int
	FilePaneWidthPct int
	SummaryPanePct   int
	Theme            string
	Keys             KeysConfig
	autoMatchSet     bool
	eagerViewsSet    bool
}

// parseYAMLSubset parses a very small subset of YAML:
// - top-level `key: value`
// - one nested map: `keys:` with indented `next_view: n` etc.
// - comments with '#'
func parseYAMLSubset(data []byte) (partialConfig, error) {
	var out partialConfig

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	section := ""

	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if strings.TrimSpace(line) == "" {
			continue
		}

		indent := countLeadingSpaces(line)
		trim := strings.TrimSpace(line)

		// Section headers: `keys:`
		if strings.HasSuffix(trim, ":") && !strings.Contains(trim[:len(trim)-1], " ") {
			name := strings.TrimSuffix(trim, ":")
			if indent == 0 {
				section = name
				continue
			}
		}

		// Leave section when indentation resets.
		if indent == 0 {
			section = ""
		}

		k, v, ok := splitKV(trim)
		if !ok {
			return out, fmt.Errorf("invalid line: %q", sc.Text())
		}
		v = unquote(strings.TrimSpace(v))

		if section == "keys" {
			switch k {
			case "next_view":
				out.Keys.NextView = v
			case "prev_view":
				out.Keys.PrevView = v
			case "copy":
				out.Keys.Copy = v
			case "resize_file_less":
				out.Keys.ResizeFileLess = v
			case "resize_file_more":
				out.Keys.ResizeFileMore = v
			case "resize_summary_less":
				out.Keys.ResizeSummaryLess = v
			case "resize_summary_more":
				out.Keys.ResizeSummaryMore = v
			}
			continue
		}

		switch k {
		case "certs_dir":
			out.CertsDir = v
		case "auto_match_key":
			b, ok := parseBool(v)
			if !ok {
				return out, fmt.Errorf("auto_match_key must be boolean, got %q", v)
			}
			out.AutoMatchKey = b
			out.autoMatchSet = true
		case "eager_views":
			b, ok := parseBool(v)
			if !ok {
				return out, fmt.Errorf("eager_views must be boolean, got %q", v)
			}
			out.EagerViews = b
			out.eagerViewsSet = true
		case "one_line_wrap_width":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return out, fmt.Errorf("one_line_wrap_width must be a non-negative int, got %q", v)
			}
			out.OneLineWrapWidth = n
		case "file_pane_width_pct":
			n, err := strconv.Atoi(v)
			if err != nil || n < 5 || n > 95 {
				return out, fmt.Errorf("file_pane_width_pct must be int 5..95, got %q", v)
			}
			out.FilePaneWidthPct = n
		case "summary_pane_height_pct":
			n, err := strconv.Atoi(v)
			if err != nil || n < 5 || n > 95 {
				return out, fmt.Errorf("summary_pane_height_pct must be int 5..95, got %q", v)
			}
			out.SummaryPanePct = n
		case "theme":
			out.Theme = v
		}
	}
	if err := sc.Err(); err != nil {
		return out, err
	}

	// Defaults within partial config: only apply boolean if set.
	if !out.autoMatchSet {
		out.AutoMatchKey = Default().AutoMatchKey
	}
	if !out.eagerViewsSet {
		out.EagerViews = Default().EagerViews
	}

	return out, nil
}

func splitKV(s string) (key, val string, ok bool) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return "", "", false
	}
	key = strings.TrimSpace(s[:i])
	val = strings.TrimSpace(s[i+1:])
	if key == "" {
		return "", "", false
	}
	return key, val, true
}

func countLeadingSpaces(s string) int {
	n := 0
	for n < len(s) && s[n] == ' ' {
		n++
	}
	return n
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func parseBool(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true, true
	case "0", "false", "no", "off":
		return false, true
	default:
		return false, false
	}
}
