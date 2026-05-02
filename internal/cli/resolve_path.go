package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// resolvePath resolves a filename, checking CERTCONV_CERTS_DIR.
func resolvePath(path string) string {
	path = expandHomePath(path)
	if path == "" {
		return path
	}
	// Already absolute or has path separator
	if filepath.IsAbs(path) || filepath.Dir(path) != "." {
		return path
	}
	// Check if it exists as-is
	if _, err := os.Stat(path); err == nil {
		return path
	}
	// Try CERTCONV_CERTS_DIR
	certsDir := expandHomePath(os.Getenv("CERTCONV_CERTS_DIR"))
	if certsDir == "" {
		certsDir = "./certs"
	}
	candidate := filepath.Join(certsDir, path)
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return path
}

func resolveTUIArg(args []string) (string, error) {
	if len(args) == 0 {
		return "", nil
	}
	raw := strings.TrimSpace(args[0])
	if raw == "" {
		return "", &ExitError{Code: 2, Msg: "path cannot be empty"}
	}

	path := expandHomePath(raw)
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return "", &ExitError{Code: 2, Msg: "path not found: " + raw}
	}
	if err != nil {
		return "", fmt.Errorf("cannot access path: %s: %w", raw, err)
	}
	if path == "" {
		return "", &ExitError{Code: 2, Msg: "path cannot be empty"}
	}
	if !filepath.IsAbs(path) {
		abs, absErr := filepath.Abs(path)
		if absErr == nil {
			path = abs
		}
	}
	if info.IsDir() {
		return path, nil
	}
	return path, nil
}

func classifyTUIPath(path string) (startDir string, selectedFile string, err error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", "", nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return "", "", fmt.Errorf("classify TUI path %q: %w", path, err)
	}
	if info.IsDir() {
		return path, "", nil
	}
	return filepath.Dir(path), path, nil
}

func expandHomePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return path
	}
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
		return path
	}
	if strings.HasPrefix(path, "~"+string(filepath.Separator)) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~"+string(filepath.Separator)))
		}
	}
	return path
}

func requireFile(path string) error {
	if path == "" {
		return fmt.Errorf("file path required")
	}
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return fmt.Errorf("file not found: %s", path)
	}
	if err != nil {
		return fmt.Errorf("cannot access file: %s: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("path is a directory: %s", path)
	}
	return nil
}
