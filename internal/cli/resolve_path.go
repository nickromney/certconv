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

func resolveDirArg(args []string) (string, error) {
	if len(args) == 0 {
		return "", nil
	}
	raw := strings.TrimSpace(args[0])
	if raw == "" {
		return "", &ExitError{Code: 2, Msg: "directory path cannot be empty"}
	}
	dir := expandHomePath(raw)
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return "", &ExitError{Code: 2, Msg: "directory not found: " + raw}
	}
	if err != nil {
		return "", fmt.Errorf("cannot access directory: %s: %w", raw, err)
	}
	if !info.IsDir() {
		return "", &ExitError{Code: 2, Msg: "path is not a directory: " + raw}
	}
	return dir, nil
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
