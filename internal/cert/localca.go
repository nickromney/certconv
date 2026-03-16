package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// LocalCAEntry describes a single CA certificate discovered on the local system.
type LocalCAEntry struct {
	Source  string `json:"source"` // e.g. "mkcert", "custom"
	File    string `json:"file"`
	Subject string `json:"subject,omitempty"`
	Issuer  string `json:"issuer,omitempty"`
	IsCA    bool   `json:"is_ca"`
	Expiry  string `json:"expiry,omitempty"`
}

// LocalCAResult holds all discovered local CA certificates.
type LocalCAResult struct {
	Entries []LocalCAEntry `json:"entries"`
}

// MkcertCARootFnForTest returns the current mkcertCARootFn for saving/restoring in tests.
func MkcertCARootFnForTest() func() (string, error) { return mkcertCARootFn }

// SetMkcertCARootFnForTest overrides mkcertCARootFn for testing.
func SetMkcertCARootFnForTest(fn func() (string, error)) { mkcertCARootFn = fn }

// DefaultMkcertCARootFnForTest returns the current defaultMkcertCARootFn for saving/restoring in tests.
func DefaultMkcertCARootFnForTest() func() string { return defaultMkcertCARootFn }

// SetDefaultMkcertCARootFnForTest overrides defaultMkcertCARootFn for testing.
func SetDefaultMkcertCARootFnForTest(fn func() string) { defaultMkcertCARootFn = fn }

// mkcertCARootFn is overridable in tests.
var mkcertCARootFn = func() (string, error) {
	out, err := exec.Command("mkcert", "-CAROOT").CombinedOutput()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// defaultMkcertCARootFn is overridable in tests.
var defaultMkcertCARootFn = defaultMkcertCAROOT

// DiscoverLocalCAs finds local CA certificates from mkcert and custom directories.
func DiscoverLocalCAs(extraDirs []string) (*LocalCAResult, error) {
	result := &LocalCAResult{}

	// 1. Try mkcert CAROOT
	if caroot, err := mkcertCARootFn(); err == nil && caroot != "" {
		if info, err := os.Stat(caroot); err == nil && info.IsDir() {
			entries := scanDirForCAs(caroot, "mkcert")
			result.Entries = append(result.Entries, entries...)
		}
	}

	// 2. Check platform-specific default mkcert location if mkcert command wasn't found
	if len(result.Entries) == 0 {
		if defaultRoot := defaultMkcertCARootFn(); defaultRoot != "" {
			if info, err := os.Stat(defaultRoot); err == nil && info.IsDir() {
				entries := scanDirForCAs(defaultRoot, "mkcert")
				result.Entries = append(result.Entries, entries...)
			}
		}
	}

	// 3. Custom directories
	for _, dir := range extraDirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		dir = expandHome(dir)
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		entries := scanDirForCAs(dir, "custom")
		result.Entries = append(result.Entries, entries...)
	}

	return result, nil
}

// defaultMkcertCAROOT returns the platform default mkcert CAROOT directory.
func defaultMkcertCAROOT() string {
	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		return filepath.Join(home, "Library", "Application Support", "mkcert")
	case "windows":
		appData := os.Getenv("LOCALAPPDATA")
		if appData == "" {
			return ""
		}
		return filepath.Join(appData, "mkcert")
	default: // linux, freebsd, etc
		// XDG_DATA_HOME or ~/.local/share
		dataHome := os.Getenv("XDG_DATA_HOME")
		if dataHome == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return ""
			}
			dataHome = filepath.Join(home, ".local", "share")
		}
		return filepath.Join(dataHome, "mkcert")
	}
}

func scanDirForCAs(dir, source string) []LocalCAEntry {
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	var result []LocalCAEntry
	for _, e := range dirEntries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		ext := strings.ToLower(filepath.Ext(name))
		// Only look at cert-like files
		if ext != ".pem" && ext != ".crt" && ext != ".cer" && ext != ".der" {
			continue
		}
		path := filepath.Join(dir, name)
		entries := parseCACertFile(path, source)
		result = append(result, entries...)
	}
	return result
}

func parseCACertFile(path, source string) []LocalCAEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var entries []LocalCAEntry

	// Try PEM first
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		entries = append(entries, LocalCAEntry{
			Source:  source,
			File:    path,
			Subject: c.Subject.String(),
			Issuer:  c.Issuer.String(),
			IsCA:    c.IsCA,
			Expiry:  c.NotAfter.UTC().Format("2006-01-02"),
		})
	}

	// If no PEM blocks found, try DER
	if len(entries) == 0 {
		c, err := x509.ParseCertificate(data)
		if err == nil {
			entries = append(entries, LocalCAEntry{
				Source:  source,
				File:    path,
				Subject: c.Subject.String(),
				Issuer:  c.Issuer.String(),
				IsCA:    c.IsCA,
				Expiry:  c.NotAfter.UTC().Format("2006-01-02"),
			})
		}
	}

	return entries
}

// expandHome expands ~ prefix to the user's home directory.
func expandHome(path string) string {
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
		return path
	}
	if strings.HasPrefix(path, fmt.Sprintf("~%c", filepath.Separator)) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, fmt.Sprintf("~%c", filepath.Separator)))
		}
	}
	return path
}
