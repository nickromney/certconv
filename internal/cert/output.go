package cert

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// OutputExistsError indicates the requested output path already exists.
// We never overwrite outputs.
type OutputExistsError struct {
	Path    string
	Suggest string
}

func (e *OutputExistsError) Error() string {
	if strings.TrimSpace(e.Suggest) != "" && e.Suggest != e.Path {
		return fmt.Sprintf("output already exists: %s (try: %s)", e.Path, e.Suggest)
	}
	return fmt.Sprintf("output already exists: %s", e.Path)
}

func IsOutputExists(err error) bool {
	var oe *OutputExistsError
	return errors.As(err, &oe)
}

// NextAvailablePath returns dest if it doesn't exist; otherwise returns an
// incremented sibling path like "file-1.ext", "file-2.ext", etc.
func NextAvailablePath(dest string) string {
	if !pathExists(dest) {
		return dest
	}
	for i := 1; i < 10_000; i++ {
		c := incrementedPath(dest, i)
		if !pathExists(c) {
			return c
		}
	}
	// Fallback (should never happen).
	return incrementedPath(dest, 10_000)
}

func ensureNotExists(dest string) error {
	if !pathExists(dest) {
		return nil
	}
	return &OutputExistsError{Path: dest, Suggest: NextAvailablePath(dest)}
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func incrementedPath(dest string, n int) string {
	dir := filepath.Dir(dest)
	base := filepath.Base(dest)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	return filepath.Join(dir, name+"-"+strconv.Itoa(n)+ext)
}

// writeFileExclusive creates dest with O_EXCL and writes data.
func writeFileExclusive(dest string, data []byte, perm os.FileMode) error {
	if err := ensureNotExists(dest); err != nil {
		return err
	}
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		if os.IsExist(err) {
			return &OutputExistsError{Path: dest, Suggest: NextAvailablePath(dest)}
		}
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

// commitTempFile links tmp into dest (atomic no-overwrite) and removes tmp.
// tmp must be on the same filesystem as dest.
func commitTempFile(tmp, dest string, perm os.FileMode) error {
	if err := ensureNotExists(dest); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	// os.Link fails if dest exists, which is exactly what we want.
	if err := os.Link(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		if os.IsExist(err) {
			return &OutputExistsError{Path: dest, Suggest: NextAvailablePath(dest)}
		}
		return err
	}

	_ = os.Chmod(dest, perm)
	_ = os.Remove(tmp)
	return nil
}

// newTempPath creates an empty temp file path in the destination directory.
func newTempPath(dest string) (string, error) {
	dir := filepath.Dir(dest)
	f, err := os.CreateTemp(dir, ".certconv-*")
	if err != nil {
		return "", err
	}
	path := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

func copyFileExclusive(src, dest string, perm os.FileMode) error {
	if err := ensureNotExists(dest); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		if os.IsExist(err) {
			return &OutputExistsError{Path: dest, Suggest: NextAvailablePath(dest)}
		}
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}
