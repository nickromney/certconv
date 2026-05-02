package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nickromney/certconv/internal/cert"
	"github.com/spf13/cobra"
)

type discoverableEntry struct {
	name  string
	path  string
	isDir bool
	ft    cert.FileType
}

var discoverableExtensions = map[string]bool{
	".pem": true,
	".der": true,
	".pfx": true,
	".p12": true,
	".cer": true,
	".crt": true,
	".key": true,
	".pub": true,
	".p7b": true,
	".p7c": true,
}

func runAutoPathAction(cmd *cobra.Command, engine *cert.Engine, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect path %q: %w", path, err)
	}

	if info.IsDir() {
		return printDirectoryDiscoverability(path)
	}

	s, err := fastSummary(path, "")
	if err != nil || s == nil {
		s, err = engine.Summary(context.Background(), path, "")
		if err != nil {
			return err
		}
	}
	printSummaryHuman(s)
	return nil
}

func printDirectoryDiscoverability(dir string) error {
	entries, err := discoverDirectoryEntries(dir)
	if err != nil {
		return err
	}

	fmt.Fprintln(outStdout)
	kv("Directory", dir)
	fmt.Fprintln(outStdout)

	if len(entries) == 0 {
		info("No certificate-like files or subdirectories found.")
		return nil
	}

	var dirs, files []discoverableEntry
	for _, entry := range entries {
		if entry.isDir {
			dirs = append(dirs, entry)
			continue
		}
		files = append(files, entry)
	}

	if len(dirs) > 0 {
		info("Subdirectories")
		for _, entry := range dirs {
			kv("", entry.name+"/")
		}
		fmt.Fprintln(outStdout)
	}

	if len(files) > 0 {
		info("Certificate-like files")
		for _, entry := range files {
			label := entry.name
			if entry.ft != cert.FileTypeUnknown && strings.TrimSpace(string(entry.ft)) != "" {
				label += " [" + string(entry.ft) + "]"
			}
			kv("", label)
		}
		fmt.Fprintln(outStdout)
	}

	step("Tip: use `certconv <file>` for a quick summary, or run interactively for the TUI.")
	return nil
}

func discoverDirectoryEntries(dir string) ([]discoverableEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read directory %q: %w", dir, err)
	}

	out := make([]discoverableEntry, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}

		path := filepath.Join(dir, name)
		if entry.IsDir() {
			out = append(out, discoverableEntry{name: name, path: path, isDir: true})
			continue
		}

		ext := strings.ToLower(filepath.Ext(name))
		if !discoverableExtensions[ext] {
			continue
		}

		ft, err := cert.DetectType(path)
		if err != nil {
			ft = cert.FileTypeUnknown
		}
		out = append(out, discoverableEntry{name: name, path: path, ft: ft})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].isDir != out[j].isDir {
			return out[i].isDir
		}
		return out[i].name < out[j].name
	})

	return out, nil
}
