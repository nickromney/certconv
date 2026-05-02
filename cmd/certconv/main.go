package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nickromney/certconv/internal/cert"
	"github.com/nickromney/certconv/internal/cli"
	"github.com/nickromney/certconv/internal/config"
	"github.com/nickromney/certconv/internal/tui"
)

var (
	// Set via -ldflags at build time.
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func main() {
	engine := cert.NewDefaultEngine()

	runTUI := func(startDir string) error {
		cfg, err := config.Load()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		}
		startPath := strings.TrimSpace(startDir)
		initialSelection := ""
		if startPath != "" {
			info, statErr := os.Stat(startPath)
			if statErr == nil && !info.IsDir() {
				initialSelection = startPath
				startDir = filepath.Dir(startPath)
			}
		}

		m := tui.New(engine, cfg, startDir)
		if initialSelection != "" {
			m = m.WithInitialSelection(initialSelection)
		}
		// Don't enable Bubble Tea mouse mode: it interferes with standard
		// terminal click-and-drag selection. Navigation is keyboard-first.
		p := tea.NewProgram(m, tea.WithAltScreen())
		_, err = p.Run()
		return err
	}

	buildInfo := cli.BuildInfo{
		Version:   Version,
		BuildTime: BuildTime,
		GitCommit: GitCommit,
	}
	root := cli.NewRootCmd(engine, runTUI, buildInfo)
	if err := root.Execute(); err != nil {
		if code, silent, ok := cli.ExitCode(err); ok {
			if !silent {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			}
			os.Exit(code)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
