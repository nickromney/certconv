package main

import (
	"fmt"
	"os"

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

	runTUI := func() error {
		cfg, err := config.Load()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		}
		m := tui.New(engine, cfg)
		opts := []tea.ProgramOption{tea.WithAltScreen()}
		if cfg.Mouse {
			opts = append(opts, tea.WithMouseCellMotion())
		}
		p := tea.NewProgram(m, opts...)
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
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
