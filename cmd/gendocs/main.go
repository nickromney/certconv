package main

import (
	"fmt"
	"os"

	"github.com/nickromney/certconv/internal/cert"
	"github.com/nickromney/certconv/internal/cli"
	"github.com/spf13/cobra/doc"
)

func main() {
	engine := cert.NewDefaultEngine()
	buildInfo := cli.BuildInfo{Version: "dev", BuildTime: "unknown", GitCommit: "unknown"}
	root := cli.NewRootCmd(engine, nil, buildInfo)

	dir := "docs/man"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	header := &doc.GenManHeader{
		Title:   "CERTCONV",
		Section: "1",
		Source:  "certconv",
	}
	if err := doc.GenManTree(root, header, dir); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Man pages generated in %s\n", dir)
}
