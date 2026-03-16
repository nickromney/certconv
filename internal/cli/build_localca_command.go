package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nickromney/certconv/internal/cert"
	"github.com/nickromney/certconv/internal/config"
	"github.com/spf13/cobra"
)

func buildLocalCACommand() *cobra.Command {
	var jsonOut bool
	var extraDirs []string
	cmd := &cobra.Command{
		Use:   "local-ca",
		Short: "Discover and list locally trusted CA certificates",
		Long: `Discover and list locally trusted CA certificates.

Searches for CA certificates installed by tools like mkcert, or in
custom directories you specify. This is useful for understanding
which local CAs are trusted in your development environment.

Discovery order:
  1. mkcert CAROOT (via "mkcert -CAROOT" command)
  2. Platform-default mkcert location if the command is not installed
  3. Directories specified via --dir flags

The --dir flag can be repeated to scan multiple custom directories.
Paths may use ~ for the home directory.

Pure Go — no external tools required (mkcert is used only for CAROOT discovery).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Merge config-specified dirs with CLI --dir flags
			allDirs := extraDirs
			if cfg, err := config.Load(); err == nil && len(cfg.LocalCADirs) > 0 {
				allDirs = append(cfg.LocalCADirs, allDirs...)
			}

			result, err := cert.DiscoverLocalCAs(allDirs)
			if err != nil {
				return err
			}

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			}

			if len(result.Entries) == 0 {
				info("No local CA certificates found")
				fmt.Fprintln(outStdout)
				info("Tip: install mkcert (https://github.com/FiloSottile/mkcert) or use --dir to specify a CA directory")
				return nil
			}

			fmt.Fprintln(outStdout)
			info(fmt.Sprintf("Found %d local CA certificate(s)", len(result.Entries)))
			fmt.Fprintln(outStdout)

			currentSource := ""
			for _, e := range result.Entries {
				if e.Source != currentSource {
					currentSource = e.Source
					kv("Source", strings.ToUpper(currentSource))
					fmt.Fprintln(outStdout)
				}
				kv("  File", e.File)
				if e.Subject != "" {
					kv("  Subject", e.Subject)
				}
				if e.Expiry != "" {
					kv("  Expires", e.Expiry)
				}
				if e.IsCA {
					kv("  CA", "true")
				}
				fmt.Fprintln(outStdout)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output JSON")
	cmd.Flags().StringArrayVar(&extraDirs, "dir", nil, "Additional directory to scan for CA certificates (repeatable)")
	return cmd
}
