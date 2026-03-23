package cli

import (
	"encoding/json"
	"fmt"

	"github.com/nickromney/certconv/internal/cert"
	"github.com/spf13/cobra"
)

func buildChainCommand(pathInput *pathInputOptions) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "chain BUNDLE",
		Short: "Order a PEM bundle from leaf to root",
		Long: `Read a PEM bundle and output certificates in chain order: leaf → intermediate(s) → root.

The ordering algorithm matches certificates by Authority Key Identifier (AKI) to
Subject Key Identifier (SKI), with a fallback to Issuer/Subject DN matching.

Outputs ordered PEM to stdout by default, or structured JSON with --json.
Warnings are emitted for broken chains (orphan certificates not reachable from leaf).

Pure Go — no external tools required.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedArgs, err := resolveInputArgs(cmd, args, 1, pathInput)
			if err != nil {
				return err
			}
			args = resolvedArgs

			path := resolvePath(args[0])
			if err := requireFile(path); err != nil {
				return err
			}

			result, orderedPEM, err := cert.OrderChain(path)
			if err != nil {
				return fmt.Errorf("chain: %w", err)
			}

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			}

			for _, w := range result.Warnings {
				warn(w)
			}

			fmt.Fprint(outStdout, string(orderedPEM))
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output JSON instead of ordered PEM")
	return cmd
}
