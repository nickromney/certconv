package cli

import (
	"context"
	"encoding/json"

	"github.com/nickromney/certconv/internal/cert"
	"github.com/spf13/cobra"
)

func buildFromP7BCommand(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "from-p7b INPUT OUTDIR",
		Short: "Extract PEM certificates from a PKCS#7 (.p7b) file",
		Long: `Extract all certificates from a PKCS#7 (.p7b/.p7c) container into
individual PEM files in the output directory.

Requires openssl. Each certificate is written as a separate file.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedArgs, err := resolveInputArgs(cmd, args, 2, pathInput)
			if err != nil {
				return err
			}
			args = resolvedArgs

			input := resolvePath(args[0])
			outDir := args[1]
			if err := requireFile(input); err != nil {
				return err
			}

			if !jsonOut {
				step("Extracting from P7B...")
			}
			result, err := engine.FromP7B(context.Background(), input, outDir)
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				return enc.Encode(result)
			}
			for _, f := range result.CertFiles {
				success("Certificate: " + f)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output JSON")
	return cmd
}
