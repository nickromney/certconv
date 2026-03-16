package cli

import (
	"encoding/json"
	"fmt"

	"github.com/nickromney/certconv/internal/cert"
	"github.com/spf13/cobra"
)

func buildLintCommand(pathInput *pathInputOptions) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "lint FILE",
		Short: "Lint a certificate for common issues",
		Long: `Lint a PEM or DER certificate for common configuration issues.

Checks performed:
  weak-key        RSA key < 2048 bits (error)
  sha1-signature  SHA-1 signature algorithm (warning)
  missing-sans    No Subject Alternative Names (warning)
  expired         Certificate has expired (error)
  not-yet-valid   Certificate is not yet valid (error)
  ca-as-leaf      CA=true with ServerAuth but no CertSign (warning)
  long-validity   Leaf cert validity > 398 days (warning)

Exit codes: 0 = clean, 1 = issues found.
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

			result, err := cert.LintFile(path)
			if err != nil {
				return fmt.Errorf("lint: %w", err)
			}

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			}

			if result.Clean {
				success("No issues found")
				return nil
			}

			fmt.Fprintln(outStdout)
			for _, issue := range result.Issues {
				switch issue.Severity {
				case cert.LintError:
					errMsg(fmt.Sprintf("[%s] %s", issue.Code, issue.Message))
				case cert.LintWarning:
					warn(fmt.Sprintf("[%s] %s", issue.Code, issue.Message))
				}
			}
			fmt.Fprintln(outStdout)

			return &ExitError{Code: 1, Silent: true}
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output JSON")
	return cmd
}
