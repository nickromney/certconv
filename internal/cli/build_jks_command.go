package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nickromney/certconv/internal/cert"
	"github.com/spf13/cobra"
)

func buildShowJKSCommand(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
	var password string
	var passwordStdin bool
	var passwordFile string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "show-jks FILE",
		Short: "List aliases in a JKS/JCEKS keystore",
		Long: `List all aliases in a Java KeyStore (JKS/JCEKS) file.

Shows alias name, entry type, and subject for each entry.
Requires keytool (part of any JDK installation).
Run "certconv doctor" to check if keytool is available.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedArgs, err := resolveInputArgs(cmd, args, 1, pathInput)
			if err != nil {
				return err
			}
			args = resolvedArgs

			inlineProvided := strings.TrimSpace(password) != ""
			pw, err := loadSecret(cmd, password, passwordStdin, passwordFile, "password", "password-stdin", "password-file")
			if err != nil {
				return err
			}
			password = pw
			if inlineProvided && strings.TrimSpace(password) != "" && !passwordStdin && strings.TrimSpace(passwordFile) == "" {
				warnInlineSecretFlag("password")
			}

			path := resolvePath(args[0])
			if err := requireFile(path); err != nil {
				return err
			}

			summary, err := engine.JKSList(context.Background(), path, password)
			if err != nil {
				return err
			}

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				enc.SetIndent("", "  ")
				return enc.Encode(summary)
			}

			fmt.Fprintln(outStdout)
			kv("File", summary.File)
			kv("Aliases", fmt.Sprintf("%d", len(summary.Aliases)))
			fmt.Fprintln(outStdout)
			for _, a := range summary.Aliases {
				kv("Alias", a.Alias)
				if a.Type != "" {
					kv("  Type", a.Type)
				}
				if a.Subject != "" {
					kv("  Subject", a.Subject)
				}
			}
			fmt.Fprintln(outStdout)
			return nil
		},
	}
	cmd.Flags().StringVarP(&password, "password", "p", "", "Keystore password")
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "Read keystore password from stdin")
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "Read keystore password from file (use '-' for stdin)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output JSON")
	return cmd
}

func buildFromJKSCommand(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
	var password string
	var passwordStdin bool
	var passwordFile string
	var alias string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "from-jks INPUT OUTDIR",
		Short: "Extract PEM certificates from a JKS/JCEKS keystore",
		Long: `Export certificates from a Java KeyStore (JKS/JCEKS) to individual PEM files.

By default, all trusted certificate entries are exported. Use --alias to
export a specific entry. Requires keytool (part of any JDK installation).`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedArgs, err := resolveInputArgs(cmd, args, 2, pathInput)
			if err != nil {
				return err
			}
			args = resolvedArgs

			inlineProvided := strings.TrimSpace(password) != ""
			pw, err := loadSecret(cmd, password, passwordStdin, passwordFile, "password", "password-stdin", "password-file")
			if err != nil {
				return err
			}
			password = pw
			if inlineProvided && strings.TrimSpace(password) != "" && !passwordStdin && strings.TrimSpace(passwordFile) == "" {
				warnInlineSecretFlag("password")
			}

			input := resolvePath(args[0])
			outDir := args[1]
			if err := requireFile(input); err != nil {
				return err
			}

			if !jsonOut {
				step("Extracting from JKS...")
			}
			result, err := engine.FromJKS(context.Background(), input, outDir, password, alias)
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
	cmd.Flags().StringVarP(&password, "password", "p", "", "Keystore password")
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "Read keystore password from stdin")
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "Read keystore password from file (use '-' for stdin)")
	cmd.Flags().StringVarP(&alias, "alias", "a", "", "Export only this alias (default: all)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output JSON")
	return cmd
}
