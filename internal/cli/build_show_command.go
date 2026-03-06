package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nickromney/certconv/internal/cert"
	"github.com/spf13/cobra"
)

func buildShowCommand(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
	var password string
	var passwordStdin bool
	var passwordFile string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "show FILE",
		Short: "Show certificate summary",
		Args:  cobra.ArbitraryArgs,
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

			s, err := engine.Summary(context.Background(), path, password)
			if err != nil {
				return err
			}

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				return enc.Encode(s)
			}

			fmt.Fprintln(outStdout)
			kv("File", s.File)
			kv("Type", string(s.FileType))
			fmt.Fprintln(outStdout)

			if s.FileType == cert.FileTypeKey {
				kv("Key Type", string(s.KeyType))
			} else {
				if s.Subject != "" {
					kv("Subject", s.Subject)
				}
				if s.Issuer != "" {
					kv("Issuer", s.Issuer)
				}
				if s.NotBefore != "" {
					kv("Not Before", s.NotBefore)
				}
				if s.NotAfter != "" {
					kv("Not After", s.NotAfter)
				}
				if s.Serial != "" {
					kv("Serial", s.Serial)
				}
			}
			fmt.Fprintln(outStdout)
			return nil
		},
	}
	cmd.Flags().StringVarP(&password, "password", "p", "", "PFX password")
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "Read PFX password from stdin")
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "Read PFX password from file (use '-' for stdin)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output JSON")
	return cmd
}

func buildShowFullCommand(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
	var password string
	var passwordStdin bool
	var passwordFile string
	cmd := &cobra.Command{
		Use:   "show-full FILE",
		Short: "Show full certificate details",
		Args:  cobra.ArbitraryArgs,
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

			d, err := engine.Details(context.Background(), path, password)
			if err != nil {
				return err
			}

			fmt.Fprint(outStdout, d.RawText)
			return nil
		},
	}
	cmd.Flags().StringVarP(&password, "password", "p", "", "PFX password")
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "Read PFX password from stdin")
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "Read PFX password from file (use '-' for stdin)")
	return cmd
}
