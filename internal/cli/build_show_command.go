package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

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

			s, err := fastSummary(path, password)
			if err != nil || s == nil {
				s, err = engine.Summary(context.Background(), path, password)
				if err != nil {
					return err
				}
			}

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				return enc.Encode(s)
			}

			printSummaryHuman(s)
			return nil
		},
	}
	cmd.Flags().StringVarP(&password, "password", "p", "", "PFX password")
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "Read PFX password from stdin")
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "Read PFX password from file (use '-' for stdin)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output JSON")
	return cmd
}

func fastSummary(path, password string) (*cert.CertSummary, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	s, err := cert.SummaryFromBytesWithPassword(path, data, password)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, nil
	}
	if s.FileType == cert.FileTypeP7B {
		return nil, nil
	}

	s.File = path
	s.NotBefore = formatSummaryTimestamp(s.NotBefore)
	s.NotAfter = formatSummaryTimestamp(s.NotAfter)
	return s, nil
}

func formatSummaryTimestamp(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return raw
	}
	return t.UTC().Format("Jan _2 15:04:05 2006 GMT")
}

func printSummaryHuman(s *cert.CertSummary) {
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
