package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/nickromney/certconv/internal/cert"
	"github.com/spf13/cobra"
)

func buildVerifyCommand(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "verify CERT CA",
		Short: "Verify certificate chain",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedArgs, err := resolveInputArgs(cmd, args, 2, pathInput)
			if err != nil {
				return err
			}
			args = resolvedArgs

			certPath := resolvePath(args[0])
			caPath := resolvePath(args[1])
			if err := requireFile(certPath); err != nil {
				return err
			}
			if err := requireFile(caPath); err != nil {
				return err
			}

			if !jsonOut {
				step("Verifying certificate chain...")
			}
			result, err := engine.VerifyChain(context.Background(), certPath, caPath)
			if err != nil {
				return err
			}

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				if err := enc.Encode(result); err != nil {
					return err
				}
				if !result.Valid {
					return &ExitError{Code: 1, Silent: true}
				}
				return nil
			}

			if result.Valid {
				success("Certificate chain verified")
				return nil
			}

			errMsg("Chain verification failed")
			fmt.Fprintln(outStdout)
			fmt.Fprintf(outStdout, "  %s\n", result.Output)
			if result.Details != "" {
				fmt.Fprintln(outStdout)
				warn(result.Details)
			}
			return fmt.Errorf("verification failed")
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output JSON")
	return cmd
}

func buildMatchCommand(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
	var keyPassword string
	var keyPasswordStdin bool
	var keyPasswordFile string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "match CERT KEY",
		Short: "Check if key matches certificate",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedArgs, err := resolveInputArgs(cmd, args, 2, pathInput)
			if err != nil {
				return err
			}
			args = resolvedArgs

			inlineProvided := strings.TrimSpace(keyPassword) != ""
			pw, err := loadSecret(cmd, keyPassword, keyPasswordStdin, keyPasswordFile, "key-password", "key-password-stdin", "key-password-file")
			if err != nil {
				return err
			}
			keyPassword = pw
			if inlineProvided && strings.TrimSpace(keyPassword) != "" && !keyPasswordStdin && strings.TrimSpace(keyPasswordFile) == "" {
				warnInlineSecretFlag("key-password")
			}

			certPath := resolvePath(args[0])
			keyPath := resolvePath(args[1])
			if err := requireFile(certPath); err != nil {
				return err
			}
			if err := requireFile(keyPath); err != nil {
				return err
			}

			if !jsonOut {
				step("Checking if key matches certificate...")
			}
			result, err := engine.MatchKeyToCert(context.Background(), certPath, keyPath, keyPassword)
			if err != nil {
				return err
			}

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				if err := enc.Encode(result); err != nil {
					return err
				}
				if !result.Match {
					return &ExitError{Code: 1, Silent: true}
				}
				return nil
			}

			if result.Match {
				success("Private key matches certificate")
				return nil
			}
			errMsg("Private key does NOT match certificate")
			return fmt.Errorf("key mismatch")
		},
	}
	cmd.Flags().StringVar(&keyPassword, "key-password", "", "Private key password (for encrypted keys)")
	cmd.Flags().BoolVar(&keyPasswordStdin, "key-password-stdin", false, "Read private key password from stdin")
	cmd.Flags().StringVar(&keyPasswordFile, "key-password-file", "", "Read private key password from file (use '-' for stdin)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output JSON")
	return cmd
}

func buildExpiryCommand(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
	var days int
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "expiry CERT",
		Short: "Check certificate expiration",
		Args:  cobra.ArbitraryArgs,
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

			result, err := engine.Expiry(context.Background(), path, days)
			if err != nil {
				return err
			}

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				if err := enc.Encode(result); err != nil {
					return err
				}
				if !result.Valid {
					return &ExitError{Code: 1, Silent: true}
				}
				return nil
			}

			info("Expiration: " + result.ExpiryDate)
			if result.Valid {
				success("Certificate valid for at least " + strconv.Itoa(days) + " more days")
				return nil
			}
			warn("Certificate expires within " + strconv.Itoa(days) + " days (or already expired)")
			return fmt.Errorf("certificate expiring")
		},
	}
	cmd.Flags().IntVar(&days, "days", 30, "Number of days to check")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output JSON")
	return cmd
}
