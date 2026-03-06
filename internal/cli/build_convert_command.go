package cli

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/nickromney/certconv/internal/cert"
	"github.com/spf13/cobra"
)

func buildToPFXCommand(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
	var password, ca, keyPassword string
	var passwordStdin, keyPasswordStdin bool
	var passwordFile, keyPasswordFile string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "to-pfx CERT KEY OUTPUT",
		Short: "Convert PEM cert + key to PFX",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedArgs, err := resolveInputArgs(cmd, args, 3, pathInput)
			if err != nil {
				return err
			}
			args = resolvedArgs

			// stdin can only be consumed once. Disallow sourcing both secrets from stdin.
			pwFromStdin := passwordStdin || strings.TrimSpace(passwordFile) == "-"
			kpwFromStdin := keyPasswordStdin || strings.TrimSpace(keyPasswordFile) == "-"
			if pwFromStdin && kpwFromStdin {
				return &ExitError{Code: 2, Msg: "only one secret may be read from stdin; use --password-file for one secret and --key-password-file for the other"}
			}

			inlineExportProvided := strings.TrimSpace(password) != ""
			inlineKeyProvided := strings.TrimSpace(keyPassword) != ""
			pw, err := loadSecret(cmd, password, passwordStdin, passwordFile, "password", "password-stdin", "password-file")
			if err != nil {
				return err
			}
			password = pw
			kpw, err := loadSecret(cmd, keyPassword, keyPasswordStdin, keyPasswordFile, "key-password", "key-password-stdin", "key-password-file")
			if err != nil {
				return err
			}
			keyPassword = kpw
			if inlineExportProvided && strings.TrimSpace(password) != "" && !passwordStdin && strings.TrimSpace(passwordFile) == "" {
				warnInlineSecretFlag("password")
			}
			if inlineKeyProvided && strings.TrimSpace(keyPassword) != "" && !keyPasswordStdin && strings.TrimSpace(keyPasswordFile) == "" {
				warnInlineSecretFlag("key-password")
			}

			certPath := resolvePath(args[0])
			keyPath := resolvePath(args[1])
			output := args[2]
			if err := requireFile(certPath); err != nil {
				return err
			}
			if err := requireFile(keyPath); err != nil {
				return err
			}

			caPath := ""
			if ca != "" {
				caPath = resolvePath(ca)
				if err := requireFile(caPath); err != nil {
					return err
				}
			}

			if !jsonOut {
				step("Creating PFX...")
			}
			if err := engine.ToPFX(context.Background(), certPath, keyPath, output, password, caPath, keyPassword); err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				return enc.Encode(struct {
					Output string `json:"output"`
				}{Output: output})
			}
			success("Created: " + output)
			return nil
		},
	}
	cmd.Flags().StringVarP(&password, "password", "p", "", "Export password")
	cmd.Flags().StringVar(&keyPassword, "key-password", "", "Private key password (for encrypted keys)")
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "Read export password from stdin")
	cmd.Flags().BoolVar(&keyPasswordStdin, "key-password-stdin", false, "Read private key password from stdin")
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "Read export password from file (use '-' for stdin)")
	cmd.Flags().StringVar(&keyPasswordFile, "key-password-file", "", "Read private key password from file (use '-' for stdin)")
	cmd.Flags().StringVarP(&ca, "ca", "a", "", "CA bundle file")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output JSON")
	return cmd
}

func buildFromPFXCommand(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
	var password string
	var passwordStdin bool
	var passwordFile string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "from-pfx INPUT OUTDIR",
		Short: "Extract PEM from PFX",
		Args:  cobra.ArbitraryArgs,
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
				step("Extracting from PFX...")
			}
			result, err := engine.FromPFX(context.Background(), input, outDir, password)
			if err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				return enc.Encode(result)
			}
			success("Certificate: " + result.CertFile)
			success("Private key: " + result.KeyFile)
			if result.CAFile != "" {
				success("CA bundle: " + result.CAFile)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&password, "password", "p", "", "PFX password")
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "Read PFX password from stdin")
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "Read PFX password from file (use '-' for stdin)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output JSON")
	return cmd
}

func buildToDERCommand(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
	var isKey bool
	var keyPassword string
	var keyPasswordStdin bool
	var keyPasswordFile string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "to-der INPUT OUTPUT",
		Short: "Convert PEM to DER",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedArgs, err := resolveInputArgs(cmd, args, 2, pathInput)
			if err != nil {
				return err
			}
			args = resolvedArgs

			inlineProvided := strings.TrimSpace(keyPassword) != ""
			kpw, err := loadSecret(cmd, keyPassword, keyPasswordStdin, keyPasswordFile, "key-password", "key-password-stdin", "key-password-file")
			if err != nil {
				return err
			}
			keyPassword = kpw
			if isKey && inlineProvided && strings.TrimSpace(keyPassword) != "" && !keyPasswordStdin && strings.TrimSpace(keyPasswordFile) == "" {
				warnInlineSecretFlag("key-password")
			}

			input := resolvePath(args[0])
			output := args[1]
			if err := requireFile(input); err != nil {
				return err
			}

			if !jsonOut {
				step("Converting to DER...")
			}
			if err := engine.ToDER(context.Background(), input, output, isKey, keyPassword); err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				return enc.Encode(struct {
					Output string `json:"output"`
				}{Output: output})
			}
			success("Created: " + output)
			return nil
		},
	}
	cmd.Flags().BoolVar(&isKey, "key", false, "Input is a private key")
	cmd.Flags().StringVar(&keyPassword, "key-password", "", "Private key password (for encrypted keys; only used with --key)")
	cmd.Flags().BoolVar(&keyPasswordStdin, "key-password-stdin", false, "Read private key password from stdin (only used with --key)")
	cmd.Flags().StringVar(&keyPasswordFile, "key-password-file", "", "Read private key password from file (use '-' for stdin; only used with --key)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output JSON")
	return cmd
}

func buildFromDERCommand(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
	var isKey bool
	var keyPassword string
	var keyPasswordStdin bool
	var keyPasswordFile string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "from-der INPUT OUTPUT",
		Short: "Convert DER to PEM",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedArgs, err := resolveInputArgs(cmd, args, 2, pathInput)
			if err != nil {
				return err
			}
			args = resolvedArgs

			inlineProvided := strings.TrimSpace(keyPassword) != ""
			kpw, err := loadSecret(cmd, keyPassword, keyPasswordStdin, keyPasswordFile, "key-password", "key-password-stdin", "key-password-file")
			if err != nil {
				return err
			}
			keyPassword = kpw
			if isKey && inlineProvided && strings.TrimSpace(keyPassword) != "" && !keyPasswordStdin && strings.TrimSpace(keyPasswordFile) == "" {
				warnInlineSecretFlag("key-password")
			}

			input := resolvePath(args[0])
			output := args[1]
			if err := requireFile(input); err != nil {
				return err
			}

			if !jsonOut {
				step("Converting to PEM...")
			}
			if err := engine.FromDER(context.Background(), input, output, isKey, keyPassword); err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				return enc.Encode(struct {
					Output string `json:"output"`
				}{Output: output})
			}
			success("Created: " + output)
			return nil
		},
	}
	cmd.Flags().BoolVar(&isKey, "key", false, "Input is a private key")
	cmd.Flags().StringVar(&keyPassword, "key-password", "", "Private key password (for encrypted keys; only used with --key)")
	cmd.Flags().BoolVar(&keyPasswordStdin, "key-password-stdin", false, "Read private key password from stdin (only used with --key)")
	cmd.Flags().StringVar(&keyPasswordFile, "key-password-file", "", "Read private key password from file (use '-' for stdin; only used with --key)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output JSON")
	return cmd
}

func buildToBase64Command(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "to-base64 INPUT OUTPUT",
		Short: "Encode file to Base64",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedArgs, err := resolveInputArgs(cmd, args, 2, pathInput)
			if err != nil {
				return err
			}
			args = resolvedArgs

			input := resolvePath(args[0])
			output := args[1]
			if err := requireFile(input); err != nil {
				return err
			}

			if !jsonOut {
				step("Encoding to Base64...")
			}
			if err := engine.ToBase64(context.Background(), input, output); err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				return enc.Encode(struct {
					Output string `json:"output"`
				}{Output: output})
			}
			success("Created: " + output)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output JSON")
	return cmd
}

func buildFromBase64Command(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "from-base64 INPUT OUTPUT",
		Short: "Decode Base64 to file",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedArgs, err := resolveInputArgs(cmd, args, 2, pathInput)
			if err != nil {
				return err
			}
			args = resolvedArgs

			input := resolvePath(args[0])
			output := args[1]
			if err := requireFile(input); err != nil {
				return err
			}

			if !jsonOut {
				step("Decoding Base64...")
			}
			if err := engine.FromBase64(context.Background(), input, output); err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				return enc.Encode(struct {
					Output string `json:"output"`
				}{Output: output})
			}
			success("Created: " + output)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output JSON")
	return cmd
}

func buildCombineCommand(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
	var ca string
	var keyPassword string
	var keyPasswordStdin bool
	var keyPasswordFile string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "combine CERT KEY OUTPUT",
		Short: "Combine cert + key into single PEM",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedArgs, err := resolveInputArgs(cmd, args, 3, pathInput)
			if err != nil {
				return err
			}
			args = resolvedArgs

			inlineProvided := strings.TrimSpace(keyPassword) != ""
			kpw, err := loadSecret(cmd, keyPassword, keyPasswordStdin, keyPasswordFile, "key-password", "key-password-stdin", "key-password-file")
			if err != nil {
				return err
			}
			keyPassword = kpw
			if inlineProvided && strings.TrimSpace(keyPassword) != "" && !keyPasswordStdin && strings.TrimSpace(keyPasswordFile) == "" {
				warnInlineSecretFlag("key-password")
			}

			certPath := resolvePath(args[0])
			keyPath := resolvePath(args[1])
			output := args[2]
			if err := requireFile(certPath); err != nil {
				return err
			}
			if err := requireFile(keyPath); err != nil {
				return err
			}

			caPath := ""
			if ca != "" {
				caPath = resolvePath(ca)
				if err := requireFile(caPath); err != nil {
					return err
				}
			}

			if !jsonOut {
				step("Creating combined PEM...")
			}
			if err := engine.CombinePEM(context.Background(), certPath, keyPath, output, caPath, keyPassword); err != nil {
				return err
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				return enc.Encode(struct {
					Output string `json:"output"`
				}{Output: output})
			}
			success("Created: " + output)
			return nil
		},
	}
	cmd.Flags().StringVarP(&ca, "ca", "a", "", "CA bundle file")
	cmd.Flags().StringVar(&keyPassword, "key-password", "", "Private key password (for encrypted keys)")
	cmd.Flags().BoolVar(&keyPasswordStdin, "key-password-stdin", false, "Read private key password from stdin")
	cmd.Flags().StringVar(&keyPasswordFile, "key-password-file", "", "Read private key password from file (use '-' for stdin)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output JSON")
	return cmd
}
