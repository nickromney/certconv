package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nickromney/certconv/internal/cert"
	"github.com/spf13/cobra"
)

type BuildInfo struct {
	Version   string
	BuildTime string
	GitCommit string
}

// NewRootCmd creates the cobra root command with all subcommands.
// The runTUI function is called when no subcommand is given.
func NewRootCmd(engine *cert.Engine, runTUI func() error, buildInfo BuildInfo) *cobra.Command {
	var (
		flagTUI                 bool
		flagNoColor             bool
		flagASCII               bool
		flagPlain               bool
		flagQuiet               bool
		flagNoWarnInlineSecrets bool
	)

	root := &cobra.Command{}
	root.Use = "certconv"
	root.Short = "Non-invasive certificate inspection and format conversion tool"
	root.Long = "certconv inspects local certificate/key files and converts between common formats (PEM, PFX/P12, DER, Base64). It does not generate new certificates or talk to remote services."
	root.RunE = func(cmd *cobra.Command, args []string) error {
		if flagTUI {
			if !isInteractiveTTY() {
				return &ExitError{Code: 2, Msg: "TUI requires a TTY (interactive stdin/stdout)"}
			}
			if runTUI != nil {
				return runTUI()
			}
			return fmt.Errorf("TUI is not available")
		}

		// No subcommand: only auto-launch TUI when interactive.
		if !isInteractiveTTY() {
			_ = cmd.Help()
			return &ExitError{Code: 2, Silent: true}
		}
		if runTUI != nil {
			return runTUI()
		}
		return cmd.Help()
	}
	root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		// Treat --tui as an alias for `certconv tui`. If a subcommand is used,
		// error rather than silently ignoring it.
		if flagTUI && cmd != root {
			return &ExitError{Code: 2, Msg: "--tui cannot be used with subcommands (use: certconv tui)"}
		}

		// Default to human-friendly output when interactive, and sane/log-friendly
		// output when piped.
		isTTY := isTerminalFn(os.Stdout)
		color := isTTY
		if flagNoColor || flagPlain {
			color = false
		}
		if strings.TrimSpace(os.Getenv("NO_COLOR")) != "" {
			color = false
		}
		if strings.TrimSpace(os.Getenv("TERM")) == "dumb" {
			color = false
		}

		unicode := isTTY
		if flagASCII || flagPlain {
			unicode = false
		}
		setOutputOptions(cmd.OutOrStdout(), cmd.ErrOrStderr(), outputOptions{color: color, unicode: unicode, quiet: flagQuiet})
		setInlineSecretWarnings(!flagNoWarnInlineSecrets)
		return nil
	}
	root.SilenceUsage = true
	root.SilenceErrors = true

	root.PersistentFlags().BoolVar(&flagTUI, "tui", false, "Launch the interactive TUI")
	root.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "Disable ANSI color output")
	root.PersistentFlags().BoolVar(&flagASCII, "ascii", false, "Use ASCII-only output (no Unicode glyphs)")
	root.PersistentFlags().BoolVarP(&flagQuiet, "quiet", "q", false, "Suppress status output (errors still print)")
	root.PersistentFlags().BoolVar(&flagPlain, "plain", false, "Plain output (implies --no-color and --ascii)")
	root.PersistentFlags().BoolVar(&flagNoWarnInlineSecrets, "no-warn-inline-secrets", false, "Disable warnings for inline secret flags")

	root.AddCommand(
		newTUICmd(runTUI),
		newShowCmd(engine),
		newShowFullCmd(engine),
		newVerifyCmd(engine),
		newMatchCmd(engine),
		newExpiryCmd(engine),
		newToPFXCmd(engine),
		newFromPFXCmd(engine),
		newToDERCmd(engine),
		newFromDERCmd(engine),
		newToBase64Cmd(engine),
		newFromBase64Cmd(engine),
		newCombineCmd(engine),
		newVersionCmd(buildInfo),
	)

	return root
}

func newTUICmd(runTUI func() error) *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Launch the interactive TUI",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !isInteractiveTTY() {
				return &ExitError{Code: 2, Msg: "TUI requires a TTY (interactive stdin/stdout)"}
			}
			if runTUI == nil {
				return fmt.Errorf("TUI is not available")
			}
			return runTUI()
		},
	}
}

func newVersionCmd(buildInfo BuildInfo) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show build information",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(outStdout, "certconv %s\n", buildInfo.Version)
			fmt.Fprintf(outStdout, "build_time: %s\n", buildInfo.BuildTime)
			fmt.Fprintf(outStdout, "git_commit: %s\n", buildInfo.GitCommit)
		},
	}
}

func newShowCmd(engine *cert.Engine) *cobra.Command {
	var password string
	var passwordStdin bool
	var passwordFile string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "show FILE",
		Short: "Show certificate summary",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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

func newShowFullCmd(engine *cert.Engine) *cobra.Command {
	var password string
	var passwordStdin bool
	var passwordFile string
	cmd := &cobra.Command{
		Use:   "show-full FILE",
		Short: "Show full certificate details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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

func newVerifyCmd(engine *cert.Engine) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "verify CERT CA",
		Short: "Verify certificate chain",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
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

func newMatchCmd(engine *cert.Engine) *cobra.Command {
	var keyPassword string
	var keyPasswordStdin bool
	var keyPasswordFile string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "match CERT KEY",
		Short: "Check if key matches certificate",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
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

func newExpiryCmd(engine *cert.Engine) *cobra.Command {
	var days int
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "expiry CERT",
		Short: "Check certificate expiration",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
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

func newToPFXCmd(engine *cert.Engine) *cobra.Command {
	var password, ca, keyPassword string
	var passwordStdin, keyPasswordStdin bool
	var passwordFile, keyPasswordFile string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "to-pfx CERT KEY OUTPUT",
		Short: "Convert PEM cert + key to PFX",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
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

func newFromPFXCmd(engine *cert.Engine) *cobra.Command {
	var password string
	var passwordStdin bool
	var passwordFile string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "from-pfx INPUT OUTDIR",
		Short: "Extract PEM from PFX",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
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

func newToDERCmd(engine *cert.Engine) *cobra.Command {
	var isKey bool
	var keyPassword string
	var keyPasswordStdin bool
	var keyPasswordFile string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "to-der INPUT OUTPUT",
		Short: "Convert PEM to DER",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
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

func newFromDERCmd(engine *cert.Engine) *cobra.Command {
	var isKey bool
	var keyPassword string
	var keyPasswordStdin bool
	var keyPasswordFile string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "from-der INPUT OUTPUT",
		Short: "Convert DER to PEM",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
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

func newToBase64Cmd(engine *cert.Engine) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "to-base64 INPUT OUTPUT",
		Short: "Encode file to Base64",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
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

func newFromBase64Cmd(engine *cert.Engine) *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "from-base64 INPUT OUTPUT",
		Short: "Decode Base64 to file",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
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

func newCombineCmd(engine *cert.Engine) *cobra.Command {
	var ca string
	var keyPassword string
	var keyPasswordStdin bool
	var keyPasswordFile string
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "combine CERT KEY OUTPUT",
		Short: "Combine cert + key into single PEM",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
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

// resolvePath resolves a filename, checking CERTCONV_CERTS_DIR.
func resolvePath(path string) string {
	if path == "" {
		return path
	}
	// Already absolute or has path separator
	if filepath.IsAbs(path) || filepath.Dir(path) != "." {
		return path
	}
	// Check if it exists as-is
	if _, err := os.Stat(path); err == nil {
		return path
	}
	// Try CERTCONV_CERTS_DIR
	certsDir := os.Getenv("CERTCONV_CERTS_DIR")
	if certsDir == "" {
		certsDir = "./certs"
	}
	candidate := filepath.Join(certsDir, path)
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return path
}

func requireFile(path string) error {
	if path == "" {
		return fmt.Errorf("file path required")
	}
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return fmt.Errorf("file not found: %s", path)
	}
	if err != nil {
		return fmt.Errorf("cannot access file: %s: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("path is a directory: %s", path)
	}
	return nil
}
