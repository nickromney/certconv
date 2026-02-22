package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

type pathInputOptions struct {
	pathStdin  bool
	path0Stdin bool
}

// NewRootCmd creates the cobra root command with all subcommands.
// The runTUI function is called when no subcommand is given.
func NewRootCmd(engine *cert.Engine, runTUI func(startDir string) error, buildInfo BuildInfo) *cobra.Command {
	var (
		flagTUI                 bool
		flagNoColor             bool
		flagASCII               bool
		flagPlain               bool
		flagQuiet               bool
		flagNoWarnInlineSecrets bool
		pathInput               pathInputOptions
		quickDER                bool
		quickPassword           string
		quickPasswordStdin      bool
		quickPasswordFile       string
		quickKeyPassword        string
		quickKeyPasswordStdin   bool
		quickKeyPasswordFile    string
	)

	root := &cobra.Command{}
	root.Use = "certconv [FILE]"
	root.Short = "Non-invasive certificate inspection and format conversion tool"
	root.Long = "certconv is a local-first certificate toolkit with an interactive TUI and a script-friendly CLI. Inspect certificate/key files, verify chains, and convert between PEM, DER, PFX/P12, and Base64. It does not generate new certificates or call remote services."
	root.Args = cobra.MaximumNArgs(1)
	root.RunE = func(cmd *cobra.Command, args []string) error {
		if quickDER {
			if flagTUI {
				return &ExitError{Code: 2, Msg: "--der cannot be used with --tui"}
			}
			if len(args) != 1 {
				return &ExitError{Code: 2, Msg: "certconv --der requires exactly 1 FILE argument"}
			}

			inlinePasswordProvided := strings.TrimSpace(quickPassword) != ""
			inlineKeyPasswordProvided := strings.TrimSpace(quickKeyPassword) != ""
			pw, err := loadSecret(cmd, quickPassword, quickPasswordStdin, quickPasswordFile, "password", "password-stdin", "password-file")
			if err != nil {
				return err
			}
			quickPassword = pw
			kpw, err := loadSecret(cmd, quickKeyPassword, quickKeyPasswordStdin, quickKeyPasswordFile, "key-password", "key-password-stdin", "key-password-file")
			if err != nil {
				return err
			}
			quickKeyPassword = kpw
			if inlinePasswordProvided && strings.TrimSpace(quickPassword) != "" && !quickPasswordStdin && strings.TrimSpace(quickPasswordFile) == "" {
				warnInlineSecretFlag("password")
			}
			if inlineKeyPasswordProvided && strings.TrimSpace(quickKeyPassword) != "" && !quickKeyPasswordStdin && strings.TrimSpace(quickKeyPasswordFile) == "" {
				warnInlineSecretFlag("key-password")
			}

			input := resolvePath(args[0])
			if err := requireFile(input); err != nil {
				return err
			}
			out, err := quickDERBytes(context.Background(), engine, input, quickPassword, quickKeyPassword)
			if err != nil {
				return err
			}
			if _, err := cmd.OutOrStdout().Write(out); err != nil {
				return err
			}
			return nil
		}

		if flagTUI {
			startDir, err := resolveDirArg(args)
			if err != nil {
				return err
			}
			if !isInteractiveTTY() {
				return &ExitError{Code: 2, Msg: "TUI requires a TTY (interactive stdin/stdout)"}
			}
			if runTUI != nil {
				return runTUI(startDir)
			}
			return fmt.Errorf("TUI is not available")
		}
		if len(args) > 0 {
			return &ExitError{
				Code: 2,
				Msg:  "positional arguments require an explicit CLI command (or --der). For directory-scoped TUI, use: certconv tui DIR",
			}
		}

		// No subcommand: only auto-launch TUI when interactive.
		if !isInteractiveTTY() {
			_ = cmd.Help()
			return &ExitError{Code: 2, Silent: true}
		}
		if runTUI != nil {
			return runTUI("")
		}
		return cmd.Help()
	}
	root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		// Treat --tui as an alias for `certconv tui`. If a subcommand is used,
		// error rather than silently ignoring it.
		if flagTUI && cmd != root {
			return &ExitError{Code: 2, Msg: "--tui cannot be used with subcommands (use: certconv tui)"}
		}
		if quickDER && cmd != root {
			return &ExitError{Code: 2, Msg: "--der is only valid without subcommands"}
		}
		if pathInput.pathStdin && pathInput.path0Stdin {
			return &ExitError{Code: 2, Msg: "use only one of --path-stdin or --path0-stdin"}
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
	root.Version = buildInfo.Version + "\nbuild_time: " + buildInfo.BuildTime + "\ngit_commit: " + buildInfo.GitCommit
	root.SetVersionTemplate("certconv {{.Version}}\n")
	root.SilenceUsage = true
	root.SilenceErrors = true

	root.PersistentFlags().BoolVar(&flagTUI, "tui", false, "Launch the interactive TUI")
	root.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "Disable ANSI color output")
	root.PersistentFlags().BoolVar(&flagASCII, "ascii", false, "Use ASCII-only output (no Unicode glyphs)")
	root.PersistentFlags().BoolVarP(&flagQuiet, "quiet", "q", false, "Suppress status output (errors still print)")
	root.PersistentFlags().BoolVar(&flagPlain, "plain", false, "Plain output (implies --no-color and --ascii)")
	root.PersistentFlags().BoolVar(&flagNoWarnInlineSecrets, "no-warn-inline-secrets", false, "Disable warnings for inline secret flags")
	root.PersistentFlags().BoolVar(&pathInput.pathStdin, "path-stdin", false, "Read missing path args from stdin (newline-delimited)")
	root.PersistentFlags().BoolVar(&pathInput.path0Stdin, "path0-stdin", false, "Read missing path args from stdin (NUL-delimited)")
	root.Flags().BoolVarP(&quickDER, "der", "d", false, "Quick convert FILE to DER and write bytes to stdout")
	root.Flags().StringVar(&quickPassword, "password", "", "Password for quick conversion when reading PFX input")
	root.Flags().BoolVar(&quickPasswordStdin, "password-stdin", false, "Read quick-conversion password from stdin")
	root.Flags().StringVar(&quickPasswordFile, "password-file", "", "Read quick-conversion password from file (use '-' for stdin)")
	root.Flags().StringVar(&quickKeyPassword, "key-password", "", "Private key password for quick conversion when reading key input")
	root.Flags().BoolVar(&quickKeyPasswordStdin, "key-password-stdin", false, "Read quick-conversion key password from stdin")
	root.Flags().StringVar(&quickKeyPasswordFile, "key-password-file", "", "Read quick-conversion key password from file (use '-' for stdin)")

	root.AddCommand(
		newTUICmd(runTUI),
		newShowCmd(engine, &pathInput),
		newShowFullCmd(engine, &pathInput),
		newVerifyCmd(engine, &pathInput),
		newMatchCmd(engine, &pathInput),
		newExpiryCmd(engine, &pathInput),
		newToPFXCmd(engine, &pathInput),
		newFromPFXCmd(engine, &pathInput),
		newToDERCmd(engine, &pathInput),
		newFromDERCmd(engine, &pathInput),
		newToBase64Cmd(engine, &pathInput),
		newFromBase64Cmd(engine, &pathInput),
		newCombineCmd(engine, &pathInput),
		newVersionCmd(buildInfo),
	)

	return root
}

func newTUICmd(runTUI func(startDir string) error) *cobra.Command {
	return &cobra.Command{
		Use:   "tui [DIR]",
		Short: "Launch the interactive TUI",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !isInteractiveTTY() {
				return &ExitError{Code: 2, Msg: "TUI requires a TTY (interactive stdin/stdout)"}
			}
			if runTUI == nil {
				return fmt.Errorf("TUI is not available")
			}
			startDir, err := resolveDirArg(args)
			if err != nil {
				return err
			}
			return runTUI(startDir)
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

func newShowCmd(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
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

func newShowFullCmd(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
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

func newVerifyCmd(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
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

func newMatchCmd(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
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

func newExpiryCmd(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
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

func newToPFXCmd(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
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

func newFromPFXCmd(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
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

func newToDERCmd(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
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

func newFromDERCmd(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
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

func newToBase64Cmd(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
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

func newFromBase64Cmd(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
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

func newCombineCmd(engine *cert.Engine, pathInput *pathInputOptions) *cobra.Command {
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

func resolveInputArgs(cmd *cobra.Command, args []string, expected int, pathInput *pathInputOptions) ([]string, error) {
	if expected < 0 {
		expected = 0
	}
	out := append([]string(nil), args...)
	if pathInput == nil {
		return requireArgCount(cmd, out, expected)
	}

	if pathInput.pathStdin || pathInput.path0Stdin {
		if usesStdinForSecrets(cmd) {
			return nil, &ExitError{Code: 2, Msg: "--path-stdin/--path0-stdin cannot be combined with secret stdin flags"}
		}
		fromStdin, err := readPathsFromStdin(cmd, pathInput.path0Stdin)
		if err != nil {
			return nil, err
		}
		out = append(fromStdin, out...)
		return requireArgCount(cmd, out, expected)
	}

	return requireArgCount(cmd, out, expected)
}

func requireArgCount(cmd *cobra.Command, args []string, expected int) ([]string, error) {
	if len(args) != expected {
		return nil, &ExitError{Code: 2, Msg: fmt.Sprintf("%s requires %d argument(s), got %d", cmd.CommandPath(), expected, len(args))}
	}
	return args, nil
}

func usesStdinForSecrets(cmd *cobra.Command) bool {
	for _, name := range []string{"password-stdin", "key-password-stdin"} {
		f := cmd.Flags().Lookup(name)
		if f != nil && strings.TrimSpace(f.Value.String()) == "true" {
			return true
		}
	}
	for _, name := range []string{"password-file", "key-password-file"} {
		f := cmd.Flags().Lookup(name)
		if f != nil && strings.TrimSpace(f.Value.String()) == "-" {
			return true
		}
	}
	return false
}

func readPathsFromStdin(cmd *cobra.Command, nulDelimited bool) ([]string, error) {
	if isTerminalFn(os.Stdin) {
		flag := "--path-stdin"
		if nulDelimited {
			flag = "--path0-stdin"
		}
		return nil, &ExitError{Code: 2, Msg: flag + " requires stdin to be piped/redirected"}
	}
	b, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		return nil, err
	}
	var raw []string
	if nulDelimited {
		raw = strings.Split(string(b), "\x00")
	} else {
		norm := strings.ReplaceAll(string(b), "\r\n", "\n")
		raw = strings.Split(norm, "\n")
	}

	paths := make([]string, 0, len(raw))
	for _, s := range raw {
		s = strings.TrimRight(s, "\r\n")
		if strings.TrimSpace(s) == "" {
			continue
		}
		paths = append(paths, s)
	}
	return paths, nil
}

func quickDERBytes(ctx context.Context, engine *cert.Engine, inputPath, password, keyPassword string) ([]byte, error) {
	ft, err := cert.DetectType(inputPath)
	if err != nil {
		return nil, fmt.Errorf("detect type: %w", err)
	}

	readNonEmpty := func(path string) ([]byte, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if len(b) == 0 {
			return nil, fmt.Errorf("conversion to DER produced empty output")
		}
		return b, nil
	}
	withTempOut := func(name string, fn func(outputPath string) error) ([]byte, error) {
		tmpDir, err := os.MkdirTemp("", "certconv-quick-der-*")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmpDir)
		outPath := filepath.Join(tmpDir, name)
		if err := fn(outPath); err != nil {
			return nil, err
		}
		return readNonEmpty(outPath)
	}

	switch ft {
	case cert.FileTypeCert, cert.FileTypeCombined:
		return engine.CertDER(ctx, inputPath)
	case cert.FileTypeDER:
		return readNonEmpty(inputPath)
	case cert.FileTypePFX:
		pemOut, err := engine.PFXCertsPEM(ctx, inputPath, password)
		if err != nil {
			return nil, err
		}
		tmpDir, err := os.MkdirTemp("", "certconv-quick-pfx-*")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmpDir)
		pemPath := filepath.Join(tmpDir, "from-pfx.pem")
		if err := os.WriteFile(pemPath, pemOut, 0o600); err != nil {
			return nil, err
		}
		return engine.CertDER(ctx, pemPath)
	case cert.FileTypeBase64:
		return withTempOut("decoded.der", func(outputPath string) error {
			return engine.FromBase64(ctx, inputPath, outputPath)
		})
	case cert.FileTypeKey:
		return withTempOut("key.der", func(outputPath string) error {
			return engine.ToDER(ctx, inputPath, outputPath, true, keyPassword)
		})
	default:
		isDER, derr := cert.IsDEREncoded(inputPath)
		if derr == nil && isDER {
			return readNonEmpty(inputPath)
		}
		return nil, fmt.Errorf("quick DER conversion not supported for detected type %q (use explicit subcommands)", ft)
	}
}

// resolvePath resolves a filename, checking CERTCONV_CERTS_DIR.
func resolvePath(path string) string {
	path = expandHomePath(path)
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
	certsDir := expandHomePath(os.Getenv("CERTCONV_CERTS_DIR"))
	if certsDir == "" {
		certsDir = "./certs"
	}
	candidate := filepath.Join(certsDir, path)
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return path
}

func resolveDirArg(args []string) (string, error) {
	if len(args) == 0 {
		return "", nil
	}
	raw := strings.TrimSpace(args[0])
	if raw == "" {
		return "", &ExitError{Code: 2, Msg: "directory path cannot be empty"}
	}
	dir := expandHomePath(raw)
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return "", &ExitError{Code: 2, Msg: "directory not found: " + raw}
	}
	if err != nil {
		return "", fmt.Errorf("cannot access directory: %s: %w", raw, err)
	}
	if !info.IsDir() {
		return "", &ExitError{Code: 2, Msg: "path is not a directory: " + raw}
	}
	return dir, nil
}

func expandHomePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return path
	}
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
		return path
	}
	if strings.HasPrefix(path, "~"+string(filepath.Separator)) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~"+string(filepath.Separator)))
		}
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
