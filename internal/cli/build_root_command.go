package cli

import (
	"context"
	"fmt"
	"os"
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
		buildTUICommand(runTUI),
		buildShowCommand(engine, &pathInput),
		buildShowFullCommand(engine, &pathInput),
		buildVerifyCommand(engine, &pathInput),
		buildMatchCommand(engine, &pathInput),
		buildExpiryCommand(engine, &pathInput),
		buildToPFXCommand(engine, &pathInput),
		buildFromPFXCommand(engine, &pathInput),
		buildToDERCommand(engine, &pathInput),
		buildFromDERCommand(engine, &pathInput),
		buildToBase64Command(engine, &pathInput),
		buildFromBase64Command(engine, &pathInput),
		buildCombineCommand(engine, &pathInput),
		buildVersionCommand(buildInfo),
	)

	return root
}

func buildTUICommand(runTUI func(startDir string) error) *cobra.Command {
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

func buildVersionCommand(buildInfo BuildInfo) *cobra.Command {
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
