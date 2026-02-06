package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

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
	root := &cobra.Command{
		Use:   "certconv",
		Short: "Non-invasive certificate inspection and format conversion tool",
		Long:  "certconv inspects local certificate/key files and converts between common formats (PEM, PFX/P12, DER, Base64). It does not generate new certificates or talk to remote services.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if runTUI != nil {
				return runTUI()
			}
			return cmd.Help()
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(
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

func newVersionCmd(buildInfo BuildInfo) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show build information",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("certconv %s\n", buildInfo.Version)
			fmt.Printf("build_time: %s\n", buildInfo.BuildTime)
			fmt.Printf("git_commit: %s\n", buildInfo.GitCommit)
		},
	}
}

func newShowCmd(engine *cert.Engine) *cobra.Command {
	var password string
	cmd := &cobra.Command{
		Use:   "show FILE",
		Short: "Show certificate summary",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := resolvePath(args[0])
			if err := requireFile(path); err != nil {
				return err
			}

			s, err := engine.Summary(context.Background(), path, password)
			if err != nil {
				return err
			}

			fmt.Println()
			kv("File", s.File)
			kv("Type", string(s.FileType))
			fmt.Println()

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
			fmt.Println()
			return nil
		},
	}
	cmd.Flags().StringVarP(&password, "password", "p", "", "PFX password")
	return cmd
}

func newShowFullCmd(engine *cert.Engine) *cobra.Command {
	var password string
	cmd := &cobra.Command{
		Use:   "show-full FILE",
		Short: "Show full certificate details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := resolvePath(args[0])
			if err := requireFile(path); err != nil {
				return err
			}

			d, err := engine.Details(context.Background(), path, password)
			if err != nil {
				return err
			}

			fmt.Print(d.RawText)
			return nil
		},
	}
	cmd.Flags().StringVarP(&password, "password", "p", "", "PFX password")
	return cmd
}

func newVerifyCmd(engine *cert.Engine) *cobra.Command {
	return &cobra.Command{
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

			step("Verifying certificate chain...")
			result, err := engine.VerifyChain(context.Background(), certPath, caPath)
			if err != nil {
				return err
			}

			if result.Valid {
				success("Certificate chain verified")
				return nil
			}

			errMsg("Chain verification failed")
			fmt.Println()
			fmt.Printf("  %s\n", result.Output)
			if result.Details != "" {
				fmt.Println()
				warn(result.Details)
			}
			return fmt.Errorf("verification failed")
		},
	}
}

func newMatchCmd(engine *cert.Engine) *cobra.Command {
	return &cobra.Command{
		Use:   "match CERT KEY",
		Short: "Check if key matches certificate",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			certPath := resolvePath(args[0])
			keyPath := resolvePath(args[1])
			if err := requireFile(certPath); err != nil {
				return err
			}
			if err := requireFile(keyPath); err != nil {
				return err
			}

			step("Checking if key matches certificate...")
			result, err := engine.MatchKeyToCert(context.Background(), certPath, keyPath)
			if err != nil {
				return err
			}

			if result.Match {
				success("Private key matches certificate")
				return nil
			}
			errMsg("Private key does NOT match certificate")
			return fmt.Errorf("key mismatch")
		},
	}
}

func newExpiryCmd(engine *cert.Engine) *cobra.Command {
	var days int
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
	return cmd
}

func newToPFXCmd(engine *cert.Engine) *cobra.Command {
	var password, ca string
	cmd := &cobra.Command{
		Use:   "to-pfx CERT KEY OUTPUT",
		Short: "Convert PEM cert + key to PFX",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
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

			step("Creating PFX...")
			if err := engine.ToPFX(context.Background(), certPath, keyPath, output, password, caPath); err != nil {
				return err
			}
			success("Created: " + output)
			return nil
		},
	}
	cmd.Flags().StringVarP(&password, "password", "p", "", "Export password")
	cmd.Flags().StringVarP(&ca, "ca", "a", "", "CA bundle file")
	return cmd
}

func newFromPFXCmd(engine *cert.Engine) *cobra.Command {
	var password string
	cmd := &cobra.Command{
		Use:   "from-pfx INPUT OUTDIR",
		Short: "Extract PEM from PFX",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			input := resolvePath(args[0])
			outDir := args[1]
			if err := requireFile(input); err != nil {
				return err
			}

			step("Extracting from PFX...")
			result, err := engine.FromPFX(context.Background(), input, outDir, password)
			if err != nil {
				return err
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
	return cmd
}

func newToDERCmd(engine *cert.Engine) *cobra.Command {
	var isKey bool
	cmd := &cobra.Command{
		Use:   "to-der INPUT OUTPUT",
		Short: "Convert PEM to DER",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			input := resolvePath(args[0])
			output := args[1]
			if err := requireFile(input); err != nil {
				return err
			}

			step("Converting to DER...")
			if err := engine.ToDER(context.Background(), input, output, isKey); err != nil {
				return err
			}
			success("Created: " + output)
			return nil
		},
	}
	cmd.Flags().BoolVar(&isKey, "key", false, "Input is a private key")
	return cmd
}

func newFromDERCmd(engine *cert.Engine) *cobra.Command {
	var isKey bool
	cmd := &cobra.Command{
		Use:   "from-der INPUT OUTPUT",
		Short: "Convert DER to PEM",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			input := resolvePath(args[0])
			output := args[1]
			if err := requireFile(input); err != nil {
				return err
			}

			step("Converting to PEM...")
			if err := engine.FromDER(context.Background(), input, output, isKey); err != nil {
				return err
			}
			success("Created: " + output)
			return nil
		},
	}
	cmd.Flags().BoolVar(&isKey, "key", false, "Input is a private key")
	return cmd
}

func newToBase64Cmd(engine *cert.Engine) *cobra.Command {
	return &cobra.Command{
		Use:   "to-base64 INPUT OUTPUT",
		Short: "Encode file to Base64",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			input := resolvePath(args[0])
			output := args[1]
			if err := requireFile(input); err != nil {
				return err
			}

			step("Encoding to Base64...")
			if err := engine.ToBase64(context.Background(), input, output); err != nil {
				return err
			}
			success("Created: " + output)
			return nil
		},
	}
}

func newFromBase64Cmd(engine *cert.Engine) *cobra.Command {
	return &cobra.Command{
		Use:   "from-base64 INPUT OUTPUT",
		Short: "Decode Base64 to file",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			input := resolvePath(args[0])
			output := args[1]
			if err := requireFile(input); err != nil {
				return err
			}

			step("Decoding Base64...")
			if err := engine.FromBase64(context.Background(), input, output); err != nil {
				return err
			}
			success("Created: " + output)
			return nil
		},
	}
}

func newCombineCmd(engine *cert.Engine) *cobra.Command {
	var ca string
	cmd := &cobra.Command{
		Use:   "combine CERT KEY OUTPUT",
		Short: "Combine cert + key into single PEM",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
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

			step("Creating combined PEM...")
			if err := engine.CombinePEM(context.Background(), certPath, keyPath, output, caPath); err != nil {
				return err
			}
			success("Created: " + output)
			return nil
		},
	}
	cmd.Flags().StringVarP(&ca, "ca", "a", "", "CA bundle file")
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
