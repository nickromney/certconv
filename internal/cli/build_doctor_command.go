package cli

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

// toolCheck describes a single external tool that certconv can use.
type toolCheck struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Found    bool   `json:"found"`
	Features string `json:"features"`
}

// lookPathFn is overridable in tests.
var lookPathFn = exec.LookPath

// toolVersionFn runs a tool with version args and returns combined output.
// Overridable in tests.
var toolVersionFn = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

func buildDoctorCommand() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check availability of external tools",
		Long: `Check availability of external tools used by certconv.

Reports the status and version of each optional dependency:
  openssl   — certificate inspection, conversion, PFX, DER, P7B
  fzf       — TUI fuzzy file picker

Works on macOS, Linux, and Windows/WSL2.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			checks := runToolChecks()

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetEscapeHTML(false)
				enc.SetIndent("", "  ")
				return enc.Encode(checks)
			}

			fmt.Fprintln(outStdout)
			info("certconv doctor")
			fmt.Fprintln(outStdout)

			allFound := true
			for _, c := range checks {
				if c.Found {
					success(fmt.Sprintf("%-12s %s", c.Name, c.Version))
				} else {
					warn(fmt.Sprintf("%-12s not found — needed for %s", c.Name, c.Features))
					allFound = false
				}
			}

			fmt.Fprintln(outStdout)
			if allFound {
				success("All external tools available")
			} else {
				warn("Some tools are missing; affected features will be unavailable")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output JSON")
	return cmd
}

func runToolChecks() []toolCheck {
	return []toolCheck{
		checkTool("openssl", []string{"version"}, "certificate inspection, conversion, PFX, DER, P7B"),
		checkTool("fzf", []string{"--version"}, "TUI fuzzy file picker"),
	}
}

func checkTool(name string, versionArgs []string, features string) toolCheck {
	tc := toolCheck{Name: name, Features: features}
	path, err := lookPathFn(name)
	if err != nil || path == "" {
		return tc
	}
	tc.Found = true

	out, err := toolVersionFn(name, versionArgs...)
	ver := strings.TrimSpace(string(out))
	// Take first line only.
	if i := strings.IndexByte(ver, '\n'); i > 0 {
		ver = ver[:i]
	}
	if err != nil && (strings.Contains(ver, "Unable to locate") || strings.Contains(ver, "not found")) {
		// Tool stub exists but runtime is missing.
		tc.Found = false
		return tc
	}
	tc.Version = ver
	return tc
}
