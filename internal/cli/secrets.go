package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func loadSecret(cmd *cobra.Command, value string, fromStdin bool, fromFile string, valueFlag, stdinFlag, fileFlag string) (string, error) {
	specified := 0
	if strings.TrimSpace(value) != "" {
		specified++
	}
	if fromStdin {
		specified++
	}
	if strings.TrimSpace(fromFile) != "" {
		specified++
	}
	if specified > 1 {
		return "", &ExitError{
			Code: 2,
			Msg:  fmt.Sprintf("use only one of --%s, --%s, or --%s", valueFlag, stdinFlag, fileFlag),
		}
	}

	if fromStdin {
		return readSecretFromStdin(cmd, stdinFlag)
	}
	if strings.TrimSpace(fromFile) != "" {
		return readSecretFromFile(cmd, fileFlag, fromFile)
	}
	return value, nil
}

func readSecretFromStdin(cmd *cobra.Command, flagName string) (string, error) {
	// Intentionally gate on the real stdin TTY-ness to avoid accidental hangs.
	// Users should pipe/redirect.
	if isTerminalFn(os.Stdin) {
		return "", &ExitError{Code: 2, Msg: fmt.Sprintf("--%s requires stdin to be piped/redirected", flagName)}
	}

	b, err := io.ReadAll(cmd.InOrStdin())
	if err != nil {
		return "", err
	}
	// Trim only trailing newlines. Do not TrimSpace: passwords may contain spaces.
	s := strings.TrimRight(string(b), "\r\n")
	return s, nil
}

func readSecretFromFile(cmd *cobra.Command, flagName string, path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "-" {
		return readSecretFromStdin(cmd, flagName)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	// Trim only trailing newlines. Do not TrimSpace: passwords may contain spaces.
	s := strings.TrimRight(string(b), "\r\n")
	return s, nil
}
