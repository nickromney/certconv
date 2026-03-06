package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

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
