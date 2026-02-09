package cli

import (
	"os"

	"github.com/mattn/go-isatty"
)

// isTerminalFn is overridable in tests.
var isTerminalFn = func(f *os.File) bool {
	if f == nil {
		return false
	}
	fd := f.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}

func isInteractiveTTY() bool {
	return isTerminalFn(os.Stdin) && isTerminalFn(os.Stdout)
}
