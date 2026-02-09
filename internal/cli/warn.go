package cli

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

var (
	inlineSecretWarnMu          sync.Mutex
	inlineSecretWarned          = map[string]bool{}
	inlineSecretWarningsEnabled = true
)

func setInlineSecretWarnings(enabled bool) {
	inlineSecretWarnMu.Lock()
	inlineSecretWarningsEnabled = enabled
	inlineSecretWarnMu.Unlock()
}

func warnInlineSecretFlag(flagName string) {
	flagName = strings.TrimSpace(flagName)
	if flagName == "" {
		return
	}
	inlineSecretWarnMu.Lock()
	enabled := inlineSecretWarningsEnabled
	inlineSecretWarnMu.Unlock()
	if !enabled {
		return
	}
	// Only nudge in interactive terminals. Avoid polluting logs/pipes.
	if !isTerminalFn(os.Stderr) {
		return
	}

	inlineSecretWarnMu.Lock()
	if inlineSecretWarned[flagName] {
		inlineSecretWarnMu.Unlock()
		return
	}
	inlineSecretWarned[flagName] = true
	inlineSecretWarnMu.Unlock()

	fmt.Fprintf(outStderr, "Warning: --%s may leak secrets via shell history. Prefer --%s-stdin or --%s-file.\n", flagName, flagName, flagName)
}
