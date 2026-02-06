package cli

import (
	"fmt"
	"os"
)

const (
	colorRed    = "\033[0;31m"
	colorGreen  = "\033[0;32m"
	colorYellow = "\033[0;33m"
	colorBlue   = "\033[0;34m"
	colorDim    = "\033[0;90m"
	colorBold   = "\033[1m"
	colorReset  = "\033[0m"
)

func info(msg string)    { fmt.Printf("%si%s  %s\n", colorBlue, colorReset, msg) }
func success(msg string) { fmt.Printf("%s✓%s  %s\n", colorGreen, colorReset, msg) }
func warn(msg string)    { fmt.Printf("%s!%s  %s\n", colorYellow, colorReset, msg) }
func errMsg(msg string)  { fmt.Fprintf(os.Stderr, "%sx%s  %s\n", colorRed, colorReset, msg) }
func step(msg string)    { fmt.Printf("%s→%s  %s\n", colorDim, colorReset, msg) }

func bold(s string) string {
	return colorBold + s + colorReset
}

func kv(key, value string) {
	fmt.Printf("  %s%s:%s %s\n", colorBold, key, colorReset, value)
}
